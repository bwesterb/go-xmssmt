// Go implementation of the XMSS[MT] post-quantum stateful hash-based signature
// scheme as described in the RFC draft
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/
package xmssmt

// Contains majority of the API

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

// XMSS[MT] instance.
// Create one using NewContextFromName, NewContextFromOid or NewContext.
type Context struct {
	// Number of worker goroutines ("threads") to use for expensive operations.
	// Will guess an appropriate number if set to 0.
	Threads int

	p            Params // parameters.
	wotsLogW     uint8  // logarithm of the Winternitz parameter
	wotsLen1     uint32 // WOTS+ chains for message
	wotsLen2     uint32 // WOTS+ chains for checksum
	wotsLen      uint32 // total number of WOTS+ chains
	wotsSigBytes uint32 // length of WOTS+ signature
	treeHeight   uint32 // height of a subtree
	indexBytes   uint32 // size of an index
	sigBytes     uint32 // size of signature
	pkBytes      uint32 // size of public key
	skBytes      uint32 // size of secret key

	mt   bool    // true for XMSSMT; false for XMSS
	oid  uint32  // OID of this configuration, if it has any
	name *string // name of algorithm
}

// Sequence number of signatures.
// (Corresponds with leaf indices in the implementation.)
type SignatureSeqNo uint64

// XMSS[MT] private key
type PrivateKey struct {
	skSeed  []byte         // first part of the private key
	skPrf   []byte         // other part of the private key
	pubSeed []byte         // first part of the public key
	root    []byte         // root node, the other part of the public key
	seqNo   SignatureSeqNo // first unused signature sequence number

	ctx *Context          // context, which contains algorithm parameters.
	ph  precomputedHashes // precomputed hashes
	// container that stores the secret key, signature sequence number
	// and caches the subtrees
	ctr PrivateKeyContainer

	// Number of signatures reserved from the container.
	// See PrivateKeyContainer.Borrow()
	borrowed uint32

	// The least signature sequence number that might still be in use
	// by a Sign() operation.
	leastSeqNoInUse SignatureSeqNo

	// Heap of retired seqNo's larger than lesatSeqNoInUse.
	// See PrivateKey.retireSeqNo().
	retiredSeqNos *uint32Heap

	mux  sync.Mutex
	cond *sync.Cond     // signalled when a subtree is generated
	wg   sync.WaitGroup // used to join all background workers when Close()ing
	// subTreeReady[sta] is true if and only if the sub tree with the given
	// address is allocated and filled.
	subTreeReady map[SubTreeAddress]bool
	// Additionally, subTreeChecked[sta] is true if the tree has been
	// generated on this run or the checksum has been checked if loaded
	// from the private key container.
	subTreeChecked map[SubTreeAddress]bool

	// If true, will precompute a subtree in advance
	precomputeNextSubTree bool
}

// XMSS[MT] public key
type PublicKey struct {
	ctx     *Context // context which contains algorithm parameters
	pubSeed []byte
	root    []byte // root node
	ph      precomputedHashes
}

// Represents a XMSS[MT] signature
type Signature struct {
	ctx   *Context       // context which contains algorithm parameter
	seqNo SignatureSeqNo // sequence number of this signature. (Same as index.)
	drv   []byte         // digest randomized value (R)

	// The signature consists of several barebones XMSS signatures.
	// sigs[0] signs hash, sigs[1] signs the root of the subtree for sigs[0],
	// sigs[2] signs the root of the subtree for sigs[1], ...
	// sigs[d-1] signs the root of the subtree for sigs[d-2].
	sigs []subTreeSig
}

// Represents a signature made by a subtree. This is basically
// an XMSS signature without all the decorations.
type subTreeSig struct {
	wotsSig  []byte
	authPath []byte
}

type Error interface {
	error
	Locked() bool // Is this error because something (like a file) was locked?
	Inner() error // Returns the wrapped error, if any
}

// Generate a new keypair for the given XMSS[MT] instance alg.
//
// Stores the private key at privKeyPath. This will create two
// files: <privKeyPath> and <privKeyPath>.cache.  The first contains
// the private key and the  second contains sensitive cached information
// derived from the private key used to increase signing performance a lot.
//
// Use ListNames() to list the supported instances of XMSS[MT].
//
// For more flexibility use NewContextFromName() to create a Context and
// then call Context.GenerateKeyPair() or Context.DeriveInto().
//
// NOTE Do not forget to Close() the PrivateKey.
func GenerateKeyPair(alg, privKeyPath string) (*PrivateKey, *PublicKey, Error) {
	ctx := NewContextFromName(alg)
	if ctx == nil {
		return nil, nil, errorf("%s is not a valid algorithm name", alg)
	}
	return ctx.GenerateKeyPair(privKeyPath)
}

// Create a signature on msg using the private key stored at privKeyPath.
//
// For more flexibility, use PrivateKey.Sign().
func Sign(privKeyPath string, msg []byte) (sig []byte, err Error) {
	sk, _, _, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return nil, err
	}

	theSig, err := sk.Sign(msg)
	if err != nil {
		sk.Close()
		return nil, err
	}

	sig, err2 := theSig.MarshalBinary()
	if err2 != nil {
		sk.Close()
		return nil, wrapErrorf(err2, "Signature.MarshalBinary")
	}

	if err = sk.Close(); err != nil {
		return nil, err
	}
	return sig, nil
}

// Checks whether sig is a valid signature of pk on msg.
func Verify(pk, sig, msg []byte) (bool, Error) {
	var theSig Signature
	var thePk PublicKey
	err := theSig.UnmarshalBinary(sig)
	if err != nil {
		return false, wrapErrorf(err, "Failed to unmarshal signature")
	}
	err = thePk.UnmarshalBinary(pk)
	if err != nil {
		return false, wrapErrorf(err, "Failed to unmarshal public key")
	}
	return thePk.Verify(&theSig, msg)
}

// Check whether the sig is a valid signature of this public key
// for the given message.
func (pk *PublicKey) Verify(sig *Signature, msg []byte) (bool, Error) {
	return pk.VerifyFrom(sig, bytes.NewReader(msg))
}

// Reads a message from the io.Reader and verifies whether the provided
// signature is valid for this public key and message.
func (pk *PublicKey) VerifyFrom(sig *Signature, msg io.Reader) (bool, Error) {
	pad := pk.ctx.newScratchPad()
	curHash := make([]byte, sig.ctx.p.N)

	rxMsg, err := pk.ctx.hashMessage(pad, msg, sig.drv,
		pk.root, uint64(sig.seqNo))
	if err != nil {
		return false, wrapErrorf(err, "Failed to hash message")
	}

	staPath, leafs := pk.ctx.subTreePathForSeqNo(sig.seqNo)

	var layer uint32
	for layer = 0; layer < pk.ctx.p.D; layer++ {
		var lTreeAddr, otsAddr, nodeAddr address
		rxAddr := staPath[layer].address()
		otsAddr.setSubTreeFrom(rxAddr)
		otsAddr.setType(ADDR_TYPE_OTS)
		lTreeAddr.setSubTreeFrom(rxAddr)
		lTreeAddr.setType(ADDR_TYPE_LTREE)
		nodeAddr.setSubTreeFrom(rxAddr)
		nodeAddr.setType(ADDR_TYPE_HASHTREE)

		rxSig := sig.sigs[layer]
		var offset uint32 = leafs[layer]
		otsAddr.setOTS(offset)
		lTreeAddr.setLTree(offset)
		wotsPk := pad.wotsBuf()
		pk.ctx.wotsPkFromSigInto(pad, rxSig.wotsSig, rxMsg, pk.ph, otsAddr, wotsPk)
		pk.ctx.lTreeInto(pad, wotsPk, pk.ph, lTreeAddr, curHash)

		// use the authentication path to hash up the merkle tree
		var height uint32
		for height = 1; height <= pk.ctx.treeHeight; height++ {
			var left, right []byte
			nodeAddr.setTreeHeight(height - 1)
			nodeAddr.setTreeIndex(offset >> 1)
			sibling := rxSig.authPath[(height-1)*pk.ctx.p.N : height*pk.ctx.p.N]

			if offset&1 == 0 {
				// we're on the left, so the sibling hash from the
				// auth path is on the right
				left = curHash
				right = sibling
			} else {
				left = sibling
				right = curHash
			}

			pk.ctx.hInto(pad, left, right, pk.ph, nodeAddr, curHash)
			offset >>= 1
		}

		rxMsg = curHash
	}

	if subtle.ConstantTimeCompare(rxMsg, pk.root) != 1 {
		return false, errorf("Invalid signature")
	}

	return true, nil
}

// Returns representation of signature with parameters compressed into
// the reserved space of the Oid prefix.  See Params.MarshalBinary().
func (sig *Signature) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 4+sig.ctx.sigBytes)
	err := sig.WriteInto(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Initializes the Signature as stored by MarshalBinary.
func (sig *Signature) UnmarshalBinary(buf []byte) error {
	var params Params
	err := params.UnmarshalBinary(buf[:4])
	if err != nil {
		return err
	}
	sig.ctx, err = NewContext(params)
	if err != nil {
		return err
	}
	sig.seqNo = SignatureSeqNo(decodeUint64(buf[4 : 4+sig.ctx.indexBytes]))
	sig.drv = make([]byte, params.N)
	sig.sigs = make([]subTreeSig, params.D)
	copy(sig.drv, buf[4+sig.ctx.indexBytes:4+sig.ctx.indexBytes+params.N])
	stOff := 4 + sig.ctx.indexBytes + params.N
	stLen := sig.ctx.wotsSigBytes + params.N*sig.ctx.treeHeight
	var i uint32
	for i = 0; i < params.D; i++ {
		stSig := &sig.sigs[i]
		stSig.wotsSig = make([]byte, sig.ctx.wotsSigBytes)
		stSig.authPath = make([]byte, params.N*sig.ctx.treeHeight)
		copy(stSig.wotsSig, buf[stOff+i*stLen:stOff+i*stLen+sig.ctx.wotsSigBytes])
		copy(stSig.authPath, buf[stOff+i*stLen+sig.ctx.wotsSigBytes:stOff+(i+1)*stLen])
	}
	return nil
}

// Writes signature to buf in the same way as returned
// by Signature.MarshalBinary().
func (sig *Signature) WriteInto(buf []byte) error {
	err := sig.ctx.p.WriteInto(buf)
	if err != nil {
		return err
	}
	encodeUint64Into(uint64(sig.seqNo), buf[4:4+sig.ctx.indexBytes])
	copy(buf[4+sig.ctx.indexBytes:], sig.drv)
	stOff := 4 + sig.ctx.indexBytes + sig.ctx.p.N
	stLen := sig.ctx.wotsSigBytes + sig.ctx.p.N*sig.ctx.treeHeight
	for i, stSig := range sig.sigs {
		copy(buf[stOff+uint32(i)*stLen:], stSig.wotsSig)
		copy(buf[stOff+uint32(i)*stLen+sig.ctx.wotsSigBytes:], stSig.authPath)
	}
	return nil
}

// Returns the sequence number of this signature.
func (sig *Signature) SeqNo() SignatureSeqNo {
	return sig.seqNo
}

func (sig Signature) String() string {
	return fmt.Sprintf("%s seqno=%d/%d",
		sig.ctx.p, sig.seqNo, sig.ctx.p.MaxSignatureSeqNo())
}

// Initializes the Signature as stored by MarshalText.
func (pk *PublicKey) UnmarshalText(text []byte) error {
	buf, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	return pk.UnmarshalBinary(buf)
}

// Returns base64 encoded version of the public key
func (pk *PublicKey) MarshalText() ([]byte, error) {
	buf, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(buf)), nil
}

// Writes the public key into buf in the same way as returned
// by PublicKey.MarshalBinary()
func (pk *PublicKey) WriteInto(buf []byte) error {
	err := pk.ctx.p.WriteInto(buf)
	if err != nil {
		return err
	}
	copy(buf[4:], pk.root)
	copy(buf[4+pk.ctx.p.N:], pk.pubSeed)
	return nil
}

// Returns representation of the public key with parameters compressed into
// the reserved space of the Oid prefix.  See Params.MarshalBinary().
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 4+pk.ctx.p.N*2)
	err := pk.WriteInto(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Initializes the PublicKey as was stored by MarshalBinary.
func (pk *PublicKey) UnmarshalBinary(buf []byte) error {
	var params Params
	err := params.UnmarshalBinary(buf[:4])
	if err != nil {
		return err
	}
	pk.ctx, err = NewContext(params)
	if err != nil {
		return err
	}
	pk.root = make([]byte, params.N)
	pk.pubSeed = make([]byte, params.N)
	copy(pk.root, buf[4:4+params.N])
	copy(pk.pubSeed, buf[4+params.N:4+params.N*2])
	pk.ph = pk.ctx.precomputeHashes(pk.pubSeed, nil)
	return nil
}

// Generates an XMSS[MT] public/private keypair
// and stores it at the given path on the filesystem.
//
// NOTE Do not forget to Close() the returned PrivateKey
func (ctx *Context) GenerateKeyPair(path string) (
	*PrivateKey, *PublicKey, Error) {
	pubSeed := make([]byte, ctx.p.N)
	skSeed := make([]byte, ctx.p.N)
	skPrf := make([]byte, ctx.p.N)
	_, err := rand.Read(pubSeed)
	if err != nil {
		return nil, nil, wrapErrorf(err, "crypto.rand.Read()")
	}
	_, err = rand.Read(skSeed)
	if err != nil {
		return nil, nil, wrapErrorf(err, "crypto.rand.Read()")
	}
	_, err = rand.Read(skPrf)
	if err != nil {
		return nil, nil, wrapErrorf(err, "crypto.rand.Read()")
	}
	return ctx.Derive(path, pubSeed, skSeed, skPrf)
}

// Derives an XMSS[MT] public/private keypair from the given seeds
// and stores it at the given path on the filesystem.
// NOTE Do not forget to Close() the returned PrivateKey
func (ctx *Context) Derive(path string, pubSeed, skSeed, skPrf []byte) (
	*PrivateKey, *PublicKey, Error) {
	ctr, err := OpenFSPrivateKeyContainer(path)
	if err != nil {
		return nil, nil, err
	}
	return ctx.DeriveInto(ctr, pubSeed, skSeed, skPrf)
}

// Derives an XMSS[MT] public/private keypair from the given seeds
// and stores it in the container.  pubSeed, skSeed and skPrf should be
// secret random ctx.p.N length byte slices.
func (ctx *Context) DeriveInto(ctr PrivateKeyContainer,
	pubSeed, skSeed, skPrf []byte) (*PrivateKey, *PublicKey, Error) {
	if len(pubSeed) != int(ctx.p.N) || len(skSeed) != int(ctx.p.N) || len(skPrf) != int(ctx.p.N) {
		return nil, nil, errorf(
			"skPrf, skSeed and pubSeed should have length %d", ctx.p.N)
	}

	concatSk := make([]byte, 3*ctx.p.N)
	copy(concatSk, skSeed)
	copy(concatSk[ctx.p.N:], skPrf)
	copy(concatSk[ctx.p.N*2:], pubSeed)
	err := ctr.Reset(concatSk, ctx.p)
	if err != nil {
		return nil, nil, err
	}

	pad := ctx.newScratchPad()
	sk, err := ctx.newPrivateKey(pad, pubSeed, skSeed, skPrf, 0, ctr)
	if err != nil {
		return nil, nil, err
	}

	// Precompute subtrees for the first few signatures.
	sk.getSubTree(pad, SubTreeAddress{Layer: 0, Tree: 0})

	return sk, sk.PublicKey(), nil
}

// Atomically runs BorrowExactly(amount) if BorrowedSeqNos()  <= treshHold.
func (sk *PrivateKey) BorrowExactlyIfBelow(amount, treshHold uint32) Error {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	if sk.borrowed <= treshHold {
		return sk.borrowExactly(amount)
	}
	return nil
}

// Ensures there are exactly the given number of signature sequence numbers are
// reserved for use by Sign().
//
// In a typical setup, each call to Sign() will write and fsync() the current
// signature sequence number to disk, such that signature sequence numbers
// aren't reused in a crash.  This does slow down Sign() quite a bit.
// To speed things up, we can reserve signatures; write the fact that we did
// this to disk and correct the signature sequence number on Close().
// The drawback is that with a crash or a missing Close(), we will loose the
// signatures that were reserved.
func (sk *PrivateKey) BorrowExactly(amount uint32) Error {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	return sk.borrowExactly(amount)
}

// Implementation of BorrowExactly.  Requires sk.mux lock.
func (sk *PrivateKey) borrowExactly(amount uint32) Error {
	if sk.borrowed == amount {
		return nil
	}

	if sk.borrowed > amount {
		err := sk.ctr.SetSeqNo(sk.seqNo + SignatureSeqNo(amount))
		if err != nil {
			return err
		}
		sk.borrowed = amount
		return nil
	}

	// sk.borrowed < amount
	_, err := sk.ctr.BorrowSeqNos(amount - sk.borrowed)
	if err != nil {
		return err
	}
	sk.borrowed = amount
	return nil
}

// Returns the number of signature sequence numbers borrowed from the container.
// See BorrowExactly() or PrivateKeyContainer.BorrowSeqNos()
func (sk *PrivateKey) BorrowedSeqNos() uint32 {
	return sk.borrowed
}

// Signs the given message.
func (sk *PrivateKey) Sign(msg []byte) (*Signature, Error) {
	return sk.SignFrom(bytes.NewReader(msg))
}

// Reads a message from the io.Reader and signs it.
func (sk *PrivateKey) SignFrom(msg io.Reader) (*Signature, Error) {
	pad := sk.ctx.newScratchPad()
	seqNo, err := sk.getSeqNo()
	if err != nil {
		return nil, err
	}
	defer sk.retireSeqNo(seqNo)

	// Compute the path of subtrees
	staPath, leafs := sk.ctx.subTreePathForSeqNo(seqNo)

	// Fetch (or generate) the subtrees
	mts := make([]*merkleTree, len(staPath))
	wotsSigs := make([][]byte, len(staPath))
	for i := len(staPath) - 1; i >= 0; i-- {
		var wotsSig []byte
		mts[i], wotsSig, err = sk.getSubTree(pad, staPath[i])
		if err != nil {
			return nil, err
		}
		wotsSigs[i] = make([]byte, len(wotsSig))
		copy(wotsSigs[i], wotsSig)
	}

	// Assemble the signature.
	sig := Signature{
		ctx:   sk.ctx,
		seqNo: seqNo,
		sigs:  make([]subTreeSig, len(staPath)),
		drv:   sk.ctx.prfUint64(pad, uint64(seqNo), sk.skPrf),
	}

	// The tail of the signature is probably cached, retrieve (or create) it
	for i := 1; i < len(staPath); i++ {
		sig.sigs[i] = subTreeSig{
			wotsSig:  wotsSigs[i-1],
			authPath: mts[i].AuthPath(leafs[i]),
		}
	}

	// Create the part of the signature unique to this message
	sig.sigs[0] = subTreeSig{
		authPath: mts[0].AuthPath(leafs[0]),
		wotsSig:  make([]byte, sk.ctx.wotsSigBytes),
	}

	mhash, err2 := sk.ctx.hashMessage(pad, msg, sig.drv, sk.root, uint64(seqNo))
	if err2 != nil {
		return nil, wrapErrorf(err2, "Failed to hash message")
	}
	otsAddr := staPath[0].address()
	otsAddr.setOTS(leafs[0])

	sk.ctx.wotsSignInto(
		pad,
		mhash,
		sk.ph,
		otsAddr,
		sig.sigs[0].wotsSig)

	return &sig, nil
}

// Close the underlying container
func (sk *PrivateKey) Close() Error {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	if sk.borrowed > 0 {
		sk.borrowed = 0
		err := sk.ctr.SetSeqNo(sk.seqNo)
		if err != nil {
			return err
		}
	}
	err := sk.ctr.Close()
	sk.cond.Broadcast()

	// There might be a background goroutine generating a subtree
	// when EnableSubTreePrecomputation() was called.  So wait for that.
	sk.wg.Wait()

	return err
}

// Return new context for the given XMSS[MT] oid (and nil if it's unknown).
func NewContextFromOid(mt bool, oid uint32) *Context {
	var lut map[uint32]regEntry
	if mt {
		lut = registryOidMTLut
	} else {
		lut = registryOidLut
	}
	entry, ok := lut[oid]
	if ok {
		ctx, _ := NewContext(entry.params)
		ctx.oid = oid
		ctx.mt = mt
		ctx.name = &entry.name
		return ctx
	} else {
		return nil
	}
}

// Return new context for the given XMSS[MT] algorithm name (and nil if the
// algorithm name is unknown).
func NewContextFromName(name string) *Context {
	entry, ok := registryNameLut[name]
	if !ok {
		return nil
	}
	ctx, _ := NewContext(entry.params)
	ctx.name = &name
	ctx.oid = entry.oid
	ctx.mt = entry.mt
	return ctx
}

// Creates a new context.
func NewContext(params Params) (ctx *Context, err Error) {
	ctx = new(Context)
	ctx.p = params
	ctx.mt = (ctx.p.D > 1)

	if ctx.p.N != 16 && ctx.p.N != 32 && ctx.p.N != 64 {
		return nil, errorf("Only N=16,32,64 are supported")
	}

	if params.D == 0 {
		return nil, errorf("D can't be zero")
	}

	if params.FullHeight%params.D != 0 {
		return nil, errorf("D does not divide FullHeight")
	}

	ctx.treeHeight = params.FullHeight / params.D

	if params.WotsW != 4 && params.WotsW != 16 && params.WotsW != 256 {
		return nil, errorf("Only WotsW=4,16,256 is supported")
	}

	if ctx.mt {
		ctx.indexBytes = (params.FullHeight + 7) / 8
	} else {
		ctx.indexBytes = 4
	}

	ctx.wotsLogW = params.WotsLogW()
	ctx.wotsLen1 = params.WotsLen1()
	ctx.wotsLen2 = params.WotsLen2()
	ctx.wotsLen = params.WotsLen()
	ctx.wotsSigBytes = params.WotsSignatureSize()
	ctx.sigBytes = (ctx.indexBytes + params.N +
		params.D*ctx.wotsSigBytes + params.FullHeight*params.N)
	ctx.pkBytes = 2 * params.N
	ctx.skBytes = ctx.indexBytes + 4*params.N

	return
}

func (sk *PrivateKey) Context() *Context {
	return sk.ctx
}

func (pk *PublicKey) Context() *Context {
	return pk.ctx
}

func (sig *Signature) Context() *Context {
	return sig.ctx
}

// Loads the private key from the given filesystem container.
//
// If the container wasn't properly closed, there might have been signatures
// lost.  The amount of returned in lostSigs.
//
// NOTE Takes ownership of ctr.  Do not forget to Close() the  PrivateKey.
func LoadPrivateKey(path string) (
	sk *PrivateKey, pk *PublicKey, lostSigs uint32, err Error) {
	ctr, err := OpenFSPrivateKeyContainer(path)
	if err != nil {
		return nil, nil, 0, err
	}
	return LoadPrivateKeyFrom(ctr)
}

// Loads the private key from the given private key container.
//
// If the container wasn't properly closed, there might have been signatures
// lost.  The amount of returned in lostSigs.
//
// NOTE Takes ownership of ctr.  Do not forget to Close() the  PrivateKey.
func LoadPrivateKeyFrom(ctr PrivateKeyContainer) (
	sk *PrivateKey, pk *PublicKey, lostSigs uint32, err Error) {
	// First check if the container is sane.
	params := ctr.Initialized()
	if params == nil {
		return nil, nil, 0, errorf("Container is not initialized")
	}
	if !ctr.CacheInitialized() {
		log.Logf("Cache is not initialized --- initializing...")
		err = ctr.ResetCache()
		if err != nil {
			return nil, nil, 0, wrapErrorf(err, "Failed to initialize cache")
		}
	}
	ctx, err := NewContext(*params)
	if err != nil {
		return nil, nil, 0, err
	}

	// Extract the private key and signature seqno
	skBuf, err := ctr.GetPrivateKey()
	if err != nil {
		return nil, nil, 0, err
	}
	var seqNo SignatureSeqNo
	seqNo, lostSigs, err = ctr.GetSeqNo()

	if err != nil {
		return nil, nil, 0, err
	}

	// Create the private and public key structures
	pad := ctx.newScratchPad()
	sk, err = ctx.newPrivateKey(
		pad,
		skBuf[params.N*2:params.N*3],
		skBuf[:params.N],
		skBuf[params.N:params.N*2],
		seqNo,
		ctr)
	if err != nil {
		return nil, nil, 0, err
	}
	pk = sk.PublicKey()
	return
}

// Returns the PublicKey for this PrivateKey.
func (sk *PrivateKey) PublicKey() *PublicKey {
	ret := PublicKey{
		ctx:     sk.ctx,
		pubSeed: sk.pubSeed,
		ph:      sk.ctx.precomputeHashes(sk.pubSeed, nil),
		root:    sk.root,
	}
	return &ret
}

// Returns the number of unretired signature sequence numbers.
//
// The PrivateKey keeps track of which signature sequence numbers might
// still be in use by a Sign() operation.  If a Sign() operation finishes
// it "retires" the signature seqno it used so that private key container
// can drop caches that are no longer relevant.
func (sk *PrivateKey) UnretiredSeqNos() uint32 {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	return uint32(sk.seqNo) - uint32(sk.leastSeqNoInUse) -
		uint32(sk.retiredSeqNos.Len())
}

// Returns the number of subtrees that are cached
func (sk *PrivateKey) CachedSubTrees() int {
	return len(sk.subTreeReady)
}

// You probably should not use this function
//
// Sets the signature sequence number.  Be very careful not to use the same
// signature sequence number twice.
func (sk *PrivateKey) DangerousSetSeqNo(seqNo SignatureSeqNo) {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	sk.seqNo = seqNo

	// We might forget to drop some cached subtrees, but that is probably
	// the least of our worries now.
	emptyHeap := uint32Heap([]uint32{})
	sk.retiredSeqNos = &emptyHeap
	heap.Init(sk.retiredSeqNos)
	sk.leastSeqNoInUse = seqNo
}

// Returns the signature sequence used next.
func (sk *PrivateKey) SeqNo() SignatureSeqNo {
	return sk.seqNo
}

// Enable subtree precomputation.
//
// By default, a subtree is computed when it's needed.  So with subtrees of
// height 10, every 1024th Sign() will be slow because a new subtree
// is generated.
//
// When subtree precomputation is enabled, the next subtree is already computed
// in a separate thread when the previous subtree is consumed.  This is useful
// when running a server which cannot tolerate a sudden spike in the duration
// of the Sign() function.
func (sk *PrivateKey) EnableSubTreePrecomputation() {
	sk.mux.Lock()
	sk.precomputeNextSubTree = true

	// ensure the next subtree is computed
	nextSta := SubTreeAddress{
		Layer: 0,
		Tree:  (uint64(sk.seqNo) >> sk.ctx.treeHeight) + 1,
	}
	_, nextTreeExists := sk.subTreeReady[nextSta]
	sk.mux.Unlock()

	if !nextTreeExists {
		sk.wg.Add(1)
		go func() {
			sk.getSubTree(sk.ctx.newScratchPad(), nextSta)
			sk.wg.Done()
		}()
	}
}
