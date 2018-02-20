// Go implementation of the XMSS[MT] post-quantum stateful hash-based signature
// scheme as described in the RFC draft
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/
package xmssmt

// Contains majority of the API

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
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
	ctx     *Context // context, which contains algorithm parameters.
	pubSeed []byte
	skSeed  []byte
	skPrf   []byte
	root    []byte         // root node
	seqNo   SignatureSeqNo // first unused signature
	// container that stores the secret key, signature sequence number
	// and caches the subtrees
	ctr PrivateKeyContainer
	// Number of signatures reserved from the container.
	// See PrivateKeyContainer.Borrow()
	borrowed uint32
	ph       precomputedHashes
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

// Check whether the sig is a valid signature of this public key
// for the given message.
func (pk *PublicKey) Verify(sig *Signature, msg []byte) (bool, Error) {
	pad := pk.ctx.newScratchPad()
	ph := pk.ctx.precomputeHashes(pk.pubSeed, nil)
	rxMsg := pk.ctx.hashMessage(pad, msg, sig.drv, pk.root, uint64(sig.seqNo))
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
		wotsPk := pk.ctx.wotsPkFromSig(pad, rxSig.wotsSig, rxMsg, ph, otsAddr)
		curHash := pk.ctx.lTree(pad, wotsPk, ph, lTreeAddr)

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

			pk.ctx.hInto(pad, left, right, ph, nodeAddr, curHash)
			offset >>= 1
		}

		rxMsg = curHash
	}

	if subtle.ConstantTimeCompare(rxMsg, pk.root) != 1 {
		return false, errorf("Invalid signature")
	}

	return true, nil
}

// Returns representation of signature as accepted by the reference
// implementation (without the message).
// Will never return an error.
func (sig *Signature) MarshalBinary() ([]byte, error) {
	ret := make([]byte, sig.ctx.sigBytes)
	encodeUint64Into(uint64(sig.seqNo), ret[:sig.ctx.indexBytes])
	copy(ret[sig.ctx.indexBytes:], sig.drv)
	stOff := sig.ctx.indexBytes + sig.ctx.p.N
	stLen := sig.ctx.wotsSigBytes + sig.ctx.p.N*sig.ctx.treeHeight
	for i, stSig := range sig.sigs {
		copy(ret[stOff+uint32(i)*stLen:], stSig.wotsSig)
		copy(ret[stOff+uint32(i)*stLen+sig.ctx.wotsSigBytes:], stSig.authPath)
	}
	return ret, nil
}

// Generates an XMSS[MT] public/private keypair from the given seeds
// and stores it at the given path on the filesystem.
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

	sk := PrivateKey{
		ctx:     ctx,
		pubSeed: pubSeed,
		ph:      ctx.precomputeHashes(pubSeed, skSeed),
		skSeed:  skSeed,
		seqNo:   0,
		skPrf:   skPrf,
		ctr:     ctr,
	}

	pad := ctx.newScratchPad()
	mt, _, err := sk.getSubTree(pad, SubTreeAddress{Layer: ctx.p.D - 1})
	if err != nil {
		return nil, nil, err
	}
	sk.root = mt.Root()

	pk := PublicKey{
		ctx:     ctx,
		pubSeed: pubSeed,
		ph:      ctx.precomputeHashes(pubSeed, nil),
		root:    sk.root,
	}

	return &sk, &pk, nil
}

// Signs the given message.
func (sk *PrivateKey) Sign(msg []byte) (*Signature, Error) {
	pad := sk.ctx.newScratchPad()
	seqNo, err := sk.getSeqNo()
	if err != nil {
		return nil, err
	}

	// Compute the path of subtrees
	staPath, leafs := sk.ctx.subTreePathForSeqNo(seqNo)

	// Fetch (or generate) the subtrees
	mts := make([]*merkleTree, len(staPath))
	wotsSigs := make([][]byte, len(staPath))
	for i := len(staPath) - 1; i >= 0; i-- {
		mts[i], wotsSigs[i], err = sk.getSubTree(pad, staPath[i])
		if err != nil {
			return nil, err
		}
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

	mhash := sk.ctx.hashMessage(pad, msg, sig.drv, sk.root, uint64(seqNo))
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
	if sk.borrowed > 0 {
		sk.seqNo -= SignatureSeqNo(sk.borrowed)
		sk.borrowed = 0
		err := sk.ctr.SetSeqNo(sk.seqNo)
		if err != nil {
			return err
		}
	}
	return sk.ctr.Close()
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
func NewContext(params Params) (ctx *Context, err error) {
	ctx = new(Context)
	ctx.p = params
	ctx.mt = (ctx.p.D > 1)

	if ctx.p.N != 32 && ctx.p.N != 64 {
		return nil, fmt.Errorf("Only N=32,64 are supported")
	}

	if params.FullHeight%params.D != 0 {
		return nil, fmt.Errorf("D does not divide FullHeight")
	}

	ctx.treeHeight = params.FullHeight / params.D

	if params.WotsW != 4 && params.WotsW != 16 && params.WotsW != 256 {
		return nil, fmt.Errorf("Only WotsW=4,16,256 is supported")
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
