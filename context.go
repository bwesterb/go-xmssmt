package xmssmt

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"reflect"
)

type HashFunc uint8

const (
	SHA2  HashFunc = 0
	SHAKE          = 1
)

// Parameters of an XMSS[MT] instance
type Params struct {
	Func       HashFunc // which has function to use
	N          uint32   // security parameter: influences length of hashes
	FullHeight uint32   // full height of tree
	D          uint32   // number of subtrees; 1 for XMSS, >1 for XMSSMT

	// WOTS+ Winternitz parameter.  Only 8, 16 and 256 are supported.
	WotsW uint16
}

// XMSS[MT] instance.
// Create one using NewContextFromName, NewContextFromOid or NewContext.
type Context struct {
	// Number of worker goroutines ("threads") to use for expensive operations.
	// Will guess an appropriate number if set to 0.
	Threads int

	p            Params  // parameters.
	mt           bool    // true for XMSSMT; false for XMSS
	oid          uint32  // OID of this configuration, if it has any
	wotsLogW     uint8   // logarithm of the Winternitz parameter
	wotsLen1     uint32  // WOTS+ chains for message
	wotsLen2     uint32  // WOTS+ chains for checksum
	wotsLen      uint32  // total number of WOTS+ chains
	wotsSigBytes uint32  // length of WOTS+ signature
	treeHeight   uint32  // height of a subtree
	indexBytes   uint32  // size of an index
	sigBytes     uint32  // size of signature
	pkBytes      uint32  // size of public key
	skBytes      uint32  // size of secret key
	name         *string // name of algorithm
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

type errorImpl struct {
	msg    string
	locked bool
	inner  error
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

func (err *errorImpl) Locked() bool { return err.locked }
func (err *errorImpl) Inner() error { return err.inner }

func (err *errorImpl) Error() string {
	if err.inner != nil {
		return fmt.Sprintf("%s: %s", err.msg, err.inner.Error())
	}
	return err.msg
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

// Returns the given subtree, either by loading it from the cache,
// or generating it.
func (sk *PrivateKey) getSubTree(pad scratchPad, sta SubTreeAddress) (
	mt *merkleTree, wotsSig []byte, err Error) {
	buf, exists, err := sk.ctr.GetSubTree(sta)
	if err != nil {
		return
	}

	treeBuf := buf[:sk.ctx.p.BareSubTreeSize()]
	mtDeref := merkleTreeFromBuf(treeBuf, sk.ctx.treeHeight+1, sk.ctx.p.N)
	mt = &mtDeref
	wotsSig = buf[sk.ctx.p.BareSubTreeSize():]

	if exists {
		return
	}

	sk.ctx.genSubTreeInto(pad, sk.skSeed, sk.ph, sta.address(), mtDeref)

	// Generate WOTS+ signature --- at least, if we're not the root.
	if sta.Layer == sk.ctx.p.D-1 {
		return
	}

	// Compute address of parent
	parentSta := SubTreeAddress{
		Layer: sta.Layer + 1,
		Tree:  sta.Tree >> sk.ctx.treeHeight,
	}

	// If the parent is not cached, we'll need to cache it.  To this end
	// we will cache all ancestors.
	// It is strictly speaking unnecessary to generate the ancestors to
	// sign the root of this tree: we will do it anyway, for otherwise
	// we cannot generate the authentication path, which we'll need
	// anyway later on.
	if !sk.ctr.HasSubTree(parentSta) {
		for layer := sk.ctx.p.D; layer > sta.Layer; layer-- {
			ancSta := SubTreeAddress{
				Layer: layer,
				Tree:  sta.Tree >> (sk.ctx.treeHeight * (layer - sta.Layer)),
			}
			if !sk.ctr.HasSubTree(ancSta) {
				_, _, err = sk.getSubTree(pad, ancSta)

				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	// Get the parent sub tree
	_, _, err = sk.getSubTree(pad, parentSta)
	if err != nil {
		return nil, nil, err
	}

	// Sign our root
	otsAddr := parentSta.address()
	leafIdx := uint32(sta.Tree & ((1 << sk.ctx.treeHeight) - 1))
	otsAddr.setOTS(leafIdx)
	sk.ctx.wotsSignInto(
		pad,
		mt.Root(),
		sk.ph,
		otsAddr,
		wotsSig)
	return
}

// Gets the next free sequence number
func (sk *PrivateKey) getSeqNo() (SignatureSeqNo, Error) {
	if sk.borrowed > 0 {
		// If we have some borrowed sequence numbers, we can simply use one
		// of them.
		sk.borrowed -= 1
		sk.seqNo += 1
		return sk.seqNo - 1, nil
	}

	// If we didn't borrow sequence numbers, then we have to increment
	// the sequence number in the container before we continue.
	err := sk.ctr.SetSeqNo(sk.seqNo + 1)
	if err != nil {
		return 0, err
	}
	sk.seqNo += 1
	return sk.seqNo - 1, nil
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

// Returns the size of the subtrees for this parameter.
func (params *Params) BareSubTreeSize() int {
	height := (params.FullHeight / params.D) + 1
	return int(((1 << height) - 1) * params.N)
}

// Returns the size of the cached subtrees for this parameter.
func (params *Params) CachedSubTreeSize() int {
	// A cached subtree contains the merkle subtree and possibly
	// a WOTS+ signature of the substree above it.
	return params.BareSubTreeSize() + int(params.WotsSignatureSize())
}

// Size of the private key as stored by PrivateKeyContainer.
// NOTE this is not equal to the privateKeySize of the spec, which includes
//      the signature sequence number, OID and root
func (params *Params) PrivateKeySize() int {
	return int(params.N * 3) // skSeed + skPrf + pubSeed
}

// Formats a new Error
func errorf(format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...)}
}

// Formats a new Error that wraps another
func wrapErrorf(err error, format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...), inner: err}
}

// Entry in the registry of algorithms
type regEntry struct {
	name   string // name, eg. XMSSMT-SHA2_20/2_256
	mt     bool   // whether its XMSSMT (instead of XMSS)
	oid    uint32 // oid of the algorithm
	params Params // parameters of the algorithm
}

// Returns paramters for the named XMSS[MT] instance (and nil if there is no
// such algorithm).
func ParamsFromName(name string) *Params {
	entry, ok := registryNameLut[name]
	if ok {
		return &entry.params
	} else {
		return nil
	}
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

	if params.FullHeight%params.D != 0 {
		return nil, fmt.Errorf("D does not divide FullHeight")
	}

	ctx.treeHeight = params.FullHeight / params.D

	if params.WotsW != 16 {
		return nil, fmt.Errorf("Only WotsW=16 is supported at the moment")
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

// Returns the 2log of the Winternitz parameter
func (params *Params) WotsLogW() uint8 {
	return 4
}

// Returns the number of  main WOTS+ chains
func (params *Params) WotsLen1() uint32 {
	return 8 * params.N / uint32(params.WotsLogW())
}

// Returns the number of WOTS+ checksum chains
func (params *Params) WotsLen2() uint32 {
	return 3
}

// Returns the total number of WOTS+ chains
func (params *Params) WotsLen() uint32 {
	return params.WotsLen1() + params.WotsLen2()
}

// Returns the size of a WOTS+ signature
func (params *Params) WotsSignatureSize() uint32 {
	return params.WotsLen() * params.N
}

// Returns the maximum signature sequence number
func (params *Params) MaxSignatureSeqNo() uint64 {
	return (1 << params.FullHeight) - 1
}

// Returns the name of the XMSSMT instance and an empty string if it has
// no name.
func (ctx *Context) Name() string {
	if ctx.name == nil {
		for _, entry := range registry {
			if reflect.DeepEqual(entry.params, ctx.p) {
				name2 := entry.name
				ctx.name = &name2
			}
		}
	}
	if ctx.name != nil {
		return *ctx.name
	}
	return ""
}

// Returns the Oid of the XMSSMT instance and 0 if it has no Oid.
func (ctx *Context) Oid() uint32 {
	return ctx.oid
}

// Returns whether this is an XMSSMT instance (as opposed to XMSS)
func (ctx *Context) MT() bool {
	return ctx.mt
}

// Get parameters of an XMSS[MT] instance
func (ctx *Context) Params() Params {
	return ctx.p
}

// Returns the size of signatures of this XMSS[MT] instance
func (ctx *Context) SignatureSize() uint32 {
	return ctx.sigBytes
}

// List all named XMSS[MT] instances
func ListNames() (names []string) {
	names = make([]string, len(registry))
	for i, entry := range registry {
		names[i] = entry.name
	}
	return
}

// Registry of named XMSS[MT] algorithms
var registry []regEntry = []regEntry{
	{"XMSSMT-SHA2_20/2_256", true, 0x00000001, Params{SHA2, 32, 20, 2, 16}},
	{"XMSSMT-SHA2_20/4_256", true, 0x00000002, Params{SHA2, 32, 20, 4, 16}},
	{"XMSSMT-SHA2_40/2_256", true, 0x00000003, Params{SHA2, 32, 40, 2, 16}},
	{"XMSSMT-SHA2_40/4_256", true, 0x00000004, Params{SHA2, 32, 40, 4, 16}},
	{"XMSSMT-SHA2_40/8_256", true, 0x00000005, Params{SHA2, 32, 40, 8, 16}},
	{"XMSSMT-SHA2_60/3_256", true, 0x00000006, Params{SHA2, 32, 60, 3, 16}},
	{"XMSSMT-SHA2_60/6_256", true, 0x00000007, Params{SHA2, 32, 60, 6, 16}},
	{"XMSSMT-SHA2_60/12_256", true, 0x00000008, Params{SHA2, 32, 60, 12, 16}},

	{"XMSSMT-SHA2_20/2_512", true, 0x00000009, Params{SHA2, 64, 20, 2, 16}},
	{"XMSSMT-SHA2_20/4_512", true, 0x0000000a, Params{SHA2, 64, 20, 4, 16}},
	{"XMSSMT-SHA2_40/2_512", true, 0x0000000b, Params{SHA2, 64, 40, 2, 16}},
	{"XMSSMT-SHA2_40/4_512", true, 0x0000000c, Params{SHA2, 64, 40, 4, 16}},
	{"XMSSMT-SHA2_40/8_512", true, 0x0000000d, Params{SHA2, 64, 40, 8, 16}},
	{"XMSSMT-SHA2_60/3_512", true, 0x0000000e, Params{SHA2, 64, 60, 3, 16}},
	{"XMSSMT-SHA2_60/6_512", true, 0x0000000f, Params{SHA2, 64, 60, 6, 16}},
	{"XMSSMT-SHA2_60/12_512", true, 0x00000010, Params{SHA2, 64, 60, 12, 16}},

	{"XMSSMT-SHAKE_20/2_256", true, 0x00000011, Params{SHAKE, 32, 20, 2, 16}},
	{"XMSSMT-SHAKE_20/4_256", true, 0x00000012, Params{SHAKE, 32, 20, 4, 16}},
	{"XMSSMT-SHAKE_40/2_256", true, 0x00000013, Params{SHAKE, 32, 40, 2, 16}},
	{"XMSSMT-SHAKE_40/4_256", true, 0x00000014, Params{SHAKE, 32, 40, 4, 16}},
	{"XMSSMT-SHAKE_40/8_256", true, 0x00000015, Params{SHAKE, 32, 40, 8, 16}},
	{"XMSSMT-SHAKE_60/3_256", true, 0x00000016, Params{SHAKE, 32, 60, 3, 16}},
	{"XMSSMT-SHAKE_60/6_256", true, 0x00000017, Params{SHAKE, 32, 60, 6, 16}},
	{"XMSSMT-SHAKE_60/12_256", true, 0x00000018, Params{SHAKE, 32, 60, 12, 16}},

	{"XMSSMT-SHAKE_20/2_512", true, 0x00000019, Params{SHAKE, 64, 20, 2, 16}},
	{"XMSSMT-SHAKE_20/4_512", true, 0x0000001a, Params{SHAKE, 64, 20, 4, 16}},
	{"XMSSMT-SHAKE_40/2_512", true, 0x0000001b, Params{SHAKE, 64, 40, 2, 16}},
	{"XMSSMT-SHAKE_40/4_512", true, 0x0000001c, Params{SHAKE, 64, 40, 4, 16}},
	{"XMSSMT-SHAKE_40/8_512", true, 0x0000001d, Params{SHAKE, 64, 40, 8, 16}},
	{"XMSSMT-SHAKE_60/3_512", true, 0x0000001e, Params{SHAKE, 64, 60, 3, 16}},
	{"XMSSMT-SHAKE_60/6_512", true, 0x0000001f, Params{SHAKE, 64, 60, 6, 16}},
	{"XMSSMT-SHAKE_60/12_512", true, 0x00000020, Params{SHAKE, 64, 60, 12, 16}},

	{"XMSS-SHA2_10_256", false, 0x00000001, Params{SHA2, 32, 10, 1, 16}},
	{"XMSS-SHA2_16_256", false, 0x00000002, Params{SHA2, 32, 16, 1, 16}},
	{"XMSS-SHA2_20_256", false, 0x00000003, Params{SHA2, 32, 20, 1, 16}},
	{"XMSS-SHA2_10_512", false, 0x00000004, Params{SHA2, 64, 10, 1, 16}},
	{"XMSS-SHA2_16_512", false, 0x00000005, Params{SHA2, 64, 16, 1, 16}},
	{"XMSS-SHA2_20_512", false, 0x00000006, Params{SHA2, 64, 20, 1, 16}},

	{"XMSS-SHAKE_10_256", false, 0x00000007, Params{SHAKE, 32, 10, 1, 16}},
	{"XMSS-SHAKE_16_256", false, 0x00000008, Params{SHAKE, 32, 16, 1, 16}},
	{"XMSS-SHAKE_20_256", false, 0x00000009, Params{SHAKE, 32, 20, 1, 16}},
	{"XMSS-SHAKE_10_512", false, 0x0000000a, Params{SHAKE, 64, 10, 1, 16}},
	{"XMSS-SHAKE_16_512", false, 0x0000000b, Params{SHAKE, 64, 16, 1, 16}},
	{"XMSS-SHAKE_20_512", false, 0x0000000c, Params{SHAKE, 64, 20, 1, 16}},
}

var registryNameLut map[string]regEntry
var registryOidLut map[uint32]regEntry
var registryOidMTLut map[uint32]regEntry

// Initializes algorithm lookup tables.
func init() {
	log = &dummyLogger{}
	registryNameLut = make(map[string]regEntry)
	registryOidLut = make(map[uint32]regEntry)
	registryOidMTLut = make(map[uint32]regEntry)
	for _, entry := range registry {
		registryNameLut[entry.name] = entry
		if entry.mt {
			registryOidMTLut[entry.oid] = entry
		} else {
			registryOidLut[entry.oid] = entry
		}
	}
}

// A scratchpad used by a single goroutine to avoid memory allocation.
type scratchPad struct {
	buf []byte
	n   uint32

	hash hashScratchPad
}

func (pad scratchPad) fBuf() []byte {
	return pad.buf[:3*pad.n]
}

func (pad scratchPad) hBuf() []byte {
	return pad.buf[3*pad.n : 7*pad.n]
}

func (pad scratchPad) prfBuf() []byte {
	return pad.buf[7*pad.n : 9*pad.n+32]
}

func (pad scratchPad) prfAddrBuf() []byte {
	return pad.buf[9*pad.n+32 : 9*pad.n+64]
}

func (pad scratchPad) wotsSkSeedBuf() []byte {
	return pad.buf[9*pad.n+64 : 10*pad.n+64]
}

func (pad scratchPad) wotsBuf() []byte {
	return pad.buf[10*pad.n+64:]
}

func (ctx *Context) newScratchPad() scratchPad {
	n := ctx.p.N
	pad := scratchPad{
		buf:  make([]byte, 10*n+64+ctx.p.N*ctx.wotsLen),
		n:    n,
		hash: ctx.newHashScratchPad(),
	}
	return pad
}

type Logger interface {
	Logf(format string, a ...interface{})
}

type dummyLogger struct{}

func (logger *dummyLogger) Logf(format string, a ...interface{}) {}

var log Logger

// Enables logging
func SetLogger(logger Logger) {
	log = logger
}
