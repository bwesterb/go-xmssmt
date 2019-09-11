package xmssmt

// The core of XMSS and XMSSMT.

import (
	"github.com/cespare/xxhash"

	"container/heap"
	"encoding/binary"
	"runtime"
	"sync"
)

// Represents a height t merkle tree of n-byte strings T[i,j] as
//
//                    T[t-1,0]
//                 /
//               (...)        (...)
//            /           \            \
//         T[1,0]        T[1,1]  ...  T[1,2^(t-2)-1]
//        /     \       /      \          \
//     T[0,0] T[0,1] T[0,2]  T[0,3]  ...  T[0,2^(t-1)-1]
//
// as an (2^t-1)*n byte array.
type merkleTree struct {
	height uint32
	n      uint32
	buf    []byte
}

// A scratchpad used by a single goroutine to avoid memory allocation.
type scratchPad struct {
	buf []byte
	n   uint32

	hash hashScratchPad
}

// Allocates memory for a merkle tree of n-byte strings of the given height.
func newMerkleTree(height, n uint32) merkleTree {
	return merkleTreeFromBuf(make([]byte, ((1<<height)-1)*n), height, n)
}

// Returns a merkle tree wrapping the given buf
func merkleTreeFromBuf(buf []byte, height, n uint32) merkleTree {
	return merkleTree{
		height: height,
		n:      n,
		buf:    buf,
	}
}

// Returns the root of the tree
func (mt *merkleTree) Root() []byte {
	return mt.Node(mt.height-1, 0)
}

// Returns a slice to the given node.
func (mt *merkleTree) Node(height, index uint32) []byte {
	ptr := mt.n * ((1 << mt.height) - (1 << (mt.height - height)) + index)
	return mt.buf[ptr : ptr+mt.n]
}

// Returns the authentication path for the given leaf
func (mt *merkleTree) AuthPath(leaf uint32) []byte {
	ret := make([]byte, mt.n*mt.height)
	node := leaf
	var i uint32
	for i = 0; i < mt.height; i++ {
		// node ^ 1 is the offset of the sibling of node
		copy(ret[i*mt.n:], mt.Node(i, node^1))
		// node / 2 is the offset of the parent of node.
		node = node / 2
	}
	return ret
}

// Compute a subtree by expanding the secret seed into WOTS+ keypairs
// and then hashing up.
func (ctx *Context) genSubTree(pad scratchPad, skSeed, pubSeed []byte,
	sta SubTreeAddress) merkleTree {
	mt := newMerkleTree(ctx.treeHeight+1, ctx.p.N)
	ctx.genSubTreeInto(pad, skSeed, ctx.precomputeHashes(pubSeed, skSeed),
		sta, mt)
	return mt
}

// Compute a subtree by expanding the secret seed into WOTS+ keypairs
// and then hashing up.
// mt should have height=ctx.treeHeight+1 and n=ctx.p.N.
func (ctx *Context) genSubTreeInto(pad scratchPad, skSeed []byte,
	ph precomputedHashes, sta SubTreeAddress, mt merkleTree) {

	// TODO we compute the leafs in parallel.  Is it worth computing
	// the internal nodes in parallel?
	log.Logf("Generating subtree %v ...", sta)

	var otsAddr, lTreeAddr, nodeAddr address
	addr := sta.address()
	otsAddr.setSubTreeFrom(addr)
	otsAddr.setType(ADDR_TYPE_OTS)
	lTreeAddr.setSubTreeFrom(addr)
	lTreeAddr.setType(ADDR_TYPE_LTREE)
	nodeAddr.setSubTreeFrom(addr)
	nodeAddr.setType(ADDR_TYPE_HASHTREE)

	// First, compute the leafs
	var idx uint32

	if ctx.Threads == 1 {
		for idx = 0; idx < (1 << ctx.treeHeight); idx++ {
			lTreeAddr.setLTree(idx)
			otsAddr.setOTS(idx)
			copy(mt.Node(0, idx), ctx.genLeaf(
				pad, ph, lTreeAddr, otsAddr))
		}
	} else {
		// The code in this branch does exactly the same as in
		// the branch above, but then in parallel.
		wg := &sync.WaitGroup{}
		mux := &sync.Mutex{}
		var perBatch uint32 = 32
		threads := ctx.Threads
		if threads == 0 {
			threads = runtime.NumCPU()
		}
		wg.Add(threads)
		for i := 0; i < threads; i++ {
			go func(lTreeAddr, otsAddr address) {
				pad := ctx.newScratchPad()
				var ourIdx uint32
				for {
					mux.Lock()
					ourIdx = idx
					idx += perBatch
					mux.Unlock()
					if ourIdx >= 1<<ctx.treeHeight {
						break
					}
					ourEnd := ourIdx + perBatch
					if ourEnd > 1<<ctx.treeHeight {
						ourEnd = 1 << ctx.treeHeight
					}
					for ; ourIdx < ourEnd; ourIdx++ {
						lTreeAddr.setLTree(ourIdx)
						otsAddr.setOTS(ourIdx)
						copy(mt.Node(0, ourIdx),
							ctx.genLeaf(
								pad,
								ph,
								lTreeAddr,
								otsAddr))
					}
				}
				wg.Done()
			}(lTreeAddr, otsAddr)
		}

		wg.Wait() // wait for all workers to finish
	}

	// Next, compute the internal nodes and root
	var height uint32
	for height = 1; height <= ctx.treeHeight; height++ {
		nodeAddr.setTreeHeight(height - 1)
		for idx = 0; idx < (1 << (ctx.treeHeight - height)); idx++ {
			nodeAddr.setTreeIndex(idx)
			ctx.hInto(pad, mt.Node(height-1, 2*idx),
				mt.Node(height-1, 2*idx+1),
				ph, nodeAddr, mt.Node(height, idx))
		}
	}
}

// Computes the leaf node associated to a WOTS+ public key.
// Note that the WOTS+ public key is destroyed.
func (ctx *Context) lTree(pad scratchPad, wotsPk []byte, ph precomputedHashes,
	addr address) []byte {
	var height uint32 = 0
	var l uint32 = ctx.wotsLen
	for l > 1 {
		addr.setTreeHeight(height)
		parentNodes := l >> 1
		var i uint32
		for i = 0; i < parentNodes; i++ {
			addr.setTreeIndex(i)
			ctx.hInto(pad, wotsPk[2*i*ctx.p.N:(2*i+1)*ctx.p.N],
				wotsPk[(2*i+1)*ctx.p.N:(2*i+2)*ctx.p.N],
				ph, addr,
				wotsPk[i*ctx.p.N:(i+1)*ctx.p.N])
		}
		if l&1 == 1 {
			copy(wotsPk[(l>>1)*ctx.p.N:((l>>1)+1)*ctx.p.N],
				wotsPk[(l-1)*ctx.p.N:l*ctx.p.N])
			l = (l >> 1) + 1
		} else {
			l = l >> 1
		}
		height++
	}
	ret := make([]byte, ctx.p.N)
	copy(ret, wotsPk[:ctx.p.N])
	return ret
}

// Generate the leaf at the given address by first computing the
// WOTS+ key pair and then using lTree.
func (ctx *Context) genLeaf(pad scratchPad, ph precomputedHashes,
	lTreeAddr, otsAddr address) []byte {
	pk := pad.wotsBuf()
	ctx.wotsPkGenInto(pad, ph, otsAddr, pk)
	return ctx.lTree(pad, pk, ph, lTreeAddr)
}

// Derive the seed for the WOTS+ key pair at the given address
// from the secret key seed
func (ctx *Context) getWotsSeed(pad scratchPad, ph precomputedHashes,
	addr address) []byte {
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	ret := make([]byte, ctx.p.N)
	ph.prfAddrSkSeedInto(pad, addr, ret)
	return ret
}

// Returns the path of subtrees associated to signature sequence number.
// Also, for each of the subtrees, returns the leaf in the subtree
// to which the subtree (or signature) below it corresponds.
func (ctx *Context) subTreePathForSeqNo(seqNo SignatureSeqNo) (
	path []SubTreeAddress, leafs []uint32) {
	path = make([]SubTreeAddress, ctx.p.D)
	leafs = make([]uint32, ctx.p.D)
	var layer uint32
	for layer = 0; layer < ctx.p.D; layer++ {
		path[layer] = SubTreeAddress{
			Layer: layer,
			Tree:  (uint64(seqNo) >> ((layer + 1) * ctx.treeHeight)),
		}
		leafs[layer] = uint32((uint64(seqNo) >> (layer * ctx.treeHeight)) &
			((1 << ctx.treeHeight) - 1))
	}
	return
}

// Returns the given subtree, either by loading it from the cache,
// or generating it.
func (sk *PrivateKey) getSubTree(pad scratchPad, sta SubTreeAddress) (
	mt *merkleTree, wotsSig []byte, err Error) {
	alreadyDone := false
	justCheckTheChecksum := false
	isRoot := (sta.Layer == sk.ctx.p.D-1)
	parentSta := SubTreeAddress{
		Layer: sta.Layer + 1,
		Tree:  sta.Tree >> sk.ctx.treeHeight,
	}
	var parentTreeReady bool
	var exists bool
	var buf []byte

	sk.mux.Lock()
	for {
		buf, exists, err = sk.ctr.GetSubTree(sta)
		subTreeReady, exists2 := sk.subTreeReady[sta]
		if err != nil {
			sk.mux.Unlock()
			return
		}

		if exists2 {
			if !exists {
				panic("This should not be possible")
			}
			if subTreeReady {
				alreadyDone = true
				justCheckTheChecksum = !sk.subTreeChecked[sta]
				break
			}

			// The sub tree exists, but is being filled by another thread.
			log.Logf("Subtree %v seems to be generated by another thread.  Waiting ...", sta)
			sk.cond.Wait()
			continue
		}

		if exists {
			panic("This should not be possible")
		}

		// The sub tree does not yet exist.  We will have to fill it.
		sk.subTreeReady[sta] = false
		sk.subTreeChecked[sta] = true
		break
	}

	if !isRoot && !alreadyDone {
		parentTreeReady = sk.subTreeReady[parentSta] &&
			sk.subTreeChecked[parentSta]
	}
	sk.mux.Unlock()

	treeBuf := buf[:sk.ctx.p.BareSubTreeSize()]
	mtDeref := merkleTreeFromBuf(treeBuf, sk.ctx.treeHeight+1, sk.ctx.p.N)
	mt = &mtDeref
	wotsSig = buf[sk.ctx.p.BareSubTreeSize() : sk.ctx.p.BareSubTreeSize()+int(sk.ctx.p.WotsSignatureSize())]

	if alreadyDone {
		if !justCheckTheChecksum {
			return
		}

		log.Logf("Checking integrity of subtree %v ...", sta)

		// The tree seems ready, but we just need to check whether it
		// hasn't been corrupted.
		storedCheckSum := binary.BigEndian.Uint64(buf[len(buf)-8:])

		sk.mux.Lock()
		intact := storedCheckSum == xxhash.Sum64(buf[:len(buf)-8])
		if intact {
			sk.subTreeChecked[sta] = true
			sk.mux.Unlock()
			return
		}

		// The tree seems corrupted.  Another thread might have reached the
		// same conclusion, so we should check whether another thread is already
		// correcting the problem for us.
		if !sk.subTreeReady[sta] {
			// There is another thread correcting the issue.  Lets wait
			// for it.
			log.Logf("Subtree %v is corrupted.  Another thread seems to be "+
				"correcting the problem.  Waiting ...", sta)
			for {
				sk.cond.Wait()
				if sk.subTreeReady[sta] {
					log.Logf(" ... the subtree has been corrected.")
					sk.mux.Unlock()
					return
				}

				log.Logf(" ... not corrected, yet.")
			}
		}

		// Mark the subtree not-ready
		log.Logf("Subtree %v is corrupted.  Correcting it ...", sta)
		sk.subTreeReady[sta] = false
		sk.mux.Unlock()
	}

	sk.ctx.genSubTreeInto(pad, sk.skSeed, sk.ph, sta, mtDeref)

	// We're not done yet.  We need to generate the WOTS+ signature
	// (and checksum) and for this, possibly, a few other sub trees.

	// Called when generating the other subtrees fails.
	abort := func() {
		sk.mux.Lock()
		delete(sk.subTreeReady, sta)
		delete(sk.subTreeChecked, sta)
		sk.cond.Broadcast()
		sk.mux.Unlock()
	}

	// Called when we were sucessful in the end.
	succeed := func() {
		binary.BigEndian.PutUint64(buf[len(buf)-8:],
			xxhash.Sum64(buf[:len(buf)-8]))

		sk.mux.Lock()
		sk.subTreeReady[sta] = true
		sk.subTreeChecked[sta] = true
		sk.cond.Broadcast()
		sk.mux.Unlock()
	}

	// Generate WOTS+ signature --- at least, if we're not the root.
	if isRoot {
		succeed()
		return
	}

	// If the parent is not cached (or checked), we'll need to cache it
	// (or check it).  To this end we will cache all ancestors.
	// It is strictly speaking unnecessary to generate the ancestors to
	// sign the root of this tree: we will do it anyway, for otherwise
	// we cannot generate the authentication path, which we'll need
	// anyway later on.
	// NOTE as we're not holding the lock, the parent tree might have
	// been generated in the meantime, but this won't hurt.
	if !parentTreeReady {
		for layer := sk.ctx.p.D - 1; layer > sta.Layer; layer-- {
			ancSta := SubTreeAddress{
				Layer: layer,
				Tree:  sta.Tree >> (sk.ctx.treeHeight * (layer - sta.Layer)),
			}
			_, _, err = sk.getSubTree(pad, ancSta)

			if err != nil {
				abort()
				return nil, nil, err
			}
		}
	}

	// Get the parent sub tree
	_, _, err = sk.getSubTree(pad, parentSta)
	if err != nil {
		abort()
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
	succeed()
	return
}

// Gets the next free sequence number
func (sk *PrivateKey) getSeqNo() (SignatureSeqNo, Error) {
	sk.mux.Lock()
	defer sk.mux.Unlock()

	if uint64(sk.seqNo) == sk.ctx.p.MaxSignatureSeqNo() {
		return 0, errorf("No unused signatures left")
	}

	if sk.borrowed > 0 {
		// If we have some borrowed sequence numbers, we can simply use one
		// of them.
		sk.borrowed -= 1
	} else {
		// If we didn't borrow sequence numbers, then we have to increment
		// the sequence number in the container before we continue.
		err := sk.ctr.SetSeqNo(sk.seqNo + 1)
		if err != nil {
			return 0, err
		}
	}

	sk.seqNo += 1

	// Check if we need to precompute a subtree
	if sk.precomputeNextSubTree &&
		(uint64(sk.seqNo)&((1<<sk.ctx.treeHeight)-1) == 0) {
		sk.wg.Add(1)
		go func(sta SubTreeAddress) {
			log.Logf("Precomputing subtree %v", sta)
			sk.getSubTree(sk.ctx.newScratchPad(), sta)
			log.Logf("Finished precomputing subtree %v", sta)
			sk.wg.Done()
		}(SubTreeAddress{
			Layer: 0,
			Tree:  (uint64(sk.seqNo) >> sk.ctx.treeHeight) + 1,
		})
	}

	return sk.seqNo - 1, nil
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

func (ctx *Context) newPrivateKey(pad scratchPad, pubSeed, skSeed, skPrf []byte,
	seqNo SignatureSeqNo, ctr PrivateKeyContainer) (
	*PrivateKey, Error) {

	if uint64(seqNo) > ctx.p.MaxSignatureSeqNo() {
		return nil, errorf(
			"Signature sequence number is too large: %d > %d",
			seqNo, ctx.p.MaxSignatureSeqNo())
	}
	ret := PrivateKey{
		ctx:     ctx,
		skSeed:  skSeed,
		pubSeed: pubSeed,
		skPrf:   skPrf,
		seqNo:   seqNo,
		ctr:     ctr,
		ph:      ctx.precomputeHashes(pubSeed, skSeed),
	}

	// Initialize helper data structures
	ret.cond = sync.NewCond(&ret.mux)
	ret.subTreeReady = make(map[SubTreeAddress]bool)
	ret.subTreeChecked = make(map[SubTreeAddress]bool)
	emptyHeap := uint32Heap([]uint32{})
	ret.retiredSeqNos = &emptyHeap
	heap.Init(ret.retiredSeqNos)
	ret.leastSeqNoInUse = seqNo

	// Register the cached subtrees
	stas, err := ctr.ListSubTrees()
	if err != nil {
		return nil, err
	}
	for _, sta := range stas {
		ret.subTreeReady[sta] = true
		ret.subTreeChecked[sta] = false
	}

	// Compute (or fetch from cache) the root
	mt, _, err := ret.getSubTree(pad, SubTreeAddress{Layer: ctx.p.D - 1})
	if err != nil {
		return nil, err
	}
	ret.root = make([]byte, ctx.p.N)
	copy(ret.root, mt.Root())

	return &ret, nil
}

// Retires the given signature sequence number.
//
// See PrivateKey.UnretiredSeqNos()
func (sk *PrivateKey) retireSeqNo(seqNo SignatureSeqNo) {
	sk.mux.Lock()
	defer sk.mux.Unlock()
	if sk.leastSeqNoInUse != seqNo {
		heap.Push(sk.retiredSeqNos, uint32(seqNo))
		return
	}

	// We have sk.leastSeqNoInUse == seqNo.  Check if we can increment
	// the leastSeqNoInUse counter by using seqNos in retiredSeqNos.
	sk.incLeastSeqNoInUse()
	for sk.retiredSeqNos.Len() != 0 &&
		sk.retiredSeqNos.Min() == uint32(sk.leastSeqNoInUse) {
		heap.Pop(sk.retiredSeqNos)
		sk.incLeastSeqNoInUse()
	}
}

// Increments leastSeqNoInUse and drops cached subtrees which have become
// irrelevant.
//
// NOTE Assumes a lock on sk.mux.
func (sk *PrivateKey) incLeastSeqNoInUse() {
	sk.leastSeqNoInUse += 1

	// Check if we can drop cached subtrees
	stas, leafs := sk.ctx.subTreePathForSeqNo(sk.leastSeqNoInUse)
	for i, sta := range stas {
		if leafs[i] != 0 {
			break
		}

		staToDrop := SubTreeAddress{
			Layer: sta.Layer,
			Tree:  sta.Tree - 1,
		}
		log.Logf("Dropping cached subtree %v ...", staToDrop)
		if err := sk.ctr.DropSubTree(staToDrop); err != nil {
			log.Logf("  failed to drop subtree %v: %v", staToDrop, err)
		} else {
			delete(sk.subTreeReady, staToDrop)
			delete(sk.subTreeChecked, staToDrop)
		}
	}
}
