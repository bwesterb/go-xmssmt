package xmssmt

import (
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

// Allocates memory for a merkle tree of n-byte strings of the given height.
func newMerkleTree(height, n uint32) merkleTree {
	return merkleTree{
		height: height,
		n:      n,
		buf:    make([]byte, ((1<<height)-1)*n),
	}
}

// Returns a slice to the given node.
func (mt *merkleTree) Node(height, index uint32) []byte {
	ptr := mt.n * ((1 << mt.height) - (1 << (mt.height - height)) + index)
	return mt.buf[ptr : ptr+mt.n]
}

// Compute a subtree by expanding the secret seed into WOTS+ keypairs
// and then hashing up.
func (ctx *Context) genSubTree(pad scratchPad, skSeed, pubSeed []byte,
	addr address) merkleTree {
	mt := newMerkleTree(ctx.treeHeight+1, ctx.p.N)
	ctx.genSubTreeInto(pad, skSeed, pubSeed, addr, mt)
	return mt
}

// Compute a subtree by expanding the secret seed into WOTS+ keypairs
// and then hashing up.
// mt should have height=ctx.treeHeight+1 and n=ctx.p.N.
func (ctx *Context) genSubTreeInto(pad scratchPad, skSeed, pubSeed []byte,
	addr address, mt merkleTree) {

	// TODO we compute the leafs in parallel.  Is it worth computing
	// the internal nodes in parallel?

	var otsAddr, lTreeAddr, nodeAddr address
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
				pad, skSeed, pubSeed, lTreeAddr, otsAddr))
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
								skSeed,
								pubSeed,
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
				pubSeed, nodeAddr, mt.Node(height, idx))
		}
	}
}

// Computes the leaf node associated to a WOTS+ public key.
// Note that the WOTS+ public key is destroyed.
func (ctx *Context) lTree(pad scratchPad, wotsPk, pubSeed []byte,
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
				pubSeed, addr,
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
func (ctx *Context) genLeaf(pad scratchPad, skSeed, pubSeed []byte,
	lTreeAddr, otsAddr address) []byte {
	seed := ctx.getWotsSeed(pad, skSeed, otsAddr)
	pk := ctx.wotsPkGen(pad, seed, pubSeed, otsAddr)
	return ctx.lTree(pad, pk, pubSeed, lTreeAddr)
}

// Derive the seed for the WOTS+ key pair at the given address
// from the secret key seed
func (ctx *Context) getWotsSeed(pad scratchPad, skSeed []byte,
	addr address) []byte {
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	return ctx.prfAddr(pad, addr, skSeed)
}
