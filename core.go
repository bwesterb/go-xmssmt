package xmssmt

// Computes the leaf node associated to a WOTS+ public key.
// Note that the WOTS+ public key is destroyed.
func (ctx *Context) lTree(wotsPk, pubSeed []byte, addr address) []byte {
	var height uint32 = 0
	var l uint32 = ctx.wotsLen
	for l > 1 {
		addr.setTreeHeight(height)
		parentNodes := l >> 1
		var i uint32
		for i = 0; i < parentNodes; i++ {
			addr.setTreeIndex(i)
			copy(wotsPk[i*ctx.p.N:(i+1)*ctx.p.N],
				ctx.h(wotsPk[2*i*ctx.p.N:(2*i+1)*ctx.p.N],
					wotsPk[(2*i+1)*ctx.p.N:(2*i+2)*ctx.p.N],
					pubSeed, addr))
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
func (ctx *Context) genLeaf(skSeed, pubSeed []byte,
	lTreeAddr, otsAddr address) []byte {
	seed := ctx.getWotsSeed(skSeed, otsAddr)
	pk := ctx.wotsPkGen(seed, pubSeed, otsAddr)
	return ctx.lTree(pk, pubSeed, lTreeAddr)
}

// Derive the seed for the WOTS+ key pair at the given address
// from the secret key seed
func (ctx *Context) getWotsSeed(skSeed []byte, addr address) []byte {
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	return ctx.prf(addr.toBytes(), skSeed)
}
