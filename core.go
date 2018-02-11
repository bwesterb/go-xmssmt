package xmssmt

// Computes the leaf node associated to a WOTS+ public key.
// Note that the WOTS+ public key is destroyed.
func (params *Params) lTree(wotsPk, pubSeed []byte, addr address) []byte {
	var height uint32 = 0
	var l uint32 = params.WotsLen
	for l > 1 {
		addr.setTreeHeight(height)
		parentNodes := l >> 1
		var i uint32
		for i = 0; i < parentNodes; i++ {
			addr.setTreeIndex(i)
			copy(wotsPk[i*params.N:(i+1)*params.N],
				params.h(wotsPk[2*i*params.N:(2*i+1)*params.N],
					wotsPk[(2*i+1)*params.N:(2*i+2)*params.N],
					pubSeed, addr))
		}
		if l&1 == 1 {
			copy(wotsPk[(l>>1)*params.N:((l>>1)+1)*params.N],
				wotsPk[(l-1)*params.N:l*params.N])
			l = (l >> 1) + 1
		} else {
			l = l >> 1
		}
		height++
	}
	ret := make([]byte, params.N)
	copy(ret, wotsPk[:params.N])
	return ret
}

// Generate the leaf at the given address by first computing the
// WOTS+ key pair and then using lTree.
func (params *Params) genLeaf(skSeed, pubSeed []byte,
	lTreeAddr, otsAddr address) []byte {
	seed := params.getWotsSeed(skSeed, otsAddr)
	pk := params.wotsPkGen(seed, pubSeed, otsAddr)
	return params.lTree(pk, pubSeed, lTreeAddr)
}

// Derive the seed for the WOTS+ key pair at the given address
// from the secret key seed
func (params *Params) getWotsSeed(skSeed []byte, addr address) []byte {
	addr.setChain(0)
	addr.setHash(0)
	addr.setKeyAndMask(0)
	return params.prf(addr.toBytes(), skSeed)
}
