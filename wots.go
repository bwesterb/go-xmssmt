package xmssmt

// Expands seed to WOTS+ secret key
func (ctx *Context) wotsExpandSeed(in []byte) []byte {
	var ret []byte = make([]byte, ctx.p.N*ctx.wotsLen)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		ctx.prfUint64Into(uint64(i), in, ret[i*ctx.p.N:])
	}
	return ret
}

// Converts a message into positions on the WOTS+ chains, which
// are called "chain lengths".
func (ctx *Context) wotsChainLengths(msg []byte) []uint8 {
	ret := make([]uint8, ctx.wotsLen)

	// compute the chain lengths for the message itself
	ctx.toBaseW(msg, ret[:ctx.wotsLen1])

	// compute the checksum
	var csum uint32 = 0
	for i := 0; i < int(ctx.wotsLen1); i++ {
		csum += uint32(ctx.p.WotsW) - 1 - uint32(ret[i])
	}
	csum = csum << (8 - ((ctx.wotsLen2 * uint32(ctx.wotsLogW)) % 8))

	// put checksum in buffer
	ctx.toBaseW(
		encodeUint64(
			uint64(csum),
			int((ctx.wotsLen2*uint32(ctx.wotsLogW)+7)/8)),
		ret[ctx.wotsLen1:])
	return ret
}

// Converts the given array of bytes into base w for the WOTS+ one-time
// signature scheme.  Only works if LogW divides into 8.
func (ctx *Context) toBaseW(input []byte, output []uint8) {
	var in uint32 = 0
	var out uint32 = 0
	var total uint8
	var bits uint8

	for consumed := 0; consumed < len(output); consumed++ {
		if bits == 0 {
			total = input[in]
			in++
			bits = 8
		}
		bits -= ctx.wotsLogW
		output[out] = uint8(uint16(total>>bits) & (ctx.p.WotsW - 1))
		out++
	}
}

// Compute the (start + steps)th value in the WOTS+ chain, given
// the start'th value in the chain.
func (ctx *Context) wotsGenChainInto(pad scratchPad, in []byte,
	start, steps uint16,
	pubSeed []byte, addr address, out []byte) {
	copy(out, in)
	var i uint16
	for i = start; i < (start+steps) && (i < ctx.p.WotsW); i++ {
		addr.setHash(uint32(i))
		ctx.fInto(pad, out, pubSeed, addr, out)
	}
}

// Generate a WOTS+ public key from secret key seed.
func (ctx *Context) wotsPkGen(pad scratchPad, seed,
	pubSeed []byte, addr address) []byte {
	buf := ctx.wotsExpandSeed(seed)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, buf[ctx.p.N*i:ctx.p.N*(i+1)],
			0, ctx.p.WotsW-1, pubSeed, addr,
			buf[ctx.p.N*i:ctx.p.N*(i+1)])
	}
	return buf
}

// Create a WOTS+ signature of a n-byte message
func (ctx *Context) wotsSign(pad scratchPad, msg, seed, pubSeed []byte,
	addr address) []byte {
	lengths := ctx.wotsChainLengths(msg)
	buf := ctx.wotsExpandSeed(seed)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, buf[ctx.p.N*i:ctx.p.N*(i+1)],
			0, uint16(lengths[i]), pubSeed, addr,
			buf[ctx.p.N*i:ctx.p.N*(i+1)])
	}
	return buf
}

// Returns the public key from a message and its WOTS+ signature.
func (ctx *Context) wotsPkFromSig(pad scratchPad, sig, msg, pubSeed []byte,
	addr address) []byte {
	lengths := ctx.wotsChainLengths(msg)
	buf := make([]byte, ctx.p.N*ctx.wotsLen)
	var i uint32
	for i = 0; i < ctx.wotsLen; i++ {
		addr.setChain(uint32(i))
		ctx.wotsGenChainInto(pad, sig[ctx.p.N*i:ctx.p.N*(i+1)],
			uint16(lengths[i]), ctx.p.WotsW-1-uint16(lengths[i]),
			pubSeed, addr,
			buf[ctx.p.N*i:ctx.p.N*(i+1)])
	}
	return buf
}
