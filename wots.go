package xmssmt

import (
	"sort"
)

// The Winternitz One-Time Signature scheme as used by XMSS[MT].

// Generate WOTS+ secret key
func (ctx *Context) genWotsSk(pad scratchPad, ph precomputedHashes,
	addr address, out []byte) {
	n := ctx.p.N
	addr.setHash(0)
	addr.setKeyAndMask(0)

	for i := uint32(0); i < ctx.wotsLen; i++ {
		addr.setChain(i)
		ctx.prfKeyGenInto(pad, ph, addr, out[i*n:(i+1)*n])
	}
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
	if ctx.p.WotsW == 256 {
		copy(output, input)
		return
	}

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
	start, steps uint16, ph precomputedHashes, addr address, out []byte) {
	copy(out, in)
	var i uint16
	for i = start; i < (start+steps) && (i < ctx.p.WotsW); i++ {
		addr.setHash(uint32(i))
		ctx.fInto(pad, out, ph, addr, out)
	}
}

// Generate a WOTS+ public key from secret key seed.
func (ctx *Context) wotsPkGen(pad scratchPad, ph precomputedHashes,
	addr address) []byte {
	ret := make([]byte, ctx.wotsLen*ctx.p.N)
	ctx.wotsPkGenInto(pad, ph, addr, ret)
	return ret
}

// Generate a WOTS+ public key from secret key seed.
func (ctx *Context) wotsPkGenInto(pad scratchPad, ph precomputedHashes,
	addr address, out []byte) {
	ctx.genWotsSk(pad, ph, addr, out)
	n := ctx.p.N

	if !ctx.x4Available {
		// Unvectorized
		for i := uint32(0); i < ctx.wotsLen; i++ {
			addr.setChain(uint32(i))
			ctx.wotsGenChainInto(pad, out[n*i:n*(i+1)],
				0, ctx.p.WotsW-1, ph, addr,
				out[n*i:n*(i+1)])
		}
		return
	}

	// Fourway vectorized
	addrs := [4]address{addr, addr, addr, addr}
	for i := uint32(0); i < ctx.wotsLen; i += 4 {
		var bufs [4][]byte
		for j := uint32(0); j < 4 && i+j < ctx.wotsLen; j++ {
			addrs[j].setChain(uint32(i + j))
			bufs[j] = out[n*(i+j) : n*(i+j+1)]
		}
		for k := uint16(0); k < ctx.p.WotsW-1; k++ {
			for j := 0; j < 4; j++ {
				addrs[j].setHash(uint32(k))
			}
			ctx.fX4Into(pad, bufs, ph.pubSeed, addrs, bufs)
		}
	}
}

// Create a WOTS+ signature of a n-byte message
func (ctx *Context) wotsSign(pad scratchPad, msg, pubSeed, skSeed []byte,
	addr address) []byte {
	ret := make([]byte, ctx.wotsSigBytes)
	ctx.wotsSignInto(pad, msg, ctx.precomputeHashes(pubSeed, skSeed), addr, ret)
	return ret
}

// Create a WOTS+ signature of a n-byte message
func (ctx *Context) wotsSignInto(pad scratchPad, msg []byte,
	ph precomputedHashes, addr address, wotsSig []byte) {
	lengths := ctx.wotsChainLengths(msg)
	ctx.genWotsSk(pad, ph, addr, wotsSig)
	n := ctx.p.N

	if !ctx.x4Available {
		// Unvectorized
		for i := uint32(0); i < ctx.wotsLen; i++ {
			addr.setChain(uint32(i))
			ctx.wotsGenChainInto(pad, wotsSig[n*i:n*(i+1)],
				0, uint16(lengths[i]), ph, addr,
				wotsSig[n*i:n*(i+1)])
		}
		return
	}

	// Fourway vectorized
	steps := make([]uint16, ctx.wotsLen)
	for i := uint32(0); i < ctx.wotsLen; i++ {
		steps[i] = uint16(lengths[i])
	}
	ctx.wotsGenChainsX4Into(pad, wotsSig, make([]uint16, ctx.wotsLen),
		steps, ph, addr, wotsSig)
}

// Compute the (start + steps)th value in the WOTS+ chain, given
// the start'th value in the chain.
func (ctx *Context) wotsGenChainsX4Into(pad scratchPad, in []byte,
	start []uint16, steps []uint16, ph precomputedHashes,
	addr address, out []byte) {
	n := ctx.p.N
	copy(out[:ctx.wotsLen*n], in)

	// We group chains by their length
	chains := make([]struct {
		start uint16
		steps uint16
		idx   uint32
	}, ctx.wotsLen)
	for i := uint32(0); i < ctx.wotsLen; i++ {
		chains[i].start = start[i]
		chains[i].steps = steps[i]
		chains[i].idx = i
	}

	// Note that we sort by reverse order so that the last chains that are
	// left over when wotsLen is not divisable by four are short.
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].steps > chains[j].steps
	})

	// Now we know what to do, do it.
	addrs := [4]address{addr, addr, addr, addr}
	for i := uint32(0); i < ctx.wotsLen; i += 4 {
		var bufs [4][]byte
		for j := uint32(0); j < 4 && i+j < ctx.wotsLen; j++ {
			idx := chains[i+j].idx
			addrs[j].setChain(idx)
			bufs[j] = out[n*idx : n*(idx+1)]
		}

		// As we reverse sorted the chains, we know the first is longest and
		// the last is shortest.
		watching := uint32(3) // we're watching the shortest initially
		for i+watching >= ctx.wotsLen {
			watching--
		}
		done := false
		for k := uint16(0); ; k++ {
			for k == chains[i+watching].steps {
				bufs[watching] = nil
				if watching == 0 {
					done = true
					break
				}
				watching--
			}
			if done {
				break
			}
			for j := uint32(0); j < watching+1; j++ {
				addrs[j].setHash(uint32(k + chains[i+j].start))
			}
			ctx.fX4Into(pad, bufs, ph.pubSeed, addrs, bufs)
		}
	}
}

// Computes the public key from a message and its WOTS+ signature and
// stores it in the provided buffer.
func (ctx *Context) wotsPkFromSigInto(pad scratchPad, sig, msg []byte,
	ph precomputedHashes, addr address, pk []byte) {
	lengths := ctx.wotsChainLengths(msg)
	n := ctx.p.N

	if !ctx.x4Available {
		// Unvectorized
		for i := uint32(0); i < ctx.wotsLen; i++ {
			addr.setChain(uint32(i))
			ctx.wotsGenChainInto(pad, sig[n*i:n*(i+1)],
				uint16(lengths[i]), ctx.p.WotsW-1-uint16(lengths[i]),
				ph, addr, pk[n*i:n*(i+1)])
		}
		return
	}

	// Fourway vectorized
	steps := make([]uint16, ctx.wotsLen)
	start := make([]uint16, ctx.wotsLen)
	for i := uint32(0); i < ctx.wotsLen; i++ {
		steps[i] = ctx.p.WotsW - 1 - uint16(lengths[i])
		start[i] = uint16(lengths[i])
	}
	ctx.wotsGenChainsX4Into(pad, sig, start, steps, ph, addr, pk)
}

// Returns the public key from a message and its WOTS+ signature.
func (ctx *Context) wotsPkFromSig(pad scratchPad, sig, msg []byte,
	ph precomputedHashes, addr address) []byte {
	pk := make([]byte, ctx.p.N*ctx.wotsLen)
	ctx.wotsPkFromSigInto(pad, sig, msg, ph, addr, pk)
	return pk
}
