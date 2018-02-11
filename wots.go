package xmssmt

// Expands seed to WOTS+ secret key
func (params *Params) wotsExpandSeed(in []byte) []byte {
	var ret []byte = make([]byte, params.N*params.WotsLen)
	var i uint32
	for i = 0; i < params.WotsLen; i++ {
		copy(ret[i*params.N:], params.prf(encodeUint64(uint64(i), 32), in))
	}
	return ret
}

// Converts a message into positions on the WOTS+ chains, which
// are called "chain lengths".
func (params *Params) wotsChainLengths(msg []byte) []uint8 {
	ret := make([]uint8, params.WotsLen)

	// compute the chain lengths for the message itself
	params.toBaseW(msg, ret[:params.WotsLen1])

	// compute the checksum
	var csum uint32 = 0
	for i := 0; i < int(params.WotsLen1); i++ {
		csum += uint32(params.WotsW) - 1 - uint32(ret[i])
	}
	csum = csum << (8 - ((params.WotsLen2 * uint32(params.WotsLogW)) % 8))

	// put checksum in buffer
	params.toBaseW(
		encodeUint64(
			uint64(csum),
			int((params.WotsLen2*uint32(params.WotsLogW)+7)/8)),
		ret[params.WotsLen1:])
	return ret
}

// Converts the given array of bytes into base w for the WOTS+ one-time
// signature scheme.  Only works if LogW divides into 8.
func (params *Params) toBaseW(input []byte, output []uint8) {
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
		bits -= params.WotsLogW
		output[out] = uint8(uint16(total>>bits) & (params.WotsW - 1))
		out++
	}
}

// Compute the (start + steps)th value in the WOTS+ chain, given
// the start'th value in the chain.
func (params *Params) wotsGenChain(in []byte, start, steps uint16,
	pubSeed []byte, addr address) []byte {
	buf := in
	var i uint16
	for i = start; i < (start+steps) && (i < params.WotsW); i++ {
		addr.setHash(uint32(i))
		buf = params.f(buf, pubSeed, addr)
	}
	return buf
}

// Generate a WOTS+ public key from secret key seed.
func (params *Params) wotsPkGen(seed, pubSeed []byte, addr address) []byte {
	buf := params.wotsExpandSeed(seed)
	var i uint32
	for i = 0; i < params.WotsLen; i++ {
		addr.setChain(uint32(i))
		copy(buf[params.N*i:params.N*(i+1)],
			params.wotsGenChain(buf[params.N*i:params.N*(i+1)],
				0, params.WotsW-1, pubSeed, addr))
	}
	return buf
}

// Create a WOTS+ signature of a n-byte message
func (params *Params) wotsSign(msg, seed, pubSeed []byte, addr address) []byte {
	lengths := params.wotsChainLengths(msg)
	buf := params.wotsExpandSeed(seed)
	var i uint32
	for i = 0; i < params.WotsLen; i++ {
		addr.setChain(uint32(i))
		copy(buf[params.N*i:params.N*(i+1)],
			params.wotsGenChain(buf[params.N*i:params.N*(i+1)],
				0, uint16(lengths[i]), pubSeed, addr))
	}
	return buf
}

// Returns the public key from a message and its WOTS+ signature.
func (params *Params) wotsPkFromSig(sig, msg, pubSeed []byte,
	addr address) []byte {
	lengths := params.wotsChainLengths(msg)
	buf := make([]byte, params.N*params.WotsLen)
	var i uint32
	for i = 0; i < params.WotsLen; i++ {
		addr.setChain(uint32(i))
		copy(buf[params.N*i:params.N*(i+1)],
			params.wotsGenChain(sig[params.N*i:params.N*(i+1)],
				uint16(lengths[i]), params.WotsW-1-uint16(lengths[i]),
				pubSeed, addr))
	}
	return buf
}
