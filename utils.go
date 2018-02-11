package xmssmt

// Encodes the given uint64 as [outLen]byte in Big Endian.
func encodeUint64(x uint64, outLen int) []byte {
	ret := make([]byte, outLen)
	for i := outLen - 1; i >= 0; i-- {
		ret[i] = byte(x)
		x >>= 8
	}
	return ret
}

// Interpret []byte as Big Endian int.
func decodeUint64(in []byte) (ret uint64) {
	// TODO should we use binary.BigEndian?
	for i := 0; i < len(in); i++ {
		ret |= uint64(in[i]) << uint64(8*(len(in)-1-i))
	}
	return
}
