package xmssmt

import (
	"encoding/binary"
)

// Encodes the given uint64 into the buffer out in Big Endian
func encodeUint64Into(x uint64, out []byte) {
	if len(out)%8 == 0 {
		binary.BigEndian.PutUint64(out[len(out)-8:], x)
		for i := 0; i < len(out)-8; i += 8 {
			binary.BigEndian.PutUint64(out[i:i+8], 0)
		}
	} else {
		for i := len(out) - 1; i >= 0; i-- {
			out[i] = byte(x)
			x >>= 8
		}
	}
}

// Encodes the given uint64 as [outLen]byte in Big Endian.
func encodeUint64(x uint64, outLen int) []byte {
	ret := make([]byte, outLen)
	encodeUint64Into(x, ret)
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
