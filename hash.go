package xmssmt

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/templexxx/xor"
	"golang.org/x/crypto/sha3"
)

const (
	HASH_PADDING_F    = 0
	HASH_PADDING_H    = 1
	HASH_PADDING_HASH = 2
	HASH_PADDING_PRF  = 3
)

func (params *Params) hash(in []byte) []byte {
	if params.Func == SHA2 {
		if params.N == 32 {
			ret := sha256.Sum256(in)
			return ret[:]
		} else { // N == 64
			ret := sha512.Sum512(in)
			return ret[:]
		}
	} else { // SHAKE
		if params.N == 32 {
			ret := make([]byte, 32)
			sha3.ShakeSum128(ret, in)
			return ret
		} else { // N == 64
			ret := make([]byte, 64)
			sha3.ShakeSum256(ret, in)
			return ret
		}
	}
}

// Compute PRF(key, in).
// in must be 32 bytes and key must be N bytes.
func (params *Params) prf(in []byte, key []byte) []byte {
	buf := make([]byte, 2*params.N+32)
	copy(buf, encodeUint64(HASH_PADDING_PRF, int(params.N)))
	copy(buf[params.N:], key)
	copy(buf[params.N*2:], in)
	return params.hash(buf)
}

// Compute hash of a message
func (params *Params) hashMessage(msg, R, root []byte, idx uint64) []byte {
	buf := make([]byte, 4*int(params.N)+len(msg))
	copy(buf, encodeUint64(HASH_PADDING_HASH, int(params.N)))
	copy(buf[params.N:], R)
	copy(buf[params.N*2:], root)
	copy(buf[params.N*3:], encodeUint64(idx, int(params.N)))
	copy(buf[params.N*4:], msg)
	return params.hash(buf)
}

// Compute the hash f used in WOTS+
func (params *Params) f(in, pubSeed []byte, addr address) []byte {
	buf := make([]byte, 3*int(params.N))
	copy(buf, encodeUint64(HASH_PADDING_F, int(params.N)))
	addr.setKeyAndMask(0)
	copy(buf[params.N:], params.prf(addr.toBytes(), pubSeed))
	addr.setKeyAndMask(1)
	bitmask := params.prf(addr.toBytes(), pubSeed)
	xor.BytesSameLen(buf[2*params.N:], in, bitmask)
	return params.hash(buf)
}

// Compute RAND_HASH used to hash up various trees
func (params *Params) h(left, right, pubSeed []byte, addr address) []byte {
	buf := make([]byte, 4*int(params.N))
	copy(buf, encodeUint64(HASH_PADDING_H, int(params.N)))
	addr.setKeyAndMask(0)
	copy(buf[params.N:], params.prf(addr.toBytes(), pubSeed))
	addr.setKeyAndMask(1)
	leftBitmask := params.prf(addr.toBytes(), pubSeed)
	addr.setKeyAndMask(2)
	rightBitmask := params.prf(addr.toBytes(), pubSeed)
	xor.BytesSameLen(buf[2*params.N:3*params.N], left, leftBitmask)
	xor.BytesSameLen(buf[3*params.N:], right, rightBitmask)
	return params.hash(buf)
}
