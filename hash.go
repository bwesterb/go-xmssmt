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

func (ctx *Context) hash(in []byte) []byte {
	if ctx.p.Func == SHA2 {
		if ctx.p.N == 32 {
			ret := sha256.Sum256(in)
			return ret[:]
		} else { // N == 64
			ret := sha512.Sum512(in)
			return ret[:]
		}
	} else { // SHAKE
		if ctx.p.N == 32 {
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

// Compute PRF(key, encodeUint64(i))
func (ctx *Context) prfUint64(i uint64, key []byte) []byte {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	encodeUint64Into(i, buf[ctx.p.N*2:])
	return ctx.hash(buf)
}

// Compute PRF(key, addr)
func (ctx *Context) prfAddr(addr address, key []byte) []byte {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	addr.writeInto(buf[ctx.p.N*2:])
	return ctx.hash(buf)
}

// Compute PRF(key, in).
// in must be 32 bytes and key must be N bytes.
func (ctx *Context) prf(in []byte, key []byte) []byte {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	copy(buf[ctx.p.N*2:], in)
	return ctx.hash(buf)
}

// Compute hash of a message
func (ctx *Context) hashMessage(msg, R, root []byte, idx uint64) []byte {
	buf := make([]byte, 4*int(ctx.p.N)+len(msg))
	encodeUint64Into(HASH_PADDING_HASH, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], R)
	copy(buf[ctx.p.N*2:], root)
	encodeUint64Into(idx, buf[ctx.p.N*3:ctx.p.N*4])
	copy(buf[ctx.p.N*4:], msg)
	return ctx.hash(buf)
}

// Compute the hash f used in WOTS+
func (ctx *Context) f(in, pubSeed []byte, addr address) []byte {
	buf := make([]byte, 3*int(ctx.p.N))
	encodeUint64Into(HASH_PADDING_F, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	copy(buf[ctx.p.N:], ctx.prfAddr(addr, pubSeed))
	addr.setKeyAndMask(1)
	bitmask := ctx.prfAddr(addr, pubSeed)
	xor.BytesSameLen(buf[2*ctx.p.N:], in, bitmask)
	return ctx.hash(buf)
}

// Compute RAND_HASH used to hash up various trees
func (ctx *Context) h(left, right, pubSeed []byte, addr address) []byte {
	buf := make([]byte, 4*int(ctx.p.N))
	encodeUint64Into(HASH_PADDING_H, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	copy(buf[ctx.p.N:], ctx.prfAddr(addr, pubSeed))
	addr.setKeyAndMask(1)
	leftBitmask := ctx.prfAddr(addr, pubSeed)
	addr.setKeyAndMask(2)
	rightBitmask := ctx.prfAddr(addr, pubSeed)
	xor.BytesSameLen(buf[2*ctx.p.N:3*ctx.p.N], left, leftBitmask)
	xor.BytesSameLen(buf[3*ctx.p.N:], right, rightBitmask)
	return ctx.hash(buf)
}
