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

// Compute the hash of in.  out must be a n-byte slice.
func (ctx *Context) hashInto(in, out []byte) {
	if ctx.p.Func == SHA2 {
		if ctx.p.N == 32 {
			ret := sha256.Sum256(in)
			copy(out, ret[:])
		} else { // N == 64
			ret := sha512.Sum512(in)
			copy(out, ret[:])
		}
	} else { // SHAKE
		if ctx.p.N == 32 {
			sha3.ShakeSum128(out, in)
		} else { // N == 64
			sha3.ShakeSum256(out, in)
		}
	}
}

// Compute PRF(key, encodeUint64(i))
func (ctx *Context) prfUint64Into(i uint64, key, out []byte) {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	encodeUint64Into(i, buf[ctx.p.N*2:])
	ctx.hashInto(buf, out)
}

// Compute PRF(key, addr)
func (ctx *Context) prfAddr(addr address, key []byte) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.prfAddrInto(addr, key, ret)
	return ret
}

// Compute PRF(key, addr) and store into out
func (ctx *Context) prfAddrInto(addr address, key, out []byte) {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	addr.writeInto(buf[ctx.p.N*2:])
	ctx.hashInto(buf, out)
}

// Compute PRF(key, in).
// in must be 32 bytes and key must be N bytes.
func (ctx *Context) prf(in, key []byte) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.prfInto(in, key, ret)
	return ret
}

// Compute PRF(key, in) and put it into out
// in must be 32 bytes and key must be N bytes.
func (ctx *Context) prfInto(in, key, out []byte) {
	buf := make([]byte, 2*ctx.p.N+32)
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	copy(buf[ctx.p.N*2:], in)
	ctx.hashInto(buf, out)
}

// Compute hash of a message and put it into out
func (ctx *Context) hashMessage(msg, R, root []byte, idx uint64) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.hashMessageInto(msg, R, root, idx, ret)
	return ret
}

// Compute hash of a message and put it into out
func (ctx *Context) hashMessageInto(msg, R, root []byte, idx uint64, out []byte) {
	buf := make([]byte, 4*int(ctx.p.N)+len(msg))
	encodeUint64Into(HASH_PADDING_HASH, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], R)
	copy(buf[ctx.p.N*2:], root)
	encodeUint64Into(idx, buf[ctx.p.N*3:ctx.p.N*4])
	copy(buf[ctx.p.N*4:], msg)
	ctx.hashInto(buf, out)
}

// Compute the hash f used in WOTS+
func (ctx *Context) f(in, pubSeed []byte, addr address) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.fInto(in, pubSeed, addr, ret)
	return ret
}

// Compute the hash f used in WOTS+ and put it into out
func (ctx *Context) fInto(in, pubSeed []byte, addr address, out []byte) {
	buf := make([]byte, 3*int(ctx.p.N))
	encodeUint64Into(HASH_PADDING_F, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	ctx.prfAddrInto(addr, pubSeed, buf[ctx.p.N:ctx.p.N*2])
	addr.setKeyAndMask(1)
	ctx.prfAddrInto(addr, pubSeed, buf[2*ctx.p.N:])
	xor.BytesSameLen(buf[2*ctx.p.N:], in, buf[2*ctx.p.N:])
	ctx.hashInto(buf, out)
}

// Compute RAND_HASH used to hash up various trees
func (ctx *Context) h(left, right, pubSeed []byte, addr address) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.hInto(left, right, pubSeed, addr, ret)
	return ret
}

// Compute RAND_HASH used to hash up various trees and put it into out
func (ctx *Context) hInto(left, right, pubSeed []byte, addr address, out []byte) {
	buf := make([]byte, 4*int(ctx.p.N))
	encodeUint64Into(HASH_PADDING_H, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	ctx.prfAddrInto(addr, pubSeed, buf[ctx.p.N:ctx.p.N*2])
	addr.setKeyAndMask(1)
	leftBitmask := ctx.prfAddr(addr, pubSeed)
	addr.setKeyAndMask(2)
	rightBitmask := ctx.prfAddr(addr, pubSeed)
	xor.BytesSameLen(buf[2*ctx.p.N:3*ctx.p.N], left, leftBitmask)
	xor.BytesSameLen(buf[3*ctx.p.N:], right, rightBitmask)
	ctx.hashInto(buf, out)
}
