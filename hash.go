package xmssmt

// The various hashes  used by WOTS+, XMSS and XMSSMT.

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
	"reflect"

	"github.com/templexxx/xor"
	"golang.org/x/crypto/sha3"
)

const (
	HASH_PADDING_F    = 0
	HASH_PADDING_H    = 1
	HASH_PADDING_HASH = 2
	HASH_PADDING_PRF  = 3
)

// Many of the hashes that we compute share the same prefix.  If this prefix
// is longer than the "rate" of the hash, then we can reduce the compution
// by precomputing the state of the hashes after consuming these common
// prefixes.  This struct contains the functions that encapsulate the
// precomputed hashes.
type precomputedHashes struct {
	// Precomputed prfAddrInto for the current pubSeed
	prfAddrPubSeedInto func(pad scratchPad, addr address, out []byte)

	// Precomputed prfAddrInto for the current skSeed
	prfAddrSkSeedInto func(pad scratchPad, addr address, out []byte)
}

// Contains preallocated hashes to prevent allocation.  See scratchPad.
type hashScratchPad struct {
	h     hash.Hash
	hV    reflect.Value
	shake sha3.ShakeHash
}

func (ctx *Context) precomputeHashes(pubSeed, skSeed []byte) (
	ph precomputedHashes) {
	if ctx.p.Func == SHA2 {
		var hPrfSk, hPrfPub hash.Hash
		switch ctx.p.N {
		case 16, 32:
			hPrfSk = sha256.New()
			hPrfPub = sha256.New()
		case 64:
			hPrfSk = sha512.New()
			hPrfPub = sha512.New()
		}

		if skSeed != nil {
			hPrfSk.Write(encodeUint64(HASH_PADDING_PRF, int(ctx.p.N)))
			hPrfSk.Write(skSeed)
		}

		hPrfPub.Write(encodeUint64(HASH_PADDING_PRF, int(ctx.p.N)))
		hPrfPub.Write(pubSeed)

		// This might break if sha{256,512}.digest is changed in the future,
		// but it's much better than using the encoding.Binary(Un)marshaler
		// interface as that forces allocations.
		// See https://stackoverflow.com/questions/45385707/
		hVprfPub := reflect.ValueOf(hPrfPub).Elem()
		hVskPub := reflect.ValueOf(hPrfSk).Elem()

		ph.prfAddrPubSeedInto = func(pad scratchPad, addr address, out []byte) {
			pad.hash.hV.Set(hVprfPub)
			addrBuf := pad.prfAddrBuf()
			addr.writeInto(addrBuf)
			pad.hash.h.Write(addrBuf)

			// hash.Sum append()s the hash to the input byte slice.  As our
			// input byte slice has enough capacity, it will write it in out.
			pad.hash.h.Sum(out[:0])
		}

		if skSeed == nil {
			return
		}

		ph.prfAddrSkSeedInto = func(pad scratchPad, addr address, out []byte) {
			pad.hash.hV.Set(hVskPub)
			addrBuf := pad.prfAddrBuf()
			addr.writeInto(addrBuf)
			pad.hash.h.Write(addrBuf)
			pad.hash.h.Sum(out[:0]) // see above
		}
	} else { // SHAKE
		// The rates of Shake128 and Shake256 are so high (136 resp. 168)
		// that precomputing does not have merit.
		ph.prfAddrPubSeedInto = func(pad scratchPad, addr address, out []byte) {
			h := pad.hash.shake
			addrBuf := pad.prfAddrBuf()
			h.Reset()
			prefBuf := pad.prfBuf()[:ctx.p.N]
			encodeUint64Into(HASH_PADDING_PRF, prefBuf)
			addr.writeInto(addrBuf)
			h.Write(prefBuf)
			h.Write(pubSeed)
			h.Write(addrBuf)
			h.Read(out[:pad.n])
		}

		if skSeed == nil {
			return
		}

		ph.prfAddrSkSeedInto = func(pad scratchPad, addr address, out []byte) {
			h := pad.hash.shake
			addrBuf := pad.prfAddrBuf()
			h.Reset()
			prefBuf := pad.prfBuf()[:ctx.p.N]
			encodeUint64Into(HASH_PADDING_PRF, prefBuf)
			addr.writeInto(addrBuf)
			h.Write(prefBuf)
			h.Write(skSeed)
			h.Write(addrBuf)
			h.Read(out[:pad.n])
		}
	}
	return
}

// Compute the hash of in.  out must be a n-byte slice.
func (ctx *Context) hashInto(pad scratchPad, in, out []byte) {
	if ctx.p.Func == SHA2 {
		switch ctx.p.N {
		case 16:
			ret := sha256.Sum256(in)
			copy(out, ret[:16])
		case 32:
			ret := sha256.Sum256(in)
			copy(out, ret[:])
		case 64:
			ret := sha512.Sum512(in)
			copy(out, ret[:])
		}
	} else { // SHAKE
		h := pad.hash.shake
		h.Reset()
		h.Write(in)
		h.Read(out[:ctx.p.N])
	}
}

// Compute PRF(key, i)
func (ctx *Context) prfUint64(pad scratchPad, i uint64, key []byte) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.prfUint64Into(pad, i, key, ret)
	return ret
}

// Compute PRF(key, i)
func (ctx *Context) prfUint64Into(pad scratchPad, i uint64, key, out []byte) {
	buf := pad.prfBuf()
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	encodeUint64Into(i, buf[ctx.p.N*2:])
	ctx.hashInto(pad, buf, out)
}

// Compute PRF(key, addr)
func (ctx *Context) prfAddr(pad scratchPad, addr address, key []byte) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.prfAddrInto(pad, addr, key, ret)
	return ret
}

// Compute PRF(key, addr) and store into out
func (ctx *Context) prfAddrInto(pad scratchPad, addr address, key, out []byte) {
	buf := pad.prfBuf()
	encodeUint64Into(HASH_PADDING_PRF, buf[:ctx.p.N])
	copy(buf[ctx.p.N:], key)
	addr.writeInto(buf[ctx.p.N*2:])
	ctx.hashInto(pad, buf, out)
}

// Compute hash of a message and put it into out
func (ctx *Context) hashMessage(pad scratchPad, msg io.Reader,
	R, root []byte, idx uint64) ([]byte, error) {
	ret := make([]byte, ctx.p.N)
	err := ctx.hashMessageInto(pad, msg, R, root, idx, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Compute hash of a message and put it into out
func (ctx *Context) hashMessageInto(pad scratchPad, msg io.Reader,
	R, root []byte, idx uint64, out []byte) error {

	var h io.Writer
	if ctx.p.Func == SHA2 {
		switch ctx.p.N {
		case 16, 32:
			h = sha256.New()
		case 64:
			h = sha512.New()
		}
	} else { // SHAKE
		h2 := pad.hash.shake
		h2.Reset()
		h = h2
	}

	h.Write(encodeUint64(HASH_PADDING_HASH, int(ctx.p.N)))
	h.Write(R)
	h.Write(root)
	h.Write(encodeUint64(idx, int(ctx.p.N)))

	_, err := io.Copy(h, msg)
	if err != nil {
		return err
	}

	if ctx.p.Func == SHA2 {
		(h.(hash.Hash)).Sum(out[:0])
	} else { // SHAKE
		(h.(io.Reader)).Read(out)
	}

	return nil
}

// Compute the hash f used in WOTS+
func (ctx *Context) f(in, pubSeed []byte, addr address) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.fInto(ctx.newScratchPad(), in, ctx.precomputeHashes(pubSeed, nil),
		addr, ret)
	return ret
}

// Compute the hash f used in WOTS+ and put it into out
func (ctx *Context) fInto(pad scratchPad, in []byte, ph precomputedHashes,
	addr address, out []byte) {
	buf := pad.fBuf()
	encodeUint64Into(HASH_PADDING_F, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	ph.prfAddrPubSeedInto(pad, addr, buf[ctx.p.N:ctx.p.N*2])
	addr.setKeyAndMask(1)
	ph.prfAddrPubSeedInto(pad, addr, buf[2*ctx.p.N:])
	xor.BytesSameLen(buf[2*ctx.p.N:], in, buf[2*ctx.p.N:])
	ctx.hashInto(pad, buf, out)
}

// Compute RAND_HASH used to hash up various trees
func (ctx *Context) h(left, right, pubSeed []byte, addr address) []byte {
	ret := make([]byte, ctx.p.N)
	ctx.hInto(ctx.newScratchPad(), left, right,
		ctx.precomputeHashes(pubSeed, nil), addr, ret)
	return ret
}

// Compute RAND_HASH used to hash up various trees and put it into out
func (ctx *Context) hInto(pad scratchPad, left, right []byte,
	ph precomputedHashes, addr address, out []byte) {
	buf := pad.hBuf()
	encodeUint64Into(HASH_PADDING_H, buf[:ctx.p.N])
	addr.setKeyAndMask(0)
	ph.prfAddrPubSeedInto(pad, addr, buf[ctx.p.N:ctx.p.N*2])
	addr.setKeyAndMask(1)
	ph.prfAddrPubSeedInto(pad, addr, buf[2*ctx.p.N:3*ctx.p.N])
	addr.setKeyAndMask(2)
	ph.prfAddrPubSeedInto(pad, addr, buf[3*ctx.p.N:])
	xor.BytesSameLen(buf[2*ctx.p.N:3*ctx.p.N], left, buf[2*ctx.p.N:3*ctx.p.N])
	xor.BytesSameLen(buf[3*ctx.p.N:], right, buf[3*ctx.p.N:])
	ctx.hashInto(pad, buf, out)
}

func (ctx *Context) newHashScratchPad() (pad hashScratchPad) {
	if ctx.p.Func == SHA2 {
		switch ctx.p.N {
		case 16, 32:
			pad.h = sha256.New()
		case 64:
			pad.h = sha512.New()
		}
		pad.hV = reflect.ValueOf(pad.h).Elem()
	} else { // SHAKE
		switch ctx.p.N {
		case 16, 32:
			pad.shake = sha3.NewShake128()
		case 64:
			pad.shake = sha3.NewShake256()
		}
	}
	return
}
