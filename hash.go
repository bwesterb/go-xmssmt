package xmssmt

// The various hashes  used by WOTS+, XMSS and XMSSMT.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"
	"reflect"

	"github.com/bwesterb/go-xmssmt/internal/f1600x4"
	"github.com/templexxx/xorsimd"
	"golang.org/x/crypto/sha3"
)

const (
	HASH_PADDING_F          = 0
	HASH_PADDING_H          = 1
	HASH_PADDING_HASH       = 2
	HASH_PADDING_PRF        = 3
	HASH_PADDING_PRF_KEYGEN = 4
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

	pubSeed []byte
	skSeed  []byte
}

// Contains preallocated hashes to prevent allocation.  See scratchPad.
type hashScratchPad struct {
	h        hash.Hash
	hV       reflect.Value
	shake    sha3.ShakeHash
	shakeX4  *f1600x4.State
	shakeX4A []uint64
}

func (ctx *Context) precomputeHashes(pubSeed, skSeed []byte) (
	ph precomputedHashes) {
	ph.pubSeed = pubSeed
	ph.skSeed = skSeed
	switch ctx.p.Func {
	case SHA2:
		var hPrfSk, hPrfPub hash.Hash
		switch ctx.p.N {
		case 16, 24, 32:
			hPrfSk = sha256.New()
			hPrfPub = sha256.New()
		case 64:
			hPrfSk = sha512.New()
			hPrfPub = sha512.New()
		}

		if skSeed != nil {
			hPrfSk.Write(encodeUint64(HASH_PADDING_PRF, int(ctx.prefixLen)))
			hPrfSk.Write(skSeed)
		}

		hPrfPub.Write(encodeUint64(HASH_PADDING_PRF, int(ctx.prefixLen)))
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

			if ctx.p.N >= 32 {
				// hash.Sum append()s the hash to the input byte slice.  As our
				// input byte slice has enough capacity, it will write it in out.
				pad.hash.h.Sum(out[:0])
			} else {
				pad.hash.h.Sum(addrBuf[:0])
				copy(out[:], addrBuf[:ctx.p.N])
			}
		}

		if skSeed == nil {
			return
		}

		ph.prfAddrSkSeedInto = func(pad scratchPad, addr address, out []byte) {
			pad.hash.hV.Set(hVskPub)
			addrBuf := pad.prfAddrBuf()
			addr.writeInto(addrBuf)
			pad.hash.h.Write(addrBuf)
			if ctx.p.N >= 32 {
				pad.hash.h.Sum(out[:0]) // see above
			} else {
				pad.hash.h.Sum(addrBuf[:0])
				copy(out[:], addrBuf[:ctx.p.N])
			}
		}
	case SHAKE, SHAKE256:
		// The rates of Shake128 and Shake256 are so high (136 resp. 168)
		// that precomputing does not have merit.
		ph.prfAddrPubSeedInto = func(pad scratchPad, addr address, out []byte) {
			h := pad.hash.shake
			addrBuf := pad.prfAddrBuf()
			h.Reset()
			prefBuf := pad.prfBuf()[:ctx.prefixLen]
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
			prefBuf := pad.prfBuf()[:ctx.prefixLen]
			encodeUint64Into(HASH_PADDING_PRF, prefBuf)
			addr.writeInto(addrBuf)
			h.Write(prefBuf)
			h.Write(skSeed)
			h.Write(addrBuf)
			h.Read(out[:pad.n])
		}
	default:
		panic("not implemented")
	}
	return
}

// Compute the hash of in.  out must be a n-byte slice.
func (ctx *Context) hashInto(pad scratchPad, in, out []byte) {
	switch ctx.p.Func {
	case SHA2:
		switch ctx.p.N {
		case 16, 24, 32:
			ret := sha256.Sum256(in)
			copy(out, ret[:ctx.p.N])
		case 64:
			ret := sha512.Sum512(in)
			copy(out, ret[:])
		}
	case SHAKE, SHAKE256:
		h := pad.hash.shake
		h.Reset()
		h.Write(in)
		h.Read(out[:ctx.p.N])
	}
}

func (ctx *Context) prfKeyGenInto(pad scratchPad, ph precomputedHashes,
	addr address, out []byte) {
	n := ctx.p.N
	pl := ctx.prefixLen
	buf := pad.prfKeyGenBuf()
	encodeUint64Into(HASH_PADDING_PRF_KEYGEN, buf[:pl])
	copy(buf[pl:pl+n], ph.skSeed)
	copy(buf[pl+n:pl+2*n], ph.pubSeed)
	addr.writeInto(buf[pl+2*n : pl+2*n+32])
	ctx.hashInto(pad, buf[:pl+2*n+32], out)
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
	pl := ctx.prefixLen
	n := ctx.p.N
	encodeUint64Into(HASH_PADDING_PRF, buf[:pl])
	copy(buf[pl:pl+n], key)
	encodeUint64Into(i, buf[n+pl:n+pl+32])
	ctx.hashInto(pad, buf[:n+pl+32], out)
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
	pl := ctx.prefixLen
	n := ctx.p.N
	encodeUint64Into(HASH_PADDING_PRF, buf[:pl])
	copy(buf[pl:pl+n], key)
	addr.writeInto(buf[n+pl : n+pl+32])
	ctx.hashInto(pad, buf[:n+pl+32], out)
}

// Set out[i] = PRF(key, addr[i]) for i=0,1,2,3.
//
// Assumes SHAKE with N either 16 or 32 and f1600x4.Available is true.
func (ctx *Context) prfAddrX4Into(pad scratchPad, addr [4]address, key []byte,
	out [4][]byte) {
	// We're computing hash( HASH_PADDING_PRF ‖ key ‖ addr ).
	a := pad.hash.shakeX4A
	pad.hash.shakeX4.Zero()
	if ctx.p.N == 16 {
		for j := 0; j < 4; j++ {
			if out[j] == nil {
				continue
			}

			a[4+j] = HASH_PADDING_PRF << 56
			a[4*2+j] = binary.LittleEndian.Uint64(key[:8])
			a[4*3+j] = binary.LittleEndian.Uint64(key[8:])

			var buf [8]byte
			for i := 0; i < 4; i++ {
				binary.BigEndian.PutUint32(buf[:4], addr[j][2*i])
				binary.BigEndian.PutUint32(buf[4:], addr[j][2*i+1])
				a[4*(4+i)+j] = binary.LittleEndian.Uint64(buf[:])
			}

			// SHAKE128 domain separator (0b1111) and padding (0b100...001).
			a[4*8+j] = 0x1f
			a[4*20+j] = 0x80 << 56
		}

		pad.hash.shakeX4.Permute()

		for j := 0; j < 4; j++ {
			if out[j] == nil {
				continue
			}
			binary.LittleEndian.PutUint64(out[j][0:8], a[j])
			binary.LittleEndian.PutUint64(out[j][8:16], a[4+j])
		}
	} else if ctx.p.N == 32 {
		for j := 0; j < 4; j++ {
			if out[j] == nil {
				continue
			}

			a[4*3+j] = HASH_PADDING_PRF << 56
			a[4*4+j] = binary.LittleEndian.Uint64(key[:8])
			a[4*5+j] = binary.LittleEndian.Uint64(key[8:16])
			a[4*6+j] = binary.LittleEndian.Uint64(key[16:24])
			a[4*7+j] = binary.LittleEndian.Uint64(key[24:32])

			var buf [8]byte
			for i := 0; i < 4; i++ {
				binary.BigEndian.PutUint32(buf[:4], addr[j][2*i])
				binary.BigEndian.PutUint32(buf[4:], addr[j][2*i+1])
				a[4*(8+i)+j] = binary.LittleEndian.Uint64(buf[:])
			}

			// SHAKE128 domain separator (0b1111) and padding (0b100...001).
			a[4*12+j] = 0x1f
			a[4*20+j] = 0x80 << 56
		}

		pad.hash.shakeX4.Permute()

		for j := 0; j < 4; j++ {
			if out[j] == nil {
				continue
			}
			binary.LittleEndian.PutUint64(out[j][0:8], a[j])
			binary.LittleEndian.PutUint64(out[j][8:16], a[4+j])
			binary.LittleEndian.PutUint64(out[j][16:24], a[8+j])
			binary.LittleEndian.PutUint64(out[j][24:32], a[12+j])
		}
	} else {
		panic("not implemented")
	}
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
	switch ctx.p.Func {
	case SHA2:
		switch ctx.p.N {
		case 16, 24, 32:
			h = sha256.New()
		case 64:
			h = sha512.New()
		}
	case SHAKE, SHAKE256:
		h2 := pad.hash.shake
		h2.Reset()
		h = h2
	}

	h.Write(encodeUint64(HASH_PADDING_HASH, int(ctx.prefixLen)))
	h.Write(R)
	h.Write(root)
	h.Write(encodeUint64(idx, int(ctx.p.N)))

	_, err := io.Copy(h, msg)
	if err != nil {
		return err
	}

	switch ctx.p.Func {
	case SHA2:
		if ctx.p.N >= 32 {
			(h.(hash.Hash)).Sum(out[:0])
		} else {
			var buf [32]byte
			(h.(hash.Hash)).Sum(buf[:0])
			copy(out[:], buf[:ctx.p.N])
		}
	case SHAKE, SHAKE256:
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

// Set out[i] = f(addr[i], key, in[i]) for i=0,1,2,3.
//
// Assumes SHAKE with N either 16 or 32 and f1600x4.Available is true.
func (ctx *Context) fX4Into(pad scratchPad, in [4][]byte, key []byte,
	addr [4]address, out [4][]byte) {
	buf := pad.fX4Buf()
	n := ctx.p.N
	for j := 0; j < 4; j++ {
		addr[j].setKeyAndMask(0)
	}
	ctx.prfAddrX4Into(pad, addr, key, [4][]byte{
		buf[0:n], buf[n : 2*n],
		buf[2*n : 3*n], buf[3*n : 4*n],
	})
	for j := 0; j < 4; j++ {
		addr[j].setKeyAndMask(1)
	}
	ctx.prfAddrX4Into(pad, addr, key, [4][]byte{
		buf[4*n : 5*n], buf[5*n : 6*n],
		buf[6*n : 7*n], buf[7*n : 8*n],
	})

	a := pad.hash.shakeX4A
	pad.hash.shakeX4.Zero()
	if ctx.p.N == 16 {
		for j := 0; j < 4; j++ {
			if in[j] == nil {
				continue
			}

			a[4*2+j] = binary.LittleEndian.Uint64(buf[j*16 : j*16+8])
			a[4*3+j] = binary.LittleEndian.Uint64(buf[j*16+8 : j*16+16])
			a[4*4+j] = (binary.LittleEndian.Uint64(buf[j*16+64:j*16+72]) ^
				binary.LittleEndian.Uint64(in[j][:8]))
			a[4*5+j] = (binary.LittleEndian.Uint64(buf[j*16+72:j*16+80]) ^
				binary.LittleEndian.Uint64(in[j][8:]))

			// SHAKE128 domain separator (0b1111) and padding (0b100...001).
			a[4*6+j] = 0x1f
			a[4*20+j] = 0x80 << 56
		}

		pad.hash.shakeX4.Permute()

		for j := 0; j < 4; j++ {
			if in[j] == nil {
				continue
			}
			binary.LittleEndian.PutUint64(out[j][0:8], a[j])
			binary.LittleEndian.PutUint64(out[j][8:16], a[4+j])
		}
	} else if ctx.p.N == 32 {
		for j := 0; j < 4; j++ {
			if in[j] == nil {
				continue
			}

			a[4*4+j] = binary.LittleEndian.Uint64(buf[j*32 : j*32+8])
			a[4*5+j] = binary.LittleEndian.Uint64(buf[j*32+8 : j*32+16])
			a[4*6+j] = binary.LittleEndian.Uint64(buf[j*32+16 : j*32+24])
			a[4*7+j] = binary.LittleEndian.Uint64(buf[j*32+24 : j*32+32])
			a[4*8+j] = (binary.LittleEndian.Uint64(buf[j*32+128:j*32+136]) ^
				binary.LittleEndian.Uint64(in[j][:8]))
			a[4*9+j] = (binary.LittleEndian.Uint64(buf[j*32+136:j*32+144]) ^
				binary.LittleEndian.Uint64(in[j][8:16]))
			a[4*10+j] = (binary.LittleEndian.Uint64(buf[j*32+144:j*32+152]) ^
				binary.LittleEndian.Uint64(in[j][16:24]))
			a[4*11+j] = (binary.LittleEndian.Uint64(buf[j*32+152:j*32+160]) ^
				binary.LittleEndian.Uint64(in[j][24:32]))

			// SHAKE128 domain separator (0b1111) and padding (0b100...001).
			a[4*12+j] = 0x1f
			a[4*20+j] = 0x80 << 56
		}

		pad.hash.shakeX4.Permute()

		for j := 0; j < 4; j++ {
			if in[j] == nil {
				continue
			}
			binary.LittleEndian.PutUint64(out[j][0:8], a[j])
			binary.LittleEndian.PutUint64(out[j][8:16], a[4+j])
			binary.LittleEndian.PutUint64(out[j][16:24], a[8+j])
			binary.LittleEndian.PutUint64(out[j][24:32], a[12+j])
		}
	} else {
		panic("not implemented")
	}
}

// Compute the hash f used in WOTS+ and put it into out
func (ctx *Context) fInto(pad scratchPad, in []byte, ph precomputedHashes,
	addr address, out []byte) {
	buf := pad.fBuf()
	n := ctx.p.N
	pl := ctx.prefixLen
	encodeUint64Into(HASH_PADDING_F, buf[:pl])
	addr.setKeyAndMask(0)
	ph.prfAddrPubSeedInto(pad, addr, buf[pl:pl+n])
	addr.setKeyAndMask(1)
	ph.prfAddrPubSeedInto(pad, addr, buf[pl+n:pl+2*n])
	xorsimd.Bytes(buf[pl+n:pl+2*n], in, buf[pl+n:pl+2*n])
	ctx.hashInto(pad, buf[:pl+2*n], out)
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
	n := ctx.p.N
	pl := ctx.prefixLen
	encodeUint64Into(HASH_PADDING_H, buf[:pl])
	addr.setKeyAndMask(0)
	ph.prfAddrPubSeedInto(pad, addr, buf[pl:pl+n])
	addr.setKeyAndMask(1)
	ph.prfAddrPubSeedInto(pad, addr, buf[pl+n:pl+2*n])
	addr.setKeyAndMask(2)
	ph.prfAddrPubSeedInto(pad, addr, buf[2*n+pl:3*n+pl])
	xorsimd.Bytes(buf[pl+n:pl+2*n], left, buf[pl+n:pl+2*n])
	xorsimd.Bytes(buf[pl+2*n:pl+3*n], right, buf[pl+2*n:pl+3*n])
	ctx.hashInto(pad, buf[:pl+3*n], out)
}

func (ctx *Context) newHashScratchPad() (pad hashScratchPad) {
	switch ctx.p.Func {
	case SHA2:
		switch ctx.p.N {
		case 16, 24, 32:
			pad.h = sha256.New()
		case 64:
			pad.h = sha512.New()
		}
		pad.hV = reflect.ValueOf(pad.h).Elem()
	case SHAKE:
		switch ctx.p.N {
		case 16, 24, 32:
			pad.shake = sha3.NewShake128()
			if f1600x4.Available {
				pad.shakeX4 = new(f1600x4.State)
				pad.shakeX4A = pad.shakeX4.Initialize()
			}
		case 64:
			pad.shake = sha3.NewShake256()
		}
	case SHAKE256:
		pad.shake = sha3.NewShake256()
	default:
		panic("Not implemented")
	}
	return
}
