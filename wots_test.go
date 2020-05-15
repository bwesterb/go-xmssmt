package xmssmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"
)

func testWotsGenChain(ctx *Context, expect string, t *testing.T) {
	var pubSeed []byte = make([]byte, ctx.p.N)
	var in []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		in[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	ret := make([]byte, ctx.p.N)
	ctx.wotsGenChainInto(ctx.newScratchPad(), in, 4, 5,
		ctx.precomputeHashes(pubSeed, nil), address(addr), ret)
	val := hex.EncodeToString(ret)
	if val != expect {
		t.Errorf("%s wotsGenChain returned %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestWotsGenChain(t *testing.T) {
	testWotsGenChain(NewContextFromOid(false, 1), "2dd7fcc039afb02d35c4b370172a7714b909d74a6ef2463538e87b05ab573d18", t)
	testWotsGenChain(NewContextFromOid(false, 4), "9b4cda48d43e57bf4b5eb57c7bd86126d523517f9f27dbe287c8501d3c00f4f1e37fab649ac4bec337bc92623acc837af3ac5be17ed1624a335eb02d0771a68c", t)
	testWotsGenChain(NewContextFromOid(false, 7), "14f78e435e3758a862fedea60af053374390d9cc3b140a2221e03281b2d84cf0", t)
	testWotsGenChain(NewContextFromOid(false, 10), "252e91e199a755ef156c9671f1e35d1853653f2956a167bc548ae3def7fc7f0842f2825ed674c212cb156c0c2908c8d3835d22c5aaf1140bcc0cffdc8b96b89f", t)
}

func testWotsPkGen(ctx *Context, expect string, t *testing.T) {
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	valHash := sha256.Sum256(
		ctx.wotsPkGen(ctx.newScratchPad(),
			ctx.precomputeHashes(pubSeed, skSeed), address(addr)))
	valHashPref := hex.EncodeToString(valHash[:8])
	if valHashPref != expect {
		t.Errorf("%s hash of wotsPkGen return value starts with %s instead of %s", ctx.Name(), valHashPref, expect)
	}
}

func TestWotsPkGen(t *testing.T) {
	testWotsPkGen(NewContextFromOid(false, 1), "6a796e5e8c68a83d", t)
	testWotsPkGen(NewContextFromOid(false, 4), "16d2cc6a8313c1ce", t)
	testWotsPkGen(NewContextFromOid(false, 7), "c4bc21424790e484", t)
	testWotsPkGen(NewContextFromOid(false, 10), "776f57dd57898069", t)
}

func testWotsSign(ctx *Context, expect string, t *testing.T) {
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var msg []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	valHash := sha256.Sum256(
		ctx.wotsSign(ctx.newScratchPad(), msg, pubSeed, skSeed, address(addr)))
	valHashPref := hex.EncodeToString(valHash[:8])
	if valHashPref != expect {
		t.Errorf("%s hash of wotsSign return value starts with %s instead of %s", ctx.Name(), valHashPref, expect)
	}
}

func TestWotsSign(t *testing.T) {
	testWotsSign(NewContextFromOid(false, 1), "81aae34c799751d3", t)
	testWotsSign(NewContextFromOid(false, 4), "f3506bcdddda4a6b", t)
	testWotsSign(NewContextFromOid(false, 7), "d68aaeaddda3d555", t)
	testWotsSign(NewContextFromOid(false, 10), "f530147152ac0893", t)
}

func testWotSignThenVerify(ctx *Context, t *testing.T) {
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var msg []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	sig := ctx.wotsSign(ctx.newScratchPad(), msg, pubSeed, skSeed, address(addr))
	pk1 := ctx.wotsPkFromSig(ctx.newScratchPad(), sig, msg,
		ctx.precomputeHashes(pubSeed, nil), address(addr))
	pk2 := ctx.wotsPkGen(ctx.newScratchPad(),
		ctx.precomputeHashes(pubSeed, skSeed), address(addr))
	if !bytes.Equal(pk1, pk2) {
		t.Errorf("%s verification of signature failed", ctx.Name())
	}
}

func TestWotsSignThenVerify(t *testing.T) {
	testWotSignThenVerify(NewContextFromOid(false, 1), t)
	testWotSignThenVerify(NewContextFromOid(false, 4), t)
	testWotSignThenVerify(NewContextFromOid(false, 7), t)
	testWotSignThenVerify(NewContextFromOid(false, 10), t)

	ctx, _ := NewContext(Params{Func: SHA2, N: 16, WotsW: 256, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
	ctx, _ = NewContext(Params{Func: SHA2, N: 16, WotsW: 16, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
	ctx, _ = NewContext(Params{Func: SHA2, N: 16, WotsW: 4, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
	ctx, _ = NewContext(Params{Func: SHAKE, N: 16, WotsW: 256, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
	ctx, _ = NewContext(Params{Func: SHAKE, N: 16, WotsW: 16, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
	ctx, _ = NewContext(Params{Func: SHAKE, N: 16, WotsW: 4, FullHeight: 1, D: 1})
	testWotSignThenVerify(ctx, t)
}

func BenchmarkWotsSign_SHA256_16_w16(b *testing.B) {
	benchmarkWotsSign(b, true, 16, 16)
}
func BenchmarkWotsSign_SHA256_16_w256(b *testing.B) {
	benchmarkWotsSign(b, true, 16, 256)
}
func BenchmarkWotsSign_SHAKE_16_w16(b *testing.B) {
	benchmarkWotsSign(b, false, 16, 16)
}
func BenchmarkWotsSign_SHAKE_16_w256(b *testing.B) {
	benchmarkWotsSign(b, false, 16, 256)
}
func BenchmarkWotsSign_SHAKE_32_w16(b *testing.B) {
	benchmarkWotsSign(b, false, 32, 16)
}
func BenchmarkWotsSign_SHAKE_32_w256(b *testing.B) {
	benchmarkWotsSign(b, false, 32, 256)
}

func benchmarkWotsSign(b *testing.B, sha bool, N uint32, WotsW uint16) {
	f := SHA2
	if !sha {
		f = SHAKE
	}

	ctx, _ := NewContext(Params{
		Func:       f,
		N:          N,
		FullHeight: 10,
		D:          1,
		WotsW:      WotsW,
	})
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var msg []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	out := make([]byte, ctx.wotsSigBytes)
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rand.Read(msg)
		ctx.wotsSignInto(pad, msg, ph, address(addr), out)
	}
}

func BenchmarkWotsVerify_SHA256_10(b *testing.B) {
	benchmarkWotsVerify(b, 1)
}
func BenchmarkWotsVerify_SHA256_16(b *testing.B) {
	benchmarkWotsVerify(b, 2)
}
func BenchmarkWotsVerify_SHA256_20(b *testing.B) {
	benchmarkWotsVerify(b, 3)
}
func benchmarkWotsVerify(b *testing.B, oid uint32) {
	ctx := NewContextFromOid(false, oid)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var msg []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	sig := ctx.wotsSign(pad, msg, pubSeed, skSeed, address(addr))
	ph := ctx.precomputeHashes(pubSeed, nil)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rand.Read(msg)
		ctx.wotsPkFromSigInto(pad, sig, msg, ph, address(addr), pad.wotsBuf())
	}
}

func BenchmarkWotsPkGen_SHA256_16_w16(b *testing.B) {
	benchmarkWotsPkGen(b, true, 16, 16)
}
func BenchmarkWotsPkGen_SHA256_16_w256(b *testing.B) {
	benchmarkWotsPkGen(b, true, 16, 256)
}
func BenchmarkWotsPkGen_SHAKE_16_w16(b *testing.B) {
	benchmarkWotsPkGen(b, false, 16, 16)
}
func BenchmarkWotsPkGen_SHAKE_16_w256(b *testing.B) {
	benchmarkWotsPkGen(b, false, 16, 256)
}
func BenchmarkWotsPkGen_SHAKE_32_w16(b *testing.B) {
	benchmarkWotsPkGen(b, false, 32, 16)
}
func BenchmarkWotsPkGen_SHAKE_32_w256(b *testing.B) {
	benchmarkWotsPkGen(b, false, 32, 256)
}

func benchmarkWotsPkGen(b *testing.B, sha bool, N uint32, WotsW uint16) {
	f := SHA2
	if !sha {
		f = SHAKE
	}

	ctx, _ := NewContext(Params{
		Func:       f,
		N:          N,
		FullHeight: 10,
		D:          1,
		WotsW:      WotsW,
	})
	var pubSeed []byte = make([]byte, ctx.p.N)
	var skSeed []byte = make([]byte, ctx.p.N)
	var msg []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	out := make([]byte, ctx.wotsLen*ctx.p.N)
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
		msg[i] = byte(3 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rand.Read(msg)
		ctx.wotsPkGenInto(pad, ph, address(addr), out)
	}
}
