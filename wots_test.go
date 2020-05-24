package xmssmt

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	"golang.org/x/crypto/sha3"
)

func refHash(in []byte) string {
	var tmp [10]byte
	h := sha3.NewShake128()
	h.Write(in)
	h.Read(tmp[:])
	return hex.EncodeToString(tmp[:])
}

func testWots(oid uint32, expectPk, expectSig, expectLeaf string, t *testing.T) {
	ctx := NewContextFromOid(false, oid)
	if ctx == nil {
		t.Fatalf("%d is not a valid oid", oid)
	}
	pubSeed := make([]byte, ctx.p.N)
	skSeed := make([]byte, ctx.p.N)
	msg := make([]byte, ctx.p.N)
	var addr, addr2 [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		msg[i] = byte(3 * i)
		pubSeed[i] = byte(2 * i)
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
		addr2[i] = 400000000 * uint32(i)
	}
	pad := ctx.newScratchPad()
	ph := ctx.precomputeHashes(pubSeed, skSeed)
	pk := ctx.wotsPkGen(pad, ph, address(addr))
	got := refHash(pk)
	if got != expectPk {
		t.Errorf("%s hash of wotsPkGen is %s instead of %s",
			ctx.Name(), got, expectPk)
	}

	sig := ctx.wotsSign(pad, msg, pubSeed, skSeed, address(addr))
	got = refHash(sig)
	if got != expectSig {
		t.Errorf("%s hash of wotsSign is %s instead of %s",
			ctx.Name(), got, expectSig)
	}

	pk2 := ctx.wotsPkFromSig(pad, sig, msg, ph, address(addr))
	if !bytes.Equal(pk2, pk) {
		t.Errorf("%s public key derived from signature does not match original",
			ctx.Name())
	}

	leaf := make([]byte, ctx.p.N)
	ctx.genLeafInto(pad, ph, addr, addr2, leaf)
	got = refHash(leaf)
	if got != expectLeaf {
		t.Errorf("%s hash of leaf is %s instead of %s",
			ctx.Name(), got, expectLeaf)
	}

}

func TestWots(t *testing.T) {
	testWots(1, "a5df5a7785a48961552e", "4443fb313e5b0c2e8bec", "fc27066a9b31c0069597", t)
	testWots(4, "b60e1297f5c9b328c5e8", "3ae3de6598456112261d", "1ae375ab3af144099b3d", t)
	testWots(7, "654c7f6754b55312197f", "a51bd20ef66e93d79464", "70dac71617da61947011", t)
	testWots(10, "e7462d29751df96bf5a4", "ffb59bc9bf87e4e4b7f0", "0cf456d0f4b02b341e12", t)
	// testWotsPkGen(13, "adbec5b9ba94bff3447d", "b32683d5888df51aa074", "58eb225e44f38082b356", t)
	// testWotsPkGen(16, "e008635b776020636868", "05d9a9d517021307b1a7", "2ed530d278acdf27e01d", t)
	// testWotsPkGen(19, "8f041a7c67b46fc80b0d", "98a906af2d18429309f6", "34457720369d5f7691e9", t)
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
