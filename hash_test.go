package xmssmt

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bwesterb/go-xmssmt/internal/f1600x4"
)

func testHashMessage(ctx *Context, expect string, t *testing.T) {
	msg := []byte("test message!")
	var R []byte = make([]byte, ctx.p.N)
	var root []byte = make([]byte, ctx.p.N)
	var idx uint64 = 123456789123456789
	for i := 0; i < int(ctx.p.N); i++ {
		R[i] = byte(2 * i)
		root[i] = byte(i)
	}
	hVal, err := ctx.hashMessage(ctx.newScratchPad(),
		bytes.NewReader(msg), R, root, idx)
	if err != nil {
		t.Errorf("%s hashMessage: %v", ctx.Name(), err)
		return
	}
	val := hex.EncodeToString(hVal)
	if val != expect {
		t.Errorf("%s hashMessage is %s instead of %s", ctx.Name(), val, expect)
	}
}
func TestHashMessage(t *testing.T) {
	testHashMessage(NewContextFromOid(false, 1), "153f0c190e9e929f680c61757f1a8e48c6f532d2fef936b4227d9c99aa05efdf", t)
	testHashMessage(NewContextFromOid(false, 4), "231602b3934f501086caf489aaa191befaed2b10bbc211b0516a96f11c76481383600892e4da35f20ccb6c252e1cbfb00640303efb235101b8d541544f74dce4", t)
	testHashMessage(NewContextFromOid(false, 7), "223b2516f22f4a9e3f9860455947b8a5142d0ab42032864828bad49d598d2a97", t)
	testHashMessage(NewContextFromOid(false, 10), "2ed0d21c1180d9bd82a5542f3ccf9c5b1eee8f88e60ff0fdbe01a784d456de7a3546074b8fbc03904bc4eb4cc45ae64f3e5f2e1dcf02d4d7b68719cefe19dafa", t)
}

func TestFX4(t *testing.T) {
	if !f1600x4.Available {
		t.Skip()
	}
	testFX4(t, 16)
	testFX4(t, 32)
}

func testFX4(t *testing.T, N uint32) {
	ctx, _ := NewContext(Params{Func: SHAKE, N: N, WotsW: 256, FullHeight: 1, D: 1})
	var addr [4]address
	var buf1 [4][]byte
	var in [4][]byte
	buf2 := make([]byte, ctx.p.N)
	var key []byte = make([]byte, ctx.p.N)
	for j := uint32(0); j < 4; j++ {
		buf1[j] = make([]byte, ctx.p.N)
		in[j] = make([]byte, ctx.p.N)
		for i := uint32(0); i < 8; i++ {
			addr[j][i] = i + 8*j
		}
		for i := uint32(0); i < ctx.p.N; i++ {
			in[j][i] = byte(j*ctx.p.N + i)
		}
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	pad := ctx.newScratchPad()
	ctx.fX4Into(pad, in, key, addr, buf1)
	ph := ctx.precomputeHashes(key, key)
	for j := 0; j < 4; j++ {
		ctx.fInto(pad, in[j], ph, addr[j], buf2)
		if !bytes.Equal(buf2, buf1[j]) {
			t.Fatal()
		}
	}
}

func TestPrfUintX4(t *testing.T) {
	if !f1600x4.Available {
		t.Skip()
	}
	testPrfUintX4(t, 16)
	testPrfUintX4(t, 32)
}

func testPrfUintX4(t *testing.T, N uint32) {
	ctx, _ := NewContext(Params{Func: SHAKE, N: N, WotsW: 256, FullHeight: 1, D: 1})
	var buf1 [4][]byte
	buf2 := make([]byte, ctx.p.N)
	var key []byte = make([]byte, ctx.p.N)
	for j := 0; j < 4; j++ {
		buf1[j] = make([]byte, ctx.p.N)
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	pad := ctx.newScratchPad()
	ctx.prfUint64X4Into(pad, [4]uint64{0, 1, 2, 3}, key, buf1)
	for j := 0; j < 4; j++ {
		ctx.prfUint64Into(pad, uint64(j), key, buf2)
		if !bytes.Equal(buf2, buf1[j]) {
			t.Fatalf("testPrfUintX4 N=%d", N)
		}
	}
}

func TestPrfX4(t *testing.T) {
	if !f1600x4.Available {
		t.Skip()
	}
	testPrfX4(t, 16)
	testPrfX4(t, 32)
}

func testPrfX4(t *testing.T, N uint32) {
	ctx, _ := NewContext(Params{Func: SHAKE, N: N, WotsW: 256, FullHeight: 1, D: 1})
	var addr [4]address
	var buf1 [4][]byte
	buf2 := make([]byte, ctx.p.N)
	var key []byte = make([]byte, ctx.p.N)
	for j := 0; j < 4; j++ {
		buf1[j] = make([]byte, ctx.p.N)
		for i := 0; i < 8; i++ {
			addr[j][i] = uint32(i + 8*j)
		}
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	pad := ctx.newScratchPad()
	ctx.prfAddrX4Into(pad, addr, key, buf1)
	for j := 0; j < 4; j++ {
		ctx.prfAddrInto(pad, addr[j], key, buf2)
		if !bytes.Equal(buf2, buf1[j]) {
			t.Fatal()
		}
	}
}

func testPrf(ctx *Context, expect string, t *testing.T) {
	var addr address
	var key []byte = make([]byte, ctx.p.N)
	for i := 0; i < 8; i++ {
		addr[i] = uint32(i)
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	val := hex.EncodeToString(ctx.prfAddr(ctx.newScratchPad(), addr, key))
	if val != expect {
		t.Errorf("%s prf is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestPrf(t *testing.T) {
	testPrf(NewContextFromOid(false, 1), "c2d06093b5c98d5a6274066c923e194f18e53eeaf533bca12b92b789eb6866f0", t)
	testPrf(NewContextFromOid(false, 4), "15a9ffa22a35fdf1308f08d7bfff0b049b3e4e93bbc1252f56846c775ccb00e6476073f6b02f2aba9ea514d497f6a4e71799e32ef2dfbb1f83b189f16d2acfa8", t)
	testPrf(NewContextFromOid(false, 7), "d8a7a685a78ac5f061b74a7ea9b3c0d5a2777999ddbb34bfec1877c4ae3070e1", t)
	testPrf(NewContextFromOid(false, 10), "01c350393a99aed6a215ec5369bc982a544a04a803796d31c11f32eaa07710e14a6548670b18c45ea91b36df4ee6225cb936e0639f4f344519a875aef6a492e9", t)
	testPrf(NewContextFromOid(true, 1), "c2d06093b5c98d5a6274066c923e194f18e53eeaf533bca12b92b789eb6866f0", t)
	testPrf(NewContextFromOid(true, 9), "15a9ffa22a35fdf1308f08d7bfff0b049b3e4e93bbc1252f56846c775ccb00e6476073f6b02f2aba9ea514d497f6a4e71799e32ef2dfbb1f83b189f16d2acfa8", t)
	testPrf(NewContextFromOid(true, 17), "d8a7a685a78ac5f061b74a7ea9b3c0d5a2777999ddbb34bfec1877c4ae3070e1", t)
	testPrf(NewContextFromOid(true, 25), "01c350393a99aed6a215ec5369bc982a544a04a803796d31c11f32eaa07710e14a6548670b18c45ea91b36df4ee6225cb936e0639f4f344519a875aef6a492e9", t)
}

func testF(ctx *Context, expect string, t *testing.T) {
	var in []byte = make([]byte, ctx.p.N)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		in[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.f(in, pubSeed, address(addr)))
	if val != expect {
		t.Errorf("%s f is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestF(t *testing.T) {
	testF(NewContextFromOid(false, 1), "81d77ae441c1daa5eee9897a826266dc3cc03cf2d7e1393391467655965cd7e9", t)
	testF(NewContextFromOid(false, 4), "4bc706c40b665a2e30ea47f1997a785c0e09295ae85687023e829b49f6ec95ea0cf5aaab320d4b8f0c215ce76acec674c7becade6d7eab4abd971cc3bed680aa", t)
	testF(NewContextFromOid(false, 7), "5238028f4c69e70079b3671c981afa580491eaf7bafeb98b1da51eac7927b33a", t)
	testF(NewContextFromOid(false, 10), "f473e2937f48a6685ed82508b230ba0aa1b1a362c2ba89fb1081e02885fe06f99a8e2bd6d60953222c0d8d626c3f452cdeca37ccef017dea4a9110128e6d0f85", t)
}

func testH(ctx *Context, expect string, t *testing.T) {
	var left []byte = make([]byte, ctx.p.N)
	var right []byte = make([]byte, ctx.p.N)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
		left[i] = byte(i)
		right[i] = byte(i + int(ctx.p.N))
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.h(left, right, pubSeed, address(addr)))
	if val != expect {
		t.Errorf("%s f is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestH(t *testing.T) {
	testH(NewContextFromOid(false, 1), "6ed9fa805fc4aa2ee130be19801ce4a232b002ea709a915dbe0beddb11eca4e9", t)
	testH(NewContextFromOid(false, 4), "cd341b0001f4adb53bedb31e3e54e4f4a2e520daf6d6bfeb1f2fbb5982f40adaa2c1e8b715b72644bf49b016404273ebf94ebe5b0d1911e9478ac94cd2aec537", t)
	testH(NewContextFromOid(false, 7), "3a533fcb775013ac476b09db9d59c07f9a16f5800fe5deeede8cfdb38e86634b", t)
	testH(NewContextFromOid(false, 10), "2516532c0ee77300a2e15bd6f1da565740302ab48105503ad1bf05305ed9247da9544b97acfe4790150157f937d8aa3f8deef1447295b8640c8cff0c4d4c006f", t)
}

func BenchmarkPrfAddX4(b *testing.B) {
	ctx, _ := NewContext(Params{Func: SHAKE, N: 16, WotsW: 16, FullHeight: 1, D: 1})
	var addr [4]address
	var buf1 [4][]byte
	var key []byte = make([]byte, ctx.p.N)
	for j := 0; j < 4; j++ {
		buf1[j] = make([]byte, ctx.p.N)
		for i := 0; i < 8; i++ {
			addr[j][i] = uint32(i + 8*j)
		}
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	pad := ctx.newScratchPad()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for k := 0; k < 1000; k++ {
			ctx.prfAddrX4Into(pad, addr, key, buf1)
		}
	}
}
