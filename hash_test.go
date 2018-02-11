package xmssmt

import (
	"encoding/hex"
	"testing"
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
	val := hex.EncodeToString(ctx.hashMessage(msg, R, root, idx))
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

func testPrf(ctx *Context, expect string, t *testing.T) {
	var in []byte = make([]byte, 32)
	var key []byte = make([]byte, ctx.p.N)
	for i := 0; i < 32; i++ {
		in[i] = byte(i)
	}
	for i := 0; i < int(ctx.p.N); i++ {
		key[i] = byte(i)
	}
	val := hex.EncodeToString(ctx.prf(in, key))
	if val != expect {
		t.Errorf("%s prf is %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestPrf(t *testing.T) {
	testPrf(NewContextFromOid(false, 1), "5b34e697465ed81910e190cbd8352daa476d71fe1a84e698b6417c41a0bf9e2c", t)
	testPrf(NewContextFromOid(false, 4), "7dc67cf82dc43ac1b054fefaa0c3a6ad3feb9b90495170902f9eb7b471000bee1789477aa7e7a988b4953bad0c0a7beeca108f9cf99a5eda8954a0e6803b5a93", t)
	testPrf(NewContextFromOid(false, 7), "da9469a708f4c15973880031f05f02c8e4ceb3c0b24d10087bad1107dc8b9cff", t)
	testPrf(NewContextFromOid(false, 10), "d61c393006402e9f6757cf6fbf4bb6f4541fd90ab0b1b243624bbfcd7dca15a62c83fc16d64666a87dbcc9b37038866d4a24fec910229f2139ff8dbcb9637dd9", t)
	testPrf(NewContextFromOid(true, 1), "5b34e697465ed81910e190cbd8352daa476d71fe1a84e698b6417c41a0bf9e2c", t)
	testPrf(NewContextFromOid(true, 9), "7dc67cf82dc43ac1b054fefaa0c3a6ad3feb9b90495170902f9eb7b471000bee1789477aa7e7a988b4953bad0c0a7beeca108f9cf99a5eda8954a0e6803b5a93", t)
	testPrf(NewContextFromOid(true, 17), "da9469a708f4c15973880031f05f02c8e4ceb3c0b24d10087bad1107dc8b9cff", t)
	testPrf(NewContextFromOid(true, 25), "d61c393006402e9f6757cf6fbf4bb6f4541fd90ab0b1b243624bbfcd7dca15a62c83fc16d64666a87dbcc9b37038866d4a24fec910229f2139ff8dbcb9637dd9", t)
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
