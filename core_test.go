package xmssmt

import (
	"encoding/hex"
	"testing"
)

func testLTree(ctx *Context, expect string, t *testing.T) {
	var pk []byte = make([]byte, ctx.p.N*ctx.wotsLen)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < len(pk); i++ {
		pk[i] = byte(i)
	}
	for i := 0; i < int(ctx.p.N); i++ {
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.lTree(ctx.newScratchPad(), pk,
		ctx.precomputeHashes(pubSeed, nil), address(addr)))
	if val != expect {
		t.Errorf("%s ltree returned %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestLTree(t *testing.T) {
	testLTree(NewContextFromOid(false, 1), "c6686977111a5ecd45156ddc0230d71a6149fc9d640619e617efa10f406367a9", t)
	testLTree(NewContextFromOid(false, 4), "493a524b6dd6ba40f62942a54e1ddf25ea092fbbb533e2cd4d1320c990b4d23a190b33a01f4c71132d744f2bbd635380ef5a98521729b95c4ac5b227a0eabfce", t)
	testLTree(NewContextFromOid(false, 7), "b0aaf136f13436cb7f96ab4a44ffa37c57c829d684f8d1faaa02c504392aed5d", t)
	testLTree(NewContextFromOid(false, 10), "17ebcd47a802b2fff66c983310e9b6f261d4052f478bd76ccde0df471b784d27192e4018a444eb3667f13521c3b146a17cf2503e71677ca4b5946dcc02bb8f81", t)
}

func testGetWotsSeed(ctx *Context, expect string, t *testing.T) {
	var skSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		skSeed[i] = byte(i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.getWotsSeed(ctx.newScratchPad(),
		ctx.precomputeHashes(skSeed, skSeed), addr))
	if val != expect {
		t.Errorf("%s getWotsSeed returned %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestGetWotsSeed(t *testing.T) {
	testGetWotsSeed(NewContextFromOid(false, 1), "a5b6a82db4e6d116400eb532da8f95ea664bd732cb04f37de025061fe31b506a", t)
	testGetWotsSeed(NewContextFromOid(false, 4), "f0c03883bfb127a613377f130b34d67057df7697fd568597ff466dababfb76c3537a218aed8408db068dfb118a7f0d9aac5ac05b6c4a7df5bb34fd0cc788c503", t)
	testGetWotsSeed(NewContextFromOid(false, 7), "cda6b76668c433cf9a1711d21ff74cd86f61f901483181f2dd4d9a8a97f988df", t)
	testGetWotsSeed(NewContextFromOid(false, 10), "fa88a0fc3013d0d732ca613c2f541f6e2dde51272330808c1bc2eda61630ae077f2d353bc0b051e82dc144118293ab4a57ace1a89b98dcbfd12aa019ddbfd4ce", t)
}

func testGenLeaf(ctx *Context, expect string, t *testing.T) {
	var skSeed []byte = make([]byte, ctx.p.N)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var lTreeAddr, otsAddr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		otsAddr[i] = 500000000 * uint32(i)
		lTreeAddr[i] = 400000000 * uint32(i)
	}
	val := hex.EncodeToString(ctx.genLeaf(ctx.newScratchPad(),
		skSeed, ctx.precomputeHashes(pubSeed, skSeed), lTreeAddr, otsAddr))
	if val != expect {
		t.Errorf("%s genLeaf returned %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestGenLeaf(t *testing.T) {
	testGenLeaf(NewContextFromOid(false, 1), "ded138d113fe40973955ad072e901e98588c62ea0cc24e51060891fb1d8390f5", t)
	testGenLeaf(NewContextFromOid(false, 4), "e022bc5c092d56020982bf32ae930bb0891fa8a0c9bd275061d0a3696b5773d0255ab47577447f8f80bb0f611e7efb9528e5d727611931eaaf0b05875d3b83d4", t)
	testGenLeaf(NewContextFromOid(false, 7), "5d9b5a7d7641256953569f0c04e4f1da8740ccc85089206297b7128ba79e9cc1", t)
	testGenLeaf(NewContextFromOid(false, 10), "055fc759420e595ff41afae36de5a0ca4894c9af1652507714f4b4fa3c64dfdcddaf78d6e80f252d84737cd5b09c60b41d97e5be457767e20cb6cef278173ae1", t)
}

func testGenSubTree(ctx *Context, expect string, t *testing.T) {
	var skSeed []byte = make([]byte, ctx.p.N)
	var pubSeed []byte = make([]byte, ctx.p.N)
	var addr [8]uint32
	for i := 0; i < int(ctx.p.N); i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	mt := ctx.genSubTree(ctx.newScratchPad(), skSeed, pubSeed, addr)
	val := hex.EncodeToString(mt.Node(ctx.treeHeight, 0))
	if val != expect {
		t.Errorf("%s genSubTree generated root %s instead of %s", ctx.Name(), val, expect)
	}
}

func TestGenSubTree5(t *testing.T) {
	testGenSubTree(NewContextFromOid(true, 5), "8a692f3894a4d7754b7a4cf540f5ef47e6f50c28ab119a162b82769f3e6ead4d", t)
	testGenSubTree(NewContextFromOid(true, 13), "3519ceb982ee15511efbbf492378b0601d1ed5b55e0708272e2da50481bbd45dc3b150f8afd6644b673750f724ba81a539565b1bbed44653280314626c89972d", t)
}

func TestGenSubTree10(t *testing.T) {
	testGenSubTree(NewContextFromOid(true, 1), "bfe8b34813f7d878ded6a4433431204412351162db29d33bccd905d61c1411e4", t)
}

func TestGenSubTree16(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping genSubTree of 2^16")
	}
	testGenSubTree(NewContextFromOid(false, 2), "fd41b44b25d0cf78b0243ffc8c783530f8ad9dd3ec3d1fd9d997245fb2fb7726", t)
}

func TestMerkleTree(t *testing.T) {
	var th uint32 = 3
	var h, i uint32
	mt := newMerkleTree(th, 2)
	for h = 0; h < th; h++ {
		for i = 0; i < 1<<(th-h-1); i++ {
			mt.Node(h, i)[0] = byte(h)
			mt.Node(h, i)[1] = byte(i)
		}
	}
	for h = 0; h < th; h++ {
		for i = 0; i < 1<<(th-h-1); i++ {
			if mt.Node(h, i)[0] != byte(h) ||
				mt.Node(h, i)[1] != byte(i) {
				t.Errorf("Node (%d,%d) has wrong value", h, i)
			}
		}
	}
}

func BenchmarkGenSubTree5SHA2_256(b *testing.B) {
	benchmarkGenSubTree(NewContextFromOid(true, 0x8), b)
}
func BenchmarkGenSubTree5SHA2_512(b *testing.B) {
	benchmarkGenSubTree(NewContextFromOid(true, 0x10), b)
}
func BenchmarkGenSubTree5SHAKE_256(b *testing.B) {
	benchmarkGenSubTree(NewContextFromOid(true, 0x18), b)
}
func BenchmarkGenSubTree5SHAKE_512(b *testing.B) {
	benchmarkGenSubTree(NewContextFromOid(true, 0x20), b)
}
func BenchmarkGenSubTree10SHA2_256(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping genSubTree 2^10")
	}
	benchmarkGenSubTree(NewContextFromOid(false, 0x1), b)
}
func BenchmarkGenSubTree16SHA2_256(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping genSubTree 2^16")
	}
	benchmarkGenSubTree(NewContextFromOid(false, 0x2), b)
}

func benchmarkGenSubTree(ctx *Context, b *testing.B) {
	skSeed := make([]byte, ctx.p.N)
	pubSeed := make([]byte, ctx.p.N)
	pad := ctx.newScratchPad()
	var addr address
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.genSubTree(pad, skSeed, pubSeed, addr)
	}
}

func BenchmarkGenLeafSHA2_256(b *testing.B) {
	benchmarkGenLeaf(NewContextFromOid(false, 1), b)
}
func BenchmarkGenLeafSHA2_512(b *testing.B) {
	benchmarkGenLeaf(NewContextFromOid(false, 4), b)
}
func BenchmarkGenLeafSHAKE_256(b *testing.B) {
	benchmarkGenLeaf(NewContextFromOid(false, 7), b)
}
func BenchmarkGenLeafSHAKE_512(b *testing.B) {
	benchmarkGenLeaf(NewContextFromOid(false, 10), b)
}

func benchmarkGenLeaf(ctx *Context, b *testing.B) {
	skSeed := make([]byte, ctx.p.N)
	pubSeed := make([]byte, ctx.p.N)
	var lTreeAddr, otsAddr address
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.genLeaf(ctx.newScratchPad(), skSeed,
			ctx.precomputeHashes(pubSeed, skSeed), lTreeAddr, otsAddr)
	}
}
