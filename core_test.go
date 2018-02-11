package xmssmt

import (
	"encoding/hex"
	"testing"
)

func testLTree(params *Params, expect string, t *testing.T) {
	var pk []byte = make([]byte, params.N*params.WotsLen)
	var pubSeed []byte = make([]byte, params.N)
	var addr [8]uint32
	for i := 0; i < len(pk); i++ {
		pk[i] = byte(i)
	}
	for i := 0; i < int(params.N); i++ {
		pubSeed[i] = byte(2 * i)
	}
	for i := 0; i < 8; i++ {
		addr[i] = 500000000 * uint32(i)
	}
	val := hex.EncodeToString(params.lTree(pk, pubSeed, address(addr)))
	if val != expect {
		t.Errorf("%s ltree returned %s instead of %s", params.Name(), val, expect)
	}
}

func TestLTree(t *testing.T) {
	testLTree(ParamsFromOid(false, 1), "c6686977111a5ecd45156ddc0230d71a6149fc9d640619e617efa10f406367a9", t)
	testLTree(ParamsFromOid(false, 4), "493a524b6dd6ba40f62942a54e1ddf25ea092fbbb533e2cd4d1320c990b4d23a190b33a01f4c71132d744f2bbd635380ef5a98521729b95c4ac5b227a0eabfce", t)
	testLTree(ParamsFromOid(false, 7), "b0aaf136f13436cb7f96ab4a44ffa37c57c829d684f8d1faaa02c504392aed5d", t)
	testLTree(ParamsFromOid(false, 10), "17ebcd47a802b2fff66c983310e9b6f261d4052f478bd76ccde0df471b784d27192e4018a444eb3667f13521c3b146a17cf2503e71677ca4b5946dcc02bb8f81", t)
}

func BenchmarkGenLeafSHA2_256(b *testing.B) {
	benchmarkGenLeaf(ParamsFromOid(false, 1), b)
}
func BenchmarkGenLeafSHA2_512(b *testing.B) {
	benchmarkGenLeaf(ParamsFromOid(false, 4), b)
}
func BenchmarkGenLeafSHAKE_256(b *testing.B) {
	benchmarkGenLeaf(ParamsFromOid(false, 7), b)
}
func BenchmarkGenLeafSHAKE_512(b *testing.B) {
	benchmarkGenLeaf(ParamsFromOid(false, 10), b)
}

func benchmarkGenLeaf(params *Params, b *testing.B) {
	skSeed := make([]byte, params.N)
	pubSeed := make([]byte, params.N)
	var lTreeAddr, otsAddr address
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		params.genLeaf(skSeed, pubSeed, lTreeAddr, otsAddr)
	}
}
