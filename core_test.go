package xmssmt

import (
	"io/ioutil"
	"os"
	"sync"
	"testing"
)

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
	var sta SubTreeAddress
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.genSubTree(pad, skSeed, pubSeed, sta)
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
	out := make([]byte, ctx.p.N)
	var lTreeAddr, otsAddr address
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.genLeafInto(ctx.newScratchPad(),
			ctx.precomputeHashes(pubSeed, skSeed), lTreeAddr, otsAddr, out)
	}
}

func TestSeqNoRetirement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TestSeqNoRetirement")
	}
	SetLogger(t)
	defer SetLogger(nil)
	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := NewContextFromName("XMSSMT-SHA2_20/4_256")
	sk, _, err := ctx.GenerateKeyPair(dir + "/key")
	sk.BorrowExactly(4000)
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(4)
	for w := 0; w < 4; w++ {
		go func() {
			for i := 0; i < 1000; i++ {
				sk.Sign([]byte("some message"))
			}
			wg.Done()
		}()
	}
	wg.Wait()

	t.Logf("unretired=%d cachedSubTrees=%d", sk.UnretiredSeqNos(),
		sk.CachedSubTrees())

	if err = sk.Close(); err != nil {
		t.Fatalf("sk.Close(): %v", err)
	}
}
