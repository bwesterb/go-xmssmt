package xmssmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"
)

// For testing we use the following XMSSMT-SHA2_60/12_256 keypair,
// formatted as accepted by the core functions of the reference implementation
//    pk: ac655131aacd5dd041b093c7dcadd70269f8cdd6afddd4dbc52d1628f5087cb45335890d5d174a65c2bb19eb301ae9c3201842c4d710a3f820fc735860646a51
//    sk: 0000000000000000b9fcdb4826ceef80b10245650bdea01b5672f5695249b04a95abf2d33363d465f01cfb56df61b7e0a2f3d7fd6bc2b4f8426404f610192f06cce1b37ac9033d515335890d5d174a65c2bb19eb301ae9c3201842c4d710a3f820fc735860646a51ac655131aacd5dd041b093c7dcadd70269f8cdd6afddd4dbc52d1628f5087cb4

func TestDeriveAndSign(t *testing.T) {
	SetLogger(t)

	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := NewContextFromName("XMSSMT-SHA2_60/12_256")
	pubSeed := []byte{83, 53, 137, 13, 93, 23, 74, 101, 194, 187, 25, 235,
		48, 26, 233, 195, 32, 24, 66, 196, 215, 16, 163, 248, 32, 252, 115,
		88, 96, 100, 106, 81}
	skSeed := []byte{185, 252, 219, 72, 38, 206, 239, 128, 177, 2, 69, 101,
		11, 222, 160, 27, 86, 114, 245, 105, 82, 73, 176, 74, 149, 171, 242,
		211, 51, 99, 212, 101}
	skPrf := []byte{240, 28, 251, 86, 223, 97, 183, 224, 162, 243, 215, 253,
		107, 194, 180, 248, 66, 100, 4, 246, 16, 25, 47, 6, 204, 225, 179,
		122, 201, 3, 61, 81}
	sk, _, err := ctx.Derive(dir+"/key", pubSeed, skSeed, skPrf)
	if err != nil {
		t.Fatalf("Derive(): %v", err)
	}
	if !bytes.Equal([]byte{172, 101, 81, 49, 170, 205, 93, 208, 65, 176, 147,
		199, 220, 173, 215, 2, 105, 248, 205, 214, 175, 221, 212,
		219, 197, 45, 22, 40, 245, 8, 124, 180},
		sk.root) {
		t.Fatalf("Derive(): generated incorrect root")
	}
	sig, err := sk.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	valHash := sha256.Sum256(sig.Bytes())
	if hex.EncodeToString(valHash[:]) != "43d9769c0e51000137db4cb4c62cafd43b09dfec7f96a70636c959f020f28541" {
		t.Fatalf("Wrong signature")
	}
}
