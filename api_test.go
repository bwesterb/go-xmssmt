package xmssmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

// For testing we use the following XMSSMT-SHA2_60/12_256 keypair,
// formatted as accepted by the core functions of the reference implementation
//    pk: ac655131aacd5dd041b093c7dcadd70269f8cdd6afddd4dbc52d1628f5087cb45335890d5d174a65c2bb19eb301ae9c3201842c4d710a3f820fc735860646a51
//    sk: 0000000000000000b9fcdb4826ceef80b10245650bdea01b5672f5695249b04a95abf2d33363d465f01cfb56df61b7e0a2f3d7fd6bc2b4f8426404f610192f06cce1b37ac9033d515335890d5d174a65c2bb19eb301ae9c3201842c4d710a3f820fc735860646a51ac655131aacd5dd041b093c7dcadd70269f8cdd6afddd4dbc52d1628f5087cb4

func TestDeriveSignVerify(t *testing.T) {
	SetLogger(t)
	defer SetLogger(nil)

	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	msg := []byte("test message")
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
	sk, pk, err := ctx.Derive(dir+"/key", pubSeed, skSeed, skPrf)
	if err != nil {
		t.Fatalf("Derive(): %v", err)
	}
	if !bytes.Equal([]byte{172, 101, 81, 49, 170, 205, 93, 208, 65, 176, 147,
		199, 220, 173, 215, 2, 105, 248, 205, 214, 175, 221, 212,
		219, 197, 45, 22, 40, 245, 8, 124, 180},
		sk.root) {
		t.Fatalf("Derive(): generated incorrect root")
	}
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	sigBytes, _ := sig.MarshalBinary()
	valHash := sha256.Sum256(sigBytes[4:])
	if hex.EncodeToString(valHash[:]) != "43d9769c0e51000137db4cb4c62cafd43b09dfec7f96a70636c959f020f28541" {
		t.Fatalf("Wrong signature")
	}

	sigOk, err := pk.Verify(sig, msg)
	if !sigOk {
		t.Fatalf("Verifying signature failed: %v", err)
	}

	sigOk, _ = pk.Verify(sig, []byte("wrong message"))
	if sigOk {
		t.Fatalf("Verifying signature did not fail")
	}

	sk.seqNo = 0x26ba0043f46012f
	sig, err = sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	sigBytes, err = sig.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to MarshalBinary() signature")
	}

	valHash = sha256.Sum256(sigBytes[4:])
	if hex.EncodeToString(valHash[:]) != "3477655201e7ec8d233e0169798cc00e294b19ff0419bf7a4ee28c526f2da6e5" {
		t.Fatalf("Wrong signature")
	}

	sigOk, err = pk.Verify(sig, msg)
	if !sigOk {
		t.Fatalf("Verifying signature failed: %v", err)
	}

	sigOk, _ = pk.Verify(sig, []byte("wrong message"))
	if sigOk {
		t.Fatalf("Verifying signature did not fail")
	}

	sig2 := new(Signature)
	err = sig2.UnmarshalBinary(sigBytes)
	if err != nil {
		t.Fatalf("Failed to UnmarshalBinary signature")
	}

	sigOk, err = pk.Verify(sig2, msg)
	if !sigOk {
		t.Fatalf("Verifying unmarshaled signature failed: %v", err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to MarshalBinary PublicKey")
	}

	pk2 := new(PublicKey)
	err = pk2.UnmarshalBinary(pkBytes)
	if err != nil {
		t.Fatalf("Failed to UnmarshalBinary PublicKey")
	}

	sigOk, err = pk2.Verify(sig, msg)
	if !sigOk {
		t.Fatalf("Verifying signature with unmarshaled PublicKeyfailed: %v", err)
	}

	if err = sk.Close(); err != nil {
		t.Fatalf("sk.Close(): %v", err)
	}
}

func TestGenerateSignVerify(t *testing.T) {
	SetLogger(t)
	defer SetLogger(nil)

	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := NewContextFromName("XMSSMT-SHA2_60/12_256")
	sk, pk, err := ctx.GenerateKeyPair(dir + "/key")
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}

	testSignThenVerify(sk, pk, t)

	if err = sk.Close(); err != nil {
		t.Fatalf("sk.Close(): %v", err)
	}
}

func testSignThenVerify(sk *PrivateKey, pk *PublicKey, t *testing.T) {
	msg := []byte("test message")
	params := sk.Context().Params()
	sk.seqNo = SignatureSeqNo(rand.Int63n(
		int64(params.MaxSignatureSeqNo())))
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	sigOk, err := pk.Verify(sig, msg)
	if !sigOk {
		t.Fatalf("Verifying signature failed: %v", err)
	}
	sigOk, _ = pk.Verify(sig, []byte("wrong message"))
	if sigOk {
		t.Fatalf("Verifying signature did not fail")
	}
}

func testGenerateSignVerify(params Params, t *testing.T) {
	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, err := NewContext(params)
	if err != nil {
		t.Fatalf("NewContext(): %v", err)
	}
	sk, pk, err := ctx.GenerateKeyPair(dir + "/key")
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}
	testSignThenVerify(sk, pk, t)

	if err = sk.Close(); err != nil {
		t.Fatalf("sk.Close(): %v", err)
	}
}

func TestWotsW4(t *testing.T) {
	SetLogger(t)
	defer SetLogger(nil)
	testGenerateSignVerify(Params{SHAKE, 32, 10, 5, 4}, t)
}
func TestWotsW256(t *testing.T) {
	SetLogger(t)
	defer SetLogger(nil)
	testGenerateSignVerify(Params{SHAKE, 32, 10, 5, 4}, t)
}

func TestPrivateKeyContainer(t *testing.T) {
	SetLogger(t)
	defer SetLogger(nil)

	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := NewContextFromName("XMSSMT-SHA2_20/4_256")
	sk, pk, err := ctx.GenerateKeyPair(dir + "/key")
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}

	testSignThenVerify(sk, pk, t)
	oldSeqNo := sk.seqNo

	if err = sk.Close(); err != nil {
		t.Fatalf("sk.Close(): %v", err)
	}

	sk2, pk2, lostSigs, err := LoadPrivateKey(dir + "/key")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	if lostSigs != 0 {
		t.Fatalf("Signatures were lost")
	}
	if sk2.seqNo != oldSeqNo {
		t.Fatalf("seqNo was stored incorrectly %d %d", oldSeqNo, sk2.seqNo)
	}

	pkBytes, _ := pk.MarshalBinary()
	pk2Bytes, _ := pk2.MarshalBinary()
	if !bytes.Equal(pkBytes, pk2Bytes) {
		t.Fatalf("public key was stored incorrectly")
	}

	testSignThenVerify(sk2, pk2, t)
	if err = sk2.Close(); err != nil {
		t.Fatalf("sk2.Close(): %v", err)
	}
}
