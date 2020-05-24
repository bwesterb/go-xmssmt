package xmssmt

import (
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

func TestXMSS(t *testing.T) {
	testXMSS(t, false, 1, "7de72d192121f414d4bb", "8b6cb278d50a3694ca38")
	testXMSS(t, false, 4, "74ee7c42b4e42a424ed9", "b9e63b0376a550eabe1b")
	testXMSS(t, false, 7, "764614ee2ce5e4bf0114", "3e9035cffa0fd4be98bd")
	testXMSS(t, false, 10, "e47fe831b6ee463e2881", "ce2dc09cd7ad8c87ae06")
	// testXMSS(t, false, 13, "5933d4b1e696804718c7", "3174d774afe25ef4020a")
	// testXMSS(t, false, 16, "cef3d38791d56efee1b3", "9939a0f87502df5d1e31")
	// testXMSS(t, false, 19, "7fa280e502275858b27b", "5759cda73cf4eee44720")
	testXMSS(t, true, 2, "9df4c75282451bf2bc53", "fd4ff4c18801147b2804")
	testXMSS(t, true, 10, "fdeb0cc4fed643bf70ce", "fbeb33a7aed7af7ea526")
	testXMSS(t, true, 18, "dbe6fc388fbd610b3401", "2c2a66cae9a16414088d")
	testXMSS(t, true, 26, "3739e7d3668932d9ca44", "ec8d62bb9d4ba74c6729")
	// testXMSS(t, true, 34, "eef50cfa8f267939ad08", "f312d051cf32d1e847e3")
	// testXMSS(t, true, 42, "2d6ae135fda1077788ca", "09a73575932668ca5e8d")
	// testXMSS(t, true, 50, "21d799da214da955d915", "090ca968b831030f31a4")
}

func testXMSS(t *testing.T, mt bool, oid uint32, expectPk, expectSig string) {
	ctx := NewContextFromOid(mt, oid)
	if ctx == nil {
		t.Fatalf("%d is not a valid oid", oid)
	}

	n := ctx.p.N
	seed := make([]byte, 3*n)
	for i := 0; i < 3*int(n); i++ {
		seed[i] = byte(i)
	}
	dir, err := ioutil.TempDir("", "go-xmssmt-tests")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	sk, pk, err := ctx.Derive(dir+"/key", seed[2*n:], seed[:n], seed[n:2*n])
	if err != nil {
		t.Fatalf("Derive(): %v", err)
	}

	pkBytes, _ := pk.MarshalBinary()
	got := refHash(pkBytes[4:]) // strip of OID
	if got != expectPk {
		t.Errorf("%s Expected public key hash %s, got %s", ctx.Name(),
			expectPk, got)
	}

	sk.DangerousSetSeqNo(SignatureSeqNo(1 << (ctx.p.FullHeight - 1)))
	sig, err := sk.Sign([]byte{37})
	if err != nil {
		t.Fatalf("%s Sign: %v", ctx.Name(), err)
	}
	sigBytes, _ := sig.MarshalBinary()
	got = refHash(sigBytes[4:]) // strip of OID
	if got != expectSig {
		t.Errorf("%s Expected signature hash %s, got %s %X", ctx.Name(),
			expectSig, got, sigBytes)
	}
}

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
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	sigBytes, _ := sig.MarshalBinary()

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
	SetLogger(t)
	defer SetLogger(nil)
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
	testGenerateSignVerify(Params{SHAKE, 16, 10, 5, 4}, t)
	testGenerateSignVerify(Params{SHAKE, 32, 10, 5, 4}, t)
	testGenerateSignVerify(Params{SHAKE, 64, 10, 5, 4}, t)
}
func TestWotsW16(t *testing.T) {
	testGenerateSignVerify(Params{SHAKE, 16, 10, 5, 16}, t)
	testGenerateSignVerify(Params{SHAKE, 32, 10, 5, 16}, t)
	testGenerateSignVerify(Params{SHAKE, 64, 10, 5, 16}, t)
}
func TestWotsW256(t *testing.T) {
	testGenerateSignVerify(Params{SHAKE, 16, 10, 5, 256}, t)
	testGenerateSignVerify(Params{SHAKE, 32, 10, 5, 256}, t)
	testGenerateSignVerify(Params{SHAKE, 64, 10, 5, 256}, t)
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
