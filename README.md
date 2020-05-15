XMSSMT for Go
-------------

This is a Go implementation of the stateful hash-based signature-scheme
XMSSMT described in [rfc8391 (XMSS: Extended Hash-Based Signatures)](
https://tools.ietf.org/html/rfc8391).

```go
package main

import (
    "github.com/bwesterb/go-xmssmt" // imported as xmssmt
    "fmt"
)

func main() {
    // Create a new keypair.  See ListNames().
    sk, pk, err := xmssmt.GenerateKeyPair("XMSSMT-SHAKE_20/4_256", "key")
    if err != nil {
        panic(err)
    }

    // Sign a message
    sig, err := sk.Sign([]byte("Example message!"))
    if err != nil {
        panic(err)
    }

    sigBytes, _ := sig.MarshalBinary() // serialize signature
    pkBytes, _ := pk.MarshalBinary()   // serialize public key
    fmt.Printf("len(sigBytes)=%d  len(pkBytes)=%d\n",
        len(sigBytes), len(pkBytes))
    sk.Close() // close the private key container

    // To verify we can simply use the Verify() method on PublicKey
    valid, _ := pk.Verify(sig, []byte("Example message!"))
    fmt.Printf("Valid=%v\n", valid)

    // Or we can use the helper xmssmt.Verify() on serialized signature and pk
    valid, _ = xmssmt.Verify(pkBytes, sigBytes, []byte("Example message!"))
    fmt.Printf("Valid=%v\n", valid)

    // To sign a new message, we open the private key container again
    sk, pk, _, _ = xmssmt.LoadPrivateKey("key")
    sig2, _ := sk.Sign([]byte("Other message"))
    valid, _ = pk.Verify(sig2, []byte("Other message"))
    fmt.Printf("Valid=%v\n", valid)
    sk.Close()

    // Or we can simply use the xmssmt.Sign() helper.
    pkBytes, _ = pk.MarshalBinary()
    sig3Bytes, _ := xmssmt.Sign("key", []byte("Third message"))
    valid, _ = xmssmt.Verify(pkBytes, sig3Bytes, []byte("Third message"))
    fmt.Printf("Valid=%v\n", valid)
}
```

See [godoc](https://godoc.org/github.com/bwesterb/go-xmssmt) for
further documentation of the API.

Note on compatibility
---------------------

`go-xmssmt` supports instances of XMSS[MT] that are (currently) not listed
in the RFC and so might not be supported by other implementations, such
as `XMSSMT-SHAKE_20/4_128_w256`.  `go-xmssmt` encodes the parameters of these
non-standard instances in the reserved space of Oid numbers,
see [`Params.MarshalBinary()`](https://godoc.org/github.com/bwesterb/go-xmssmt#Params.MarshalBinary).
For maximum compatibility, one can check whether the instance is supported
by the RFC by checking `Context.FromRFC()`.

Changes
-------

### 1.3.0 (unreleased)

- When available, use AVX2 to compute SHAKE fourway.  This makes SHAKE
  faster than SHA2.

### 1.2.0 (27-12-2019)

- Add support for instance names not listed in RFC.

### 1.1.0 (20-12-2019)

- Add support for security parameter N=16.
