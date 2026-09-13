# AGENTS.md

Guidance for AI coding agents working on `go-xmssmt`.

## What this is

A single-package Go library (`package xmssmt`, module
`github.com/bwesterb/go-xmssmt`) implementing XMSS and XMSS^MT, the
stateful hash-based signature schemes from RFC 8391 and NIST SP 800-208.
It is a cryptographic library: correctness and interoperability with other
implementations matter more than anything else. The CLI lives in a separate
repo, `github.com/bwesterb/xmssmt`.

## Layout

All code is in the repo root; there are no subpackages.

| File | Contents |
| --- | --- |
| `api.go` | Public API: `Context`, `PrivateKey`, `PublicKey`, `Signature`, `Error`, key generation, signing, verification, (un)marshalling. |
| `params.go` | `Params`, instance names/OIDs, the instance registry, name parsing (`ParamsFromName2`), WOTS+ derived sizes. `//go:generate enumer -type HashFunc` produces `hashfunc_enumer.go`. |
| `core.go` | Merkle trees, subtree generation, `scratchPad` (preallocated buffers), sequence-number bookkeeping. |
| `wots.go` | WOTS+ one-time signatures, including checksum and base-w conversion. |
| `hash.go` | F, H, H_msg, PRF, PRF_keygen constructions for SHA2/SHAKE/SHAKE256, precomputed hash prefixes, and 2-way/4-way parallel SHAKE via `cloudflare/circl`. |
| `address.go` | The 8×uint32 hash address and `SubTreeAddress`. |
| `container.go` | `PrivateKeyContainer` interface and the filesystem container (`<path>` plus `<path>.cache`, mmap'ed subtree cache, lockfile). `container_windows.go` / `container_other.go` hold the OS-specific bits. |
| `misc.go` | Big-endian helpers and the pluggable `Logger` (`SetLogger`, `EnableLogging`). |

Tests sit next to the code (`*_test.go`). `main_test.go` is the runnable
`Example` that doubles as the README sample.

## Build, test, lint

```sh
go build ./...
go test ./...            # full suite, ~6 s on a laptop
go test -short ./...     # skips the slow subtree/retirement tests
go test -bench . -run xx # benchmarks (some skip under -short)
go vet ./...
gofmt -l .               # must print nothing
```

CI (`.github/workflows/go.yml`) runs `go test ./...` on Linux, macOS and
Windows with the stable and previous Go release. Keep Windows working:
the filesystem container has had Windows-specific bugs before
(mmap, file creation), and `container_windows.go` exists for that reason.

Regenerate `hashfunc_enumer.go` with `go generate ./...` if `HashFunc`
changes (needs `enumer` on `PATH`). Do not edit the generated file.

## Conventions

- Formatting is plain `gofmt`. No other linters are configured.
- Exported functions return the package's `Error` interface (with
  `Locked()` and `Inner()`), not a bare `error`. Wrap with `wrapErrorf` /
  `errorf` from `misc.go`. `MarshalBinary`-style methods that implement
  standard interfaces return `error`.
- Hot paths avoid allocation: pass a `scratchPad` around and write results
  into caller-supplied buffers (`...Into(pad, ..., out []byte)` naming).
  Follow that pattern when touching `core.go`, `wots.go` or `hash.go`.
- `Context.Threads` controls goroutine fan-out; parallel code lives in
  `core.go` (`genSubTreeInto`) and `hash.go` (multi-lane SHAKE).
- Names like `XMSSMT-SHAKE_20/4_256` are parsed by `parseParamsFromName`.
  Suffixes `_NIST` / `_RFC` select the PRF construction, `_w4` / `_w256`
  the Winternitz parameter. Instances not in the RFC/NIST tables get OIDs
  in the reserved space; see `Params.MarshalBinary`.

## Things that must not silently change

- **Wire formats and test vectors.** `api_test.go` and `wots_test.go` check
  public keys and signatures against vectors from the XMSS reference
  implementation. Any change to hashing, addressing, WOTS+ checksums,
  key derivation, or serialization must keep those tests passing, or come
  with an explicit, documented compatibility break in the README changelog.
- **Private key derivation.** `Derive()` output is part of the contract
  (see the 1.4.0 changelog entry). Do not alter how seeds turn into keys.
- **Statefulness.** A sequence number may be used at most once. Anything
  touching `getSeqNo`, `retireSeqNo`, `BorrowExactly`, or the container's
  `SetSeqNo`/`GetSeqNo` needs to preserve that the persisted sequence number
  is advanced before a signature is released, also under concurrency and on
  `Close()`. `TestSeqNoRetirement` exercises this; do not weaken it.
- **Non-standard instances.** Two past security bugs (1.5.0, 1.6.0) were in
  the w≠16 and n=16 checksum code in `wots.go`. Test any change there with
  `w4`, `w256` and 128-bit instances, not just the RFC defaults.

## When you change behaviour

- Add an entry under `### Unreleased` in `README.md`; that section is the
  changelog. Security-relevant fixes get a clear description of impact.
- Keep the `Example` in `main_test.go` and the README snippet in sync.
- New instances go in the registry in `params.go` and should be covered by
  `params_test.go`.
- Run the full (non-`-short`) test suite before finishing.
