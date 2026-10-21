# Independent APCC-1 Go verifier

This module verifies APCC-1 detached certificates without importing, invoking,
or generating code from the Python implementation. It has three modes:

```bash
go run ./cmd/apcc-verify historical --certificate envelope.json --trust trust.json
go run ./cmd/apcc-verify causal --certificate envelope.json --trust trust.json \
  --predecessor DIGEST=parent-envelope.json --max-depth 64 \
  --max-certificates 4096 --max-total-bytes 67108864
go run ./cmd/apcc-verify current --certificate envelope.json --trust trust.json \
  --authority-status status.json --request-nonce NONCE --now-ms UNIX_MS \
  --highest-trust-log-sequence SEQUENCE --highest-trust-log-head DIGEST \
  --maximum-staleness-ms BOUND
```

Every invocation writes exactly one compact JSON object. Verification success
exits `0`, protocol rejection exits `1`, and CLI/I/O misuse exits `2`.

The historical mode proves canonical bytes, certificate and statement digests,
role-scoped signatures, internal bindings, predecessor-root consistency, and
attestation validity at commit time. Causal mode additionally resolves every
predecessor by payload digest, compares all six reference fields, and enforces
explicit depth, distinct-certificate, and aggregate-byte limits. Current mode
instead proves one nonce-bound signed status relative to caller-supplied time,
staleness, and trust-log high-water values.

An offline verifier cannot prove database linearization, current logical-node
pointers, predecessor currency, or complete transitive revocation state. Those
claims require the authority store. A valid historical certificate proves only
history; current consumption requires a fresh status from that store.

## Canonicalization qualification

`internal/jcs` is a standard-library-only RFC 8785 reference, independent of
the CJ1 parser and encoder. It is used by tests, not by certificate verification.
Its input limits are 2 MiB and 128 value levels. The qualification tests cover
all 26 rows of the official RFC 8785 Appendix B (24 finite binary64 outputs and
two nonfinite rejections), the RFC serialization and UTF-16 sorting examples,
duplicate properties, Unicode surrogate errors, and exponent boundaries.

The CJ1 differential tests establish a **subset-conformance bridge**: canonical
bytes in APCC's restricted profile agree with the independently qualified JCS
reference. APCC-CJ1 continues to reject numbers, booleans, null, non-ASCII
property names and non-NFC strings. This is not a claim that APCC accepts full
JCS, nor does canonicalizer qualification establish the other APCC-1 gates.

Primary specification: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html).
Run the qualification and module checks from this directory:

```bash
go test -count=1 ./internal/jcs ./internal/cj1
go test -count=1 ./...
go vet ./...
gofmt -l .
```
