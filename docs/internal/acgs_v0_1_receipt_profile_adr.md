# ADR: ACGS v0.1 Local Receipt Profile

## Decision

ACGS v0.1 uses a local in-toto/DSSE-shaped governance receipt profile.

This profile is designed to be portable and verifier-first, but it is not an
implementation of in-toto, DSSE, SCITT, Sigstore/Rekor, COSE, W3C Verifiable
Credentials, or any compliance framework.

## Drivers

- v0.1 leads with governed software and DevOps fixtures.
- Step-level supply-chain evidence maps naturally to in-toto-style statements.
- Payload/signature separation maps naturally to DSSE-style envelopes.
- The first public artifact should be independently runnable without external
  transparency services, registries, credentials, or model calls.

## Receipt Boundary

The local profile records:

- action;
- policy version and policy hash;
- constitution-author, executor, validator, and auditor identities;
- evidence hashes;
- decision;
- validator votes and dissent;
- rejected alternative;
- previous receipt hash;
- canonicalization metadata;
- signature metadata.

Canonical payload bytes are generated with deterministic JSON sorting and compact
separators. This is a local canonicalization contract for v0.1 fixtures, not a
claim of RFC 8785, DSSE, or COSE canonicalization.

The local profile also does not implement DSSE Pre-Authentication Encoding (PAE),
in-toto's full Envelope/Statement/Predicate layering, or SCITT transparency-service
registration receipts. Future standards alignment should replace the local
canonicalization contract with the selected standard's signing and receipt
semantics rather than treating the current bytes as standards-compliant.

## Signature Semantics

Signatures prove only that a verifier-trusted declared key signed the canonical
payload bytes. Public keys embedded only in the receipt bundle are not trusted.
They do not prove real-world accountability, regulator-grade control, hardware
rooting, human authorization, or key custody outside the agent process.

Default verification fails closed for invalid schema, broken hash chains, missing
decisions, role-separation violations, tampering, invalid signatures, and replay
mismatch. Explicit report mode may mark signatures as unverifiable without failing
solely for that status.

## Alternatives

| alternative | decision | reason |
|---|---|---|
| Full in-toto/DSSE compliance | deferred | Too much interop surface before the verifier proves the core receipt contract. |
| SCITT-compatible transparency receipts | deferred | Strong future direction, but registry and transparency-service assumptions exceed v0.1. |
| Sigstore/Rekor integration | deferred | Valuable for public DevOps artifacts, but not required for offline conformance fixtures. |
| COSE/CBOR profile | deferred | Good compact envelope option, but less directly tied to DevOps benchmark semantics. |
| W3C Verifiable Credentials | deferred | Useful for identity alignment, but heavier than v0.1 needs. |

## Consequences

- ACGS v0.1 can ship an offline verifier and fixtures without pretending to be a
  standards implementation.
- Future migration should preserve the same action, policy, role, evidence,
  decision, and chain-continuity fields.
- Any public wording must say "local in-toto/DSSE-shaped profile" unless and
  until a standards-compliant implementation exists.
