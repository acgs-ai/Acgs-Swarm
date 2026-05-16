# ACGS v0.1 Standards Research

Research mission: validate the v0.1 verifier-first receipt and benchmark
positioning against current standards and agent-governance benchmark surfaces.

## Verdict

Professor-critic verdict: pass.

The current implementation is safe to describe as a local in-toto/DSSE-shaped
profile only because the docs explicitly avoid claiming standards compliance. The
trusted-signer verifier fix is necessary and aligned with the source evidence:
receipts must not trust key material merely because it appears inside the object
being verified.

## Source-Backed Findings

### DSSE and in-toto

DSSE is designed to authenticate both message and type, avoid canonicalization, and
support arbitrary encodings. The v0.1 profile signs deterministic local JSON bytes,
so it must remain "DSSE-shaped" rather than DSSE-compliant.

The in-toto attestation envelope guidance expects an array of signatures, an
authenticated payload type, key-id hints, and a base64-encoded Statement payload.
It also says consumers should not rely only on media type for predicate semantics.
The v0.1 receipt has similar concepts, but not the full Envelope/Statement/Predicate
layering.

Implication: keep the current local profile boundary and migrate later to actual
DSSE/in-toto semantics if external interoperability becomes a v0.2 goal.

### SCITT

SCITT is now published as RFC 9943. Its architecture centers on signed statements
registered with a transparency service, which issues receipts after recording the
statement in an append-only verifiable data structure. It also defines CBOR/COSE
message structures and COSE receipts.

Implication: ACGS v0.1 does not issue SCITT receipts. The natural migration path is
to represent governance receipts as signed statements about agent actions and then
register them with a SCITT transparency service or compatible private service.

### Sigstore and Rekor

Sigstore keyless signing binds ephemeral keys to OIDC identities through Fulcio and
logs signing events in Rekor. Rekor provides a transparency-log witness and a
timestamped entry, shifting verification away from trusting only a long-lived key
stored by the signer.

Implication: ACGS v0.1's external trusted-signer registry is a local trust root, not
Sigstore identity binding. That is acceptable for offline fixtures, but public
artifact provenance should eventually support Sigstore/Rekor or SCITT-style
transparency.

### W3C Verifiable Credentials

W3C VC Data Model 2.0 allows conceptually aligned credential formats to describe
transformations into conforming VC documents, but only conforming documents with
valid securing mechanisms should be called compatible or compliant.

Implication: ACGS should not call v0.1 receipts Verifiable Credentials. A future VC
mapping must document whether transformation is one-way or round-trippable and
provide a test suite.

### Benchmark Overlay Positioning

SWE-bench's official evaluation applies generated patches to real repositories in
Docker and requires JSONL predictions with `instance_id`, `model_name_or_path`, and
`model_patch`. AgentDojo reports utility/security outcomes over user and injection
task combinations. TheAgentCompany evaluates agents performing real workplace-like
tasks such as browsing, coding, running programs, and communicating with coworkers.

Implication: ACGS is best positioned as a governance overlay that scores evidence
quality and forensic reconstructability on top of task benchmarks, not as a
replacement for their task-success metrics.

## Required Boundaries

- Do not claim DSSE, in-toto, SCITT, Sigstore/Rekor, COSE, or W3C VC compliance.
- Do not call local receipts SCITT receipts.
- Do not call local receipts Verifiable Credentials.
- Do not claim official SWE-bench performance without the Docker harness bundle.
- Keep DevOps as the lead v0.1 vertical and healthcare/insurance as follow-on
  positioning only.

## Recommended Follow-Ups

1. Add a v0.2 ADR that chooses between actual in-toto/DSSE, SCITT/COSE, or
   Sigstore/Rekor integration.
2. Add a sample migration table from local receipt fields to in-toto Statement and
   SCITT Signed Statement fields.
3. Keep the default offline conformance suite at zero model cost; publish optional
   frontier-model overlays separately.

## Sources

- RFC 9943, SCITT Architecture: signed statements, transparency services, and
  receipts.
- DSSE specification repository: message/type authentication and avoidance of
  canonicalization.
- in-toto Attestation Framework envelope specification: multiple signatures,
  authenticated payload type, key-id hint, and base64 Statement payload.
- Sigstore signing overview: Fulcio identity certificates and Rekor transparency
  log.
- W3C Verifiable Credentials Data Model 2.0: compatibility and conformance rules.
- SWE-bench evaluation guide: Docker evaluation and JSONL prediction fields.
- AgentDojo benchmark API: utility/security results for user/injection tasks.
- TheAgentCompany repository: workplace-style agent task benchmark.
