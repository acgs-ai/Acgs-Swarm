---
date: 2026-06-01
topic: dsse-intoto-receipt-projector
focus: Rung 1 of externally-verifiable governance receipts
mode: repo-grounded
status: completed
origin: docs/ideation/ (surprise-me ideation run e1190504 — idea #1, Rung 1)
---

# feat: DSSE / in-toto projector for governance receipts (Rung 1)

## Summary

Add a **one-way projector** that renders an existing `GovernanceReceipt` as an
in-toto Statement wrapped in a DSSE envelope, so external supply-chain tooling
(cosign, in-toto verifiers) can read ACGS governance receipts. This is **Rung 1**
of the "externally-verifiable receipts" direction — it deliberately does **not**
build the Merkle log, inclusion/consistency proofs, or gossip witnessing (Rungs
2-4). The projector is purely additive: a new module
`src/constitutional_swarm/governance_receipts_dsse.py` plus tests. No existing
receipt model, digest, hash, or `verify_bundle` semantics change.

The load-bearing design constraint: **DSSE's signing pre-image (PAE) differs from
the receipt's existing detached-signature pre-image**, so historical receipt
signatures cannot be reused as DSSE signatures. The projector therefore emits an
**unsigned** DSSE envelope for legacy receipts (explicitly marked as a projection
to re-verify against the original), and supports **opt-in DSSE signing for new
receipts** at projection time given an Ed25519 key.

---

## Problem Frame

`governance_receipts.py` ships a "local in-toto/DSSE-**shaped**" receipt profile
(`PROFILE_VERSION = "acgs.local.intoto-dsse-shaped.v0.1"`) that is explicitly
**not** an implementation of in-toto, DSSE, SCITT, Sigstore, COSE, or W3C VC. The
`gap_register.md` row `GAP-V01-PORTABLE-RECEIPTS` records this as a closed boundary
with "migration notes for future SCITT, Sigstore/Rekor, COSE, and W3C VC
alignment." Today a receipt can only be verified by ACGS's own
`acgs-verify-receipts` CLI over a full bundle — no external tool can read it.

Rung 1 closes the smallest, highest-value slice of that gap: a **projection** to
the canonical in-toto Statement + DSSE envelope shapes, so the receipts become
*readable and (optionally) verifiable* by the existing sigstore/in-toto ecosystem
— **without** ACGS claiming standards compliance and without touching the
authoritative receipt model.

### Scope boundary

**In scope:** in-toto Statement projection, DSSE envelope (unsigned + opt-in
signed), DSSE PAE, a verifier helper for signed envelopes, tests.

### Deferred to Follow-Up Work (out of scope for this plan)

- **Rung 2-3:** Merkle tree / signed tree head (STH) over the receipt log;
  inclusion and consistency proofs.
- **Rung 4:** gossiped STH witnessing / split-view detection.
- SCITT / Sigstore-Rekor **upload/transparency-log submission**.
- CLI changes to `governance_receipts_cli.py` beyond what tests need to exercise
  the projector (no new `acgs-verify-receipts` subcommands this PR).
- Modifying `build_receipt`, `verify_bundle`, or any receipt model.
- Re-signing or migrating historical receipts.

### Outside this product's identity

- Claiming in-toto / DSSE / SCITT / Sigstore **compliance or certification**.
  The profile stays "-shaped"; this projector stays a "projection." (Enforced by
  a claim-boundary test — see U2.)

---

## Requirements

- **R1.** `to_in_toto_statement(receipt)` returns a canonical in-toto Statement v1
  dict: `_type` = in-toto Statement type, `subject` built from
  `payload.evidence_hashes`, `predicateType` = an ACGS-owned URI, `predicate`
  carrying the governance fields (decision, roles, validator_votes,
  previous_receipt_hash, policy info, rejected_alternative, metadata, and the
  source `payload_digest`).
- **R2.** `to_dsse_envelope(receipt, *, signer=None)` returns a DSSE envelope:
  `payloadType` = in-toto media type, `payload` = base64(canonical statement JSON),
  `signatures` = `[]` when `signer is None`, else one Ed25519 signature over the
  **DSSE PAE**.
- **R3.** PAE is the spec construction `DSSEv1 SP len(type) SP type SP len(body) SP body`
  and is verified against the authoritative DSSE known-answer vector.
- **R4.** Legacy/unsigned projections are explicitly distinguishable: an unsigned
  envelope carries a non-claim marker and `verify_dsse_envelope` returns an
  `unsigned_projection` status (never "valid").
- **R5.** Historical receipt signatures are **never** copied into the DSSE
  `signatures` array (different pre-image). Signing only happens when a caller
  supplies a key for a new projection.
- **R6.** `verify_dsse_envelope(envelope, *, trusted_public_keys)` round-trips the
  PAE and returns a structured result for signed envelopes (valid / invalid /
  unsigned_projection / untrusted_key).
- **R7.** No "compliant"/"certified"/"compliance" wording in public symbols,
  constants, or docstrings; the profile string stays "-shaped". Reuse
  `canonical_json_bytes`/`sha256_hex` — no second canonicalization scheme. No new
  dependencies (cryptography + pydantic already present).

---

## Key Technical Decisions

### KTD1 — New standalone module, strictly additive
The projector lives in `src/constitutional_swarm/governance_receipts_dsse.py` and
imports from `governance_receipts.py`. It does **not** modify `build_receipt`,
`verify_bundle`, `payload_digest`, `receipt_hash`, or any model. *Rationale:* the
receipt model is the authoritative audit artifact and is referenced by
`gap_register` closure evidence; a projection must not risk its byte-stability.
New public names are exported via the new module's own `__all__` only — we do
**not** touch the top-level package `__init__` (avoids the known `__all__`
discoverability drift, out of scope here).

### KTD2 — Reuse the existing canonicalization, don't invent a second
Statement → bytes uses `canonical_json_bytes` (json `sort_keys`, `(",",":")`,
`ensure_ascii=True`). *Rationale:* a divergent canonical scheme would create a
third hashing regime and break determinism guarantees; the constraint is explicit
in the feature request.

### KTD3 — PAE pre-image ≠ receipt signature pre-image → legacy = unsigned projection
The receipt's `SignatureRecord` signs `payload_canonical_bytes` directly; DSSE
signs `PAE(payloadType, base64payload)`. These are different byte strings, so an
existing `signature_hex` is **meaningless** as a DSSE signature. *Decision:* for a
receipt without a re-signable key, emit `signatures: []` plus an explicit
`_acgs_non_claim` marker in the envelope; only produce a DSSE signature when a
caller passes a key (new-receipt path). *Rationale:* fabricating a DSSE signature
from the old one would be a silent integrity lie.

### KTD4 — Canonical type URIs for interop, ACGS-owned predicateType, non-claim wording
Use the real in-toto Statement `_type` and the in-toto DSSE media `payloadType`
(this is what makes the projection *readable* by in-toto tooling), and an
ACGS-owned `predicateType` (e.g. `https://acgs.ai/attestations/governance-receipt/v0.1`).
*Rationale:* using the standard envelope/type strings is required for a projection
to be useful; the **claim boundary** is about not asserting compliance/certification
in prose or profile strings, not about avoiding the type URIs. The
`profile_version` carried in the predicate stays the `...intoto-dsse-shaped.v0.1`
string. Enforced by the U2 claim-boundary test and consistent with
`GAP-V01-PORTABLE-RECEIPTS`.

### KTD5 — Evidence-digest algorithm is sha256, validated fail-closed
`evidence_hashes` is `dict[str,str]` with no recorded algorithm, but the v0.1
profile hashes with sha256 throughout (`sha256_hex`). The in-toto `subject`
digest set requires an algorithm label, so we label `sha256` and **validate each
digest is 64-char lowercase hex**; a non-conforming digest raises `ValueError`
(fail-closed) rather than emitting a mislabeled subject. *Rationale:* honest
projection over silent mislabeling; matches the receipt module's fail-closed
posture.

### KTD6 — `DsseSigner` value object, not a raw key
Signing takes a small `DsseSigner` (a frozen dataclass binding `key_id: str` +
`private_key: Ed25519PrivateKey`), mirroring `SignatureRecord.key_id`. *Rationale:*
keeps key-id provenance in the DSSE `keyid` field and keeps the signature API
symmetric with the existing receipt signature record.

---

## High-Level Technical Design

Data flow (projection + verify). Authoritative; prose governs on any disagreement.

```mermaid
flowchart TD
    R[GovernanceReceipt] --> S[to_in_toto_statement -> dict]
    S --> CB[canonical_json_bytes  reused]
    CB --> P64[base64 payload]
    P64 --> ENV[DSSE envelope: payloadType, payload, signatures]
    P64 --> PAE[PAE: DSSEv1 SP len type SP type SP len payload SP payload]
    PAE --> SIG{signer provided?}
    SIG -->|no| U[signatures = [] + _acgs_non_claim marker]
    SIG -->|yes, Ed25519| G[signatures = [keyid, sig over PAE]]
    U --> ENV
    G --> ENV
    ENV --> V[verify_dsse_envelope]
    V --> VR{signatures empty?}
    VR -->|yes| UP[status: unsigned_projection]
    VR -->|no| CK[recompute PAE, Ed25519 verify vs trusted_public_keys]
    CK --> OK[status: valid / invalid / untrusted_key]
```

---

## Output Structure

```text
src/constitutional_swarm/
  governance_receipts.py          # unchanged (imported from)
  governance_receipts_dsse.py     # NEW — projector module (U1)
tests/
  test_governance_receipts_dsse.py  # NEW — projector tests (U2)
docs/internal/
  acgs_v0_1_receipt_profile_adr.md  # MODIFIED — add non-claim projection note (U3)
```

---

## Implementation Units

### U1. `governance_receipts_dsse.py` — the projector module

**Goal:** Implement the in-toto Statement projection, DSSE envelope (unsigned +
opt-in signed), PAE, the `DsseSigner` value object, and `verify_dsse_envelope`.

**Requirements:** R1, R2, R3, R4, R5, R6, R7.

**Dependencies:** none (imports existing `governance_receipts.py`).

**Files:**
- `src/constitutional_swarm/governance_receipts_dsse.py` (create)

**Approach:**
- Module docstring states: "One-way **projection** of a local v0.1 governance
  receipt to in-toto Statement / DSSE envelope shapes. Not an implementation of,
  and not a compliance claim against, in-toto / DSSE / SCITT / Sigstore."
- Constants: `STATEMENT_TYPE` (in-toto Statement v1 type URI), `DSSE_PAYLOAD_TYPE`
  (in-toto JSON media type), `PREDICATE_TYPE` (ACGS-owned URI),
  `UNSIGNED_PROJECTION_NOTE` (human-readable non-claim string),
  `EVIDENCE_DIGEST_ALG = "sha256"`. Module `__all__` lists the public functions
  and `DsseSigner`.
- `DsseSigner` — frozen dataclass `{key_id: str, private_key: Ed25519PrivateKey}`.
- `to_in_toto_statement(receipt) -> dict`: build `subject` from
  `receipt.payload.evidence_hashes` as `[{"name": name, "digest": {"sha256": digest}}]`
  after validating each digest is 64-char lowercase hex (else `ValueError`); sort
  subjects by name for determinism. `predicate` carries `receipt_id, action,
  policy_version, policy_hash, decision, roles (dumped), validator_votes (dumped),
  rejected_alternative, previous_receipt_hash, metadata, profile_version`, and
  `source_payload_digest = receipt.payload_digest`.
- `_pae(payload_type: str, payload: bytes) -> bytes`: exact DSSE PAE construction.
- `to_dsse_envelope(receipt, *, signer: DsseSigner | None = None) -> dict`:
  `payload = base64.standard_b64encode(canonical_json_bytes(statement))`;
  `payloadType = DSSE_PAYLOAD_TYPE`; when `signer is None` → `signatures: []` and
  add `_acgs_non_claim: UNSIGNED_PROJECTION_NOTE`; when signer present →
  `signatures: [{"keyid": signer.key_id, "sig": base64(ed25519_sign(_pae(...)))}]`
  (no `_acgs_non_claim`). **Never** read `receipt.signatures` into the envelope.
- `verify_dsse_envelope(envelope, *, trusted_public_keys: Mapping[str, str]) -> dict`:
  if `signatures` empty → `{"status": "unsigned_projection", ...}`; else recompute
  PAE from `payloadType` + `payload`, look up `keyid` in `trusted_public_keys`
  (hex Ed25519 pubkey); missing key → `untrusted_key`; signature check →
  `valid`/`invalid`. Return a plain dict (consistent with the module's
  serialization-first style) — do not introduce a pydantic model unless a test
  needs one.

**Patterns to follow:**
- Canonicalization + hashing: `canonical_json_bytes`, `sha256_hex` from
  `governance_receipts.py`.
- Ed25519 usage: `cryptography.hazmat.primitives.asymmetric.ed25519`
  (`Ed25519PrivateKey.generate()`, `.sign()`, `Ed25519PublicKey.from_public_bytes`,
  `.verify()`) — mirror `tests/test_private_vote.py` and `src/.../mesh`.
- Model dumping: `model_dump(mode="json", exclude_none=False)` as receipts do.
- Module-docstring header style (no AGPL banner; triple-quoted docstring first),
  matching `merkle_crdt.py`.

**Test scenarios:** see U2 (tests live in their own unit/file).

**Verification:** module imports cleanly; `ruff check src/` clean; the U2 test
file passes.

---

### U2. `test_governance_receipts_dsse.py` — projector tests

**Goal:** Prove the projection contract, PAE correctness, both signing paths, the
unsigned-legacy path, the evidence-digest guard, and the claim boundary.

**Requirements:** R1-R7.

**Dependencies:** U1.

**Files:**
- `tests/test_governance_receipts_dsse.py` (create)

**Approach:** Build a valid `ReceiptPayload`/`GovernanceReceipt` via the existing
`build_receipt` (reuse any helper/fixtures from `tests/test_governance_receipts.py`)
and project it. Run via `pytest --import-mode=importlib`.

**Test scenarios:**
- **Statement shape (happy path):** `to_in_toto_statement` returns `_type ==
  STATEMENT_TYPE`, `predicateType == PREDICATE_TYPE`, `subject` is the
  name-sorted `[{"name","digest":{"sha256":...}}]` derived from `evidence_hashes`,
  and `predicate["source_payload_digest"] == receipt.payload_digest` with decision,
  roles, and validator_votes present.
- **Deterministic canonical bytes:** `canonical_json_bytes(to_in_toto_statement(r))`
  is byte-identical across two calls and stable under input key reordering.
- **PAE known-answer vector:** `_pae("http://example.com/HelloWorld", b"hello world")
  == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"` (authoritative DSSE
  spec example).
- **Signed new-receipt round-trip (happy path):** with a generated `DsseSigner`,
  `to_dsse_envelope(r, signer=...)` yields one signature; `verify_dsse_envelope`
  with the matching trusted pubkey returns `status == "valid"`.
- **Tamper detection (error path):** mutating the envelope `payload` after signing
  makes `verify_dsse_envelope` return `status == "invalid"`.
- **Untrusted key (error path):** verifying a signed envelope with an empty/wrong
  `trusted_public_keys` returns `status == "untrusted_key"`.
- **Unsigned legacy projection:** `to_dsse_envelope(r)` (no signer) →
  `signatures == []` and `_acgs_non_claim` present; `verify_dsse_envelope` returns
  `status == "unsigned_projection"` (never "valid").
- **No signature fabrication (R5):** a receipt carrying a real `SignatureRecord`
  (ed25519) projected without a signer still yields `signatures == []` — the old
  `signature_hex` does not leak into the envelope.
- **Evidence-digest guard (edge/error):** an evidence digest that is not 64-char
  lowercase hex raises `ValueError`; a valid 64-hex digest passes.
- **Claim boundary (R7):** assert none of the module's public string constants /
  `predicateType` / docstring contain `"compliant"`, `"certified"`, or
  `"compliance"`; assert the projected `predicate["profile_version"]` still ends
  with `"intoto-dsse-shaped.v0.1"`.

**Verification:** all scenarios pass under `pytest tests/test_governance_receipts_dsse.py
--import-mode=importlib`; full suite still green (`1651 passed`-class baseline
unchanged + new tests).

---

### U3. Non-claim projection note in the receipt-profile ADR

**Goal:** Record the projector as a forward-alignment step while preserving the
non-claim boundary, so docs and `gap_register` stay coherent.

**Requirements:** R7 (claim discipline), traceability.

**Dependencies:** U1.

**Files:**
- `docs/internal/acgs_v0_1_receipt_profile_adr.md` (modify — append a short
  "DSSE/in-toto projection (non-claim)" subsection)

**Approach:** Add a few lines: what the projector does, that it is a one-way
projection, that legacy receipts project **unsigned** (re-verify against the
original), that signing is opt-in for new receipts, and an explicit "this is not a
compliance claim against in-toto/DSSE/SCITT/Sigstore" sentence. Reference the new
module path. Do **not** alter the `gap_register.md` closure row (no claim status
change).

**Patterns to follow:** existing ADR tone in `docs/internal/`.

**Test expectation: none -- documentation-only unit (no behavioral change).**

**Verification:** ADR renders; wording contains the explicit non-claim sentence;
no "compliant/certified" language introduced.

---

## Risks & Dependencies

- **Over-claim wording risk** (the project's stated highest claim-integrity risk):
  using real in-toto type strings could read as a compliance claim. *Mitigation:*
  KTD4 + the U2 claim-boundary test + the U3 non-claim ADR note.
- **Evidence-digest algorithm ambiguity:** receipts don't record the hash alg.
  *Mitigation:* KTD5 fail-closed 64-hex validation; documented `sha256` assumption.
- **base64 variant:** DSSE uses standard RFC 4648 base64 (not url-safe). Use
  `base64.standard_b64encode`/`standard_b64decode`; covered by the round-trip test.
- **Determinism:** statement field/subject ordering must be stable. *Mitigation:*
  reuse `canonical_json_bytes` (sort_keys) + sort subjects by name; determinism
  test.
- **Dependency:** none new — `cryptography` and `pydantic` are already required.

---

## Sources & Research

- Code: `src/constitutional_swarm/governance_receipts.py` (models, `build_receipt`,
  `canonical_json_bytes`, `payload_canonical_bytes`, `sha256_hex`),
  `src/constitutional_swarm/governance_receipts_cli.py`,
  `src/constitutional_swarm/merkle_crdt.py` (header style),
  `tests/test_governance_receipts.py`, `tests/test_private_vote.py` (Ed25519 usage).
- Boundary rules: `docs/internal/gap_register.md` (`GAP-V01-PORTABLE-RECEIPTS`,
  allowed-claims section), `docs/internal/acgs_v0_1_receipt_profile_adr.md`.
- Standards (external, settled — no live web research needed): in-toto Statement
  v1 layout; DSSE envelope + PAE construction `DSSEv1 SP len(type) SP type SP
  len(body) SP body`; the DSSE spec known-answer vector used in U2.
- Origin: ideation run e1190504 (idea #1 "externally-verifiable receipts", Rung 1)
  and its deep-dive (the PAE pre-image constraint is the central design finding).
