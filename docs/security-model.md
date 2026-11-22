# Security model and trust boundaries

This document complements [`SECURITY.md`](../SECURITY.md) with runtime-facing security boundaries.

## Scope
`constitutional-swarm` provides governance runtime controls and evidence paths.
It does not claim complete end-to-end security for external systems that integrate it.

## Security-relevant components
- `AgentDNA` local constitutional checks
- `ConstitutionalMesh` signed voting, quorum, settlement
- Settlement stores (`JSONLSettlementStore`, `SQLiteSettlementStore`)
- Governance receipts (`governance_receipts.py`) and verifier tooling
- Optional remote vote transport (`remote_vote_transport/`)

## Trust boundaries
### 1) Local agent boundary
`AgentDNA.validate(...)` enforces local constitutional checks before downstream acceptance.

### 2) Peer validation boundary
- **Strict-majority vs weighted-BFT vs stake vs APCC:**
  - `ConstitutionalMesh` (`mesh/core.py`) enforces equal-weight assigned-peer **strict majority** (`> 1/2`) over a complete signed electorate (persistent `SettlementStore` requires `quorum >= 3`; non-persistent defaults to `2/3`). This differs from weighted 2/3 approval + fault-domain limits in `quorum_certificate.py`, the integer-stake `2F + 1` model in `specs/mesh.tla`, and logical-node exclusivity in `apcc/`.
  - `ConstitutionalMesh.request_validation(...)` grants assignment-level uniqueness only (repeated submissions for the same logical task create distinct assignments), and there is no assignment expiry, automatic peer reassignment on RPC timeout, or late-vote protocol.
  - `ConstitutionalMesh.submit_vote(...)` requires signed Ed25519 vote envelopes; `MeshResult.accepted` on an unsettled preview (`quorum_met=False`, `settled=False`) is **never authoritative**. Authoritative consumers must require `settled=True` and `quorum_met=True` alongside complete signed evidence.

### 3) Transport boundary (optional)
Remote vote transport introduces network trust boundaries:
- signer identity and key distribution,
- transport mode selection (such as `auto`, `tls`, or `plaintext` modes in transport configuration),
- replay protections in signed request envelopes.

Use explicit trusted signer configuration for non-local deployments.

### 4) Persistence boundary
Settlement records are durability/recovery artifacts.
Persistence protects continuity and post-incident replay, but operators still need secure storage controls.

### 5) Receipt verification boundary
Receipt verification checks payload integrity, hash-linking, and signature validity per receipt profile.
This supports evidence replay, not universal attestation for every external process.

## Threats addressed (high level)
- Policy violations detectable at local enforcement points
- Invalid or unsigned votes rejected by mesh vote workflow
- Settlement replay/recovery paths with consistency checks
- Receipt tampering detectable through canonical digests and verification

## Threats not fully addressed by this package alone
- Compromised host/system where agent process runs
- Secrets management and key lifecycle outside application integration
- Network perimeter hardening and infrastructure controls
- Regulatory/compliance obligations beyond runtime evidence generation

## Operational guidance
- Keep private signing keys out of source control.
- Persist and rotate keys with your organization’s key management approach.
- Use least-privilege runtime identities.
- Run repository tests and relevant script-level checks before release.
- Report vulnerabilities through [`SECURITY.md`](../SECURITY.md).
