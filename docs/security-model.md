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
`ConstitutionalMesh.submit_vote(...)` requires signed votes.
Quorum-based settlement governs acceptance/rejection finality.

### 3) Transport boundary (optional)
Remote vote transport introduces network trust boundaries:
- signer identity and key distribution,
- transport mode selection,
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
