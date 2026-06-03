# Decisions

Index of architecture & product decisions. Detailed ADRs live in
[`docs/internal/`](docs/internal/); the invariants they encode are summarized in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Standing invariants (do not change without an ADR)

| Decision | Value / rule | Rationale |
|---|---|---|
| Constitutional hash | `608508a9bd224290` | Stable identity of the canonical constitution. |
| Precedent quorum | 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`) | Byzantine-tolerant precedent setting. |
| Signed votes mandatory | `ConstitutionalMesh.submit_vote` requires Ed25519 signatures | No unauthenticated trust updates. |
| `manifold.py` is frozen | Birkhoff/Sinkhorn baseline is **not** fixed | Its uniformity collapse is the kept empirical control; `spectral_sphere.py` is the production direction. |
| `EvolutionLog` write rules | Strict monotonicity + acceleration enforced at write time | Append-only, SQLite-backed governance metrics. |
| Two-phase audit commit | Cache Phase 1 in `_retry_state`, clear only on Phase 2 success | Crash-safe Arweave audit logging. |

## Architecture Decision Records (`docs/internal/`)

| ADR / note | Topic |
|---|---|
| [`acgs_v0_1_receipt_profile_adr.md`](docs/internal/acgs_v0_1_receipt_profile_adr.md) | Governance receipt profile. |
| [`acgs_v0_1_verifier_first_scope.md`](docs/internal/acgs_v0_1_verifier_first_scope.md) | Verifier-first scope for v0.1. |
| [`rust_core_protocol_adr.md`](docs/internal/rust_core_protocol_adr.md) | Rust core protocol direction. |
| [`abliteration_threat_model.md`](docs/internal/abliteration_threat_model.md) | Abliteration threat model + defense mapping. |
| [`governance_benchmark_plan.md`](docs/internal/governance_benchmark_plan.md) | Governance benchmark methodology. |
| [`swebench_swarm_backend_and_recovery.md`](docs/internal/swebench_swarm_backend_and_recovery.md) | SWE-bench swarm backend + recovery. |
| [`acgs_v0_1_standards_research.md`](docs/internal/acgs_v0_1_standards_research.md), [`claims_map.md`](docs/internal/claims_map.md), [`gap_register.md`](docs/internal/gap_register.md) | Standards research, claims mapping, gap register. |

(See [`docs/internal/`](docs/internal/) for the full set, including audits and checklists.)

## Tooling decisions (this workspace)

| Decision | Choice | Rationale |
|---|---|---|
| Dependency/runner | `uv` + `uv.lock` | Reproducible installs; the system interpreter is `python3` with no global pip/ruff/pytest. |
| Standalone setup | `uv sync --no-sources` (in `make setup`) | `pyproject` pins `acgs-lite = { workspace = true }` for monorepo dev; a standalone clone resolves it from PyPI instead. See [BLOCKERS.md](BLOCKERS.md) B1. |
| Pytest path | `pythonpath = ["src", "."]` | A few tests `import scripts.*`; repo root must be importable when running from root. |
| Static analysis | ruff only (no mypy/pyright yet) | Recorded as [BLOCKERS.md](BLOCKERS.md) B3; `make typecheck` runs ruff as the interim gate. |
| Single source of truth for commands | `tools/registry.yaml` | Validated by `make agent-check`; `TOOLS.md` is the human view. |

## Decisions log

### 2026-06-03 — Governed-handoff kernel hardening (make the security claims true)

A real-world validation pass found `governed_handoff.py`'s evidence bundle did not
deliver the forgery-resistance its framing implies, and the deterministic gate was
default-ALLOW. Hardened the kernel (executor side unchanged) so the repo's own
security claims hold:

| Change | Before | After |
|---|---|---|
| Evidence bundle integrity | `verify_bundle` only re-checked chain self-consistency → a coherent chain fabricated from scratch verified green (verifier == forger) | `build_bundle` optionally Ed25519-signs a domain-separated attestation pre-image (`BUNDLE_SIG_DOMAIN`, binds chain_hash + constitution_hash + version pin + final_state + task identity). `verify_bundle(..., trusted_public_keys=...)` REQUIRES a valid signature for `ok` when a trust anchor is supplied. Trust derives only from out-of-band keys, never the bundle-embedded key. |
| `tool_call` gate | default-ALLOW (denylist only) → `curl http://x/` ran | code-owned default-DENY allowlist `DEFAULT_COMMAND_ALLOWLIST = (python, python3, pytest)`; constitution may extend, never weaken the default |
| Constitution version pin | `608508a9bd224290` computed + emitted but never compared | `_intake` fails closed if the constitution **declares** a `constitutional_version` / `constitutional_hash` that ≠ the pinned constant (enforce-if-declared; silent when undeclared, preserving existing configs) |

**New public surface:** `BundleSigner`, `verify_bundle(trusted_public_keys=...)`,
`build_bundle(constitutional_version=, signer=)`, env `ACGS_SIGNING_KEY` /
`ACGS_SIGNING_KEY_ID`, CLI `acgs-swarm verify --trusted-key KEYID=HEX`. Backward
compatible: with no signer/anchor, `verify_bundle(path)` still returns `ok` on
chain-consistency and runs stay unsigned (honestly reported as `signed: false`).
The constitutional hash constant itself is **unchanged** — this only adds
enforcement that references it. Signing uses the core `cryptography` dep (no new
optional extra). Deferred: REVIEW-halts-loop and full executor loop-ification
(belong with the agent-loop work, not this correctness fix).

**Why:** the productized signed-evidence-bundle space is commoditized (Microsoft
AGT, nono, Pipelock, Fuzentry), so the durable, identity-aligned move is making
the deterministic kernel actually forgery-resistant as research.
