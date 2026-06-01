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
