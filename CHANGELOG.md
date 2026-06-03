# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

### Added
- Abliteration-hardened steering: `violation_subspace.ViolationSubspace` gained
  `orthogonalize_against(r_hat)` and `refusal_alignment(r_hat)`. The former projects
  the refusal direction `r̂` out of the governance steering subspace so the steering
  edit in the original residual space is orthogonal to `r̂` and survives abliteration
  (which only zeros write matrices along `r̂`); it handles the plain (RepE/mean-diff)
  and LEACE regimes (deflation computed in `r̃ = dewhitener @ r̂` space for LEACE) and
  multi-directional refusal sets. The latter reports the fraction of `r̂` captured by
  the subspace (∈ `[0, 1]`) to quantify exposure and verify the fix. A subspace lying
  entirely within the refusal span raises (must be refit, not hardened). Pure-NumPy,
  CI-safe; closes the "harden steering" follow-up in
  `docs/internal/abliteration_threat_model.md`.
- Static type-checking with mypy (closes BLOCKERS.md B3): `[tool.mypy]` config in
  `pyproject.toml` (`ignore_missing_imports`, with an adoption baseline that
  allow-lists modules carrying pre-existing type errors so the rest of the package
  — including new code — is checked and protected from regressions). `make
  typecheck` now runs `mypy` (was a ruff stand-in) and is part of `make verify`; a
  `typecheck` CI job gates PRs. `mypy>=1.11` added to the `dev` extra.
- Abliteration-aware quorum admission: `node_admission.AbliterationAdmissionGate`
  screens candidate validators' residual-stream write matrices with the
  abliteration detector and feeds the rejected agent ids into
  `CommitteeSelector.select(exclude=...)`, so an abliterated model cannot be
  sampled into a committee. Defaults to the `min` aggregation preset (flags if any
  single write matrix collapses), closing the minority-subset evasion the `median`
  default misses. `screen()` returns per-agent `AbliterationReport`s for the
  down-weight-instead-of-exclude alternative; `select_admissible()` is a one-call
  screen-then-select wrapper supporting the fault-domain-independent path.
  Exported as `AbliterationAdmissionGate` / `AdmissionDecision`.
- Activation-path admission: `node_admission.ActivationAdmissionGate` screens nodes
  that expose final-hidden-state activations but not write matrices, via
  `detect_from_activations` (harmful/benign separation-collapse vs. a trusted
  reference). Candidates are passed as `ActivationProbe(harmful, harmless)`; the
  `screen()` / `select_admissible()` surface matches the weight gate, so either
  modality feeds the same `CommitteeSelector.select(exclude=...)` path. Exported as
  `ActivationAdmissionGate` / `ActivationProbe`.
- `detect_from_weights` gained a configurable `aggregate` parameter
  (`"median"` default | `"mean"` | `"min"` | `"quantile"` with a `quantile` knob)
  so callers can trade robustness for minority-subset sensitivity.
- Agent-operability layer: a `Makefile` with one-command targets (`setup`, `dev`,
  `test`, `lint`, `typecheck`, `smoke`, `verify`, `agent-check`); a tool registry
  (`tools/registry.yaml` + JSON schema + runbooks) and agent registry
  (`agents/*.agent.yaml` + schema) for `researcher`/`coder`/`reviewer`/`qa`/`docs`/`release`;
  a `scripts/agent_check.py` self-validation gate wired into a new
  `agent-check` CI workflow; root entry-point docs (`ARCHITECTURE`, `PROJECT_MAP`,
  `TOOLS`, `TASKS`, `DECISIONS`, `BLOCKERS`); and `.env.example`.
- Standalone setup path documented (`uv sync --no-sources`) so a non-monorepo
  checkout resolves `acgs-lite` from PyPI.

### Fixed
- Type-checking: graduated the stable-core modules to a clean mypy pass and
  removed their `[[tool.mypy.overrides]]` allow-list entry, so they are now
  enforced. Fixes are annotation-only / behavior-preserving: `compiler` (cast the
  post-init-normalized `GoalSpec.steps`; `GoalSpec.steps` widened to a covariant
  `Sequence`), `dna` (`_stats_lock` declared as an `init=False` field), `mesh.core`
  (typed optional `RemoteVoteClient` import; cast the spectral shadow manifold),
  `governance_receipts` (`Final` literal constants), `governed_handoff`
  (narrowing + a renamed local), `private_vote` (corrected `# type: ignore` code),
  `protocol` (guard `asdict` against dataclass *types*), `remote_vote_transport`
  (`inspect.isawaitable` narrowing).
- Type-checking: graduated the remaining optional-dependency-gated subpackages
  (`bittensor`, `langgraph_runtime`, `swe_bench`, `latent_dna`,
  `eval.monotonic_mas.evaluator`) and **removed the adoption allow-list entirely**
  — the whole package is now enforced. The acgs-lite `valid-type` /
  `object-not-callable` noise (no `py.typed`) is handled package-wide by a single
  `follow_imports = "skip"` override on `acgs_lite.*`, which also makes the gate
  robust to acgs-lite version drift between the local workspace build and CI's
  PyPI wheel. Remaining fixes were annotation-only / behavior-preserving:
  `_HFModelLike` protocol gained `eval`/`__call__`; import-or-stub fallbacks in
  `langgraph_runtime` annotated to match their real signatures; a `partial`
  replaced a loop-capture lambda; `SwarmGraphState` casts on read-only `Mapping`
  reads; `_summarize_rows` widened to a covariant `Sequence`; a corrected
  `timings: list[tuple[int, str, float]]` annotation; `PICKERS` typed as
  `dict[str, Callable[..., tuple[int, str]]]`; walrus narrowing for optional
  duration lists. 108 source files check clean with no heavy extras installed
  (closes the BLOCKERS.md B3 follow-up).
- `SpectralSphereManifold` default `smoothing` lowered from `0.999` to `0.9`. The
  over-damped default retained 99.9% of stale state per projection, so the
  production trust manifold (built with defaults in `mesh/core.py`, consumed by
  `_select_peers`) accumulated trust at ~0.1% per cycle and stayed near zero
  within the O(10)-cycle window it exists to win against Birkhoff uniformity
  collapse. Restores responsiveness while keeping noise-damping hysteresis.
- `private_vote.tally(..., require_all_revealed=True)` now gates on reveal
  *validity*, not mere presence. A present-but-invalid reveal (correct commit
  digest, wrong nonce) previously bypassed the gate and the ballot was silently
  dropped instead of raising `MissingRevealError`.
- pytest `pythonpath` now includes the repo root so tests importing `scripts.*`
  collect when run from the project root; interpreter-agnostic assertion in the
  official SWE-bench command test (`sys.executable` may be `python3`).
- Docs: `CLAUDE.md` and `AGENTS.md` no longer describe this checkout
  unconditionally as a "git submodule" (closes BLOCKERS.md B6). The standalone
  repository (its own remote) is now the documented default git workflow, and the
  submodule `git add`/`git commit`-from-`packages/constitutional_swarm/` rules are
  scoped to the ACGS-monorepo checkout only.

## [1.0.0] - 2026-04-23

### Added
- Signed envelope for remote votes: nonce + timestamp + Ed25519 signature; replay window enforced server-side (task sec-wss-envelope)
- Startup settlement reconciliation: `ConstitutionalMesh.reconcile_pending_settlements()` returns a `ReconciliationReport`; optional `auto_reconcile` kwarg on mesh construction (task sec-startup-reconcile)
- `RemoteVoteReplayError`, `RecoveredAssignmentError` exceptions exposed via top-level import
- `SettlementRecord.schema_version` (default 1) and `is_recovered` flag persisted in JSONL + SQLite stores (idempotent ALTER on load) (tasks sec-schema-version-prep, sec-settle-replay)
- `GoalStep` dataclass with Mapping compatibility; unknown keys preserved in `GoalStep.extra` (task refactor-goalspec)
- Shadow spectral invariant test (`tests/test_shadow_spectral_invariant.py`, N=100 zero-divergence) (task cov-e2e-remote)

### Changed
- Remote vote transport: tri-state `transport_security: Literal["plaintext", "tls", "auto"]`; `auto` resolves to `tls` unless host is loopback; passing both `ssl_context` and `transport_security` raises `ValueError` (task sec-wss-envelope)
- Envelope requirement: remote vote requests missing nonce/timestamp are rejected; no legacy compat path
- Public API narrowed: top-level `__all__` now = `["AgentDNA", "ConstitutionalMesh", "GovernanceManifold", "SwarmExecutor", "TaskDAG"]`. Advanced names remain importable from submodules (e.g. `from constitutional_swarm.remote_vote_transport import RemoteVoteClient`) (task api-narrow-final)
- `mesh.py` split into `mesh/` package: `core`, `voting`, `settlement`, `peers`, `exceptions` (backward-compat facade in `__init__.py`) (task refactor-mesh-split)
- `remote_vote_transport.py` split into `remote_vote_transport/` package: `protocol`, `transport`, `peer` (backward-compat facade) (task refactor-transport-split)

### Removed
- Legacy envelope compat path for unsigned remote vote requests

### Migration
- See `MIGRATION.md` for the 0.3 -> 1.0 upgrade guide (transport_security, schema_version, register_agent)


## [0.3.0] - 2026-04-23

### Breaking Changes

`register_agent()` has been **removed** (not just deprecated). Calling it now raises
`AttributeError`. See [MIGRATION.md](MIGRATION.md) for the upgrade guide.

**Before (0.2.x):**
```python
# public-key-only peer
mesh.register_agent("agent-1", vote_public_key=pub_key)
```

**After (0.3.0):**
```python
# public-key-only peer (signing happens outside this process)
mesh.register_remote_agent("agent-1", vote_public_key=pub_key)

# local signer (this process holds and uses the private key)
mesh.register_local_signer("agent-1", vote_private_key=priv_key)
```

### Added
- Added `MIGRATION.md` with a mapping table and before/after examples for the
  `register_agent()` → `register_local_signer()` / `register_remote_agent()` migration.
- Added two new `collect_remote_votes()` tests: missing-route `KeyError` and
  wrong-`assignment_id` response handling.

### Changed
- `register_agent()` now raises `AttributeError` (removed; was `DeprecationWarning` in 0.2.x).
- `collect_remote_votes()` KeyError message now names the missing peer ID and
  shows the expected `peer_routes` key syntax.
- `HarnessResult.resolved` and `LocalSWEBenchHarness.evaluate()` docstrings now
  document the `evaluation_mode="local_dockerless"` distinction so downstream
  consumers can distinguish local results from official SWE-bench leaderboard scores.

## [0.2.0] - 2026-04-16

### Added
- Added `EvolutionLog`, a SQLite-backed append-only governance metric log whose SQLite triggers reject regressions, gaps, and deceleration at write time for capability-curve entries.
- Added remote vote transport primitives so public-key-only peers can validate and sign mesh votes outside the producer process.
- Added remote vote transport tests and evolution log tests, bringing the package test inventory from 38 to 40 files.
- Added self-contained paper build assets so the ICLR 2027 and NDSS 2027 manuscripts compile directly from the repo.

### Changed
- Mesh peers now register explicitly with `register_local_signer(...)` and `register_remote_agent(...)`, and the public docs and examples now match that split.
- Remote vote verification now requires detached signatures, and malformed remote vote responses fail closed instead of coercing types.
- Deterministic DAG node IDs now use explicit collision detection during compiler and DAG node creation.
- The constitutional mesh settlement path now rejects duplicate JSONL settlement appends and avoids persisting raw content in settled records.
- Package guidance, README examples, and paper text now document the new governance and transport behavior.

### Fixed
- Fixed the paper sources so both submissions build cleanly with local vendored template assets and warning-free LaTeX logs.
- Removed tracked Python bytecode caches from the repository and ignored local Codex/OMX session artifacts and generated paper PDFs.

### Removed
- Removed the obsolete `HANDOFF_FORGECODE.md` handoff document.

### Breaking Changes

`register_agent()` has been split into two explicit methods. Code using the old API will receive a `DeprecationWarning` and will break in v0.3.0.

**Before (0.1.x):**
```python
mesh.register_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)
```

**After (0.2.x):**
```python
# For peers whose keys live outside this process:
mesh.register_remote_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)

# For peers whose private key lives in this process:
mesh.register_local_signer(
    agent_id="agent-1",
    domain="safety",
    vote_private_key=my_priv_key,
)
```
