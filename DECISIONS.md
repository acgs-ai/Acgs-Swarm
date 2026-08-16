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
| Static analysis | mypy (whole package, no allow-list) + ruff | `make typecheck` runs mypy across two CI surfaces (no-extras + `transport`); `make typecheck-coverage` guards extra-gating. See [BLOCKERS.md](BLOCKERS.md) B3 and the 2026-06-03 typecheck env-consistency log entry below. |
| Single source of truth for commands | `tools/registry.yaml` | Validated by `make agent-check`; `TOOLS.md` is the human view. |

## Decisions log

### 2026-08-15 — Public façade and receipt identity

- `__all__` is the stable eager façade. Star-import no longer dumps research
  symbols. Legacy names stay lazy. Documented in `docs/API_COMPATIBILITY.md`.
  Next published version should be 1.1.0.
- `receipt_digest` is the v0.1 payload digest (canonical statement identity),
  not the signed-envelope hash. Mesh receipts use key id `settlement-receipt`.

### 2026-06-03 — Typecheck gate environment consistency

The mypy gate ran only in a dev-only CI job, so type errors that surface only when
an optional `py.typed` extra is installed (e.g. `websockets`/`transport`) never
blocked a PR — a structural blind spot proven by `gossip_protocol.py`. Decisions:

- **Two blocking typecheck CI jobs**, not one: keep the no-extras job (the published
  library's distribution contract) and add `typecheck-transport` (`.[dev,transport]`,
  matching the local `make typecheck` default `EXTRAS="dev transport"`). A single
  replace was the lighter alternative; two jobs guarantee a superset without leaning
  on the dominance argument.
- **Heavy `research` (torch/transformers) stays out of the gate** — heavy and crashes
  mypy; `follow_imports = "skip"` if ever gated.
- **`warn_unused_ignores` stays OFF** — env-divergent ignores would flip-flop;
  re-enabling cleanly needs the `# type: ignore[code,unused-ignore]` idiom — deferred.
- **Regression guardrail**: `make typecheck-coverage` (`scripts/check_typecheck_coverage.py`)
  asserts every optional extra is `checked` (installed by a blocking mypy job) or
  `excepted` (with a reason) in `[tool.constitutional_swarm.typecheck_coverage]`, so a
  new extra-gated module cannot silently reopen the blind spot. `langgraph` is excepted
  with a known live error (`swarm_topology.py:126`) pending a code fix + mypy-band pin.

Plan: `docs/plans/2026-06-03-003-fix-typecheck-env-consistency-plan.md`.

### 2026-06-03 — Governed-handoff kernel hardening (make the security claims true)

A real-world validation pass found `governed_handoff.py`'s evidence bundle did not
deliver the forgery-resistance its framing implies, and the deterministic gate was
default-ALLOW. Hardened the kernel (executor side unchanged) so the repo's own
security claims hold:

| Change | Before | After |
|---|---|---|
| Evidence bundle integrity | `verify_bundle` only re-checked chain self-consistency → a coherent chain fabricated from scratch verified green (verifier == forger) | `build_bundle` optionally Ed25519-signs a domain-separated attestation pre-image (`BUNDLE_SIG_DOMAIN`, binds chain_hash + constitution_hash + version pin + final_state + task identity). `verify_bundle(..., trusted_public_keys=...)` REQUIRES a valid signature for `ok` when a trust anchor is supplied. Trust derives only from out-of-band keys, never the bundle-embedded key. |
| `tool_call` gate | default-ALLOW (denylist only) → `curl http://x/` ran | code-owned default-DENY allowlist `DEFAULT_COMMAND_ALLOWLIST = (true, echo)`; a constitution may EXTEND it but never weaken the default. Interpreter/test-runner/shell commands (`python*`, `pypy*`, `pytest`, `bash`, `env`, `uv`, `node`, …) are in `DENIED_INTERPRETER_COMMANDS` and are denied UNCONDITIONALLY — an allowlist cannot re-enable them, since `python -c <code>` / a `pytest` conftest / `bash -c` would bypass every other gate. `ACGS_TEST` therefore runs only pre-vetted non-interpreter commands; running the real test suite is a supervisor responsibility outside the governed directive stream. |
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
