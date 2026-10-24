# Blockers

Onboarding/execution blockers, each with owner, impact, and next action.
Resolved items are kept for history. Validate the live state with
`make agent-check` and `make verify`.

| ID | Status | Impact | Blocker | Owner | Next action |
|----|--------|--------|---------|-------|-------------|
| B1 | **Mitigated** | High | Bare `uv sync` fails on a standalone clone: `pyproject` pins `acgs-lite = { workspace = true }` but there is no uv workspace. | maintainers | `make setup` passes `--no-sources` so acgs-lite resolves from PyPI. Permanent fix: make the workspace source monorepo-only (e.g. via a uv override) so plain `uv sync` works everywhere. |
| B2 | **Mitigated** | High | No global `python`/`pip`/`ruff`/`pytest` on the system (only `python3`); docs historically said `python -m ...`. | maintainers | All commands now route through `uv run`/`make`. Remaining: B4 (README still shows raw `python -m` commands). |
| B3 | **Resolved** | Medium | No static type checker (mypy/pyright) is configured, though the code is type-annotated. `make typecheck` runs ruff as a stand-in. | maintainers | Fixed: mypy configured in `pyproject.toml` `[tool.mypy]` (`ignore_missing_imports`, adoption baseline allow-listing pre-existing-error modules); `make typecheck` now runs `mypy` and is part of `make verify`; a `typecheck` CI job gates PRs. The **entire package is now enforced** — there is no adoption allow-list. Stable-core modules graduated first (bench, compiler, dna, governance_receipts, governed_handoff, mesh.core, private_vote, protocol, remote_vote_transport); the optional-dep-gated subpackages (bittensor/langgraph_runtime/swe_bench/latent_dna/eval.evaluator) graduated next. The acgs-lite `valid-type`/`object-not-callable` noise (it ships no `py.typed`) is handled package-wide by a single `follow_imports = "skip"` override on `acgs_lite.*`, which also makes the gate robust to acgs-lite version drift between the local workspace build and CI's PyPI wheel — the reproducibility gap that previously bit `dna.py`. The remaining fixes were annotation-only / behavior-preserving (protocol stub signatures, `Sequence` covariance, walrus narrowing, a corrected `timings` tuple annotation, `partial` for a loop-capture lambda, `cast` bridges for `Mapping[str, object]` reads). 110 source files check clean. The gate is now **environment-consistent**: a `typecheck-transport` CI job type-checks the `transport` (`websockets`, ships `py.typed`) surface alongside the no-extras job, and `make typecheck-coverage` (`scripts/check_typecheck_coverage.py`) fails CI if a new optional extra escapes the type surface without being classified `checked`/`excepted`. `langgraph`/`langchain` ship `py.typed` and carry a known live error (`langgraph_runtime/swarm_topology.py:126`) plus a mypy-1.11 crash — excepted pending a code fix + a crash-free mypy band. See `docs/plans/2026-06-03-003-fix-typecheck-env-consistency-plan.md`. |
| B4 | **Resolved** | Low | `README.md` "Verification commands" listed `python -m ruff` / `python -m pytest`, which don't work on this machine (no global tools). | docs role | Fixed: README now leads with `make` targets and the `uv run --no-sync` raw form. |
| B5 | **Resolved** | Medium | Running pytest from the repo root failed to collect `test_governance_receipts.py` and `test_protocol_canonicalization.py` (`No module named 'scripts'`). | — | Fixed: `pyproject` `pythonpath = ["src", "."]`. Both files now collect and pass. |
| B6 | **Resolved** | Low | `CLAUDE.md`/`AGENTS.md` describe this repo as a "git submodule" of an ACGS monorepo, but this checkout is a standalone repo with its own remote. Submodule-specific `git add`/`git commit` guidance may mislead. | maintainers | Fixed: `CLAUDE.md` and `AGENTS.md` now lead with the standalone context (own remote; branch/commit/push from this root) and scope the submodule `git add`/`git commit`-from-`packages/constitutional_swarm/` rules to the monorepo checkout only. AGENTS.md carries an authoritative regeneration-surviving note. |
| B7 | **Resolved** | Low | `test_build_official_eval_command_uses_instance_ids_from_predictions` asserted the literal prefix `python -m swebench...`, but the command is built from `sys.executable`, whose basename is `python3` here (CI's setup-python makes it `python`). | — | Fixed: assertion now checks `-m swebench.harness.run_evaluation`, independent of the interpreter name. |
| B8 | **Open** | High | APCC-1 rotation and the bounded SQLite/W1 B6 supervisor are implemented. The unchanged v3 qualification remains incomplete at 9,220/10,000. Trusted PostgreSQL execution, workload qualification, full W6, warm cells, ablations, campaign measurements and final reviews remain open. | APCC-1 implementation and review lanes | Owner chose preserve v3 and source optimization. Retained batching/reuse/index changes and seven durable boundaries are documented in [source evidence](experiments/apcc-1/b6-source-optimization-20261017/README.md). Later [checkpoint](experiments/apcc-1/b6-checkpoint-diagnostics-20261017/README.md) and [access-path](experiments/apcc-1/b6-access-path-20261017/README.md) comparisons rejected every new candidate; no newer qualification attempt or pooled diagnostic successes. Access-path replay: 1,636 comparison/wiring and 120 profile proofs. Current source adds an authenticated SQLite [W2 depth profile](docs/internal/APCC-1-W2-Causal-Profile.md), with default compatibility, tamper/observer checks, and explicit PostgreSQL exclusion. Targeted SQLite/profile tests: 410 passed; spawned 100-agent/100-proof chain: 3 tests passed. The W2 diagnostic driver passes 30 tests (200-operation rotation); a separate uninstrumented CLI run and fresh replay pass 100 operations. Both record occupancy 3/16. Full make verify: 3,357 passed, 57 skipped, 95 deselected; all 767 input pins unchanged. See [W2 evidence](experiments/apcc-1/w2-causal-profile-20261017/README.md). W2 timed pacing/warm qualification remains open; the [fresh-provisioning candidate](docs/internal/APCC-1-Fresh-Provisioning-Candidate.md) is reviewed design only, unmeasured. Preserve fixed v3 window/floor, durability, every live proof check. See [remaining plan](docs/internal/APCC-1-Remaining-Execution-Plan.md). |

W2 checkpoint — 2026-10-17: the [fixed-window functional controller and replay capsule](experiments/apcc-1/w2-campaign-20261017/README.md)
now pass bounded cold/warm continuation,200-operation two-chain execution,
real16-permit cleanup and all14 fresh-process ledger/manifest audits. Full local
gate:3,444 passed,57 skipped,95 deselected. Qualification is explicitly deferred;
four1,000-second windows still exceed the unchanged1,200-second observer cap.
The [separate renewal protocol draft](docs/internal/APCC-1-W2-Observer-Renewal-Protocol-Draft.md)
has passed architectural review as a proposal only. Implementation and crash-point
validation remain open; no renewal, authority-key export, longer launch lifetime
or fresh-provisioning transaction has been adopted.

Latest W2 status — 2026-10-18: [observer renewal implementation](docs/internal/APCC-1-W2-Renewal-Implementation-2026-10-18.md)
and its [sealed Phase 1 evidence](experiments/apcc-1/w2-renewal-20261018/README.md)
complete four real 1,000-second warm windows after cold conditioning, with
1,700 verified operations, four renewals and zero overload/late under functional
5-second SLA / 10-second handover limits. All six fresh CLI audits pass.
Numeric generation passed 3,771 tests with 979 unchanged gate inputs. Its first
real cold 10/s attempt failed qualification: 66 on-time commits, one admission
rejection, zero late completions and 9,933 unexecuted slots out of 10,000.
The other 344 campaign windows remain unexecuted. The original numeric CLI
initialization failure is retained; a separately pinned read-only auditor
verifies the fatal prefix and rejects qualification. Its additive full gate
passes 3,774 tests with 981 unchanged gate inputs. The [numeric failure capsule](experiments/apcc-1/w2-numeric-cold-20261018/README.md)
is sealed and checksum-verified. Qualification remains open: diagnose admission
RPC contention before proposing a new source candidate; the current evidence
does not prove its exact cause. No timing threshold, observer cap,
durability path, W1 result, public B6 adapter or W6 composition was changed.

## Reporting a new blocker

Add a row above with a unique `Bn` id, set **Status** to `Open`, fill in
impact/owner/next action, and link any fix in the PR. If a single Makefile
target or doc would have unblocked you, that is the next action.
