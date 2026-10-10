<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# swe_bench

## Purpose
Evaluation scaffold for running constitutional-swarm against the SWE-Bench software-engineering benchmark. Provides a governed agent, a benchmark harness, and a swarm coordinator that drives multi-agent task execution under constitutional validation.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Public exports: `CodexSWEBenchAgent`, optional `MiniSWEBenchAgent`, `SWEBenchAgent`, `SWEBenchHarness`, `SWEPatch` |
| `agent.py` | `SWEBenchAgent` — governed single-agent wrapper that executes SWE-Bench instances under `AgentDNA` + mesh settlement |
| `harness.py` | `SWEBenchHarness` — orchestrates instance loading, agent invocation, and result scoring |
| `swarm_coordinator.py` | `SwarmCoordinator` — distributes SWE-Bench instances across a mesh of agents via `SwarmExecutor`. CRDT nodes get `bodes_passed=True` only when `governed is True` and `metadata["governance_action"] == "accepted"`; rejected, empty and ungoverned patches record `False` |
| `governed_agent.py` | `GovernedAgent` — evaluates patches through the shared `eval.monotonic_mas.detectors.role.evaluate_payload` (raw + normalized passes; semantic pass is opt-in via `semantic=True`). Adds `governance_normalized_changed`, `governance_semantic_status`, `governance_semantic_hits` metadata |
| `_diff.py` | `DIFF_MARKER`, `extract_unified_diff()` — the single diff extractor for every patch adapter. A patch needs a file header (`diff --git`, `--- a/`, `+++ b/`); hunk-only `@@` output is not a patch |
| `_messages_agent.py` | `_MessagesAPIAgent` base (Claude, OAuth, Vertex), `build_swe_bench_prompt()` (also used by Gemini and Codex), shared timeout/error mapping and stats |
| `run_one_by_one.py` | Resumable runs. `run_one`, `run_swarm_batch`, `run_best_of_k_batch` take `run_root=`; library calls without it use a private per-process temp root (never the cwd). The CLI `--run-root` defaults to `.omc/swe_bench_runs`. Instance ids must match `[A-Za-z0-9][A-Za-z0-9._-]*`, and path components reject a leading `-` |
| `local_harness.py` / `_subprocess.py` | Dockerless local evaluation (`evaluation_mode="local_dockerless"`; requires the official `test_patch` and parseable JUnit) and the minimal-environment, process-group-killing subprocess runner. Not a security sandbox |
| `mini_swe_agent.py` | Optional subprocess adapter that maps an installed `mini` / `mini-swe-agent` CLI into `SWEBenchAgent` / `SWEPatch` without making it a required dependency |
| `recovery_orchestrator.py` | `SWERecoveryController` — recovery-plane classifier and policy-capped attempt ledger around completed SWE-Bench rows |

## For AI Agents

### Working In This Directory
- Treat this as an evaluation (non-production) surface — changes here must not leak into the stable core API.
- Optional external agent backends, including mini-swe-agent, must remain pluggable workers or recovery targets; do not make them the swarm coordinator/brain.
- Preserve local-vs-official scoring boundaries: generated patches are not official SWE-Bench scores until official harness output exists.
- When adding new metrics or scoring rules, update `test_swe_bench_agent.py` and `test_swarm_coordinator.py` in the same change.
- Keep SWE-Bench dataset access behind explicit loader functions; do not hard-code paths.
- Reuse `_diff.extract_unified_diff` and `_MessagesAPIAgent`; do not add per-backend diff extractors or prompt copies.
- Oracle-selected best-of-k results are `pass@k` (`resolve_metric: "pass@k"`, `selection: "oracle"` in `scripts/run_mc_swarm.py`); never compare them with pass@1.

### Testing Requirements
- `tests/test_swe_bench_agent.py`, `tests/test_swarm_coordinator.py`.
- Optional backend/recovery changes should also cover `tests/test_mini_swe_adapter.py`, `tests/test_run_swe_bench_swarm_lite_backends.py`, and `tests/test_recovery_orchestrator.py` when relevant.

## Dependencies

### Internal
- `constitutional_swarm.dna` — embedded constitutional validation
- `constitutional_swarm.swarm` — DAG execution
- `constitutional_swarm.mesh` — peer settlement

### External
- SWE-Bench dataset / harness utilities (loaded lazily)

<!-- MANUAL: -->
