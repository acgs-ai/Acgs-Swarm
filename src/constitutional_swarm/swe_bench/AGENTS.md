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
| `swarm_coordinator.py` | `SwarmCoordinator` — distributes SWE-Bench instances across a mesh of agents via `SwarmExecutor` |
| `mini_swe_agent.py` | Optional subprocess adapter that maps an installed `mini` / `mini-swe-agent` CLI into `SWEBenchAgent` / `SWEPatch` without making it a required dependency |
| `recovery_orchestrator.py` | `SWERecoveryController` — recovery-plane classifier and policy-capped attempt ledger around completed SWE-Bench rows |

## For AI Agents

### Working In This Directory
- Treat this as an evaluation (non-production) surface — changes here must not leak into the stable core API.
- Optional external agent backends, including mini-swe-agent, must remain pluggable workers or recovery targets; do not make them the swarm coordinator/brain.
- Preserve local-vs-official scoring boundaries: generated patches are not official SWE-Bench scores until official harness output exists.
- When adding new metrics or scoring rules, update `test_swe_bench_agent.py` and `test_swarm_coordinator.py` in the same change.
- Keep SWE-Bench dataset access behind explicit loader functions; do not hard-code paths.

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
