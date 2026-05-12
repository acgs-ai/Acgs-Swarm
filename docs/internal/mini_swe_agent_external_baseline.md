# mini-swe-agent external baseline for Acgs-Swarm SWE-bench

## Decision

Use `SWE-agent/mini-swe-agent` as an external baseline/control for Acgs-Swarm SWE-bench work, not as a replacement for the constitutional runtime. The implementation seam should be an optional CLI/subprocess runner that maps mini output into existing Acgs-Swarm artifacts.

Source inspected for this plan: upstream `SWE-agent/mini-swe-agent`, shallow clone commit `bc85a45`.

## Concept mapping

| mini-swe-agent concept | Local Acgs-Swarm touchpoint | Adaptation note |
|---|---|---|
| `DefaultAgent` linear message/action trajectory | `src/constitutional_swarm/swe_bench/agent.py`, `src/constitutional_swarm/swe_bench/codex_agent.py` | Treat as a black-box baseline first. Do not mix mini's linear trajectory with swarm/DAG execution until comparator evidence exists. |
| `LocalEnvironment` subprocess command execution with timeout/env | `src/constitutional_swarm/swe_bench/local_harness.py`, `src/constitutional_swarm/swe_bench/codex_agent.py` | Reuse the same design principle: bounded subprocesses, explicit cwd/env, safe failure metadata, cleanup in `finally`. |
| `run/benchmarks/swebench.py` predictions and trajectories | `src/constitutional_swarm/swe_bench/harness.py`, `scripts/run_official_swarm_swebench.py` | Convert adapter output to `SWEPatch` and SWE-bench prediction JSONL rows rather than inventing a new result format. |
| Model/config adapter ecology | Existing Codex/Claude/Gemini/Vertex adapters in `src/constitutional_swarm/swe_bench/` | Keep mini model/provider setup outside default Acgs-Swarm dependencies. Operator installs/configures mini separately. |
| SWE-bench batch runner | `scripts/run_official_swarm_swebench.py` | Preserve local-vs-official result separation. mini-generated patches are not official scores until the official harness evaluates them. |

## No-go areas

- Do not vendor mini-swe-agent source into this repository.
- Do not add mini-swe-agent as a required `pyproject.toml` dependency in this pass.
- Do not change `src/constitutional_swarm/manifold.py` or governance core behavior for this baseline adapter.
- Do not label black-box mini output as governed. Governance metadata may annotate the wrapper process, but mini internals remain external.
- Do not conflate local patch generation, Docker-less local harness results, and official SWE-bench scores.
- Do not require provider credentials, Docker, or mini-swe-agent installation for default CI tests.

## Stage 2 implementation status

Implemented as a narrow optional adapter because mini's CLI/subprocess shape maps cleanly to Acgs-Swarm's existing `SWEPatch` and prediction JSONL artifacts. The adapter remains a comparator and optional worker backend, not a runtime migration. It stops at safe metadata if mini is missing, times out, exits nonzero, or emits no diff. Live runs execute in an explicit work directory or the adapter's temporary isolated workspace; no-confirmation/yolo mode remains opt-in.

Implementation files:

- `src/constitutional_swarm/swe_bench/mini_swe_agent.py` — optional subprocess adapter and `MiniSWEBenchAgent`.
- `scripts/run_swe_bench_swarm_lite.py` — `--backend mini` selection for swarm runs; `codex` remains default.
- `scripts/run_official_swarm_swebench.py` — official wrapper pass-through for `--backend mini`.
- `tests/test_mini_swe_adapter.py` and `tests/test_run_swe_bench_swarm_lite_backends.py` — mocked/local coverage; no mini CLI required.

See also `docs/internal/swebench_swarm_backend_and_recovery.md` for operator usage and the recovery-controller boundary.

## Required artifact labels

Adapter-produced metadata should distinguish:

- `backend = mini_external_baseline`
- `score_source = not_evaluated` for generated patches before any harness run
- `score_source = local_harness` for Docker-less local evaluation
- `score_source = official_swebench` only when official SWE-bench output exists

## Verification strategy

Default verification is mocked/local and should not depend on mini-swe-agent being installed. Real mini/provider/Docker/official SWE-bench runs are opt-in and must document exact model, dataset slice, runtime, source labels, and whether official harness output exists.

## Swarm embedding rule

Embedding mini-swe-agent into the swarm is appropriate only as a pluggable `SWEBenchAgent` backend or recovery target. It must not become the coordinator, replace CRDT/gossip settlement, or bypass constitutional-swarm result accounting.
