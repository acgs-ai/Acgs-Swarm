# SWE-Bench swarm backends and recovery controller

Date: 2026-05-12

## Scope

This note documents the optional SWE-Bench swarm backend and recovery-plane
changes added around the existing evaluation scaffold. These changes do not
replace `SwarmCoordinator`, CRDT settlement, mesh validation, or any stable core
runtime API.

## Backend model

`SwarmCoordinator` still receives a list of `SWEBenchAgent`-compatible workers
and routes instances through in-memory or gossip coordination. Backends are
selected at the runner layer:

| Backend | Agent class | Default? | Dependency behavior |
|---|---|---:|---|
| `codex` | `CodexSWEBenchAgent` | yes | Uses the existing Codex CLI adapter path. |
| `claude` | `ClaudeSWEBenchAgent` | no | Uses the existing Anthropic adapter path. |
| `mini` | `MiniSWEBenchAgent` | no | Optional subprocess adapter for an installed `mini` / `mini-swe-agent` CLI. |

The mini backend is intentionally a worker backend, not the swarm brain. It is
safe to mix conceptually with the swarm because it only has to satisfy the
`SWEBenchAgent.solve(...) -> SWEPatch` contract.

## Running the mini backend

Example local runner invocation:

```bash
PYTHONPATH="$PWD:$PWD/src" \
python scripts/run_swe_bench_swarm_lite.py \
  --backend mini \
  --mini-binary mini \
  --model mini-model-name \
  --limit 1 \
  --agents 1 \
  --mode in-memory \
  --agent-timeout 240 \
  --harness-timeout 600 \
  --output /tmp/acgs-swarm-mini.json
```

Optional mini-specific flags:

- `--mini-binary`: executable name or path; defaults to resolving `mini` then
  `mini-swe-agent`.
- `--mini-extra-arg`: append one extra CLI argument per use.
- `--mini-yolo`: explicit opt-in for no-confirmation mode. It is never enabled
  by default.

The official wrapper also accepts `--backend mini` and passes it through to the
swarm runner before invoking the official SWE-Bench harness.

## Safety and scoring boundaries

- `codex` remains the default backend.
- mini-swe-agent is not vendored and is not a required dependency.
- Missing mini CLI, timeout, non-zero exit, or malformed/no-diff output becomes
  safe failure metadata instead of an uncaught exception.
- The mini subprocess receives a minimal environment: `PATH` plus explicitly
  provided env keys. Ambient secrets are not inherited by default.
- `MiniSWEBenchAgent` metadata uses `backend = mini_external_baseline` and
  starts with `score_source = not_evaluated`.
- A generated patch is not an official score until the official SWE-Bench
  harness evaluates the exported prediction JSONL.

## Recovery controller

`SWERecoveryController` lives in
`src/constitutional_swarm/swe_bench/recovery_orchestrator.py`. It is a
recovery-plane helper around completed rows, not a replacement for swarm
coordination.

Modes:

| Mode | Behavior |
|---|---|
| `off` | Inert. Preserves baseline rows and emits no recovery attempts. |
| `advisory` | Classifies failures and records recommendations only. No reruns. |
| `active` | Runs policy-capped recovery attempts through an injected `attempt_runner`. |

Core invariants:

- baseline rows are copied and remain immutable from the controller's point of
  view;
- recovery attempts are separate audit records;
- `final_rows` is a derived reporting view, not a silent replacement of the
  baseline;
- baseline and recovered summaries are reported separately with deltas;
- per-instance and global caps prevent retry loops;
- native build incompatibility is marked blocked rather than retried blindly;
- local-vs-official disagreement is escalated/recommended, not auto-scored.

## Using mini as a recovery target

The intended integration shape is:

```text
Signal: TEST_FAILURE / PATCH_APPLY_FAILED / AGENT_TIMEOUT
Policy action: reroute_agent / rebuild_with_timeout
Attempt runner target: MiniSWEBenchAgent or another SWEBenchAgent backend
```

That keeps mini-swe-agent useful as a specialist worker or recovery lane while
preserving constitutional-swarm's routing, settlement, and reporting boundaries.
