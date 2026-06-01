# Tools

Human-readable index of every supported command. **Source of truth** is the
machine-readable [`tools/registry.yaml`](tools/registry.yaml) (validated against
[`tools/schemas/registry.schema.json`](tools/schemas/registry.schema.json) by
`make agent-check`). Per-tool runbooks live in
[`tools/runbooks/`](tools/runbooks/).

## Runner model

This repo is `uv`-managed. There is **no bare `python`/`pip`/`ruff`/`pytest`**
on the system — everything runs through the project venv via `uv run`. Create
the venv once with `make setup`, then use the `make` targets below.

## One-command targets (Makefile)

| Command | Purpose |
|---|---|
| `make setup` | Create the venv + install package & dev extras (standalone-safe, uses `--no-sources`). |
| `make dev` | `setup` + smoke check — a ready-to-develop environment. |
| `make test` | Default pytest suite (skips slow/benchmark/e2e/research/bittensor). |
| `make test-all` | Adds research-marked tests. |
| `make lint` | `ruff check src/constitutional_swarm/` (CI gate). |
| `make format` | `ruff format` source + scripts. |
| `make typecheck` | Static gate — ruff lint (no mypy/pyright configured; see [BLOCKERS.md](BLOCKERS.md) B3). |
| `make smoke` | Offline import + CLI `--help` sanity (no credentials). |
| `make agent-check` | Validate registries + doc completeness. |
| `make verify` | Full local gate: lint → agent-check → smoke → test. |
| `make clean` | Remove caches and build artifacts. |

Run `make help` for the live list.

## Product CLIs (installed console scripts)

| Command | Purpose | Runbook |
|---|---|---|
| `uv run --no-sync acgs-swarm {run\|verify\|pack}` | Governed task handoff + evidence bundles. | [governed-handoff.md](tools/runbooks/governed-handoff.md) |
| `uv run --no-sync acgs-verify-receipts <bundle.json>` | Verify a governance receipt bundle. | — |

## Evaluation & ops scripts (`scripts/`)

| Command | Purpose |
|---|---|
| `python scripts/reproduce_paper_claims.py` | Emit JSON metrics reproducing empirical claims. |
| `python scripts/run_governance_benchmark.py --model-backend offline-deterministic` | Governance benchmark (offline default). |
| `python scripts/run_swe_bench_lite.py --limit 10` | SWE-bench Lite harness (needs API key, costs tokens). |
| `python scripts/verify_citations.py --json` | Verify paper/doc citations resolve. |
| `python scripts/generate_security_report.py` | Build `security-audit-report.md` from security tests. |
| `python scripts/testnet_deploy.py {register\|miner\|validator} ...` | Bittensor testnet deploy ([runbook](tools/runbooks/testnet-deploy.md)). |
| `python scripts/agent_check.py` | The agent-operability gate (same as `make agent-check`). |

> Prefix script invocations with `uv run --no-sync` so they run in the venv.
> Additional eval scripts exist under `scripts/`; all are catalogued or wrapped
> by the registry. If you add a script, add a registry entry — no tool should
> live only in an undocumented script.

## Environment variables

None are required for `setup`, `smoke`, `lint`, `agent-check`, or the default
`test` suite. Credentials matter only for live LLM runs, eval logging, and
deployment. See [`.env.example`](.env.example) for the full list with
required-vs-optional annotations.
