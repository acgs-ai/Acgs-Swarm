# 02 · Getting started — environment, commands, agent loop

[← 01 Overview](01-overview.md) · Next: [03 Domains →](03-domains.md)

This page is the operational on-ramp. The authoritative command list is
[`TOOLS.md`](../../TOOLS.md) (human view) backed by
[`tools/registry.yaml`](../../tools/registry.yaml) (machine source of truth,
validated by `make agent-check`). Read this page for the *why*, that file for the
*exact flags*.

## Runner model (read this first)

This repo is **`uv`-managed**. There is **no bare `python` / `pip` / `ruff` /
`pytest`** assumed on the system — everything runs through the project venv via
`uv run --no-sync`, or (preferably) through `make` targets that wrap it. Create
the venv once with `make setup`. The system interpreter is `python3`.

> Standalone gotcha (BLOCKERS.md B1): a bare `uv sync` fails on a standalone
> clone because `pyproject` pins `acgs-lite = { workspace = true }` for monorepo
> dev. `make setup` passes `--no-sources` so `acgs-lite` resolves from PyPI.
> **Always bootstrap with `make setup`, not raw `uv sync`.**

## The five commands you actually need

```bash
make setup          # one-time: create venv + install package & dev extras (standalone-safe)
make verify         # full local gate: lint → typecheck → agent-check → typecheck-coverage → smoke → test
make agent-check    # prove registries + docs are self-consistent
make test           # default pytest suite (skips slow/e2e/research/bittensor)
make lint           # ruff check on src/constitutional_swarm/
```

Other targets: `make dev` (setup + smoke), `make test-all` (adds research),
`make format`, `make typecheck`, `make typecheck-coverage`, `make smoke`,
`make agent-self-evolve`, `make clean`. Run `make help` for the live list.

### Raw equivalents (when you can't use make)

```bash
uv run --no-sync ruff check src/constitutional_swarm/
uv run --no-sync ruff format --check src/
uv run --no-sync pytest tests/ --import-mode=importlib -q
uv run --no-sync pytest -m "not slow and not e2e and not research" tests/ --import-mode=importlib -q
uv build
```

## Test suite shape

- Location & invocation: `pytest tests/ --import-mode=importlib`.
- Expected baseline (per `CLAUDE.md`/`AGENTS.md`): **~1503 passed (dev)** /
  **~1652 passed + 2 xfailed (research)**. The 2 xfails are the intentional
  Birkhoff collapse in `manifold.py` — expected, not a regression.
- **Parity rule:** every module `foo.py` has a matching `tests/test_foo.py`.
  Keep parity when you add a module.
- `tests/security/` = one test per security-audit finding (regression guards).
  `tests/fixtures/` = shared data.
- Extra-gated suites: `pip install -e ".[transport]"` for
  `test_gossip_protocol.py` / `test_remote_vote_transport.py`;
  `".[research]"` for torch-backed latent-DNA / swarm-ODE / spectral tests;
  bittensor tests skip cleanly if the extra is absent.

## Optional extras (what gates what)

Heavy deps are gated so the core import stays light (`pyproject.toml`
`[project.optional-dependencies]`):

| Extra | Pulls in | Needed for |
|---|---|---|
| `transport` | `websockets` | remote vote transport, gossip protocol |
| `research` | `torch`, `transformers` | latent DNA, swarm ODE, spectral-sphere torch paths |
| `bittensor` | Bittensor SDK | `bittensor/` subnet integration |
| `langgraph` / `langgraph-swarm` | LangGraph | `langgraph_runtime/` adapter & handoff topology |
| `vertex` / `gemini` / `semantic` | cloud / ST SDKs | specific SWE-bench agents, semantic role detector |

**Rule:** the top-level `import constitutional_swarm` must succeed with none of
these installed. Keep their imports inside functions/`TYPE_CHECKING`. (See the
known `mac_acgs_loop.py` import-leak in
[`src/constitutional_swarm/AGENTS.md`](../../src/constitutional_swarm/AGENTS.md).)

## The agent-operability loop

This repo is **self-describing and tool-executable**. A fresh agent should:

1. Read [`README.md`](../../README.md), [`AGENTS.md`](../../AGENTS.md), then
   [`ARCHITECTURE.md`](../../ARCHITECTURE.md) + [`PROJECT_MAP.md`](../../PROJECT_MAP.md)
   (or just start here in the wiki).
2. `make setup` — one-command environment.
3. Discover tools in [`TOOLS.md`](../../TOOLS.md) / [`tools/registry.yaml`](../../tools/registry.yaml).
4. Select a **role** from [`agents/`](../../agents/) —
   `researcher`, `coder`, `reviewer`, `qa`, `docs`, `release` (one
   `<role>.agent.yaml` manifest each, validated against `agents/schemas/agent.schema.json`).
5. `make verify` — full local gate before changing anything.
6. `make agent-check` — prove registries + docs are self-consistent.
7. Produce the role's declared artifacts; record any blocker in
   [`BLOCKERS.md`](../../BLOCKERS.md).

Key maps: [`TASKS.md`](../../TASKS.md) (what to do next) ·
[`DECISIONS.md`](../../DECISIONS.md) (why things are the way they are).

## Product CLIs (installed console scripts)

After `make setup`:

| Command | Purpose |
|---|---|
| `uv run --no-sync acgs-swarm {run\|verify\|pack}` | Governed task handoff + evidence bundles (`governed_handoff.py`). |
| `uv run --no-sync acgs-verify-receipts <bundle.json>` | Verify a governance receipt bundle (`governance_receipts_cli.py`). |
| `uv run --no-sync acgs-agent-self-evolve` | Build offline self-evolution harnesses for every repo agent. |

## Environment variables

None are required for `setup`, `smoke`, `lint`, `agent-check`, or the default
`test` suite. Credentials matter only for live LLM runs, eval logging, and
deployment. See [`.env.example`](../../.env.example) for the annotated list.

Continue to [03 Domains →](03-domains.md).
