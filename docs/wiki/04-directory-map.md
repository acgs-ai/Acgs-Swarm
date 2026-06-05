# 04 · Directory map — what every folder is for

[← 03 Domains](03-domains.md) · Next: [05 Module Reference →](05-module-reference.md)

Folder-by-folder guide. The terse canonical version is
[`PROJECT_MAP.md`](../../PROJECT_MAP.md); this page adds purpose and "when you'd
touch it." Most directories also ship a local `AGENTS.md` with finer detail —
**read the nearest `AGENTS.md` before editing in a directory.**

## Repository root

| Path | What it is | Touch it when… |
|---|---|---|
| `src/constitutional_swarm/` | The Python package — all runtime + research code. | Implementing or fixing any behavior. |
| `tests/` | Pytest suite (~1.6k tests). `tests/security/` = one test per audit finding; `tests/fixtures/` = shared data. | Adding/changing code (keep test parity). |
| `scripts/` | Operational & eval CLIs (deploy, benchmarks, reproduction, `agent_check.py`). | Running evals, deploys, or repro; adding an operator script (then add a registry entry). |
| `agents/` | **Agent registry** — one `<role>.agent.yaml` per role + JSON schema + `templates/`. | Defining/altering an agent role. |
| `tools/` | **Tool registry** — `registry.yaml` (source of truth), `schemas/`, `runbooks/`. | Adding a command; documenting a tool. |
| `examples/` | Runnable artifacts: `constitution.yaml`, `governed-handoff/`, LangGraph demo. | Writing/validating a usage example. |
| `docs/` | Long-form docs; `docs/internal/` holds ADRs, audits, research notes; `docs/wiki/` is this wiki. | Documenting design, decisions, or onboarding. |
| `specs/` | TLA+ formal specifications + model-checker configs (`mesh.tla`, `constitution_reconfig.tla`). | Changing protocol semantics that have a formal model. |
| `paper/`, `papers/`, `references.bib` | Package paper draft; conference drafts (ICLR/NDSS 2027); shared BibTeX. | Writing/citing research claims. |
| `.github/workflows/` | CI: `ci.yml`, `agent-check.yml`, `security.yml`, `publish.yml`, `tla-check.yml`, `verify-cites.yml`. | Changing the CI gates. |
| `Makefile`, `pyproject.toml`, `uv.lock` | Build/runner config; extras; ruff/mypy/pytest config; locked deps. | Changing commands, deps, or lint/type config. |

### Root markdown docs (the "operating manual")

| File | Role |
|---|---|
| [`README.md`](../../README.md) | Public package overview, install paths, quickstart, maturity tiers. |
| [`ARCHITECTURE.md`](../../ARCHITECTURE.md) | Authoritative one-page system view + invariants. |
| [`PROJECT_MAP.md`](../../PROJECT_MAP.md) | Terse folder/module map. |
| [`AGENTS.md`](../../AGENTS.md) | Agent working rules (Codex/OMX read this); git context. |
| [`CLAUDE.md`](../../CLAUDE.md) | Claude Code working notes (module map, invariants, skill routing). |
| [`DECISIONS.md`](../../DECISIONS.md) | Decision index + standing invariants + decisions log. |
| [`BLOCKERS.md`](../../BLOCKERS.md) | Onboarding/execution blockers with status (B1–B7). |
| [`TASKS.md`](../../TASKS.md) | Working roadmap / next actions. |
| [`TOOLS.md`](../../TOOLS.md) | Human index of every supported command. |
| [`MIGRATION.md`](../../MIGRATION.md) | API migration notes. |
| [`SECURITY.md`](../../SECURITY.md), [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md), [`CODEOWNERS`](../../CODEOWNERS) | Policy & contribution governance. |

## `src/constitutional_swarm/` layout

The package is mostly **flat modules** plus a few subpackages. Page 5 walks each
module's code logic. The subpackages:

| Subpackage | Purpose | Extra | Local guide |
|---|---|---|---|
| `mesh/` | `ConstitutionalMesh` split into `core`, `peers`, `voting`, `settlement`, `exceptions`. | — (core) | — |
| `remote_vote_transport/` | WebSocket remote-vote RPC: `peer`, `protocol`, `transport`. | `[transport]` | — |
| `langgraph_runtime/` | LangGraph adapter: `runtime`, `nodes`, `guards`, `state`, `streaming`, `swarm_topology`, `agent`, `coordinator_adapter`, `checkpointer_bridge`. | `[langgraph]` | [`langgraph_runtime/AGENTS.md`](../../src/constitutional_swarm/langgraph_runtime/AGENTS.md) |
| `bittensor/` | Full governance subnet (miner/validator/SN-owner, precedent, emissions, audit). | `[bittensor]` | [`bittensor/AGENTS.md`](../../src/constitutional_swarm/bittensor/AGENTS.md) |
| `swe_bench/` | SWE-bench solving scaffolds + swarm coordinator + harnesses + recovery. | varies | [`swe_bench/AGENTS.md`](../../src/constitutional_swarm/swe_bench/AGENTS.md) |
| `eval/monotonic_mas/` | Role-drift/handoff/dedupe detectors + autoresearch evaluator + abliteration detector. | `[semantic]` opt | — |

Top-level package guide: [`src/constitutional_swarm/AGENTS.md`](../../src/constitutional_swarm/AGENTS.md).

## `docs/` layout

| Path | Contents |
|---|---|
| `docs/wiki/` | **This wiki** (maintainer/agent entry point). |
| `docs/concepts.md`, `architecture.md`, `security-model.md`, `quickstart.md`, `examples.md`, `faq.md`, `community.md`, `roadmap.md` | Public long-form docs. |
| `docs/langgraph_runtime.md`, `docs/maci_dp_protocol.md` | Adapter + MACI/DP protocol drafts. |
| `docs/internal/` | ADRs, audits, threat models, gap/claims registers, SWE-bench backend notes. |
| `docs/plans/` | Dated implementation plans (e.g. typecheck env-consistency, DSSE projector). |
| `docs/solutions/` | Documented past solutions (bugs/patterns/decisions) with YAML frontmatter — **search here before debugging a documented area.** |
| `docs/recipes/` | Task recipes (e.g. extended-refusal finetuning). |
| `docs/dogfood-reports/`, `docs/pulse-reports/` | Generated dogfood/product-pulse outputs. |
| `docs/RUNTIME_OPTIMIZATION_REPORT.md`, `docs/AGENT_SKILL_AUDIT.md`, `docs/public-replication*` | Perf bottlenecks, skill audit, replication assets. |

## `agents/`, `tools/`, `scripts/`, `specs/`, `examples/`

- **`agents/`** — roles: `researcher`, `coder`, `reviewer`, `qa`, `docs`,
  `release` (each `<role>.agent.yaml`), validated against
  `agents/schemas/agent.schema.json`. `agents/templates/` is a large library of
  domain agent templates (academic, engineering, product, …) with `INVENTORY.md`
  and `PROVENANCE.md`.
- **`tools/`** — `registry.yaml` is the **single source of truth** for commands
  (validated by `make agent-check` against `schemas/registry.schema.json`);
  `runbooks/` holds per-tool guides (setup, test, governed-handoff,
  testnet-deploy, agent-check, agent-self-evolve, typecheck-coverage).
- **`scripts/`** — see [05 §scripts](05-module-reference.md) and `TOOLS.md`.
  Notable: `reproduce_paper_claims.py`, `run_governance_benchmark.py`,
  `run_swe_bench_lite.py`, `verify_citations.py`, `generate_security_report.py`,
  `testnet_deploy.py`, `agent_check.py`, `agent_self_evolve.py`.
- **`specs/`** — TLA+ models: `mesh.tla` + `MeshMC.cfg` (mesh safety),
  `constitution_reconfig.tla` + `.cfg` (joint-consensus reconfiguration). Checked
  by the `tla-check` CI workflow. See [`specs/AGENTS.md`](../../specs/AGENTS.md).
- **`examples/`** — `constitution.yaml` (minimal 4-principle constitution, used by
  `testnet_deploy.py --constitution`), `governed-handoff/` (a `.acgs/` config +
  task for the `acgs-swarm` CLI demo), `langgraph_swarm_demo.py`.

Continue to [05 Module Reference →](05-module-reference.md).
