# constitutional-swarm — Maintainer & Agent Wiki

> **Audience:** future maintainers, incoming AI agents, and teams picking up this
> codebase cold. This wiki is the **single navigable entry point** that ties the
> repo's existing docs together and fills the gaps they don't cover (per-module
> code logic, end-to-end runtime flows, a consolidated roadmap, and a handoff
> checklist). It does not replace the canonical docs — it routes you to them.

## What this repo is, in one paragraph

`constitutional-swarm` is an **orchestrator-free constitutional governance
runtime for multi-agent systems**, built on `acgs-lite`. Governance is embedded
*per agent* (`AgentDNA`) instead of enforced by a central coordinator; agents
execute work compiled into DAGs; peers validate each other's outputs with
**mandatory Ed25519-signed votes** (`ConstitutionalMesh`); decisions settle into
a durable, replayable audit trail (settlement stores + governance receipts); and
trust between agents evolves inside bounded manifolds (`spectral_sphere`). Around
this stable core sits a research stack (the **MCFS** — Manifold-Constrained
Federated Swarm) of experimental modules.

## How to read this wiki (recommended path)

Read top-to-bottom on your first pass; jump by need afterward.

| # | Page | Read it when you want… |
|---|------|------------------------|
| 1 | [01-overview.md](01-overview.md) | The mission, the four core patterns, and the stable/advanced/research maturity tiers. |
| 2 | [02-getting-started.md](02-getting-started.md) | To set up the environment, run tests/lint, and understand the agent-operability loop (`make` targets, registries, roles). |
| 3 | [03-domains.md](03-domains.md) | The conceptual vocabulary: constitutional governance, peer validation, settlement, trust dynamics, privacy, Bittensor, SWE-bench. |
| 4 | [04-directory-map.md](04-directory-map.md) | A folder-by-folder map of the whole repository and what each directory/file is for. |
| 5 | [05-module-reference.md](05-module-reference.md) | Per-module code logic: purpose, public API, how it works, and the invariants/gotchas you must not break. |
| 6 | [06-runtime-flows.md](06-runtime-flows.md) | End-to-end walkthroughs: how a governed task actually flows through the system, step by step. |
| 7 | [07-roadmap.md](07-roadmap.md) | The consolidated development roadmap, current state, open blockers, and the next tasks for an incoming agent. |
| 8 | [08-handoff.md](08-handoff.md) | The seamless-handoff checklist: conventions, invariants, git workflow, CI gates, and "do not touch" landmines. |
| 9 | [09-glossary.md](09-glossary.md) | Definitions of every acronym and domain term used across the codebase. |

## Canonical sources of truth (this wiki defers to these)

This wiki **synthesizes and cross-links**; it never silently re-defines. When a
fact lives in one of these, that file wins:

| Concern | Canonical file |
|---|---|
| Public API surface | [`src/constitutional_swarm/__init__.py`](../../src/constitutional_swarm/__init__.py) `__all__` |
| One-page architecture | [`ARCHITECTURE.md`](../../ARCHITECTURE.md) |
| Folder map (terse) | [`PROJECT_MAP.md`](../../PROJECT_MAP.md) |
| Runnable commands | [`TOOLS.md`](../../TOOLS.md) + [`tools/registry.yaml`](../../tools/registry.yaml) |
| Design decisions & invariants | [`DECISIONS.md`](../../DECISIONS.md) |
| Onboarding/execution blockers | [`BLOCKERS.md`](../../BLOCKERS.md) |
| Next actions | [`TASKS.md`](../../TASKS.md) |
| Agent working rules (per directory) | the `AGENTS.md` in each directory |
| Claude Code working notes | [`CLAUDE.md`](../../CLAUDE.md) |
| Deep concepts / security model | [`docs/concepts.md`](../concepts.md), [`docs/security-model.md`](../security-model.md) |

## Non-negotiable invariants (memorize before editing)

These are repeated across the codebase because breaking them silently corrupts
governance evidence. Full detail in [08-handoff.md](08-handoff.md) and
[`DECISIONS.md`](../../DECISIONS.md).

- **Constitutional hash:** `608508a9bd224290` (stable identity of the canonical constitution).
- **Precedent quorum:** 3-of-5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`).
- **Signed votes are mandatory** on `ConstitutionalMesh.submit_vote` (Ed25519).
- **`manifold.py` is a frozen research control — do not "fix" its collapse.** The production direction is `spectral_sphere.py`.
- **`EvolutionLog` enforces strict monotonicity + non-negative acceleration at write time** — raise, never silently drop.
- **Keep the core import light:** heavy/optional deps (`transport`, `research`, `bittensor`, `langgraph`) stay gated behind extras.

## Maintenance note

When code changes, update the affected wiki page **and** the canonical source it
mirrors. The module reference (page 5) and runtime flows (page 6) are the pages
most likely to drift — they describe code logic directly. Treat a stale wiki as a
bug.
