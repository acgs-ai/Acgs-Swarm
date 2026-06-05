# constitutional-swarm

## Purpose
Orchestrator-free constitutional governance runtime for multi-agent systems. Built on `acgs-lite`, it embeds governance per agent, supports DAG-compiled execution without a central orchestrator, provides peer-validated settlement via `ConstitutionalMesh`, and ships research modules for the MCFS (Manifold-Constrained Federated Swarm) stack — latent DNA steering, spectral-sphere trust dynamics, Merkle-CRDT artifact stores, and SWE-Bench evaluation scaffolds. This is a **standalone repository** with its own remote (the default working context); it is *also* vendored as a git submodule in the ACGS monorepo. See "Working In This Directory" for the git workflow in each context.

## Key Files
| File | Description |
|------|-------------|
| `pyproject.toml` | Package metadata, optional extras (`transport`, `research`, `bittensor`), ruff config, pytest config (`pythonpath = ["src"]`) |
| `uv.lock` | Locked dependency graph for `uv` |
| `CLAUDE.md` | Claude Code working notes (submodule rules, test commands, module map, invariants) |
| `SECURITY.md` | Security contact and disclosure policy |
| `CODEOWNERS` | Review routing for protected paths |
| `references.bib` | Shared BibTeX entries for papers/ drafts |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/` | Python package source for `constitutional_swarm` (see `src/AGENTS.md`) |
| `tests/` | Pytest suite — 1603 passing, 1 skipped, 2 xfailed (see `tests/AGENTS.md`) |
| `docs/` | Long-form design docs, including MACI DP protocol draft (see `docs/AGENTS.md`) |
| `docs/solutions/` | Documented solutions to past problems (bugs, best practices, design/workflow patterns), organized by category with YAML frontmatter (`module`, `tags`, `problem_type`) — relevant when implementing or debugging in documented areas |
| `examples/` | Minimal runnable artifacts (e.g., sample constitution YAML) (see `examples/AGENTS.md`) |
| `scripts/` | Operational scripts: testnet deploy, citation verification, security reporting (see `scripts/AGENTS.md`) |
| `specs/` | TLA+ formal specifications and model-checker configs (see `specs/AGENTS.md`) |
| `paper/` | Package paper draft (Markdown, long-form) (see `paper/AGENTS.md`) |
| `papers/` | Conference paper drafts: ICLR 2027, NDSS 2027 (see `papers/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **Default context — standalone repo (own remote).** Branch from `main`; `git add` / `git commit` / `git push` from this repo root. Stage files explicitly (`.py` + the specific docs you changed) — never `git add -A`.
- **Monorepo context only — git submodule.** When working inside the ACGS monorepo checkout (not here), run `git add` / `git commit` from inside `packages/constitutional_swarm/`, not the monorepo root; the parent-repo integration branch is `fix/p0-security-hardening`. These submodule rules do not apply to the standalone checkout.
- Base branch: `main`.
- Do not "fix" `src/constitutional_swarm/manifold.py` (Birkhoff/Sinkhorn baseline) — its uniformity collapse is the empirical proof kept as a research control. `spectral_sphere.py` is the production-direction replacement.
- Feature branches live in `.worktrees/` (gitignored); create with `git worktree add .worktrees/<name> -b <name>`.
- Repository memories persist in CLAUDE.md and `.claude/rules/`; Codex/OMX read this `AGENTS.md`.

### Testing Requirements
```bash
# From this repo root (standalone); inside the monorepo, prefix with packages/constitutional_swarm/
python -m pytest tests/ --import-mode=importlib -q     # 1603 passed, 1 skipped, 2 xfailed
python -m ruff check src/                              # 53 known pre-existing errors in latent_dna.py
python -m ruff format src/
```
WebSocket gossip tests require `pip install -e ".[transport]"`.

### Common Patterns
- Optional extras gate heavy dependencies: `transport` (websockets), `research` (torch + latent DNA), `bittensor` (subnet integration). Keep core import-free of these.
- Vote signatures are **mandatory** on `ConstitutionalMesh.submit_vote` (Ed25519 via `register_local_signer` / `sign_vote` / `register_remote_agent`).
- Two-phase commit pattern in `bittensor/arweave_audit_log.py`: cache Phase 1 in `_retry_state`, clear only on Phase 2 success.
- `TierManager` and `PrecedentStore` are thread-safe via `threading.Lock`.

## Key Invariants
- Constitutional hash: `608508a9bd224290`
- Precedent quorum: 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`)
- `EvolutionLog` enforces strict monotonicity + acceleration at write time (declarative, SQLite-backed, append-only)
- Manifold peer selection is wired in `mesh.py:_select_peers()` (trust-weighted sampling + one exploration slot)

<!-- MANUAL: Notes added below this line are preserved on regeneration. -->

## Agent-operability layer

This repo is self-describing and tool-executable. A fresh agent should:

1. Read [`README.md`](README.md) and this file, then [`ARCHITECTURE.md`](ARCHITECTURE.md) + [`PROJECT_MAP.md`](PROJECT_MAP.md). For a guided, top-to-bottom orientation (domains, per-module code logic, runtime flows, roadmap, handoff checklist), use the consolidated wiki: [`docs/wiki/`](docs/wiki/README.md).
2. `make setup` — one-command environment (standalone-safe; uses `uv sync --no-sources`).
3. Discover tools in [`TOOLS.md`](TOOLS.md) / [`tools/registry.yaml`](tools/registry.yaml).
4. Select a role from [`agents/`](agents/) (`researcher`, `coder`, `reviewer`, `qa`, `docs`, `release`).
5. `make verify` — full local gate (lint → agent-check → smoke → test).
6. `make agent-check` — prove registries + docs are self-consistent.
7. Produce the role's declared artifacts; record any blocker in [`BLOCKERS.md`](BLOCKERS.md).

Key maps: [`TASKS.md`](TASKS.md) (what to do next) · [`DECISIONS.md`](DECISIONS.md) (why things are the way they are).

> **Repository context (authoritative).** This checkout is a standalone
> repository with its own remote — work here directly (branch from `main`,
> commit/push from this root). It is *also* vendored as a git submodule in the
> ACGS monorepo; the submodule-only `git add`/`git commit`-from-
> `packages/constitutional_swarm/` rule applies *only* when working inside that
> monorepo checkout. If any auto-generated section above still reads "this is a
> git submodule" unconditionally, this note governs.
