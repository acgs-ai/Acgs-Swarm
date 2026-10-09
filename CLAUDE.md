# constitutional_swarm — Claude Notes

For repo-wide rules, see `/CLAUDE.md` and `.claude/rules/` (Claude Code auto-loads these). AGENTS.md serves Codex/OMX.

## Repository context & git workflow

This is a **standalone repository** with its own remote — that is the default
working context. Work here directly:

- Base branch: `main`. Branch from `main`; `git add` / `git commit` / `git push`
  from this repo root.
- Stage files explicitly (`.py` and the specific docs you changed) — never
  `git add -A`.

It is **also vendored as a git submodule** in the ACGS monorepo. The
submodule-only rules apply *only when you are working inside that monorepo
checkout*, not here:

- Run `git add` / `git commit` from inside `packages/constitutional_swarm/`, not
  the monorepo root.
- Parent-repo integration branch: `fix/p0-security-hardening`.

If your working directory is this repo (its own `.git`, own remote), you are in
the standalone context — ignore the submodule rules.

## Testing

```bash
# Standalone (this repo) — from the repo root. Setup installs the locked tools.
make setup
make test
```

## Commands

```bash
# Lint with the pinned Ruff policy
make lint

# Static type checking
make typecheck

# Full local gate
make verify

# Include the WebSocket transport extra in the locked environment
make setup EXTRAS="dev transport"
make test
```

`make setup` records the normalized extras in `.venv/.make-extras`. Later Make
gates reuse that exact set when `EXTRAS` is omitted; if you request a different
set explicitly, rerun `make setup EXTRAS="..."` first. `SYNC_FLAGS` now covers
base sync options only; Make always appends the normalized `EXTRAS` arguments.

`ruff format --check` is not yet a blocking CI gate because the repository has
pre-existing format debt. The formatting baseline is `line-length = 100`.
Establish a clean baseline in a dedicated formatting follow-up, then add the
blocking check without mixing mechanical changes into a behavioral patch. Use
`make format` only for a deliberate formatting change.

## Module map (MCFS research stack)

| Module | Purpose |
|--------|---------|
| `evolution_log.py` | Declarative evolution log — SQLite-backed, append-only, enforces strict monotonicity + acceleration at write time |
| `latent_dna.py` | BODES hook + `LatentDNAWrapper.generate_governed()` — LLM residual steering |
| `spectral_sphere.py` | SpectralSphereManifold — replaces Birkhoff, fixes uniformity collapse |
| `merkle_crdt.py` | Content-addressed DAG artifact store (SHA-256 CIDs, set-union merge) |
| `swarm_ode.py` | Projected RK4 continuous-time trust dynamics |
| `gossip_protocol.py` | WebSocket gossip transport for MerkleCRDT (`pip install .[transport]`) |
| `swe_bench/` | Evaluation scaffold — `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator` |
| `manifold.py` | Birkhoff/Sinkhorn baseline — **do not fix**, collapse is the empirical proof |
| `mesh.py` | Full swarm mesh + settlement store |
| `bittensor/` | Bittensor subnet integration (`pip install .[bittensor]`) |
| `examples/constitution.yaml` | Minimal sample constitution — 4 principles, 3 domains, quorum=0.6; required by `testnet_deploy.py --constitution` flag |

## Worktree workflow

Feature branches live in `.worktrees/` (gitignored). Create with:

```bash
git worktree add .worktrees/<branch-name> -b <branch-name>
cd .worktrees/<branch-name>
make setup
make test
```

## Key invariants

- Constitutional hash: `608508a9bd224290`
- Precedent quorum: 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`)
- ArweaveAuditLogger: two-phase commit — cache Phase 1 result in `_retry_state`, clear only on success
- TierManager and PrecedentStore are thread-safe via `threading.Lock`
- Manifold peer selection is wired in `mesh.py:_select_peers()` — trust-weighted sampling with one exploration slot

## Supporting docs

- `README.md` — package overview, install paths, and public API examples
- `CHANGELOG.md` — release notes for shipped package behavior
- `paper/README.md` — entry point for the package paper draft and manuscript assets
- `paper/constitutional_swarm_paper.md` — long-form Markdown paper draft for package claims and theory
- `docs/maci_dp_protocol.md` — MCFS privacy and MACI protocol draft
- `docs/solutions/` — documented solutions to past problems (bugs, best practices, design/workflow patterns), organized by category with YAML frontmatter (`module`, `tags`, `problem_type`); relevant when implementing or debugging in documented areas
- `HANDOFF_CODEX.md` — historical implementation handoff for Codex/OMX

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming -> invoke office-hours
- Bugs, errors, "why is this broken", 500 errors -> invoke investigate
- Ship, deploy, push, create PR -> invoke ship
- QA, test the site, find bugs -> invoke qa
- Code review, check my diff -> invoke review
- Update docs after shipping -> invoke document-release
- Weekly retro -> invoke retro
- Design system, brand -> invoke design-consultation
- Visual audit, design polish -> invoke design-review
- Architecture review -> invoke plan-eng-review
- Save progress, checkpoint, resume -> invoke checkpoint
- Code quality, health check -> invoke health
