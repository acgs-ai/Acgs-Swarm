# Blockers

Onboarding/execution blockers, each with owner, impact, and next action.
Resolved items are kept for history. Validate the live state with
`make agent-check` and `make verify`.

| ID | Status | Impact | Blocker | Owner | Next action |
|----|--------|--------|---------|-------|-------------|
| B1 | **Mitigated** | High | Bare `uv sync` fails on a standalone clone: `pyproject` pins `acgs-lite = { workspace = true }` but there is no uv workspace. | maintainers | `make setup` passes `--no-sources` so acgs-lite resolves from PyPI. Permanent fix: make the workspace source monorepo-only (e.g. via a uv override) so plain `uv sync` works everywhere. |
| B2 | **Mitigated** | High | No global `python`/`pip`/`ruff`/`pytest` on the system (only `python3`); docs historically said `python -m ...`. | maintainers | All commands now route through `uv run`/`make`. Remaining: B4 (README still shows raw `python -m` commands). |
| B3 | **Resolved** | Medium | No static type checker (mypy/pyright) is configured, though the code is type-annotated. `make typecheck` runs ruff as a stand-in. | maintainers | Fixed: mypy configured in `pyproject.toml` `[tool.mypy]` (`ignore_missing_imports`, adoption baseline allow-listing pre-existing-error modules); `make typecheck` now runs `mypy` and is part of `make verify`; a `typecheck` CI job gates PRs. Stable-core modules graduated to clean (bench, compiler, dna, governance_receipts, governed_handoff, mesh.core, private_vote, protocol, remote_vote_transport) and are now enforced. Remaining follow-up: the optional-dep-gated subpackages (bittensor/langgraph_runtime/swe_bench/latent_dna/eval.evaluator) stay allow-listed — their errors stem from untyped third-party packages (acgs-lite lacks `py.typed`) and types that only resolve with `[bittensor]`/`[langgraph]`/`[research]` installed; graduating them needs those extras in the typecheck env (+ shims), tracked separately. |
| B4 | **Resolved** | Low | `README.md` "Verification commands" listed `python -m ruff` / `python -m pytest`, which don't work on this machine (no global tools). | docs role | Fixed: README now leads with `make` targets and the `uv run --no-sync` raw form. |
| B5 | **Resolved** | Medium | Running pytest from the repo root failed to collect `test_governance_receipts.py` and `test_protocol_canonicalization.py` (`No module named 'scripts'`). | — | Fixed: `pyproject` `pythonpath = ["src", "."]`. Both files now collect and pass. |
| B6 | **Resolved** | Low | `CLAUDE.md`/`AGENTS.md` describe this repo as a "git submodule" of an ACGS monorepo, but this checkout is a standalone repo with its own remote. Submodule-specific `git add`/`git commit` guidance may mislead. | maintainers | Fixed: `CLAUDE.md` and `AGENTS.md` now lead with the standalone context (own remote; branch/commit/push from this root) and scope the submodule `git add`/`git commit`-from-`packages/constitutional_swarm/` rules to the monorepo checkout only. AGENTS.md carries an authoritative regeneration-surviving note. |
| B7 | **Resolved** | Low | `test_build_official_eval_command_uses_instance_ids_from_predictions` asserted the literal prefix `python -m swebench...`, but the command is built from `sys.executable`, whose basename is `python3` here (CI's setup-python makes it `python`). | — | Fixed: assertion now checks `-m swebench.harness.run_evaluation`, independent of the interpreter name. |

## Reporting a new blocker

Add a row above with a unique `Bn` id, set **Status** to `Open`, fill in
impact/owner/next action, and link any fix in the PR. If a single Makefile
target or doc would have unblocked you, that is the next action.
