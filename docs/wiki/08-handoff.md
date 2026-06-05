# 08 · Handoff — the seamless pickup checklist

[← 07 Roadmap](07-roadmap.md) · Next: [09 Glossary →](09-glossary.md)

Everything a new maintainer or agent needs to start changing code **without
breaking governance guarantees or repo conventions.** Read this before your first
commit.

## First 10 minutes

```bash
make setup          # bootstrap venv (standalone-safe; never raw `uv sync`)
make agent-check    # prove registries + docs are self-consistent
make verify         # lint → typecheck → agent-check → typecheck-coverage → smoke → test
```

If `make verify` is green, the repo is healthy and you're cleared to work.
Then: read [01](01-overview.md)→[06](06-runtime-flows.md) of this wiki, the
nearest `AGENTS.md` to your target, and `docs/solutions/` for anything touching a
documented area.

## Non-negotiable invariants (the landmines)

Breaking any of these silently corrupts governance evidence or trust. They are
repeated across `ARCHITECTURE.md`, `DECISIONS.md`, `AGENTS.md`, `CLAUDE.md` —
believe the repetition.

| Invariant | Rule | Enforced by |
|---|---|---|
| **Constitutional hash** | `608508a9bd224290` is the canonical identity; changing it needs an ADR. `governed_handoff._intake` fails closed if a constitution declares a different one. | `constants.py`, `governed_handoff.py`, guards |
| **Precedent quorum** | 3-of-5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`). | `bittensor/`, mesh |
| **Signed votes mandatory** | `ConstitutionalMesh.submit_vote` requires a valid Ed25519 signature; else `InvalidVoteSignatureError`. No unauthenticated trust updates. | `mesh/core.py` |
| **`manifold.py` is frozen** | Its uniformity collapse is the kept empirical control. **Do not "fix" it** — send the fix through `spectral_sphere.py`. The 2 xfail tests are this collapse. | xfail tests, AGENTS.md |
| **`EvolutionLog` write rules** | Strict monotonicity + non-negative acceleration at write time; raise `NonIncreasingValueError`/`DecelerationBlockedError`, never silently drop. Append-only (no UPDATE/DELETE → `MutationBlockedError`). | `evolution_log.py` |
| **Two-phase audit commit** | `bittensor/arweave_audit_log.py`: cache Phase 1 in `_retry_state`, clear only on Phase 2 success. | `arweave_audit_log.py` |
| **Light core import** | `import constitutional_swarm` must succeed with no optional extras installed. Gate `transport`/`research`/`bittensor`/`langgraph` imports behind functions/`TYPE_CHECKING`. | smoke test, mypy coverage |
| **Public surface in `__init__.py`** | Any new public symbol → add to imports **and** `__all__` (alphabetized). | `make agent-check` |

## Conventions to match

- **Errors are domain-specific exception classes** (see `__init__.py` `__all__`).
  Prefer raising one of these over a bare `ValueError`.
- **`@dataclass(frozen=True)`** for records crossing module boundaries
  (`SettlementRecord`, `MeshProof`, `TransitionCertificate`, …).
- **SQLite-backed stores** (`EvolutionLog`, `SQLiteSettlementStore`) use WAL-safe
  append-only writes.
- **CRDT/Merkle modules** use SHA-256 CIDs for content addressing.
- **Test parity:** every `foo.py` has a `tests/test_foo.py`. Add one when you add
  a module.
- **`latent_dna.py` ruff exceptions:** ~53 pre-existing RUF002/RUF003 (Greek
  characters). **Do not mass-rewrite** — suppress targeted rules if needed.
- **Commands go through `uv`/`make`** — no bare `python`/`pip`/`ruff`/`pytest`.
- **Stage files explicitly** — never `git add -A`. Stage the `.py` and the
  specific docs you changed.

## Git workflow

The most common confusion. Determine your context first:

- **Standalone repo (default, this checkout — own `.git`, own remote):** branch
  from `main`; `git add`/`commit`/`push` from this repo root. This is the normal
  case.
- **Inside the ACGS monorepo (vendored submodule):** `git add`/`commit` from
  inside `packages/constitutional_swarm/`, not the monorepo root; the parent
  integration branch is `fix/p0-security-hardening`. **These submodule rules
  apply only in the monorepo checkout.**

Feature branches live in `.worktrees/` (gitignored):
`git worktree add .worktrees/<name> -b <name>`. Authoritative detail:
[`CLAUDE.md`](../../CLAUDE.md) and [`AGENTS.md`](../../AGENTS.md).

## CI gates (what must pass before merge)

`.github/workflows/`: `ci.yml` (lint + typecheck surfaces + tests),
`agent-check.yml` (registry/doc consistency), `security.yml` (security
regression suite), `tla-check.yml` (TLA+ model checks), `verify-cites.yml`
(citations resolve), `publish.yml` (release). Run `make verify` locally to
front-run most of these. The two blocking mypy jobs are no-extras + `transport`.

## When you hit a blocker

Add a row to [`BLOCKERS.md`](../../BLOCKERS.md) with a unique `Bn` id, status
`Open`, and impact/owner/next-action. If a single `make` target or doc would have
unblocked you, that's the next action. Don't work around a blocker silently.

## Where to record what you learn

- A solved bug / reusable pattern / design or workflow learning →
  `docs/solutions/<category>/` with YAML frontmatter (`module`, `tags`,
  `problem_type`). Future agents grep this first.
- A decision that changes an invariant → an ADR in `docs/internal/` + a row in
  `DECISIONS.md`.
- A new command → a `tools/registry.yaml` entry (+ runbook); `TOOLS.md` is the
  human mirror.

## Quick "am I about to break something?" check

Before committing, ask:
1. Did I touch `manifold.py` to "improve" it? → **Stop.** Use `spectral_sphere.py`.
2. Did I add an unconditional heavy import to a core module? → gate it.
3. Did I add a public symbol without `__all__`? → `make agent-check` will fail.
4. Did I change a vote/receipt/settlement byte format? → check `protocol.py`
   `legacy_*` stability and the verifier.
5. Did I add a module without a test? → add `tests/test_<module>.py`.

Continue to [09 Glossary →](09-glossary.md).
