# Tasks

Working roadmap and next actions. Strategic direction lives in
[`docs/roadmap.md`](docs/roadmap.md); architecture decisions in
[`DECISIONS.md`](DECISIONS.md).

## Recently completed

- **Abliteration detector** for swarm-node trust (`eval/monotonic_mas/abliteration_detector.py`) — added, input-validation hardened, edge-case coverage, threat model documented (`docs/internal/abliteration_threat_model.md`).
- **Agent-operability layer** (this change): Makefile one-command targets, `.env.example`, tool registry (`tools/`), agent registry (`agents/`), `scripts/agent_check.py`, `agent-check` CI, and the root understanding docs (ARCHITECTURE / PROJECT_MAP / TOOLS / TASKS / DECISIONS / BLOCKERS).

## Active direction (from `docs/roadmap.md`)

### Stable core
- Improve onboarding docs/examples for governed execution and mesh settlement.
- Maintain API stability for `AgentDNA`, `ConstitutionalMesh`, `SwarmExecutor`, `TaskDAG`.
- Expand regression coverage around signed-vote settlement and replay/recovery.

### Advanced runtime
- Operator guidance for remote vote transport (`[transport]`).
- Stronger examples for receipt verification + settlement evidence.
- Integration quality for LangGraph and Bittensor optional modules.

### Research / experimental
- Iterate on `latent_dna`, `swarm_ode`, `merkle_crdt`.
- Keep `manifold.py` as the baseline control while evaluating the spectral-sphere direction.
- Improve reproducibility assets for benchmark/eval scripts and paper claims.

## Recommended next tasks for an incoming agent

1. **Resolve open blockers** — see [`BLOCKERS.md`](BLOCKERS.md). Highest value: add a dedicated type checker (B3) and align README verification commands with the Makefile (B4).
2. **Land the current branch** — `feat/abliteration-detector`; run `make verify` and open a PR (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).
3. **Backfill registry coverage** — audit `scripts/` and ensure every operator-facing script has a `tools/registry.yaml` entry.
4. **Expand settlement/replay regression tests** (stable-core priority above).

## How to pick up work

```bash
make setup          # one-time
make agent-check    # confirm the repo is self-consistent
make verify         # full local gate before you start changing things
```

Then read [`AGENTS.md`](AGENTS.md) and select a role from
[`agents/`](agents/) that matches your task.
