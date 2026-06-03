# Tasks

Working roadmap and next actions. Strategic direction lives in
[`docs/roadmap.md`](docs/roadmap.md); architecture decisions in
[`DECISIONS.md`](DECISIONS.md).

## Recently completed

- **Abliteration detector** for swarm-node trust (`eval/monotonic_mas/abliteration_detector.py`) — added, input-validation hardened, edge-case coverage, threat model documented (`docs/internal/abliteration_threat_model.md`). Merged via #56.
- **DSSE/in-toto receipt projector** (`governance_receipts_dsse.py`) — merged via #55.
- **Agent-operability layer + correctness fixes** (PR #57): Makefile one-command targets, `.env.example`, tool registry (`tools/`), agent registry (`agents/`), `scripts/agent_check.py`, `agent-check` CI, the root understanding docs; plus two fixes — `SpectralSphereManifold` smoothing default `0.999→0.9` and `private_vote` reveal-validity gate — and onboarding-blocker fixes (B4/B5/B7).

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

1. **Resolve open blockers** — see [`BLOCKERS.md`](BLOCKERS.md). All onboarding blockers are now resolved or mitigated (B3 mypy gate and B6 standalone-vs-submodule framing both closed); remaining type-checker work is graduating the allow-listed modules in `[tool.mypy]`.
2. **Add DSSE receipts to the tool registry** — `governance_receipts_dsse.py` (merged via #55) is not yet represented in `tools/registry.yaml`; add an entry and any runbook.
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
