# Architecture

Authoritative one-page system view. Deep dives live in
[`docs/architecture.md`](docs/architecture.md),
[`docs/concepts.md`](docs/concepts.md), and
[`docs/security-model.md`](docs/security-model.md).

## What this is

`constitutional-swarm` is an **orchestrator-free constitutional governance
runtime** for multi-agent systems. Governance is embedded *per agent* (Agent
DNA) rather than enforced by a central coordinator; peers validate each other's
outputs with signed votes; decisions settle into a durable, replayable audit
trail. Built on `acgs-lite`.

## Runtime flow

```text
Agent call / input
  → AgentDNA                 local constitutional enforcement (in the agent path)
  → DAGCompiler + SwarmExecutor   orchestrator-free DAG execution
  → ConstitutionalMesh       peer validation with mandatory signed votes
  → SettlementStore          durable finalization evidence (JSONL / SQLite)
  → Governance receipts       canonicalized, replayable audit trail (acgs-verify-receipts)
  → Trust dynamics           spectral_sphere (production) · manifold (baseline control)
```

## Maturity tiers

| Tier | Modules | Stability |
|---|---|---|
| **Stable core** | `AgentDNA`, `DAGCompiler`/`TaskDAG`/`SwarmExecutor`, `ConstitutionalMesh`, settlement stores, governance receipts + verifier | APIs stable |
| **Advanced runtime** | remote vote transport (`[transport]`), `EvolutionLog`, `SpectralSphereManifold`, LangGraph adapter (`[langgraph]`), Bittensor (`[bittensor]`) | stable APIs, optional |
| **Research / experimental** | `latent_dna` (`[research]`), `swarm_ode`, `merkle_crdt` + `gossip_protocol`, `swe_bench/`, `manifold.py` (kept as empirical control) | experimental |

## Data & trust boundaries

- **Local enforcement:** policy checks run *inside* the agent runtime path, not as a gate service.
- **Peer validation:** assigned validators vote on outputs; **signed votes are mandatory** on `ConstitutionalMesh.submit_vote` (Ed25519).
- **Durable settlement:** finalized decisions persist as replayable evidence.
- **Bounded trust dynamics:** trust updates are projected into bounded manifolds (`spectral_sphere`); the `manifold.py` Birkhoff/Sinkhorn baseline is **intentionally not fixed** — its uniformity collapse is the kept empirical control.
- See [`docs/security-model.md`](docs/security-model.md) and [`SECURITY.md`](SECURITY.md).

## Key invariants

- Constitutional hash: `608508a9bd224290`
- Precedent quorum: 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`)
- `EvolutionLog` enforces strict monotonicity + acceleration at write time (SQLite, append-only)
- ArweaveAuditLogger two-phase commit: cache Phase 1 in `_retry_state`, clear only on Phase 2 success

## Optional extras

Heavy dependencies are gated behind extras so the core import stays light:
`transport` (websockets), `research` (torch + latent DNA), `bittensor`,
`langgraph`, `vertex`/`gemini`, `semantic`. See
[`pyproject.toml`](pyproject.toml) `[project.optional-dependencies]`.

## Where things live

Module-by-module and folder-by-folder layout: [`PROJECT_MAP.md`](PROJECT_MAP.md).
Runnable commands: [`TOOLS.md`](TOOLS.md). Design decisions: [`DECISIONS.md`](DECISIONS.md).
