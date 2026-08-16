# 01 · Overview — mission, patterns, maturity tiers

[← Wiki home](README.md) · Next: [02 Getting Started →](02-getting-started.md)

## The mission

Most multi-agent systems can *execute* tasks. Few can *show their work* —
what policy was applied, which peers validated an output, what decision was
settled, and how to replay the evidence later. `constitutional-swarm` exists to
make that governance trail **first-class and verifiable**, without a central
orchestrator.

It is deliberately **not** a generic agent framework, an orchestration platform,
or a compliance certificate. It is a governance runtime you embed into an
existing agent stack. (See the "What this is / is not" table in
[`README.md`](../../README.md).)

## The four breakthrough patterns

The package docstring (`src/constitutional_swarm/__init__.py`) names four
patterns; everything in the codebase is an elaboration of one of them.

| Pattern | Name | Embodied by | Core idea |
|---|---|---|---|
| **A** | Agent DNA | `dna.py` (`AgentDNA`) | Constitutional validation is *embedded in each agent's runtime path*, not a remote gate. Unsafe outputs are caught locally before acceptance. |
| **B** | Stigmergic Swarm | `compiler.py`, `swarm.py`, `execution.py`, `artifact.py` | Tasks compile to a DAG; capable agents claim and complete nodes; coordination happens through a shared artifact store, **with no orchestrator**. |
| **C** | Constitutional Mesh | `mesh/`, `settlement_store.py`, `governance_receipts*.py`, `quorum_certificate.py`, `validator_set.py` | Peers validate each other's outputs with **mandatory signed votes**; quorum settles decisions into durable, replayable evidence. |
| **D** | Governance Manifold | `spectral_sphere.py` (production), `manifold.py` (baseline control), `swarm_ode.py` | Trust between agents is projected into a **bounded manifold**, guaranteeing bounded influence and compositional stability. |

Patterns A–C are the **stable core**. Pattern D is split: `spectral_sphere.py`
is the production direction; `manifold.py` (Birkhoff/Sinkhorn) is intentionally
**kept as a research control** whose uniformity collapse is the empirical proof
motivating the replacement — see [03-domains.md](03-domains.md#trust-dynamics).

## The MCFS research stack

Beyond the core, the repo hosts the **MCFS** — Manifold-Constrained Federated
Swarm — a research track exploring how far the governance ideas extend:

- **Latent DNA** (`latent_dna.py`, `violation_subspace.py`) — steer an LLM's
  residual stream away from a learned "violation subspace" (BODES/LEACE).
- **Continuous-time trust** (`swarm_ode.py`) — projected RK4 integration of a
  trust vector field, with DP-noise gossip calibration.
- **Content-addressed artifacts** (`merkle_crdt.py`, `gossip_protocol.py`) — a
  Merkle-CRDT DAG that converges across gossiping replicas.
- **Privacy & federation** (`privacy_accountant.py`, `private_vote.py`,
  `federated_bridge.py`) — (ε,δ)-DP accounting, commit-reveal private voting
  with nullifiers, cross-org credential gating.
- **Bittensor subnet** (`bittensor/`) — a full governance subnet:
  miners deliberate, validators grade, an SN-owner escalates, precedents become
  case law and codified rules.
- **Evaluation** (`swe_bench/`, `eval/`, `forensic_benchmark.py`, `bench.py`) —
  SWE-bench solving scaffolds, role-drift detectors, and benchmark protocols.

## Maturity tiers (what to trust)

The single most important mental model for an incoming maintainer: **not all
modules are equally stable.** The repo declares three tiers (see
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) and the README maturity table).

| Tier | Stability | Modules |
|---|---|---|
| **Stable core** | APIs stable; most users start here | `AgentDNA`; `DAGCompiler`/`TaskDAG`/`SwarmExecutor`; `ConstitutionalMesh` + signed-vote workflow; `JSONLSettlementStore`/`SQLiteSettlementStore`; governance receipts + `acgs-verify-receipts`; `governed_handoff` CLI. |
| **Advanced runtime** | Stable APIs, optional in many deployments | remote vote transport (`[transport]`); `EvolutionLog`; `SpectralSphereManifold`; LangGraph adapter (`[langgraph]`/`[langgraph-swarm]`); Bittensor (`[bittensor]`); `epoch_reconfig`, `debate_resolver`, `node_admission`, `validator_set`, `quorum_certificate`. |
| **Research / experimental** | Experimental surfaces — not hardened defaults | `latent_dna` (`[research]`); `swarm_ode`; `merkle_crdt` + `gossip_protocol`; `violation_subspace`; `private_vote`, `privacy_accountant`, `federated_bridge`; `mac_acgs_loop`; `swe_bench/`, `eval/`, `forensic_benchmark`; `manifold.py` (kept control). |

When you make changes: stable-core APIs require care and regression tests;
research modules can iterate freely **except** where an invariant is documented
(`manifold.py` collapse, `EvolutionLog` write rules).

## Relationship to acgs-lite and the ACGS monorepo

- **Built on `acgs-lite`:** this package extends `acgs-lite` from governing
  *single actions* to governing *societies of agents*. `Constitution` and the
  base validation primitives come from `acgs-lite`.
- **Standalone-first, submodule-also:** this checkout is a **standalone repo
  with its own remote** (the default working context). It is *also* vendored as a
  git submodule in the ACGS monorepo. The git workflow differs between the two —
  see [08-handoff.md](08-handoff.md#git-workflow) and [`CLAUDE.md`](../../CLAUDE.md).

Continue to [02 Getting Started →](02-getting-started.md).
