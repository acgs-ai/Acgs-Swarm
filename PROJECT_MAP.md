# Project Map

Folder-by-folder guide. For the runtime view see
[`ARCHITECTURE.md`](ARCHITECTURE.md); for commands see [`TOOLS.md`](TOOLS.md).

## Top level

| Path | What it is |
|---|---|
| `src/constitutional_swarm/` | The Python package (all runtime + research code). |
| `tests/` | Pytest suite (~1665 collected). `tests/security/` = one test per audit finding; `tests/fixtures/` = shared data. |
| `scripts/` | Operational & eval CLIs (deploy, benchmarks, reproduction, `agent_check.py`). |
| `agents/` | **Agent registry** — one `<role>.agent.yaml` manifest per role + JSON schema. |
| `tools/` | **Tool registry** — `registry.yaml`, `schemas/`, `runbooks/`. |
| `examples/` | Runnable artifacts (`constitution.yaml`, `governed-handoff/`, LangGraph demo). |
| `docs/` | Long-form design docs; `docs/internal/` holds ADRs, audits, and research notes. |
| `specs/` | TLA+ formal specifications + model-checker configs. |
| `paper/`, `papers/`, `references.bib` | Package paper draft, conference drafts (ICLR/NDSS 2027), shared BibTeX. |
| `.github/workflows/` | CI: `ci.yml`, `agent-check.yml`, `security.yml`, `publish.yml`, `tla-check.yml`, `verify-cites.yml`. |

## Package modules (`src/constitutional_swarm/`)

### Stable core
| Module | Purpose |
|---|---|
| `dna.py` | `AgentDNA` — local constitutional enforcement embedded per agent. |
| `compiler.py`, `execution.py`, `swarm.py` | DAG compilation + orchestrator-free execution. |
| `mesh/` | `ConstitutionalMesh` — peer validation, signed votes, settlement. |
| `settlement_store.py` | Durable JSONL / SQLite settlement evidence. |
| `governance_receipts.py`, `governance_receipts_cli.py` | Canonicalized receipts + `acgs-verify-receipts`. |
| `governed_handoff.py` | `acgs-swarm` CLI — governed task handoff (run/verify/pack). |
| `quorum_certificate.py`, `validator_set.py`, `contract.py`, `capability.py` | Quorum, validator selection, contracts, capabilities. |

### Advanced runtime
| Module | Purpose |
|---|---|
| `remote_vote_transport/`, `gossip_protocol.py` | Remote/gossip vote transport (`[transport]`). |
| `evolution_log.py` | Invariant-enforced governance metrics (monotonicity + acceleration). |
| `spectral_sphere.py` | `SpectralSphereManifold` — bounded trust dynamics (production direction). |
| `langgraph_runtime/` | LangGraph adapter (`[langgraph]`, `[langgraph-swarm]`). |
| `bittensor/` | Bittensor subnet integration (`[bittensor]`). |
| `epoch_reconfig.py`, `debate_resolver.py`, `settlement_store.py` | Reconfiguration, debate resolution, settlement. |

### Research / experimental
| Module | Purpose |
|---|---|
| `latent_dna.py`, `dna.py` hooks | BODES residual steering (`[research]`). |
| `swarm_ode.py` | Projected RK4 continuous-time trust dynamics. |
| `merkle_crdt.py` | Content-addressed DAG artifact store (SHA-256 CIDs). |
| `manifold.py` | Birkhoff/Sinkhorn baseline — **do not fix** (kept empirical control). |
| `swe_bench/` | SWE-bench evaluation scaffold (agents, harness, coordinator). |
| `eval/` | Evaluation utilities incl. `monotonic_mas/abliteration_detector.py`. |
| `privacy_accountant.py`, `private_vote.py`, `federated_bridge.py` | DP accounting, private voting, federation. |

Other notable modules: `artifact.py`, `constants.py`, `protocol.py`,
`violation_subspace.py`, `forensic_benchmark.py`, `bench.py`,
`mac_acgs_loop.py`, `governed_handoff.py`.

## Per-directory guides

Most directories ship their own `AGENTS.md` with local detail:
`src/constitutional_swarm/AGENTS.md`, `tests/`, `scripts/`, `docs/`,
`examples/`, `specs/`, `paper/`, `papers/`. Start from the root
[`AGENTS.md`](AGENTS.md).
