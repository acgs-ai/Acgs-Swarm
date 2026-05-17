# Architecture overview

## One-view flow
```text
Input/task
  -> AgentDNA (local constitutional check)
  -> DAGCompiler/SwarmExecutor (distributed task execution)
  -> ConstitutionalMesh (peer vote + quorum)
  -> Settlement store (durable finalized result)
  -> Governance receipts verifier path
  -> Trust dynamics updates (optional)
```

## Main runtime components
| Component | Purpose | Tier |
|---|---|---|
| `AgentDNA` (`dna.py`) | Local constitutional enforcement | Stable core |
| `DAGCompiler`, `TaskDAG` (`compiler.py`) | Compile goals into executable DAGs | Stable core |
| `SwarmExecutor` (`swarm.py`) | Capability-based orchestrator-free execution | Stable core |
| `ConstitutionalMesh` (`mesh/`) | Peer validation, signed votes, quorum settlement | Stable core |
| `settlement_store.py` | Durable settlement persistence (JSONL/SQLite) | Stable core |
| `governance_receipts.py` | Replayable governance receipt schema + verification | Stable core |
| `remote_vote_transport/` | Networked peer vote transport | Advanced runtime |
| `evolution_log.py` | Invariant-enforced governance metrics log | Advanced runtime |
| `spectral_sphere.py` | Bounded trust projection (current direction) | Advanced runtime |
| `manifold.py` | Birkhoff/Sinkhorn baseline control | Research/experimental |
| `latent_dna.py`, `swarm_ode.py`, `merkle_crdt.py` | Research modules for MCFS stack | Research/experimental |
| `swe_bench/` | Evaluation scaffolding and harness components | Research/experimental |

## Trust boundaries
1. **Local boundary:** `AgentDNA` validates actions/content before acceptance.
2. **Peer boundary:** assigned validators sign votes; quorum controls finality.
3. **Persistence boundary:** settlement records capture final outcomes for recovery/replay.
4. **Receipt boundary:** canonical payload hashing/signature checks support independent verification.

See [`docs/security-model.md`](security-model.md) for security-focused details.

## Advanced documentation
- LangGraph adapter: [`docs/langgraph_runtime.md`](langgraph_runtime.md)
- Migration guide: [`MIGRATION.md`](../MIGRATION.md)
- MCFS protocol draft: [`docs/maci_dp_protocol.md`](maci_dp_protocol.md)
- Research manuscripts: [`paper/README.md`](../paper/README.md)
