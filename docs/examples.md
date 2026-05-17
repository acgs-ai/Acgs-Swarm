# Examples

This page maps common goals to runnable assets.

## Beginner examples
| Goal | Path | Notes |
|---|---|---|
| Minimal constitution file | [`examples/constitution.yaml`](../examples/constitution.yaml) | Small starter config used by scripts/tests |
| Governed handoff demo | `examples/governed-handoff/` | CLI-oriented governed workflow demo |
| LangGraph demo | [`examples/langgraph_swarm_demo.py`](../examples/langgraph_swarm_demo.py) | Requires LangGraph extras |

## Runtime workflows
| Workflow | Entry point |
|---|---|
| Governed execution with local policy checks | `AgentDNA` + quickstart in [`docs/quickstart.md`](quickstart.md) |
| Peer-validated settlement | `ConstitutionalMesh` quickstart in [`README.md`](../README.md) |
| Receipt verification | `scripts/verify_governance_receipts.py` and `acgs-verify-receipts` |
| Local testnet simulation | `python scripts/testnet_deploy.py --constitution examples/constitution.yaml` |

## Research/evaluation workflows
| Workflow | Entry point |
|---|---|
| SWE-bench-lite swarm evaluation | `scripts/run_swe_bench_swarm_lite.py` |
| Governance benchmark and replication assets | `scripts/run_governance_benchmark.py`, [`docs/public-replication.md`](public-replication.md) |
| Trust convergence evaluation | `scripts/eval_trust_convergence.py` |
| Paper-claim reproduction helpers | `scripts/reproduce_paper_claims.py` |

## Notes
- Treat research/evaluation scripts as experimental unless documented otherwise.
- Install required extras before running optional modules.
