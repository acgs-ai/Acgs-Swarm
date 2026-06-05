# constitutional-swarm
[![PyPI](https://img.shields.io/pypi/v/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![Python](https://img.shields.io/pypi/pyversions/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Orchestrator-free constitutional governance runtime for multi-agent systems.**

## 30-second explanation
`constitutional-swarm` extends `acgs-lite` from governing single actions to governing societies of agents.
It combines local constitutional enforcement (`AgentDNA`), DAG-based swarm execution (`SwarmExecutor`), peer validation (`ConstitutionalMesh`), durable settlement stores, replayable governance receipts, and bounded trust dynamics.

This package is **not** a generic agent framework and **not** an all-in-one orchestration platform.
It is a governance runtime you can embed into your existing agent stack.

## Why it exists
Most multi-agent systems can execute tasks, but fewer can show:
- what policy was applied,
- which peers validated outputs,
- what decision was settled,
- and how to replay evidence later.

`constitutional-swarm` focuses on governed execution and verifiable governance evidence.

## What this package provides
- Local constitutional checks on agent actions (`AgentDNA`)
- Orchestrator-free task execution over DAGs (`DAGCompiler`, `SwarmExecutor`)
- Peer validation with signed votes and quorum settlement (`ConstitutionalMesh`)
- Durable settlement persistence (`JSONLSettlementStore`, `SQLiteSettlementStore`)
- Replayable governance receipts and verifier tooling (`governance_receipts`, `acgs-verify-receipts`)
- Trust-dynamics modules with bounded projection (`spectral_sphere`, `manifold` baseline)

## What this package does not provide
- A full hosted agent platform
- Turnkey workflow UI / dashboards
- Compliance certification or regulator approval
- A claim that all modules are production-ready
- A replacement for your existing model/runtime/orchestration tools

## What this is / what this is not
| This is | This is not |
|---|---|
| An orchestrator-free governance runtime | A generic no-governance multi-agent framework |
| Local constitutional enforcement + peer validation | A centralized coordinator product |
| Durable settlement + replayable receipts | A compliance certificate |
| Stable core plus clearly separated research modules | A claim that all APIs are stable |

## Install
Requires Python **3.11+** (`pyproject.toml`).

```bash
# Core runtime
pip install constitutional-swarm

# Optional extras
pip install "constitutional-swarm[transport]"   # websockets remote-vote transport
pip install "constitutional-swarm[research]"    # torch + transformers research stack
pip install "constitutional-swarm[bittensor]"   # Bittensor subnet integration
pip install "constitutional-swarm[langgraph]"   # LangGraph runtime adapter
pip install "constitutional-swarm[langgraph-swarm]"  # LangGraph handoff topology
```

## 5-minute quickstart
Create `quickstart.py`:

```python
from acgs_lite import Constitution
from constitutional_swarm import AgentDNA, ConstitutionalMesh

# 1) Local constitutional enforcement
# Start with default constitutional rules, then load custom rules as needed.
agent = AgentDNA.default(agent_id="worker-1")
validation = agent.validate("summarize the meeting notes")
assert validation.valid

# 2) Peer-validated settlement
constitution = Constitution.default()
required_votes = 2
mesh = ConstitutionalMesh(constitution, peers_per_validation=3, quorum=required_votes)
mesh.register_local_signer("producer", domain="writing")
mesh.register_local_signer("peer-1", domain="writing")
mesh.register_local_signer("peer-2", domain="writing")
mesh.register_local_signer("peer-3", domain="writing")

assignment = mesh.request_validation("producer", "safe draft content", "artifact-1")
for voter_id in assignment.peers[:required_votes]:
    mesh.submit_vote(
        assignment.assignment_id,
        voter_id,
        approved=True,
        reason="constitutional check passed",
        signature=mesh.sign_vote(
            assignment.assignment_id,
            voter_id,
            approved=True,
            reason="constitutional check passed",
        ),
    )

result = mesh.get_result(assignment.assignment_id)
print(result.accepted, result.quorum_met, result.settled)
```

Run it:

```bash
python quickstart.py
```

Expected: settled quorum result (`accepted=True`, `quorum_met=True`, `settled=True`).

## Architecture in one view
```text
Agent call/input
  -> AgentDNA (local constitutional enforcement)
  -> DAGCompiler + SwarmExecutor (orchestrator-free execution)
  -> ConstitutionalMesh (peer validation + signed votes)
  -> SettlementStore (durable finalization evidence)
  -> Governance receipts / verifier (replayable audit trail)
  -> Trust dynamics (spectral_sphere current direction, manifold baseline control)
```

## Maturity tiers
### Stable core
- `AgentDNA`
- `DAGCompiler`, `TaskDAG`, `SwarmExecutor`
- `ConstitutionalMesh` signed-vote workflow
- `JSONLSettlementStore`, `SQLiteSettlementStore`
- Governance receipts + verifier CLI (`acgs-verify-receipts`)

### Advanced runtime (stable APIs, optional in many deployments)
- Remote vote transport (`constitutional_swarm.remote_vote_transport`, `[transport]`)
- `EvolutionLog` invariant-enforced governance metrics
- `SpectralSphereManifold` bounded trust dynamics (current direction)
- LangGraph runtime adapter (`[langgraph]`, `[langgraph-swarm]`)
- Bittensor integration (`[bittensor]`)

### Research / experimental modules
- `latent_dna` (BODES-based steering hooks, `[research]`)
- `swarm_ode`
- `merkle_crdt` + `gossip_protocol`
- `swe_bench/` evaluation modules and scripts
- `manifold.py` Birkhoff/Sinkhorn baseline retained as research control

## Core concepts
- **Governed execution:** each step can be policy-checked before execution/acceptance.
- **Local constitutional enforcement:** policy checks run inside the agent runtime path.
- **Peer validation:** assigned peers vote on outputs with signatures.
- **Durable settlement:** final decisions are persisted as replayable evidence.
- **Replayable receipts:** governance receipts are canonicalized and verifiable.
- **Bounded trust dynamics:** trust updates are projected into bounded manifolds.

## Common use cases
- Governed agent execution in coding/review workflows
- Peer-validated output acceptance before downstream automation
- Decentralized or orchestrator-free agent task flows
- Governance receipt generation and settlement evidence retention
- Research experiments on trust dynamics and swarm behavior

## When to use this package
Use `constitutional-swarm` when you need:
- verifiable governance steps inside agent workflows,
- peer-validated acceptance/rejection,
- durable, replayable governance evidence,
- explicit separation between stable runtime and research modules.

## When not to use this package
Choose another tool first when you need:
- only basic orchestration with no governance/validation,
- a hosted platform with UI-first operations,
- fully fixed APIs across all experimental modules,
- compliance attestations by default.

## Examples
- `examples/constitution.yaml` — minimal constitution config
- `examples/langgraph_swarm_demo.py` — LangGraph adapter example
- `examples/governed-handoff/` — governed coding-agent handoff demo
- See [`docs/examples.md`](docs/examples.md) for task-oriented walkthroughs

## Security and trust boundaries
- See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and support policy.
- See [`docs/security-model.md`](docs/security-model.md) for technical trust boundaries.
- Signed votes are required for `ConstitutionalMesh.submit_vote`.
- Remote vote transport security mode should be configured explicitly for non-loopback use.
- Treat optional research modules as experimental surfaces, not hardened defaults.

## Documentation map
> **Maintainers & AI agents:** start at the consolidated wiki —
> [`docs/wiki/`](docs/wiki/README.md). It ties these docs together with
> per-module code logic, end-to-end runtime flows, the roadmap, and a handoff
> checklist.

| Audience | Start here | Then read |
|---|---|---|
| New contributors | [`docs/quickstart.md`](docs/quickstart.md) | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`docs/community.md`](docs/community.md) |
| Runtime integrators | [`docs/concepts.md`](docs/concepts.md) | [`docs/architecture.md`](docs/architecture.md), [`docs/security-model.md`](docs/security-model.md) |
| Agent-framework maintainers | [`docs/architecture.md`](docs/architecture.md) | [`docs/langgraph_runtime.md`](docs/langgraph_runtime.md), [`MIGRATION.md`](MIGRATION.md) |
| Governance/community contributors | [`docs/community.md`](docs/community.md) | [`docs/roadmap.md`](docs/roadmap.md), [`docs/faq.md`](docs/faq.md) |
| Researchers | [`docs/roadmap.md`](docs/roadmap.md) | [`docs/maci_dp_protocol.md`](docs/maci_dp_protocol.md), [`paper/README.md`](paper/README.md), `docs/internal/*` |

## Verification commands

This repo is `uv`-managed; prefer the one-command targets (see [`TOOLS.md`](TOOLS.md)):

```bash
make setup        # create the venv + install dev extras (standalone-safe)
make verify       # lint -> agent-check -> smoke -> tests
make agent-check  # validate agent/tool registries + doc completeness
```

The equivalent raw invocations run through the venv (no global `python`/`pip`/`ruff` is assumed):

```bash
uv run --no-sync ruff check src/constitutional_swarm/
uv run --no-sync ruff format --check src/
uv run --no-sync pytest tests/ --import-mode=importlib -q
uv run --no-sync pytest -m "not slow and not e2e and not research" tests/ --import-mode=importlib -q
uv build
```

If optional extras are installed, run targeted suites (for example transport or research-marked tests).

## Contributing
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## Roadmap
See [`docs/roadmap.md`](docs/roadmap.md).

## License
AGPL-3.0-or-later (see package metadata in `pyproject.toml`).
