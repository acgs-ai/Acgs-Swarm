# LangGraph Runtime

The `constitutional_swarm.langgraph_runtime` package is an OUTER message-passing
shell that wraps the existing MCFS kernel in a LangGraph
[`StateGraph`](https://langchain-ai.github.io/langgraph/) topology. It does not
replace the kernel — `swarm_ode`, `spectral_sphere`, `merkle_crdt`,
`evolution_log`, and `AgentDNA.validate` remain the source of truth for trust
dynamics, manifold projection, artifact storage, monotonic audit, and
constitutional compliance. The runtime simply expresses the multi-agent control
flow (validate -> generate -> append -> settle -> stream) as a graph so we can
use LangGraph features (checkpointing, human-in-the-loop interrupts, streaming,
middleware) without rewriting the math.

This unit ships behind an optional extra (`pip install constitutional-swarm[langgraph]`)
so the base package keeps its minimal dependency footprint. The fail-closed
constitutional contract is preserved end-to-end: the constitutional hash is
checked at graph entry, `AgentDNA.validate` runs on every patch before any
artifact is appended, and quorum / vote machinery stays in `mesh.py` — the
graph only observes its outcome.

## Install

```bash
pip install constitutional-swarm[langgraph]
# Optional handoff topology:
pip install constitutional-swarm[langgraph-swarm]
```

The base extra installs `langgraph >= 1.0` and `langchain >= 1.0`. The
`langgraph-swarm` extra adds the upstream
[`langgraph-swarm`](https://github.com/langchain-ai/langgraph-swarm-py) package
for handoff-style topologies. Neither extra is required for any code outside
`constitutional_swarm.langgraph_runtime`.

## Architecture

```
                                       constitutional_swarm
+--------------------------+         +-------------------------------------+
|  SWEBenchAgent           |         |  langgraph_runtime/                 |
|  swe_bench/agent.py      | <-----> |    runtime.py                       |
|  swe_bench/              |         |    handoff.py                       |
|  governed_agent.py       |         |    streaming.py                     |
|  swarm_coordinator.py    |         |    guards.py                        |
+--------------------------+         |    observers.py                     |
                                     +-------------------------------------+
                                                       |
                                                       v
                                       +-------------------------------------+
                                       |  MCFS kernel (authoritative math)   |
                                       |    merkle_crdt.MerkleCRDT           |
                                       |    evolution_log.EvolutionLog       |
                                       |    swarm_ode.SwarmODE               |
                                       |    spectral_sphere                  |
                                       |    dna.AgentDNA.validate            |
                                       |    constants.CONSTITUTIONAL_HASH    |
                                       +-------------------------------------+
```

The new module sits between the existing agent entry points and the kernel. It
never re-implements kernel logic; it composes kernel calls inside graph nodes.

## Invariants preserved

The following invariants are enforced inside the runtime and MUST NOT be broken
by extensions:

- **Constitutional hash check at graph entry.** Every compiled graph validates
  the incoming state against `constitutional_swarm.constants.CONSTITUTIONAL_HASH`
  (`608508a9bd224290`). A mismatch raises `ConstitutionalHashError` and the
  graph aborts. This mirrors the fail-closed posture of the rest of the package.
- **AgentDNA.validate runs in the `validate` node.** Violations or
  `risk_score >= 0.3` route the graph to `END` with `governed=True` and an empty
  patch — the same contract enforced in
  `swe_bench/governed_agent.py:135`.
- **Every artifact appended to `MerkleCRDT` carries the constitutional hash.**
  The `append_crdt` node attaches the hash to the artifact metadata before
  hashing, so any downstream consumer can verify provenance.
- **`evolution_log` audit mirror enforces append-only monotonicity +
  acceleration.** A registered `EvolutionLogObserver` writes one row per graph
  transition; the SQLite-backed log rejects out-of-order or non-accelerating
  writes at write time, as it does today.
- **Quorum / voting machinery stays in `mesh.py`.** The graph only observes the
  `quorum_reached` field on incoming state; it never decides quorum itself, and
  it never short-circuits the mesh.

## Usage

There are three supported shapes, in order of how much of the existing harness
they replace.

### Shape A — `StateGraph` factory

The lowest-level entry point. `build_swarm_graph` returns a compiled LangGraph
state graph that you can drive directly with `invoke`, `ainvoke`, or `stream`.

```python
from constitutional_swarm.langgraph_runtime import build_swarm_graph
from constitutional_swarm.dna import AgentDNA

constitution = load_constitution("examples/constitution.yaml")
graph = build_swarm_graph(constitution, generator=my_llm_generator)

result = graph.invoke({
    "task_id": "django__django-12345",
    "task": {"instance_id": "django__django-12345", "problem_statement": "..."},
    "agent_dna": AgentDNA.from_constitution(constitution),
})

print(result["patch"], result["governed"])
```

Nodes in the default factory: `validate -> generate -> append_crdt -> settle`,
with an early-exit edge from `validate` to `END` on governance rejection.

### Shape B — `LangGraphSWEBenchAgent` subclass

A drop-in replacement for `SWEBenchAgent` for callers that already expect the
SWE-bench agent surface. The subclass takes a `graph_factory` (defaulting to
`build_swarm_graph`) and runs each task through the compiled graph.

```python
from constitutional_swarm.langgraph_runtime import LangGraphSWEBenchAgent
from constitutional_swarm.swe_bench import SWEBenchHarness

agent = LangGraphSWEBenchAgent(
    constitution=constitution,
    graph_factory=build_swarm_graph,
)
harness = SWEBenchHarness(agent=agent)
report = harness.run(tasks)
```

The subclass slots in anywhere a `SWEBenchAgent` is accepted —
`SwarmCoordinator`, the harness, integration tests — without touching the
caller. Governance metadata (`governed`, `governance_risk_score`,
`governance_violation_rule_ids`) is populated from the graph's final state.

### Shape C — Handoff swarm

For agent-to-agent handoff topologies, `build_handoff_swarm` wraps
`langgraph_swarm.create_swarm` with a constitutional guard on every transition.

```python
from constitutional_swarm.langgraph_runtime import build_handoff_swarm

swarm = build_handoff_swarm(
    agents={"planner": planner_graph, "executor": executor_graph},
    agent_names=("planner", "executor"),
    constitution=constitution,
)

result = swarm.invoke({"messages": [{"role": "user", "content": "Fix the bug."}]})
```

This requires the `[langgraph-swarm]` extra. Without the constitutional guard
wrapper, `langgraph-swarm` would bypass our fail-closed handoff check — see
"Trade-offs" below.

## Human-in-the-loop interrupts

LangGraph's `interrupt_before` argument pauses the graph at a node and exposes
the current state for review. The runtime accepts it on `build_swarm_graph`:

```python
from langgraph.checkpoint.memory import MemorySaver

graph = build_swarm_graph(
    constitution,
    generator=my_llm_generator,
    checkpointer=MemorySaver(),
    interrupt_before=("settle",),
)

config = {"configurable": {"thread_id": "review-1"}}
state = graph.invoke(initial_state, config=config)
# Inspect, mutate, or approve state, then resume:
final = graph.invoke(None, config=config)
```

The pause happens AFTER the constitutional hash check and AFTER
`AgentDNA.validate`, so a human reviewer only sees patches that have already
passed the fail-closed contract. The reviewer's role is approval, not bypass.

## Streaming -> gossip

`stream_to_crdt` adapts LangGraph's `astream` output into a stream of
`MerkleCRDT` artifacts and (optionally) gossip broadcasts.

```python
from constitutional_swarm.langgraph_runtime import stream_to_crdt
from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.gossip_protocol import GossipNode

crdt = MerkleCRDT()
gossip = GossipNode(...)

async for cid in stream_to_crdt(graph, inputs, crdt, gossip_node=gossip):
    print("appended", cid)
```

Each yielded CID corresponds to one artifact appended to the CRDT and
broadcast to peers via the configured gossip node. The function preserves the
constitutional hash on every artifact and is safe to drive from an `asyncio`
event loop.

## Trade-offs

**What LangGraph buys us:**

- **Checkpointing.** `MemorySaver` and (later) `SqliteSaver` give us
  free pause/resume on long-running multi-step runs.
- **Human-in-the-loop.** `interrupt_before` / `interrupt_after` plug into our
  governance review without bespoke wiring.
- **Streaming.** First-class `astream` over node outputs lets us pipe
  intermediate state directly into gossip / CRDT without inventing a callback
  protocol.
- **Middleware.** Per-node observers (logging, tracing, metrics) compose
  cleanly without monkey-patching the agent.

**What it costs us:**

- **Second source of truth for control flow.** The MCFS kernel already encodes
  who runs when. The graph is a parallel description of the same control flow
  in LangGraph terms. We pay for this in mental overhead and in keeping the two
  in sync when the kernel evolves.
- **Dependency tree.** `langgraph` and `langchain` together pull in a
  non-trivial set of transitive packages. We isolate this behind an optional
  extra.
- **`langgraph-swarm` bypasses fail-closed by default.** Out of the box,
  `langgraph_swarm.create_swarm` lets agents hand off without re-validating
  invariants. We wrap every handoff in `constitutional_hash_guard` so the hash
  check fires on every transition, but this is glue we own — upstream does not
  enforce it.

**Recommendation.** Use LangGraph as the OUTER shell and keep `swarm_ode`,
`spectral_sphere`, `merkle_crdt`, and `evolution_log` as the INNER kernel. The
graph orchestrates; the kernel decides. New constitutional logic belongs in the
kernel, not in this module.

## Version pinning rationale

- **`langgraph 1.x` (GA, October 2025).** Production-ready API, stable
  `StateGraph` / `MessagesState` semantics, supported checkpointer interface.
- **`langchain 1.0`.** `create_agent` is now the canonical factory for chat
  agents. `AgentExecutor` and `langgraph.prebuilt.create_react_agent` remain as
  deprecated shims and SHOULD NOT be used in new code paths.
- **`langgraph-swarm` (pinned major).** Used only for handoff topologies and
  wrapped by our guard layer.

We pin `>= 1.0, < 2.0` on both LangChain and LangGraph until a 2.x migration
plan exists.

## Future work

- **Pluggable LLM providers.** Today `generator=...` is a callable. A small
  Protocol with `generate(messages, **kwargs) -> str` will let providers
  (Anthropic, OpenAI, local, fake) drop in without touching node code.
- **Persistent `SqliteSaver` for production runs.** `MemorySaver` is fine for
  tests and demos but loses state on restart. A `SqliteSaver` checkpointer
  scoped per-thread is the natural next step.
- **Multi-node distributed checkpointing.** For the mesh case, checkpointer
  state should replicate over the same gossip transport that backs MerkleCRDT,
  so a graph paused on node A can resume on node B.
- **Tracing middleware.** A LangSmith-compatible tracer would let us see
  per-node latencies and token counts without adding code to each node.
