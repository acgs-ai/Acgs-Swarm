# langgraph_runtime — Agent guidance

## What this module is

OUTER message-passing shell over the MCFS kernel. LangGraph `StateGraph`
expresses multi-agent topologies; MCFS math (`swarm_ode`, `spectral_sphere`,
`merkle_crdt`, `evolution_log`) stays authoritative.

## Where to plug in

- New LLM provider -> subclass `LangGraphSWEBenchAgent`, override generation in
  your `graph_factory`'s nodes.
- New topology -> write a new `build_*_graph(...)` factory in this module
  (don't modify `runtime.py`).
- New guard -> add to `guards.py` (pure function on state mapping -> route name).
- New invariant audit -> register an `EvolutionLogObserver` and call from a
  graph callback.

## Hard invariants (do not break)

- Constitutional hash must be checked at the top of every graph entry.
- `AgentDNA.validate` must run on every patch before `append_crdt`.
- Every appended `MerkleCRDT` node must carry the constitutional hash.
- `evolution_log` writes must be strictly monotonic + accelerating (use
  `EvolutionLogObserver`, which handles this).
- `langgraph-swarm` handoffs MUST be wrapped by `constitutional_hash_guard`.

## Testing

- `tests/test_langgraph_*.py`, run with `--import-mode=importlib`.
- Use `FakeListChatModel` from `langchain_core.language_models.fake_chat_models`
  — never real API keys.
- Use `pytest.importorskip("langgraph")` for tests that actually drive a
  compiled graph.

## Do NOT

- Add new constitutional logic in this module — the kernel owns it. This is glue.
- Modify `swe_bench/agent.py`, `swarm_coordinator.py`, `dna.py`,
  `merkle_crdt.py`, `evolution_log.py`, `swarm_ode.py`, or `constants.py` from
  inside this module.
- Touch `latent_dna.py` (53 pre-existing RUF002/RUF003 errors are not our
  problem).
