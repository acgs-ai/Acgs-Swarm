"""Constitutional handoff topology via langgraph-swarm.

This module exposes ``build_handoff_swarm`` plus an opt-in
``constitutional_guard_middleware`` helper. The threat model has two layers:

1. **Construction-time hash check** (always-on). ``build_handoff_swarm``
   refuses to compile a swarm whose constitution document does not match
   ``CONSTITUTIONAL_HASH``. This prevents a swarm being assembled around a
   forged constitution.

2. **Runtime per-agent guard** (opt-in helper). ``constitutional_guard_middleware``
   returns a ``before_agent`` AgentMiddleware that halts (``jump_to=end``)
   if ``state["constitutional_hash"]`` does not equal ``CONSTITUTIONAL_HASH``.
   Callers wire it into each peer agent's ``create_agent(middleware=[...])``
   so that an A->B handoff cannot bypass validation: the receiving agent's
   first action is the hash check.

This is an OPTIONAL alt to ``runtime.build_swarm_graph`` (Unit 5). Install with::

    pip install constitutional-swarm[langgraph-swarm]

Notes
-----
* ``build_handoff_swarm`` does NOT introspect agents to verify the runtime
  middleware is attached — that is the caller's responsibility. The helper
  is provided so the wiring is one import away.
* ``langgraph_swarm.create_swarm`` reads ``agent.name`` for routing. The
  ``agent_names`` parameter here is a fail-fast cross-check against that
  attribute so constitution-vs-runtime drift surfaces at construction time
  rather than as a cryptic ``Literal`` mismatch downstream.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH

if TYPE_CHECKING:  # pragma: no cover - typing only
    from langchain.agents.middleware import AgentMiddleware


class LangGraphSwarmUnavailable(ImportError):
    """Raised when ``langgraph_swarm`` (or its peers) is not installed."""


def _import_create_swarm() -> Any:
    """Import ``langgraph_swarm.create_swarm`` lazily.

    Extracted as a module-level seam so tests can monkeypatch the import
    failure path without touching ``sys.modules``.
    """
    try:
        from langgraph_swarm import create_swarm
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise LangGraphSwarmUnavailable(
            "langgraph_swarm not installed; "
            "pip install constitutional-swarm[langgraph-swarm]"
        ) from exc
    return create_swarm


def _import_memory_saver() -> Any:
    """Import ``MemorySaver`` lazily."""
    try:
        from langgraph.checkpoint.memory import MemorySaver
    except ImportError as exc:  # pragma: no cover - langgraph is a hard peer dep
        raise LangGraphSwarmUnavailable(
            "langgraph not installed; "
            "pip install constitutional-swarm[langgraph-swarm]"
        ) from exc
    return MemorySaver


def constitutional_guard_middleware(
    *,
    expected_hash: str = CONSTITUTIONAL_HASH,
    name: str = "constitutional_hash_guard",
) -> AgentMiddleware:
    """Return a ``before_agent`` middleware that fails closed on hash mismatch.

    Wire this into every peer agent so direct A->B handoffs cannot bypass
    validation::

        from langchain.agents import create_agent
        from constitutional_swarm.langgraph_runtime.swarm_topology import (
            constitutional_guard_middleware,
        )

        guard = constitutional_guard_middleware()
        alice = create_agent(model=..., name="alice", middleware=[guard])

    The receiving agent's first action is the hash check; on mismatch the
    middleware returns ``{"jump_to": "end"}`` and the agent never invokes
    the model. The constitutional hash is sourced from state, so the caller
    is responsible for plumbing ``constitutional_hash`` into the swarm's
    ``state_schema`` (extend ``langgraph_swarm.SwarmState``).
    """
    try:
        from langchain.agents import AgentState
        from langchain.agents.middleware import before_agent
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise LangGraphSwarmUnavailable(
            "langchain not installed; "
            "pip install constitutional-swarm[langgraph-swarm]"
        ) from exc

    # Declare the middleware's state-schema contribution. langchain merges
    # this into each agent's compiled state graph; without it, the
    # ``constitutional_hash`` field would be dropped before the guard could
    # read it and every handoff would (incorrectly) halt.
    class _GuardedState(AgentState):
        constitutional_hash: str

    @before_agent(can_jump_to=["end"], state_schema=_GuardedState, name=name)
    def _guard(state: Any, runtime: Any) -> dict[str, Any] | None:
        if isinstance(state, dict):
            actual = state.get("constitutional_hash", "")
        else:  # AgentState dataclass / pydantic-style
            actual = getattr(state, "constitutional_hash", "")
        if actual != expected_hash:
            return {"jump_to": "end"}
        return None

    return _guard


def build_handoff_swarm(
    agents: Sequence[Any],
    *,
    agent_names: Sequence[str],
    constitution: dict[str, Any],
    default_agent: str | None = None,
    checkpointer: Any = None,
) -> Any:
    """Build a guarded handoff swarm.

    Parameters
    ----------
    agents:
        Sequence of compiled langchain agents (results of
        ``langchain.agents.create_agent``). Each must already have a
        ``name`` set; callers are encouraged to also include
        ``constitutional_guard_middleware()`` in each agent's middleware
        list so per-agent runtime validation runs on every handoff.
    agent_names:
        Parallel list of names; must match ``agents`` 1:1 and each
        ``agent_names[i]`` must equal ``agents[i].name``. Drift here is a
        construction error.
    constitution:
        Must have ``constitution["hash"] == CONSTITUTIONAL_HASH`` or this
        raises a fail-closed RuntimeError.
    default_agent:
        Name of the agent to receive the first message. Defaults to
        ``agent_names[0]``.
    checkpointer:
        Optional langgraph checkpointer. Defaults to ``MemorySaver``.

    Returns
    -------
    A compiled langgraph state graph (``CompiledStateGraph``).

    Raises
    ------
    RuntimeError
        If ``constitution["hash"]`` does not equal ``CONSTITUTIONAL_HASH``.
    ValueError
        If ``agents`` and ``agent_names`` lengths differ, or any
        ``agent_names[i] != agents[i].name``.
    LangGraphSwarmUnavailable
        If ``langgraph_swarm`` is not installed.
    """
    actual_hash = constitution.get("hash", "")
    if actual_hash != CONSTITUTIONAL_HASH:
        raise RuntimeError(
            f"constitution hash mismatch: expected {CONSTITUTIONAL_HASH!r}, "
            f"got {actual_hash!r}"
        )

    if len(agents) != len(agent_names):
        raise ValueError(
            f"agents/agent_names length mismatch: "
            f"{len(agents)}/{len(agent_names)}"
        )

    for idx, (agent, declared_name) in enumerate(
        zip(agents, agent_names, strict=True)
    ):
        runtime_name = getattr(agent, "name", None)
        if runtime_name != declared_name:
            raise ValueError(
                f"agent[{idx}] name drift: agent_names[{idx}]={declared_name!r}, "
                f"agent.name={runtime_name!r}"
            )

    chosen_default = default_agent or agent_names[0]
    if chosen_default not in agent_names:
        raise ValueError(
            f"default_agent {chosen_default!r} not in agent_names {list(agent_names)}"
        )

    create_swarm = _import_create_swarm()
    memory_saver_cls = _import_memory_saver()

    swarm = create_swarm(
        agents=list(agents),
        default_active_agent=chosen_default,
    )
    return swarm.compile(checkpointer=checkpointer or memory_saver_cls())


__all__ = [
    "LangGraphSwarmUnavailable",
    "build_handoff_swarm",
    "constitutional_guard_middleware",
]
