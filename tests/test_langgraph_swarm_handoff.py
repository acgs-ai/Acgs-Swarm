"""Tests for the langgraph-swarm handoff topology (Unit 8).

These tests are skipped unless the optional langgraph-swarm / langchain
stack is installed. They cover four invariants:

1. ``build_handoff_swarm`` with a matching constitution hash compiles.
2. ``build_handoff_swarm`` with a mismatched constitution hash raises
   ``RuntimeError`` (fail-closed).
3. The compiled graph exposes each agent as an addressable node.
4. The import path raises ``LangGraphSwarmUnavailable`` when
   ``langgraph_swarm`` cannot be imported.

A fifth direct-call test verifies the ``constitutional_guard_middleware``
helper halts agents whose runtime state carries a forged hash.
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "langgraph_swarm",
    reason="langgraph_swarm not installed - skip handoff topology tests",
)
pytest.importorskip(
    "langchain",
    reason="langchain not installed - skip handoff topology tests",
)
pytest.importorskip(
    "langchain_core",
    reason="langchain_core not installed - skip handoff topology tests",
)

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime import swarm_topology
from constitutional_swarm.langgraph_runtime.swarm_topology import (
    LangGraphSwarmUnavailable,
    build_handoff_swarm,
    constitutional_guard_middleware,
)
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import (
    FakeListChatModel,
)


def _make_agent(name: str, response: str = "ok"):
    """Build a trivial named agent backed by a fake list chat model."""
    return create_agent(
        model=FakeListChatModel(responses=[response]),
        name=name,
    )


def _valid_constitution() -> dict:
    return {"hash": CONSTITUTIONAL_HASH, "principles": ["P1"], "domains": ["D1"]}


def test_build_handoff_swarm_compiles_with_matching_hash():
    """A matching constitution hash + well-formed agents must compile."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")

    compiled = build_handoff_swarm(
        agents=[alice, bob],
        agent_names=["alice", "bob"],
        constitution=_valid_constitution(),
    )

    # Verify a compiled langgraph object — supports invoke + get_graph
    assert hasattr(compiled, "invoke")
    assert hasattr(compiled, "get_graph")


def test_build_handoff_swarm_rejects_mismatched_hash():
    """A forged constitution hash must fail closed at construction time."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")

    bad_constitution = {"hash": "deadbeefdeadbeef"}

    with pytest.raises(RuntimeError, match="constitution hash mismatch"):
        build_handoff_swarm(
            agents=[alice, bob],
            agent_names=["alice", "bob"],
            constitution=bad_constitution,
        )


def test_compiled_graph_has_agents_addressable_by_name():
    """Each declared agent name must appear as a node in the compiled graph."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")
    carol = _make_agent("carol")

    compiled = build_handoff_swarm(
        agents=[alice, bob, carol],
        agent_names=["alice", "bob", "carol"],
        constitution=_valid_constitution(),
        default_agent="alice",
    )

    node_keys = set(compiled.get_graph().nodes.keys())
    for name in ("alice", "bob", "carol"):
        assert name in node_keys, f"agent {name!r} not addressable in {node_keys!r}"


def test_import_path_raises_when_langgraph_swarm_missing(monkeypatch):
    """If langgraph_swarm cannot be imported, surface a typed error."""

    def _fail_import():
        raise LangGraphSwarmUnavailable(
            "langgraph_swarm not installed (simulated)"
        )

    monkeypatch.setattr(
        swarm_topology, "_import_create_swarm", _fail_import
    )

    alice = _make_agent("alice")
    bob = _make_agent("bob")

    with pytest.raises(LangGraphSwarmUnavailable):
        build_handoff_swarm(
            agents=[alice, bob],
            agent_names=["alice", "bob"],
            constitution=_valid_constitution(),
        )


def test_build_handoff_swarm_rejects_name_drift():
    """agent_names[i] must match agents[i].name (fail-fast on construction drift)."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")

    with pytest.raises(ValueError, match="name drift"):
        build_handoff_swarm(
            agents=[alice, bob],
            agent_names=["alice", "robert"],  # declared name != agent.name
            constitution=_valid_constitution(),
        )


def test_build_handoff_swarm_rejects_length_mismatch():
    """agent_names length must match agents length."""
    alice = _make_agent("alice")

    with pytest.raises(ValueError, match="length mismatch"):
        build_handoff_swarm(
            agents=[alice],
            agent_names=["alice", "bob"],
            constitution=_valid_constitution(),
        )


def test_constitutional_guard_middleware_halts_on_forged_hash():
    """The middleware helper must short-circuit agents on hash mismatch.

    Exercises the runtime per-handoff enforcement helper directly: a peer
    agent wired with ``constitutional_guard_middleware`` must NOT invoke its
    model when ``state["constitutional_hash"]`` is forged, and MUST invoke
    its model when the hash matches.
    """
    guard = constitutional_guard_middleware()
    agent = create_agent(
        model=FakeListChatModel(responses=["bob speaks"]),
        name="bob",
        middleware=[guard],
    )

    # Mismatch: only the user message remains; no AI response was generated.
    forged = agent.invoke(
        {
            "messages": [{"role": "user", "content": "ping"}],
            "constitutional_hash": "deadbeefdeadbeef",
        }
    )
    assert len(forged["messages"]) == 1

    # Match: the agent runs and the fake model produces one AI response.
    ok = agent.invoke(
        {
            "messages": [{"role": "user", "content": "ping"}],
            "constitutional_hash": CONSTITUTIONAL_HASH,
        }
    )
    assert len(ok["messages"]) == 2
