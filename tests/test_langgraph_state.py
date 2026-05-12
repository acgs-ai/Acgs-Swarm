"""Tests for the LangGraph runtime SwarmGraphState schema.

These tests intentionally do NOT require ``langgraph`` to be installed —
the optional-dep pattern in ``state.py`` falls back to a plain ``list``
for the messages annotation, so the module imports cleanly either way.
"""

from __future__ import annotations

import json

from constitutional_swarm.langgraph_runtime.state import (
    SwarmGraphState,
    init_state,
    serialize_for_crdt,
)


def test_init_state_default_keys_and_values():
    """init_state populates every documented field with the right default."""
    state = init_state({})

    assert state["task_id"] == "unknown"
    assert state["problem_statement"] == ""
    assert state["messages"] == []
    assert state["patch"] == ""
    assert state["cid"] == ""
    assert state["governed"] is False
    assert state["intervention_rate"] == 0.0
    assert state["constitutional_hash"] == ""
    assert state["risk_score"] == 0.0
    assert state["violations"] == []
    assert state["peer_votes"] == {}
    assert state["quorum_reached"] is False
    assert state["active_agent"] == ""

    expected_keys = {
        "task_id",
        "problem_statement",
        "messages",
        "patch",
        "cid",
        "governed",
        "intervention_rate",
        "constitutional_hash",
        "risk_score",
        "violations",
        "peer_votes",
        "quorum_reached",
        "active_agent",
    }
    assert set(state.keys()) == expected_keys


def test_init_state_extracts_instance_id_and_problem_statement():
    """init_state pulls instance_id and problem_statement from the task dict."""
    task = {
        "instance_id": "django__django-12345",
        "problem_statement": "Fix the broken admin URL resolver.",
        "extra_field": "ignored",
    }
    state = init_state(task)

    assert state["task_id"] == "django__django-12345"
    assert state["problem_statement"] == "Fix the broken admin URL resolver."
    # Other defaults still hold.
    assert state["patch"] == ""
    assert state["governed"] is False


def test_serialize_for_crdt_is_deterministic_and_sorted():
    """serialize_for_crdt produces sorted-key, compact, deterministic JSON."""
    state = init_state({"instance_id": "abc", "problem_statement": "do thing"})
    # Mutate a couple of fields to make ordering observable.
    state["patch"] = "diff --git a b"
    state["governed"] = True
    state["risk_score"] = 0.25

    payload_a = serialize_for_crdt(state)
    payload_b = serialize_for_crdt(state)

    # Determinism: same input → same string.
    assert payload_a == payload_b

    # Sorted keys: round-trip via json.dumps with sort_keys must match.
    parsed = json.loads(payload_a)
    assert payload_a == json.dumps(parsed, sort_keys=True, separators=(",", ":"))

    # Compact separators: no spaces after colons or commas.
    assert ": " not in payload_a
    assert ", " not in payload_a


def test_serialize_for_crdt_strips_messages():
    """serialize_for_crdt omits the ``messages`` field entirely."""
    state = init_state({"instance_id": "abc"})
    # Inject something that would not be JSON-serializable if included.
    state["messages"] = [object()]  # type: ignore[list-item]

    payload = serialize_for_crdt(state)
    parsed = json.loads(payload)

    assert "messages" not in parsed
    # Sanity: other fields are still present.
    assert parsed["task_id"] == "abc"


def test_swarm_graph_state_allows_partial_dicts():
    """total=False: SwarmGraphState accepts a subset of keys without error."""
    partial: SwarmGraphState = {"task_id": "only-id"}
    assert partial["task_id"] == "only-id"
    assert "patch" not in partial

    # Empty dict is also a valid SwarmGraphState.
    empty: SwarmGraphState = {}
    assert empty == {}

    # serialize_for_crdt handles partials too.
    assert serialize_for_crdt(partial) == '{"task_id":"only-id"}'
    assert serialize_for_crdt(empty) == "{}"
