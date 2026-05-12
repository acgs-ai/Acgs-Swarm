"""Shared TypedDict state schema for LangGraph swarm graphs.

SwarmGraphState carries everything a graph node may read or update during one
task's lifecycle. Total=False so partial updates are valid (LangGraph convention).
"""

from __future__ import annotations

import json
from typing import Annotated, Any, TypedDict

try:
    from langgraph.graph.message import add_messages

    _MessageList = Annotated[list, add_messages]
except ImportError:
    _MessageList = list  # type: ignore[misc]


class SwarmGraphState(TypedDict, total=False):
    task_id: str
    problem_statement: str
    messages: _MessageList  # type: ignore[valid-type]
    patch: str
    cid: str
    governed: bool
    intervention_rate: float
    constitutional_hash: str
    risk_score: float
    violations: list[str]
    peer_votes: dict[str, str]
    quorum_reached: bool
    active_agent: str


def init_state(task: dict[str, Any]) -> SwarmGraphState:
    """Initialize a graph state for one SWE-bench-style task."""
    return SwarmGraphState(
        task_id=task.get("instance_id", "unknown"),
        problem_statement=task.get("problem_statement", ""),
        messages=[],
        patch="",
        cid="",
        governed=False,
        intervention_rate=0.0,
        constitutional_hash="",
        risk_score=0.0,
        violations=[],
        peer_votes={},
        quorum_reached=False,
        active_agent="",
    )


def serialize_for_crdt(state: SwarmGraphState) -> str:
    """Canonical JSON serialization for MerkleCRDT.append payload.

    Drops ``messages`` (LangChain BaseMessage objects aren't JSON-safe and
    aren't part of the auditable artifact contract).
    """
    safe = {k: v for k, v in state.items() if k != "messages"}
    return json.dumps(safe, sort_keys=True, separators=(",", ":"))


__all__ = ["SwarmGraphState", "init_state", "serialize_for_crdt"]
