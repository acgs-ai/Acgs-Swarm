"""Tests for langgraph_runtime.streaming → MerkleCRDT bridge.

Covers:
1. Settled chunks are mirrored into the CRDT (exactly one node per settle).
2. Appended payload is canonical JSON with the constitutional hash embedded.
3. When a gossip node is provided, gossip_round is invoked per append.
4. When no node reaches ``settle``, the CRDT remains empty.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("langgraph")

from langgraph.graph import END, START, StateGraph  # noqa: I001
from typing_extensions import TypedDict

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.streaming import stream_to_crdt
from constitutional_swarm.merkle_crdt import MerkleCRDT


class _StreamState(TypedDict, total=False):
    task_id: str
    patch: str
    governed: bool
    other: str


def _build_settling_graph() -> Any:
    """Two-node graph: produce -> settle. Both pass via START/END."""

    def produce(state: _StreamState) -> dict:
        return {"patch": "diff --git a b", "governed": True}

    def settle(state: _StreamState) -> dict:
        # Pass through governed + patch so they appear in the ``settle`` update chunk.
        # Under stream_mode="updates", each chunk shows only that node's writes, so the
        # settle node must re-emit any field the CRDT bridge needs to observe.
        return {
            "other": "settled",
            "governed": bool(state.get("governed", False)),
            "patch": state.get("patch", ""),
        }

    builder = StateGraph(_StreamState)
    builder.add_node("produce", produce)
    builder.add_node("settle", settle)
    builder.add_edge(START, "produce")
    builder.add_edge("produce", "settle")
    builder.add_edge("settle", END)
    return builder.compile()


def _build_non_settling_graph() -> Any:
    """Single-node graph that never reaches a ``settle`` node."""

    def only(state: _StreamState) -> dict:
        return {"patch": "noop"}

    builder = StateGraph(_StreamState)
    builder.add_node("only", only)
    builder.add_edge(START, "only")
    builder.add_edge("only", END)
    return builder.compile()


async def _drain(stream) -> list[dict]:
    chunks: list[dict] = []
    async for c in stream:
        chunks.append(c)
    return chunks


async def test_settled_chunk_appended_to_crdt() -> None:
    graph = _build_settling_graph()
    crdt = MerkleCRDT("agent-test")
    assert crdt.size == 0

    inputs = {"task_id": "t-1"}
    chunks = await _drain(stream_to_crdt(graph, inputs, crdt))

    # Exactly one append from the ``settle`` node update.
    assert crdt.size == 1
    # And the chunks were yielded so callers can observe them.
    assert len(chunks) >= 1


async def test_payload_is_canonical_json_with_constitutional_hash() -> None:
    graph = _build_settling_graph()
    crdt = MerkleCRDT("agent-test")

    await _drain(stream_to_crdt(graph, {"task_id": "t-2"}, crdt))

    assert crdt.size == 1
    (only_cid,) = list(crdt.all_cids())
    node = crdt.get(only_cid)
    assert node is not None

    # Payload is canonical JSON (sorted keys, compact separators).
    decoded = json.loads(node.payload)
    assert decoded["constitutional_hash"] == CONSTITUTIONAL_HASH
    assert decoded["task_id"] == "t-2"
    # Canonical form: re-serializing with sort_keys/separators yields the same bytes.
    re_canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), default=str)
    assert re_canonical == node.payload

    # Governed flag flowed through into bodes_passed.
    assert node.bodes_passed is True
    # And the DAG-node constitutional_hash field is set (CRDT-level invariant).
    assert node.constitutional_hash == CONSTITUTIONAL_HASH


async def test_gossip_round_called_once_per_settle() -> None:
    graph = _build_settling_graph()
    crdt = MerkleCRDT("agent-test")

    gossip_node = AsyncMock()
    gossip_node.gossip_round = AsyncMock(return_value={"peers_contacted": 0})

    await _drain(
        stream_to_crdt(
            graph,
            {"task_id": "t-3"},
            crdt,
            gossip_node=gossip_node,
            gossip_peers=3,
        )
    )

    assert crdt.size == 1
    gossip_node.gossip_round.assert_awaited_once_with(n_peers=3)


async def test_no_settle_leaves_crdt_empty() -> None:
    graph = _build_non_settling_graph()
    crdt = MerkleCRDT("agent-test")

    chunks = await _drain(stream_to_crdt(graph, {"task_id": "t-4"}, crdt))

    # Graph emitted chunks but none from a ``settle`` node.
    assert len(chunks) >= 1
    assert crdt.size == 0
