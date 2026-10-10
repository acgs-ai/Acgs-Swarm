"""Stream LangGraph events into MerkleCRDT + optional gossip transport.

Pipes ``graph.astream(...)`` updates into the CRDT artifact store and (if a
gossip node is provided) triggers a gossip round so peers converge. The CRDT
verifies CIDs and the constitutional hash on every append; this module does
not bypass those checks.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import aclosing
from typing import Any, cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.guards import (
    has_clean_validation_evidence,
    has_completed_acceptance,
    has_pinned_constitutional_hash,
)
from constitutional_swarm.langgraph_runtime.state import (
    SwarmGraphState,
    serialize_for_crdt,
)

_EVIDENCE_KEYS = frozenset({"governed", "risk_score", "violations"})


def _is_cached_update(chunk: object) -> bool:
    """Return True when an ``updates`` chunk replays cached or pending writes."""
    if not isinstance(chunk, dict):
        return False
    metadata = chunk.get("__metadata__")
    return isinstance(metadata, dict) and bool(metadata.get("cached"))


async def stream_to_crdt(
    graph: Any,
    inputs: dict,
    crdt: Any,
    *,
    gossip_node: Any | None = None,
    settle_node_name: str = "settle",
    gossip_peers: int = 2,
    config: dict | None = None,
) -> AsyncIterator[dict]:
    """Stream graph events; mirror the settled final state into the CRDT.

    After the stream is exhausted, append the accumulated state to ``crdt``
    once, and only when the final patch is the patch that the validating node
    checked with clean evidence AND the patch that the ``settle_node_name``
    node saw when its own last update declared ``governance_status="accepted"``.
    The decision waits for the end of the stream because LangGraph emits
    same-step sibling updates as separate chunks: a sibling streamed after the
    settle node can still rewrite the state the graph ends with. If
    ``gossip_node`` is provided, trigger one gossip round after the append.

    Each node update is bound to the patch the node actually read, taken from
    LangGraph's ``tasks`` stream (the task's input state), so a same-step
    sibling cannot attach validation evidence or a settle verdict to a patch
    the node never saw. Graphs that ignore ``stream_mode`` and yield plain
    ``{node: update}`` chunks are treated as sequential: the patch a node read
    is the accumulated patch before its update. Writes whose read patch cannot
    be established fail closed: a cached or re-applied update
    (``__metadata__.cached``) or a task whose result event never arrives means
    no append.

    Yields each ``{node_name: update}`` chunk so callers can do their own
    observation. A caller that stops iterating early gets no append, and
    closing this generator closes the graph's stream.
    """
    constitutional_hash = inputs.get("constitutional_hash", "")
    if not has_pinned_constitutional_hash(constitutional_hash):
        raise ValueError(
            "constitutional hash mismatch: "
            f"expected {CONSTITUTIONAL_HASH!r}, got {constitutional_hash!r}"
        )

    cfg = config or {"configurable": {"thread_id": inputs.get("task_id", "stream")}}

    snapshot = dict(inputs)
    snapshot.update(
        {
            "cid": "",
            "governed": False,
            "risk_score": None,
            "violations": None,
            "settled": False,
            "governance_status": "rejected",
        }
    )
    validated_patch: str | None = None
    settle_patch: str | None = None
    task_input_patches: dict[object, object] = {}
    # LangGraph re-applies cached node results and pending writes as an
    # ``updates`` chunk with no task result event, so the patch those writes
    # were made against is unknown. Either signal withholds the append.
    unobserved_writes = False

    def observe(node_name: object, update: object, read_patch: object) -> None:
        nonlocal validated_patch, settle_patch
        if node_name == "__metadata__":
            return
        if not isinstance(update, dict):
            return
        if "constitutional_hash" in update and not (
            has_pinned_constitutional_hash(update["constitutional_hash"])
            and update["constitutional_hash"] == constitutional_hash
        ):
            raise ValueError(
                "streamed constitutional hash does not match validated input: "
                f"{update['constitutional_hash']!r}"
            )
        if "patch" in update:
            patch_update = update["patch"]
            if type(patch_update) is not str or patch_update != validated_patch:
                validated_patch = None
            # A node attests to its own output patch, not the one it read.
            read_patch = patch_update
        snapshot.update(update)
        if _EVIDENCE_KEYS.intersection(update):
            validated_patch = None
            if (
                _EVIDENCE_KEYS.issubset(update)
                and has_clean_validation_evidence(snapshot)
                and type(read_patch) is str
            ):
                validated_patch = read_patch
        # Acceptance must be declared by the settle node's own update; a
        # status accumulated from an intermediate node is not a verdict.
        if (
            type(node_name) is str
            and node_name == settle_node_name
            and "governance_status" in update
        ):
            status = update["governance_status"]
            accepted = type(status) is str and status == "accepted"
            settle_patch = read_patch if accepted and type(read_patch) is str else None

    async with aclosing(
        graph.astream(inputs, config=cfg, stream_mode=["updates", "tasks"])
    ) as stream:
        async for chunk in stream:
            if isinstance(chunk, tuple) and len(chunk) == 2:
                mode, data = chunk
                if mode == "updates":
                    if _is_cached_update(data):
                        unobserved_writes = True
                    yield data
                elif mode == "tasks" and isinstance(data, dict):
                    task_id = data.get("id")
                    if "input" in data:
                        task_input = data["input"]
                        task_input_patches[task_id] = (
                            task_input.get("patch")
                            if isinstance(task_input, dict)
                            else getattr(task_input, "patch", None)
                        )
                    elif "result" in data:
                        read_patch = task_input_patches.pop(task_id, None)
                        if data.get("error") is None:
                            observe(data.get("name"), data["result"], read_patch)
                continue
            # Plain ``{node: update}`` chunk from a graph without stream modes.
            if isinstance(chunk, dict):
                if _is_cached_update(chunk):
                    unobserved_writes = True
                for node_name, update in chunk.items():
                    observe(node_name, update, snapshot.get("patch"))
            yield chunk

    current_patch = snapshot.get("patch")
    if (
        not unobserved_writes
        and not task_input_patches
        and validated_patch is not None
        and type(current_patch) is str
        and current_patch == validated_patch
        and current_patch == settle_patch
        and has_completed_acceptance(snapshot)
    ):
        payload = serialize_for_crdt(cast("SwarmGraphState", snapshot))
        crdt.append(
            payload=payload,
            bodes_passed=has_clean_validation_evidence(snapshot),
            constitutional_hash=constitutional_hash,
        )
        if gossip_node is not None:
            await gossip_node.gossip_round(n_peers=gossip_peers)


__all__ = ["stream_to_crdt"]
