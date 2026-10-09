"""Stream LangGraph events into MerkleCRDT + optional gossip transport.

Pipes ``graph.astream(...)`` updates into the CRDT artifact store and (if a
gossip node is provided) triggers a gossip round so peers converge. The CRDT
verifies CIDs and the constitutional hash on every append; this module does
not bypass those checks.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.state import (
    SwarmGraphState,
    serialize_for_crdt,
)


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
    """Stream graph events; mirror settled states into the CRDT.

    On every chunk where the ``settle_node_name`` node emits an update, append
    the state to ``crdt``. If ``gossip_node`` is provided, trigger one gossip
    round per append.

    Yields each chunk so callers can do their own observation.
    """
    constitutional_hash = inputs.get("constitutional_hash", "")
    if constitutional_hash != CONSTITUTIONAL_HASH:
        raise ValueError(
            "constitutional hash mismatch: "
            f"expected {CONSTITUTIONAL_HASH!r}, got {constitutional_hash!r}"
        )

    cfg = config or {"configurable": {"thread_id": inputs.get("task_id", "stream")}}

    snapshot = dict(inputs)
    async for chunk in graph.astream(inputs, config=cfg, stream_mode="updates"):
        # chunk shape under stream_mode="updates": {node_name: state_update_dict}
        if isinstance(chunk, dict):
            for update in chunk.values():
                if not isinstance(update, dict):
                    continue
                if (
                    "constitutional_hash" in update
                    and update["constitutional_hash"] != constitutional_hash
                ):
                    raise ValueError(
                        "streamed constitutional hash does not match validated input: "
                        f"{update['constitutional_hash']!r}"
                    )
                snapshot.update(update)
            snapshot["constitutional_hash"] = constitutional_hash

            if (
                settle_node_name in chunk
                and snapshot.get("governance_status") == "accepted"
                and snapshot.get("settled") is True
                and snapshot.get("governed") is True
            ):
                payload = serialize_for_crdt(cast("SwarmGraphState", snapshot))
                crdt.append(
                    payload=payload,
                    bodes_passed=True,
                    constitutional_hash=constitutional_hash,
                )
                if gossip_node is not None:
                    await gossip_node.gossip_round(n_peers=gossip_peers)
        yield chunk


__all__ = ["stream_to_crdt"]
