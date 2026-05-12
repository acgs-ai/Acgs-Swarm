"""Stream LangGraph events into MerkleCRDT + optional gossip transport.

Pipes ``graph.astream(...)`` updates into the CRDT artifact store and (if a
gossip node is provided) triggers a gossip round so peers converge. The CRDT
verifies CIDs and the constitutional hash on every append; this module does
not bypass those checks.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH


def _serialize_state(state: Any) -> str:
    """Canonical JSON for CRDT payload. Strips ``messages`` (BaseMessage objects)."""
    if not isinstance(state, dict):
        return json.dumps({"value": str(state)}, sort_keys=True, separators=(",", ":"))
    safe = {k: v for k, v in state.items() if k != "messages"}
    return json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)


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
    cfg = config or {"configurable": {"thread_id": inputs.get("task_id", "stream")}}

    async for chunk in graph.astream(inputs, config=cfg, stream_mode="updates"):
        # chunk shape under stream_mode="updates": {node_name: state_update_dict}
        if isinstance(chunk, dict) and settle_node_name in chunk:
            settled_update = chunk[settle_node_name]
            payload_state = {**inputs, **(settled_update or {})}
            payload_state.setdefault("constitutional_hash", CONSTITUTIONAL_HASH)
            payload = _serialize_state(payload_state)
            governed = bool(payload_state.get("governed", False))
            crdt.append(
                payload=payload,
                bodes_passed=governed,
                constitutional_hash=CONSTITUTIONAL_HASH,
            )
            if gossip_node is not None:
                await gossip_node.gossip_round(n_peers=gossip_peers)
        yield chunk


__all__ = ["stream_to_crdt"]
