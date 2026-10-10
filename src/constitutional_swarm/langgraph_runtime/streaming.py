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
from constitutional_swarm.langgraph_runtime.guards import (
    has_clean_validation_evidence,
    has_completed_acceptance,
    has_pinned_constitutional_hash,
)
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

    Append the accumulated state to ``crdt`` only when the ``settle_node_name``
    node's own update declares ``governance_status="accepted"`` and the state
    still carries clean validation evidence bound to the same patch. If
    ``gossip_node`` is provided, trigger one gossip round per append.

    Yields each chunk so callers can do their own observation.
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
    async for chunk in graph.astream(inputs, config=cfg, stream_mode="updates"):
        # chunk shape under stream_mode="updates": {node_name: state_update_dict}
        if isinstance(chunk, dict):
            for update in chunk.values():
                if not isinstance(update, dict):
                    continue
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
                snapshot.update(update)
                evidence_keys = {"governed", "risk_score", "violations"}
                if evidence_keys.intersection(update):
                    validated_patch = None
                    if evidence_keys.issubset(update) and has_clean_validation_evidence(snapshot):
                        patch = snapshot.get("patch")
                        if type(patch) is str:
                            validated_patch = patch

            current_patch = snapshot.get("patch")
            # Acceptance must be declared by the settle node's own update; a
            # status accumulated from an intermediate node is not a verdict.
            settle_update = chunk.get(settle_node_name)
            if (
                isinstance(settle_update, dict)
                and type(settle_update.get("governance_status")) is str
                and settle_update.get("governance_status") == "accepted"
                and validated_patch is not None
                and type(current_patch) is str
                and current_patch == validated_patch
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
        yield chunk


__all__ = ["stream_to_crdt"]
