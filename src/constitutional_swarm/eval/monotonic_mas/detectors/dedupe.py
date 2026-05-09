"""Dedupe detector for redundant_work traces.

HONEST CONTRACT NOTE: MerkleCRDT.append() does NOT natively dedupe by content.
CIDs are computed from (agent_id, payload, parent_cids, ...), so two distinct
agents producing the same payload yield DIFFERENT CIDs. The "set-union dedupe"
property of MerkleCRDT.merge() acts on CID equality, not content equality.

For this mission's "catch redundant work" claim, the detector implements a
governance LAYER on top of MerkleCRDT: a content-hash filter that rejects
appends whose normalized-payload-hash already exists in the local replica.
This is a real governance pattern (workflow dedupe in ACGS) but it is NOT a
native MerkleCRDT feature. The decision log records this clarification so the
final report does not over-claim.
"""

from __future__ import annotations

import hashlib

from constitutional_swarm.merkle_crdt import MerkleCRDT


def _content_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_dedupe(trace: dict, governance_enabled: bool) -> tuple[bool, dict]:
    """Replay a redundant_work trace; return (caught, debug_info).

    The trace contains two agents producing the same payload. We append both,
    optionally with a content-hash dedupe wrapper. caught=True iff the second
    append is rejected as a content duplicate.
    """
    crdt = MerkleCRDT(agent_id="replay-coord", reject_unverified=True)
    payload = trace["payload"]
    seen_hashes: set[str] = set()
    rejections = 0

    for agent_id in trace["agents"]:
        ph = _content_hash(payload)
        if governance_enabled and ph in seen_hashes:
            rejections += 1
            continue
        # Rebind crdt.agent_id per write to mimic the agent producing this node.
        crdt.agent_id = agent_id
        crdt.append(payload=payload, payload_type="patch", bodes_passed=True)
        seen_hashes.add(ph)

    caught = rejections >= 1  # at least one duplicate was filtered
    return caught, {"rejections": rejections, "crdt_size": len(crdt._nodes)}
