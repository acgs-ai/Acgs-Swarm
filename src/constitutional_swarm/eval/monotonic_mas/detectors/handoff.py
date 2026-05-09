"""Missed-handoff detector.

Simulates a handoff via two MerkleCRDT replicas + a synchronous merge() loop.
Without governance: the destination replica never merges (handoff dropped).
With governance: gossip-style merges happen each round; we check whether the
artifact arrives at the destination within the trace's deadline_rounds.

We use the synchronous MerkleCRDT.merge() rather than the async
gossip_protocol.SwarmNode because the trace replay is in-process and
deterministic. The catch criterion is the structural property gossip
provides — eventual delivery — not the WebSocket transport itself.
"""

from __future__ import annotations

from constitutional_swarm.merkle_crdt import MerkleCRDT


def detect_handoff(trace: dict, governance_enabled: bool) -> tuple[bool, dict]:
    """Replay a missed_handoff trace; return (caught, debug_info).

    caught=True iff the artifact is present in the dst replica within
    deadline_rounds.
    """
    src_id = trace["context"]["src"]
    dst_id = trace["context"]["dst"]
    deadline = int(trace["context"]["deadline_rounds"])

    src = MerkleCRDT(agent_id=src_id, reject_unverified=True)
    dst = MerkleCRDT(agent_id=dst_id, reject_unverified=True)

    # src produces the artifact
    src.append(payload=trace["payload"], payload_type="handoff", bodes_passed=True)

    delivered_round = None
    if governance_enabled:
        for r in range(1, deadline + 1):
            new = dst.merge(src)
            if new > 0:
                delivered_round = r
                break
    # else: handoff dropped — no merge attempted, dst stays empty

    caught = delivered_round is not None and delivered_round <= deadline
    return caught, {
        "delivered_round": delivered_round,
        "deadline_rounds": deadline,
        "dst_size": len(dst._nodes),
    }
