"""Evidence-based detector for missing and late handoff acknowledgements."""

from __future__ import annotations

def detect_handoff(trace: dict, governance_enabled: bool) -> tuple[bool, dict]:
    """Inspect recorded handoff events after a complete observation window."""
    src_id = trace["context"]["src"]
    dst_id = trace["context"]["dst"]
    deadline = int(trace["context"]["deadline_rounds"])
    events = trace.get("events", [])
    sent = [
        event
        for event in events
        if event.get("type") == "handoff_sent"
        and event.get("src") == src_id
        and event.get("dst") == dst_id
    ]
    if not sent:
        return False, {
            "status": "unavailable",
            "unavailable_reason": "trace has no matching handoff_sent events",
            "handoffs_observed": 0,
        }

    observation_end = trace["context"].get("observation_end_round")
    required_end = max(int(event["round"]) + deadline for event in sent)
    if observation_end is None or int(observation_end) < required_end:
        return False, {
            "status": "unavailable",
            "unavailable_reason": "trace observation window does not cover every deadline",
            "required_observation_end_round": required_end,
            "observation_end_round": observation_end,
        }

    acknowledgements = [event for event in events if event.get("type") == "handoff_ack"]
    failed_ids: list[str] = []
    for handoff in sent:
        matching = [
            event
            for event in acknowledgements
            if event.get("handoff_id") == handoff["handoff_id"]
            and event.get("src") == src_id
            and event.get("dst") == dst_id
            and int(event["round"]) >= int(handoff["round"])
        ]
        deadline_round = int(handoff["round"]) + deadline
        if not matching or min(int(event["round"]) for event in matching) > deadline_round:
            failed_ids.append(handoff["handoff_id"])

    return governance_enabled and bool(failed_ids), {
        "status": "available",
        "deadline_rounds": deadline,
        "handoffs_observed": len(sent),
        "missed_or_late_handoff_ids": failed_ids,
    }
