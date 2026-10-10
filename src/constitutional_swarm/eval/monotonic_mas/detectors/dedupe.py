"""Evidence-based detector for independently completed duplicate work."""

from __future__ import annotations

import hashlib


def _canonical_payload(payload: str) -> str:
    """Return the identity used for completed-work duplicate detection."""
    return " ".join(payload.casefold().split())


def _content_hash(payload: str) -> str:
    return hashlib.sha256(_canonical_payload(payload).encode("utf-8")).hexdigest()


def detect_dedupe(trace: dict, governance_enabled: bool) -> tuple[bool, dict]:
    """Inspect recorded completion events without manufacturing observations.

    A repeated canonical payload is redundant completed work even when both
    completion events belong to the same agent. Event identity is validated by
    the trace schema; distinct event IDs represent distinct completion records.
    """
    completions = [
        event for event in trace.get("events", []) if event.get("type") == "work_completed"
    ]
    if not completions:
        return False, {
            "status": "unavailable",
            "unavailable_reason": "trace has no independent work_completed events",
            "duplicate_policy": "repeated canonical payload",
            "completion_events": 0,
            "duplicate_events": 0,
        }

    seen_hashes: set[str] = set()
    duplicates = 0
    for event in completions:
        payload_hash = _content_hash(event["payload"])
        if payload_hash in seen_hashes:
            duplicates += 1
        seen_hashes.add(payload_hash)

    return governance_enabled and duplicates > 0, {
        "status": "available",
        "duplicate_policy": "repeated canonical payload",
        "completion_events": len(completions),
        "duplicate_events": duplicates,
    }
