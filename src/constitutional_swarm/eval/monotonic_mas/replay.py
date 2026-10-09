"""Trace-replay adapter for monotonic-mas-coordination autoresearch mission.

Iterates a JSONL trace corpus and dispatches each trace to the per-mode
detector, returning aggregate per-mode catch rates and a per-trace ledger.

Intentionally does NOT use SwarmCoordinator.run_in_memory — see iter 0001
decision-log entry for the architectural rationale (we exercise the three
governance MECHANISMS directly rather than wrapping the SWE-bench task
abstraction; SwarmCoordinator gets exercised in a follow-up live mission).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from constitutional_swarm.eval.monotonic_mas.detectors import (
    detect_dedupe,
    detect_handoff,
    detect_role,
)
from constitutional_swarm.eval.monotonic_mas.trace_schema import load_traces, validate_trace

Detector = Callable[[dict[str, Any], bool], tuple[bool, dict[str, Any]]]

DEFAULT_DETECTORS: dict[str, Detector] = {
    "redundant_work": detect_dedupe,
    "missed_handoff": detect_handoff,
    "role_drift": detect_role,
}


def run_replay(
    corpus_path: str,
    *,
    governance_enabled: bool,
    traces: list[dict[str, Any]] | None = None,
    detectors: Mapping[str, Detector] | None = None,
) -> dict[str, Any]:
    """Run the corpus through per-mode detectors. Return aggregate stats.

    Returns a dict with per-mode catch rates, per-trace ledger, and BODES
    violation count proxy (counts trace-level role-drift violations seen).
    """
    counts = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    totals = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    unavailable = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    catches = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    semantic_status_counts: dict[str, int] = {}
    semantic_unavailable_reasons: set[str] = set()
    bodes_proxy = 0  # role-drift violations are proxy for BODES violations
    ledger: list[dict[str, Any]] = []
    dispatch = DEFAULT_DETECTORS if detectors is None else detectors

    trace_records = load_traces(corpus_path) if traces is None else [
        validate_trace(trace, line_number=index)
        for index, trace in enumerate(traces, start=1)
    ]
    for trace in trace_records:
        mode = trace["failure_mode"]
        if mode not in dispatch:
            continue
        totals[mode] += 1
        caught, debug = dispatch[mode](trace, governance_enabled)
        if debug.get("status", "available") == "unavailable":
            unavailable[mode] += 1
        else:
            counts[mode] += 1
        if caught:
            catches[mode] += 1
        if mode == "role_drift":
            semantic_status = str(debug.get("semantic_status", "not_reported"))
            semantic_status_counts[semantic_status] = (
                semantic_status_counts.get(semantic_status, 0) + 1
            )
            semantic_reason = debug.get("semantic_unavailable_reason")
            if semantic_status == "unavailable" and semantic_reason:
                semantic_unavailable_reasons.add(str(semantic_reason))
        ledger.append({
            "trace_id": trace["trace_id"],
            "mode": mode,
            "caught": caught,
            "debug": debug,
        })

    # bodes_violations := role_drift events NOT caught by governance.
    # When governance is disabled this naturally equals role-drift total
    # (no suppression). When governance is enabled, every uncaught role-drift
    # action would have been emitted, which is what BODES is designed to
    # prevent — so any non-zero value here means BODES failed.
    bodes_proxy = (
        counts["role_drift"] - catches["role_drift"] if governance_enabled else counts["role_drift"]
    )

    def _rate(mode: str) -> float:
        return catches[mode] / counts[mode] if counts[mode] > 0 else 0.0

    complete = {
        mode: counts[mode] > 0
        and counts[mode] == totals[mode]
        and unavailable[mode] == 0
        for mode in counts
    }
    if semantic_status_counts.get("unavailable", 0) > 0:
        complete["role_drift"] = False

    return {
        "catch_rate_dedupe": _rate("redundant_work"),
        "catch_rate_handoff": _rate("missed_handoff"),
        "catch_rate_role": _rate("role_drift"),
        "traces_per_mode": counts,
        "total_traces_per_mode": totals,
        "unavailable_traces_per_mode": unavailable,
        "complete_traces_per_mode": complete,
        "catches_per_mode": catches,
        "traces_replayed": sum(counts.values()),
        "bodes_violations_proxy": bodes_proxy,
        "semantic_status_counts": semantic_status_counts,
        "semantic_unavailable_reasons": sorted(semantic_unavailable_reasons),
        "ledger": ledger,
    }
