"""Trace-replay adapter for monotonic-mas-coordination autoresearch mission.

Iterates a JSONL trace corpus and dispatches each trace to the per-mode
detector, returning aggregate per-mode catch rates and a per-trace ledger.

Intentionally does NOT use SwarmCoordinator.run_in_memory — see iter 0001
decision-log entry for the architectural rationale (we exercise the three
governance MECHANISMS directly rather than wrapping the SWE-bench task
abstraction; SwarmCoordinator gets exercised in a follow-up live mission).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from constitutional_swarm.eval.monotonic_mas.detectors import (
    detect_dedupe,
    detect_handoff,
    detect_role,
)

_DISPATCH = {
    "redundant_work": detect_dedupe,
    "missed_handoff": detect_handoff,
    "role_drift": detect_role,
}


def run_replay(corpus_path: str, *, governance_enabled: bool) -> dict[str, Any]:
    """Run the corpus through per-mode detectors. Return aggregate stats.

    Returns a dict with per-mode catch rates, per-trace ledger, and BODES
    violation count proxy (counts trace-level role-drift violations seen).
    """
    counts = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    catches = {"redundant_work": 0, "missed_handoff": 0, "role_drift": 0}
    bodes_proxy = 0  # role-drift violations are proxy for BODES violations
    ledger: list[dict[str, Any]] = []

    p = Path(corpus_path)
    if not p.exists():
        raise FileNotFoundError(f"Corpus not found: {corpus_path}")

    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            trace = json.loads(line)
            mode = trace["failure_mode"]
            if mode not in _DISPATCH:
                continue
            counts[mode] += 1
            caught, debug = _DISPATCH[mode](trace, governance_enabled)
            if caught:
                catches[mode] += 1
            # Role-drift catches translate to "BODES caught a violation pre-output."
            # The mission's BODES-violation gate counts UNCAUGHT role-drift
            # violations (i.e. things that escaped governance). With governance
            # enabled, every role-drift catch is suppression — so escaped =
            # role_drift_total - role_caught.
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

    return {
        "catch_rate_dedupe": _rate("redundant_work"),
        "catch_rate_handoff": _rate("missed_handoff"),
        "catch_rate_role": _rate("role_drift"),
        "traces_per_mode": counts,
        "catches_per_mode": catches,
        "traces_replayed": sum(counts.values()),
        "bodes_violations_proxy": bodes_proxy,
        "ledger": ledger,
    }
