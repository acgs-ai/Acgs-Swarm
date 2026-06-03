"""Conditional-edge guard primitives for LangGraph swarm graphs.

Pure functions: take a state Mapping, return a route name string. No LangGraph
import - these are reusable in any state machine.

Mirrors:
- Fail-closed contract: src/constitutional_swarm/swe_bench/governed_agent.py:135
  (reject if violations OR risk_score >= 0.3)
- Constitutional hash invariant: src/constitutional_swarm/constants.py:9
  (CONSTITUTIONAL_HASH = "608508a9bd224290")
- Precedent quorum: 3-of-5 super-majority (per
  src/constitutional_swarm/mesh/core.py:400)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH

_RISK_THRESHOLD = 0.3
_QUORUM_NUMERATOR = 3
_QUORUM_DENOMINATOR = 5


def constitutional_hash_guard(state: Mapping[str, object]) -> str:
    """Return 'ok' if state's constitutional_hash matches CONSTITUTIONAL_HASH, else 'halt'.

    Fail-closed: missing or empty hash routes to 'halt'.
    """
    actual = state.get("constitutional_hash", "")
    if actual == CONSTITUTIONAL_HASH:
        return "ok"
    return "halt"


def fail_closed_guard(state: Mapping[str, object]) -> str:
    """Return 'accept' if no violations AND risk < threshold; else 'reject'.

    Mirrors swe_bench/governed_agent.py:135 - fail-closed on either signal.
    """
    violations = state.get("violations") or []
    # state is a generic Mapping[str, object]; risk_score is numeric per
    # SwarmGraphState. cast bridges the read-only-object value to float().
    risk = float(cast("float", state.get("risk_score", 0.0) or 0.0))
    if violations or risk >= _RISK_THRESHOLD:
        return "reject"
    return "accept"


def quorum_guard(state: Mapping[str, object]) -> str:
    """Return 'settled' if 3-of-5 super-majority reached, 'continue' otherwise.

    Counts vote values equal to 'accept' in state['peer_votes'].
    """
    votes = state.get("peer_votes") or {}
    if not isinstance(votes, dict):
        return "continue"
    accept_count = sum(1 for v in votes.values() if v == "accept")
    total = len(votes)
    if total >= _QUORUM_DENOMINATOR and accept_count >= _QUORUM_NUMERATOR:
        return "settled"
    return "continue"


__all__ = [
    "constitutional_hash_guard",
    "fail_closed_guard",
    "quorum_guard",
]
