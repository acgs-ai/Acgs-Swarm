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

import math
from collections.abc import Mapping
from typing import cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH

_RISK_THRESHOLD = 0.3
_QUORUM_NUMERATOR = 3
_QUORUM_DENOMINATOR = 5


def has_pinned_constitutional_hash(value: object) -> bool:
    """Return whether *value* is the exact pinned hash string."""
    return type(value) is str and value == CONSTITUTIONAL_HASH


def has_clean_validation_evidence(state: Mapping[str, object]) -> bool:
    """Require explicit, well-formed evidence of clean validation."""
    if state.get("governed") is not True:
        return False
    violations = state.get("violations")
    if type(violations) not in (list, tuple):
        return False
    concrete_violations = cast("list[object] | tuple[object, ...]", violations)
    if len(concrete_violations) != 0:
        return False
    risk = state.get("risk_score")
    if type(risk) not in (int, float):
        return False
    try:
        numeric_risk = float(cast("int | float", risk))
    except OverflowError:
        return False
    return math.isfinite(numeric_risk) and 0.0 <= numeric_risk < _RISK_THRESHOLD


def has_completed_acceptance(state: Mapping[str, object]) -> bool:
    """Require terminal acceptance, a pinned hash, and clean validation."""
    return (
        type(state.get("governance_status")) is str
        and state.get("governance_status") == "accepted"
        and has_pinned_constitutional_hash(state.get("constitutional_hash"))
        and has_clean_validation_evidence(state)
    )


def constitutional_hash_guard(state: Mapping[str, object]) -> str:
    """Return 'ok' if state's constitutional_hash matches CONSTITUTIONAL_HASH, else 'halt'.

    Fail-closed: missing or empty hash routes to 'halt'.
    """
    if has_pinned_constitutional_hash(state.get("constitutional_hash")):
        return "ok"
    return "halt"


def fail_closed_guard(state: Mapping[str, object]) -> str:
    """Return 'accept' if no violations AND risk < threshold; else 'reject'.

    Mirrors swe_bench/governed_agent.py:135 - fail-closed on either signal.
    """
    return "accept" if has_clean_validation_evidence(state) else "reject"


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
    "has_clean_validation_evidence",
    "has_completed_acceptance",
    "has_pinned_constitutional_hash",
    "quorum_guard",
]
