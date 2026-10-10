"""Node primitives for LangGraph swarm graphs.

Each function takes a state Mapping and returns a partial update dict (the
LangGraph add_node convention). These are pure-ish -- they may call into
MerkleCRDT or AgentDNA side-effects, but they don't depend on a live graph
runtime. They can be unit-tested in isolation with stubs.

Wraps:
- AgentDNA.validate          (dna.py:215)
- MerkleCRDT.append          (merkle_crdt.py:151)
- swarm_ode.SwarmODE.__call__ (swarm_ode.py:50, 116)
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from typing import Any, cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.guards import (
    has_clean_validation_evidence,
    has_pinned_constitutional_hash,
)
from constitutional_swarm.langgraph_runtime.state import (
    SwarmGraphState,
    serialize_for_crdt,
)


def validate_node(state: Mapping[str, Any], *, dna: Any) -> dict[str, Any]:
    """Run AgentDNA.validate on state['patch']; populate risk_score / violations.

    Empty patch short-circuits with empty violations + zero risk (matches the
    'no_patch_to_govern' branch in swe_bench/governed_agent.py:109).
    """
    if dna is None:
        raise ValueError("dna is required for constitutional patch validation")
    if not has_pinned_constitutional_hash(getattr(dna, "hash", None)):
        raise ValueError("DNA hash does not match the package constitutional hash")

    patch = state.get("patch", "")
    if not patch:
        return {"violations": [], "risk_score": 0.0, "governed": True}
    result = dna.validate(patch)
    if not has_pinned_constitutional_hash(getattr(dna, "hash", None)):
        raise ValueError("DNA hash changed during constitutional patch validation")
    if (
        not hasattr(result, "valid")
        or not hasattr(result, "violations")
        or not hasattr(result, "risk_score")
    ):
        raise ValueError("validator returned incomplete validation evidence")
    valid = result.valid
    if type(valid) is not bool:
        raise ValueError("validator valid verdict must be a boolean")
    reported_violations = result.violations
    if type(reported_violations) not in (list, tuple):
        raise ValueError("validator violations must be a concrete sequence")
    violations: list[str] = []
    for violation in reported_violations:
        rule_id = getattr(violation, "rule_id", violation)
        if type(rule_id) is not str:
            raise ValueError("validator violation identifiers must be strings")
        violations.append(rule_id)
    reported_risk = result.risk_score
    if type(reported_risk) not in (int, float):
        raise ValueError("validator risk_score must be numeric")
    try:
        risk_score = float(reported_risk)
    except OverflowError as exc:
        raise ValueError("validator risk_score is outside the supported range") from exc
    if not math.isfinite(risk_score) or risk_score < 0.0:
        raise ValueError("validator risk_score must be finite and non-negative")
    return {
        "violations": violations,
        "risk_score": risk_score,
        "governed": valid,
    }


def generate_node(
    state: Mapping[str, Any],
    *,
    generator: Callable[[Mapping[str, Any]], tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Delegate generation to a callable injected from the SWEBenchAgent subclass.

    The generator returns ``(patch_str, stats_dict)`` exactly like
    ``SWEBenchAgent._generate_patch``.
    """
    patch, stats = generator(state)
    return {
        "patch": patch,
        "intervention_rate": float(stats.get("intervention_rate", 0.0)),
        "cid": "",
        "governed": False,
        "risk_score": 0.0,
        "violations": [],
        "settled": False,
        "governance_status": "rejected",
    }


def append_crdt_node(state: Mapping[str, Any], *, crdt: Any) -> dict[str, Any]:
    """Append the current state to a MerkleCRDT.  Returns the new CID in state."""
    constitutional_hash = state.get("constitutional_hash", "")
    if not has_pinned_constitutional_hash(constitutional_hash):
        raise ValueError(
            "constitutional hash mismatch: "
            f"expected {CONSTITUTIONAL_HASH!r}, got {constitutional_hash!r}"
        )
    if not has_clean_validation_evidence(state):
        raise ValueError("clean validation evidence is required before CRDT append")
    if crdt is None:
        return {"cid": ""}
    # ``serialize_for_crdt`` accepts a plain mapping snapshot.
    # (operates on a concrete dict, not the ``Mapping`` protocol). The cast bridges
    # the read-only ``Mapping`` parameter to the ``SwarmGraphState`` TypedDict the
    # serializer declares; keys are a superset by construction.
    payload = serialize_for_crdt(cast("SwarmGraphState", dict(state)))
    node = crdt.append(
        payload=payload,
        bodes_passed=True,
        constitutional_hash=constitutional_hash,
    )
    # MerkleCRDT.append returns a DAGNode whose CID lives on .cid; stubs may
    # return a plain string -- coerce uniformly via str().
    cid = getattr(node, "cid", node)
    return {"cid": str(cid)}


def evolve_trust_node(
    state: Mapping[str, Any],
    *,
    ode: Any,
    h: Any,
    t: float,
    dt: float = 0.1,
) -> dict[str, Any]:
    """Step the swarm trust ODE.

    Calls ``ode(h, t)`` per ``swarm_ode.py:50`` (``__call__(self, H, t) -> Tensor``).
    Returns the new trust matrix in a private key so the caller can persist it
    without bloating graph state.
    """
    h_next = ode(h, t)
    return {
        "trust_step_completed": True,
        "trust_step_t": t + dt,
        "_h_next": h_next,
    }


def settle_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Settlement step.

    Vote collection is decoupled (Plan invariant #9 -- mesh handles voting; the
    graph only reflects whether quorum was reached upstream).
    """
    if not has_pinned_constitutional_hash(
        state.get("constitutional_hash")
    ) or not has_clean_validation_evidence(state):
        return {
            "patch": "",
            "cid": "",
            "governed": False,
            "settled": False,
            "governance_status": "rejected",
        }
    return {
        "settled": bool(state.get("quorum_reached", False)),
        "governance_status": "accepted",
    }


__all__ = [
    "append_crdt_node",
    "evolve_trust_node",
    "generate_node",
    "settle_node",
    "validate_node",
]
