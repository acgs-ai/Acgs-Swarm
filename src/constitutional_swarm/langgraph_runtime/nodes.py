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

import json
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH

if TYPE_CHECKING:
    from constitutional_swarm.langgraph_runtime.state import SwarmGraphState

# ---------------------------------------------------------------------------
# serialize_for_crdt resolution
#
# Unit 2 (state.py) defines the canonical serializer.  Until Unit 2 lands we
# fall back to a minimal local implementation that mirrors the documented
# contract: stable JSON encoding, private keys (prefixed with "_") stripped.
# Resolving at import time keeps `append_crdt_node` hot-path allocation-free.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - the fallback branch is exercised in worktrees
    from constitutional_swarm.langgraph_runtime.state import (
        serialize_for_crdt as _serialize_for_crdt,
    )
except ImportError:  # Unit 2 not merged yet

    def _serialize_for_crdt(state: SwarmGraphState) -> str:
        """Local fallback serializer; reconciled when Unit 2 merges."""
        public = {k: v for k, v in state.items() if not str(k).startswith("_")}
        return json.dumps(public, default=str, sort_keys=True)


def validate_node(state: Mapping[str, Any], *, dna: Any) -> dict[str, Any]:
    """Run AgentDNA.validate on state['patch']; populate risk_score / violations.

    Empty patch short-circuits with empty violations + zero risk (matches the
    'no_patch_to_govern' branch in swe_bench/governed_agent.py:109).
    """
    patch = state.get("patch", "")
    if not patch:
        return {"violations": [], "risk_score": 0.0, "governed": True}
    result = dna.validate(patch)
    violations = [
        getattr(v, "rule_id", str(v))
        for v in (getattr(result, "violations", ()) or ())
    ]
    return {
        "violations": violations,
        "risk_score": float(getattr(result, "risk_score", 0.0) or 0.0),
        "governed": True,
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
        "constitutional_hash": CONSTITUTIONAL_HASH,
    }


def append_crdt_node(state: Mapping[str, Any], *, crdt: Any) -> dict[str, Any]:
    """Append the current state to a MerkleCRDT.  Returns the new CID in state."""
    # ``dict(state)`` matches the eventual Unit 2 ``serialize_for_crdt`` signature
    # (operates on a concrete dict, not the ``Mapping`` protocol). The cast bridges
    # the read-only ``Mapping`` parameter to the ``SwarmGraphState`` TypedDict the
    # serializer declares; keys are a superset by construction.
    payload = _serialize_for_crdt(cast("SwarmGraphState", dict(state)))
    governed = bool(state.get("governed", False))
    node = crdt.append(payload=payload, bodes_passed=governed)
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
    return {"settled": bool(state.get("quorum_reached", False))}


__all__ = [
    "append_crdt_node",
    "evolve_trust_node",
    "generate_node",
    "settle_node",
    "validate_node",
]
