"""LangGraph StateGraph factory for constitutional swarm runtime.

The factory compiles a LangGraph graph that wraps MCFS primitives as the
authoritative kernel. Nodes call into existing constitutional_swarm
primitives; the graph only handles orchestration and fail-closed guards.

Fail-closed contract:
    - Constitution hash mismatch raises ConstitutionalHashError at build time.
    - At runtime, the constitutional_hash_guard halts the graph if the
      generated state lacks the expected hash.
    - The fail_closed_guard short-circuits to END if a validator records any
      violation or the risk_score crosses the 0.3 threshold.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, TypedDict, cast

from constitutional_swarm.constants import CONSTITUTIONAL_HASH


class ConstitutionalHashError(RuntimeError):
    """Raised when a constitution's hash does not match the package constant."""


def _state_schema():
    """Return the state schema for the StateGraph.

    Prefer the canonical ``SwarmState`` from Unit 1; fall back to a local
    TypedDict so per-key dict merging (the LangGraph default for TypedDict
    schemas) is preserved even before Unit 1 lands. A plain ``dict`` schema
    replaces the entire state on every node return, which is not the
    intended semantics.
    """
    try:
        from constitutional_swarm.langgraph_runtime.state import SwarmState

        return SwarmState
    except ImportError:

        class SwarmState(TypedDict, total=False):
            patch: str
            violations: list
            risk_score: float
            intervention_rate: float
            governed: bool
            constitutional_hash: str
            cid: str
            quorum_reached: bool
            settled: bool
            messages: list

        return SwarmState


def _import_or_stub_guards():
    """Import shipped guards from Unit 3, else provide minimal stubs."""
    try:
        from constitutional_swarm.langgraph_runtime.guards import (
            constitutional_hash_guard,
            fail_closed_guard,
        )

        return constitutional_hash_guard, fail_closed_guard
    except ImportError:

        def constitutional_hash_guard(state: Mapping[str, object]) -> str:
            return (
                "ok"
                if state.get("constitutional_hash") == CONSTITUTIONAL_HASH
                else "halt"
            )

        def fail_closed_guard(state: Mapping[str, object]) -> str:
            risk = float(cast("float", state.get("risk_score", 0.0) or 0.0))
            if state.get("violations") or risk >= 0.3:
                return "reject"
            return "accept"

        return constitutional_hash_guard, fail_closed_guard


def _import_or_stub_nodes():
    """Import shipped nodes from Unit 2, else provide minimal stubs."""
    try:
        from constitutional_swarm.langgraph_runtime.nodes import (
            append_crdt_node,
            generate_node,
            settle_node,
            validate_node,
        )

        return generate_node, validate_node, append_crdt_node, settle_node
    except ImportError:

        def generate_node(
            state: Mapping[str, Any],
            *,
            generator: Callable[[Mapping[str, Any]], tuple[str, dict[str, Any]]],
        ) -> dict[str, Any]:
            patch, stats = generator(state)
            return {
                "patch": patch,
                "intervention_rate": float(stats.get("intervention_rate", 0.0)),
                "constitutional_hash": CONSTITUTIONAL_HASH,
            }

        def validate_node(state: Mapping[str, Any], *, dna: Any) -> dict[str, Any]:
            patch = state.get("patch", "")
            if not patch or dna is None:
                return {"violations": [], "risk_score": 0.0, "governed": True}
            r = dna.validate(patch)
            return {
                "violations": [
                    getattr(v, "rule_id", str(v))
                    for v in (getattr(r, "violations", ()) or ())
                ],
                "risk_score": float(getattr(r, "risk_score", 0.0) or 0.0),
                "governed": True,
            }

        def append_crdt_node(state: Mapping[str, Any], *, crdt: Any) -> dict[str, Any]:
            if crdt is None:
                return {"cid": ""}
            payload = json.dumps(
                {k: v for k, v in state.items() if k != "messages"},
                sort_keys=True,
                separators=(",", ":"),
            )
            cid = crdt.append(
                payload=payload, bodes_passed=bool(state.get("governed", False))
            )
            return {"cid": str(cid)}

        def settle_node(state: Mapping[str, Any]) -> dict[str, Any]:
            return {"settled": bool(state.get("quorum_reached", False))}

        return generate_node, validate_node, append_crdt_node, settle_node


def build_swarm_graph(
    constitution: dict[str, Any],
    *,
    generator: Callable[[Any], tuple[str, dict]],
    dna: Any = None,
    crdt: Any = None,
    checkpointer: Any = None,
    interrupt_before: tuple[str, ...] = (),
):
    """Compile a constitutional StateGraph.

    Fail-closed on hash mismatch — raises ConstitutionalHashError.

    Parameters
    ----------
    constitution:
        Must contain a ``hash`` key equal to ``CONSTITUTIONAL_HASH`` or
        compilation aborts before any graph is built.
    generator:
        Callable invoked by ``generate_node``. Returns ``(patch, stats)``.
    dna:
        Optional DNA validator instance with a ``validate(patch)`` method.
    crdt:
        Optional MerkleCRDT instance with an ``append(payload, bodes_passed)`` method.
    checkpointer:
        LangGraph checkpointer. Defaults to a fresh ``MemorySaver()``.
    interrupt_before:
        Tuple of node names to interrupt before. Passed through to
        ``StateGraph.compile``.

    Returns
    -------
    CompiledStateGraph
        Ready-to-invoke LangGraph runnable.
    """
    actual = constitution.get("hash", "")
    if actual != CONSTITUTIONAL_HASH:
        raise ConstitutionalHashError(
            f"constitution hash mismatch: expected {CONSTITUTIONAL_HASH!r}, "
            f"got {actual!r}"
        )

    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph

    hash_guard, fc_guard = _import_or_stub_guards()
    generate_node, validate_node, append_crdt_node, settle_node = (
        _import_or_stub_nodes()
    )

    g = StateGraph(_state_schema())
    g.add_node("generate", lambda s: generate_node(s, generator=generator))
    g.add_node("validate", lambda s: validate_node(s, dna=dna))
    g.add_node("append_crdt", lambda s: append_crdt_node(s, crdt=crdt))
    g.add_node("settle", settle_node)

    g.add_edge(START, "generate")
    g.add_conditional_edges(
        "generate", hash_guard, {"ok": "validate", "halt": END}
    )
    g.add_conditional_edges(
        "validate", fc_guard, {"accept": "append_crdt", "reject": END}
    )
    g.add_edge("append_crdt", "settle")
    g.add_edge("settle", END)

    return g.compile(
        checkpointer=checkpointer or MemorySaver(),
        interrupt_before=list(interrupt_before),
    )


__all__ = ["ConstitutionalHashError", "build_swarm_graph"]
