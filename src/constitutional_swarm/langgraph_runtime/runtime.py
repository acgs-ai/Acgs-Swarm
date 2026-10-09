"""LangGraph StateGraph factory for constitutional swarm runtime.

The factory compiles a LangGraph graph that wraps MCFS primitives as the
authoritative kernel. Nodes call into existing constitutional_swarm
primitives; the graph only handles orchestration and fail-closed guards.

Fail-closed contract:
    - Constitution hash mismatch raises ConstitutionalHashError at build time.
    - At runtime, the constitutional_hash_guard halts before generation when
      caller state lacks the expected hash and checks the same value again
      after generation.
    - The fail_closed_guard short-circuits to END if a validator records any
      violation or the risk_score crosses the 0.3 threshold.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.guards import (
    constitutional_hash_guard,
    fail_closed_guard,
)
from constitutional_swarm.langgraph_runtime.nodes import (
    append_crdt_node,
    generate_node,
    settle_node,
    validate_node,
)
from constitutional_swarm.langgraph_runtime.state import SwarmGraphState


class ConstitutionalHashError(RuntimeError):
    """Raised when a constitution's hash does not match the package constant."""


def build_swarm_graph(
    constitution: dict[str, Any],
    *,
    generator: Callable[[Any], tuple[str, dict]],
    dna: Any,
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
        Required DNA validator instance with a ``validate(patch)`` method.
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
    if dna is None:
        raise ValueError("dna is required for constitutional graph validation")

    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph

    g = StateGraph(SwarmGraphState)
    g.add_node("generate", lambda s: generate_node(s, generator=generator))
    g.add_node("validate", lambda s: validate_node(s, dna=dna))
    g.add_node("append_crdt", lambda s: append_crdt_node(s, crdt=crdt))
    g.add_node("settle", lambda s: settle_node(s))
    g.add_node("accept", lambda _state: {"governance_status": "accepted"})
    g.add_node(
        "reject",
        lambda _state: {
            "patch": "",
            "governed": False,
            "cid": "",
            "settled": False,
            "governance_status": "rejected",
        },
    )
    g.add_node(
        "halt",
        lambda _state: {
            "patch": "",
            "governed": False,
            "cid": "",
            "settled": False,
            "governance_status": "halted",
        },
    )

    g.add_conditional_edges(
        START, constitutional_hash_guard, {"ok": "generate", "halt": "halt"}
    )
    g.add_conditional_edges(
        "generate", constitutional_hash_guard, {"ok": "validate", "halt": "halt"}
    )
    g.add_conditional_edges(
        "validate", fail_closed_guard, {"accept": "accept", "reject": "reject"}
    )
    g.add_edge("accept", "append_crdt")
    g.add_edge("append_crdt", "settle")
    g.add_edge("settle", END)
    g.add_edge("halt", END)
    g.add_edge("reject", END)

    return g.compile(
        checkpointer=checkpointer or MemorySaver(),
        interrupt_before=list(interrupt_before),
    )


__all__ = ["ConstitutionalHashError", "build_swarm_graph"]
