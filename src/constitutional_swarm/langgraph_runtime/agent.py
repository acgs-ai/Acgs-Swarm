"""LangGraph-backed SWE-bench agent.

Subclasses :class:`SWEBenchAgent` (``swe_bench/agent.py:68``) and overrides
``_generate_patch`` to drive a per-task LangGraph ``StateGraph``. The base
class still owns timeout handling, error capture, and ``SWEPatch``
construction; this class only owns generation.

Composable with :class:`GovernedAgent` (``swe_bench/governed_agent.py``) — wrap
an instance in ``GovernedAgent`` for post-hoc constitutional validation on top
of the in-flight guard nodes inside the graph.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from constitutional_swarm.langgraph_runtime.guards import has_completed_acceptance
from constitutional_swarm.swe_bench.agent import SWEBenchAgent

if TYPE_CHECKING:
    from constitutional_swarm.latent_dna import LatentDNAWrapper


class LangGraphSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates generation to a compiled LangGraph.

    Parameters
    ----------
    graph_factory:
        Callable returning a CompiledStateGraph for this agent. Called once
        per task (so the graph can be parameterised by task metadata). The
        graph's ``invoke(state)`` must return a state dict with ``patch``,
        ``intervention_rate``, ``governed=True``, a finite ``risk_score`` below
        the runtime threshold, an empty concrete ``violations`` sequence, the
        exact pinned ``constitutional_hash``, and
        ``governance_status="accepted"`` emitted only after completion.
        ``settled`` is optional peer-quorum evidence and does not authorize
        patch release.
    llm:
        Optional ``langchain_core.language_models.BaseChatModel`` used by the
        graph's internal nodes. The ``graph_factory`` is responsible for
        wiring it in; this attribute is just held for introspection.
    model_name:
        Identifier recorded in result metadata. Defaults to
        ``"langgraph-swarm-agent"``.
    max_new_tokens:
        Token budget for patch generation (passed through to the base class).
    timeout_s:
        Hard timeout used by the base ``solve()`` wrapper.
    wrapper:
        Optional :class:`LatentDNAWrapper` mirrored on the base class. The
        graph factory typically reads this off the agent instance to wire in
        BODES steering inside graph nodes.
    constitutional_hash:
        Caller-validated constitution hash placed in initial graph state.
        When omitted, :func:`init_state` preserves a hash carried by the task.
    """

    def __init__(
        self,
        *,
        graph_factory: Callable[[], Any],
        llm: Any = None,
        model_name: str = "langgraph-swarm-agent",
        max_new_tokens: int = 512,
        timeout_s: float = 60.0,
        wrapper: LatentDNAWrapper | None = None,
        constitutional_hash: str | None = None,
    ) -> None:
        super().__init__(
            wrapper=wrapper,
            model_name=model_name,
            max_new_tokens=max_new_tokens,
            timeout_s=timeout_s,
        )
        self._graph_factory = graph_factory
        self._llm = llm
        self._constitutional_hash = constitutional_hash

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Run the compiled graph for one task and unpack patch + stats.

        Returns
        -------
        (patch_str, stats_dict)
            ``stats_dict`` always contains ``intervention_rate`` (float),
            validation evidence, ``constitutional_hash`` (str), and
            ``settled`` (bool). A patch is returned only for explicit completed
            acceptance; additional graph-emitted keys are merged in.
        """
        from constitutional_swarm.langgraph_runtime.state import init_state

        graph = self._graph_factory()
        initial = init_state(task, constitutional_hash=self._constitutional_hash)

        config = {"configurable": {"thread_id": initial.get("task_id", "unknown")}}
        result = graph.invoke(initial, config=config)

        stats: dict[str, Any] = {
            "intervention_rate": float(result.get("intervention_rate", 0.0)),
            "violations": result.get("violations"),
            "risk_score": result.get("risk_score"),
            "governed": result.get("governed"),
            "constitutional_hash": result.get("constitutional_hash", "") or "",
            "settled": bool(result.get("settled", False)),
        }
        governance_status = result.get("governance_status")
        if governance_status is not None:
            stats["governance_status"] = governance_status
        if not has_completed_acceptance(result):
            # Only terminal verdicts keep their own label; anything else
            # (including "accepted" without complete evidence) is incomplete.
            if type(governance_status) is str and governance_status in {"rejected", "halted"}:
                stats["error"] = f"governance_{governance_status}"
            else:
                stats["error"] = "governance_incomplete"
            return "", stats
        patch = result.get("patch", "")
        if type(patch) is not str:
            stats["governance_status"] = "rejected"
            stats["error"] = "invalid_patch"
            return "", stats
        stats["violations"] = list(result["violations"])
        return patch, stats


__all__ = ["LangGraphSWEBenchAgent"]
