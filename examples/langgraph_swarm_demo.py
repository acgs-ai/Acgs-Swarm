"""End-to-end demo: 3 LangGraph agents x 5 mock SWE-bench tasks.

Run:
    pip install constitutional-swarm[langgraph]
    python examples/langgraph_swarm_demo.py

Uses FakeListChatModel -- no API key required.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Make the demo runnable from a source checkout (no install required).
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from constitutional_swarm.swe_bench.agent import SWEBenchAgent  # noqa: E402


class MockSolverAgent(SWEBenchAgent):
    """Deterministic stub agent for the demo -- returns a fixed pseudo-patch."""

    def __init__(self, *, agent_id: str, **kwargs: Any) -> None:
        super().__init__(model_name=f"mock-{agent_id}", **kwargs)
        self._agent_id = agent_id

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        instance = task.get("instance_id", "unknown")
        patch = (
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            f"+fix-by-{self._agent_id}-for-{instance}\n"
        )
        return patch, {"intervention_rate": 0.0, "agent_id": self._agent_id}


def _make_tasks(n: int = 5) -> list[dict[str, str]]:
    return [
        {
            "instance_id": f"demo__demo-{i:03d}",
            "problem_statement": f"Demo bug #{i}: fix the off-by-one.",
        }
        for i in range(n)
    ]


def _fallback_run_langgraph(
    agents: list[SWEBenchAgent], tasks: list[dict[str, Any]]
) -> dict[str, Any]:
    """Local fallback that delegates to ``SwarmCoordinator.run_in_memory``.

    Used when the ``langgraph_runtime`` sibling units have not landed yet.
    Reusing the existing coordinator keeps the demo aligned with the canonical
    assignment + aggregation semantics.
    """
    from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator

    return SwarmCoordinator(agents).run_in_memory(tasks)


def _make_graph_factory(agent_id: str):
    """Build a tiny deterministic LangGraph factory for the demo.

    The real runtime wires provider/model nodes inside this factory. For the
    checkout demo we keep it local and deterministic so it runs without API
    keys while still exercising ``LangGraphSWEBenchAgent`` through a compiled
    graph.
    """

    def _factory():
        from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]

        def generate_node(state: dict[str, Any]) -> dict[str, Any]:
            task_id = state.get("task_id") or state.get("instance_id") or "unknown"
            patch = (
                "--- a/file.py\n"
                "+++ b/file.py\n"
                "@@ -1 +1 @@\n"
                "-old\n"
                f"+fix-by-{agent_id}-for-{task_id}\n"
            )
            return {
                "patch": patch,
                "intervention_rate": 0.0,
                "violations": [],
                "constitutional_hash": "",
                "settled": False,
            }

        builder = StateGraph(dict)
        builder.add_node("generate", generate_node)
        builder.add_edge(START, "generate")
        builder.add_edge("generate", END)
        return builder.compile()

    return _factory


def _build_agents() -> list[SWEBenchAgent]:
    """Build three agents.

    Prefer the LangGraph-backed agent if the runtime extension is available;
    otherwise fall back to a deterministic mock subclass of SWEBenchAgent.
    """
    try:
        from constitutional_swarm.langgraph_runtime.agent import (  # type: ignore[import-not-found]
            LangGraphSWEBenchAgent,
        )
        from langchain_core.language_models.fake_chat_models import (  # type: ignore[import-not-found]
            FakeListChatModel,
        )

        agents: list[SWEBenchAgent] = []
        for i in range(3):
            llm = FakeListChatModel(
                responses=[
                    "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n"
                    f"+fix-by-a{i}\n"
                ]
            )
            agents.append(
                LangGraphSWEBenchAgent(
                    graph_factory=_make_graph_factory(f"a{i}"),
                    llm=llm,
                    model_name=f"langgraph-a{i}",
                )
            )
        return agents
    except ImportError:
        return [MockSolverAgent(agent_id=f"a{i}") for i in range(3)]


def main() -> int:
    agents = _build_agents()
    tasks = _make_tasks(5)

    try:
        from constitutional_swarm.langgraph_runtime.coordinator_adapter import (  # type: ignore[import-not-found]
            run_langgraph,
        )

        result = run_langgraph(agents, tasks)
    except ImportError:
        # Local fallback for early-merge demo: emulate the coordinator inline.
        result = _fallback_run_langgraph(agents, tasks)

    print("=== LangGraph swarm demo ===")
    print(f"total={result['total']}")
    print(f"resolved={result['resolved']}")
    print(f"resolve_rate={result['resolve_rate']:.3f}")
    print(f"crdt_size={result['crdt_size']}")
    print(f"governed_count={result['governed_count']}")
    print(f"mean_intervention={result['mean_intervention']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
