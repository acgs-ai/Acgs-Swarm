"""Tests for the LangGraph coordinator adapter (``run_langgraph``).

The adapter mirrors :meth:`SwarmCoordinator.run_in_memory` as a free function,
optionally routing each agent's ``solve`` through a compiled LangGraph. These
tests focus on the public API surface (return shape, routing, validation) and
intentionally do not require LangGraph itself unless test #6 runs.
"""

from __future__ import annotations

import pytest
from constitutional_swarm.langgraph_runtime.coordinator_adapter import (
    run_langgraph,
)
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_tasks(n: int = 5) -> list[dict]:
    return [
        {
            "instance_id": f"repo-{i}",
            "problem_statement": f"Bug {i}",
            "patch": "--- a/f.py\n+++ b/f.py",
            "FAIL_TO_PASS": [],
        }
        for i in range(n)
    ]


class _SuccessAgent(SWEBenchAgent):
    """Agent that always returns a non-empty fixed patch."""

    def _generate_patch(self, task: dict) -> tuple[str, dict]:
        return "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n", {
            "intervention_rate": 0.0,
        }


class _DomainAgent(SWEBenchAgent):
    """Agent that only succeeds on tasks whose instance_id starts with ``prefix``."""

    def __init__(self, prefix: str) -> None:
        super().__init__()
        self.prefix = prefix
        self.seen: list[str] = []

    def _generate_patch(self, task: dict) -> tuple[str, dict]:
        tid = task.get("instance_id", "")
        self.seen.append(tid)
        if tid.startswith(self.prefix):
            return "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n", {
                "intervention_rate": 0.0,
            }
        return "", {"intervention_rate": 0.0}


# ---------------------------------------------------------------------------
# Test 1 — Aggregate shape matches SwarmCoordinator.run_in_memory
# ---------------------------------------------------------------------------


def test_run_langgraph_returns_expected_shape() -> None:
    """The return dict mirrors SwarmCoordinator.run_in_memory exactly."""
    result = run_langgraph([_SuccessAgent()], _make_tasks(3))
    assert set(result.keys()) == {
        "patches",
        "total",
        "resolved",
        "resolve_rate",
        "crdt_size",
        "governed_count",
        "mean_intervention",
    }
    assert result["total"] == 3
    assert result["resolved"] == 3
    assert result["resolve_rate"] == pytest.approx(1.0)
    assert result["crdt_size"] == 3
    # Stub _SuccessAgent has wrapper=None, so governed=False on every patch.
    assert result["governed_count"] == 0
    assert result["mean_intervention"] == pytest.approx(0.0)
    assert all(isinstance(p, SWEPatch) for p in result["patches"])
    assert [p.task_id for p in result["patches"]] == ["repo-0", "repo-1", "repo-2"]


def test_run_langgraph_default_stub_agent_resolves_nothing() -> None:
    """Bare SWEBenchAgent stub returns empty patches → resolve_rate=0."""
    result = run_langgraph([SWEBenchAgent()], _make_tasks(4))
    assert result["total"] == 4
    assert result["resolved"] == 0
    assert result["resolve_rate"] == pytest.approx(0.0)
    assert result["crdt_size"] == 4


def test_run_langgraph_empty_tasks_yields_zero_resolve_rate() -> None:
    result = run_langgraph([_SuccessAgent()], [])
    assert result["total"] == 0
    assert result["crdt_size"] == 0
    assert result["resolve_rate"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Test 2 — Routing weights steer tasks to the highest-weighted agent
# ---------------------------------------------------------------------------


def test_routing_weights_steer_tasks_to_competent_agent() -> None:
    """Trust-weighted routing should send domain-A tasks to the A-specialist."""
    a = _DomainAgent("django")
    b = _DomainAgent("numpy")
    tasks = [
        {"instance_id": "django-1", "problem_statement": "x", "patch": "", "FAIL_TO_PASS": []},
        {"instance_id": "numpy-1", "problem_statement": "x", "patch": "", "FAIL_TO_PASS": []},
        {"instance_id": "django-2", "problem_statement": "x", "patch": "", "FAIL_TO_PASS": []},
    ]
    weights = [
        [1.0, 0.0, 1.0],  # agent a wins for tasks 0 and 2
        [0.0, 1.0, 0.0],  # agent b wins for task 1
    ]
    result = run_langgraph([a, b], tasks, routing_weights=weights)
    assert result["resolve_rate"] == pytest.approx(1.0)
    assert a.seen == ["django-1", "django-2"]
    assert b.seen == ["numpy-1"]


def test_routing_weights_ties_break_to_lower_index() -> None:
    """When weights tie, the lower-index agent wins (mirrors SwarmCoordinator)."""
    a = _DomainAgent("a")
    b = _DomainAgent("b")
    tasks = [
        {"instance_id": "x-0", "problem_statement": "x", "patch": "", "FAIL_TO_PASS": []},
    ]
    weights = [[0.5], [0.5]]
    run_langgraph([a, b], tasks, routing_weights=weights)
    assert a.seen == ["x-0"]
    assert b.seen == []


# ---------------------------------------------------------------------------
# Test 3 — max_tasks caps the subset
# ---------------------------------------------------------------------------


def test_max_tasks_caps_subset() -> None:
    result = run_langgraph([_SuccessAgent()], _make_tasks(10), max_tasks=3)
    assert result["total"] == 3
    assert result["crdt_size"] == 3
    assert [p.task_id for p in result["patches"]] == ["repo-0", "repo-1", "repo-2"]


def test_max_tasks_none_uses_all_tasks() -> None:
    result = run_langgraph([_SuccessAgent()], _make_tasks(5), max_tasks=None)
    assert result["total"] == 5


# ---------------------------------------------------------------------------
# Test 4 — Empty agents list raises ValueError
# ---------------------------------------------------------------------------


def test_empty_agents_raises_value_error() -> None:
    with pytest.raises(ValueError, match="at least one agent"):
        run_langgraph([], _make_tasks(3))


# ---------------------------------------------------------------------------
# Test 5 — Mismatched routing_weights shape raises ValueError
# ---------------------------------------------------------------------------


def test_routing_weights_wrong_row_count_raises() -> None:
    """Wrong number of rows (must equal n_agents) → ValueError."""
    with pytest.raises(ValueError, match="routing_weights must be"):
        run_langgraph(
            [SWEBenchAgent(), SWEBenchAgent()],
            _make_tasks(2),
            routing_weights=[[1.0, 0.0]],  # only 1 row, need 2
        )


def test_routing_weights_wrong_col_count_raises() -> None:
    """Wrong number of cols (must equal len(subset)) → ValueError."""
    with pytest.raises(ValueError, match="routing_weights must be"):
        run_langgraph(
            [SWEBenchAgent(), SWEBenchAgent()],
            _make_tasks(3),
            routing_weights=[[1.0, 0.0], [0.0, 1.0]],  # 2x2, need 2x3
        )


def test_routing_weights_validation_respects_max_tasks() -> None:
    """Validation shape uses the truncated subset length, not raw tasks."""
    # 5 raw tasks, capped to 2 → weights must be 1x2, not 1x5.
    result = run_langgraph(
        [_SuccessAgent()],
        _make_tasks(5),
        max_tasks=2,
        routing_weights=[[1.0, 1.0]],
    )
    assert result["total"] == 2


# ---------------------------------------------------------------------------
# Test 6 — Real LangGraph factory (optional; skipped if langgraph absent)
# ---------------------------------------------------------------------------


def test_run_langgraph_with_real_graph_factory() -> None:
    """Smoke test: a trivial compiled graph drives one task through the adapter.

    Requires both the ``langgraph`` runtime *and* the Unit 9
    ``LangGraphSWEBenchAgent`` shim. Skips cleanly when either is missing so
    this slice can land before Unit 9 finalizes.
    """
    pytest.importorskip("langgraph", reason="langgraph not installed")
    try:
        from constitutional_swarm.langgraph_runtime.agent import (  # noqa: F401
            LangGraphSWEBenchAgent,
        )
    except ImportError:
        pytest.skip("LangGraphSWEBenchAgent (Unit 9) not yet merged")

    from langgraph.graph import END, START, StateGraph

    def _graph_factory(_agent: SWEBenchAgent):
        builder = StateGraph(dict)

        def _node(_state: dict) -> dict:
            return {
                "patch": "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n",
                "intervention_rate": 0.0,
            }

        builder.add_node("solve", _node)
        builder.add_edge(START, "solve")
        builder.add_edge("solve", END)
        return builder.compile()

    result = run_langgraph(
        [_SuccessAgent()],
        _make_tasks(1),
        graph_factory=_graph_factory,
    )
    assert result["total"] == 1
    assert isinstance(result["patches"][0], SWEPatch)
