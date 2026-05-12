"""Tests for LangGraphSWEBenchAgent.

The tests build a tiny in-test ``StateGraph`` with ``MemorySaver`` so they
exercise the real graph dispatcher rather than a hand-rolled mock. No real
LLM is invoked; where a chat model is needed we use
``FakeListChatModel`` from ``langchain_core``.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from constitutional_swarm.langgraph_runtime.agent import LangGraphSWEBenchAgent
from constitutional_swarm.swe_bench.agent import SWEPatch
from constitutional_swarm.swe_bench.governed_agent import GovernedAgent
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

_FAKE_DIFF = (
    "--- a/src/foo.py\n"
    "+++ b/src/foo.py\n"
    "@@ -1 +1 @@\n"
    "-hello\n"
    "+goodbye\n"
)

_TASK: dict[str, Any] = {
    "instance_id": "django__django-11099",
    "repo": "django/django",
    "base_commit": "abc123",
    "problem_statement": "UsernameValidator allows trailing newline in usernames",
    "FAIL_TO_PASS": [
        "tests/auth_tests/test_validators.py::UsernameValidatorTestCase::test_unicode"
    ],
    "hints_text": "",
}


def _make_fixed_graph(
    patch: str,
    *,
    intervention_rate: float = 0.25,
    violations: list[str] | None = None,
    constitutional_hash: str = "608508a9bd224290",
    settled: bool = True,
    raise_in_node: Exception | None = None,
):
    """Build a compiled StateGraph that yields a fixed patch + stats."""

    def generate_node(state: dict[str, Any]) -> dict[str, Any]:
        if raise_in_node is not None:
            raise raise_in_node
        return {
            "patch": patch,
            "intervention_rate": intervention_rate,
            "violations": list(violations or []),
            "constitutional_hash": constitutional_hash,
            "settled": settled,
        }

    builder = StateGraph(dict)
    builder.add_node("generate", generate_node)
    builder.add_edge(START, "generate")
    builder.add_edge("generate", END)
    return builder.compile(checkpointer=MemorySaver())


def test_solve_returns_swepatch_with_graph_stats() -> None:
    """solve() returns SWEPatch with patch + intervention_rate from graph."""
    graph = _make_fixed_graph(_FAKE_DIFF, intervention_rate=0.37)

    agent = LangGraphSWEBenchAgent(
        graph_factory=lambda: graph,
        llm=FakeListChatModel(responses=["unused"]),
    )
    result = agent.solve(_TASK)

    assert isinstance(result, SWEPatch)
    assert result.task_id == "django__django-11099"
    assert result.patch == _FAKE_DIFF
    assert result.success is True
    assert result.governed is False  # No wrapper passed.
    assert result.intervention_rate == pytest.approx(0.37)
    assert result.metadata["model"] == "langgraph-swarm-agent"
    assert result.metadata["constitutional_hash"] == "608508a9bd224290"
    assert result.metadata["violations"] == []
    assert result.metadata["settled"] is True


def test_solve_propagates_graph_invoke_error_as_failed_swepatch() -> None:
    """Exception inside the graph becomes a failed SWEPatch with error metadata."""
    graph = _make_fixed_graph(
        "",
        raise_in_node=RuntimeError("graph blew up"),
    )

    agent = LangGraphSWEBenchAgent(graph_factory=lambda: graph)
    result = agent.solve(_TASK)

    assert result.success is False
    assert result.patch == ""
    # Base class records exception type in metadata; the original RuntimeError
    # may be wrapped by LangGraph but the error key must be populated.
    assert "error" in result.metadata
    assert result.metadata["error"] != "timeout"


def test_governed_wrapper_rejects_violating_patch() -> None:
    """Wrapping a LangGraphSWEBenchAgent in GovernedAgent rejects unsafe patches."""
    unsafe_patch = (
        "--- a/danger.py\n"
        "+++ b/danger.py\n"
        "@@ -1 +1 @@\n"
        "-pass\n"
        "+os.system('rm -rf /etc')\n"
    )
    graph = _make_fixed_graph(unsafe_patch, intervention_rate=0.1)

    base = LangGraphSWEBenchAgent(graph_factory=lambda: graph)
    governed = GovernedAgent(base)

    result = governed.solve(_TASK)

    assert result.success is False
    assert result.patch == ""
    assert result.governed is True
    assert result.metadata["governance_action"] == "rejected"
    assert result.metadata["governance_violation_count"] >= 1
    assert result.intervention_rate == 1.0


def test_governed_wrapper_accepts_clean_patch() -> None:
    """GovernedAgent passes through clean patches with governed=True."""
    graph = _make_fixed_graph(_FAKE_DIFF, intervention_rate=0.0)

    base = LangGraphSWEBenchAgent(graph_factory=lambda: graph)
    governed = GovernedAgent(base)

    result = governed.solve(_TASK)

    assert result.success is True
    assert result.patch == _FAKE_DIFF
    assert result.governed is True
    assert result.metadata["governance_action"] == "accepted"
    assert result.metadata["governance_violation_count"] == 0


def test_empty_patch_yields_failed_swepatch_without_governance() -> None:
    """Empty graph output produces an un-successful SWEPatch (base class rule)."""
    graph = _make_fixed_graph("", intervention_rate=0.0)

    agent = LangGraphSWEBenchAgent(graph_factory=lambda: graph)
    result = agent.solve(_TASK)

    assert result.success is False
    assert result.patch == ""
    assert result.intervention_rate == 0.0


def test_graph_factory_invoked_per_solve_call() -> None:
    """graph_factory is invoked once per solve() so callers can parametrise per-task."""
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        return _make_fixed_graph(_FAKE_DIFF)

    agent = LangGraphSWEBenchAgent(graph_factory=factory)
    agent.solve(_TASK)
    agent.solve({**_TASK, "instance_id": "foo__bar-2"})

    assert calls["n"] == 2
