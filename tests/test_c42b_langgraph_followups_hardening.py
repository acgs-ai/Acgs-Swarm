"""C42b regression tests: invalid-input handling in the LangGraph runtime.

All tests use in-process fake graphs (``invoke`` / ``astream``), so they run
without the optional ``langgraph`` dependency.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.agent import LangGraphSWEBenchAgent
from constitutional_swarm.langgraph_runtime.coordinator_adapter import run_langgraph
from constitutional_swarm.langgraph_runtime.streaming import stream_to_crdt
from constitutional_swarm.swe_bench.agent import SWEPatch

_PATCH = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n"
_TASK = {"instance_id": "c42b-task", "problem_statement": "fix"}


class _InvokeGraph:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state

    def invoke(self, _initial: object, **_kwargs: object) -> dict[str, Any]:
        return dict(self.state)


class _ChunkGraph:
    def __init__(self, chunks: list[dict[str, Any]]) -> None:
        self.chunks = chunks

    async def astream(self, _inputs: object, **_kwargs: object):
        for chunk in self.chunks:
            yield chunk


class _RecordingCRDT:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class _ResultAgent:
    def __init__(self, result: SWEPatch) -> None:
        self.result = result

    def solve(self, _task: object) -> SWEPatch:
        return self.result


def _accepted_state(**overrides: object) -> dict[str, Any]:
    state: dict[str, Any] = {
        "patch": _PATCH,
        "intervention_rate": 0.0,
        "governed": True,
        "risk_score": 0.0,
        "violations": [],
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "settled": False,
        "governance_status": "accepted",
    }
    state.update(overrides)
    return state


# ---------------------------------------------------------------------------
# L2 — coordinator maps RecursionError from result serialization to a
#      structured per-result rejection instead of aborting the batch.
# ---------------------------------------------------------------------------


def test_run_langgraph_rejects_result_too_deep_to_serialize() -> None:
    nested: list[Any] = []
    for _ in range(sys.getrecursionlimit() + 200):
        nested = [nested]
    deep = SWEPatch(
        task_id="c42b-deep",
        patch=_PATCH,
        success=True,
        governed=True,
        metadata={"deep": nested},
    )

    outcome = run_langgraph([_ResultAgent(deep)], [{"instance_id": "c42b-deep"}])

    (rejected,) = outcome["patches"]
    assert rejected.patch == ""
    assert rejected.success is False
    assert rejected.governed is False
    assert rejected.metadata["governance_status"] == "rejected"
    # Interpreters whose C recursion limit is low reject at metadata
    # validation; others reject at result serialization. Both fail closed.
    assert rejected.metadata["error"] in {"invalid_result", "invalid_metadata"}
    if rejected.metadata["error"] == "invalid_result":
        assert rejected.metadata["result_serialization_error"] == {"type": "RecursionError"}
    assert outcome["crdt_size"] == 1
    assert outcome["patch_generated"] == 0


# ---------------------------------------------------------------------------
# L3 — only the settle node's own update can declare acceptance.
# ---------------------------------------------------------------------------


_VALIDATE = {"validate": {"governed": True, "risk_score": 0.0, "violations": []}}


@pytest.mark.asyncio
async def test_streaming_rejects_acceptance_declared_by_intermediate_node() -> None:
    crdt = _RecordingCRDT()
    chunks: list[dict[str, Any]] = [
        {"generate": {"patch": _PATCH}},
        {
            "validate": {
                "governed": True,
                "risk_score": 0.0,
                "violations": [],
                "governance_status": "accepted",
            }
        },
        {"settle": {"settled": True}},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42b-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("settle_update", [None, "accepted", {"governance_status": None}])
async def test_streaming_rejects_malformed_settle_update(settle_update: object) -> None:
    crdt = _RecordingCRDT()
    chunks: list[dict[str, Any]] = [
        {"generate": {"patch": _PATCH, "governance_status": "accepted"}},
        _VALIDATE,
        {"settle": settle_update},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42b-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_appends_when_settle_node_declares_acceptance() -> None:
    crdt = _RecordingCRDT()
    chunks: list[dict[str, Any]] = [
        {"generate": {"patch": _PATCH}},
        _VALIDATE,
        {"settle": {"governance_status": "accepted", "settled": True}},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42b-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert len(crdt.calls) == 1
    assert crdt.calls[0]["bodes_passed"] is True
    assert crdt.calls[0]["constitutional_hash"] == CONSTITUTIONAL_HASH


# ---------------------------------------------------------------------------
# L4 — an accepted graph state must carry an exact built-in ``str`` patch.
# ---------------------------------------------------------------------------


class _SpoofStr(str):
    def strip(self, chars: str | None = None) -> str:
        return "spoof"


@pytest.mark.parametrize(
    "bad_patch",
    [_SpoofStr(_PATCH), _PATCH.encode(), None, [_PATCH]],
    ids=["str-subclass", "bytes", "none", "list"],
)
def test_agent_rejects_non_plain_str_patch_from_accepted_state(bad_patch: object) -> None:
    graph = _InvokeGraph(_accepted_state(patch=bad_patch))
    agent = LangGraphSWEBenchAgent(
        graph_factory=lambda: graph,
        constitutional_hash=CONSTITUTIONAL_HASH,
    )

    result = agent.solve(_TASK)

    assert type(result.patch) is str
    assert result.patch == ""
    assert result.success is False
    assert result.metadata["error"] == "invalid_patch"
    assert result.metadata["governance_status"] == "rejected"


def test_agent_releases_plain_str_patch_from_accepted_state() -> None:
    graph = _InvokeGraph(_accepted_state())
    agent = LangGraphSWEBenchAgent(
        graph_factory=lambda: graph,
        constitutional_hash=CONSTITUTIONAL_HASH,
    )

    result = agent.solve(_TASK)

    assert type(result.patch) is str
    assert result.patch == _PATCH
    assert result.success is True
    assert "error" not in result.metadata


# ---------------------------------------------------------------------------
# I3 — incomplete runs are labelled governance_incomplete, never
#      governance_accepted or an interpolated graph-supplied string.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"violations": ["R-1"]},
        {"constitutional_hash": "wrong"},
        {"risk_score": 0.9},
        {"governance_status": "approved"},
        {"governance_status": None},
        {"governance_status": 1},
    ],
    ids=[
        "accepted-with-violation",
        "accepted-bad-hash",
        "accepted-high-risk",
        "unknown-status",
        "missing-status",
        "non-str-status",
    ],
)
def test_agent_labels_incomplete_run_as_governance_incomplete(
    overrides: dict[str, object],
) -> None:
    graph = _InvokeGraph(_accepted_state(**overrides))
    agent = LangGraphSWEBenchAgent(graph_factory=lambda: graph)

    result = agent.solve(_TASK)

    assert result.patch == ""
    assert result.success is False
    assert result.metadata["error"] == "governance_incomplete"


@pytest.mark.parametrize("status", ["rejected", "halted"])
def test_agent_keeps_terminal_rejection_label(status: str) -> None:
    graph = _InvokeGraph(_accepted_state(governance_status=status, patch=""))
    agent = LangGraphSWEBenchAgent(graph_factory=lambda: graph)

    result = agent.solve(_TASK)

    assert result.patch == ""
    assert result.metadata["error"] == f"governance_{status}"
