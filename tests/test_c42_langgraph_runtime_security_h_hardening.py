from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.agent import LangGraphSWEBenchAgent
from constitutional_swarm.langgraph_runtime.coordinator_adapter import run_langgraph
from constitutional_swarm.langgraph_runtime.nodes import append_crdt_node
from constitutional_swarm.langgraph_runtime.runtime import (
    ConstitutionalHashError,
    build_swarm_graph,
)
from constitutional_swarm.langgraph_runtime.streaming import stream_to_crdt
from constitutional_swarm.langgraph_runtime.swarm_topology import (
    build_handoff_swarm,
    constitutional_guard_middleware,
)
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch


_PATCH = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
_TASK = {"instance_id": "c42-1", "problem_statement": "repair it"}


class _RecordingCRDT:
    def __init__(self, _agent_id: str | None = None) -> None:
        self.calls: list[dict[str, object]] = []

    @property
    def size(self) -> int:
        return len(self.calls)

    def append(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "cid"


class _DNA:
    def __init__(self, result: object, *, dna_hash: object = CONSTITUTIONAL_HASH) -> None:
        self.hash = dna_hash
        self._result = result

    def validate(self, _patch: str) -> object:
        return self._result


def _run_compiled(
    dna: object,
    *,
    interrupt_before: tuple[str, ...] = (),
    quorum_reached: bool = False,
) -> dict[str, Any]:
    pytest.importorskip("langgraph")
    crdt = _RecordingCRDT()

    def graph_factory(_agent: SWEBenchAgent):
        return build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: (_PATCH, {"intervention_rate": 0.0}),
            dna=dna,
            crdt=crdt,
            interrupt_before=interrupt_before,
        )

    result = run_langgraph(
        [SWEBenchAgent()],
        [{**_TASK, "quorum_reached": quorum_reached}],
        graph_factory=graph_factory,
    )
    result["recording_crdt"] = crdt
    return result


@pytest.mark.parametrize(
    "validation_result",
    [
        SimpleNamespace(valid=True, violations=("R1",), risk_score=0.0),
        SimpleNamespace(valid=True, violations=(), risk_score=0.3),
        SimpleNamespace(valid=True, risk_score=0.0),
        SimpleNamespace(valid=True, violations=()),
        SimpleNamespace(valid=True, violations=(), risk_score=None),
        SimpleNamespace(valid=True, violations=(), risk_score=True),
        SimpleNamespace(valid=True, violations=(), risk_score="0.0"),
        SimpleNamespace(valid=True, violations=(), risk_score=-0.1),
        SimpleNamespace(valid=True, violations=(), risk_score=float("nan")),
        SimpleNamespace(valid=True, violations=(), risk_score=float("inf")),
        SimpleNamespace(valid=True, violations=(), risk_score=float("-inf")),
        SimpleNamespace(valid=False, violations=(), risk_score=0.0),
        SimpleNamespace(valid="yes", violations=(), risk_score=0.0),
        SimpleNamespace(violations=(), risk_score=0.0),
    ],
)
def test_run_langgraph_rejects_invalid_validation_evidence(
    validation_result: object,
) -> None:
    result = _run_compiled(_DNA(validation_result))

    assert result["patch_generated"] == 0
    assert result["patches"][0].patch == ""
    assert result["recording_crdt"].calls == []


def test_run_langgraph_rejects_interrupted_run_before_settle() -> None:
    completed = _run_compiled(
        _DNA(SimpleNamespace(valid=True, violations=(), risk_score=0.0)),
        quorum_reached=False,
    )
    result = _run_compiled(
        _DNA(SimpleNamespace(valid=True, violations=(), risk_score=0.0)),
        interrupt_before=("settle",),
    )

    assert completed["patch_generated"] == 1
    assert completed["patches"][0].metadata["settled"] is False
    assert result["patch_generated"] == 0
    assert result["patches"][0].patch == ""


def test_build_swarm_graph_rejects_unpinned_dna_hash() -> None:
    pytest.importorskip("langgraph")
    dna = _DNA(
        SimpleNamespace(valid=True, violations=(), risk_score=0.0),
        dna_hash="wrong",
    )

    with pytest.raises(ConstitutionalHashError, match="DNA hash mismatch"):
        build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: (_PATCH, {}),
            dna=dna,
        )


def test_build_swarm_graph_rejects_hash_equality_object() -> None:
    pytest.importorskip("langgraph")

    class _EqualHash:
        def __eq__(self, _other: object) -> bool:
            return True

    dna = _DNA(
        SimpleNamespace(valid=True, violations=(), risk_score=0.0),
        dna_hash=_EqualHash(),
    )

    with pytest.raises(ConstitutionalHashError, match="DNA hash mismatch"):
        build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: (_PATCH, {}),
            dna=dna,
        )


def test_run_langgraph_rejects_dna_hash_drift_before_dispatch() -> None:
    pytest.importorskip("langgraph")
    dna = _DNA(SimpleNamespace(valid=True, violations=(), risk_score=0.0))
    generated: list[bool] = []

    def graph_factory(_agent: SWEBenchAgent):
        graph = build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: (generated.append(True) and _PATCH, {}),
            dna=dna,
        )
        dna.hash = "wrong"
        return graph

    result = run_langgraph(
        [SWEBenchAgent()],
        [_TASK],
        graph_factory=graph_factory,
    )

    assert result["patch_generated"] == 0
    assert generated == []


def test_run_langgraph_rejects_spoofed_violations_container() -> None:
    class _Violations(list[str]):
        pass

    result = _run_compiled(
        _DNA(
            SimpleNamespace(
                valid=True,
                violations=_Violations(),
                risk_score=0.0,
            )
        )
    )

    assert result["patch_generated"] == 0
    assert result["recording_crdt"].calls == []


@pytest.mark.parametrize("dna_hash", [None, "wrong"])
def test_build_handoff_swarm_rejects_unpinned_dna_hash(dna_hash: object) -> None:
    class _Agent:
        name = "peer"

    dna = None if dna_hash is None else SimpleNamespace(hash=dna_hash)
    expected = ValueError if dna is None else RuntimeError

    with pytest.raises(expected, match="dna|DNA hash"):
        build_handoff_swarm(
            [_Agent()],
            agent_names=["peer"],
            constitution={"hash": CONSTITUTIONAL_HASH},
            dna=dna,
        )


def test_constitutional_guard_middleware_rejects_unpinned_threshold() -> None:
    with pytest.raises(ValueError, match="package constitutional hash"):
        constitutional_guard_middleware(expected_hash="wrong")


def test_run_langgraph_rejects_incomplete_custom_graph_result() -> None:
    pytest.importorskip("langgraph")
    from langgraph.graph import END, START, StateGraph

    def graph_factory(_agent: SWEBenchAgent):
        graph = StateGraph(dict)
        graph.add_node(
            "generate",
            lambda _state: {
                "patch": _PATCH,
                "constitutional_hash": CONSTITUTIONAL_HASH,
                "governed": True,
                "risk_score": 0.0,
                "violations": [],
            },
        )
        graph.add_edge(START, "generate")
        graph.add_edge("generate", END)
        return graph.compile()

    result = run_langgraph(
        [SWEBenchAgent()],
        [_TASK],
        graph_factory=graph_factory,
    )

    assert result["patch_generated"] == 0
    assert result["patches"][0].patch == ""


def test_append_crdt_node_rejects_missing_validation_evidence() -> None:
    crdt = _RecordingCRDT()

    with pytest.raises(ValueError, match="validation evidence"):
        append_crdt_node(
            {
                "patch": _PATCH,
                "constitutional_hash": CONSTITUTIONAL_HASH,
                "governed": True,
            },
            crdt=crdt,
        )

    assert crdt.calls == []


class _ChunkGraph:
    def __init__(self, chunks: list[dict[str, object]]) -> None:
        self._chunks = chunks

    async def astream(self, _inputs: dict, **_kwargs: object):
        for chunk in self._chunks:
            yield chunk


@pytest.mark.asyncio
async def test_streaming_rejects_inherited_terminal_evidence() -> None:
    crdt = _RecordingCRDT()
    inputs = {
        "task_id": "c42-stream",
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "governance_status": "accepted",
        "governed": True,
        "risk_score": 0.0,
        "violations": [],
        "settled": True,
    }

    async for _chunk in stream_to_crdt(
        _ChunkGraph([{"settle": {"settled": True}}]),
        inputs,
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_rejects_malformed_validation_update() -> None:
    crdt = _RecordingCRDT()
    chunks: list[dict[str, object]] = [
        {"generate": {"patch": _PATCH}},
        {
            "validate": {
                "governed": True,
                "violations": [],
                "risk_score": float("nan"),
            }
        },
        {"settle": {"governance_status": "accepted", "settled": False}},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_rejects_patch_changed_after_validation() -> None:
    crdt = _RecordingCRDT()
    chunks: list[dict[str, object]] = [
        {"generate": {"patch": "patch-a"}},
        {
            "validate": {
                "governed": True,
                "violations": [],
                "risk_score": 0.0,
            }
        },
        {"transform": {"patch": "patch-b"}},
        {"settle": {"governance_status": "accepted", "settled": False}},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_rejects_non_plain_patch_after_validation() -> None:
    class _EqualPatch(str):
        def __eq__(self, _other: object) -> bool:
            return True

        def __ne__(self, _other: object) -> bool:
            return False

    crdt = _RecordingCRDT()
    chunks: list[dict[str, object]] = [
        {"generate": {"patch": "patch-a"}},
        {
            "validate": {
                "governed": True,
                "violations": [],
                "risk_score": 0.0,
            }
        },
        {"transform": {"patch": _EqualPatch("patch-b")}},
        {"settle": {"governance_status": "accepted", "settled": False}},
    ]

    async for _chunk in stream_to_crdt(
        _ChunkGraph(chunks),
        {"task_id": "c42-stream", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


def test_coordinator_uses_canonical_payload_and_exact_bodes_predicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    captured: list[_RecordingCRDT] = []

    class _CapturedCRDT(_RecordingCRDT):
        def __init__(self, agent_id: str) -> None:
            super().__init__(agent_id)
            captured.append(self)

    class _ResultAgent:
        def solve(self, _task: dict[str, object]) -> SWEPatch:
            return SWEPatch(
                task_id="c42-1",
                patch=_PATCH,
                success=True,
                governed=True,
                duration_s=0.0,
                metadata={
                    "z": 1,
                    "violations": ["R1"],
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                    "governance_status": "accepted",
                    "a": 2,
                },
            )

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _CapturedCRDT)
    result = run_langgraph([_ResultAgent()], [_TASK])  # type: ignore[list-item]

    call = captured[0].calls[0]
    payload = call["payload"]
    assert isinstance(payload, str)
    assert payload == json.dumps(
        json.loads(payload),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    assert call["bodes_passed"] is False
    assert result["patch_generated"] == 0


@pytest.mark.parametrize("error", ["timeout", "RuntimeError"])
def test_coordinator_does_not_mark_failed_governed_result_as_bodes(
    monkeypatch: pytest.MonkeyPatch,
    error: str,
) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    captured: list[_RecordingCRDT] = []

    class _CapturedCRDT(_RecordingCRDT):
        def __init__(self, agent_id: str) -> None:
            super().__init__(agent_id)
            captured.append(self)

    class _ResultAgent:
        def solve(self, _task: dict[str, object]) -> SWEPatch:
            return SWEPatch(
                task_id="c42-1",
                patch="",
                success=False,
                governed=True,
                metadata={
                    "error": error,
                    "violations": [],
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                },
            )

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _CapturedCRDT)
    run_langgraph([_ResultAgent()], [_TASK])  # type: ignore[list-item]

    assert captured[0].calls[0]["bodes_passed"] is False


@pytest.mark.parametrize(
    ("metadata", "governed", "expected_patch_count"),
    [
        ({"violations": [], "risk_score": 0.0}, True, 1),
        ({"violations": [], "risk_score": 0.0}, False, 1),
        ({"violations": ["R1"]}, False, 0),
        ({"governed": False, "violations": [], "risk_score": 0.0}, True, 0),
        ({"violations": ["R1"]}, True, 0),
        ({"violations": [], "risk_score": 0.3}, True, 0),
        ({"violations": [], "risk_score": float("nan")}, True, 0),
        ({"violations": [], "risk_score": None}, True, 0),
        ({"violations": [], "risk_score": True}, True, 0),
        ({"violations": [], "risk_score": "0.0"}, True, 0),
    ],
)
def test_coordinator_rejects_unsafe_incomplete_validation_metadata(
    metadata: dict[str, object],
    governed: bool,
    expected_patch_count: int,
) -> None:
    class _ResultAgent:
        def solve(self, _task: dict[str, object]) -> SWEPatch:
            return SWEPatch(
                task_id="c42-1",
                patch=_PATCH,
                success=True,
                governed=governed,
                metadata=metadata,
            )

    result = run_langgraph([_ResultAgent()], [_TASK])  # type: ignore[list-item]

    assert result["patch_generated"] == expected_patch_count
    assert bool(result["patches"][0].patch) is bool(expected_patch_count)


def test_agent_rejects_spoofed_incomplete_result() -> None:
    class _Graph:
        def invoke(self, _initial: dict, *, config: dict) -> dict[str, object]:
            return {
                "patch": _PATCH,
                "constitutional_hash": CONSTITUTIONAL_HASH,
                "governance_status": "accepted",
                "governed": True,
            }

    agent = LangGraphSWEBenchAgent(graph_factory=_Graph)
    result = agent.solve(_TASK)

    assert result.success is False
    assert result.patch == ""
