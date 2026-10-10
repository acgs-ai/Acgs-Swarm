"""C51a regression tests: invalid-input handling for runtime residual LOWs.

* ``stream_to_crdt`` must not append a patch that a same-step sibling node
  rewrites after the settle node's update was streamed.
* ``ExternalAgentAdapter`` must resolve the operator command on the fixed
  subprocess path and fail closed on relative, empty, or unparseable commands.

LangGraph-backed tests call ``pytest.importorskip`` inside the test so the
remaining tests still run without the optional dependency.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from constitutional_swarm import governed_handoff
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.governed_handoff import ExternalAgentAdapter, TaskSpec
from constitutional_swarm.langgraph_runtime.streaming import stream_to_crdt

_PATCH = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n"
_OTHER_PATCH = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+z\n"
_INPUTS = {"task_id": "c51a", "constitutional_hash": CONSTITUTIONAL_HASH}


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


async def _drain(stream: Any) -> list[Any]:
    return [chunk async for chunk in stream]


def _validated_chunks() -> list[dict[str, Any]]:
    return [
        {"produce": {"patch": _PATCH}},
        {"validate": {"governed": True, "risk_score": 0.0, "violations": []}},
        {"settle": {"governance_status": "accepted", "settled": True}},
    ]


# ---------------------------------------------------------------------------
# Item 2 — the CRDT append reflects the state the graph ends with.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streaming_rejects_patch_rewritten_after_settle_chunk() -> None:
    chunks = [*_validated_chunks(), {"sibling": {"patch": _OTHER_PATCH}}]
    crdt = _RecordingCRDT()
    gossip = AsyncMock()

    yielded = await _drain(
        stream_to_crdt(_ChunkGraph(chunks), dict(_INPUTS), crdt, gossip_node=gossip)
    )

    assert yielded == chunks
    assert crdt.calls == []
    gossip.gossip_round.assert_not_awaited()


@pytest.mark.asyncio
async def test_streaming_rejects_settle_verdict_withdrawn_later() -> None:
    chunks = [
        *_validated_chunks(),
        {"settle": {"governance_status": "rejected", "settled": True}},
    ]
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(_ChunkGraph(chunks), dict(_INPUTS), crdt))

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_appends_once_with_final_state() -> None:
    chunks = [*_validated_chunks(), {"sibling": {"other": "note"}}]
    crdt = _RecordingCRDT()
    gossip = AsyncMock()

    await _drain(
        stream_to_crdt(_ChunkGraph(chunks), dict(_INPUTS), crdt, gossip_node=gossip, gossip_peers=4)
    )

    assert len(crdt.calls) == 1
    payload = json.loads(crdt.calls[0]["payload"])
    assert payload["patch"] == _PATCH
    assert crdt.calls[0]["bodes_passed"] is True
    gossip.gossip_round.assert_awaited_once_with(n_peers=4)


def _build_parallel_graph(*, sibling_rewrites_patch: bool) -> Any:
    pytest.importorskip("langgraph")
    from langgraph.graph import END, START, StateGraph
    from typing_extensions import TypedDict

    class _State(TypedDict, total=False):
        task_id: str
        constitutional_hash: str
        patch: str
        governed: bool
        risk_score: float
        violations: list[str]
        governance_status: str
        settled: bool
        other: str

    def produce(_state: _State) -> dict:
        return {"patch": _PATCH}

    def validate(_state: _State) -> dict:
        return {"governed": True, "risk_score": 0.0, "violations": []}

    def settle(_state: _State) -> dict:
        return {"governance_status": "accepted", "settled": True}

    async def sibling(_state: _State) -> dict:
        # Finish after ``settle`` so its update is streamed second.
        await asyncio.sleep(0.05)
        if sibling_rewrites_patch:
            return {"patch": _OTHER_PATCH}
        return {"other": "note"}

    builder = StateGraph(_State)
    builder.add_node("produce", produce)
    builder.add_node("validate", validate)
    builder.add_node("settle", settle)
    builder.add_node("sibling", sibling)
    builder.add_edge(START, "produce")
    builder.add_edge("produce", "validate")
    builder.add_edge("validate", "settle")
    builder.add_edge("validate", "sibling")
    builder.add_edge("settle", END)
    builder.add_edge("sibling", END)
    return builder.compile()


@pytest.mark.asyncio
async def test_langgraph_same_step_sibling_patch_rewrite_is_not_appended() -> None:
    graph = _build_parallel_graph(sibling_rewrites_patch=True)
    crdt = _RecordingCRDT()

    chunks = await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    assert [next(iter(chunk)) for chunk in chunks][-2:] == ["settle", "sibling"]
    assert (await graph.ainvoke(dict(_INPUTS)))["patch"] == _OTHER_PATCH
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_langgraph_same_step_sibling_append_matches_final_patch() -> None:
    graph = _build_parallel_graph(sibling_rewrites_patch=False)
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    final = await graph.ainvoke(dict(_INPUTS))
    assert len(crdt.calls) == 1
    assert json.loads(crdt.calls[0]["payload"])["patch"] == final["patch"] == _PATCH


# ---------------------------------------------------------------------------
# Rework round 1 — bind evidence and the settle verdict to the patch each
# node read; close the graph stream with the outer generator.
# ---------------------------------------------------------------------------


def _lg_builder() -> tuple[Any, Any, Any]:
    pytest.importorskip("langgraph")
    from langgraph.graph import END, START, StateGraph
    from typing_extensions import TypedDict

    class _State(TypedDict, total=False):
        task_id: str
        constitutional_hash: str
        patch: str
        governed: bool
        risk_score: float
        violations: list[str]
        governance_status: str
        settled: bool
        other: str

    return StateGraph(_State), START, END


def _validate(_state: dict) -> dict:
    return {"governed": True, "risk_score": 0.0, "violations": []}


def _settle(_state: dict) -> dict:
    return {"governance_status": "accepted", "settled": True}


@pytest.mark.asyncio
async def test_langgraph_patch_revised_after_settle_is_not_appended() -> None:
    builder, start, end = _lg_builder()
    builder.add_node("produce", lambda _s: {"patch": _PATCH})
    builder.add_node("validate", _validate)
    builder.add_node("settle", _settle)
    builder.add_node("revise", lambda _s: {"patch": _OTHER_PATCH})
    builder.add_node("revalidate", _validate)
    for left, right in [
        (start, "produce"),
        ("produce", "validate"),
        ("validate", "settle"),
        ("settle", "revise"),
        ("revise", "revalidate"),
        ("revalidate", end),
    ]:
        builder.add_edge(left, right)
    graph = builder.compile()
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    final = await graph.ainvoke(dict(_INPUTS))
    assert final["patch"] == _OTHER_PATCH
    assert final["governance_status"] == "accepted"
    assert crdt.calls == []


def _build_validate_sibling_graph(*, slow_node: str, sibling_rewrites_patch: bool) -> Any:
    builder, start, end = _lg_builder()

    async def validate(state: dict) -> dict:
        if slow_node == "validate":
            await asyncio.sleep(0.05)
        return _validate(state)

    async def sibling(_state: dict) -> dict:
        if slow_node == "sibling":
            await asyncio.sleep(0.05)
        return {"patch": _OTHER_PATCH} if sibling_rewrites_patch else {"other": "note"}

    builder.add_node("produce", lambda _s: {"patch": _PATCH})
    builder.add_node("validate", validate)
    builder.add_node("sibling", sibling)
    builder.add_node("settle", _settle)
    for left, right in [
        (start, "produce"),
        ("produce", "validate"),
        ("produce", "sibling"),
        ("validate", "settle"),
        ("sibling", "settle"),
        ("settle", end),
    ]:
        builder.add_edge(left, right)
    return builder.compile()


@pytest.mark.asyncio
@pytest.mark.parametrize("slow_node", ["validate", "sibling"])
async def test_langgraph_evidence_does_not_attach_to_sibling_patch(slow_node: str) -> None:
    graph = _build_validate_sibling_graph(slow_node=slow_node, sibling_rewrites_patch=True)
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    assert (await graph.ainvoke(dict(_INPUTS)))["patch"] == _OTHER_PATCH
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_langgraph_validate_with_benign_sibling_appends_once() -> None:
    graph = _build_validate_sibling_graph(slow_node="sibling", sibling_rewrites_patch=False)
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    assert len(crdt.calls) == 1
    assert json.loads(crdt.calls[0]["payload"])["patch"] == _PATCH


@pytest.mark.asyncio
async def test_streaming_rejects_revalidated_patch_settle_never_saw() -> None:
    chunks = [
        *_validated_chunks(),
        {"revise": {"patch": _OTHER_PATCH}},
        {"revalidate": {"governed": True, "risk_score": 0.0, "violations": []}},
    ]
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(_ChunkGraph(chunks), dict(_INPUTS), crdt))

    assert crdt.calls == []


class _ClosingGraph:
    def __init__(self, chunks: list[dict[str, Any]], *, fail_after: int | None = None) -> None:
        self.chunks = chunks
        self.fail_after = fail_after
        self.closed = False

    async def astream(self, _inputs: object, **_kwargs: object):
        try:
            for index, chunk in enumerate(self.chunks):
                if index == self.fail_after:
                    raise RuntimeError("graph failed mid-stream")
                yield chunk
        finally:
            self.closed = True


@pytest.mark.asyncio
async def test_streaming_aclose_closes_graph_stream_without_append() -> None:
    graph = _ClosingGraph(_validated_chunks())
    crdt = _RecordingCRDT()
    stream = stream_to_crdt(graph, dict(_INPUTS), crdt)

    await stream.__anext__()
    await stream.aclose()

    assert graph.closed is True
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_break_early_does_not_append() -> None:
    graph = _ClosingGraph(_validated_chunks())
    crdt = _RecordingCRDT()
    stream = stream_to_crdt(graph, dict(_INPUTS), crdt)

    async for chunk in stream:
        if "settle" in chunk:
            break
    assert crdt.calls == []
    await stream.aclose()
    assert graph.closed is True
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_exception_mid_stream_does_not_append() -> None:
    graph = _ClosingGraph([*_validated_chunks(), {"after": {"other": "x"}}], fail_after=3)
    crdt = _RecordingCRDT()

    with pytest.raises(RuntimeError, match="mid-stream"):
        await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    assert graph.closed is True
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_streaming_full_drain_appends_exactly_once() -> None:
    graph = _ClosingGraph(_validated_chunks())
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))

    assert graph.closed is True
    assert len(crdt.calls) == 1


# ---------------------------------------------------------------------------
# Rework round 2 — writes whose read patch is unknown fail closed; non-dict
# (pydantic) task inputs still bind.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_langgraph_cached_post_settle_patch_writer_is_not_appended() -> None:
    builder, start, end = _lg_builder()
    from langgraph.cache.memory import InMemoryCache
    from langgraph.types import CachePolicy

    builder.add_node("produce", lambda _s: {"patch": _PATCH})
    builder.add_node("validate", _validate)
    builder.add_node("settle", _settle)
    builder.add_node("tamper", lambda _s: {"patch": _OTHER_PATCH}, cache_policy=CachePolicy())
    for left, right in [
        (start, "produce"),
        ("produce", "validate"),
        ("validate", "settle"),
        ("settle", "tamper"),
        ("tamper", end),
    ]:
        builder.add_edge(left, right)
    graph = builder.compile(cache=InMemoryCache())

    for run in range(2):
        crdt = _RecordingCRDT()
        chunks = await _drain(stream_to_crdt(graph, dict(_INPUTS), crdt))
        cached = any(isinstance(c.get("__metadata__"), dict) for c in chunks)
        assert cached is (run == 1)
        assert crdt.calls == []


class _TupleGraph:
    def __init__(self, events: list[tuple[str, dict[str, Any]]]) -> None:
        self.events = events

    async def astream(self, _inputs: object, **_kwargs: object):
        for event in self.events:
            yield event


def _task_events(
    task_id: str, name: str, read_patch: str, result: dict[str, Any]
) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("tasks", {"id": task_id, "name": name, "input": {"patch": read_patch}}),
        ("updates", {name: result}),
        ("tasks", {"id": task_id, "name": name, "error": None, "result": result}),
    ]


def _settled_task_events() -> list[tuple[str, dict[str, Any]]]:
    return [
        *_task_events("1", "produce", "", {"patch": _PATCH}),
        *_task_events(
            "2", "validate", _PATCH, {"governed": True, "risk_score": 0.0, "violations": []}
        ),
        *_task_events("3", "settle", _PATCH, {"governance_status": "accepted", "settled": True}),
    ]


@pytest.mark.asyncio
async def test_task_stream_settled_run_appends_once() -> None:
    crdt = _RecordingCRDT()

    chunks = await _drain(stream_to_crdt(_TupleGraph(_settled_task_events()), dict(_INPUTS), crdt))

    assert [next(iter(c)) for c in chunks] == ["produce", "validate", "settle"]
    assert len(crdt.calls) == 1


@pytest.mark.asyncio
async def test_task_stream_started_task_without_result_is_not_appended() -> None:
    events = [
        *_settled_task_events(),
        ("tasks", {"id": "4", "name": "tamper", "input": {"patch": _PATCH}}),
    ]
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(_TupleGraph(events), dict(_INPUTS), crdt))

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_task_stream_cached_update_is_not_appended() -> None:
    events = [
        *_settled_task_events(),
        ("updates", {"tamper": {"other": "x"}, "__metadata__": {"cached": True}}),
    ]
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(_TupleGraph(events), dict(_INPUTS), crdt))

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_langgraph_pydantic_state_settled_run_appends_once() -> None:
    pytest.importorskip("langgraph")
    pydantic = pytest.importorskip("pydantic")
    from langgraph.graph import END, START, StateGraph

    class _State(pydantic.BaseModel):
        task_id: str = ""
        constitutional_hash: str = ""
        patch: str = ""
        governed: bool = False
        risk_score: float = 0.0
        violations: list[str] = []
        governance_status: str = ""
        settled: bool = False

    builder = StateGraph(_State)
    builder.add_node("produce", lambda _s: {"patch": _PATCH})
    builder.add_node("validate", _validate)
    builder.add_node("settle", _settle)
    for left, right in [
        (START, "produce"),
        ("produce", "validate"),
        ("validate", "settle"),
        ("settle", END),
    ]:
        builder.add_edge(left, right)
    crdt = _RecordingCRDT()

    await _drain(stream_to_crdt(builder.compile(), dict(_INPUTS), crdt))

    assert len(crdt.calls) == 1
    assert json.loads(crdt.calls[0]["payload"])["patch"] == _PATCH


# ---------------------------------------------------------------------------
# Item 3 — external adapter command resolution and fixed PATH order.
# ---------------------------------------------------------------------------


def test_fixed_subprocess_path_searches_system_directories_first() -> None:
    assert governed_handoff.FIXED_SUBPROCESS_PATH.split(":") == [
        "/usr/bin",
        "/bin",
        "/usr/local/bin",
    ]


def _forbid_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("child launched for invalid command"),
    )


@pytest.mark.parametrize(
    "command",
    ["./agent", "bin/agent --flag", "../agent", "   ", 'codex "unterminated'],
)
def test_external_adapter_rejects_relative_empty_or_unparseable_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    _forbid_child(monkeypatch)

    with pytest.raises(RuntimeError, match="fail closed"):
        ExternalAgentAdapter(name="codex", command=command).propose_actions(
            TaskSpec("c51a", tmp_path / "task.md", "", {})
        )


def test_external_adapter_rejects_command_missing_from_fixed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, str]] = []

    def fake_which(name: str, *, path: str) -> str | None:
        seen.append((name, path))
        return None

    monkeypatch.setattr(governed_handoff.shutil, "which", fake_which)
    _forbid_child(monkeypatch)

    with pytest.raises(RuntimeError, match="fail closed"):
        ExternalAgentAdapter(name="codex", command="codex exec").propose_actions(
            TaskSpec("c51a", tmp_path / "task.md", "", {})
        )
    assert seen == [("codex", governed_handoff.FIXED_SUBPROCESS_PATH)]


def test_external_adapter_runs_command_resolved_on_fixed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_which(name: str, *, path: str) -> str | None:
        assert path == governed_handoff.FIXED_SUBPROCESS_PATH
        return "/trusted/bin/codex" if name == "codex" else None

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured.update({"argv": argv, **kwargs})
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.shutil, "which", fake_which)
    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)
    monkeypatch.setenv("PATH", "/untrusted/bin")
    task = TaskSpec("c51a", tmp_path / "task.md", "", {})

    ExternalAgentAdapter(name="codex", command="codex exec --json").propose_actions(task)

    assert captured["argv"] == ["/trusted/bin/codex", "exec", "--json", str(task.path)]
    assert captured["env"]["PATH"] == governed_handoff.FIXED_SUBPROCESS_PATH


def test_external_adapter_accepts_absolute_executable_and_rejects_non_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)
    executable = tmp_path / "agent"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(stat.S_IRWXU)
    task = TaskSpec("c51a", tmp_path / "task.md", "", {})

    ExternalAgentAdapter(name="codex", command=f"{executable} run").propose_actions(task)
    assert captured["argv"] == [str(executable), "run", str(task.path)]

    executable.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if os.access(executable, os.X_OK):  # pragma: no cover - root ignores mode bits
        pytest.skip("running as a user that bypasses execute permission checks")
    captured.clear()
    with pytest.raises(RuntimeError, match="fail closed"):
        ExternalAgentAdapter(name="codex", command=str(executable)).propose_actions(task)
    assert captured == {}
