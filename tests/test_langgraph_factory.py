"""Tests for the LangGraph StateGraph factory (Unit 5)."""

from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.runtime import (
    ConstitutionalHashError,
    build_swarm_graph,
)

# ---------------------------------------------------------------------------
# Stub collaborators
# ---------------------------------------------------------------------------


def _clean_generator(_state):
    return "diff --git a/x b/x\n", {"intervention_rate": 0.0}


class _CleanDNA:
    """DNA validator stub that reports no violations and low risk."""

    class _Result:
        violations = ()
        risk_score = 0.0

    def validate(self, _patch):
        return self._Result()


class _RiskyDNA:
    """DNA validator stub that reports risk_score >= 0.3 -> reject."""

    class _Result:
        violations = ()
        risk_score = 0.5

    def validate(self, _patch):
        return self._Result()


class _CRDT:
    """Minimal MerkleCRDT stub returning a deterministic CID."""

    def __init__(self):
        self.calls = 0

    def append(self, *, payload, bodes_passed):
        self.calls += 1
        return f"cid-{self.calls}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_hash_mismatch_raises():
    with pytest.raises(ConstitutionalHashError):
        build_swarm_graph(
            {"hash": "deadbeefdeadbeef"},
            generator=_clean_generator,
        )


def test_happy_path_runs_end_to_end():
    crdt = _CRDT()
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=_clean_generator,
        dna=_CleanDNA(),
        crdt=crdt,
    )

    initial = {
        "patch": "",
        "violations": [],
        "risk_score": 0.0,
        "quorum_reached": True,
    }
    final = graph.invoke(
        initial,
        config={"configurable": {"thread_id": "test-happy"}},
    )

    assert final.get("settled") is True
    assert final.get("cid")
    assert final.get("cid") != ""
    assert final.get("constitutional_hash") == CONSTITUTIONAL_HASH
    assert crdt.calls == 1


def test_reject_branch_when_risk_too_high():
    crdt = _CRDT()
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=_clean_generator,
        dna=_RiskyDNA(),
        crdt=crdt,
    )

    initial = {
        "patch": "",
        "violations": [],
        "risk_score": 0.0,
        "quorum_reached": True,
    }
    final = graph.invoke(
        initial,
        config={"configurable": {"thread_id": "test-reject"}},
    )

    assert not final.get("settled")
    assert final.get("cid", "") == ""
    assert crdt.calls == 0
    assert float(final.get("risk_score", 0.0)) >= 0.3


def test_compiles_with_interrupt_before():
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=_clean_generator,
        dna=_CleanDNA(),
        crdt=_CRDT(),
        interrupt_before=("settle",),
    )
    assert graph is not None
