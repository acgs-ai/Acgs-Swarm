"""Tests for langgraph_runtime.guards - pure conditional-edge guard primitives.

These guards must:
  * Return route name strings only (never raise on missing keys)
  * Have no langgraph dependency (work in any state machine)
  * Mirror the fail-closed contract from swe_bench/governed_agent.py:135
  * Use the canonical CONSTITUTIONAL_HASH from constants.py
  * Honor the 3-of-5 super-majority quorum rule
"""

from __future__ import annotations

import sys

import pytest
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime import guards
from constitutional_swarm.langgraph_runtime.guards import (
    constitutional_hash_guard,
    fail_closed_guard,
    quorum_guard,
)

# ---------------------------------------------------------------------------
# constitutional_hash_guard
# ---------------------------------------------------------------------------


class TestConstitutionalHashGuard:
    def test_returns_ok_when_hash_matches(self) -> None:
        state = {"constitutional_hash": CONSTITUTIONAL_HASH}
        assert constitutional_hash_guard(state) == "ok"

    def test_returns_halt_when_hash_differs(self) -> None:
        state = {"constitutional_hash": "deadbeefcafebabe"}
        assert constitutional_hash_guard(state) == "halt"

    def test_returns_halt_on_missing_hash(self) -> None:
        assert constitutional_hash_guard({}) == "halt"

    def test_returns_halt_on_empty_hash(self) -> None:
        assert constitutional_hash_guard({"constitutional_hash": ""}) == "halt"

    def test_returns_halt_on_none_hash(self) -> None:
        # ``None`` is not equal to the canonical hash string -> halt
        assert constitutional_hash_guard({"constitutional_hash": None}) == "halt"

    def test_canonical_hash_value_unchanged(self) -> None:
        # Hard string constant - protects against silent drift.
        assert CONSTITUTIONAL_HASH == "608508a9bd224290"


# ---------------------------------------------------------------------------
# fail_closed_guard
# ---------------------------------------------------------------------------


class TestFailClosedGuard:
    def test_accepts_clean_state(self) -> None:
        state = {"violations": [], "risk_score": 0.0}
        assert fail_closed_guard(state) == "accept"

    def test_accepts_clean_state_with_missing_fields(self) -> None:
        # Both fields absent -> defaults of [] and 0.0 -> accept
        assert fail_closed_guard({}) == "accept"

    def test_accepts_state_just_below_threshold(self) -> None:
        state = {"violations": [], "risk_score": 0.29999}
        assert fail_closed_guard(state) == "accept"

    def test_rejects_on_violations_only(self) -> None:
        state = {"violations": ["principle_x_breach"], "risk_score": 0.0}
        assert fail_closed_guard(state) == "reject"

    def test_rejects_on_risk_at_threshold(self) -> None:
        # Threshold is inclusive (>=)
        state = {"violations": [], "risk_score": 0.3}
        assert fail_closed_guard(state) == "reject"

    def test_rejects_on_risk_above_threshold(self) -> None:
        state = {"violations": [], "risk_score": 0.85}
        assert fail_closed_guard(state) == "reject"

    def test_rejects_on_both_signals(self) -> None:
        state = {"violations": ["v1", "v2"], "risk_score": 0.9}
        assert fail_closed_guard(state) == "reject"

    def test_rejects_on_violations_with_none_risk(self) -> None:
        # ``None`` should coerce to 0.0 via the ``or 0.0`` fallback,
        # but violations alone still trigger reject.
        state = {"violations": ["v"], "risk_score": None}
        assert fail_closed_guard(state) == "reject"

    def test_none_risk_score_coerces_to_zero(self) -> None:
        state = {"violations": [], "risk_score": None}
        assert fail_closed_guard(state) == "accept"


# ---------------------------------------------------------------------------
# quorum_guard
# ---------------------------------------------------------------------------


class TestQuorumGuard:
    def test_continue_when_no_votes(self) -> None:
        assert quorum_guard({}) == "continue"
        assert quorum_guard({"peer_votes": {}}) == "continue"

    def test_continue_when_fewer_than_five_votes(self) -> None:
        state = {
            "peer_votes": {
                "p1": "accept",
                "p2": "accept",
                "p3": "accept",
                "p4": "accept",
            }
        }
        # Only 4 votes -> below quorum denominator -> continue
        assert quorum_guard(state) == "continue"

    def test_continue_when_five_votes_but_fewer_than_three_accepts(self) -> None:
        state = {
            "peer_votes": {
                "p1": "accept",
                "p2": "accept",
                "p3": "reject",
                "p4": "reject",
                "p5": "reject",
            }
        }
        assert quorum_guard(state) == "continue"

    def test_settled_on_three_of_five_accepts(self) -> None:
        state = {
            "peer_votes": {
                "p1": "accept",
                "p2": "accept",
                "p3": "accept",
                "p4": "reject",
                "p5": "reject",
            }
        }
        assert quorum_guard(state) == "settled"

    def test_settled_on_all_five_accepts(self) -> None:
        state = {
            "peer_votes": {f"p{i}": "accept" for i in range(5)},
        }
        assert quorum_guard(state) == "settled"

    def test_settled_on_more_than_five_votes_with_three_accepts(self) -> None:
        state = {
            "peer_votes": {
                "p1": "accept",
                "p2": "accept",
                "p3": "accept",
                "p4": "reject",
                "p5": "reject",
                "p6": "reject",
                "p7": "abstain",
            }
        }
        assert quorum_guard(state) == "settled"

    def test_continue_when_six_votes_but_only_two_accepts(self) -> None:
        state = {
            "peer_votes": {
                "p1": "accept",
                "p2": "accept",
                "p3": "reject",
                "p4": "reject",
                "p5": "reject",
                "p6": "reject",
            }
        }
        assert quorum_guard(state) == "continue"

    def test_continue_on_malformed_peer_votes_non_dict(self) -> None:
        # Lists, strings, etc. should not crash - fail-closed to ``continue``.
        assert quorum_guard({"peer_votes": ["accept", "accept", "accept"]}) == "continue"
        assert quorum_guard({"peer_votes": "accept"}) == "continue"
        assert quorum_guard({"peer_votes": 42}) == "continue"

    def test_continue_when_peer_votes_is_none(self) -> None:
        assert quorum_guard({"peer_votes": None}) == "continue"

    def test_non_accept_values_do_not_count(self) -> None:
        # Only the literal string "accept" counts toward the quorum.
        state = {
            "peer_votes": {
                "p1": "ACCEPT",
                "p2": "yes",
                "p3": True,
                "p4": 1,
                "p5": "accept",
            }
        }
        assert quorum_guard(state) == "continue"


# ---------------------------------------------------------------------------
# Cross-cutting: no langgraph dependency
# ---------------------------------------------------------------------------


def test_guards_module_does_not_import_langgraph() -> None:
    """The guards module must remain LangGraph-free.

    These primitives are reusable in any state machine; pulling in langgraph
    would defeat that and break installs without the optional dep.
    """
    source = guards.__file__
    assert source is not None
    with open(source, encoding="utf-8") as fh:
        text = fh.read()
    assert "import langgraph" not in text
    assert "from langgraph" not in text


def test_langgraph_not_required_at_runtime() -> None:
    """Importing guards must succeed even if langgraph is absent.

    We can't uninstall langgraph at test time, but we can assert the module
    object has no ``langgraph`` attribute and that all three guards are
    callable without any langgraph-typed state.
    """
    assert not hasattr(guards, "langgraph")
    # All three guards accept plain dicts and return plain strings.
    assert isinstance(constitutional_hash_guard({}), str)
    assert isinstance(fail_closed_guard({}), str)
    assert isinstance(quorum_guard({}), str)


def test_guards_callable_when_langgraph_module_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force-remove ``langgraph`` from sys.modules and re-exercise guards.

    Confirms the guard functions never touch langgraph at call time.
    """
    monkeypatch.setitem(sys.modules, "langgraph", None)
    assert constitutional_hash_guard({"constitutional_hash": CONSTITUTIONAL_HASH}) == "ok"
    assert fail_closed_guard({"violations": [], "risk_score": 0.0}) == "accept"
    assert (
        quorum_guard({"peer_votes": dict.fromkeys(("a", "b", "c", "d", "e"), "accept")})
        == "settled"
    )
