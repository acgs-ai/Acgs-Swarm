"""Unit tests for langgraph_runtime.nodes.

These tests rely only on light-weight stubs/mocks for the injected
dependencies (``dna``, ``generator``, ``crdt``, ``ode``).  langgraph itself
is intentionally NOT imported -- the node primitives must work as plain
callables regardless of whether the runtime is installed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.nodes import (
    append_crdt_node,
    evolve_trust_node,
    generate_node,
    settle_node,
    validate_node,
)

# ---------------------------------------------------------------------------
# validate_node
# ---------------------------------------------------------------------------


def test_validate_node_empty_patch_short_circuits() -> None:
    dna = MagicMock()
    out = validate_node({"patch": ""}, dna=dna)

    assert out == {"violations": [], "risk_score": 0.0, "governed": True}
    dna.validate.assert_not_called()


def test_validate_node_missing_patch_key_short_circuits() -> None:
    dna = MagicMock()
    out = validate_node({}, dna=dna)

    assert out == {"violations": [], "risk_score": 0.0, "governed": True}
    dna.validate.assert_not_called()


def test_validate_node_extracts_rule_ids_from_objects() -> None:
    """Mirrors stub-shaped violations exposing ``.rule_id`` attributes."""
    violation = SimpleNamespace(rule_id="R-001", rule_text="No raw SQL")
    result = SimpleNamespace(violations=(violation,), risk_score=0.42)
    dna = MagicMock()
    dna.validate.return_value = result

    out = validate_node({"patch": "DROP TABLE users;"}, dna=dna)

    dna.validate.assert_called_once_with("DROP TABLE users;")
    assert out["violations"] == ["R-001"]
    assert out["risk_score"] == pytest.approx(0.42)
    assert out["governed"] is True


def test_validate_node_handles_string_violations() -> None:
    """Production ``DNAValidationResult.violations`` is ``tuple[str, ...]``.

    The fallback ``str(v)`` in the node must round-trip those strings.
    """
    result = SimpleNamespace(
        violations=("R-002: pii-leak", "R-003: unsafe-eval"),
        risk_score=0.91,
    )
    dna = MagicMock()
    dna.validate.return_value = result

    out = validate_node({"patch": "exec(input())"}, dna=dna)

    assert out["violations"] == ["R-002: pii-leak", "R-003: unsafe-eval"]
    assert out["risk_score"] == pytest.approx(0.91)
    assert out["governed"] is True


def test_validate_node_handles_none_risk_score() -> None:
    result = SimpleNamespace(violations=(), risk_score=None)
    dna = MagicMock()
    dna.validate.return_value = result

    out = validate_node({"patch": "noop"}, dna=dna)

    assert out["risk_score"] == 0.0
    assert out["violations"] == []


# ---------------------------------------------------------------------------
# generate_node
# ---------------------------------------------------------------------------


def test_generate_node_returns_patch_and_constitutional_hash() -> None:
    generator = MagicMock(
        return_value=("--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n", {"intervention_rate": 0.25})
    )
    state = {"task": {"problem": "fix it"}}

    out = generate_node(state, generator=generator)

    generator.assert_called_once_with(state)
    assert out["patch"].startswith("--- a")
    assert out["intervention_rate"] == pytest.approx(0.25)
    assert out["constitutional_hash"] == CONSTITUTIONAL_HASH


def test_generate_node_defaults_intervention_rate_to_zero() -> None:
    generator = MagicMock(return_value=("patch", {}))

    out = generate_node({}, generator=generator)

    assert out["intervention_rate"] == 0.0
    assert out["constitutional_hash"] == CONSTITUTIONAL_HASH


# ---------------------------------------------------------------------------
# append_crdt_node
# ---------------------------------------------------------------------------


def test_append_crdt_node_serializes_state_and_returns_cid() -> None:
    crdt = MagicMock()
    crdt.append.return_value = SimpleNamespace(cid="bafy-cid-001")

    state = {"patch": "P", "governed": True, "_h_next": "private"}
    out = append_crdt_node(state, crdt=crdt)

    crdt.append.assert_called_once()
    kwargs = crdt.append.call_args.kwargs
    # Private keys must be stripped from the serialized payload.
    decoded = json.loads(kwargs["payload"])
    assert "_h_next" not in decoded
    assert decoded["patch"] == "P"
    assert decoded["governed"] is True
    assert kwargs["bodes_passed"] is True
    assert out == {"cid": "bafy-cid-001"}


def test_append_crdt_node_defaults_governed_flag_to_false() -> None:
    crdt = MagicMock()
    crdt.append.return_value = SimpleNamespace(cid="bafy-cid-002")

    out = append_crdt_node({"patch": "P"}, crdt=crdt)

    kwargs = crdt.append.call_args.kwargs
    assert kwargs["bodes_passed"] is False
    assert out["cid"] == "bafy-cid-002"


def test_append_crdt_node_accepts_string_cid_return() -> None:
    """Stubs that return a bare CID string (not a DAGNode) still produce
    a string CID in the partial update dict."""
    crdt = MagicMock()
    crdt.append.return_value = "raw-cid-string"

    out = append_crdt_node({"patch": "P"}, crdt=crdt)

    assert out == {"cid": "raw-cid-string"}


# ---------------------------------------------------------------------------
# evolve_trust_node
# ---------------------------------------------------------------------------


def test_evolve_trust_node_steps_ode_and_advances_time() -> None:
    ode = MagicMock(return_value="H_next_matrix")
    h = "H_current"
    t = 1.0
    dt = 0.25

    out = evolve_trust_node({}, ode=ode, h=h, t=t, dt=dt)

    ode.assert_called_once_with(h, t)
    assert out["trust_step_completed"] is True
    assert out["trust_step_t"] == pytest.approx(t + dt)
    assert out["_h_next"] == "H_next_matrix"


def test_evolve_trust_node_default_dt() -> None:
    ode = MagicMock(return_value="next")
    out = evolve_trust_node({}, ode=ode, h="h", t=0.0)

    assert out["trust_step_t"] == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# settle_node
# ---------------------------------------------------------------------------


def test_settle_node_true_when_quorum_reached() -> None:
    assert settle_node({"quorum_reached": True}) == {"settled": True}


def test_settle_node_false_when_quorum_missing() -> None:
    assert settle_node({}) == {"settled": False}


def test_settle_node_false_when_quorum_falsy() -> None:
    assert settle_node({"quorum_reached": False}) == {"settled": False}
    assert settle_node({"quorum_reached": 0}) == {"settled": False}
