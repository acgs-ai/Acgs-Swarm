"""Execute only audited pure functions, never a backend/model package."""

import ast
import copy
import hashlib
import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional, Union, cast

import pytest

from offline_foundations.decisions import (
    confidence_metrics,
    fixture_coverage,
    policy_oracle_reference,
    strict_projection,
    upstream_gate_reference,
)

SOURCES = Path(__file__).resolve().parent / "fixtures/pinned_sources"
PINS = {
    "acgs-guards.py": "f82a0d5d214b1f9df806c62389bba9d9c975e0b3a40ebe28a390a33cda705dd2",
    "laya-serve.py": "8545e6abbaa5be1ea29ea3b2652a3b8577e5a03e39cd3fa0822da09a2a52a2e1",
    "laya-confidence.py": "396024e9606cb58ac8f14dcfade8ab48bc5678ad45d483eb2f235e34d39b5a49",
    "laya-common.py": "9b4a1c30073da76fc422ea0a1edc91862d7a069c0f84e38de195be5da7792bd4",
    "sglang-serving.py": "25e0e6488fc03c270a0f256c0b9099698f7f8c75a8d032b561c9c4afd759caec",
    "sglang-joint_schema.py": "965c5fc09c3a9e6ca31b5fd9a059922b14943ef929ba901c2aa95a025ca7a0a0",
}


def reference(filename, names=None):
    raw = (SOURCES / (filename + ".txt")).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINS[filename]
    tree = ast.parse(raw, filename=filename)
    if names is None:
        # confidence.py is pure Python; audit before executing its whole source.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(n.name in {"math", "typing"} for n in node.names)
            if isinstance(node, ast.ImportFrom):
                assert node.module == "typing"
    else:
        # Other files import model/serving libraries. Extract ONLY the named
        # pure function ASTs; their imports and module bodies are never executed.
        functions = [
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names
        ]
        assert {n.name for n in functions} == set(names)
        tree = ast.Module(body=functions, type_ignores=[])
        assert not any(
            isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree)
        )
    ns = {
        "math": math,
        "json": json,
        "Any": Any,
        "Dict": dict,
        "List": list,
        "Optional": Optional,
        "Union": Union,
        "Mapping": Mapping,
        "cast": cast,
        "_RISK_THRESHOLD": 0.3,
    }
    exec(compile(tree, filename, "exec"), ns)  # noqa: S102 - hash-guarded pure ASTs only
    return ns


def test_pinned_laya_gate_against_recorded_reference():
    laya = reference("laya-confidence.py")
    for value in (None, 0, 0.79, 0.8, 1, True, float("nan"), float("inf"), -0.1, 1.1):
        for threshold in (None, 0, 0.8, 1, {"choice:2": 0.8}, {"default": 0.5}):
            data = {
                "type": "choice",
                "probabilities": {"a": 0.8, "b": 0.1, "c": 0.1},
                "answer_confidence": value,
                "confidence": 0.4,
            }
            answers = [{"answers": {"fixture": copy.deepcopy(data)}}]
            laya["apply_confidence_gate"](answers, threshold)
            actual = answers[0]["answers"]["fixture"]
            expected = upstream_gate_reference(data, threshold)
            assert actual.get("abstention") == expected["abstention"]
            assert actual.get("abstention_threshold") == expected["threshold"]
            assert actual["probabilities"] == data["probabilities"]
    # The upstream reference accepts finite out-of-range reported confidence;
    # the consumer's stricter refusal is intentionally tested separately in A04.


def test_pinned_systemone_math_and_laya_jev():
    systemone = reference(
        "sglang-serving.py", ("_normalized", "_choice_confidence", "_score_confidence")
    )
    laya = reference("laya-confidence.py")
    for k in (1, 2, 4, 8, 16):
        for p in ([1 / k] * k, [1] + [0] * (k - 1), list(range(1, k + 1))):
            q = systemone["_normalized"](p)
            choice = systemone["_choice_confidence"](q)
            score = systemone["_score_confidence"](q)
            for kind, expected in (("choice", choice), ("score", score)):
                answer = {
                    "type": kind,
                    "probabilities": {str(i): v for i, v in enumerate(q)},
                }
                assert laya["jev_confidence"](answer) == pytest.approx(expected)
            if k > 1:
                assert confidence_metrics(q)["normalized_top_mass_v1"] == pytest.approx(
                    choice
                )
    assert systemone["_normalized"]([0, 0]) == [0.5, 0.5]


def test_pinned_serializer_bytes_without_tokenizer():
    laya = reference("laya-common.py", ("serialize_state",))
    clef = reference("sglang-joint_schema.py", ("_render",))
    for state in (
        "early decisive late",
        {"z": "late", "a": "éarly"},
        ["early", "late"],
    ):
        req = {
            "state": state,
            "instruction": "fixture",
            "options": [{"id": "x", "meaning": "read"}],
        }
        for backend, render in (
            ("laya", laya["serialize_state"]),
            ("clef", clef["_render"]),
        ):
            actual = render(state).encode("utf-8")
            observed = fixture_coverage(req, backend=backend)
            assert observed["source_state_sha256"] == hashlib.sha256(actual).hexdigest()
            assert observed["state_bytes"] == len(actual)
            assert observed["exact_tokenizer_parity"] == "untested"


def test_pinned_projection_and_policy_oracle_reference():
    serve = reference("laya-serve.py", ("_project_jev_strict",))
    answer = {
        "type": "choice",
        "choice": "x",
        "probabilities": {"x": 0.8, "y": 0.2},
        "confidence": 0.4,
        "answer_confidence": 0.8,
        "coverage": {"status": "complete"},
        "abstention": "abstained",
        "act_probability": 1,
    }
    assert serve["_project_jev_strict"]({"model": "fixture", "answers": {"a": answer}})[
        "answers"
    ]["a"] == strict_projection(answer)
    guards = reference("acgs-guards.py", ("has_clean_validation_evidence",))
    for governed in (None, False, True):
        for violations in (None, [], (), ["dirty"], ""):
            for risk in (
                None,
                False,
                0,
                0.29,
                0.3,
                -1,
                float("nan"),
                float("inf"),
                10**500,
            ):
                state = {
                    "governed": governed,
                    "violations": violations,
                    "risk_score": risk,
                }
                assert policy_oracle_reference(state) == guards[
                    "has_clean_validation_evidence"
                ](state)
