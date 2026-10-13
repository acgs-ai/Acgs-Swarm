import copy
import json
import math

import pytest

from offline_foundations.decisions import (
    DecisionAttempts,
    DecisionError,
    bucket,
    build_envelope,
    confidence_metrics,
    fixture_coverage,
    normalize_boolean,
    normalize_vector,
    ordinal_summary,
    parse_payload,
    policy_oracle_reference,
    strict_projection,
    upstream_gate_reference,
)


def request():
    return {
        "schema_version": 1,
        "case_id": "synthetic-case",
        "instruction": "Recommend one read-only review capability; never launch work.",
        "state": "Correct a documented spelling.",
        "options": [
            {"id": "d", "role": "docs", "meaning": "Review documentation wording only"},
            {
                "id": "t",
                "role": "tests",
                "meaning": "Review specified unit-test behavior",
            },
            {"id": "c", "role": "code", "meaning": "Review specified implementation"},
            {
                "id": "e",
                "role": "escalate",
                "meaning": "Missing, ambiguous or unsupported scope",
            },
        ],
        "identity": {
            "model": "recorded-synthetic-v1",
            "model_revision": "fixture-revision-1",
            "config_digest": "1" * 64,
            "schema_digest": "2" * 64,
            "adapter_digest": "3" * 64,
            "weights_digest": None,
            "tokenizer_digest": None,
        },
        "gate": {
            "metric": "answer_confidence",
            "thresholds": {"choice:3-5": 0.8},
            "calibrated": False,
        },
    }


def payload(req=None):
    req = req or request()
    return {
        "type": "choice",
        "choice": "d",
        "probabilities": {"d": 0.8, "t": 0.1, "c": 0.05, "e": 0.05},
        "answer_confidence": 0.8,
        "confidence": 0.5,
        "x_jev_confidence": 0.73,
        "coverage": fixture_coverage(req),
        "selection_provenance": "full_option_pool",
    }


def test_a01_named_vector_statistics_and_ties():
    for k in (2, 4, 8, 16):
        uniform = [1 / k] * k
        assert confidence_metrics(uniform)["entropy_concentration_v1"] == pytest.approx(
            0
        )
        assert confidence_metrics([1] + [0] * (k - 1))["normalized_top_mass_v1"] == 1
    metrics = confidence_metrics([0.8, 0.2])
    assert metrics["entropy_concentration_v1"] == pytest.approx(0.2780719051)
    assert metrics["normalized_top_mass_v1"] == pytest.approx(0.6)
    assert metrics["max_probability_v1"] == 0.8
    req = request()
    data = payload(req)
    data["probabilities"] = dict.fromkeys(("d", "t", "c", "e"), 0.25)
    envelope = build_envelope(req, data).data
    assert envelope["proposal"]["argmax"] == "d"
    assert envelope["proposal"]["tie_rule"] == "schema_order_v1"


def test_a02_binned_answer_confidence_not_reconstructed_from_vector():
    req = request()
    data = payload(req)
    data["answer_confidence"] = 0.9
    data["calibration"] = {
        "identity": req["identity"],
        "binning_digest": "b" * 64,
        "raw_temperature": 0.1,
        "applied_temperature": 0.5,
    }
    record = build_envelope(req, data).data
    assert record["reported_metrics"]["answer_confidence"] == 0.9
    assert record["derived_metrics"]["max_probability_v1"] == 0.8
    assert record["reported_metrics"]["confidence"] == 0.5


def test_a03_gate_threshold_equality_and_unconfigured_state():
    assert upstream_gate_reference(payload(), None)["abstention"] is None
    for threshold, expected in [(0, "passed"), (0.8, "passed"), (1, "abstained")]:
        assert upstream_gate_reference(payload(), threshold)["abstention"] == expected
        req = request()
        req["gate"]["thresholds"] = {"choice:3-5": threshold}
        assert build_envelope(req, payload(req)).data["gate"]["status"] == expected
    req = request()
    req["gate"] = None
    assert build_envelope(req, payload(req)).data["gate"]["status"] == "not_configured"


def test_a04_no_silent_metric_fallback_or_malformed_confidence():
    data = payload()
    del data["answer_confidence"]
    assert upstream_gate_reference(data, 0.4)["metric"] == "confidence"
    assert build_envelope(request(), data).data["gate"]["status"] == "unevaluated"
    for invalid in (float("nan"), float("inf"), True, -0.1, 1.1):
        data = payload()
        data["answer_confidence"] = invalid
        assert (
            build_envelope(request(), data).data["consumer"]["status"] == "unavailable"
        )
    data = payload()
    del data["answer_confidence"]
    del data["confidence"]
    assert upstream_gate_reference(data, 0.8)["abstention"] == "unevaluated"


def test_a05_uncovered_bucket_refused_despite_upstream_default():
    req = request()
    req["gate"]["thresholds"] = {"choice:2": 0.8}
    assert (
        upstream_gate_reference(payload(), req["gate"]["thresholds"])["threshold"] == 0
    )
    req["gate"]["thresholds"]["default"] = 0.5
    assert (
        upstream_gate_reference(payload(), req["gate"]["thresholds"])["threshold"]
        == 0.5
    )
    assert build_envelope(req, payload(req)).data["gate"]["status"] == "unevaluated"
    req["gate"]["thresholds"] = {"choice:four": 0.5}
    with pytest.raises(DecisionError):
        build_envelope(req, payload(req))
    assert bucket("choice", 4) == "choice:3-5"


def test_a06_strict_projection_preserves_diagnostic_unknowns():
    data = strict_projection(payload())
    assert "confidence" in data
    assert (
        not {"answer_confidence", "coverage", "abstention", "act_probability"}
        & data.keys()
    )
    result = build_envelope(request(), data).data
    assert result["coverage"]["status"] == "unknown"
    assert result["consumer"]["status"] == "unavailable"


def test_a07_abstention_and_action_do_not_authorize_use():
    for status in ("abstained", "unevaluated"):
        data = payload()
        data["abstention"] = status
        data["act_probability"] = 1
        result = build_envelope(request(), data).data
        assert result["proposal"]["declared"] == "d"
        assert result["consumer"]["choice"] == "e"
        assert result["consumer"]["status"] == "unavailable"
        assert result["authority"] == "not_evaluated"


def test_a08_boolean_semantics_and_ordinal_statistics():
    assert normalize_boolean([0.2, 0.8], ["false", "true"])["p_true"] == 0.8
    assert normalize_boolean([0.8, 0.2], ["true", "false"])["p_true"] == 0.8
    summary = ordinal_summary([0.1, 0.2, 0.3, 0.4], threshold=2)
    assert summary == {"expected_score": 2.0, "modal_label": 3, "p_at_or_above": 0.7}


def test_a09_rounding_duplicates_and_malformed_vectors():
    vector = normalize_vector(
        {"a": 0.3333, "b": 0.3333, "c": 0.3333}, ("a", "b", "c"), 4
    )
    assert vector["original"]["a"] == 0.3333
    assert sum(vector["normalized"].values()) == pytest.approx(1)
    assert vector["normalization_applied"] is True
    for values in (
        {"a": 1},
        {"a": 0, "b": 0},
        {"a": -0.1, "b": 1.1},
        {"a": 0.6, "b": 0.6},
        {"a": True, "b": 0},
        {"a": 0.5, "b": 0.5, "extra": 0},
    ):
        with pytest.raises(DecisionError):
            normalize_vector(values, ("a", "b"), 4)
    with pytest.raises(DecisionError):
        parse_payload('{"probabilities":{"a":0.5,"a":0.5}}')
    with pytest.raises(DecisionError):
        normalize_vector({"a": 1}, ("a",), 4)
    req = request()
    req["options"][-1]["role"] = "docs"
    with pytest.raises(DecisionError):
        build_envelope(req, payload(req))


def test_a10_serializer_state_coverage_is_not_token_parity():
    for state in (
        "early decisive late",
        {"z": "late", "a": "early"},
        ["early", "middle", "late"],
    ):
        req = request()
        req["state"] = state
        for backend in ("laya", "clef"):
            full = fixture_coverage(req, backend=backend)
            assert full["status"] == "complete"
            clipped = fixture_coverage(req, backend=backend, state_budget=5)
            assert clipped["status"] == "incomplete"
            assert clipped["exact_tokenizer_parity"] == "untested"
    req = request()
    req["state"] = ["early", "middle", "late"]
    assert fixture_coverage(req, state_budget=6)["retention"] == "suffix"
    req["state"] = "early middle late"
    assert fixture_coverage(req, state_budget=6)["retention"] == "prefix"


def test_a11_distinct_ids_do_not_prove_intact_criteria():
    req = request()
    for option in req["options"]:
        option["meaning"] = "common-prefix-" * 10 + option["role"]
    clipped = fixture_coverage(req, option_budget=10)
    assert clipped["options_distinct"] == 4
    assert clipped["criterion_complete"] is False
    for option in req["options"]:
        option["id"] = "common-prefix-" + option["role"]
    assert fixture_coverage(req, option_budget=5)["options_distinct"] == 1


def test_a12_instruction_and_criterion_loss_independent_of_state():
    req = request()
    req["instruction"] = "shared " * 100 + "never launch work"
    report = fixture_coverage(req, instruction_budget=10, option_budget=5)
    assert report["state_complete"] is True
    assert report["instruction_complete"] is False
    assert report["criterion_complete"] is False
    data = payload(req)
    data["coverage"] = report
    assert build_envelope(req, data).data["consumer"]["status"] == "unavailable"


def test_a13_zero_state_room_and_fixed_schema_failure():
    req = request()
    for report in (
        fixture_coverage(req, state_budget=0),
        fixture_coverage(req, fixed_schema_fits=False),
        fixture_coverage(req, markers_present=False),
    ):
        data = payload(req)
        data["coverage"] = report
        assert build_envelope(req, data).data["consumer"]["status"] == "unavailable"
    for field, value in (
        ("retained_state_bytes", 0),
        ("retained_state_sha256", "0" * 64),
        ("options_distinct", 0),
        ("serializer", "unrecognized"),
        ("exact_tokenizer_parity", "qualified"),
    ):
        data = payload(req)
        data["coverage"][field] = value
        assert build_envelope(req, data).data["consumer"]["status"] == "unavailable"


def test_a14_calibration_identity_and_temperature_provenance():
    req = request()
    req["gate"]["calibrated"] = True
    data = payload(req)
    assert build_envelope(req, data).data["gate"]["status"] == "unevaluated"
    data["calibration"] = {
        "identity": req["identity"],
        "binning_digest": "b" * 64,
        "raw_temperature": 0.1,
        "applied_temperature": 0.5,
    }
    assert build_envelope(req, data).data["gate"]["status"] == "passed"
    wrong = copy.deepcopy(data)
    wrong["calibration"]["identity"]["config_digest"] = "f" * 64
    assert build_envelope(req, wrong).data["gate"]["status"] == "unevaluated"
    assert (
        data["calibration"]["raw_temperature"]
        != data["calibration"]["applied_temperature"]
    )


def test_a15_tournament_excluded_and_attempt_accounting_durable(tmp_path):
    data = payload()
    data["selection_provenance"] = "tournament_elimination"
    assert build_envelope(request(), data).data["consumer"]["status"] == "unavailable"
    path = tmp_path / "decision.db"
    ledger = DecisionAttempts(path)
    for i, status in enumerate(("empty", "timeout", "refusal", "malformed", "success")):
        ledger.append(
            f"a{i}",
            "case",
            status,
            raw_response="recorded " + status,
            retry_of=None if i == 0 else "a0",
        )
    assert len(DecisionAttempts(path).records("case")) == 5
    ledger.append(
        "a4", "case", "success", raw_response="recorded success", retry_of="a0"
    )
    assert len(ledger.records("case")) == 5
    with pytest.raises(DecisionError):
        ledger.append("a4", "case", "success", raw_response="changed", retry_of="a0")


def test_a16_authority_isolation_and_pinned_oracle_reference():
    for field in ("governed", "risk_score", "settlement", "commit", "authority"):
        data = payload()
        data[field] = True
        with pytest.raises(DecisionError):
            build_envelope(request(), data)
    data = payload()
    data["choice"] = "outside-pool"
    assert build_envelope(request(), data).data["consumer"]["status"] == "unavailable"
    for risk, expected in (
        (0.29, True),
        (0.30, False),
        (math.nan, False),
        (False, False),
    ):
        assert (
            policy_oracle_reference(
                {"governed": True, "violations": [], "risk_score": risk}
            )
            is expected
        )
    assert policy_oracle_reference({"risk_score": 0.29}) is False
    assert (
        policy_oracle_reference(
            {"governed": True, "violations": ["dirty"], "risk_score": 0}
        )
        is False
    )
    result = build_envelope(request(), payload()).data
    assert "risk_score" not in result
    assert result["qualification"]["live_endpoint"] == "unrun"
    assert json.loads(json.dumps(result)) == result
