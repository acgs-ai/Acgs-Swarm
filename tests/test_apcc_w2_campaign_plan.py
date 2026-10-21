"""Frozen numeric plan validation cannot authorize execution or pooled counts."""

import hashlib
import json
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical import w2_campaign_plan as p


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def validate(raw):
    return p.validate_plan(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_committed_artifact_and_all_denominators():
    path = (
        Path(__file__).resolve().parents[1]
        / "experiments/apcc-1/w2_campaign_plan_v1.json"
    )
    assert path.read_bytes() == p.frozen_plan_bytes()
    plan = p.load_plan(path, expected_sha256=p.frozen_plan_sha256())
    for cell in plan["cells"].values():
        assert cell["scheduled_ops"] == cell["min_commit_floor"] == 10_000
        assert cell["rate_pps"] * cell["window_ms"] == 10_000_000
    assert plan["timing_bounds"]["slot_hard_ceiling_ms"] == 225


@pytest.mark.parametrize(
    "field",
    [
        "campaign_plan_version",
        "qualification_floor_ops",
        "pool_concurrency_permits",
        "observer_lifetime_cap_ms",
    ],
)
def test_header_substitution(field):
    plan = p.frozen_plan()
    plan[field] = "other" if isinstance(plan[field], str) else plan[field] - 1
    with pytest.raises(ValueError):
        validate(canonical(plan))


@pytest.mark.parametrize(
    "field",
    [
        "admission_grace_ms",
        "op_sla_ms",
        "slot_hard_ceiling_ms",
        "window_drain_ms",
        "renewal_drain_ms",
    ],
)
def test_frozen_timing_cannot_be_relaxed(field):
    plan = p.frozen_plan()
    plan["timing_bounds"][field] += 1
    with pytest.raises(ValueError):
        validate(canonical(plan))


@pytest.mark.parametrize("cell", ["cell_10_pps", "cell_100_pps", "cell_500_pps"])
@pytest.mark.parametrize(
    "field", ["rate_pps", "scheduled_ops", "window_ms", "min_commit_floor"]
)
def test_cell_fields_and_floors_cannot_change(cell, field):
    plan = p.frozen_plan()
    plan["cells"][cell][field] -= 1
    with pytest.raises(ValueError):
        validate(canonical(plan))


@pytest.mark.parametrize("replacement", [True, 10000.0, "10000", None])
def test_numeric_types_are_exact(replacement):
    plan = p.frozen_plan()
    plan["qualification_floor_ops"] = replacement
    with pytest.raises(ValueError):
        validate(canonical(plan))


@pytest.mark.parametrize(
    "mutation",
    [
        "trailing",
        "pretty",
        "duplicate",
        "unknown",
        "missing",
        "nested-unknown",
        "nested-missing",
        "cell-extra",
        "cell-missing",
        "boolean-eligible",
    ],
)
def test_exact_canonical_schema(mutation):
    raw = p.frozen_plan_bytes()
    plan = p.frozen_plan()
    if mutation == "trailing":
        raw += b"\n"
    elif mutation == "pretty":
        raw = json.dumps(plan, indent=2).encode()
    elif mutation == "duplicate":
        raw = raw.replace(
            b'{"campaign_plan_version":',
            b'{"qualification_floor_ops":10000,"campaign_plan_version":',
            1,
        )
    else:
        if mutation == "unknown":
            plan["algorithm"] = "Ed25519"
        elif mutation == "missing":
            del plan["observer_lifetime_cap_ms"]
        elif mutation == "nested-unknown":
            plan["timing_bounds"]["extra"] = 1
        elif mutation == "nested-missing":
            del plan["timing_bounds"]["op_sla_ms"]
        elif mutation == "cell-extra":
            plan["cells"]["cell_1_pps"] = plan["cells"]["cell_10_pps"]
        elif mutation == "cell-missing":
            del plan["cells"]["cell_10_pps"]
        elif mutation == "boolean-eligible":
            plan["campaign_eligible"] = True
        raw = canonical(plan)
    with pytest.raises(ValueError):
        validate(raw)


def test_external_pin_cannot_be_replaced_by_protocol_digest():
    from constitutional_swarm.apcc.crypto import sha256_digest

    raw = p.frozen_plan_bytes()
    for pin in ("0" * 64, p.frozen_plan_sha256().upper(), sha256_digest(raw)):
        with pytest.raises(ValueError):
            p.validate_plan(raw, expected_sha256=pin)


@pytest.mark.parametrize("cell", ["cell_10_pps", "cell_100_pps", "cell_500_pps"])
def test_translation_never_enables_qualification(cell):
    plan = p.diagnostic_window_plan(cell)
    assert plan.qualification is False
    assert plan.operation_floor == plan.scheduled_operations == 10_000
    assert plan.admission_grace_ns == 25_000_000
    assert plan.operation_sla_ns == 200_000_000
    assert plan.drain_ns == 1_000_000_000
    last = plan.slot(9999)
    assert last.deadline_ns <= plan.duration_ns


def test_caller_mutation_cannot_change_frozen_contract():
    plan = p.frozen_plan()
    plan["cells"]["cell_500_pps"]["min_commit_floor"] = 100
    assert p.frozen_plan()["cells"]["cell_500_pps"]["min_commit_floor"] == 10_000
    with pytest.raises(ValueError):
        p.diagnostic_window_plan("unknown")
