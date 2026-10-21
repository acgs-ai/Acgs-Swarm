"""Frozen W2 numeric matrix validation, with no execution or qualification grant.

This controller plan uses canonical JSON integers. It is not an APCC authority
object. Renewal authorization separately binds its external byte digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan

PLAN_VERSION = "w2_campaign_plan_v1"
_MAX_PLAN_BYTES = 16_384


def frozen_plan() -> dict[str, Any]:
    """Return fresh data, so caller mutations cannot change the frozen contract."""
    return {
        "campaign_plan_version": PLAN_VERSION,
        "qualification_floor_ops": 10_000,
        "pool_concurrency_permits": 16,
        "observer_lifetime_cap_ms": 1_200_000,
        "timing_bounds": {
            "admission_grace_ms": 25,
            "op_sla_ms": 200,
            "slot_hard_ceiling_ms": 225,
            "window_drain_ms": 1_000,
            "renewal_drain_ms": 2_000,
        },
        "cells": {
            f"cell_{rate}_pps": {
                "rate_pps": rate,
                "scheduled_ops": 10_000,
                "window_ms": duration,
                "min_commit_floor": 10_000,
            }
            for rate, duration in ((10, 1_000_000), (100, 100_000), (500, 20_000))
        },
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def frozen_plan_bytes() -> bytes:
    """Return the exact canonical external artifact bytes without a newline."""
    return _canonical(frozen_plan())


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate campaign plan field")
        result[name] = value
    return result


def _exact(value: object, expected: object) -> None:
    if type(value) is not type(expected):
        raise ValueError("campaign plan field has wrong JSON type")
    if isinstance(expected, dict):
        if not isinstance(value, dict) or set(value) != set(expected):
            raise ValueError("campaign plan has unknown or missing fields")
        for name, item in expected.items():
            _exact(value[name], item)
    elif value != expected:
        raise ValueError("campaign plan differs from frozen numeric specification")


def validate_plan(raw: bytes, *, expected_sha256: str) -> dict[str, Any]:
    """Validate an external pin and every frozen field; this grants no execution."""
    if type(raw) is not bytes or len(raw) > _MAX_PLAN_BYTES:
        raise ValueError("invalid campaign plan bytes")
    if (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("campaign plan pin must be lowercase SHA256 hexadecimal")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("campaign plan external SHA256 mismatch")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("malformed campaign plan") from exc
    _exact(value, frozen_plan())
    if _canonical(value) != raw:
        raise ValueError("noncanonical campaign plan")
    return dict(value)


def load_plan(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    """Read and validate one externally pinned numeric plan."""
    return validate_plan(path.read_bytes(), expected_sha256=expected_sha256)


def frozen_plan_sha256() -> str:
    """Return the frozen artifact pin; it is not evidence of Phase 1 completion."""
    return hashlib.sha256(frozen_plan_bytes()).hexdigest()


def diagnostic_window_plan(cell_id: str) -> WindowPlan:
    """Translate numeric timing for diagnostics with qualification always disabled.

    Slot completion must additionally satisfy the 225ms absolute slot ceiling;
    the existing WindowPlan accounts for the 200ms admission-relative SLA only.
    Only the separately gated campaign verifier may assert qualification.
    """
    plan = frozen_plan()
    if cell_id not in plan["cells"]:
        raise ValueError("unknown frozen campaign cell")
    cell = plan["cells"][cell_id]
    timing = plan["timing_bounds"]
    return WindowPlan(
        duration_ns=cell["window_ms"] * 1_000_000,
        scheduled_operations=cell["scheduled_ops"],
        admission_grace_ns=timing["admission_grace_ms"] * 1_000_000,
        operation_sla_ns=timing["op_sla_ms"] * 1_000_000,
        drain_ns=timing["window_drain_ms"] * 1_000_000,
        operation_floor=cell["min_commit_floor"],
        qualification=False,
    )
