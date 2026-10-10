"""Validation for monotonic-MAS trace evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast


class TraceValidationError(ValueError):
    """A corpus trace violates the evidence schema."""


FAILURE_MODES = frozenset({"redundant_work", "missed_handoff", "role_drift"})
MAX_JSONL_LINE_BYTES = 1024 * 1024


def _fail(line_number: int, field: str, detail: str) -> None:
    raise TraceValidationError(f"line {line_number}: field {field}: {detail}")


def _require_type(
    value: object, expected: type, *, line_number: int, field: str
) -> None:
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        _fail(line_number, field, f"expected {expected.__name__}")


def validate_trace(raw: object, *, line_number: int) -> dict[str, Any]:
    """Validate one decoded trace and return it with a narrowed type."""
    if not isinstance(raw, dict):
        _fail(line_number, "$", "expected object")
    trace = cast(dict[str, Any], raw)

    required = {
        "trace_id": str,
        "failure_mode": str,
        "agents": list,
        "payload": str,
        "context": dict,
    }
    for field, expected in required.items():
        if field not in trace:
            _fail(line_number, field, "required field is missing")
        _require_type(trace[field], expected, line_number=line_number, field=field)

    if not trace["trace_id"]:
        _fail(line_number, "trace_id", "must not be empty")
    if trace["failure_mode"] not in FAILURE_MODES:
        _fail(
            line_number,
            "failure_mode",
            f"must be a supported mode: {', '.join(sorted(FAILURE_MODES))}",
        )
    agents = trace["agents"]
    if not agents or any(not isinstance(agent, str) or not agent for agent in agents):
        _fail(line_number, "agents", "expected a non-empty list of agent identifiers")

    context = trace["context"]
    if trace["failure_mode"] == "missed_handoff":
        for field in ("src", "dst"):
            if field not in context:
                _fail(line_number, f"context.{field}", "required field is missing")
            _require_type(
                context[field], str, line_number=line_number, field=f"context.{field}"
            )
        if "deadline_rounds" not in context:
            _fail(line_number, "context.deadline_rounds", "required field is missing")
        _require_type(
            context["deadline_rounds"],
            int,
            line_number=line_number,
            field="context.deadline_rounds",
        )
        if context["deadline_rounds"] < 0:
            _fail(line_number, "context.deadline_rounds", "must be non-negative")
        if "observation_end_round" in context:
            _require_type(
                context["observation_end_round"],
                int,
                line_number=line_number,
                field="context.observation_end_round",
            )

    if "events" not in trace:
        return trace
    events = trace["events"]
    _require_type(events, list, line_number=line_number, field="events")
    event_ids: set[str] = set()
    sent_handoff_ids: set[str] = set()
    for index, event in enumerate(events):
        prefix = f"events[{index}]"
        if not isinstance(event, dict):
            _fail(line_number, prefix, "expected object")
        event_type = event.get("type")
        if not isinstance(event_type, str):
            _fail(line_number, f"{prefix}.type", "expected str")
        if event_type not in {"work_completed", "handoff_sent", "handoff_ack"}:
            continue
        fields = ["event_id"]
        if event_type == "work_completed":
            fields.extend(("agent_id", "payload"))
        else:
            fields.extend(("handoff_id", "src", "dst"))
        for field in fields:
            if field not in event:
                _fail(line_number, f"{prefix}.{field}", "required field is missing")
            _require_type(
                event[field], str, line_number=line_number, field=f"{prefix}.{field}"
            )
            if not event[field]:
                _fail(line_number, f"{prefix}.{field}", "must not be empty")
        event_id = event["event_id"]
        if event_id in event_ids:
            _fail(line_number, f"{prefix}.event_id", "must be unique within a trace")
        event_ids.add(event_id)
        if event_type == "handoff_sent":
            handoff_id = event["handoff_id"]
            if handoff_id in sent_handoff_ids:
                _fail(
                    line_number,
                    f"{prefix}.handoff_id",
                    "must identify exactly one handoff_sent event",
                )
            sent_handoff_ids.add(handoff_id)
        if event_type in {"handoff_sent", "handoff_ack"}:
            for endpoint in ("src", "dst"):
                if event[endpoint] != context[endpoint]:
                    _fail(
                        line_number,
                        f"{prefix}.{endpoint}",
                        f"must match context.{endpoint}",
                    )
            if "round" not in event:
                _fail(line_number, f"{prefix}.round", "required field is missing")
            _require_type(
                event["round"], int, line_number=line_number, field=f"{prefix}.round"
            )
            if event["round"] < 0:
                _fail(line_number, f"{prefix}.round", "must be non-negative")
    return trace


def decode_traces(corpus_bytes: bytes) -> list[dict[str, Any]]:
    """Decode and validate an immutable JSONL corpus snapshot."""
    traces: list[dict[str, Any]] = []
    for line_number, line in enumerate(corpus_bytes.splitlines(), start=1):
        if len(line) > MAX_JSONL_LINE_BYTES:
            _fail(
                line_number,
                "$",
                "JSONL line exceeds the 1 MiB byte limit",
            )
        if not line.strip():
            continue
        traces.append(validate_trace(json.loads(line), line_number=line_number))
    return traces


def load_traces(corpus_path: str | Path) -> list[dict[str, Any]]:
    """Read, decode and validate a JSONL corpus."""
    path = Path(corpus_path)
    if not path.exists():
        raise FileNotFoundError(f"Corpus not found: {corpus_path}")
    return decode_traces(path.read_bytes())
