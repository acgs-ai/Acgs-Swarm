"""Recorded-vector decision contracts. No backend package or model is imported."""

import json
import math

from .records import (
    ContractError,
    Database,
    FrozenRecord,
    append_only,
    canonical,
    hash_id,
    identity,
    number,
    sha,
)

DecisionError = ContractError
PROTOCOL = "acgs-shadow-decision/v1"
METRICS = ("answer_confidence", "confidence", "x_jev_confidence")
PAYLOAD_KEYS = {
    "type",
    "choice",
    "probabilities",
    *METRICS,
    "act_probability",
    "abstention",
    "abstention_threshold",
    "coverage",
    "calibration",
    "selection_provenance",
}
VALID_BUCKETS = {
    f"{kind}:{size}"
    for kind in ("choice", "score", "noul")
    for size in ("2", "3-5", "6-10", "11+")
}


def parse_payload(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DecisionError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise DecisionError("Nonfinite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (TypeError, json.JSONDecodeError) as exc:
        raise DecisionError("Malformed recorded response") from exc


def normalize_vector(values, option_ids, decimals=4):
    option_ids = tuple(option_ids)
    if len(option_ids) < 2 or len(set(option_ids)) != len(option_ids):
        raise DecisionError("At least two distinct semantic options are required")
    if not isinstance(values, dict) or set(values) != set(option_ids):
        raise DecisionError("The vector must contain exactly the declared options")
    original = {key: number(values[key]) for key in option_ids}
    total = sum(original.values())
    if type(decimals) is not int or not 0 <= decimals <= 12:
        raise DecisionError("Explicit exposed probability precision is required")
    tolerance = len(option_ids) * 0.5 * (10**-decimals) + 1e-8
    if total <= 0 or abs(total - 1) > tolerance:
        raise DecisionError("Probability sum exceeds the known rounding residual")
    return {
        "original": original,
        "normalized": {k: v / total for k, v in original.items()},
        "rounding_decimals": decimals,
        "sum_original": total,
        "rounding_tolerance": tolerance,
        "normalization_applied": total != 1,
    }


def confidence_metrics(vector):
    p = [number(x) for x in vector]
    if len(p) < 2 or not math.isclose(sum(p), 1, abs_tol=1e-7):
        raise DecisionError("A normalized multi-option vector is required")
    k = len(p)
    entropy = -sum(x * math.log(x) for x in p if x > 0)
    return {
        "entropy_concentration_v1": max(0, min(1, 1 - entropy / math.log(k))),
        "normalized_top_mass_v1": (max(p) - 1 / k) / (1 - 1 / k),
        "max_probability_v1": max(p),
    }


def bucket(kind, k):
    if kind not in ("choice", "score", "noul") or type(k) is not int or k < 1:
        raise DecisionError("Unknown question bucket")
    size = "2" if k <= 2 else "3-5" if k <= 5 else "6-10" if k <= 10 else "11+"
    return f"{kind}:{size}"


def check_thresholds(thresholds):
    if not isinstance(thresholds, dict) or not thresholds:
        raise DecisionError("An explicit threshold map is required")
    if any(k not in VALID_BUCKETS | {"default"} for k in thresholds):
        raise DecisionError("Misspelled threshold bucket")
    return {k: number(v) for k, v in thresholds.items()}


def upstream_gate_reference(data, threshold):
    """Source-backed math/reference behavior; not execution of an endpoint."""
    if threshold is None:
        return {"abstention": None, "metric": None, "threshold": None}
    if isinstance(threshold, dict):
        threshold = check_thresholds(threshold).get(
            bucket(data.get("type"), len(data.get("probabilities", {}))),
            threshold.get("default", 0),
        )
    threshold = number(threshold)
    value, metric = None, None
    for name in ("answer_confidence", "confidence"):
        candidate = data.get(name)
        if type(candidate) in (int, float) and math.isfinite(candidate):
            value, metric = candidate, name
            break
    status = (
        "unevaluated"
        if value is None
        else "abstained"
        if value < threshold
        else "passed"
    )
    return {"abstention": status, "metric": metric, "threshold": threshold}


def strict_projection(data):
    return {
        k: data[k]
        for k in ("type", "choice", "probabilities", "confidence")
        if k in data
    }


def normalize_boolean(vector, semantic_order):
    if set(semantic_order) != {"false", "true"} or len(semantic_order) != 2:
        raise DecisionError("Explicit boolean semantic order is required")
    normalized = normalize_vector(
        dict(zip(semantic_order, vector, strict=True)), semantic_order
    )
    return {
        "p_true": normalized["normalized"]["true"],
        "semantic_order": list(semantic_order),
    }


def ordinal_summary(vector, threshold):
    normalized = normalize_vector(
        {str(i): p for i, p in enumerate(vector)},
        tuple(str(i) for i in range(len(vector))),
    )["normalized"]
    if type(threshold) is not int or not 0 <= threshold < len(vector):
        raise DecisionError("Ordinal threshold is invalid")
    p = list(normalized.values())
    return {
        "expected_score": sum(i * x for i, x in enumerate(p)),
        "modal_label": max(range(len(p)), key=p.__getitem__),
        "p_at_or_above": sum(p[threshold:]),
    }


def fixture_coverage(
    req,
    backend="laya",
    state_budget=None,
    instruction_budget=None,
    option_budget=None,
    fixed_schema_fits=True,
    markers_present=True,
):
    """Deterministic UTF-8 serializer/budget fixtures, explicitly NOT token parity."""
    if backend not in ("laya", "clef"):
        raise DecisionError("Unknown serializer fixture")
    state = req["state"]
    text = (
        state
        if isinstance(state, str)
        else json.dumps(
            state,
            ensure_ascii=False,
            sort_keys=backend == "clef",
            separators=(",", ":") if backend == "clef" else (", ", ": "),
        )
    )
    raw = text.encode("utf-8")
    retention = "suffix" if backend == "laya" and isinstance(state, list) else "prefix"
    state_limit = len(raw) if state_budget is None else state_budget
    if type(state_limit) is not int or state_limit < 0:
        raise DecisionError("Invalid fixture state budget")
    retained = (
        raw[-state_limit:]
        if retention == "suffix" and state_limit
        else raw[:state_limit]
    )
    instructions = req["instruction"].encode()
    head = (
        instructions
        if instruction_budget is None
        else instructions[:instruction_budget]
    )
    fragments = []
    complete = True
    for opt in req["options"]:
        whole = f"{opt['id']}: {opt['meaning']}".encode()
        fragment = whole if option_budget is None else whole[:option_budget]
        fragments.append(fragment)
        complete = complete and fragment == whole
    state_complete = retained == raw and len(retained) > 0
    instruction_complete = head == instructions
    status = (
        "complete"
        if all(
            (
                state_complete,
                instruction_complete,
                complete,
                fixed_schema_fits,
                markers_present,
            )
        )
        else "incomplete"
    )
    return {
        "status": status,
        "unit": "utf8_bytes_reference_only",
        "request_digest": sha(canonical(req).encode()),
        "serializer": f"{backend}_reference_v1",
        "state_complete": state_complete,
        "instruction_complete": instruction_complete,
        "criterion_complete": complete,
        "fixed_schema_fits": fixed_schema_fits,
        "markers_present": markers_present,
        "options_distinct": len(set(fragments)),
        "state_bytes": len(raw),
        "retained_state_bytes": len(retained),
        "retention": retention,
        "source_state_sha256": sha(raw),
        "retained_state_sha256": sha(retained),
        "instruction_sha256": sha(instructions),
        "retained_instruction_sha256": sha(head),
        "exact_tokenizer_parity": "untested",
    }


def diagnostic_safe(value):
    if isinstance(value, float) and not math.isfinite(value):
        return {"invalid_numeric": repr(value)}
    if isinstance(value, dict):
        return {k: diagnostic_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [diagnostic_safe(v) for v in value]
    return value


def build_envelope(req, data):
    if (
        set(req)
        != {
            "schema_version",
            "case_id",
            "instruction",
            "state",
            "options",
            "identity",
            "gate",
        }
        or type(req["schema_version"]) is not int
        or req["schema_version"] != 1
    ):
        raise DecisionError("Decision request schema/version mismatch")
    identity(req["case_id"])
    if (
        not isinstance(req["instruction"], str)
        or not req["instruction"].strip()
        or len(req["instruction"].encode()) > 16384
    ):
        raise DecisionError("Instruction must be nonempty bounded UTF-8 text")
    options = req["options"]
    if (
        len(options) != 4
        or any(set(o) != {"id", "role", "meaning"} for o in options)
        or {o["role"] for o in options} != {"docs", "tests", "code", "escalate"}
    ):
        raise DecisionError(
            "Primary schema requires four genuine review/escalation roles"
        )
    for o in options:
        identity(o["id"])
        identity(o["meaning"])
    ids = tuple(o["id"] for o in options)
    if len(set(ids)) != 4:
        raise DecisionError("Duplicate option ID")
    model = req["identity"]
    if set(model) != {
        "model",
        "model_revision",
        "config_digest",
        "schema_digest",
        "adapter_digest",
        "weights_digest",
        "tokenizer_digest",
    }:
        raise DecisionError(
            "Complete explicit identity fields required, including unknown digests"
        )
    identity(model["model"])
    identity(model["model_revision"])
    for name in ("config_digest", "schema_digest", "adapter_digest"):
        hash_id(model[name])
    for name in ("weights_digest", "tokenizer_digest"):
        if model[name] is not None:
            hash_id(model[name])
    if not isinstance(data, dict) or set(data) - PAYLOAD_KEYS:
        raise DecisionError(
            "Unknown/authority fields are forbidden in shadow responses"
        )
    errors = []
    try:
        vector = normalize_vector(data.get("probabilities"), ids)
    except DecisionError as exc:
        vector = None
        errors.append(str(exc))
    proposal = data.get("choice")
    if data.get("type") != "choice" or proposal not in ids:
        errors.append("invalid_type_or_out_of_pool_proposal")
    derived = confidence_metrics(list(vector["normalized"].values())) if vector else {}
    argmax = max(ids, key=lambda k: vector["normalized"][k]) if vector else None
    if argmax != proposal:
        errors.append("declared_choice_disagrees_with_argmax")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        coverage = {"status": "unknown", "exact_tokenizer_parity": "untested"}
    else:
        serializer = coverage.get("serializer")
        backend = {"laya_reference_v1": "laya", "clef_reference_v1": "clef"}.get(
            serializer
        )
        # Only a fully recomputable synthetic reference is consumable here.
        # Backend/tokenizer proofs require a separately qualified adapter.
        if backend is None or coverage != fixture_coverage(req, backend=backend):
            errors.append("incomplete_or_unbound_coverage")
    if coverage.get("status") != "complete":
        errors.append("unknown_or_incomplete_coverage")
    gate = req["gate"]
    status, metric, threshold = "not_configured", None, None
    if gate is not None:
        if (
            not isinstance(gate, dict)
            or set(gate) != {"metric", "thresholds", "calibrated"}
            or type(gate["calibrated"]) is not bool
        ):
            raise DecisionError("Malformed consumer gating policy")
        metric = gate["metric"]
        if metric not in METRICS:
            raise DecisionError("Metric identity must be explicit")
        thresholds = check_thresholds(gate["thresholds"])
        threshold = thresholds.get(bucket("choice", len(ids)))
        if threshold is None:
            status = "unevaluated"
            errors.append("consumer_bucket_uncovered")
        elif metric not in data:
            status = "unevaluated"
            errors.append("missing_required_metric_no_fallback")
        else:
            try:
                value = number(data[metric])
                status = "abstained" if value < threshold else "passed"
            except DecisionError:
                status = "invalid"
                errors.append("invalid_reported_metric")
        if gate["calibrated"]:
            calibration = data.get("calibration", {})
            if (
                not isinstance(calibration, dict)
                or calibration.get("identity") != model
                or not calibration.get("binning_digest")
            ):
                status = "unevaluated"
                errors.append("unverifiable_calibration_identity")
            else:
                hash_id(calibration["binning_digest"])
                number(calibration.get("raw_temperature"), 0, 100)
                number(calibration.get("applied_temperature"), 0, 100)
    if status in ("abstained", "unevaluated", "invalid"):
        errors.append("consumer_gate_unavailable")
    if data.get("abstention") in ("abstained", "unevaluated"):
        errors.append("backend_annotation_unavailable")
    if data.get("selection_provenance") not in (None, "full_option_pool"):
        errors.append("tournament_or_unknown_candidate_selection")
    escalation = next(o["id"] for o in options if o["role"] == "escalate")
    body = {
        "protocol": PROTOCOL,
        "case_id": req["case_id"],
        "request": req,
        "request_digest": sha(canonical(req).encode()),
        "identity": model,
        "proposal": {
            "declared": proposal,
            "argmax": argmax,
            "tie_rule": "schema_order_v1",
        },
        "vector": vector,
        "reported_metrics": {k: diagnostic_safe(data.get(k)) for k in METRICS},
        "derived_metrics": derived,
        "gate": {"status": status, "metric": metric, "threshold": threshold},
        "coverage": coverage,
        "calibration": data.get("calibration"),
        "raw_payload": diagnostic_safe(data),
        "consumer": {
            "status": "unavailable" if errors else "available_recorded_fixture",
            "choice": escalation if errors else proposal,
            "reasons": sorted(set(errors)),
        },
        "authority": "not_evaluated",
        "qualification": {
            "live_endpoint": "unrun",
            "exact_tokenizer_boundary_parity": "untested",
            "real_calibration": "unqualified",
        },
    }
    return FrozenRecord.seal(diagnostic_safe(body))


def policy_oracle_reference(state):
    """Pinned clean-evidence reference, not a new execution/authority gate."""
    risk = state.get("risk_score")
    try:
        numeric = float(risk) if type(risk) in (int, float) else math.nan
    except OverflowError:
        numeric = math.nan
    return (
        state.get("governed") is True
        and type(state.get("violations")) in (list, tuple)
        and len(state["violations"]) == 0
        and math.isfinite(numeric)
        and 0 <= numeric < 0.3
    )


class DecisionAttempts(Database):
    def __init__(self, path):
        super().__init__(
            path,
            "CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY,case_id TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);"
            + append_only("attempts"),
        )

    def append(self, attempt_id, case_id, status, raw_response, retry_of=None):
        identity(attempt_id)
        identity(case_id)
        if status not in ("empty", "timeout", "refusal", "malformed", "success"):
            raise DecisionError("Unknown recorded attempt status")
        record = {
            "attempt_id": attempt_id,
            "case_id": case_id,
            "status": status,
            "raw_response": raw_response,
            "retry_of": retry_of,
            "model_call_executed": False,
            "mode": "recorded_fixture",
        }
        body = canonical(record)
        digest = sha(body.encode())
        with self.connect(True) as db:
            old = db.execute(
                "SELECT body FROM attempts WHERE id=?", (attempt_id,)
            ).fetchone()
            if old:
                if old[0] != body:
                    raise DecisionError("Attempt idempotency conflict")
                return
            if retry_of:
                parent = db.execute(
                    "SELECT case_id FROM attempts WHERE id=?", (retry_of,)
                ).fetchone()
                if not parent or parent[0] != case_id:
                    raise DecisionError("Retry must link to the same case")
            db.execute(
                "INSERT INTO attempts VALUES(?,?,?,?)",
                (attempt_id, case_id, body, digest),
            )

    def records(self, case_id):
        with self.connect() as db:
            rows = db.execute(
                "SELECT body,digest FROM attempts WHERE case_id=? ORDER BY rowid",
                (case_id,),
            ).fetchall()
            result = []
            for r in rows:
                if sha(r["body"].encode()) != r["digest"]:
                    raise DecisionError("Attempt record checksum mismatch")
                result.append(json.loads(r["body"]))
            return result
