"""Autoresearch evaluator for monotonic-mas-coordination mission.

CLI: python -m constitutional_swarm.eval.monotonic_mas.evaluator \
       --iter N --run-id RID --corpus PATH

Iter 0: governance disabled, baseline calibration. Forces pass=True.
Iter N>=1: governance enabled, per-mode logit recorded into 3 evolution_logs.

Exits 0 always; the autoresearch loop reads stdout JSON.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib
import json
import math
import os
import sqlite3
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.eval.monotonic_mas.replay import Detector, run_replay
from constitutional_swarm.eval.monotonic_mas.trace_schema import decode_traces
from constitutional_swarm.evolution_log import (
    DecelerationBlockedError,
    DuplicateRecordError,
    EvolutionLog,
    MissingPriorEpochError,
    NonIncreasingValueError,
)

EXPECTED_HASH = "608508a9bd224290"
LOGIT_EPS = 1e-6
EVALUATION_VERSION = 3
PRODUCTION_EVALUATION_VARIANT = "production-v1"


def logit(rate: float) -> float:
    """Unbounded transform: -log(1 - clamp(rate, 0, 1 - eps)).

    Strictly increasing on [0, 1); maps 0 -> 0, 0.5 -> 0.693, 0.95 -> 2.996,
    1-eps -> 13.82. Used so evolution_log's strict-acceleration invariant is
    satisfiable on a metric whose raw form is bounded in [0,1].
    """
    r = max(0.0, min(rate, 1.0 - LOGIT_EPS))
    return -math.log(1.0 - r)


def import_graph_audit() -> dict:
    """R4: confirm corpus generator does not import constitutional_swarm.

    Re-imports the generator and inspects its module __dict__ for any name
    starting with 'constitutional_swarm'. Raises if any are found.
    """
    sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root
    try:
        gen = importlib.import_module("tests.fixtures._generators.mast_synth")
    except ImportError:
        # Generator may not be on sys.path for some invocations; skip gracefully
        return {"audited": False, "reason": "generator not importable from this context"}

    leaked = [name for name in dir(gen) if "constitutional_swarm" in name.lower()]
    # also look at the source for any 'import constitutional_swarm' line
    gen_file = gen.__file__
    if gen_file is None:
        return {"audited": False, "reason": "generator module exposes no source file"}
    src = Path(gen_file).read_text()
    has_import_line = any(
        line.strip().startswith(("import constitutional_swarm", "from constitutional_swarm"))
        for line in src.splitlines()
    )
    if leaked or has_import_line:
        raise RuntimeError(
            f"R4 violation: corpus generator leaks constitutional_swarm "
            f"(leaked symbols={leaked}, has_import_line={has_import_line})"
        )
    return {"audited": True, "leaked": []}


def _baseline_path(run_dir: Path) -> Path:
    return run_dir / "baseline.json"


def _evaluation_path(run_dir: Path, iter_n: int) -> Path:
    return run_dir / "evaluations" / f"iteration-{iter_n:04d}.json"


def _evolution_log_db(run_dir: Path, mode: str) -> Path:
    return run_dir / "evolution_logs" / f"{mode}.sqlite"


def _request_path(run_dir: Path, iter_n: int) -> Path:
    return run_dir / "evaluations" / f"iteration-{iter_n:04d}.request.json"


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content)
    os.replace(temporary, path)


def _publish(path: Path, result: dict[str, Any]) -> None:
    published = dict(result)
    published["result_digest"] = _result_digest(published)
    content = json.dumps(published, indent=2) + "\n"
    _atomic_write(path, content)
    sys.stdout.write(content)


def _result_digest(result: dict[str, Any]) -> str:
    payload = {key: value for key, value in result.items() if key != "result_digest"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _load_object(
    path: Path, *, required: dict[str, type | tuple[type, ...]]
) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"persisted input {path} must contain a JSON object")
    for field, expected in required.items():
        if field not in value:
            raise ValueError(f"persisted input {path} is missing field {field}")
        field_value = value[field]
        expects_number = expected in {int, float} or (
            isinstance(expected, tuple) and any(item in {int, float} for item in expected)
        )
        invalid_number = expects_number and (
            isinstance(field_value, bool)
            or not isinstance(field_value, (int, float))
            or not math.isfinite(float(field_value))
        )
        if not isinstance(field_value, expected) or invalid_number:
            expected_name = (
                " or ".join(item.__name__ for item in expected)
                if isinstance(expected, tuple)
                else expected.__name__
            )
            raise ValueError(
                f"persisted input {path} field {field} must be {expected_name}"
            )
    return value


def _validate_mapping(
    path: Path,
    value: dict[str, Any],
    field: str,
    required: Mapping[str, type | tuple[type, ...]],
) -> None:
    mapping = value[field]
    if not isinstance(mapping, dict):
        raise ValueError(f"persisted input {path} field {field} must be dict")
    for nested_field, expected in required.items():
        qualified = f"{field}.{nested_field}"
        if nested_field not in mapping:
            raise ValueError(f"persisted input {path} is missing field {qualified}")
        nested_value = mapping[nested_field]
        invalid_int = expected is int and (
            isinstance(nested_value, bool)
            or not isinstance(nested_value, int)
            or nested_value < 0
        )
        if not isinstance(nested_value, expected) or invalid_int:
            expected_name = (
                " or ".join(item.__name__ for item in expected)
                if isinstance(expected, tuple)
                else expected.__name__
            )
            raise ValueError(
                f"persisted input {path} field {qualified} must be {expected_name}"
            )


def _validate_result(
    path: Path, *, expected_iter: int, expected_request_digest: str
) -> dict[str, Any]:
    common: dict[str, type | tuple[type, ...]] = {
        "pass": bool,
        "score": (int, float),
        "iter": int,
        "request_digest": str,
        "result_digest": str,
    }
    value = _load_object(path, required=common)
    if value["iter"] != expected_iter:
        raise ValueError(
            f"persisted result {path} has iteration {value['iter']}; "
            f"expected iteration {expected_iter}"
        )
    if value["request_digest"] != expected_request_digest:
        raise ValueError(f"persisted result {path} does not match request identity")
    if value["result_digest"] != _result_digest(value):
        raise ValueError(f"persisted result {path} failed result digest validation")

    if "error" in value:
        _load_object(
            path,
            required={**common, "error": str, "error_detail": str},
        )
        if value["pass"] is not False:
            raise ValueError(f"persisted failure result {path} must have pass=false")
        return value

    complete: dict[str, type | tuple[type, ...]] = {
        **common,
        "catch_rate_dedupe": (int, float),
        "catch_rate_handoff": (int, float),
        "catch_rate_role": (int, float),
        "logit_dedupe": (int, float),
        "logit_handoff": (int, float),
        "logit_role": (int, float),
        "baseline_catch_rate_dedupe": (int, float),
        "baseline_catch_rate_handoff": (int, float),
        "baseline_catch_rate_role": (int, float),
        "monotonic_accepted_dedupe": bool,
        "monotonic_accepted_handoff": bool,
        "monotonic_accepted_role": bool,
        "constitutional_hash_ok": bool,
        "bodes_violations": int,
        "traces_replayed": int,
        "traces_per_mode": dict,
        "total_traces_per_mode": dict,
        "unavailable_traces_per_mode": dict,
        "complete_traces_per_mode": dict,
        "semantic_status_counts": dict,
        "semantic_unavailable_reasons": list,
        "elapsed_seconds": (int, float),
        "audit_R4": dict,
    }
    _load_object(path, required=complete)
    mode_count_fields = {
        "redundant_work": int,
        "missed_handoff": int,
        "role_drift": int,
    }
    for field in (
        "traces_per_mode",
        "total_traces_per_mode",
        "unavailable_traces_per_mode",
    ):
        _validate_mapping(path, value, field, mode_count_fields)
    _validate_mapping(
        path,
        value,
        "complete_traces_per_mode",
        {mode: bool for mode in mode_count_fields},
    )

    if expected_iter == 0:
        _load_object(path, required={"iter_0_force_pass": bool})
        if value["iter_0_force_pass"] is not True or value["pass"] is not True:
            raise ValueError(f"persisted iter 0 result {path} must be force-pass")
        return value

    gate_fields = {
        "dedupe_strict_improvement_or_saturated": bool,
        "handoff_strict_improvement_or_saturated": bool,
        "role_strict_improvement_or_saturated": bool,
        "dedupe_corpus_integrity": bool,
        "handoff_corpus_integrity": bool,
        "role_corpus_integrity": bool,
        "monotonic_dedupe": bool,
        "monotonic_handoff": bool,
        "monotonic_role": bool,
        "constitutional_hash_ok": bool,
    }
    _load_object(
        path,
        required={"gates": dict, "saturated": dict, "evolution_log_errors": dict},
    )
    _validate_mapping(path, value, "gates", gate_fields)
    _validate_mapping(
        path,
        value,
        "saturated",
        {"dedupe": bool, "handoff": bool, "role": bool},
    )
    _validate_mapping(
        path,
        value,
        "evolution_log_errors",
        {
            "dedupe": (str, type(None)),
            "handoff": (str, type(None)),
            "role": (str, type(None)),
        },
    )
    if value["pass"] != all(value["gates"][field] for field in gate_fields):
        raise ValueError(f"persisted result {path} pass does not match its gates")
    return value


def _iteration_request(
    args: argparse.Namespace,
    corpus_bytes: bytes,
    run_dir: Path,
    *,
    evaluation_variant: str = PRODUCTION_EVALUATION_VARIANT,
) -> dict[str, Any]:
    baseline_path = _baseline_path(run_dir)
    prior_path = _evaluation_path(run_dir, args.iter_n - 1)
    request = {
        "evaluation_version": EVALUATION_VERSION,
        "evaluation_variant": evaluation_variant,
        "iter": args.iter_n,
        "run_id": args.run_id,
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "baseline_sha256": (
            hashlib.sha256(baseline_path.read_bytes()).hexdigest()
            if args.iter_n >= 1 and baseline_path.exists()
            else None
        ),
        "prior_evaluation_sha256": (
            hashlib.sha256(prior_path.read_bytes()).hexdigest()
            if args.iter_n >= 1 and prior_path.exists()
            else None
        ),
    }
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    request["request_digest"] = hashlib.sha256(canonical).hexdigest()
    return request


def _validate_history_variant(
    run_dir: Path, iter_n: int, evaluation_variant: str
) -> None:
    """Require every persisted dependency to use one evaluation variant."""
    if iter_n < 1:
        return
    history_iterations = {0, iter_n - 1}
    for history_iter in sorted(history_iterations):
        result_path = (
            _baseline_path(run_dir)
            if history_iter == 0
            else _evaluation_path(run_dir, history_iter)
        )
        if not result_path.exists():
            continue
        request_path = _request_path(run_dir, history_iter)
        if not request_path.exists():
            raise ValueError(
                f"persisted history {result_path} has no request identity"
            )
        request = _load_object(
            request_path,
            required={
                "iter": int,
                "evaluation_variant": str,
                "request_digest": str,
            },
        )
        if request["iter"] != history_iter:
            raise ValueError(
                f"persisted request {request_path} does not match expected iteration "
                f"{history_iter}"
            )
        if request["evaluation_variant"] != evaluation_variant:
            raise ValueError(
                f"evaluation variant mismatch: iteration {history_iter} used "
                f"{request['evaluation_variant']!r}, current request uses "
                f"{evaluation_variant!r}"
            )


def _try_record(db_path: Path, epoch: int, metric: str, value: float) -> tuple[bool, str | None]:
    """Open EvolutionLog, attempt record, return (accepted, error_kind)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with EvolutionLog(str(db_path)) as log:
            log.record(epoch=epoch, metric=metric, value=value)
        return True, None
    except MissingPriorEpochError:
        return False, "missing_prior_epoch"
    except NonIncreasingValueError:
        return False, "non_increasing_value"
    except DecelerationBlockedError:
        return False, "deceleration_blocked"
    except DuplicateRecordError:
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
                (epoch, metric),
            ).fetchone()
        if row is not None and float(row[0]) == value:
            return True, "reconciled_duplicate"
        return False, "duplicate_value_conflict"
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"invalid evolution log {db_path}: {exc}") from exc


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--iter", type=int, required=True, dest="iter_n")
    p.add_argument("--run-id", required=True)
    p.add_argument("--corpus", required=True)
    p.add_argument("--mission-root", default=".omc/autoresearch/monotonic-mas-coordination")
    args = p.parse_args()

    try:
        _execute_iteration(args)
    except (OSError, ValueError, RecursionError) as exc:
        out = {
            "pass": False,
            "score": 0.0,
            "iter": args.iter_n,
            "error": "input_error",
            "error_kind": type(exc).__name__,
            "error_detail": str(exc),
        }
        print(json.dumps(out, indent=2))
        sys.exit(0)


def _execute_iteration(
    args: argparse.Namespace,
    *,
    detectors: Mapping[str, Detector] | None = None,
    evaluation_variant: str = PRODUCTION_EVALUATION_VARIANT,
) -> None:
    """Validate, identify and serialize one idempotent iteration request."""
    if detectors is not None and evaluation_variant == PRODUCTION_EVALUATION_VARIANT:
        raise ValueError(
            "injected detectors require a stable non-production evaluation_variant"
        )
    if not evaluation_variant.strip():
        raise ValueError("evaluation_variant must not be empty")
    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        raise FileNotFoundError(f"Corpus not found: {args.corpus}")
    corpus_bytes = corpus_path.read_bytes()
    traces = decode_traces(corpus_bytes)
    run_dir = Path(args.mission_root) / "runs" / args.run_id
    evaluations_dir = run_dir / "evaluations"
    evaluations_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "evolution_logs").mkdir(exist_ok=True)

    lock_path = run_dir / ".evaluation.lock"
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        _validate_history_variant(run_dir, args.iter_n, evaluation_variant)
        request = _iteration_request(
            args,
            corpus_bytes,
            run_dir,
            evaluation_variant=evaluation_variant,
        )
        request_path = _request_path(run_dir, args.iter_n)
        result_path = _evaluation_path(run_dir, args.iter_n)
        if result_path.exists() and not request_path.exists():
            raise ValueError(
                f"persisted result {result_path} has no request identity; refusing overwrite"
            )
        if request_path.exists():
            persisted_request = _load_object(
                request_path,
                required={
                    "evaluation_version": int,
                    "evaluation_variant": str,
                    "iter": int,
                    "run_id": str,
                    "corpus_sha256": str,
                    "constitutional_hash": str,
                    "baseline_sha256": (str, type(None)),
                    "prior_evaluation_sha256": (str, type(None)),
                    "request_digest": str,
                },
            )
            if persisted_request != request:
                raise ValueError(
                    f"iteration request conflict for run {args.run_id!r} iter {args.iter_n}"
                )
            if result_path.exists():
                _validate_result(
                    result_path,
                    expected_iter=args.iter_n,
                    expected_request_digest=request["request_digest"],
                )
                sys.stdout.write(result_path.read_text())
                return
        else:
            _atomic_write(request_path, json.dumps(request, indent=2) + "\n")

        _execute_iteration_locked(
            args,
            request_digest=request["request_digest"],
            traces=traces,
            detectors=detectors,
        )


def _execute_iteration_locked(
    args: argparse.Namespace,
    *,
    request_digest: str,
    traces: list[dict[str, Any]],
    detectors: Mapping[str, Detector] | None,
) -> None:
    """Body of main(); wrapped by main() in (OSError, ValueError) handler.

    Raises FileNotFoundError if --corpus path missing, json.JSONDecodeError if
    a JSONL line is malformed; main() converts these into structured pass=false
    output per the CLI "exits 0 always" contract.
    """
    t0 = time.perf_counter()
    run_dir = Path(args.mission_root) / "runs" / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # R4 import-graph audit (first iteration only)
    audit = {"audited": False, "skipped": True}
    if args.iter_n <= 1:
        try:
            audit = import_graph_audit()
        except RuntimeError as exc:
            # Hard fail — emit pass=false with clear error
            out = {
                "pass": False,
                "score": 0.0,
                "iter": args.iter_n,
                "request_digest": request_digest,
                "error": "R4_import_graph_violation",
                "error_detail": str(exc),
            }
            _publish(_evaluation_path(run_dir, args.iter_n), out)
            return

    governance_enabled = args.iter_n >= 1
    replay_result = run_replay(
        args.corpus,
        governance_enabled=governance_enabled,
        traces=traces,
        detectors=detectors,
    )

    cr_dd = replay_result["catch_rate_dedupe"]
    cr_hf = replay_result["catch_rate_handoff"]
    cr_rl = replay_result["catch_rate_role"]
    bodes = replay_result["bodes_violations_proxy"] if governance_enabled else 0
    # When governance is disabled (iter 0), bodes_violations isn't a meaningful
    # gate — calibration only. Force to 0 to satisfy schema.

    constitutional_hash_ok = CONSTITUTIONAL_HASH == EXPECTED_HASH
    score = (cr_dd + cr_hf + cr_rl) / 3.0

    # ----- iter 0 = baseline calibration -----
    if args.iter_n == 0:
        baseline = {
            "iter": 0,
            "request_digest": request_digest,
            "baseline_catch_rate_dedupe": cr_dd,
            "baseline_catch_rate_handoff": cr_hf,
            "baseline_catch_rate_role": cr_rl,
            "constitutional_hash_ok": constitutional_hash_ok,
            "traces_replayed": replay_result["traces_replayed"],
            "traces_per_mode": replay_result["traces_per_mode"],
            "total_traces_per_mode": replay_result["total_traces_per_mode"],
            "unavailable_traces_per_mode": replay_result["unavailable_traces_per_mode"],
            "complete_traces_per_mode": replay_result["complete_traces_per_mode"],
            "semantic_status_counts": replay_result["semantic_status_counts"],
            "semantic_unavailable_reasons": replay_result["semantic_unavailable_reasons"],
            "audit_R4": audit,
        }
        _atomic_write(_baseline_path(run_dir), json.dumps(baseline, indent=2) + "\n")

        out = {
            "pass": True,  # iter 0 force-pass per evaluator.json contract
            "score": score,
            "iter": 0,
            "request_digest": request_digest,
            "catch_rate_dedupe": cr_dd,
            "catch_rate_handoff": cr_hf,
            "catch_rate_role": cr_rl,
            "logit_dedupe": logit(cr_dd),
            "logit_handoff": logit(cr_hf),
            "logit_role": logit(cr_rl),
            "baseline_catch_rate_dedupe": cr_dd,
            "baseline_catch_rate_handoff": cr_hf,
            "baseline_catch_rate_role": cr_rl,
            "monotonic_accepted_dedupe": True,
            "monotonic_accepted_handoff": True,
            "monotonic_accepted_role": True,
            "constitutional_hash_ok": constitutional_hash_ok,
            "bodes_violations": 0,
            "traces_replayed": replay_result["traces_replayed"],
            "traces_per_mode": replay_result["traces_per_mode"],
            "total_traces_per_mode": replay_result["total_traces_per_mode"],
            "unavailable_traces_per_mode": replay_result["unavailable_traces_per_mode"],
            "complete_traces_per_mode": replay_result["complete_traces_per_mode"],
            "semantic_status_counts": replay_result["semantic_status_counts"],
            "semantic_unavailable_reasons": replay_result["semantic_unavailable_reasons"],
            "elapsed_seconds": time.perf_counter() - t0,
            "audit_R4": audit,
            "iter_0_force_pass": True,
        }
        _publish(_evaluation_path(run_dir, 0), out)
        return

    # ----- iter N>=1 -----
    baseline_file = _baseline_path(run_dir)
    if not baseline_file.exists():
        out = {
            "pass": False,
            "score": 0.0,
            "iter": args.iter_n,
            "request_digest": request_digest,
            "error": "baseline_missing",
            "error_detail": f"Run iter 0 first; expected {baseline_file}",
        }
        _publish(_evaluation_path(run_dir, args.iter_n), out)
        return
    baseline = _load_object(
        baseline_file,
        required={
            "iter": int,
            "baseline_catch_rate_dedupe": (int, float),
            "baseline_catch_rate_handoff": (int, float),
            "baseline_catch_rate_role": (int, float),
        },
    )

    bdd = baseline["baseline_catch_rate_dedupe"]
    bhf = baseline["baseline_catch_rate_handoff"]
    brl = baseline["baseline_catch_rate_role"]
    SATURATION_CEILING = 1.0 - LOGIT_EPS

    prior_eval = _evaluation_path(run_dir, args.iter_n - 1)
    if prior_eval.exists():
        prior_request_path = _request_path(run_dir, args.iter_n - 1)
        prior_request = _load_object(
            prior_request_path,
            required={"iter": int, "request_digest": str},
        )
        if prior_request["iter"] != args.iter_n - 1:
            raise ValueError(
                f"persisted request {prior_request_path} does not match expected iteration "
                f"{args.iter_n - 1}"
            )
        prior = _validate_result(
            prior_eval,
            expected_iter=args.iter_n - 1,
            expected_request_digest=prior_request["request_digest"],
        )
        if "error" in prior:
            prior_at_ceiling_dd = prior_at_ceiling_hf = prior_at_ceiling_rl = False
        else:
            prior_passed = prior["pass"] is True
            prior_at_ceiling_dd = (
                prior_passed and float(prior["catch_rate_dedupe"]) >= SATURATION_CEILING
            )
            prior_at_ceiling_hf = (
                prior_passed and float(prior["catch_rate_handoff"]) >= SATURATION_CEILING
            )
            prior_at_ceiling_rl = (
                prior_passed and float(prior["catch_rate_role"]) >= SATURATION_CEILING
            )
    else:
        prior_at_ceiling_dd = prior_at_ceiling_hf = prior_at_ceiling_rl = False

    traces_per_mode = replay_result["traces_per_mode"]
    complete_per_mode = replay_result["complete_traces_per_mode"]
    n_dd = int(traces_per_mode.get("redundant_work", 0))
    n_hf = int(traces_per_mode.get("missed_handoff", 0))
    n_rl = int(traces_per_mode.get("role_drift", 0))

    # Evolution-log records (epoch starts at 1 for iter 1). Unavailable
    # channels have no measurement and therefore must not create a zero record.
    epoch = args.iter_n
    rec_dd, err_dd = (
        _try_record(
            _evolution_log_db(run_dir, "dedupe"),
            epoch,
            "logit_catch_rate_dedupe",
            logit(cr_dd),
        )
        if complete_per_mode["redundant_work"]
        else (False, "unavailable")
    )
    rec_hf, err_hf = (
        _try_record(
            _evolution_log_db(run_dir, "handoff"),
            epoch,
            "logit_catch_rate_handoff",
            logit(cr_hf),
        )
        if complete_per_mode["missed_handoff"]
        else (False, "unavailable")
    )
    rec_rl, err_rl = (
        _try_record(
            _evolution_log_db(run_dir, "role"), epoch, "logit_catch_rate_role", logit(cr_rl)
        )
        if complete_per_mode["role_drift"]
        else (False, "unavailable")
    )

    # ITER 2 FIX (revised 2026-05-09 post-reviewer A+B): per-mode saturation
    # handling. Original threshold 0.999 + raw saturation override let a flat
    # sub-ceiling plateau pass even when evolution_log rejected the value as
    # non-increasing. Tightened to two conjoint requirements:
    #   (A) ceiling:     cr_m >= 1.0 - LOGIT_EPS (matches logit() cap; the
    #                    point past which the logit transform is constant and
    #                    no further improvement is measurable)
    #   (B) persistence: prior iter's cr_m was also at ceiling (terminal-
    #                    success must be held, not just touched)
    # Per the mission contract (evaluator.json stop_conditions.logit_inflection),
    # saturation is terminal-success per mode -- but only after the metric has
    # both reached AND held the ceiling.
    at_ceiling_dd = cr_dd >= SATURATION_CEILING
    at_ceiling_hf = cr_hf >= SATURATION_CEILING
    at_ceiling_rl = cr_rl >= SATURATION_CEILING

    sat_dd = at_ceiling_dd and prior_at_ceiling_dd
    sat_hf = at_ceiling_hf and prior_at_ceiling_hf
    sat_rl = at_ceiling_rl and prior_at_ceiling_rl
    saturated = {"dedupe": sat_dd, "handoff": sat_hf, "role": sat_rl}

    mono_dd = rec_dd or sat_dd
    mono_hf = rec_hf or sat_hf
    mono_rl = rec_rl or sat_rl

    # POST-HOC GATE FIX (CCG synthesis after iter 4 adversarial review):
    # The original `cr_m >= baseline_m` gate has a logical hole: with
    # baseline=0 and cr_m=0, the predicate is True, so an ineffective
    # detector that catches nothing falsely passes. Replace with strict
    # improvement OR saturation, plus a corpus-integrity check that prevents
    # missing-mode or empty-corpus from satisfying the gate vacuously.
    MIN_TRACES_PER_MODE = 1  # missions making statistical claims should override
    # Option D contract pivot (decision-log entry, iter 4): the
    # `no_bodes_violations` gate is REDUNDANT in trace-replay mode where BODES
    # is not running live. bodes_violations is a pass-through of
    # role-mode-uncaught traces; demoted to informational field; not gated.
    gates = {
        "dedupe_strict_improvement_or_saturated": (cr_dd > bdd) or sat_dd,
        "handoff_strict_improvement_or_saturated": (cr_hf > bhf) or sat_hf,
        "role_strict_improvement_or_saturated": (cr_rl > brl) or sat_rl,
        "dedupe_corpus_integrity": (
            n_dd >= MIN_TRACES_PER_MODE and complete_per_mode["redundant_work"]
        ),
        "handoff_corpus_integrity": (
            n_hf >= MIN_TRACES_PER_MODE and complete_per_mode["missed_handoff"]
        ),
        "role_corpus_integrity": (
            n_rl >= MIN_TRACES_PER_MODE and complete_per_mode["role_drift"]
        ),
        "monotonic_dedupe": mono_dd,
        "monotonic_handoff": mono_hf,
        "monotonic_role": mono_rl,
        "constitutional_hash_ok": constitutional_hash_ok,
    }
    pass_all = all(gates.values())

    out = {
        "pass": pass_all,
        "score": score,
        "iter": args.iter_n,
        "request_digest": request_digest,
        "catch_rate_dedupe": cr_dd,
        "catch_rate_handoff": cr_hf,
        "catch_rate_role": cr_rl,
        "logit_dedupe": logit(cr_dd),
        "logit_handoff": logit(cr_hf),
        "logit_role": logit(cr_rl),
        "baseline_catch_rate_dedupe": bdd,
        "baseline_catch_rate_handoff": bhf,
        "baseline_catch_rate_role": brl,
        "monotonic_accepted_dedupe": rec_dd,
        "monotonic_accepted_handoff": rec_hf,
        "monotonic_accepted_role": rec_rl,
        "constitutional_hash_ok": constitutional_hash_ok,
        "bodes_violations": bodes,
        "traces_replayed": replay_result["traces_replayed"],
        "traces_per_mode": replay_result["traces_per_mode"],
        "total_traces_per_mode": replay_result["total_traces_per_mode"],
        "unavailable_traces_per_mode": replay_result["unavailable_traces_per_mode"],
        "complete_traces_per_mode": replay_result["complete_traces_per_mode"],
        "semantic_status_counts": replay_result["semantic_status_counts"],
        "semantic_unavailable_reasons": replay_result["semantic_unavailable_reasons"],
        "elapsed_seconds": time.perf_counter() - t0,
        "gates": gates,
        "saturated": saturated,
        "evolution_log_errors": {
            "dedupe": err_dd, "handoff": err_hf, "role": err_rl,
        },
        "audit_R4": audit,
    }
    _publish(_evaluation_path(run_dir, args.iter_n), out)


if __name__ == "__main__":
    main()
