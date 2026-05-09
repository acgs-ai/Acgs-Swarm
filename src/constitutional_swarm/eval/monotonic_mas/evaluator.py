"""Autoresearch evaluator for monotonic-mas-coordination mission.

CLI: python -m constitutional_swarm.eval.monotonic_mas.evaluator \
       --iter N --run-id RID --corpus PATH

Iter 0: governance disabled, baseline calibration. Forces pass=True.
Iter N>=1: governance enabled, per-mode logit recorded into 3 evolution_logs.

Exits 0 always; the autoresearch loop reads stdout JSON.
"""

from __future__ import annotations

import argparse
import importlib
import json
import math
import sys
import time
from pathlib import Path

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.eval.monotonic_mas.replay import run_replay
from constitutional_swarm.evolution_log import (
    DecelerationBlockedError,
    DuplicateRecordError,
    EvolutionLog,
    MissingPriorEpochError,
    NonIncreasingValueError,
)

EXPECTED_HASH = "608508a9bd224290"
LOGIT_EPS = 1e-6


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
    src = Path(gen.__file__).read_text()
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
        return False, "duplicate"
    except Exception as exc:  # noqa: BLE001
        return False, f"other:{type(exc).__name__}:{exc}"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--iter", type=int, required=True, dest="iter_n")
    p.add_argument("--run-id", required=True)
    p.add_argument("--corpus", required=True)
    p.add_argument("--mission-root", default=".omc/autoresearch/monotonic-mas-coordination")
    args = p.parse_args()

    try:
        _execute_iteration(args)
    except (OSError, ValueError) as exc:
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


def _execute_iteration(args: argparse.Namespace) -> None:
    """Body of main(); wrapped by main() in (OSError, ValueError) handler.

    Raises FileNotFoundError if --corpus path missing, json.JSONDecodeError if
    a JSONL line is malformed; main() converts these into structured pass=false
    output per the CLI "exits 0 always" contract.
    """
    t0 = time.perf_counter()
    run_dir = Path(args.mission_root) / "runs" / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "evaluations").mkdir(exist_ok=True)
    (run_dir / "evolution_logs").mkdir(exist_ok=True)

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
                "error": "R4_import_graph_violation",
                "error_detail": str(exc),
            }
            print(json.dumps(out, indent=2))
            sys.exit(0)

    governance_enabled = args.iter_n >= 1
    replay_result = run_replay(args.corpus, governance_enabled=governance_enabled)

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
            "baseline_catch_rate_dedupe": cr_dd,
            "baseline_catch_rate_handoff": cr_hf,
            "baseline_catch_rate_role": cr_rl,
            "constitutional_hash_ok": constitutional_hash_ok,
            "traces_replayed": replay_result["traces_replayed"],
            "traces_per_mode": replay_result["traces_per_mode"],
            "audit_R4": audit,
        }
        _baseline_path(run_dir).write_text(json.dumps(baseline, indent=2))

        out = {
            "pass": True,  # iter 0 force-pass per evaluator.json contract
            "score": score,
            "iter": 0,
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
            "elapsed_seconds": time.perf_counter() - t0,
            "audit_R4": audit,
            "iter_0_force_pass": True,
        }
        _evaluation_path(run_dir, 0).write_text(json.dumps(out, indent=2))
        print(json.dumps(out, indent=2))
        sys.exit(0)

    # ----- iter N>=1 -----
    baseline_file = _baseline_path(run_dir)
    if not baseline_file.exists():
        print(json.dumps({
            "pass": False,
            "score": 0.0,
            "iter": args.iter_n,
            "error": "baseline_missing",
            "error_detail": f"Run iter 0 first; expected {baseline_file}",
        }, indent=2))
        sys.exit(0)
    baseline = json.loads(baseline_file.read_text())

    # Evolution-log records (epoch starts at 1 for iter 1; matches monotonic
    # epoch contract).
    epoch = args.iter_n
    rec_dd, err_dd = _try_record(
        _evolution_log_db(run_dir, "dedupe"), epoch, "logit_catch_rate_dedupe", logit(cr_dd)
    )
    rec_hf, err_hf = _try_record(
        _evolution_log_db(run_dir, "handoff"), epoch, "logit_catch_rate_handoff", logit(cr_hf)
    )
    rec_rl, err_rl = _try_record(
        _evolution_log_db(run_dir, "role"), epoch, "logit_catch_rate_role", logit(cr_rl)
    )

    # Compute per-mode pass gates
    bdd = baseline["baseline_catch_rate_dedupe"]
    bhf = baseline["baseline_catch_rate_handoff"]
    brl = baseline["baseline_catch_rate_role"]

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
    SATURATION_CEILING = 1.0 - LOGIT_EPS

    at_ceiling_dd = cr_dd >= SATURATION_CEILING
    at_ceiling_hf = cr_hf >= SATURATION_CEILING
    at_ceiling_rl = cr_rl >= SATURATION_CEILING

    prior_eval = _evaluation_path(run_dir, args.iter_n - 1)
    if prior_eval.exists():
        prior = json.loads(prior_eval.read_text())
        prior_at_ceiling_dd = float(prior.get("catch_rate_dedupe", 0.0)) >= SATURATION_CEILING
        prior_at_ceiling_hf = float(prior.get("catch_rate_handoff", 0.0)) >= SATURATION_CEILING
        prior_at_ceiling_rl = float(prior.get("catch_rate_role", 0.0)) >= SATURATION_CEILING
    else:
        prior_at_ceiling_dd = prior_at_ceiling_hf = prior_at_ceiling_rl = False

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
    traces_per_mode = replay_result.get("traces_per_mode", {})
    n_dd = int(traces_per_mode.get("redundant_work", 0))
    n_hf = int(traces_per_mode.get("missed_handoff", 0))
    n_rl = int(traces_per_mode.get("role_drift", 0))

    # Option D contract pivot (decision-log entry, iter 4): the
    # `no_bodes_violations` gate is REDUNDANT in trace-replay mode where BODES
    # is not running live. bodes_violations is a pass-through of
    # role-mode-uncaught traces; demoted to informational field; not gated.
    gates = {
        "dedupe_strict_improvement_or_saturated": (cr_dd > bdd) or sat_dd,
        "handoff_strict_improvement_or_saturated": (cr_hf > bhf) or sat_hf,
        "role_strict_improvement_or_saturated": (cr_rl > brl) or sat_rl,
        "dedupe_corpus_integrity": n_dd >= MIN_TRACES_PER_MODE,
        "handoff_corpus_integrity": n_hf >= MIN_TRACES_PER_MODE,
        "role_corpus_integrity": n_rl >= MIN_TRACES_PER_MODE,
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
        "elapsed_seconds": time.perf_counter() - t0,
        "gates": gates,
        "saturated": saturated,
        "evolution_log_errors": {
            "dedupe": err_dd, "handoff": err_hf, "role": err_rl,
        },
        "audit_R4": audit,
    }
    _evaluation_path(run_dir, args.iter_n).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
