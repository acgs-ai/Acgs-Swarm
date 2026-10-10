#!/usr/bin/env python3
"""Standalone multi-candidate swarm runner (claude CLI backend).

Self-contained: does not depend on the package's ClaudeSWEBenchAgent so it
survives repo-level reverts. Spawns N parallel ``claude -p`` subprocesses
per instance, evaluates each candidate via LocalSWEBenchHarness, picks the
best by (resolved, applied, patch) score.

Metric: the winner is chosen with the local harness verdict itself (oracle
selection, stopping at the first resolved candidate), so ``resolve_rate`` is a
pass@k rate with k = ``--agents``, not a single-sample resolve rate. The same
holds for ``patch_rate`` (patch@k) and ``apply_rate`` (apply@k): they are rates
over the oracle-selected winners. The summary and every row carry
``resolve_metric="pass@k"``, ``patch_metric="patch@k"``,
``apply_metric="apply@k"``, ``selection="oracle"`` and ``k`` so the numbers
cannot be compared against pass@1 runs unlabelled.

Candidate counters: because selection stops at the first resolved candidate,
later candidates are never run through the harness. ``mc_applied_candidates``
and ``mc_resolved_candidates`` (and the per-row ``n_candidates_applied`` /
``n_candidates_resolved``) count over the ``mc_evaluated_candidates``
(``n_candidates_evaluated``) that were actually evaluated; the rest are
reported as ``mc_unevaluated_candidates`` (``n_candidates_unevaluated``).

Usage
-----
    python scripts/run_mc_swarm.py \
        --limit 50 --agents 4 --model sonnet \
        --agent-timeout 600 --harness-timeout 120 \
        --output /tmp/mc.json --predictions-output /tmp/mc.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from constitutional_swarm.swe_bench._diff import extract_unified_diff  # noqa: E402
from constitutional_swarm.swe_bench._messages_agent import (  # noqa: E402
    build_swe_bench_prompt,
)

_log = logging.getLogger(__name__)

# Oracle best-of-k selection over local-harness verdicts == pass@k; the patch
# and apply rates of the selected winners are any-of-k rates as well.
_RESOLVE_METRIC = "pass@k"
_PATCH_METRIC = "patch@k"
_APPLY_METRIC = "apply@k"
_SELECTION = "oracle"

# One shared extractor: a file header is required (hunk-only output is not a
# patch) and any prose before the first header is cut.
_extract_diff = extract_unified_diff

# The one shared SWE-bench prompt (same text the API adapters send).
_build_prompt = build_swe_bench_prompt


@dataclass
class Candidate:
    patch: str = ""
    duration_s: float = 0.0
    error: str | None = None
    raw_length: int = 0
    timed_out: bool = False
    agent_idx: int = -1


def _call_claude(
    claude_bin: str,
    model: str,
    prompt: str,
    timeout_s: float,
    agent_idx: int,
) -> Candidate:
    cmd = [
        claude_bin, "--print", "--model", model,
        "--tools", "",
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--output-format", "text",
    ]
    env = os.environ.copy()
    env["DISABLE_OMC"] = "1"
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True,
            timeout=timeout_s, check=False, env=env,
        )
    except subprocess.TimeoutExpired:
        return Candidate(agent_idx=agent_idx, duration_s=time.perf_counter() - t0,
                         error="timeout", timed_out=True)
    dur = time.perf_counter() - t0
    if proc.returncode != 0:
        return Candidate(agent_idx=agent_idx, duration_s=dur,
                         error=f"exit_{proc.returncode}", raw_length=len(proc.stdout or ""))
    raw = proc.stdout or ""
    patch = _extract_diff(raw)
    return Candidate(agent_idx=agent_idx, patch=patch, duration_s=dur, raw_length=len(raw))


async def _gen_candidates(
    claude_bin: str, model: str, prompt: str, n_agents: int, timeout_s: float,
) -> list[Candidate]:
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _call_claude, claude_bin, model, prompt, timeout_s, i)
        for i in range(n_agents)
    ]
    return await asyncio.gather(*tasks)


def _score(row: dict[str, Any]) -> tuple[int, int, int]:
    return (
        int(bool(row.get("resolved"))),
        int(bool(row.get("applied"))),
        int(bool(row.get("patch_generated"))),
    )


def _evaluate_patch(harness, instance: dict[str, Any], cand: Candidate) -> dict[str, Any]:
    if not cand.patch:
        return {
            "instance_id": instance.get("instance_id"),
            "repo": instance.get("repo"),
            "patch_generated": False,
            "applied": False,
            "resolved": False,
            "fail_to_pass_passed": 0,
            "fail_to_pass_failed": 0,
            "pass_to_pass_passed": 0,
            "pass_to_pass_failed": 0,
            "stage": "patch_generation",
            "error": cand.error or "no_patch",
            "log_tail": "",
            "patch": "",
            "agent_duration_s": cand.duration_s,
            "harness_duration_s": 0.0,
            "duration_s": cand.duration_s,
        }
    hr = harness.evaluate(instance, cand.patch)
    return {
        "instance_id": hr.instance_id,
        "repo": instance.get("repo"),
        "patch_generated": True,
        "applied": hr.applied,
        "resolved": hr.resolved,
        "fail_to_pass_passed": hr.fail_to_pass_passed,
        "fail_to_pass_failed": hr.fail_to_pass_failed,
        "pass_to_pass_passed": hr.pass_to_pass_passed,
        "pass_to_pass_failed": hr.pass_to_pass_failed,
        "stage": hr.stage,
        "error": hr.error,
        "log_tail": hr.log_tail,
        "patch": cand.patch,
        "agent_duration_s": cand.duration_s,
        "harness_duration_s": hr.duration_s,
        "duration_s": cand.duration_s + hr.duration_s,
    }


def _select_winner(
    harness: Any, instance: dict[str, Any], cands: list[Candidate]
) -> dict[str, Any]:
    """Evaluate candidates in order and return the oracle winner's row.

    Stops at the first resolved candidate. The per-candidate counters only
    cover the candidates actually evaluated; ``n_candidates_evaluated`` /
    ``n_candidates_unevaluated`` make that denominator explicit.
    """
    if not cands:
        raise ValueError("at least one candidate is required")
    best_row: dict[str, Any] | None = None
    best_score = (-1, -1, -1)
    winner_idx = -1
    per_scores: list[tuple[int, int, int]] = []
    c_applied = 0
    c_resolved = 0
    for ci, c in enumerate(cands):
        row = _evaluate_patch(harness, instance, c)
        sc = _score(row)
        per_scores.append(sc)
        if row.get("applied"):
            c_applied += 1
        if row.get("resolved"):
            c_resolved += 1
        if sc > best_score:
            best_score = sc
            best_row = row
            winner_idx = ci
        if sc[0] == 1:  # resolved, no need to eval rest
            break
    assert best_row is not None  # every score beats the (-1, -1, -1) sentinel

    n = len(cands)
    best_row["n_candidates"] = n
    best_row["n_valid_candidates"] = sum(1 for c in cands if c.patch)
    best_row["n_candidates_evaluated"] = len(per_scores)
    best_row["n_candidates_unevaluated"] = n - len(per_scores)
    best_row["n_candidates_applied"] = c_applied
    best_row["n_candidates_resolved"] = c_resolved
    best_row["winner_idx"] = winner_idx
    best_row["per_candidate_scores"] = per_scores
    best_row["n_timeouts"] = sum(1 for c in cands if c.timed_out)
    return best_row


def _format_progress(idx: int, total: int, row: dict[str, Any], *, k: int) -> str:
    ft = row["fail_to_pass_passed"] + row["fail_to_pass_failed"]
    pt = row["pass_to_pass_passed"] + row["pass_to_pass_failed"]
    return (
        f"[{idx}/{total}] {row['instance_id']} "
        f"applied@{k}={row['applied']} resolved@{k}={row['resolved']} "
        f"winner={row['winner_idx']}/{k} valid={row['n_valid_candidates']} "
        f"evaluated={row['n_candidates_evaluated']}/{k} "
        f"cand_applied={row['n_candidates_applied']} timeouts={row['n_timeouts']} "
        f"F2P={row['fail_to_pass_passed']}/{ft} "
        f"P2P={row['pass_to_pass_passed']}/{pt} "
        f"dur={row['duration_s']:.1f}s"
    )


def _write_predictions(rows: list[dict[str, Any]], path: Path, model: str) -> None:
    with path.open("w") as f:
        for r in rows:
            if r.get("patch"):
                f.write(json.dumps({
                    "instance_id": r["instance_id"],
                    "model_name_or_path": model,
                    "model_patch": r["patch"],
                }) + "\n")


def _build_summary(
    rows: list[dict[str, Any]],
    *,
    k: int,
    total_cands: int,
    total_valid: int,
    total_applied_cands: int,
    total_resolved_cands: int,
    total_timeouts: int,
) -> dict[str, Any]:
    """Aggregate per-instance winner rows; labels every winner rate as @k."""
    for row in rows:
        row["resolve_metric"] = _RESOLVE_METRIC
        row["patch_metric"] = _PATCH_METRIC
        row["apply_metric"] = _APPLY_METRIC
        row["selection"] = _SELECTION
        row["k"] = k
    total_evaluated = sum(int(r.get("n_candidates_evaluated", 0)) for r in rows)
    n = len(rows)
    applied = sum(1 for r in rows if r["applied"])
    resolved = sum(1 for r in rows if r["resolved"])
    patch_gen = sum(1 for r in rows if r["patch_generated"])
    return {
        "instances": n,
        "patch_generated": patch_gen,
        "applied": applied,
        "resolved": resolved,
        "patch_rate": patch_gen / n if n else 0.0,
        "apply_rate": applied / n if n else 0.0,
        "resolve_rate": resolved / n if n else 0.0,
        "resolve_metric": _RESOLVE_METRIC,
        "patch_metric": _PATCH_METRIC,
        "apply_metric": _APPLY_METRIC,
        "rate_metrics": {
            "patch_rate": _PATCH_METRIC,
            "apply_rate": _APPLY_METRIC,
            "resolve_rate": _RESOLVE_METRIC,
        },
        "selection": _SELECTION,
        "k": k,
        "agents": k,
        "mode": "multi-candidate",
        "mc_total_candidates": total_cands,
        "mc_valid_candidates": total_valid,
        "mc_evaluated_candidates": total_evaluated,
        "mc_unevaluated_candidates": total_cands - total_evaluated,
        "mc_applied_candidates": total_applied_cands,
        "mc_resolved_candidates": total_resolved_cands,
        "mc_timeouts": total_timeouts,
        "rows": rows,
    }


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {n}")
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--jsonl", type=Path, default=None)
    ap.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite")
    ap.add_argument("--split", default="test")
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--agents", type=_positive_int, default=4)
    ap.add_argument("--agent-timeout", type=float, default=600.0)
    ap.add_argument("--harness-timeout", type=float, default=120.0)
    ap.add_argument("--env-timeout", type=float, default=900.0)
    ap.add_argument("--python-version", default=None)
    ap.add_argument("--env-isolation", action="store_true")
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--predictions-output", type=Path, default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    saved = sys.argv[:]
    sys.argv = [saved[0]]
    try:
        from constitutional_swarm.swe_bench.local_harness import (
            LocalSWEBenchHarness,
            load_instances,
        )
    finally:
        sys.argv = saved

    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("error: claude CLI not found on PATH", file=sys.stderr)
        return 1

    instances = load_instances(
        jsonl_path=args.jsonl,
        dataset=args.dataset,
        split=args.split,
        limit=args.limit,
    )
    harness = LocalSWEBenchHarness(
        timeout_s=args.harness_timeout,
        env_isolation=args.env_isolation,
        env_timeout_s=args.env_timeout,
        python_version=args.python_version,
    )

    total_cands = 0
    total_valid = 0
    total_applied_cands = 0
    total_resolved_cands = 0
    total_timeouts = 0

    rows: list[dict[str, Any]] = []
    for idx, inst in enumerate(instances, start=1):
        prompt = _build_prompt(inst)
        cands = asyncio.run(
            _gen_candidates(claude_bin, args.model, prompt, args.agents, args.agent_timeout)
        )
        n = len(cands)
        total_cands += n
        total_valid += sum(1 for c in cands if c.patch)
        total_timeouts += sum(1 for c in cands if c.timed_out)

        best_row = _select_winner(harness, inst, cands)
        total_applied_cands += best_row["n_candidates_applied"]
        total_resolved_cands += best_row["n_candidates_resolved"]
        rows.append(best_row)
        print(_format_progress(idx, len(instances), best_row, k=n), flush=True)

    summary = _build_summary(
        rows,
        k=args.agents,
        total_cands=total_cands,
        total_valid=total_valid,
        total_applied_cands=total_applied_cands,
        total_resolved_cands=total_resolved_cands,
        total_timeouts=total_timeouts,
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=2))
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2))
    if args.predictions_output:
        _write_predictions(rows, args.predictions_output, args.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
