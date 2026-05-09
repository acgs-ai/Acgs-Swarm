"""One-by-one SWE-bench Lite runner with append-only per-instance log.

Designed for incremental, manually-paced exploration:

  python -m constitutional_swarm.swe_bench.run_one_by_one \\
      --run-id smoke-2026-05-09 --model claude-haiku-4-5 --next

Each invocation:
  1. Loads the next un-attempted instance from SWE-bench Lite (or the one
     specified via ``--instance-id``).
  2. Runs ``ClaudeOAuthSWEBenchAgent`` on it (uses the user's Claude Code
     OAuth session — no API key needed; never hands the token to anything
     external).
  3. Appends a single JSONL line to
     ``.omc/swe_bench_runs/<run-id>/results.jsonl``.
  4. Recomputes ``summary.json`` (totals, succeeded, tokens, est. cost).
  5. Prints a running tally to stdout.

Output is durable so a session interruption never loses a result.

Cost discipline
---------------
Each invocation runs exactly ONE instance. There is no batch/loop mode.
The user controls cadence by calling the script repeatedly. This is
intentional — keeps token spend transparent and pause-friendly.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Rough public pricing (per 1M tokens) for cost estimation.
# Update if pricing changes; this is for sanity-display only, not billing.
_PRICING_PER_1M: dict[str, tuple[float, float]] = {
    # model: (input_per_1m_usd, output_per_1m_usd)
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-7": (15.0, 75.0),
    # Vertex Gemini pricing (rough; varies by context-length tier on Vertex)
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.30, 2.50),
    # Preview models — pricing not finalized; estimates match prior tiers.
    "gemini-3.1-pro-preview": (1.25, 10.0),
    "gemini-3-flash-preview": (0.30, 2.50),
}

_DEFAULT_RUN_ROOT = Path(".omc/swe_bench_runs")


def _run_dir(run_id: str) -> Path:
    return _DEFAULT_RUN_ROOT / run_id


def _results_path(run_id: str) -> Path:
    return _run_dir(run_id) / "results.jsonl"


def _summary_path(run_id: str) -> Path:
    return _run_dir(run_id) / "summary.json"


def _attempted_ids(run_id: str) -> set[str]:
    """Return the set of instance_ids already attempted in this run."""
    p = _results_path(run_id)
    if not p.exists():
        return set()
    ids: set[str] = set()
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "instance_id" in rec:
                ids.add(rec["instance_id"])
    return ids


def _load_next_task(run_id: str, *, dataset: str, split: str) -> dict[str, Any] | None:
    """Stream the dataset and return the first task whose instance_id is not yet attempted."""
    from datasets import load_dataset

    attempted = _attempted_ids(run_id)
    ds = load_dataset(dataset, split=split, streaming=True)
    for task in ds:
        if task["instance_id"] not in attempted:
            return _normalize_task(task)
    return None


def _load_specific_task(instance_id: str, *, dataset: str, split: str) -> dict[str, Any] | None:
    from datasets import load_dataset

    ds = load_dataset(dataset, split=split, streaming=True)
    for task in ds:
        if task["instance_id"] == instance_id:
            return _normalize_task(task)
    return None


def _normalize_task(raw: dict[str, Any]) -> dict[str, Any]:
    """Coerce SWE-bench Lite's str-encoded list fields back into Python lists."""
    ftp = raw.get("FAIL_TO_PASS", "[]")
    if isinstance(ftp, str):
        try:
            ftp = json.loads(ftp)
        except json.JSONDecodeError:
            ftp = [ftp]
    ptp = raw.get("PASS_TO_PASS", "[]")
    if isinstance(ptp, str):
        try:
            ptp = json.loads(ptp)
        except json.JSONDecodeError:
            ptp = []
    return {
        "instance_id": raw["instance_id"],
        "repo": raw["repo"],
        "base_commit": raw["base_commit"],
        "problem_statement": raw["problem_statement"],
        "hints_text": raw.get("hints_text", ""),
        "FAIL_TO_PASS": ftp,
        "PASS_TO_PASS": ptp,
    }


def _estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = _PRICING_PER_1M.get(model)
    if not rates:
        return 0.0
    in_usd = (input_tokens / 1_000_000.0) * rates[0]
    out_usd = (output_tokens / 1_000_000.0) * rates[1]
    return in_usd + out_usd


def _append_result(run_id: str, record: dict[str, Any]) -> None:
    p = _results_path(run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(record) + "\n")


def _recompute_summary(run_id: str, *, model: str, dataset: str, split: str) -> dict[str, Any]:
    """Recompute the running-tally summary.json from results.jsonl (idempotent)."""
    p = _results_path(run_id)
    if not p.exists():
        return {"total": 0}
    records: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    total = len(records)
    succeeded = sum(1 for r in records if r.get("success"))
    errored = sum(1 for r in records if r.get("error"))
    in_tok = sum(r.get("input_tokens", 0) or 0 for r in records)
    out_tok = sum(r.get("output_tokens", 0) or 0 for r in records)
    cost = sum(r.get("est_cost_usd", 0.0) or 0.0 for r in records)
    durations = [r.get("elapsed_s") for r in records if r.get("elapsed_s") is not None]

    summary = {
        "run_id": run_id,
        "model": model,
        "dataset": dataset,
        "split": split,
        "total": total,
        "succeeded": succeeded,
        "errored": errored,
        "success_rate": (succeeded / total) if total else 0.0,
        "input_tokens_total": in_tok,
        "output_tokens_total": out_tok,
        "est_cost_usd_total": round(cost, 6),
        "mean_duration_s": (sum(durations) / len(durations)) if durations else 0.0,
        "instance_ids": [r.get("instance_id") for r in records],
    }
    _summary_path(run_id).write_text(json.dumps(summary, indent=2))
    return summary


def _record_from_solve(
    *,
    task: dict[str, Any],
    result: Any,
    model: str,
    elapsed_s: float,
    batch_id: str | None = None,
    agent_index: int | None = None,
) -> dict[str, Any]:
    md = result.metadata or {}
    in_tok = int(md.get("input_tokens", 0) or 0)
    out_tok = int(md.get("output_tokens", 0) or 0)
    cost = _estimate_cost_usd(model, in_tok, out_tok)
    return {
        "instance_id": task["instance_id"],
        "repo": task["repo"],
        "base_commit": task["base_commit"],
        "model": model,
        "auth": "oauth",
        "batch_id": batch_id,
        "agent_index": agent_index,
        "success": bool(result.success),
        "patch_length": len(result.patch),
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "stop_reason": md.get("stop_reason"),
        "raw_length": md.get("raw_length"),
        "elapsed_s": round(elapsed_s, 3),
        "est_cost_usd": round(cost, 6),
        "error": md.get("error"),
        "stderr_tail": md.get("stderr_tail"),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _save_patch(run_id: str, instance_id: str, patch: str) -> None:
    patch_dir = _run_dir(run_id) / "patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    (patch_dir / f"{instance_id}.diff").write_text(patch)


def _build_agent(
    *,
    provider: str,
    model: str,
    project_id: str | None,
    region: str,
    timeout_s: float,
    max_new_tokens: int,
    governed: bool = False,
):
    """Construct the SWEBenchAgent for the chosen provider, optionally governed."""
    if provider == "oauth":
        from constitutional_swarm.swe_bench.claude_oauth_agent import (
            ClaudeOAuthSWEBenchAgent,
        )
        base = ClaudeOAuthSWEBenchAgent(
            model=model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
        )
    elif provider == "vertex-claude":
        from constitutional_swarm.swe_bench.vertex_agent import (
            VertexClaudeSWEBenchAgent,
        )
        base = VertexClaudeSWEBenchAgent(
            project_id=project_id,
            region=region,
            model=model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
        )
    elif provider == "gemini":
        from constitutional_swarm.swe_bench.gemini_agent import GeminiSWEBenchAgent
        base = GeminiSWEBenchAgent(
            project_id=project_id,
            region=region,
            model=model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
        )
    else:
        raise ValueError(f"Unknown provider {provider!r}")

    if governed:
        from constitutional_swarm.swe_bench.governed_agent import GovernedAgent
        return GovernedAgent(base)
    return base


def run_one(
    *,
    run_id: str,
    model: str,
    provider: str = "oauth",
    project_id: str | None = None,
    region: str = "global",
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    split: str = "test",
    instance_id: str | None = None,
    timeout_s: float = 180.0,
    max_new_tokens: int = 4096,
    governed: bool = False,
) -> dict[str, Any]:
    """Run exactly one instance and return the per-instance record."""
    if instance_id:
        task = _load_specific_task(instance_id, dataset=dataset, split=split)
        if task is None:
            raise ValueError(f"instance_id {instance_id!r} not found in {dataset}/{split}")
    else:
        task = _load_next_task(run_id, dataset=dataset, split=split)
        if task is None:
            raise RuntimeError(
                f"No more un-attempted instances in {dataset}/{split} for run {run_id!r}"
            )

    log.info("Running instance %s (provider=%s, model=%s, governed=%s)",
             task["instance_id"], provider, model, governed)
    agent = _build_agent(
        provider=provider,
        model=model,
        project_id=project_id,
        region=region,
        timeout_s=timeout_s,
        max_new_tokens=max_new_tokens,
        governed=governed,
    )
    t0 = time.time()
    result = agent.solve(task)
    elapsed = time.time() - t0

    record = _record_from_solve(task=task, result=result, model=model, elapsed_s=elapsed)
    record["provider"] = provider
    _append_result(run_id, record)
    _save_patch(run_id, task["instance_id"], result.patch)
    summary = _recompute_summary(run_id, model=model, dataset=dataset, split=split)
    _print_tally(record, summary)
    return record


def run_swarm_batch(
    *,
    run_id: str,
    model: str,
    k: int,
    provider: str = "oauth",
    project_id: str | None = None,
    region: str = "global",
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    split: str = "test",
    timeout_s: float = 180.0,
    max_new_tokens: int = 4096,
    models: list[str] | None = None,
    governed: bool = False,
) -> list[dict[str, Any]]:
    """Run a single k-agent swarm batch over k next-un-attempted instances.

    Architecture: SwarmCoordinator.run_in_memory distributes k tasks across
    k agents (round-robin), with all agents writing to a shared MerkleCRDT.
    Each agent's result is recorded as a separate entry in results.jsonl,
    tagged with the same batch_id so the swarm event can be reconstructed.

    Cost: k model calls per invocation. No parallelism (sequential
    in-memory) — kept simple to stay below the [transport] extra dependency.
    """
    from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator

    if k < 1:
        raise ValueError("--swarm-k must be >= 1")

    # Collect k next-un-attempted tasks.
    attempted = _attempted_ids(run_id)
    from datasets import load_dataset

    tasks: list[dict[str, Any]] = []
    ds = load_dataset(dataset, split=split, streaming=True)
    for raw in ds:
        if raw["instance_id"] in attempted:
            continue
        tasks.append(_normalize_task(raw))
        if len(tasks) >= k:
            break
    if not tasks:
        raise RuntimeError(
            f"No more un-attempted instances in {dataset}/{split} for run {run_id!r}"
        )
    if len(tasks) < k:
        log.warning("Only %d un-attempted instances left; running with k=%d", len(tasks), len(tasks))
        k = len(tasks)

    # Build k agents via the chosen provider. If `models` is given, each
    # agent uses one model from the roster (heterogeneous swarm); k overrides
    # by replicating with model-cycling.
    roster: list[str]
    if models:
        roster = [models[i % len(models)] for i in range(k)]
    else:
        roster = [model] * k
    log.info("Agent roster: %s (governed=%s)", roster, governed)
    agents = [
        _build_agent(
            provider=provider,
            model=roster[i],
            project_id=project_id,
            region=region,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            governed=governed,
        )
        for i in range(k)
    ]
    coord = SwarmCoordinator(agents)
    batch_id = f"batch-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-k{k}"
    log.info("Swarm batch %s: %d agents x %d tasks (model=%s)", batch_id, k, len(tasks), model)

    # Round-robin: task j -> agent j % k. Track elapsed per-instance via timing wrapper.
    timings: list[float] = []
    original_solves = [a.solve for a in agents]

    def _wrap(agent_idx: int):
        original = original_solves[agent_idx]
        def wrapped(task):
            t0 = time.time()
            r = original(task)
            timings.append((agent_idx, task["instance_id"], time.time() - t0))
            return r
        return wrapped

    for i, agent in enumerate(agents):
        agent.solve = _wrap(i)  # type: ignore[method-assign]

    t_batch = time.time()
    aggregate = coord.run_in_memory(tasks)
    batch_elapsed = time.time() - t_batch

    # Build a per-instance lookup of timings.
    elapsed_by_iid = {iid: dt for (_, iid, dt) in timings}

    records: list[dict[str, Any]] = []
    for j, task in enumerate(tasks):
        result = aggregate["patches"][j]
        # Round-robin assignment: task j -> agent (j % k) -> roster[j % k].
        agent_idx = j % k
        record = _record_from_solve(
            task=task,
            result=result,
            model=roster[agent_idx],
            elapsed_s=elapsed_by_iid.get(task["instance_id"], 0.0),
            batch_id=batch_id,
            agent_index=agent_idx,
        )
        record["provider"] = provider
        records.append(record)
        _append_result(run_id, record)
        _save_patch(run_id, task["instance_id"], result.patch)

    summary = _recompute_summary(run_id, model=model, dataset=dataset, split=split)

    print("=" * 60)
    print(f"Swarm batch {batch_id} ({k} agents, model={model}, dataset={dataset}):")
    print(f"  CRDT size: {aggregate['crdt_size']}  resolved: {aggregate['resolved']}/{aggregate['total']}  "
          f"resolve_rate: {aggregate['resolve_rate']:.3f}")
    print(f"  governed_count: {aggregate['governed_count']}  mean_intervention: {aggregate['mean_intervention']:.3f}")
    print(f"  batch wall time: {batch_elapsed:.1f}s")
    print("-" * 60)
    for r in records:
        print(f"  agent#{r['agent_index']}: {r['instance_id']}  "
              f"success={r['success']}  patch={r['patch_length']}  "
              f"in/out={r['input_tokens']}/{r['output_tokens']}  "
              f"${r['est_cost_usd']:.4f}  {r['elapsed_s']}s")
    print("-" * 60)
    print(f"Run {summary['run_id']!r} totals (model={summary['model']}):")
    print(f"  attempted={summary['total']}  succeeded={summary['succeeded']}  "
          f"errored={summary['errored']}  rate={summary['success_rate']:.3f}")
    print(f"  est_total_cost=${summary['est_cost_usd_total']:.4f}")
    print("=" * 60)
    return records


def run_best_of_k_batch(
    *,
    run_id: str,
    model: str,
    k: int,
    picker: str = "longest",
    provider: str = "oauth",
    project_id: str | None = None,
    region: str = "global",
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    split: str = "test",
    timeout_s: float = 180.0,
    max_new_tokens: int = 4096,
    models: list[str] | None = None,
    governed: bool = False,
) -> dict[str, Any]:
    """Best-of-K: run k agents on the SAME task, picker selects the winner.

    Storage layout (one task per invocation):
      .omc/swe_bench_runs/<run-id>/results.jsonl
        — k+1 lines per call: k candidate records + 1 winner record
        — candidates have is_winner=False; winner has is_winner=True
        — the winner duplicates the chosen candidate's content (so summary
          aggregates can filter by is_winner=True without rejoining)
      .omc/swe_bench_runs/<run-id>/patches/<instance_id>.diff
        — the WINNER's patch
      .omc/swe_bench_runs/<run-id>/patches/<instance_id>.agent<N>.diff
        — per-candidate patches (kept for audit)

    The picker name and reason are recorded on the winner record.
    """
    from constitutional_swarm.swe_bench.pickers import PICKERS, needs_dna

    if k < 1:
        raise ValueError("--best-of-k must be >= 1")
    if picker not in PICKERS:
        raise ValueError(f"Unknown picker {picker!r}; choose from {sorted(PICKERS)}")

    # Pull ONE next-un-attempted task. We compare against the WINNER records
    # (is_winner=True) so a previous best-of-K invocation on the same instance
    # marks it as attempted.
    attempted = _attempted_winner_ids(run_id)
    from datasets import load_dataset

    task: dict[str, Any] | None = None
    ds = load_dataset(dataset, split=split, streaming=True)
    for raw in ds:
        if raw["instance_id"] in attempted:
            continue
        task = _normalize_task(raw)
        break
    if task is None:
        raise RuntimeError(
            f"No more un-attempted instances in {dataset}/{split} for run {run_id!r}"
        )

    # Build agent roster (heterogeneous if --models given).
    if models:
        roster = [models[i % len(models)] for i in range(k)]
    else:
        roster = [model] * k

    log.info(
        "Best-of-%d on %s: roster=%s, picker=%s, governed=%s",
        k, task["instance_id"], roster, picker, governed,
    )
    agents = [
        _build_agent(
            provider=provider,
            model=roster[i],
            project_id=project_id,
            region=region,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            governed=governed,
        )
        for i in range(k)
    ]

    # Run all k agents on the SAME task, sequentially.
    batch_id = f"bok-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-k{k}-{picker}"
    candidates: list[Any] = []
    elapsed_per_agent: list[float] = []
    for i, agent in enumerate(agents):
        t0 = time.time()
        result = agent.solve(task)
        elapsed_per_agent.append(time.time() - t0)
        candidates.append(result)

    # Picker selection.
    picker_fn = PICKERS[picker]
    if needs_dna(picker):
        from constitutional_swarm.dna import AgentDNA
        from constitutional_swarm.eval.monotonic_mas.detectors.mcfs_constitution import (
            MCFS_ROLE_CONSTITUTION,
        )
        dna = AgentDNA(
            constitution=MCFS_ROLE_CONSTITUTION,
            agent_id="picker-judge",
            strict=False,
            risk_scoring=True,
        )
        winner_idx, picker_reason = picker_fn(candidates, dna)
    else:
        winner_idx, picker_reason = picker_fn(candidates)

    # Persist k candidate records.
    cand_records: list[dict[str, Any]] = []
    for i, result in enumerate(candidates):
        rec = _record_from_solve(
            task=task,
            result=result,
            model=roster[i],
            elapsed_s=elapsed_per_agent[i],
            batch_id=batch_id,
            agent_index=i,
        )
        rec["provider"] = provider
        rec["mode"] = "best-of-k"
        rec["picker"] = picker
        rec["is_winner"] = False
        rec["candidate_count"] = k
        cand_records.append(rec)
        _append_result(run_id, rec)
        # Per-candidate patch file for audit.
        if result.patch:
            patch_dir = _run_dir(run_id) / "patches"
            patch_dir.mkdir(parents=True, exist_ok=True)
            (patch_dir / f"{task['instance_id']}.agent{i}.diff").write_text(result.patch)

    # Build winner record.
    if winner_idx < 0:
        # No winner — entire batch failed. Synthesize a marker record.
        winner_rec = {
            "instance_id": task["instance_id"],
            "repo": task["repo"],
            "base_commit": task["base_commit"],
            "model": "<best-of-k-no-winner>",
            "auth": cand_records[0].get("auth") if cand_records else "unknown",
            "batch_id": batch_id,
            "agent_index": -1,
            "success": False,
            "patch_length": 0,
            "input_tokens": sum(r["input_tokens"] for r in cand_records),
            "output_tokens": sum(r["output_tokens"] for r in cand_records),
            "stop_reason": None,
            "raw_length": None,
            "elapsed_s": round(sum(elapsed_per_agent), 3),
            "est_cost_usd": round(sum(r["est_cost_usd"] for r in cand_records), 6),
            "error": "no_valid_candidate",
            "stderr_tail": picker_reason,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "provider": provider,
            "mode": "best-of-k",
            "picker": picker,
            "picker_reason": picker_reason,
            "is_winner": True,
            "candidate_count": k,
        }
    else:
        # Winner = clone of the chosen candidate, re-tagged.
        winner_rec = dict(cand_records[winner_idx])
        winner_rec["is_winner"] = True
        winner_rec["picker_reason"] = picker_reason
        # Cost includes ALL k candidate calls (you paid for them; only one
        # contributes to the resolve rate).
        winner_rec["est_cost_usd"] = round(
            sum(r["est_cost_usd"] for r in cand_records), 6
        )
        winner_rec["input_tokens"] = sum(r["input_tokens"] for r in cand_records)
        winner_rec["output_tokens"] = sum(r["output_tokens"] for r in cand_records)
        winner_rec["elapsed_s"] = round(sum(elapsed_per_agent), 3)
    _append_result(run_id, winner_rec)

    # The winner's patch is the canonical instance patch.
    if winner_idx >= 0 and candidates[winner_idx].patch:
        _save_patch(run_id, task["instance_id"], candidates[winner_idx].patch)

    summary = _recompute_summary_winners(
        run_id, model=model, dataset=dataset, split=split
    )

    print("=" * 60)
    print(f"Best-of-{k} on {task['instance_id']}  (picker={picker})")
    print(f"  picker_reason: {picker_reason}")
    print(f"  total wall: {sum(elapsed_per_agent):.1f}s  cost: ${winner_rec['est_cost_usd']:.4f}")
    print("-" * 60)
    for i, rec in enumerate(cand_records):
        marker = "★" if i == winner_idx else " "
        print(f"  {marker} agent#{i} ({roster[i]}): "
              f"success={rec['success']} patch={rec['patch_length']} "
              f"in/out={rec['input_tokens']}/{rec['output_tokens']} "
              f"${rec['est_cost_usd']:.4f} {rec['elapsed_s']}s")
    print("-" * 60)
    print(f"Run {summary['run_id']!r} winners-only:")
    print(f"  attempted={summary['total']}  succeeded={summary['succeeded']}  "
          f"errored={summary['errored']}  rate={summary['success_rate']:.3f}")
    print(f"  est_total_cost=${summary['est_cost_usd_total']:.4f}")
    print("=" * 60)
    return winner_rec


def _attempted_winner_ids(run_id: str) -> set[str]:
    """Like _attempted_ids but only counts is_winner=True records.

    For best-of-K runs we want a subsequent invocation to skip an instance
    only if a winner was already chosen for it. Pure-candidate records
    (is_winner=False) shouldn't block re-attempts.
    """
    p = _results_path(run_id)
    if not p.exists():
        return set()
    ids: set[str] = set()
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Backwards compat: legacy records (no `mode` field) count as winners
            # so prior round-robin batches are still treated as attempted.
            if rec.get("is_winner", True) and "instance_id" in rec:
                ids.add(rec["instance_id"])
    return ids


def _recompute_summary_winners(
    run_id: str, *, model: str, dataset: str, split: str,
) -> dict[str, Any]:
    """Best-of-K-aware summary: aggregate ONLY winner records.

    Keeps the headline metrics interpretable (one row per instance) and
    counts the full k-call cost via the winner record's rolled-up cost.
    Falls back to the legacy summary if no winner records exist (e.g.,
    pre-best-of-k runs).
    """
    p = _results_path(run_id)
    if not p.exists():
        return {"total": 0, "run_id": run_id, "model": model,
                "dataset": dataset, "split": split,
                "succeeded": 0, "errored": 0, "success_rate": 0.0,
                "input_tokens_total": 0, "output_tokens_total": 0,
                "est_cost_usd_total": 0.0, "mean_duration_s": 0.0,
                "instance_ids": []}
    winners: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Only count is_winner=True (or legacy records without is_winner).
            if rec.get("is_winner", True):
                winners.append(rec)

    total = len(winners)
    succeeded = sum(1 for r in winners if r.get("success"))
    errored = sum(1 for r in winners if r.get("error"))
    in_tok = sum(r.get("input_tokens", 0) or 0 for r in winners)
    out_tok = sum(r.get("output_tokens", 0) or 0 for r in winners)
    cost = sum(r.get("est_cost_usd", 0.0) or 0.0 for r in winners)
    durations = [r.get("elapsed_s") for r in winners if r.get("elapsed_s") is not None]

    summary = {
        "run_id": run_id,
        "model": model,
        "dataset": dataset,
        "split": split,
        "total": total,
        "succeeded": succeeded,
        "errored": errored,
        "success_rate": (succeeded / total) if total else 0.0,
        "input_tokens_total": in_tok,
        "output_tokens_total": out_tok,
        "est_cost_usd_total": round(cost, 6),
        "mean_duration_s": (sum(durations) / len(durations)) if durations else 0.0,
        "instance_ids": [r.get("instance_id") for r in winners],
    }
    _summary_path(run_id).write_text(json.dumps(summary, indent=2))
    return summary


def _print_tally(record: dict[str, Any], summary: dict[str, Any]) -> None:
    print("=" * 60)
    print(f"Instance: {record['instance_id']}")
    print(f"  success={record['success']}  patch_len={record['patch_length']}  "
          f"elapsed={record['elapsed_s']}s")
    print(f"  in_tok={record['input_tokens']}  out_tok={record['output_tokens']}  "
          f"est_cost=${record['est_cost_usd']:.4f}")
    if record["error"]:
        print(f"  ERROR: {record['error']}: {(record.get('stderr_tail') or '')[:200]}")
    print("-" * 60)
    print(f"Run {summary['run_id']!r} totals (model={summary['model']}):")
    print(f"  attempted={summary['total']}  succeeded={summary['succeeded']}  "
          f"errored={summary['errored']}  rate={summary['success_rate']:.3f}")
    print(f"  total_in_tok={summary['input_tokens_total']}  "
          f"total_out_tok={summary['output_tokens_total']}  "
          f"est_total_cost=${summary['est_cost_usd_total']:.4f}")
    print(f"  mean_duration={summary['mean_duration_s']:.1f}s")
    print("=" * 60)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--run-id", required=True, help="Run identifier; results aggregate under .omc/swe_bench_runs/<run-id>/")
    p.add_argument("--model", default="claude-haiku-4-5", help="Model id (default: claude-haiku-4-5; use gemini-2.5-pro for --provider gemini)")
    p.add_argument(
        "--models",
        nargs="+",
        default=None,
        help="Heterogeneous swarm roster (overrides --model when given). "
             "k is taken as len(--models) unless --swarm-k is set higher (which cycles).",
    )
    p.add_argument(
        "--provider",
        default="oauth",
        choices=["oauth", "vertex-claude", "gemini"],
        help="Backend: oauth (Claude Code seat), vertex-claude (Anthropic on Vertex), gemini (Vertex Gemini).",
    )
    p.add_argument("--project-id", default=None, help="GCP project (vertex-* providers).")
    p.add_argument("--region", default="global", help="Vertex region (default 'global').")
    p.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite")
    p.add_argument("--split", default="test")
    p.add_argument(
        "--next",
        action="store_true",
        dest="use_next",
        help="Run the next un-attempted instance in the dataset.",
    )
    p.add_argument("--instance-id", default=None, help="Run a specific instance by id (overrides --next).")
    p.add_argument(
        "--swarm-k",
        type=int,
        default=1,
        help="Round-robin multi-task batch: k agents on k DIFFERENT tasks (default 1 = single agent). "
             "NOT a real swarm; results are independent. Use --best-of-k for best-of-K voting.",
    )
    p.add_argument(
        "--best-of-k",
        type=int,
        default=0,
        dest="best_of_k",
        help="Best-of-K mode: k agents on the SAME task; --picker chooses the winner. "
             "Mutually exclusive with --swarm-k.",
    )
    p.add_argument(
        "--picker",
        choices=["longest", "first-valid", "governed-score", "vote"],
        default="longest",
        help="Best-of-K winner selector (default: longest).",
    )
    p.add_argument("--timeout-s", type=float, default=180.0)
    p.add_argument("--max-new-tokens", type=int, default=4096)
    p.add_argument(
        "--governed",
        action="store_true",
        help="Wrap each agent in GovernedAgent: AgentDNA-validate every patch "
             "against MCFS_ROLE_CONSTITUTION; reject patches with violations or "
             "risk_score>=0.3.",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.swarm_k < 1:
        p.error("--swarm-k must be >= 1")
    if args.best_of_k < 0:
        p.error("--best-of-k must be >= 0")
    if args.best_of_k > 0 and args.swarm_k > 1:
        p.error("--best-of-k and --swarm-k > 1 are mutually exclusive")
    # If --models given without --best-of-k, default swarm_k to len(models)
    # for the round-robin path. For --best-of-k, the user supplies it explicitly.
    if args.models and args.swarm_k == 1 and args.best_of_k == 0:
        args.swarm_k = len(args.models)
    # For --best-of-k: if --models given without --best-of-k value, infer k.
    if args.models and args.best_of_k > 0 and args.best_of_k != len(args.models):
        log.warning(
            "--best-of-k=%d but --models has %d entries; roster will cycle",
            args.best_of_k, len(args.models),
        )
    if args.best_of_k == 0 and args.models and args.swarm_k > 1:
        # already handled via swarm-k path
        pass
    if args.best_of_k > 0 and args.instance_id:
        p.error("--instance-id is incompatible with --best-of-k (pulls next-un-attempted)")
    if args.swarm_k >= 2 and args.instance_id:
        p.error("--instance-id is incompatible with --swarm-k >= 2 (swarm pulls k next-un-attempted)")
    if args.swarm_k == 1 and args.best_of_k == 0 and not args.instance_id and not args.use_next:
        p.error("Pass either --next, --instance-id <id>, --swarm-k >= 2, or --best-of-k >= 1")

    try:
        if args.best_of_k >= 1:
            run_best_of_k_batch(
                run_id=args.run_id,
                model=args.model,
                k=args.best_of_k,
                picker=args.picker,
                models=args.models,
                provider=args.provider,
                project_id=args.project_id,
                region=args.region,
                dataset=args.dataset,
                split=args.split,
                timeout_s=args.timeout_s,
                max_new_tokens=args.max_new_tokens,
                governed=args.governed,
            )
        elif args.swarm_k >= 2:
            run_swarm_batch(
                run_id=args.run_id,
                model=args.model,
                k=args.swarm_k,
                models=args.models,
                provider=args.provider,
                project_id=args.project_id,
                region=args.region,
                dataset=args.dataset,
                split=args.split,
                timeout_s=args.timeout_s,
                max_new_tokens=args.max_new_tokens,
                governed=args.governed,
            )
        else:
            run_one(
                run_id=args.run_id,
                model=args.model,
                provider=args.provider,
                project_id=args.project_id,
                region=args.region,
                dataset=args.dataset,
                split=args.split,
                instance_id=args.instance_id,
                timeout_s=args.timeout_s,
                max_new_tokens=args.max_new_tokens,
                governed=args.governed,
            )
    except Exception as exc:  # noqa: BLE001 — top-level CLI error path
        log.error("run failed: %s: %s", type(exc).__name__, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
