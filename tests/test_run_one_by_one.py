"""Regression tests for run_one_by_one fixes from Codex --base main review.

Covers:
- _run_lock: exclusive file lock serializes parallel claim+append on the
  same run-id (prevents double-spending paid attempts on the same instance).
- _recompute_summary: filters is_winner=False audit rows so best-of-K
  candidates do not inflate logical-attempt totals or cost.
- pyproject [gemini] extra: declares google-genai so --provider gemini is
  installable on a clean environment.
"""

from __future__ import annotations

import json
import threading
import time
import tomllib
from pathlib import Path

import pytest


def _set_omc_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point _run_dir() at a sandboxed location for the duration of a test."""
    from constitutional_swarm.swe_bench import run_one_by_one as m

    sandbox = tmp_path / ".omc" / "swe_bench_runs"
    monkeypatch.setattr(m, "_run_dir", lambda run_id: sandbox / run_id)
    return sandbox


def test_run_lock_serializes_parallel_holders(tmp_path, monkeypatch):
    """Two threads contending for the same run-id lock must not overlap."""
    from constitutional_swarm.swe_bench import run_one_by_one as m

    _set_omc_root(tmp_path, monkeypatch)
    inside = 0
    overlap_seen = False
    lock_event = threading.Event()

    def hold(run_id: str, hold_s: float) -> None:
        nonlocal inside, overlap_seen
        with m._run_lock(run_id):
            inside += 1
            if inside > 1:
                overlap_seen = True
            time.sleep(hold_s)
            inside -= 1
            lock_event.set()

    t1 = threading.Thread(target=hold, args=("run-x", 0.10))
    t2 = threading.Thread(target=hold, args=("run-x", 0.10))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert not overlap_seen, "two holders were inside _run_lock at the same time"
    assert lock_event.is_set()


def test_run_lock_independent_run_ids_do_not_block(tmp_path, monkeypatch):
    """Locks on different run-ids must not serialize against each other."""
    from constitutional_swarm.swe_bench import run_one_by_one as m

    _set_omc_root(tmp_path, monkeypatch)
    started = threading.Event()
    finished = threading.Event()

    def hold_a() -> None:
        with m._run_lock("run-a"):
            started.set()
            time.sleep(0.30)

    def acquire_b() -> None:
        started.wait(timeout=2)
        with m._run_lock("run-b"):
            finished.set()

    t1 = threading.Thread(target=hold_a)
    t2 = threading.Thread(target=acquire_b)
    t1.start()
    t2.start()
    # run-b must finish quickly even though run-a is still holding its lock.
    assert finished.wait(timeout=1.0), "independent run-id was blocked by another lock"
    t1.join(timeout=2)
    t2.join(timeout=1)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_recompute_summary_excludes_best_of_k_candidates(tmp_path, monkeypatch):
    """Best-of-K candidate audit rows must not inflate summary totals."""
    from constitutional_swarm.swe_bench import run_one_by_one as m

    sandbox = _set_omc_root(tmp_path, monkeypatch)
    run_dir = sandbox / "run-mixed"
    rows = [
        # Single-mode row (no is_winner field) — counts.
        {"instance_id": "a", "success": True, "input_tokens": 100,
         "output_tokens": 50, "est_cost_usd": 0.01, "elapsed_s": 1.0},
        # Best-of-K candidate audit rows — must NOT count.
        {"instance_id": "b", "is_winner": False, "success": False,
         "input_tokens": 200, "output_tokens": 80, "est_cost_usd": 0.02},
        {"instance_id": "b", "is_winner": False, "success": True,
         "input_tokens": 200, "output_tokens": 80, "est_cost_usd": 0.02},
        {"instance_id": "b", "is_winner": False, "success": False,
         "input_tokens": 200, "output_tokens": 80, "est_cost_usd": 0.02},
        # Best-of-K winner row — counts as the single logical attempt for "b".
        {"instance_id": "b", "is_winner": True, "success": True,
         "input_tokens": 600, "output_tokens": 240, "est_cost_usd": 0.06,
         "elapsed_s": 4.0},
    ]
    _write_jsonl(run_dir / "results.jsonl", rows)

    summary = m._recompute_summary(
        "run-mixed",
        model="claude-sonnet-4-6",
        dataset="princeton-nlp/SWE-bench_Lite",
        split="test",
    )

    # 2 logical attempts (a single-mode + b winner), not 5 raw rows.
    assert summary["total"] == 2
    assert summary["succeeded"] == 2
    # Cost = single-mode 0.01 + winner 0.06 = 0.07. Candidate rows must NOT
    # be added on top.
    assert summary["est_cost_usd_total"] == pytest.approx(0.07, abs=1e-9)
    assert summary["instance_ids"] == ["a", "b"]


def test_pyproject_declares_gemini_extra_with_google_genai():
    """The Gemini agent imports `from google import genai` — the extra used
    to install it must include `google-genai`. The `vertex` extra is for
    Anthropic-on-Vertex (no genai SDK) and must NOT be conflated."""
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    extras = data["project"]["optional-dependencies"]
    assert "gemini" in extras, "pyproject must declare a [gemini] extra"
    gemini_deps = " ".join(extras["gemini"]).lower()
    assert "google-genai" in gemini_deps, (
        f"[gemini] extra must include google-genai, got: {extras['gemini']}"
    )
