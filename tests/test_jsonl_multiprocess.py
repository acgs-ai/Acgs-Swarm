"""Process-boundary tests for the JSONL assignment index.

These prove cooperating multi-process writers under the existing advisory
lock. They do not claim safety against non-cooperating writers that skip
the lock.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from constitutional_swarm.settlement_store import JSONLSettlementStore

WORKER = Path(__file__).resolve().parent / "jsonl_mp_worker.py"


def _wait_exists(
    path: Path, procs: list[subprocess.Popen[str]], timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        exited = [proc for proc in procs if proc.poll() is not None]
        if exited:
            details = []
            for proc in procs:
                proc.kill()
                out, err = proc.communicate(timeout=2)
                details.append(f"rc={proc.returncode} stdout={out!r} stderr={err!r}")
            raise AssertionError(f"worker exited before {path} existed: {details}")
        time.sleep(0.01)
    for proc in procs:
        proc.kill()
    raise AssertionError(f"worker never became ready: {path}")


def _run(
    *args: str,
    check: bool = False,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(WORKER), *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _ids(path: Path) -> list[str]:
    store = JSONLSettlementStore(path)
    return [record.assignment["assignment_id"] for record in store.load_all()]


def test_two_processes_same_assignment_exactly_one_commits(tmp_path) -> None:
    path = tmp_path / "same.jsonl"
    ready_a = tmp_path / "ready-a"
    ready_b = tmp_path / "ready-b"
    go = tmp_path / "go"
    proc_a = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "dup",
            "--ready-file",
            str(ready_a),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc_b = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "dup",
            "--ready-file",
            str(ready_b),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_exists(ready_a, [proc_a, proc_b])
    _wait_exists(ready_b, [proc_a, proc_b])
    go.write_text("go", encoding="utf-8")
    out_a, err_a = proc_a.communicate(timeout=15)
    out_b, err_b = proc_b.communicate(timeout=15)
    codes = sorted((proc_a.returncode, proc_b.returncode))
    assert codes == [0, 2], (
        proc_a.returncode,
        out_a,
        err_a,
        proc_b.returncode,
        out_b,
        err_b,
    )
    assert _ids(path) == ["dup"]


def test_two_processes_distinct_assignments_both_commit(tmp_path) -> None:
    path = tmp_path / "distinct.jsonl"
    ready_a = tmp_path / "ready-a"
    ready_b = tmp_path / "ready-b"
    go = tmp_path / "go"
    proc_a = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "alpha",
            "--ready-file",
            str(ready_a),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc_b = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "beta",
            "--ready-file",
            str(ready_b),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_exists(ready_a, [proc_a, proc_b])
    _wait_exists(ready_b, [proc_a, proc_b])
    go.write_text("go", encoding="utf-8")
    assert proc_a.wait(timeout=15) == 0
    assert proc_b.wait(timeout=15) == 0
    assert set(_ids(path)) == {"alpha", "beta"}


def test_warm_index_sees_external_process_append(tmp_path) -> None:
    path = tmp_path / "warm.jsonl"
    ready = tmp_path / "ready"
    go = tmp_path / "go"
    warm = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "warm-append",
            str(path),
            "warm",
            "--next-id",
            "after",
            "--ready-file",
            str(ready),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_exists(ready, [warm])
    other = _run("append", str(path), "other")
    assert other.returncode == 0, other.stderr
    go.write_text("go", encoding="utf-8")
    assert warm.wait(timeout=15) == 0
    assert set(_ids(path)) == {"warm", "other", "after"}


def test_crash_during_append_does_not_commit(tmp_path) -> None:
    path = tmp_path / "crash.jsonl"
    crashed = _run("crash-partial", str(path), "torn")
    assert crashed.returncode == 17
    recovered = _run("append", str(path), "after-crash")
    assert recovered.returncode == 0, recovered.stderr
    assert _ids(path) == ["after-crash"]


def test_torn_tail_before_two_processes_start(tmp_path) -> None:
    path = tmp_path / "torn.jsonl"
    good = {
        "assignment": {"assignment_id": "ok"},
        "result": {"ok": True},
        "constitutional_hash": "abc123",
        "schema_version": 1,
    }
    path.write_text(
        json.dumps(good) + "\n" + '{"assignment":{"assignment_id":"torn"',
        encoding="utf-8",
    )
    ready_a = tmp_path / "ready-a"
    ready_b = tmp_path / "ready-b"
    go = tmp_path / "go"
    proc_a = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "a",
            "--ready-file",
            str(ready_a),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc_b = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "append",
            str(path),
            "b",
            "--ready-file",
            str(ready_b),
            "--go-file",
            str(go),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_exists(ready_a, [proc_a, proc_b])
    _wait_exists(ready_b, [proc_a, proc_b])
    go.write_text("go", encoding="utf-8")
    assert proc_a.wait(timeout=15) == 0
    assert proc_b.wait(timeout=15) == 0
    assert set(_ids(path)) == {"ok", "a", "b"}
