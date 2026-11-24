#!/usr/bin/env python3
"""Measure single-thread CPU speed of a W2 host before the window clock starts.

The W2 campaign paces ten proposals per second through one serial section, so a
host whose cores are slow loses operations regardless of the code under test.
This probe times a fixed amount of single-thread work of the kinds the campaign
does (interpreter loop, JSON, SHA-256, SQLite) and compares the fastest round
with a limit chosen before the run.

The decision uses the probe alone. It is taken before any campaign operation is
scheduled and never reads campaign results, so it cannot select runs by outcome.
Without a limit the probe only records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import time

PROBE_REVISION = "w2-host-probe-v1"
DEFAULT_ROUNDS = 7
# Each round repeats the work so that it lasts a few hundred milliseconds.
_REPEATS = 8

_DOCUMENT = {
    "workflow": "w2-host-probe",
    "nodes": [
        {
            "index": index,
            "digest": f"{index:064x}",
            "parents": [f"{parent:064x}" for parent in range(max(0, index - 3), index)],
            "payload": {"text": "x" * 96, "flags": [True, False, None], "weight": index * 7},
        }
        for index in range(48)
    ],
}


def _json_work() -> int:
    total = 0
    for _ in range(120):
        text = json.dumps(_DOCUMENT, sort_keys=True, separators=(",", ":"))
        total += len(json.loads(text)["nodes"]) + len(text)
    return total


def _hash_work() -> int:
    digest = hashlib.sha256()
    block = bytes(range(256)) * 16
    for _ in range(2_000):
        digest.update(block)
        block = digest.digest() + block[32:]
    return int.from_bytes(digest.digest()[:6], "big")


def _sqlite_work() -> int:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute(
            "CREATE TABLE t (k INTEGER PRIMARY KEY, parent INTEGER, v BLOB NOT NULL)"
        )
        connection.execute("CREATE INDEX t_parent ON t(parent)")
        connection.execute("BEGIN")
        connection.executemany(
            "INSERT INTO t(k, parent, v) VALUES (?, ?, ?)",
            ((key, key // 3, b"v" * 128) for key in range(6_000)),
        )
        connection.execute("COMMIT")
        total = 0
        for key in range(0, 2_000):
            total += connection.execute(
                "SELECT COUNT(*) FROM t WHERE parent = ?", (key,)
            ).fetchone()[0]
        return total
    finally:
        connection.close()


def _loop_work() -> int:
    depth = 0
    peak = 0
    text = '{"a":[1,2,{"b":"c"}]}' * 6_000
    for char in text:
        if char in "[{":
            depth += 1
            if depth > peak:
                peak = depth
        elif char in "]}":
            depth -= 1
    return peak + len(text)


_WORK = (
    ("json", _json_work),
    ("sha256", _hash_work),
    ("sqlite", _sqlite_work),
    ("loop", _loop_work),
)


def run_round() -> dict[str, object]:
    """Run the fixed work once; return its CPU and wall time and a work checksum."""
    parts: dict[str, int] = {}
    checksum = 0
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    for name, work in _WORK:
        part_start = time.process_time_ns()
        for _ in range(_REPEATS):
            checksum = (checksum * 1_000_003 + work()) % (1 << 61)
        parts[name] = time.process_time_ns() - part_start
    return {
        "cpu_ns": time.process_time_ns() - cpu_start,
        "wall_ns": time.perf_counter_ns() - wall_start,
        "parts_cpu_ns": parts,
        "checksum": checksum,
    }


def _cpu_identity() -> dict[str, object]:
    identity: dict[str, object] = {"machine": platform.machine(), "cpu_count": os.cpu_count()}
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return identity
    models: list[str] = []
    mhz: list[float] = []
    flags = ""
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "model name" and value not in models:
            models.append(value)
        elif key == "cpu MHz":
            try:
                mhz.append(float(value))
            except ValueError:
                pass
        elif key == "flags" and not flags:
            flags = value
    identity["model_names"] = models
    identity["cpu_mhz"] = mhz
    identity["flags_sha256"] = hashlib.sha256(flags.encode("utf-8")).hexdigest() if flags else None
    identity["hypervisor_flag"] = "hypervisor" in flags.split()
    return identity


def decide(best_cpu_ms: float, max_cpu_ms: float | None) -> bool | None:
    """Return None when only recording, otherwise whether the host is admitted."""
    if max_cpu_ms is None:
        return None
    return best_cpu_ms <= max_cpu_ms


def parse_limit(raw: str) -> float | None:
    """Parse the limit; an empty value means record only."""
    text = raw.strip()
    if not text:
        return None
    limit = float(text)
    if not limit > 0 or limit != limit or limit == float("inf"):
        raise ValueError(f"host probe limit must be a positive finite number: {raw!r}")
    return limit


def probe(rounds: int, max_cpu_ms: float | None, phase: str) -> dict[str, object]:
    results = [run_round() for _ in range(rounds)]
    checksums = {result["checksum"] for result in results}
    if len(checksums) != 1:
        raise RuntimeError("host probe rounds did not perform identical work")
    cpu_ms = sorted(int(result["cpu_ns"]) / 1e6 for result in results)  # type: ignore[call-overload]
    best = cpu_ms[0]
    return {
        "revision": PROBE_REVISION,
        "phase": phase,
        "rounds": results,
        "work_checksum": checksums.pop(),
        "best_cpu_ms": round(best, 3),
        "median_cpu_ms": round(cpu_ms[len(cpu_ms) // 2], 3),
        "worst_cpu_ms": round(cpu_ms[-1], 3),
        "max_cpu_ms": max_cpu_ms,
        "admitted": decide(best, max_cpu_ms),
        "hostname": platform.node(),
        "cpu": _cpu_identity(),
        "python_version": sys.version,
        "load_average": list(os.getloadavg()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="JSON result path (new file)")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument(
        "--max-cpu-ms",
        default="",
        help="Admit the host only if the fastest round uses at most this much CPU; empty records only",
    )
    parser.add_argument("--phase", choices=("before", "after"), default="before")
    args = parser.parse_args()
    if args.rounds < 3:
        parser.error("--rounds must be at least 3")
    limit = parse_limit(args.max_cpu_ms)
    # Claim the output path first, so an existing file fails before measuring.
    with args.output.open("x", encoding="utf-8") as output:
        result = probe(args.rounds, limit, args.phase)
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    summary = {
        key: result[key]
        for key in ("phase", "best_cpu_ms", "median_cpu_ms", "max_cpu_ms", "admitted")
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
