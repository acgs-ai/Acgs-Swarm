#!/usr/bin/env python3
"""Record the host's single-thread CPU speed at intervals while a W2 window runs.

This runs beside the campaign, as a separate process, and repeats one round of
the fixed work of ``w2_host_probe`` every few seconds. It answers one question:
when a window slows down part-way through, does work that has nothing to do
with the campaign slow down on that host at the same time?

It is record-only. Nothing reads its output to admit, void, account or verify a
run, and it takes no limit. It does add load: one round is about 0.2 s of CPU
on one core per interval.

Each sample is one JSON line, flushed as it is written, so a killed monitor
leaves a readable file. Samples carry the host-wide ``/proc/stat`` tick
counters; the campaign's diagnostics sidecar samples the same counters, which
places a sample in the window without relying on a shared clock.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from collections.abc import Callable
import signal
import time

try:
    from scripts import w2_host_probe
except ImportError:  # executed as ``python scripts/w2_host_monitor.py``
    import w2_host_probe  # type: ignore[no-redef]

MONITOR_REVISION = "w2-host-monitor-v1"
DEFAULT_INTERVAL_SECONDS = 10.0
# The monitor must not outlive its job if nothing stops it.
DEFAULT_MAX_SECONDS = 3 * 3600.0


def host_cpu_ticks() -> list[int] | None:
    """Host-wide [user, nice, system, idle, iowait, irq, softirq, steal] ticks."""
    try:
        with open("/proc/stat", encoding="ascii") as handle:
            fields = handle.readline().split()
    except OSError:
        return None
    if len(fields) < 9 or fields[0] != "cpu":
        return None
    try:
        return [int(value) for value in fields[1:9]]
    except ValueError:
        return None


def _load_average() -> list[float] | None:
    try:
        return list(os.getloadavg())
    except OSError:
        return None


def header(interval_seconds: float) -> dict[str, object]:
    return {
        "type": "header",
        "revision": MONITOR_REVISION,
        "probe_revision": w2_host_probe.PROBE_REVISION,
        "interval_seconds": interval_seconds,
        "rounds_per_sample": 1,
        "record_only": True,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "pid": os.getpid(),
    }


def sample(sequence: int) -> dict[str, object]:
    """Run one round of the fixed probe work and describe the host around it."""
    ticks_before = host_cpu_ticks()
    at_monotonic_ns = time.monotonic_ns()
    at_unix_ns = time.time_ns()
    result = w2_host_probe.run_round()
    return {
        "type": "sample",
        "sequence": sequence,
        "at_monotonic_ns": at_monotonic_ns,
        "at_unix_ns": at_unix_ns,
        "cpu_ns": result["cpu_ns"],
        "wall_ns": result["wall_ns"],
        "parts_cpu_ns": result["parts_cpu_ns"],
        "checksum": result["checksum"],
        "host_cpu_ticks": ticks_before,
        "load_average": _load_average(),
    }


def monitor(
    output: Path,
    interval_seconds: float,
    max_seconds: float,
    wait_for_stop: Callable[[float], bool],
) -> int:
    """Append samples to ``output`` (a new file) until stopped; return their count.

    ``wait_for_stop(seconds)`` waits up to that long and returns True once a stop
    has been requested.
    """
    deadline = time.monotonic() + max_seconds
    count = 0
    stopped = False
    with output.open("x", encoding="utf-8") as handle:

        def emit(record: dict[str, object]) -> None:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()

        emit(header(interval_seconds))
        next_at = time.monotonic()
        while time.monotonic() < deadline:
            emit(sample(count))
            count += 1
            # A fixed schedule, so a slow round does not push later samples back.
            next_at += interval_seconds
            now = time.monotonic()
            if next_at < now:
                next_at = now
            if wait_for_stop(max(0.0, min(next_at, deadline) - now)):
                stopped = True
                break
        emit({"type": "footer", "samples": count, "stopped": stopped})
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="JSONL path (new file)")
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS)
    args = parser.parse_args()
    if not args.interval_seconds > 0:
        parser.error("--interval-seconds must be positive")
    if not args.max_seconds > 0:
        parser.error("--max-seconds must be positive")
    # No signal handler: the stop signals stay blocked and are collected between
    # rounds, so a signal can neither interrupt a round nor run code re-entrantly.
    stop_signals = {signal.SIGTERM, signal.SIGINT}
    signal.pthread_sigmask(signal.SIG_BLOCK, stop_signals)

    def wait_for_stop(seconds: float) -> bool:
        return signal.sigtimedwait(stop_signals, seconds) is not None

    monitor(args.output, args.interval_seconds, args.max_seconds, wait_for_stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
