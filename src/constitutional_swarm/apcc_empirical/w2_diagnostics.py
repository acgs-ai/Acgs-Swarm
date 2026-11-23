"""Opt-in controller-side diagnostics for a W2 campaign window.

Set ``APCC_W2_DIAGNOSTICS=1`` to record, next to the window ledger, where the
controller process spent time that the ledger's five phase stamps cannot
separate.  The sidecar never feeds accounting or verification, and with the
variable unset :func:`from_env` returns ``None`` and the campaign runs exactly
as before.

Four independent signals are recorded so a stall can be attributed:

* **GC pauses** from ``gc.callbacks``.  A collection holds the GIL, so it
  stalls the admission loop and every worker thread at once.
* **Heartbeat gaps.**  A thread that only sleeps 5 ms at a time notes whenever
  it wakes late.  Each gap carries the host's CPU steal and CPU pressure
  deltas, which separates "this process was not scheduled" (steal or pressure
  rose) from "this process held the GIL" (they did not).
* **A once-a-second sample** of host CPU ticks, load average, CPU time of the
  authority, executor, observer and closure-verifier processes, and the size of
  the store's write-ahead log.  It separates a slow host (every process slows
  together) from a slow store (the authority's CPU or its WAL moves alone).
* **Per-operation sub-phase stamps** on the campaign clock: lock waits, the two
  observation RPCs, row encoding, prefix verification, closure verification and
  the wait for the ordered publish turn.
"""

from __future__ import annotations

import gc
import json
import os
import sqlite3
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ENV = "APCC_W2_DIAGNOSTICS"
REVISION = "w2-diagnostics-v2"
_HEARTBEAT_INTERVAL_S = 0.005
_HEARTBEAT_GAP_NS = 20_000_000
_GC_PAUSE_FLOOR_NS = 1_000_000


def _cpu_steal_ticks() -> int | None:
    """Host-wide steal time in clock ticks, or None where /proc lacks it."""
    try:
        with open("/proc/stat", encoding="ascii") as handle:
            fields = handle.readline().split()
    except OSError:
        return None
    if len(fields) < 9 or fields[0] != "cpu":
        return None
    return int(fields[8])


def _cpu_pressure_us() -> int | None:
    """Total microseconds some task waited for a CPU, or None without PSI."""
    try:
        with open("/proc/pressure/cpu", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("some "):
                    for item in line.split():
                        if item.startswith("total="):
                            return int(item[6:])
    except OSError:
        return None
    return None


def _delta(after: int | None, before: int | None) -> int | None:
    return None if after is None or before is None else after - before


def _host_cpu_ticks() -> list[int] | None:
    """Host-wide [user, nice, system, idle, iowait, irq, softirq, steal] ticks."""
    try:
        with open("/proc/stat", encoding="ascii") as handle:
            fields = handle.readline().split()
    except OSError:
        return None
    if len(fields) < 9 or fields[0] != "cpu":
        return None
    return [int(value) for value in fields[1:9]]


def _load_average() -> float | None:
    try:
        return os.getloadavg()[0]
    except OSError:
        return None


def _process_cpu_ticks(pid: int) -> int | None:
    """utime + stime of ``pid`` in clock ticks, or None once it has exited."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            # The command name may contain spaces; fields are counted after it.
            fields = handle.read().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
    if len(fields) < 13:
        return None
    return int(fields[11]) + int(fields[12])


def _file_size(path: str) -> int | None:
    try:
        return os.stat(path).st_size
    except OSError:
        return None


def sqlite_durability_profile(database: str) -> dict[str, Any]:
    """Report the durability settings a store at ``database`` runs with.

    The store is not opened.  Its journal mode is read from the file header
    (bytes 18 and 19 are both 2 for WAL).  ``synchronous`` and
    ``wal_autocheckpoint`` are per-connection and the APCC store sets neither,
    so its connections use this SQLite library's defaults; those are read from
    a scratch WAL database opened with the same library.
    """
    profile: dict[str, Any] = {"sqlite_version": sqlite3.sqlite_version}
    try:
        with open(database, "rb") as handle:
            header = handle.read(20)
        profile["header_write_read_versions"] = [header[18], header[19]]
        profile["journal_mode_is_wal"] = header[18] == 2 and header[19] == 2
    except (OSError, IndexError):
        profile["journal_mode_is_wal"] = None
    with tempfile.TemporaryDirectory() as scratch:
        connection = sqlite3.connect(os.path.join(scratch, "probe.db"))
        try:
            profile["scratch_journal_mode"] = connection.execute(
                "PRAGMA journal_mode=WAL"
            ).fetchone()[0]
            profile["default_synchronous"] = connection.execute("PRAGMA synchronous").fetchone()[0]
            profile["default_wal_autocheckpoint"] = connection.execute(
                "PRAGMA wal_autocheckpoint"
            ).fetchone()[0]
            profile["compile_options"] = sorted(
                row[0]
                for row in connection.execute("PRAGMA compile_options")
                if "SYNCHRONOUS" in row[0] or "AUTOCHECKPOINT" in row[0]
            )
        finally:
            connection.close()
    return profile


class W2Diagnostics:
    """Collects diagnostics for one window; all times are campaign-clock ns."""

    def __init__(self, clock: Callable[[], int]) -> None:
        self._clock = clock
        self._gc_started: int | None = None
        self._gc_pauses: list[dict[str, int]] = []
        self._gc_totals: dict[int, list[int]] = {0: [0, 0], 1: [0, 0], 2: [0, 0]}
        self._gaps: list[dict[str, int | None]] = []
        self._operations: dict[int, dict[str, int]] = {}
        self._slots: list[tuple[int, int, int]] = []
        self._processes: dict[str, int] = {}
        self._files: dict[str, str] = {}
        self._samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._heartbeat, name="w2-diagnostics-heartbeat", daemon=True
        )
        self._started = False

    @classmethod
    def from_env(cls, clock: Callable[[], int]) -> W2Diagnostics | None:
        return cls(clock) if os.environ.get(ENV) == "1" else None

    def watch(self, *, processes: dict[str, int], files: dict[str, str]) -> None:
        """Name the processes and files the once-a-second sample should cover."""
        self._processes = dict(processes)
        self._files = dict(files)

    def _sample(self, now: int) -> None:
        self._samples.append(
            {
                "at_ns": now,
                "host_cpu_ticks": _host_cpu_ticks(),
                "load_average_1m": _load_average(),
                "process_cpu_ticks": {
                    name: _process_cpu_ticks(pid) for name, pid in self._processes.items()
                },
                "file_bytes": {name: _file_size(path) for name, path in self._files.items()},
            }
        )

    def start(self) -> None:
        gc.callbacks.append(self._on_gc)
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        self._stop.set()
        self._thread.join(timeout=1)
        try:
            gc.callbacks.remove(self._on_gc)
        except ValueError:
            pass

    def _on_gc(self, phase: str, info: dict[str, int]) -> None:
        now = self._clock()
        if phase == "start":
            self._gc_started = now
            return
        started, self._gc_started = self._gc_started, None
        if started is None:
            return
        generation = int(info.get("generation", -1))
        duration = now - started
        totals = self._gc_totals.setdefault(generation, [0, 0])
        totals[0] += 1
        totals[1] += duration
        if duration >= _GC_PAUSE_FLOOR_NS:
            self._gc_pauses.append(
                {
                    "start_ns": started,
                    "duration_ns": duration,
                    "generation": generation,
                    "collected": int(info.get("collected", 0)),
                }
            )

    def _heartbeat(self) -> None:
        previous = self._clock()
        steal, pressure = _cpu_steal_ticks(), _cpu_pressure_us()
        self._sample(previous)
        while not self._stop.wait(_HEARTBEAT_INTERVAL_S):
            now = self._clock()
            gap = now - previous
            if now // 1_000_000_000 != previous // 1_000_000_000:
                self._sample(now)
            if gap >= _HEARTBEAT_GAP_NS:
                new_steal, new_pressure = _cpu_steal_ticks(), _cpu_pressure_us()
                self._gaps.append(
                    {
                        "start_ns": previous,
                        "gap_ns": gap,
                        "steal_ticks": _delta(new_steal, steal),
                        "cpu_pressure_us": _delta(new_pressure, pressure),
                    }
                )
                steal, pressure = new_steal, new_pressure
            elif now // 1_000_000_000 != previous // 1_000_000_000:
                # Rebase the counters once a second so a gap's deltas cover
                # roughly the gap itself, not everything since the window began.
                steal, pressure = _cpu_steal_ticks(), _cpu_pressure_us()
            previous = now

    def stamp(self, ticket: int, name: str) -> None:
        """Record ``name`` for operation ``ticket`` at the current clock."""
        self._operations.setdefault(ticket, {})[name] = self._clock()

    def flag(self, ticket: int, name: str, value: int) -> None:
        self._operations.setdefault(ticket, {})[name] = value

    def slot(self, index: int, woke_ns: int, decided_ns: int) -> None:
        """Record when the admission loop reached and left slot ``index``."""
        self._slots.append((index, woke_ns, decided_ns))

    def to_object(self) -> dict[str, Any]:
        return {
            "revision": REVISION,
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "heartbeat_interval_ns": int(_HEARTBEAT_INTERVAL_S * 1e9),
            "heartbeat_gap_floor_ns": _HEARTBEAT_GAP_NS,
            "gc_pause_floor_ns": _GC_PAUSE_FLOOR_NS,
            "gc_enabled": gc.isenabled(),
            "gc_threshold": list(gc.get_threshold()),
            "gc_freeze_count": gc.get_freeze_count(),
            "gc_totals": {
                str(generation): {"collections": count, "total_ns": total}
                for generation, (count, total) in sorted(self._gc_totals.items())
            },
            "gc_pauses": self._gc_pauses,
            "heartbeat_gaps": self._gaps,
            "watched_processes": self._processes,
            "watched_files": self._files,
            "samples": self._samples,
            "sqlite_durability": sqlite_durability_profile(self._files["authority_db"])
            if "authority_db" in self._files
            else None,
            "slots": [
                {"slot_index": index, "woke_ns": woke, "decided_ns": decided}
                for index, woke, decided in self._slots
            ],
            "operations": [
                {"ticket": ticket, **stamps} for ticket, stamps in sorted(self._operations.items())
            ],
            "written_wall_ms": int(time.time() * 1000),
        }

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_object(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
