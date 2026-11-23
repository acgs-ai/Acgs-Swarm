"""The W2 diagnostics sidecar is opt-in and never touches the ledger."""

from __future__ import annotations

import gc
import json
import time
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical import w2_diagnostics
from constitutional_swarm.apcc_empirical.w2_diagnostics import W2Diagnostics


def _clock() -> int:
    return time.monotonic_ns()


def test_disabled_unless_the_environment_opts_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(w2_diagnostics.ENV, raising=False)
    assert W2Diagnostics.from_env(_clock) is None
    monkeypatch.setenv(w2_diagnostics.ENV, "0")
    assert W2Diagnostics.from_env(_clock) is None
    monkeypatch.setenv(w2_diagnostics.ENV, "1")
    assert isinstance(W2Diagnostics.from_env(_clock), W2Diagnostics)


def test_start_and_stop_leave_no_gc_callback_behind() -> None:
    before = list(gc.callbacks)
    diagnostics = W2Diagnostics(_clock)
    diagnostics.start()
    assert len(gc.callbacks) == len(before) + 1
    diagnostics.stop()
    diagnostics.stop()
    assert gc.callbacks == before


def test_stop_without_start_is_harmless() -> None:
    before = list(gc.callbacks)
    W2Diagnostics(_clock).stop()
    assert gc.callbacks == before


def test_collections_are_counted_per_generation() -> None:
    diagnostics = W2Diagnostics(_clock)
    diagnostics.start()
    try:
        gc.collect(2)
        gc.collect(0)
    finally:
        diagnostics.stop()
    totals = diagnostics.to_object()["gc_totals"]
    assert totals["2"]["collections"] >= 1
    assert totals["0"]["collections"] >= 1
    assert totals["2"]["total_ns"] > 0


def test_long_collections_are_recorded_as_pauses() -> None:
    ticks = iter([1_000, 1_000 + 5_000_000, 9_000_000, 9_000_100])
    diagnostics = W2Diagnostics(lambda: next(ticks))
    diagnostics._on_gc("start", {"generation": 2})
    diagnostics._on_gc("stop", {"generation": 2, "collected": 7})
    diagnostics._on_gc("start", {"generation": 0})
    diagnostics._on_gc("stop", {"generation": 0, "collected": 0})
    result = diagnostics.to_object()
    assert result["gc_pauses"] == [
        {"start_ns": 1_000, "duration_ns": 5_000_000, "generation": 2, "collected": 7}
    ]
    assert result["gc_totals"]["0"] == {"collections": 1, "total_ns": 100}


def test_heartbeat_records_only_the_tick_that_arrived_late() -> None:
    # The first reading is the baseline, the second arrives 100 ms late, and
    # every later one is 1 ms after the one before.
    readings = [0, 100_000_000, 100_000_000]

    def clock() -> int:
        if len(readings) > 1:
            return readings.pop(0)
        readings[0] += 1_000_000
        return readings[0]

    diagnostics = W2Diagnostics(clock)
    diagnostics.start()
    time.sleep(0.05)
    diagnostics.stop()
    gaps = diagnostics.to_object()["heartbeat_gaps"]
    assert [(gap["start_ns"], gap["gap_ns"]) for gap in gaps] == [(0, 100_000_000)]
    assert set(gaps[0]) == {"start_ns", "gap_ns", "steal_ticks", "cpu_pressure_us"}


def test_stamps_slots_and_sidecar_round_trip(tmp_path: Path) -> None:
    ticks = iter(range(100, 1_000, 100))
    diagnostics = W2Diagnostics(lambda: next(ticks))
    diagnostics.stamp(3, "snapshot_acquired_ns")
    diagnostics.stamp(3, "row_built_ns")
    diagnostics.flag(3, "fast_observed", 1)
    diagnostics.stamp(1, "row_built_ns")
    diagnostics.slot(7, 40, 55)
    path = tmp_path / "window-000.diagnostics.json"
    diagnostics.write(path)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["revision"] == w2_diagnostics.REVISION
    assert loaded["operations"] == [
        {"ticket": 1, "row_built_ns": 300},
        {"ticket": 3, "snapshot_acquired_ns": 100, "row_built_ns": 200, "fast_observed": 1},
    ]
    assert loaded["slots"] == [{"slot_index": 7, "woke_ns": 40, "decided_ns": 55}]
