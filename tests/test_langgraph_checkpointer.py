"""Tests for the LangGraph -> evolution_log audit side-car.

These tests exercise the ``EvolutionLogObserver`` against a real
``EvolutionLog`` instance (in-memory SQLite, matching the existing test
suite pattern in ``tests/test_evolution_log.py``). The end-to-end test
that requires the actual ``langgraph`` package is skipped when langgraph
is not installed.
"""

from __future__ import annotations

import pytest
from constitutional_swarm.evolution_log import EvolutionLog
from constitutional_swarm.langgraph_runtime.checkpointer_bridge import (
    EvolutionLogObserver,
    observe_stream,
)

# ---------------------------------------------------------------------------
# Pure-Python observer behavior (no langgraph required)
# ---------------------------------------------------------------------------


class TestObserverAccumulator:
    def test_five_observe_calls_record_five_rows(self) -> None:
        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="m")
            for _ in range(5):
                obs.observe({"node": {"step": 1}})

            assert obs.count == 5
            assert obs.epoch == 5

            rows = log._conn.execute(  # type: ignore[union-attr]
                "SELECT epoch, value FROM evolution_log WHERE metric = ? ORDER BY epoch",
                ("m",),
            ).fetchall()
            assert len(rows) == 5

    def test_cumulative_is_triangular_sequence(self) -> None:
        """Cumulative values after N calls must be 1, 3, 6, 10, 15, ..."""
        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="m")
            for _ in range(5):
                obs.observe({})

            rows = log._conn.execute(  # type: ignore[union-attr]
                "SELECT value FROM evolution_log WHERE metric = ? ORDER BY epoch",
                ("m",),
            ).fetchall()
            values = [r["value"] for r in rows]
            assert values == [1.0, 3.0, 6.0, 10.0, 15.0]

    def test_sequence_is_strictly_increasing_and_accelerating(self) -> None:
        """Six observe calls produce no regression and no deceleration."""
        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="audit")
            for _ in range(6):
                obs.observe({})

            # Both invariant queries must come back empty.
            assert log.detect_regression() == []
            assert log.detect_deceleration() == []

            # And the dashboard must mark this metric as strictly monotone.
            dash = {row.metric: row for row in log.dashboard()}
            assert dash["audit"].strictly_increasing == "YES"
            assert dash["audit"].strictly_accelerating == "YES"

    def test_observer_records_under_configured_metric(self) -> None:
        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="custom_metric")
            obs.observe({})
            obs.observe({})

            rows = log._conn.execute(  # type: ignore[union-attr]
                "SELECT DISTINCT metric FROM evolution_log"
            ).fetchall()
            assert [r["metric"] for r in rows] == ["custom_metric"]

    def test_count_and_epoch_properties_track(self) -> None:
        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="m")
            assert obs.count == 0
            assert obs.epoch == 0
            assert obs.cumulative == 0.0

            obs.observe({})
            assert obs.count == 1
            assert obs.epoch == 1
            assert obs.cumulative == 1.0

            obs.observe({})
            assert obs.count == 2
            assert obs.epoch == 2
            assert obs.cumulative == 3.0

    def test_epoch_offset_continues_existing_log(self) -> None:
        """epoch_offset lets an observer pick up after prior entries.

        evolution_log requires contiguous epochs, so the offset is only
        meaningful when the log has already been primed up through that
        epoch with values that match the observer's growth pattern.
        """
        with EvolutionLog(":memory:") as log:
            # Prime the log with triangular numbers for epochs 1-3 so the
            # observer can continue from epoch 4 with value 10 (= T_4).
            log.record(1, "m", 1.0)
            log.record(2, "m", 3.0)
            log.record(3, "m", 6.0)

            obs = EvolutionLogObserver(log, metric="m", epoch_offset=3)
            # Counter and cumulative must be aligned with the log state to
            # continue an existing trajectory.
            obs._n = 3
            obs._cumulative = 6.0

            obs.observe({})
            assert obs.epoch == 4
            assert obs.cumulative == 10.0
            row = log._conn.execute(  # type: ignore[union-attr]
                "SELECT value FROM evolution_log WHERE metric = ? AND epoch = ?",
                ("m", 4),
            ).fetchone()
            assert row["value"] == 10.0


# ---------------------------------------------------------------------------
# End-to-end with real LangGraph (skipped when not installed)
# ---------------------------------------------------------------------------


class TestObserveStreamE2E:
    async def test_observe_real_langgraph_stream(self) -> None:
        langgraph = pytest.importorskip("langgraph")
        del langgraph  # only used to gate the test
        from typing import TypedDict

        from langgraph.graph import END, START, StateGraph

        class State(TypedDict):
            n: int

        def bump_a(state: State) -> dict:
            return {"n": state["n"] + 1}

        def bump_b(state: State) -> dict:
            return {"n": state["n"] + 10}

        def bump_c(state: State) -> dict:
            return {"n": state["n"] + 100}

        builder = StateGraph(State)
        builder.add_node("a", bump_a)
        builder.add_node("b", bump_b)
        builder.add_node("c", bump_c)
        builder.add_edge(START, "a")
        builder.add_edge("a", "b")
        builder.add_edge("b", "c")
        builder.add_edge("c", END)
        graph = builder.compile()

        with EvolutionLog(":memory:") as log:
            obs = EvolutionLogObserver(log, metric="lg_audit")
            final = await observe_stream(graph, {"n": 0, "task_id": "t1"}, obs)

            # Three nodes -> three update chunks.
            assert obs.count == 3
            assert obs.epoch == 3
            assert final["n"] == 111

            # Invariants held throughout.
            assert log.detect_regression() == []
            assert log.detect_deceleration() == []
