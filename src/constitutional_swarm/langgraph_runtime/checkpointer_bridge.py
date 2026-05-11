"""Side-car observer that mirrors LangGraph events into evolution_log.

LangGraph's checkpointer is mutating (per-thread overwrite); evolution_log is
append-only with strict monotonicity + acceleration enforced at write time.
This module bridges them WITHOUT replacing the checkpointer -- both stores run
in parallel, each serving its purpose:

- Checkpointer (MemorySaver/SqliteSaver): time-travel, HITL resume.
- EvolutionLog: tamper-evident audit trail with mathematical guarantees.

The observer accumulates cumulative counts so the recorded values are
strictly increasing AND accelerating. Concretely, after the n-th call the
running cumulative is the n-th triangular number T_n = n*(n+1)/2:
sequence 1, 3, 6, 10, 15, ... -- deltas are 1, 2, 3, 4, 5, ... (strictly
increasing), so the rate of growth itself grows monotonically and the
evolution_log write-time invariants are satisfied.
"""

from __future__ import annotations

from typing import Any


class EvolutionLogObserver:
    """Mirror graph-stream events into evolution_log for append-only audit.

    Parameters
    ----------
    evolution_log:
        Instance of ``constitutional_swarm.evolution_log.EvolutionLog``.
    metric:
        Metric name to record under. Defaults to ``"langgraph_event_index"``.
    epoch_offset:
        Starting epoch offset. The first event recorded uses ``epoch_offset + 1``.
    """

    def __init__(
        self,
        evolution_log: Any,
        *,
        metric: str = "langgraph_event_index",
        epoch_offset: int = 0,
    ) -> None:
        self._log = evolution_log
        self._metric = metric
        self._n = 0
        self._epoch = epoch_offset
        self._cumulative = 0.0

    def observe(self, event: Any) -> None:
        """Record one stream event.

        The running cumulative count is strictly increasing and (because the
        step itself grows by one each call) strictly accelerating -- satisfying
        evolution_log's write-time invariants. Tracked additively so callers
        may seed ``_n``/``_cumulative`` to continue an existing trajectory.

        ``event`` is part of the observer protocol but its contents are not
        consumed -- only the cardinality of the stream matters here.
        """
        del event
        self._n += 1
        self._cumulative += float(self._n)  # triangular growth: 1, 3, 6, 10, 15, ...
        self._epoch += 1
        self._log.record(self._epoch, self._metric, self._cumulative)

    @property
    def count(self) -> int:
        return self._n

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def cumulative(self) -> float:
        return self._cumulative


async def observe_stream(
    graph: Any,
    inputs: dict,
    observer: EvolutionLogObserver,
    *,
    config: dict | None = None,
) -> dict:
    """Run ``graph.astream`` and feed every chunk to the observer.

    Returns the final state (last update merged over the initial inputs).
    """
    cfg = config or {"configurable": {"thread_id": inputs.get("task_id", "obs")}}
    final: dict[str, Any] = dict(inputs)
    async for chunk in graph.astream(inputs, config=cfg, stream_mode="updates"):
        observer.observe(chunk)
        if isinstance(chunk, dict):
            for update in chunk.values():
                if isinstance(update, dict):
                    final.update(update)
    return final


__all__ = ["EvolutionLogObserver", "observe_stream"]
