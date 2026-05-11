"""Adapter routing SwarmCoordinator tasks through a LangGraph runtime.

Free function -- does NOT monkey-patch SwarmCoordinator. Mirrors the
``run_in_memory`` API surface but each agent's ``solve`` runs through a
compiled LangGraph (via LangGraphSWEBenchAgent).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import asdict
from typing import Any

from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch


def run_langgraph(
    agents: Sequence[SWEBenchAgent],
    tasks: Sequence[dict[str, Any]],
    *,
    graph_factory: Callable[[SWEBenchAgent], Any] | None = None,
    max_tasks: int | None = None,
    routing_weights: list[list[float]] | None = None,
) -> dict[str, Any]:
    """Run agents through a LangGraph runtime; aggregate via shared MerkleCRDT.

    Parameters
    ----------
    agents:
        SWEBenchAgent instances. If ``graph_factory`` is provided, each agent is
        wrapped in a LangGraphSWEBenchAgent on a per-task basis. Otherwise
        agents are used as-is (test mode).
    tasks:
        Tasks to assign (each must have ``instance_id``).
    graph_factory:
        Optional ``(agent) -> CompiledStateGraph`` factory. When provided, each
        agent is wrapped in a LangGraphSWEBenchAgent that calls
        ``graph_factory(agent)`` for each task's invoke.
    max_tasks:
        Cap on tasks to process.
    routing_weights:
        Same shape as SwarmCoordinator.run_in_memory (n_agents x n_tasks).

    Returns
    -------
    dict with keys: ``patches``, ``total``, ``resolved``, ``resolve_rate``,
    ``crdt_size``, ``governed_count``, ``mean_intervention``.
    """
    if not agents:
        raise ValueError("run_langgraph requires at least one agent.")

    subset = list(tasks) if max_tasks is None else list(tasks)[:max_tasks]
    n_agents = len(agents)

    effective_agents: list[SWEBenchAgent]
    if graph_factory is None:
        effective_agents = list(agents)
    else:
        from constitutional_swarm.langgraph_runtime.agent import (
            LangGraphSWEBenchAgent,
        )

        effective_agents = [
            LangGraphSWEBenchAgent(graph_factory=lambda a=a: graph_factory(a))
            for a in agents
        ]

    if routing_weights is not None:
        if len(routing_weights) != n_agents or any(
            len(row) != len(subset) for row in routing_weights
        ):
            cols = len(routing_weights[0]) if routing_weights else 0
            raise ValueError(
                f"routing_weights must be {n_agents}x{len(subset)}; got "
                f"{len(routing_weights)}x{cols}"
            )
        assignments: list[tuple[SWEBenchAgent, dict[str, Any]]] = []
        for j, task in enumerate(subset):
            best_i = 0
            best_w = routing_weights[0][j]
            for i in range(1, n_agents):
                if routing_weights[i][j] > best_w:
                    best_w = routing_weights[i][j]
                    best_i = i
            assignments.append((effective_agents[best_i], task))
    else:
        assignments = [
            (effective_agents[i % n_agents], task) for i, task in enumerate(subset)
        ]

    shared_crdt = MerkleCRDT("coordinator")
    patches: list[SWEPatch] = []
    for agent, task in assignments:
        result = agent.solve(task)
        patches.append(result)
        payload = json.dumps(asdict(result))
        shared_crdt.append(payload=payload, bodes_passed=result.governed)

    return _aggregate(patches, shared_crdt)


def _aggregate(patches: list[SWEPatch], crdt: MerkleCRDT) -> dict[str, Any]:
    total = len(patches)
    resolved = sum(1 for p in patches if p.success)
    governed = [p for p in patches if p.governed]
    mean_intervention = (
        sum(p.intervention_rate for p in governed) / len(governed)
        if governed
        else 0.0
    )
    return {
        "patches": patches,
        "total": total,
        "resolved": resolved,
        "resolve_rate": resolved / total if total > 0 else 0.0,
        "crdt_size": crdt.size,
        "governed_count": len(governed),
        "mean_intervention": mean_intervention,
    }


__all__ = ["run_langgraph"]
