"""Adapter routing SwarmCoordinator tasks through a LangGraph runtime.

Free function -- does NOT monkey-patch SwarmCoordinator. Mirrors the
``run_in_memory`` API surface but each agent's ``solve`` runs through a
compiled LangGraph (via LangGraphSWEBenchAgent).
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, replace
from functools import partial
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch
from constitutional_swarm.swe_bench.harness import _patch_generation_metrics


def run_langgraph(
    agents: Sequence[SWEBenchAgent],
    tasks: Sequence[dict[str, Any]],
    *,
    graph_factory: Callable[[SWEBenchAgent], Any] | None = None,
    max_tasks: int | None = None,
    routing_weights: list[list[float]] | None = None,
    constitutional_hash: str | None = CONSTITUTIONAL_HASH,
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
    constitutional_hash:
        Constitution hash forwarded to graph-backed agents and stamped into
        result metadata. ``None`` retains backward compatibility by selecting
        the package constitutional hash.

    Returns
    -------
    The canonical outcome keys are ``patch_generated`` and ``patch_rate``;
    deprecated ``resolved`` aliases remain for compatibility. The result also
    includes ``patches``, ``crdt_size``, and shared generation diagnostics.
    """
    if not agents:
        raise ValueError("run_langgraph requires at least one agent.")
    configured_hash = (
        CONSTITUTIONAL_HASH if constitutional_hash is None else constitutional_hash
    )
    if configured_hash != CONSTITUTIONAL_HASH:
        raise ValueError(
            "configured constitutional hash mismatch: "
            f"expected {CONSTITUTIONAL_HASH!r}, got {configured_hash!r}"
        )

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
            LangGraphSWEBenchAgent(
                graph_factory=partial(graph_factory, a),
                constitutional_hash=configured_hash,
            )
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
        result, bodes_passed, artifact_hash = _normalize_result(
            agent.solve(task),
            configured_hash=configured_hash,
        )
        patches.append(result)
        payload = json.dumps(asdict(result), allow_nan=False)
        shared_crdt.append(
            payload=payload,
            bodes_passed=bodes_passed,
            constitutional_hash=artifact_hash,
        )

    return _aggregate(patches, shared_crdt)


def _normalize_result(
    result: SWEPatch,
    *,
    configured_hash: str,
) -> tuple[SWEPatch, bool, str]:
    """Bind one result to the configured constitution without aborting a batch."""
    if not isinstance(result.metadata, Mapping):
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_metadata",
            diagnostic_key="reported_metadata_type",
            diagnostic_value=result.metadata,
        )
    try:
        metadata = dict(result.metadata)
    except (TypeError, ValueError) as exc:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_metadata",
            diagnostic_key="metadata_conversion_error",
            diagnostic_value=exc,
        )
    result_hash = metadata.get("constitutional_hash")
    governance_status = metadata.get("governance_status")

    if not isinstance(result_hash, (str, type(None))):
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="constitutional_hash_mismatch",
            diagnostic_key="actual_constitutional_hash",
            diagnostic_value=result_hash,
            extra={"expected_constitutional_hash": configured_hash},
        )
    if governance_status is not None and not isinstance(governance_status, str):
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_governance_status",
            diagnostic_key="reported_governance_status",
            diagnostic_value=governance_status,
        )
    governance_attempted = result.governed or governance_status in {
        "accepted",
        "rejected",
        "halted",
    }

    if result_hash in (None, ""):
        metadata["constitutional_hash"] = configured_hash
    elif result_hash != configured_hash:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="constitutional_hash_mismatch",
            diagnostic_key="actual_constitutional_hash",
            diagnostic_value=result_hash,
            extra={"expected_constitutional_hash": configured_hash},
        )

    try:
        json.dumps(metadata, allow_nan=False)
    except (TypeError, ValueError) as exc:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_metadata",
            diagnostic_key="metadata_serialization_error",
            diagnostic_value=exc,
        )

    if governance_status in {"rejected", "halted"}:
        metadata.setdefault("error", f"governance_{governance_status}")
        normalized = replace(
            result,
            patch="",
            success=False,
            governed=False,
            metadata=metadata,
        )
        bodes_passed = False
    elif governance_status == "accepted":
        normalized = replace(result, metadata=metadata)
        bodes_passed = True
    elif governance_status is None:
        normalized = replace(result, metadata=metadata)
        bodes_passed = result.governed
    else:
        metadata.update(
            {
                "governance_status": "rejected",
                "error": "invalid_governance_status",
                "reported_governance_status": governance_status,
            }
        )
        normalized = replace(
            result,
            patch="",
            success=False,
            governed=False,
            metadata=metadata,
        )
        bodes_passed = False
    artifact_hash = configured_hash if governance_attempted else ""
    return normalized, bodes_passed, artifact_hash


def _reject_malformed_result(
    result: SWEPatch,
    *,
    configured_hash: str,
    error: str,
    diagnostic_key: str | None = None,
    diagnostic_value: object = None,
    extra: Mapping[str, object] | None = None,
) -> tuple[SWEPatch, bool, str]:
    """Return a JSON-safe per-result rejection for malformed agent metadata."""
    metadata: dict[str, Any] = {
        "constitutional_hash": configured_hash,
        "governance_status": "rejected",
        "error": error,
    }
    if diagnostic_key is not None:
        metadata[diagnostic_key] = _json_safe_diagnostic(diagnostic_value)
    if extra is not None:
        metadata.update(extra)
    rejected = replace(
        result,
        patch="",
        success=False,
        governed=False,
        metadata=metadata,
    )
    return rejected, False, configured_hash


def _json_safe_diagnostic(value: object) -> object:
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return {"type": "float", "value": "non-finite"}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    return {"type": type(value).__name__}


def _aggregate(patches: list[SWEPatch], crdt: MerkleCRDT) -> dict[str, Any]:
    return {
        "patches": patches,
        **_patch_generation_metrics(patches),
        "crdt_size": crdt.size,
    }


__all__ = ["run_langgraph"]
