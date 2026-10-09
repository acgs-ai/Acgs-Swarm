"""Adapter routing SwarmCoordinator tasks through a LangGraph runtime.

Free function -- does NOT monkey-patch SwarmCoordinator. Mirrors the
``run_in_memory`` API surface but each agent's ``solve`` runs through a
compiled LangGraph (via LangGraphSWEBenchAgent).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, replace
from functools import partial
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.guards import (
    has_clean_validation_evidence,
    has_completed_acceptance,
    has_pinned_constitutional_hash,
)
from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.strict_json import StrictJSONError, canonical_dumps
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
    configured_hash = CONSTITUTIONAL_HASH if constitutional_hash is None else constitutional_hash
    if not has_pinned_constitutional_hash(configured_hash):
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
        assignments = [(effective_agents[i % n_agents], task) for i, task in enumerate(subset)]

    shared_crdt = MerkleCRDT("coordinator")
    patches: list[SWEPatch] = []
    for agent, task in assignments:
        result, bodes_passed, artifact_hash = _normalize_result(
            agent.solve(task),
            configured_hash=configured_hash,
        )
        patches.append(result)
        try:
            payload = canonical_dumps(asdict(result))
        except (StrictJSONError, TypeError, ValueError) as exc:
            result, bodes_passed, artifact_hash = _reject_malformed_result(
                result,
                configured_hash=configured_hash,
                error="invalid_result",
                diagnostic_key="result_serialization_error",
                diagnostic_value=exc,
            )
            patches[-1] = result
            payload = canonical_dumps(asdict(result))
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
    if type(result.metadata) is not dict:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_metadata",
            diagnostic_key="reported_metadata_type",
            diagnostic_value=result.metadata,
        )
    metadata = result.metadata.copy()
    result_hash = metadata.get("constitutional_hash")
    governance_status = metadata.get("governance_status")

    if type(result_hash) not in (str, type(None)):
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="constitutional_hash_mismatch",
            diagnostic_key="actual_constitutional_hash",
            diagnostic_value=result_hash,
            extra={"expected_constitutional_hash": configured_hash},
        )
    if governance_status is not None and type(governance_status) is not str:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_governance_status",
            diagnostic_key="reported_governance_status",
            diagnostic_value=governance_status,
        )
    governance_attempted = result.governed is True or governance_status in {
        "accepted",
        "rejected",
        "halted",
    }

    if result_hash not in (None, "") and result_hash != configured_hash:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="constitutional_hash_mismatch",
            diagnostic_key="actual_constitutional_hash",
            diagnostic_value=result_hash,
            extra={"expected_constitutional_hash": configured_hash},
        )

    try:
        canonical_dumps(metadata)
    except (StrictJSONError, TypeError, ValueError) as exc:
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_metadata",
            diagnostic_key="metadata_serialization_error",
            diagnostic_value=exc,
        )

    violations = metadata.get("violations", [])
    if type(violations) is not list or any(type(item) is not str for item in violations):
        return _reject_malformed_result(
            result,
            configured_hash=configured_hash,
            error="invalid_violations",
            diagnostic_key="reported_violations_type",
            diagnostic_value=violations,
        )

    validation_evidence_present = any(
        key in metadata for key in ("governed", "risk_score", "violations")
    )
    validation_evidence = {
        "governed": metadata.get("governed", True),
        "risk_score": metadata.get("risk_score", 0.0),
        "violations": violations,
    }
    unsafe_validation_evidence = (
        governance_status is None
        and validation_evidence_present
        and not has_clean_validation_evidence(validation_evidence)
    )
    invalid_acceptance = governance_status == "accepted" and not has_completed_acceptance(metadata)

    validation_rejected = unsafe_validation_evidence or invalid_acceptance
    if governance_status in {"rejected", "halted"} or validation_rejected:
        if validation_rejected:
            metadata["governance_status"] = "rejected"
            metadata["error"] = "governance_rejected"
        else:
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
        bodes_passed = result.governed is True and result.success is True
    elif governance_status is None:
        normalized = replace(result, metadata=metadata)
        bodes_passed = result.governed is True and result.success is True and not violations
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
    normalized_status = metadata.get("governance_status")
    artifact_hash = (
        configured_hash
        if governance_attempted
        and (result_hash == configured_hash or normalized_status in {"rejected", "halted"})
        else ""
    )
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
    task_id = result.task_id if type(result.task_id) is str else "unknown"
    rejected = SWEPatch(
        task_id=task_id,
        patch="",
        success=False,
        governed=False,
        intervention_rate=0.0,
        duration_s=0.0,
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
