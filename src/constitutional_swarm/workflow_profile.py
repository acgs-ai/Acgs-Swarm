"""Explicit trusted workflow budgets; profiles are never caller RPC options."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum

from constitutional_swarm.governance_errors import GovernanceBypassDenied


class WorkflowProfile(Enum):
    """Versioned admission profile selected by the trusted supervisor."""

    DEFAULT = "default"
    W6_INDEPENDENT_10000 = "w6-independent-10000-v1"

    @property
    def max_nodes(self) -> int:
        return 10_000 if self is self.W6_INDEPENDENT_10000 else 1000

    @property
    def max_frame_bytes(self) -> int:
        return 16_777_216 if self is self.W6_INDEPENDENT_10000 else 1_048_576

    @property
    def control_timeout_seconds(self) -> float:
        return 30.0 if self is self.W6_INDEPENDENT_10000 else 2.0

    def frame_budget(self, operation: str, configured: int) -> int:
        """Larger frames carry workflow control descriptions, never artifacts."""
        if self is self.W6_INDEPENDENT_10000 and operation not in {
            "create_workflow",
            "attach_workflow",
            "workflow_node_states",
            "load_dag",
            "available_tasks",
        }:
            return min(configured, self.DEFAULT.max_frame_bytes)
        return configured


def require_workflow_profile(value: WorkflowProfile) -> WorkflowProfile:
    if type(value) is not WorkflowProfile:
        raise TypeError("workflow_profile must be WorkflowProfile")
    return value


def validate_workflow_nodes(
    profile: WorkflowProfile,
    nodes: Mapping[str, Sequence[str]],
    capabilities: Mapping[str, Sequence[str]],
) -> None:
    """Validate the whole graph before any durable workflow row is written."""
    require_workflow_profile(profile)
    if not isinstance(nodes, Mapping) or not nodes:
        raise GovernanceBypassDenied("invalid_workflow_definition")
    if len(nodes) > profile.max_nodes:
        raise GovernanceBypassDenied("node_status_batch_too_large")
    if not isinstance(capabilities, Mapping) or set(capabilities) - set(nodes):
        raise GovernanceBypassDenied("invalid_workflow_capabilities")
    indegree: dict[str, int] = {}
    children: dict[str, list[str]] = {}
    for node_id, dependencies in nodes.items():
        if type(node_id) is not str or not node_id or not node_id.encode("utf-8"):
            raise GovernanceBypassDenied("invalid_workflow_node_identity")
        if type(dependencies) not in (tuple, list) or any(
            type(dep) is not str or not dep for dep in dependencies
        ):
            raise GovernanceBypassDenied("invalid_workflow_dependencies")
        if len(set(dependencies)) != len(dependencies):
            raise GovernanceBypassDenied("duplicate_predecessor")
        if profile is WorkflowProfile.W6_INDEPENDENT_10000 and dependencies:
            raise GovernanceBypassDenied("workflow_profile_requires_independent_nodes")
        required = capabilities.get(node_id, ())
        if type(required) not in (tuple, list) or any(
            type(cap) is not str or not cap for cap in required
        ):
            raise GovernanceBypassDenied("invalid_workflow_capabilities")
        for cap in required:
            cap.encode("utf-8")
        indegree[node_id] = len(dependencies)
        for dep in dependencies:
            if dep not in nodes:
                raise GovernanceBypassDenied("unknown_predecessor")
            children.setdefault(dep, []).append(node_id)
    pending = [node_id for node_id, count in indegree.items() if count == 0]
    visited = 0
    while pending:
        node_id = pending.pop()
        visited += 1
        for child in children.get(node_id, ()):
            indegree[child] -= 1
            if indegree[child] == 0:
                pending.append(child)
    if visited != len(nodes):
        raise GovernanceBypassDenied("workflow_cycle")
