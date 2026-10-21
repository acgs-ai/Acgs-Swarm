"""Workflow rotation keeps authority and executor projections bound atomically."""

from dataclasses import replace
import time

import pytest

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
)
from constitutional_swarm.apcc.verifier import ScopedTrust
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.authority_service import (
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.execution import ExecutionStatus
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    GovernedNodeState,
    GovernanceBypassDenied,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode
from constitutional_swarm.workflow_profile import WorkflowProfile
from tests.gcb_apcc_support import (
    InProcessExecutionClientHarness,
    authority_child_config,
    compose_test_executor,
    producer_key,
    provision_executor_workflow,
)
from tests.test_apcc_observation import _launch_expectations, _observer_launch
from tests.test_apcc_observation_target import _nonce
from tests.test_governed_commit import _trusted_admin


def _dag(workflow, *node_ids):
    return TaskDAG(
        dag_id=workflow,
        nodes={node_id: TaskNode(node_id=node_id) for node_id in node_ids or ("root",)},
    )


def _provision(admin, dag, key):
    provision_executor_workflow(admin, dag, policy_version="1")
    admin.register_agent(
        workflow_id=dag.dag_id,
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )


def _produce(executor, key, workflow, node_id="root"):
    authorization = sign_attempt_authorization(
        executor.prepare_claim(node_id, "agent"), key
    )
    executor.claim(node_id, "agent", authorization)
    payload = executor.produce_result(
        node_id,
        Artifact(f"artifact-{workflow}-{node_id}", node_id, "agent", "text", workflow),
        authorization=authorization,
    )
    receipt = sign_governed_receipt(payload, key)
    return authorization, receipt


def test_spawned_rotation_preserves_signed_historical_observations_and_rejects_old_capabilities(
    tmp_path,
):
    key = producer_key()
    config = authority_child_config(
        tmp_path / "rotation.db", tmp_path / "keys", producers={"agent": key}
    )
    authority = start_authority(config)
    observer = None
    try:
        launch_config = _observer_launch(config, tmp_path)
        observer = start_authority_observer(authority, launch_config)
        first, second = _dag("first"), _dag("second")
        _provision(authority.admin_client, first, key)
        _provision(authority.admin_client, second, key)
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        executor.load_dag(first)
        old_authorization, old_receipt = _produce(executor, key, "first")
        old_request = executor.build_request(old_receipt)
        assert executor.commit(old_request).outcome is CommitOutcome.COMMITTED
        assert executor.is_complete
        executor.load_dag(second)
        assert executor.progress == {"ready": 1}
        for operation in (
            lambda: executor.claim("root", "agent", old_authorization),
            lambda: executor.build_request(old_receipt),
            lambda: executor.commit(old_request),
            lambda: executor.produce_result(
                "root",
                Artifact("stale", "root", "agent", "text", "stale"),
                authorization=old_authorization,
            ),
        ):
            with pytest.raises(GovernanceBypassDenied):
                operation()
        assert executor.progress == {"ready": 1}
        _, receipt = _produce(executor, key, "second")
        request = executor.build_request(receipt)
        assert executor.commit(request).outcome is CommitOutcome.COMMITTED
        assert executor.is_complete
        launch = observer.launch_attestation
        stream = AuthorityObservationVerificationStream(launch.session_id)
        for committed in (old_request, request):
            target = executor.observation_target(
                committed, request_nonce=_nonce(committed.commit_id)
            )
            response = observer.client.observe(target)
            verified = stream.consume(
                response,
                launch=launch,
                pinned_controller_public_key=launch_config.controller_key_source.expected_public_key,
                expected_experiment_id=launch_config.experiment_id,
                expected_run_id=launch_config.run_id,
                expected_launch=_launch_expectations(launch),
                trust=ScopedTrust(config.authority.trust_bindings),
                now_ms=int(time.time() * 1000),
                maximum_staleness_ms=5000,
            )
            assert verified.consumable
            assert (
                verified.authority_proof
                is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
            )
            assert (
                sha256_digest(response.snapshot.output_bytes)
                == committed.receipt.payload.output_digest
            )
            assert (
                response.snapshot.request.workflow_id
                == committed.receipt.payload.workflow_id
            )
        assert stream.next_sequence == 3
    finally:
        if observer is not None:
            observer.close()
        authority.close()


@pytest.mark.parametrize(
    "stage", ["ready", "claimed", "result_produced", "denied", "revoked"]
)
def test_real_authority_noncommitted_workflow_cannot_rotate(tmp_path, stage):
    key = producer_key()
    admin = _trusted_admin(tmp_path / "incomplete.db")
    first, second = _dag("first"), _dag("second")
    _provision(admin, first, key)
    _provision(admin, second, key)
    executor = compose_test_executor(
        CapabilityRegistry(),
        ArtifactStore(),
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(first)
    if stage == "claimed":
        authorization = sign_attempt_authorization(
            executor.prepare_claim("root", "agent"), key
        )
        executor.claim("root", "agent", authorization)
    elif stage in {"result_produced", "denied", "revoked"}:
        _, receipt = _produce(executor, key, "first")
        request = admin.build_request(receipt)
        if stage == "denied":
            invalid = replace(
                request, receipt=request.receipt.replace(signature="invalid")
            )
            assert executor.commit(invalid).outcome is CommitOutcome.DENIED
        elif stage == "revoked":
            assert executor.commit(request).outcome is CommitOutcome.COMMITTED
            admin.revoke_root(
                workflow_id="first",
                node_id="root",
                event_id="revoke-root",
                reason="test",
            )
    before = _projection(executor)
    with pytest.raises(GovernanceBypassDenied):
        executor.load_dag(second)
    assert _projection(executor) == before
    assert executor.dag.dag_id == "first"


def _state(workflow, node_id, status="ready", *, commit_id=None):
    return GovernedNodeState(workflow, node_id, status, 0, None, None, None, commit_id)


class _StatusClient:
    """Fault injection at the trusted client response boundary, not security proof."""

    _workflow_profile = WorkflowProfile.DEFAULT

    def __init__(self):
        self.current = ()
        self.attached = None
        self.status_calls = []
        self.attach_calls = []

    def attach_workflow(self, *, workflow_id, nodes, **kwargs):
        self.attach_calls.append(workflow_id)
        if self.attached is not None:
            return self.attached
        return {node_id: _state(workflow_id, node_id) for node_id in nodes}

    def workflow_node_states(self, workflow_id, node_ids):
        self.status_calls.append((workflow_id, tuple(node_ids)))
        return self.current


def _projection(executor):
    return (
        executor._dag.dag_id,
        tuple(
            (key, node.status, node.claimed_by, node.artifact_id, dict(node.metadata))
            for key, node in executor._dag.nodes.items()
        ),
        set(executor._ready_ids),
        tuple(node.node_id for node in executor._ready_list),
        dict(executor._ready_index),
        dict(executor._pending_deps),
        {key: list(value) for key, value in executor._children.items()},
        executor._completed_count,
        executor._total_count,
        executor._dag_has_constrained,
        executor._all_ready_unconstrained,
    )


def _fake_executor():
    client = _StatusClient()
    executor = compose_test_executor(
        CapabilityRegistry(), ArtifactStore(), client, policy_version="1"
    )
    executor.load_dag(_dag("first", "a", "b"))
    client.current = tuple(
        _state("first", node, "governed_committed", commit_id=f"commit-{node}")
        for node in ("a", "b")
    )
    return executor, client


@pytest.mark.parametrize(
    "fault",
    [
        "short",
        "reordered",
        "identity",
        "invalid_status",
        "ready",
        "claimed",
        "result_produced",
        "denied",
        "revoked",
        "completed",
        "missing_commit",
    ],
)
def test_rotation_checks_fresh_complete_ordered_authority_snapshot_before_attachment(
    fault,
):
    executor, client = _fake_executor()
    states = list(client.current)
    if fault == "short":
        states.pop()
    elif fault == "reordered":
        states.reverse()
    elif fault == "identity":
        states[-1] = replace(states[-1], workflow_id="different")
    elif fault == "missing_commit":
        states[-1] = replace(states[-1], commit_id=None)
    else:
        states[-1] = replace(states[-1], status=fault)
    client.current = tuple(states)
    # A forged locally completed cache must never permit rotation.
    for node in executor._dag.nodes.values():
        node.status = ExecutionStatus.GOVERNED_COMMITTED
    executor._completed_count = executor._total_count
    before = _projection(executor)
    with pytest.raises((GovernanceBypassDenied, ValueError)):
        executor.load_dag(_dag("second"))
    assert _projection(executor) == before
    assert client.status_calls == [("first", ("a", "b"))]
    assert client.attach_calls == ["first"]


@pytest.mark.parametrize(
    "fault",
    [
        "short",
        "reordered",
        "identity",
        "invalid_status",
        "missing_dependency",
        "profile",
    ],
)
def test_failed_replacement_keeps_prior_dag_and_all_indexes_usable(fault):
    executor, client = _fake_executor()
    second = _dag("second", "a", "b")
    attached = {node: _state("second", node) for node in ("a", "b")}
    if fault == "short":
        attached.pop("b")
    elif fault == "reordered":
        attached = dict(zip(attached, reversed(tuple(attached.values())), strict=True))
    elif fault == "identity":
        attached["b"] = replace(attached["b"], node_id="wrong")
    elif fault == "invalid_status":
        attached["b"] = replace(attached["b"], status="bad-status")
    elif fault == "missing_dependency":
        second.nodes["b"].depends_on = ("missing",)
    else:
        client._workflow_profile = WorkflowProfile.W6_INDEPENDENT_10000
    client.attached = attached
    before = _projection(executor)
    with pytest.raises((GovernanceBypassDenied, KeyError, ValueError)):
        executor.load_dag(second)
    assert _projection(executor) == before
    client._workflow_profile = WorkflowProfile.DEFAULT
    client.current = tuple(_state("first", node) for node in ("a", "b"))
    assert executor.progress == {"ready": 2}
    assert [node.node_id for node in executor.available_tasks("agent")] == ["a", "b"]


def test_successful_rotation_uses_fresh_authority_even_if_local_projection_is_incomplete():
    executor, client = _fake_executor()
    assert executor._completed_count == 0
    executor.load_dag(_dag("second"))
    assert executor._dag.dag_id == "second"
    assert executor._total_count == 1
    assert executor._completed_count == 0
    assert executor._ready_ids == {"root"}
    assert client.status_calls == [("first", ("a", "b"))]


def test_ungoverned_executor_cannot_change_workflow_identity():
    executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
    executor.load_dag(_dag("first"))
    before = _projection(executor)
    with pytest.raises(GovernanceBypassDenied):
        executor.load_dag(_dag("second"))
    assert _projection(executor) == before


@pytest.mark.parametrize("mutation", ["missing", "topology", "capability", "digest"])
def test_real_authority_replacement_requires_exact_signed_provisioning(
    tmp_path, mutation
):
    key = producer_key()
    admin = _trusted_admin(tmp_path / "bindings.db")
    first, second = _dag("first"), _dag("second")
    _provision(admin, first, key)
    if mutation != "missing":
        _provision(admin, second, key)
    executor = compose_test_executor(
        CapabilityRegistry(),
        ArtifactStore(),
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(first)
    _, receipt = _produce(executor, key, "first")
    assert (
        executor.commit(admin.build_request(receipt)).outcome is CommitOutcome.COMMITTED
    )
    if mutation == "topology":
        second = second.add_node(TaskNode(node_id="extra"))
    elif mutation == "capability":
        second.nodes["root"].required_capabilities = ("other",)
    elif mutation == "digest":
        second.nodes["root"].description = "changed"
    before = _projection(executor)
    with pytest.raises((GovernanceBypassDenied, PermissionError)):
        executor.load_dag(second)
    assert _projection(executor) == before
    assert executor.is_complete


def test_same_workflow_reload_recovers_incomplete_state_but_rejects_topology_change(
    tmp_path,
):
    key = producer_key()
    admin = _trusted_admin(tmp_path / "reload.db")
    dag = _dag("first")
    _provision(admin, dag, key)
    executor = compose_test_executor(
        CapabilityRegistry(),
        ArtifactStore(),
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(dag)
    authorization = sign_attempt_authorization(
        executor.prepare_claim("root", "agent"), key
    )
    executor.claim("root", "agent", authorization)
    executor.load_dag(dag)
    assert executor.progress == {"claimed": 1}
    before = _projection(executor)
    with pytest.raises((GovernanceBypassDenied, PermissionError)):
        executor.load_dag(dag.add_node(TaskNode(node_id="extra")))
    assert _projection(executor) == before
    payload = executor.produce_result(
        "root",
        Artifact("recovered", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    assert (
        executor.commit(
            admin.build_request(sign_governed_receipt(payload, key))
        ).outcome
        is CommitOutcome.COMMITTED
    )


def test_revoked_ancestor_taints_completed_descendant_and_prevents_rotation(tmp_path):
    key = producer_key()
    admin = _trusted_admin(tmp_path / "tainted.db")
    first = _dag("first").add_node(TaskNode(node_id="child", depends_on=("root",)))
    second = _dag("second")
    _provision(admin, first, key)
    _provision(admin, second, key)
    executor = compose_test_executor(
        CapabilityRegistry(),
        ArtifactStore(),
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(first)
    for node_id in ("root", "child"):
        _, receipt = _produce(executor, key, "first", node_id)
        assert (
            executor.commit(admin.build_request(receipt)).outcome
            is CommitOutcome.COMMITTED
        )
    assert executor.is_complete
    admin.revoke_root(
        workflow_id="first", node_id="root", event_id="revoke-ancestor", reason="test"
    )
    assert admin.node_state("first", "child").status == "superseded"
    before = _projection(executor)
    with pytest.raises(GovernanceBypassDenied):
        executor.load_dag(second)
    assert _projection(executor) == before
