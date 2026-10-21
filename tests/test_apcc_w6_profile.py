"""Opt-in W6 control-plane capacity; representative commits are not a campaign."""

from dataclasses import replace
from contextlib import contextmanager
import hashlib
import json
import sqlite3
import time
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
)
from constitutional_swarm.apcc.verifier import ScopedTrust
import constitutional_swarm.authority_service as authority_service
from constitutional_swarm.authority_child import AuthorityChildConfig
from constitutional_swarm.authority_ipc import FrameSizeError, digest, verify_response
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.authority_service import (
    _AuthorityExecutionChannel,
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    ControlAction,
    TrustedGovernanceBootstrap,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from constitutional_swarm.workflow_profile import WorkflowProfile
from tests.gcb_apcc_support import (
    authority_child_config,
    producer_key,
    provision_executor_workflow,
    typed_bootstrap,
)
from tests.test_apcc_observation import _launch_expectations, _observer_launch
from tests.test_apcc_authority_service import _raw_channel_rpc


def _nodes(count):
    return {f"node-{index:05d}": () for index in range(count)}


def _config(tmp_path, profile=WorkflowProfile.DEFAULT, *, producers=None):
    base = authority_child_config(
        tmp_path / "w6.db",
        tmp_path / "w6.keys",
        producers=producers or {"agent": producer_key()},
    )
    return AuthorityChildConfig(
        database_path=base.database_path,
        authority=base.authority,
        key_source=base.key_source,
        outbox_sink=base.outbox_sink,
        provision=base.provision,
        workflow_profile=profile,
    )


def _workflow_rows(path, workflow_id):
    with sqlite3.connect(path) as connection:
        return tuple(
            connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE workflow_id=?", (workflow_id,)
            ).fetchone()[0]
            for table in ("workflows", "nodes", "logical_nodes")
        )


def _bootstrap(profile):
    base = typed_bootstrap()
    return TrustedGovernanceBootstrap(
        config=base.config,
        runtime=base.runtime,
        policy_signer=base._policy_signer,
        registry_signer=base._registry_signer,
        control_signer=base._control_signer,
        workflow_profile=profile,
    )


@pytest.mark.parametrize(
    ("profile", "limit"),
    [(WorkflowProfile.DEFAULT, 1000), (WorkflowProfile.W6_INDEPENDENT_10000, 10000)],
)
def test_spawned_profile_workflow_limit_and_last_node_denial_are_atomic(
    tmp_path, profile, limit
):
    config = _config(tmp_path, profile)
    authority = start_authority(config)
    try:
        authority.admin_client.create_workflow(
            workflow_id="at-limit", nodes=_nodes(limit), policy_version="1"
        )
        assert _workflow_rows(config.database_path, "at-limit")[:2] == (1, limit)
        with pytest.raises(GovernanceBypassDenied):
            authority.admin_client.create_workflow(
                workflow_id="over-limit", nodes=_nodes(limit + 1), policy_version="1"
            )
        assert _workflow_rows(config.database_path, "over-limit") == (0, 0, 0)
        malformed = _nodes(limit)
        last = next(reversed(malformed))
        with pytest.raises((GovernanceBypassDenied, ValueError, TypeError)):
            authority.admin_client.create_workflow(
                workflow_id="malformed-last",
                nodes=malformed,
                policy_version="1",
                required_capabilities={last: ["valid", {}]},
            )
        assert _workflow_rows(config.database_path, "malformed-last") == (0, 0, 0)
        assert authority.admin_client.health()["authority_pid"] == authority.pid
    finally:
        authority.close()


def test_spawned_w6_profile_rejects_edges_and_untrusted_profile_injection(tmp_path):
    config = _config(tmp_path, WorkflowProfile.W6_INDEPENDENT_10000)
    authority = start_authority(config)
    try:
        with pytest.raises(GovernanceBypassDenied):
            authority.admin_client.create_workflow(
                workflow_id="with-edge",
                nodes={"first": (), "last": ("first",)},
                policy_version="1",
            )
        assert _workflow_rows(config.database_path, "with-edge") == (0, 0, 0)
        with pytest.raises(GovernanceBypassDenied):
            authority.admin_client._client._rpc(
                "create_workflow",
                {
                    "workflow_id": "injected",
                    "nodes": {"node": []},
                    "policy_version": "1",
                    "required_capabilities": {},
                    "input_digests": {},
                    "workflow_profile": "DEFAULT",
                },
            )
        assert _workflow_rows(config.database_path, "injected") == (0, 0, 0)
        authority.admin_client.create_workflow(
            workflow_id="positive-control", nodes={"node": ()}, policy_version="1"
        )
        assert _workflow_rows(config.database_path, "positive-control")[:2] == (1, 1)
    finally:
        authority.close()


@pytest.mark.parametrize("profile", ["W6_INDEPENDENT_10000", "unknown", None, 10000])
def test_trusted_child_configuration_rejects_non_enum_profile(tmp_path, profile):
    with pytest.raises((ValueError, TypeError)):
        _config(tmp_path, profile)


@pytest.mark.parametrize("substitution", ["default", "unknown-profile"])
def test_spawned_scheduler_rejects_activation_profile_substitution(
    tmp_path, monkeypatch, substitution
):
    config = _config(tmp_path, WorkflowProfile.W6_INDEPENDENT_10000)
    authority = start_authority(config)
    encode = authority_service.canonical_json
    substitutions = []

    def substitute(value):
        if isinstance(value, dict) and value.get("stage") == "ACTIVATE_SCHEDULER":
            substitutions.append(value["workflow_profile"])
            value = {**value, "workflow_profile": substitution}
        return encode(value)

    monkeypatch.setattr(authority_service, "canonical_json", substitute)
    try:
        with pytest.raises((GovernanceBypassDenied, ValueError, RuntimeError)):
            authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert substitutions == [WorkflowProfile.W6_INDEPENDENT_10000.value]
    finally:
        authority.close()


def test_spawned_w6_full_dag_order_and_three_signed_observed_commits(tmp_path):
    producers = {
        f"agent-{index}": producer_key(f"agent-{index}") for index in range(1000)
    }
    config = _config(
        tmp_path, WorkflowProfile.W6_INDEPENDENT_10000, producers=producers
    )
    assert len(config.authority.producer_trust) == 1000
    authority = start_authority(config)
    observer = None
    node_ids = tuple(_nodes(10000))
    dag = TaskDAG(
        dag_id="w6", nodes={node_id: TaskNode(node_id=node_id) for node_id in node_ids}
    )
    try:
        launch_config = _observer_launch(config, tmp_path)
        observer = start_authority_observer(authority, launch_config)
        provision_executor_workflow(authority.admin_client, dag, policy_version="1")
        for agent_id in ("agent-0", "agent-499", "agent-999"):
            authority.admin_client.register_agent(
                workflow_id="w6",
                agent_id=agent_id,
                public_key=producers[agent_id].public_key(),
            )
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        executor.load_dag(dag)
        assert (
            tuple(node.node_id for node in executor.available_tasks("agent-0"))
            == node_ids
        )
        launch = observer.launch_attestation
        stream = AuthorityObservationVerificationStream(launch.session_id)
        for node_id, agent_id in zip(
            (node_ids[0], node_ids[5000], node_ids[-1]),
            ("agent-0", "agent-499", "agent-999"),
            strict=True,
        ):
            key = producers[agent_id]
            authorization = sign_attempt_authorization(
                executor.prepare_claim(node_id, agent_id), key
            )
            executor.claim(node_id, agent_id, authorization)
            payload = executor.produce_result(
                node_id,
                Artifact(f"artifact-{node_id}", node_id, agent_id, "text", node_id),
                authorization=authorization,
            )
            request = executor.build_request(sign_governed_receipt(payload, key))
            assert executor.commit(request).outcome is CommitOutcome.COMMITTED
            nonce = b64u_encode(hashlib.sha256(node_id.encode()).digest()[:16])
            target = executor.observation_target(request, request_nonce=nonce)
            response = observer.client.observe(target)
            assert response.snapshot.state is AuthorityObservationState.COMMITTED
            assert response.snapshot.request == target
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
                == request.receipt.payload.output_digest
            )
        assert stream.next_sequence == 4
        assert len(executor.available_tasks("agent-0")) == 9997
        assert not executor.is_complete
        with pytest.raises(GovernanceBypassDenied) as oversized:
            executor._rpc("commit", {"request": {"padding": "x" * 1_048_576}})
        assert isinstance(oversized.value.__cause__, FrameSizeError)
        with sqlite3.connect(config.database_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM commit_index"
            ).fetchone() == (3,)
    finally:
        if observer is not None:
            observer.close()
        authority.close()


@pytest.mark.parametrize("count", [2, 10000])
def test_w6_database_reopen_requires_matching_trusted_profile(tmp_path, count):
    config = _config(tmp_path, WorkflowProfile.W6_INDEPENDENT_10000)
    authority = start_authority(config)
    try:
        authority.admin_client.create_workflow(
            workflow_id="large", nodes=_nodes(count), policy_version="1"
        )
    finally:
        authority.close()
    default_reopen = replace(_config(tmp_path), provision=False)
    with pytest.raises(RuntimeError, match="workflow_profile_mismatch"):
        unexpected = start_authority(default_reopen)
        unexpected.close()
    matching_reopen = replace(
        _config(tmp_path, WorkflowProfile.W6_INDEPENDENT_10000), provision=False
    )
    assert matching_reopen.authority == config.authority
    assert (
        matching_reopen.key_source.expected_identity_public_key
        == config.key_source.expected_identity_public_key
    )
    reopened = start_authority(matching_reopen)
    try:
        assert reopened.admin_client.health()["authority_pid"] == reopened.pid
        assert _workflow_rows(config.database_path, "large")[:2] == (1, count)
    finally:
        reopened.close()


def test_w6_full_status_uses_one_read_transaction_and_attestation(
    tmp_path, monkeypatch
):
    base = typed_bootstrap()
    bootstrap = TrustedGovernanceBootstrap(
        config=base.config,
        runtime=base.runtime,
        policy_signer=base._policy_signer,
        registry_signer=base._registry_signer,
        control_signer=base._control_signer,
        workflow_profile=WorkflowProfile.W6_INDEPENDENT_10000,
    )
    admin = bootstrap.provision(tmp_path / "chunked.db")
    with pytest.raises(GovernanceBypassDenied, match="workflow_profile_mismatch"):
        admin._command(
            ControlAction.CREATE_WORKFLOW,
            "mismatched",
            {
                "nodes": {"root": []},
                "policy_version": "1",
                "admission_profile": WorkflowProfile.DEFAULT.value,
            },
        )
    assert _workflow_rows(tmp_path / "chunked.db", "mismatched") == (0, 0, 0)
    nodes = _nodes(10000)
    admin.create_workflow(workflow_id="chunked", nodes=nodes, policy_version="1")
    store_type = type(admin.commit_port._apcc_store)
    original_read = store_type._read_transaction
    original_attest = store_type._attest_batch_snapshot
    original_batch = store_type._logical_node_status_batch_at
    connections = []
    attestations = []
    batches = []

    @contextmanager
    def read(self):
        with original_read(self) as connection:
            connections.append(connection)
            yield connection

    def attest(self, connection, certificate_digests=None):
        assert connections == [connection]
        result = original_attest(self, connection, certificate_digests)
        attestations.append(result)
        return result

    def batch(self, connection, requests, semantic_snapshot=None):
        assert connections == [connection]
        assert len(attestations) == 1
        assert semantic_snapshot is attestations[0]
        assert 0 < len(requests) <= 1000
        batches.append(tuple(requests))
        return original_batch(self, connection, requests, semantic_snapshot)

    monkeypatch.setattr(store_type, "_read_transaction", read)
    monkeypatch.setattr(store_type, "_attest_batch_snapshot", attest)
    monkeypatch.setattr(store_type, "_logical_node_status_batch_at", batch)
    ordered_ids = tuple(reversed(nodes))
    states = admin.commit_port.workflow_node_states("chunked", ordered_ids)
    assert tuple(state.node_id for state in states) == ordered_ids
    assert all(
        state.workflow_id == "chunked" and state.status == "ready" for state in states
    )
    assert len(connections) == len(attestations) == 1
    assert len(batches) == 10


@pytest.mark.parametrize("substitution", ["truncated", "reordered"])
def test_w6_full_status_client_rejects_incomplete_or_reordered_response(
    monkeypatch, substitution
):
    node_ids = tuple(_nodes(10000))
    response = [
        {
            "workflow_id": "w6",
            "node_id": node_id,
            "status": "ready",
            "version": 0,
            "attempt_id": None,
            "claimed_by": None,
            "artifact_id": None,
            "commit_id": None,
        }
        for node_id in node_ids
    ]
    client = object.__new__(_AuthorityExecutionChannel)
    client._rpc_lock = threading.RLock()
    client._workflow_profile = WorkflowProfile.W6_INDEPENDENT_10000
    poisoned = []

    def rpc(_self, operation, parameters):
        assert operation == "workflow_node_states"
        assert parameters == {"workflow_id": "w6", "node_ids": list(node_ids)}
        return response

    monkeypatch.setattr(_AuthorityExecutionChannel, "_rpc", rpc)
    monkeypatch.setattr(
        _AuthorityExecutionChannel, "_poison", lambda _self: poisoned.append(True)
    )
    assert (
        tuple(state.node_id for state in client.workflow_node_states("w6", node_ids))
        == node_ids
    )
    if substitution == "truncated":
        response.pop()
    else:
        response[-1], response[0] = response[0], response[-1]
    with pytest.raises(GovernanceBypassDenied):
        client.workflow_node_states("w6", node_ids)
    assert poisoned == [True]


def test_profile_transport_defaults_preserve_explicit_legacy_override(tmp_path):
    config = _config(tmp_path)
    assert config.max_frame_bytes == 1_048_576
    assert config.workflow_profile.max_nodes == 1000
    assert config.workflow_profile.control_timeout_seconds == 2.0
    legacy_override = replace(config, max_frame_bytes=2_097_152)
    assert legacy_override.max_frame_bytes == 2_097_152
    assert legacy_override.workflow_profile is WorkflowProfile.DEFAULT
    w6 = AuthorityChildConfig(
        database_path=config.database_path,
        authority=config.authority,
        key_source=config.key_source,
        workflow_profile=WorkflowProfile.W6_INDEPENDENT_10000,
    )
    assert w6.max_frame_bytes == 16_777_216
    assert w6.workflow_profile.max_nodes == 10000
    assert w6.workflow_profile.control_timeout_seconds == 30.0
    assert replace(w6, max_frame_bytes=1_048_576).max_frame_bytes == 1_048_576
    with pytest.raises(ValueError):
        replace(w6, max_frame_bytes=16_777_217)


@pytest.mark.parametrize(
    "field",
    [
        "admission_profile",
        "command_id",
        "action",
        "workflow_id",
        "store_id",
        "signature",
        "row_command_id",
        "row_expected_control_version",
        "row_resulting_control_version",
    ],
)
def test_persisted_admission_requires_authentic_signed_command(tmp_path, field):
    path = tmp_path / "tampered.db"
    bootstrap = _bootstrap(WorkflowProfile.W6_INDEPENDENT_10000)
    admin = bootstrap.provision(path)
    admin.create_workflow(workflow_id="small-w6", nodes=_nodes(2), policy_version="1")
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT command_id, command_material FROM gcb_control_events"
        ).fetchone()
        material = json.loads(row[1])
        if field.startswith("row_"):
            column = field.removeprefix("row_")
            value = "tampered-row" if column == "command_id" else 42
            connection.execute(
                f"UPDATE gcb_control_events SET {column}=? WHERE command_id=?",
                (value, row[0]),
            )
        elif field == "admission_profile":
            material["parameters"][field] = WorkflowProfile.DEFAULT.value
        else:
            material[field] = "tampered"
        if not field.startswith("row_"):
            connection.execute(
                "UPDATE gcb_control_events SET command_material=? WHERE command_id=?",
                (json.dumps(material), row[0]),
            )
    reopen = (
        _bootstrap(WorkflowProfile.DEFAULT)
        if field == "admission_profile"
        else bootstrap
    )
    with pytest.raises((GovernanceBypassDenied, ValueError)):
        reopen.open_admin(path)


def test_signed_legacy_admission_without_profile_reopens_as_default(
    tmp_path, monkeypatch
):
    path = tmp_path / "legacy.db"
    bootstrap = _bootstrap(WorkflowProfile.DEFAULT)
    admin = bootstrap.provision(path)
    admin._command(
        ControlAction.CREATE_WORKFLOW,
        "legacy",
        {"nodes": {"root": []}, "policy_version": "1"},
    )
    future_ms = bootstrap.runtime.clock.now_ms() + 3_600_000
    monkeypatch.setattr(bootstrap.runtime.clock, "now_ms", lambda: future_ms)
    reopened = bootstrap.open_admin(path)
    assert reopened.node_state("legacy", "root").status == "ready"
    with sqlite3.connect(path) as connection:
        material = json.loads(
            connection.execute(
                "SELECT command_material FROM gcb_control_events"
            ).fetchone()[0]
        )
    assert "admission_profile" not in material["parameters"]


def test_w6_control_frame_accepts_exact_budget_and_rejects_one_extra_byte(tmp_path):
    config = replace(
        _config(tmp_path, WorkflowProfile.W6_INDEPENDENT_10000), max_frame_bytes=4096
    )
    authority = start_authority(config)
    client = authority.admin_client._client
    envelope = {
        "operation": "create_workflow",
        "request": {
            "workflow_id": "w",
            "nodes": {"root": []},
            "policy_version": "1",
            "required_capabilities": {},
            "input_digests": {},
        },
    }
    encoded = authority_service.canonical_json(envelope)
    envelope["request"]["workflow_id"] += "w" * (4096 - len(encoded))
    exact = authority_service.canonical_json(envelope)
    assert len(exact) == config.max_frame_bytes

    def verified(response, sequence, request_digest):
        return verify_response(
            response,
            public_key=Ed25519PublicKey.from_public_bytes(client._ipc_public_key),
            session=client._session,
            channel="admin",
            sequence=sequence,
            authority_pid=authority.pid,
            request_digest=request_digest,
        )

    try:
        accepted = _raw_channel_rpc(client, exact)
        _result, error = verified(accepted, 1, digest(envelope))
        assert error is None
        assert _workflow_rows(config.database_path, envelope["request"]["workflow_id"])[
            :2
        ] == (1, 1)
        envelope["request"]["workflow_id"] += "w"
        beyond = authority_service.canonical_json(envelope)
        assert len(beyond) == config.max_frame_bytes + 1
        rejected = _raw_channel_rpc(client, beyond)
        _result, error = verified(
            rejected, 2, digest({"invalid_frame": "frame_too_large", "sequence": 2})
        )
        assert error["code"] == "frame_too_large"
        assert _workflow_rows(
            config.database_path, envelope["request"]["workflow_id"]
        ) == (0, 0, 0)
        assert authority._execution_channel.health()["authority_pid"] == authority.pid
    finally:
        authority.close()
