"""Exact governed-request targets for the independently signed observer."""

from dataclasses import replace
import hashlib
import sqlite3
import time

import pytest

from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
)
from constitutional_swarm.apcc.verifier import ScopedTrust
from constitutional_swarm.authority_service import (
    _AuthorityExecutionChannel,
    _SwarmExecutionHandle,
    _encode_commit_request,
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    DetachedSigner,
    PolicySigner,
    authority_child_config,
    canonical_nonce,
    producer_key,
    provision_executor_workflow,
)
from tests.test_apcc_authority_service import _provision, _request, _stage
from tests.test_apcc_observation import _launch_expectations, _observer_launch


def _nonce(label):
    return b64u_encode(hashlib.sha256(label.encode()).digest()[:16])


def _database_snapshot(path):
    with sqlite3.connect(path) as connection:
        return tuple(connection.iterdump())


@pytest.fixture
def spawned_request(tmp_path):
    key = producer_key("agent")
    config = authority_child_config(
        tmp_path / "target.db",
        tmp_path / "target.keys",
        producers={"agent": key},
    )
    authority = start_authority(config)
    observer = None
    try:
        launch_config = _observer_launch(config, tmp_path)
        observer = start_authority_observer(authority, launch_config)
        dag = TaskDAG(dag_id="wf").add_node(TaskNode(node_id="root"))
        provision_executor_workflow(authority.admin_client, dag, policy_version="1")
        authority.admin_client.register_agent(
            workflow_id="wf", agent_id="agent", public_key=key.public_key()
        )
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        executor.load_dag(dag)
        authorization = sign_attempt_authorization(
            executor.prepare_claim("root", "agent"), key
        )
        executor.claim("root", "agent", authorization)
        payload = executor.produce_result(
            "root",
            Artifact("artifact", "root", "agent", "text", "result"),
            authorization=authorization,
        )
        request = executor.build_request(sign_governed_receipt(payload, key))
        yield config, authority, executor, observer, request, launch_config
    finally:
        if observer is not None:
            observer.close()
        authority.close()


def test_spawned_observation_target_reaches_signed_observer_and_exact_replay(
    spawned_request,
):
    config, authority, executor, observer, request, launch_config = spawned_request
    assert authority.controlled_boot.publishable_evidence
    assert executor.commit(request).outcome is CommitOutcome.COMMITTED
    first = executor.observation_target(request, request_nonce=_nonce("target-first"))
    assert executor.commit(request).outcome is CommitOutcome.COMMITTED
    second = executor.observation_target(request, request_nonce=_nonce("target-second"))
    assert first.authority_store_id == config.authority.authority_store_id
    assert first.workflow_id == request.receipt.payload.workflow_id
    assert first.node_id == request.receipt.payload.node_id
    assert first.attempt_id == request.receipt.payload.attempt_id
    assert first.expected_commit_id == request.commit_id
    assert first.request_nonce != second.request_nonce
    assert replace(first, request_nonce=second.request_nonce) == second
    before = _database_snapshot(config.database_path)
    responses = [observer.client.observe(target) for target in (first, second)]
    assert all(
        response.snapshot.state is AuthorityObservationState.COMMITTED
        for response in responses
    )
    assert [response.snapshot.request for response in responses] == [first, second]
    launch = observer.launch_attestation
    stream = AuthorityObservationVerificationStream(launch.session_id)
    for response in responses:
        verified = stream.consume(
            response,
            launch=launch,
            pinned_controller_public_key=(
                launch_config.controller_key_source.expected_public_key
            ),
            expected_experiment_id=launch_config.experiment_id,
            expected_run_id=launch_config.run_id,
            expected_launch=_launch_expectations(launch),
            trust=ScopedTrust(config.authority.trust_bindings),
            now_ms=int(time.time() * 1000),
            maximum_staleness_ms=5000,
        )
        assert verified.consumable is True
        assert (
            verified.authority_proof
            is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
        )
        assert response.snapshot.output_bytes is not None
        assert (
            sha256_digest(response.snapshot.output_bytes)
            == request.receipt.payload.output_digest
        )
    assert stream.next_sequence == 3
    assert _database_snapshot(config.database_path) == before


def test_spawned_observation_target_requires_an_existing_committed_request(
    spawned_request,
):
    config, _, executor, _, request, _ = spawned_request
    before = _database_snapshot(config.database_path)
    with pytest.raises(GovernanceBypassDenied, match="observation_target_unavailable"):
        executor.observation_target(request, request_nonce=_nonce("uncommitted-target"))
    assert _database_snapshot(config.database_path) == before
    invalid = replace(request, receipt=request.receipt.replace(signature="invalid"))
    assert executor.commit(invalid).outcome is CommitOutcome.DENIED
    before = _database_snapshot(config.database_path)
    with pytest.raises(GovernanceBypassDenied, match="observation_target_unavailable"):
        executor.observation_target(invalid, request_nonce=_nonce("denied-target"))
    with sqlite3.connect(config.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM commit_index").fetchone() == (
            0,
        )
    assert _database_snapshot(config.database_path) == before


@pytest.mark.parametrize("field", ["nonce", "node_id", "workflow_id", "attempt_id"])
def test_spawned_observation_target_rejects_same_commit_id_wrong_request(
    spawned_request, field
):
    config, _, executor, _, request, _ = spawned_request
    assert executor.commit(request).outcome is CommitOutcome.COMMITTED
    payload = replace(
        request.receipt.payload,
        **{field: canonical_nonce("wrong-receipt") if field == "nonce" else "other"},
    )
    different = replace(request, receipt=request.receipt.replace(payload=payload))
    assert different.commit_id == request.commit_id
    before = _database_snapshot(config.database_path)
    with pytest.raises(
        GovernanceBypassDenied, match="observation_target_binding_mismatch"
    ):
        executor.observation_target(different, request_nonce=_nonce("wrong-target"))
    assert _database_snapshot(config.database_path) == before
    assert (
        executor.observation_target(
            request, request_nonce=_nonce("positive-control")
        ).expected_commit_id
        == request.commit_id
    )


def test_observation_target_does_not_rebuild_sign_or_mutate(tmp_path, monkeypatch):
    path = tmp_path / "read-only-target.db"
    key = producer_key()
    bootstrap, admin = _provision(path)
    _stage(admin, key)
    request = _request(bootstrap, admin, key)
    assert admin.commit(request).outcome is CommitOutcome.COMMITTED
    before = _database_snapshot(path)

    def forbidden(*args, **kwargs):
        pytest.fail("observation target attempted request construction or signing")

    monkeypatch.setattr(type(admin.commit_port), "_to_apcc_request", forbidden)
    monkeypatch.setattr(type(admin.commit_port), "_prepare_apcc_candidate", forbidden)
    monkeypatch.setattr(DetachedSigner, "sign", forbidden)
    monkeypatch.setattr(PolicySigner, "sign", forbidden)
    first = admin.commit_port.observation_target(
        request, request_nonce=_nonce("read-only-first")
    )
    second = admin.commit_port.observation_target(
        request, request_nonce=_nonce("read-only-second")
    )
    assert replace(first, request_nonce=second.request_nonce) == second
    assert _database_snapshot(path) == before


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE decisions SET request_hash='wrong'",
        "UPDATE decisions SET workflow_id='wrong'",
        "UPDATE decisions SET nonce='wrong'",
        "UPDATE commit_index SET request_json='{}'",
        "UPDATE commit_index SET request_digest='wrong'",
        "UPDATE request_index SET request_digest='wrong'",
        "DELETE FROM request_index",
    ],
)
def test_observation_target_refuses_corrupt_persisted_binding(tmp_path, sql):
    path = tmp_path / "corrupt-target.db"
    key = producer_key()
    bootstrap, admin = _provision(path)
    _stage(admin, key)
    request = _request(bootstrap, admin, key)
    assert admin.commit(request).outcome is CommitOutcome.COMMITTED
    assert (
        admin.commit_port.observation_target(
            request, request_nonce=_nonce("before-corruption")
        ).expected_commit_id
        == request.commit_id
    )
    with sqlite3.connect(path) as connection:
        connection.execute(sql)
    before = _database_snapshot(path)
    # Read attestation may reject corruption before target binding checks.
    with pytest.raises((GovernanceBypassDenied, ValueError)):
        admin.commit_port.observation_target(
            request, request_nonce=_nonce("after-corruption")
        )
    assert _database_snapshot(path) == before


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {"commit_request": {}, "request_nonce": "invalid"},
        {"commit_request": None, "request_nonce": _nonce("malformed")},
        {"commit_request": {}, "request_nonce": 7},
    ],
)
def test_spawned_observation_target_malformed_rpc_fails_without_state_changes(
    spawned_request, parameters
):
    config, _, executor, _, request, _ = spawned_request
    assert executor.commit(request).outcome is CommitOutcome.COMMITTED
    before = _database_snapshot(config.database_path)
    with pytest.raises((GovernanceBypassDenied, ValueError)):
        executor._rpc("observation_target", parameters)
    assert _database_snapshot(config.database_path) == before
    assert executor.health()["executor_pid"] == executor.pid


def test_spawned_observation_target_valid_request_bad_nonce_fails_closed(
    spawned_request,
):
    config, _, executor, _, request, _ = spawned_request
    assert executor.commit(request).outcome is CommitOutcome.COMMITTED
    before = _database_snapshot(config.database_path)
    for nonce in ("", "not-a-nonce", _nonce("valid") + "="):
        with pytest.raises((GovernanceBypassDenied, ValueError)):
            executor._rpc(
                "observation_target",
                {
                    "commit_request": _encode_commit_request(request),
                    "request_nonce": nonce,
                },
            )
    assert _database_snapshot(config.database_path) == before
    assert (
        executor.observation_target(
            request, request_nonce=_nonce("after-invalid-nonces")
        ).expected_commit_id
        == request.commit_id
    )


@pytest.mark.parametrize(
    "client_type", [_AuthorityExecutionChannel, _SwarmExecutionHandle]
)
def test_observation_target_clients_reject_substituted_response_identity(
    tmp_path, monkeypatch, client_type
):
    path = tmp_path / "response-target.db"
    key = producer_key()
    bootstrap, admin = _provision(path)
    _stage(admin, key)
    request = _request(bootstrap, admin, key)
    assert admin.commit(request).outcome is CommitOutcome.COMMITTED
    nonce = _nonce("response-target")
    target = admin.commit_port.observation_target(request, request_nonce=nonce)
    response = target.to_object()
    client = object.__new__(client_type)

    def substitute_response(_self, operation, parameters):
        assert operation == "observation_target"
        assert parameters["request_nonce"] == nonce
        return response

    monkeypatch.setattr(client_type, "_rpc", substitute_response)
    assert client.observation_target(request, request_nonce=nonce) == target
    for field in (
        "authority_store_id",
        "workflow_id",
        "node_id",
        "attempt_id",
        "expected_commit_id",
        "request_nonce",
    ):
        response = {
            **target.to_object(),
            field: _nonce("substituted") if field == "request_nonce" else "substituted",
        }
        with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
            client.observation_target(request, request_nonce=nonce)
    response = {**target.to_object(), "unexpected": "field"}
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        client.observation_target(request, request_nonce=nonce)
    response = target.to_object()
    assert client.observation_target(request, request_nonce=nonce) == target
