"""Real spawned renewal boundaries; small fixtures are never qualification."""

from dataclasses import replace
import os
import time

import pytest

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.observation import encode_signed_authority_observation
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc_empirical.w2_renewal_runtime import (
    W2RenewalConfig,
    start_w2_renewal_authority,
)
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    sign_attempt_authorization,
    sign_governed_receipt,
    CommitOutcome,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    authority_child_config,
    producer_key,
    provision_executor_workflow,
)
from tests.test_apcc_observation import _observer_launch
from tests.test_apcc_observation_target import _nonce


def _start(tmp_path, *, maximum_renewals=2, plan_builder=None, on_spawn=None):
    key = producer_key("agent")
    child = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys", producers={"agent": key}
    )
    child = replace(
        child,
        authority=replace(
            child.authority, causal_profile=AuthorityCausalProfile.W2_LINEAR_100
        ),
    )
    launch = replace(_observer_launch(child, tmp_path), launch_lifetime_ms=60_000)
    config = W2RenewalConfig(
        sha256_digest(b"placeholder"),
        str(tmp_path / "journal" / "renewal.jsonl"),
        "rep-1",
        launch.controller_key_source.expected_public_key,
        launch.experiment_id,
        launch.run_id,
        maximum_renewals=maximum_renewals,
        maximum_total_lifetime_ms=(maximum_renewals + 1) * 60_000,
        maximum_single_launch_ms=60_000,
        handover_timeout_ms=10_000,
    )
    prepared = []

    def freeze(info):
        prepared.append(info)
        return sha256_digest(b"frozen-plan")

    service = start_w2_renewal_authority(
        child, config, launch, plan_builder=plan_builder or freeze, on_spawn=on_spawn
    )
    if plan_builder is None:
        assert prepared[0]["renewal_key_id"].startswith("renewal-")
    return service, key


def _operation(service, execution, key, workflow):
    dag = TaskDAG(dag_id=workflow).add_node(TaskNode(node_id="root"))
    provision_executor_workflow(service.admin_client, dag, policy_version="1")
    service.admin_client.register_agent(
        workflow_id=workflow, agent_id="agent", public_key=key.public_key()
    )
    with (
        execution.w2_epoch(service.epoch, service.config.plan_digest),
        execution.w2_lane(0),
    ):
        execution.check_w2_admission_epoch()
        execution.load_dag(dag)
        authorization = sign_attempt_authorization(
            execution.prepare_claim("root", "agent"), key
        )
        execution.claim("root", "agent", authorization)
        payload = execution.produce_result(
            "root",
            Artifact("artifact", "root", "agent", "text", "payload"),
            authorization=authorization,
        )
        request = execution.build_request(sign_governed_receipt(payload, key))
        assert execution.commit(request).outcome is CommitOutcome.COMMITTED
        target = execution.observation_target(request, request_nonce=_nonce(workflow))
        return service.observer.client.observe(target)


def test_real_two_epochs_reject_stale_and_unwrapped_requests(tmp_path):
    service, key = _start(tmp_path)
    try:
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        first = _operation(service, execution, key, "first")
        prior_pid = service.observer.pid
        result = service.renew(
            final_observation=encode_signed_authority_observation(first),
            ledger_digest=sha256_digest(b"ledger"),
            ledger_seal_digest=sha256_digest(b"seal"),
            launch_lifetime_ms=60_000,
        )
        assert service.epoch == 1
        assert service.observer.pid != prior_pid
        assert result["continuity"]
        repeated = service.renew(
            final_observation=encode_signed_authority_observation(first),
            ledger_digest=sha256_digest(b"ledger"),
            ledger_seal_digest=sha256_digest(b"seal"),
            launch_lifetime_ms=60_000,
        )
        assert repeated == result
        with pytest.raises(ProcessLookupError):
            os.kill(prior_pid, 0)
        with execution.w2_epoch(0, service.config.plan_digest):
            with pytest.raises(GovernanceBypassDenied):
                execution.check_w2_admission_epoch()
        with pytest.raises(GovernanceBypassDenied):
            service.authority.admin_client.health()
        second = _operation(service, execution, key, "second")
        assert second.session_id != first.session_id
        assert len(service.evidence()["records"]) == 5
    finally:
        pids = service.owned_pids[:]
        service.close()
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_observer_crash_is_fatal_before_retirement(tmp_path):
    service, _ = _start(tmp_path)
    try:
        service.observer.close()
        assert service.authority.controlled_boot.phase == "failed"
        with pytest.raises(GovernanceBypassDenied):
            service.admin_client.health()
    finally:
        service.close()


def _drain(service, final):
    from constitutional_swarm.apcc.crypto import b64u_encode
    from constitutional_swarm.authority_ipc import canonical_json

    with service._admission_condition:
        service._fencing = True

    tail = service.observer.client._rpc(
        "w2_seal_tail_v1", {"nonce": _nonce("test-tail")}
    )

    return service._control(
        "drain",
        {
            "final_observation": b64u_encode(
                encode_signed_authority_observation(final)
            ),
            "ledger_digest": sha256_digest(b"ledger"),
            "ledger_seal_digest": sha256_digest(b"seal"),
            "observer_tail": b64u_encode(canonical_json(tail)),
        },
    )


def test_drained_epoch_fences_execution_admin_and_old_status(tmp_path):
    service, key = _start(tmp_path)
    try:
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        final = _operation(service, execution, key, "first")
        _drain(service, final)
        with pytest.raises(GovernanceBypassDenied):
            service.admin_client.health()
        with execution.w2_epoch(service.epoch, service.config.plan_digest):
            with pytest.raises(GovernanceBypassDenied):
                execution.check_w2_admission_epoch()
        with pytest.raises(GovernanceBypassDenied):
            service.observer.client.observe(final.snapshot.request)
        assert service.evidence()["records"][-1]["body"]["state"] == "DRAINED"
    finally:
        service.close()


def test_future_status_endpoint_cannot_sign_before_activation(tmp_path):
    service, _ = _start(tmp_path)
    try:
        endpoint = service.authority._w2_renewal["status"][0]
        with pytest.raises(
            GovernanceBypassDenied, match="retired_or_unprepared_status_epoch"
        ):
            endpoint.current_status(sha256_digest(b"unknown"), _nonce("unknown"))
    finally:
        service.close()


def test_claimed_incomplete_workflow_prevents_drain(tmp_path):
    service, key = _start(tmp_path)
    try:
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        final = _operation(service, execution, key, "complete")
        dag = TaskDAG(dag_id="incomplete").add_node(TaskNode(node_id="root"))
        provision_executor_workflow(service.admin_client, dag, policy_version="1")
        service.admin_client.register_agent(
            workflow_id=dag.dag_id, agent_id="agent", public_key=key.public_key()
        )
        with (
            execution.w2_epoch(service.epoch, service.config.plan_digest),
            execution.w2_lane(1),
        ):
            execution.load_dag(dag)
            auth = sign_attempt_authorization(
                execution.prepare_claim("root", "agent"), key
            )
            execution.claim("root", "agent", auth)
        # Refresh an independently signed final proof after the extra mutation.
        final = service.observer.client.observe(final.snapshot.request)
        with pytest.raises(GovernanceBypassDenied, match="complete admitted workflow"):
            _drain(service, final)
        assert service.evidence()["records"][-1]["body"]["state"] == "ACTIVE"
    finally:
        service.close()


@pytest.mark.parametrize("role", ["authority", "scheduler", "observer", "controller"])
def test_owned_child_crash_revokes_whole_session(tmp_path, role):
    service, _ = _start(tmp_path)
    process = {
        "authority": service.authority._process,
        "scheduler": service.authority._scheduler_worker.process,
        "observer": service.observer._process,
        "controller": service.signer.process,
    }[role]
    pids = service.owned_pids[:]
    try:
        process.kill()
        deadline = time.monotonic() + 5
        while (
            service.authority.controlled_boot.phase != "failed"
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert service.authority.controlled_boot.phase == "failed"
        with pytest.raises(GovernanceBypassDenied):
            service.admin_client.health()
    finally:
        service.close()
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_tampered_side_journal_fences_epoch_without_sqlite_mutation(tmp_path):
    service, _ = _start(tmp_path)
    try:
        path = tmp_path / "journal" / "renewal.jsonl"
        original = path.read_bytes()
        path.write_bytes(original[:-1])
        with pytest.raises(GovernanceBypassDenied, match="renewal journal"):
            service.admin_client.health()
        path.write_bytes(original)
        with pytest.raises(GovernanceBypassDenied, match="terminally fenced"):
            service.admin_client.health()
    finally:
        service.close()


def test_older_consumable_observation_cannot_close_newer_tail(tmp_path):
    service, key = _start(tmp_path)
    try:
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        old = _operation(service, execution, key, "first")
        # Different nonce makes the new authority-issued status unambiguous.
        request = replace(old.snapshot.request, request_nonce=_nonce("newer-tail"))
        service.observer.client.observe(request)
        with pytest.raises(GovernanceBypassDenied, match="tail binding mismatch"):
            _drain(service, old)
    finally:
        service.close()


def test_idempotent_control_nonce_and_changed_body_rejection(tmp_path):
    service, key = _start(tmp_path)
    try:
        from constitutional_swarm.apcc.crypto import b64u_encode
        from constitutional_swarm.authority_ipc import canonical_json

        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        final = _operation(service, execution, key, "first")
        tail = service.observer.client._rpc(
            "w2_seal_tail_v1", {"nonce": _nonce("test-tail")}
        )
        body = {
            "final_observation": b64u_encode(
                encode_signed_authority_observation(final)
            ),
            "ledger_digest": sha256_digest(b"ledger"),
            "ledger_seal_digest": sha256_digest(b"seal"),
            "observer_tail": b64u_encode(canonical_json(tail)),
        }
        with service._admission_condition:
            service._fencing = True
        first = service._control("drain", body, request_id="stable-drain")
        assert service._control("drain", body, request_id="stable-drain") == first
        assert len(service.evidence()["records"]) == 2
        with pytest.raises(GovernanceBypassDenied, match="changed body"):
            service._control(
                "drain",
                {**body, "ledger_digest": sha256_digest(b"changed")},
                request_id="stable-drain",
            )
    finally:
        service.close()


@pytest.mark.parametrize("stage", ["drain", "prepare", "retire"])
def test_interrupted_handover_is_terminal_and_children_close(
    tmp_path, monkeypatch, stage
):
    import json

    service, key = _start(tmp_path)
    execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
    final = _operation(service, execution, key, "first")
    original = service._control

    def interrupted(operation, request, **kwargs):
        result = original(operation, request, **kwargs)
        if operation == stage:
            raise KeyboardInterrupt("cancelled after durable transition")
        return result

    monkeypatch.setattr(service, "_control", interrupted)
    pids = service.owned_pids[:]
    with pytest.raises(KeyboardInterrupt):
        service.renew(
            final_observation=encode_signed_authority_observation(final),
            ledger_digest=sha256_digest(b"ledger"),
            ledger_seal_digest=sha256_digest(b"seal"),
            launch_lifetime_ms=60_000,
        )
    records = [
        json.loads(line)
        for line in (tmp_path / "journal" / "renewal.jsonl").read_bytes().splitlines()
    ]
    assert records[-1]["body"]["state"] == "FAILED"
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_five_real_epochs_preserve_authority_and_exhaust_renewal_budget(tmp_path):
    service, key = _start(tmp_path, maximum_renewals=4)
    pids = []
    try:
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
        authority_pid, execution_pid = service.authority.pid, execution.pid
        for epoch in range(5):
            final = _operation(service, execution, key, f"epoch-{epoch}")
            assert (
                service.authority.pid == authority_pid
                and execution.pid == execution_pid
            )
            pids.append(service.observer.pid)
            if epoch < 4:
                service.renew(
                    final_observation=encode_signed_authority_observation(final),
                    ledger_digest=sha256_digest(f"ledger-{epoch}".encode()),
                    ledger_seal_digest=sha256_digest(b"seal"),
                    launch_lifetime_ms=60_000,
                )
        assert len(set(pids)) == 5
        assert len(service.evidence()["records"]) == 17
        with pytest.raises(
            (ValueError, GovernanceBypassDenied), match="budget exhausted"
        ):
            service.renew(
                final_observation=encode_signed_authority_observation(final),
                ledger_digest=sha256_digest(b"over-budget"),
                ledger_seal_digest=sha256_digest(b"seal"),
                launch_lifetime_ms=60_000,
            )
    finally:
        all_pids = service.owned_pids[:]
        service.close()
    for pid in all_pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_plan_freeze_failure_closes_bootstrapped_children(tmp_path):
    import multiprocessing

    prior = {p.pid for p in multiprocessing.active_children()}

    def fail(_info):
        raise ValueError("external plan freeze failed")

    with pytest.raises(ValueError, match="external plan freeze failed"):
        _start(tmp_path, plan_builder=fail)
    assert {p.pid for p in multiprocessing.active_children()} == prior
    assert not (tmp_path / "journal").exists()


@pytest.mark.parametrize("kind", ["monotonic", "wall"])
def test_owner_clock_gate_irreversibly_rejects_expiry_or_rollback(monkeypatch, kind):
    from types import SimpleNamespace
    from constitutional_swarm.apcc_empirical.w2_renewal_runtime import _RenewalOwner

    owner = _RenewalOwner.__new__(_RenewalOwner)
    owner.config = SimpleNamespace(maximum_total_lifetime_ms=1000)
    owner.monotonic_origin = 0
    owner.highest_wall_ms = 5000
    owner.failed = False
    monkeypatch.setattr(
        time, "monotonic_ns", lambda: 1_000_000_000 if kind == "monotonic" else 10
    )
    monkeypatch.setattr(time, "time", lambda: 5.0 if kind == "monotonic" else 4.0)
    with pytest.raises(ValueError, match="rollback or lifetime exhausted"):
        owner._clock_gate()
    assert owner.failed


@pytest.mark.parametrize("crossing", ["checkpoint", "active_fsync"])
def test_activation_expiring_during_checkpoint_or_fsync_stays_fenced(
    tmp_path, monkeypatch, crossing
):
    from types import SimpleNamespace as N
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from constitutional_swarm.apcc_empirical import w2_renewal_runtime as runtime
    from constitutional_swarm.apcc_empirical.w2_renewal_journal import RenewalJournal

    journal = RenewalJournal.create(
        tmp_path / "journal" / "records",
        Ed25519PrivateKey.generate(),
        key_id="test",
        context={
            "authority_store_id": "s",
            "authority_session_id": "a",
            "repetition_id": "r",
        },
        plan_digest=sha256_digest(b"plan"),
        not_before_ms=1000,
        expires_at_ms=2000,
        maximum_total_lifetime_ms=4000,
        maximum_renewals=1,
    )
    for state, stamp in [("DRAINED", 1500), ("PREPARED", 1600), ("RETIRED", 1700)]:
        journal.transition(state, 0, state, {}, now_ms=stamp)
    owner = runtime._RenewalOwner.__new__(runtime._RenewalOwner)
    owner.config = N(
        maximum_total_lifetime_ms=4000, handover_timeout_ms=1000, maximum_renewals=1
    )
    owner.monotonic_origin = 1_000_000_000
    owner.highest_wall_ms, owner.start_ms, owner.epoch = 1700, 1000, 0
    owner.failed, owner.journal, owner.handover_start = False, journal, 1.7
    owner.control_replies = {}
    owner.checkpoint, owner.prepared_continuity = "checkpoint", b"continuity"
    owner.launch = N(not_before_ms="1000", not_after_ms="2000")
    successor = N(
        not_before_ms="1800",
        not_after_ms="3000",
        initial_trust_sequence="0",
        initial_trust_head="head",
        canonical_digest=sha256_digest(b"launch"),
    )
    owner.prepared_launch = successor
    owner._verify_launch = lambda _raw: successor
    clock = [1.999]

    def checkpoint():
        if crossing == "checkpoint":
            clock[0] = 2.001
        return "checkpoint", "0", "head"

    owner._checkpoint = checkpoint
    original = journal.transition

    def transition(state, *args, **kwargs):
        result = original(state, *args, **kwargs)
        if state == "ACTIVE" and crossing == "active_fsync":
            clock[0] = 2.001
        return result

    monkeypatch.setattr(journal, "transition", transition)
    monkeypatch.setattr(time, "time", lambda: clock[0])
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "monotonic_ns", lambda: int(clock[0] * 1e9))
    try:
        with pytest.raises(ValueError, match="activation validity exhausted"):
            owner.control(
                {
                    "operation": "activate",
                    "request": {"request_id": "activate", "body": {"launch": "unused"}},
                }
            )
        assert owner.failed
        assert journal.records()[-1]["body"]["state"] == "FAILED"
        with pytest.raises(ValueError):
            owner._gate(1)
    finally:
        journal.close()


def test_failed_successor_bootstrap_is_in_public_spawn_lineage(tmp_path, monkeypatch):
    from constitutional_swarm import authority_service

    events = []
    service, key = _start(
        tmp_path, on_spawn=lambda role, pid: events.append((role, pid))
    )
    execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
    final = _operation(service, execution, key, "first")
    original = authority_service._verify_hardened_ready

    def fail(ready, pid, role):
        if role == "observer":
            raise ValueError("injected successor startup failure")
        return original(ready, pid, role)

    monkeypatch.setattr(authority_service, "_verify_hardened_ready", fail)
    with pytest.raises(ValueError, match="successor startup failure"):
        service.renew(
            final_observation=encode_signed_authority_observation(final),
            ledger_digest=sha256_digest(b"ledger"),
            ledger_seal_digest=sha256_digest(b"seal"),
            launch_lifetime_ms=60_000,
        )
    assert [role for role, _ in events] == [
        "scheduler",
        "authority",
        "controller",
        "observer-0",
        "observer-1",
    ]
    assert set(service.owned_pids) == {pid for _, pid in events}
    for _, pid in events:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_renewal_waits_for_admission_clock_and_actual_proof_permit_release(
    tmp_path, monkeypatch
):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from constitutional_swarm.apcc_empirical.w2_renewal_campaign import EpochWorkerPool

    service, key = _start(tmp_path)
    execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")
    final = _operation(service, execution, key, "first")
    pool = EpochWorkerPool(
        execution,
        lambda: execution.w2_epoch(service.epoch, service.config.plan_digest),
        admission_scope=service.admission_scope,
        begin_admission=service.begin_admission,
        end_admission=service.end_admission,
    )
    clock_entered, clock_release = threading.Event(), threading.Event()
    proof_release, renewal_waiting = threading.Event(), threading.Event()
    tail_seen = threading.Event()
    observer_type = type(service.observer.client)
    original_rpc = observer_type._rpc

    def rpc(client, operation, request):
        if operation == "w2_seal_tail_v1":
            tail_seen.set()
        return original_rpc(client, operation, request)

    monkeypatch.setattr(observer_type, "_rpc", rpc)
    original_wait = service._admission_condition.wait

    def wait(timeout=None):
        renewal_waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(service._admission_condition, "wait", wait)

    def clock():
        clock_entered.set()
        assert clock_release.wait(5)
        return 1

    def verify(_admitted):
        assert service.evidence()["records"][-1]["body"]["state"] == "ACTIVE"
        assert proof_release.wait(5)

    try:
        with ThreadPoolExecutor(max_workers=2) as threads:
            submitted = threads.submit(
                pool.submit_before, verify, deadline_ns=2, clock=clock
            )
            assert clock_entered.wait(5)
            renewal = threads.submit(
                service.renew,
                final_observation=encode_signed_authority_observation(final),
                ledger_digest=sha256_digest(b"ledger"),
                ledger_seal_digest=sha256_digest(b"seal"),
                launch_lifetime_ms=60_000,
            )
            assert not tail_seen.wait(0.05)
            clock_release.set()
            future = submitted.result(5)
            assert renewal_waiting.wait(5)
            assert not tail_seen.is_set()
            with pytest.raises(GovernanceBypassDenied, match="admission fenced"):
                with service.admission_scope():
                    pass
            proof_release.set()
            future.result(5)
            renewal.result(10)
            assert (
                tail_seen.is_set()
                and service.epoch == 1
                and service._admission_count == 0
            )
    finally:
        clock_release.set()
        proof_release.set()
        pool.close()
        service.close()
