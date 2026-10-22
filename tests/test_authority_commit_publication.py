"""Regression tests: a durable commit is never reported as failed.

The commit transaction writes the decision and its PENDING outbox row
atomically; outbox publication runs afterwards. Before this fix a publication
failure (a lock wait, a sink error) turned the reply into ``internal_error``
although the decision was already durable, and the executor's post-commit
projection refresh could do the same on a transport failure. Retrying such a
"failed" commit returns COMMITTED with no duplicate rows, so the caller was
misinformed rather than protected.
"""

from __future__ import annotations

import threading
import time
from dataclasses import replace

import pytest

from constitutional_swarm import authority_child, authority_service
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    GovernedCommitBoundary,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.authority_harness import (
    OutsideWriter,
    no_process_hardening,
    prepare_commit,
    read_key_bundle,
    recording_sink_class,
    start_in_thread_authority,
    store_counts,
    wait_until,
)
from tests.gcb_apcc_support import (
    InProcessExecutionClientHarness,
    authority_child_config,
    compose_test_executor,
    producer_key,
    provision_executor_workflow,
    typed_bootstrap,
)

_IN_THREAD_BUSY_MS = 1_000


def _start(tmp_path, monkeypatch, sink, *, config=None, raw=None):
    no_process_hardening(monkeypatch)
    monkeypatch.setattr(authority_child, "_DiscardSink", sink)
    if config is None:
        config = authority_child_config(
            tmp_path / "authority.db",
            tmp_path / "authority.keys",
            producers={"agent": producer_key("agent")},
        )
    raw = raw if raw is not None else read_key_bundle(config)
    authority = start_in_thread_authority(config, raw, busy_timeout_ms=_IN_THREAD_BUSY_MS)
    return authority, config, raw


def _lock_after_commit(monkeypatch, writer: OutsideWriter) -> None:
    """Take an outside write lock between the durable commit and publication."""
    original = GovernedCommitBoundary.commit

    def commit_then_lock(self, request):
        decision = original(self, request)
        writer.acquire()
        monkeypatch.setattr(GovernedCommitBoundary, "commit", original)
        return decision

    monkeypatch.setattr(GovernedCommitBoundary, "commit", commit_then_lock)


def test_lock_between_commit_and_publication_returns_committed(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config, _raw = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        _lock_after_commit(monkeypatch, writer)
        started = time.monotonic()
        decision = executor.commit(request)
        assert decision.outcome is CommitOutcome.COMMITTED
        assert time.monotonic() - started < authority_service._AUTHORITY_RPC_TIMEOUT_S
        counts = store_counts(config.database_path)
        assert counts["decisions"] == 1 and counts["commit_index"] == 1
        (event_id,) = counts["commit_events"]
        assert event_id not in sink.events
        assert counts["outbox"].get("PENDING", 0) >= 1
        assert authority.is_alive(), authority.failures
        writer.release()
        assert wait_until(lambda: event_id in sink.events, 15.0)
        assert wait_until(
            lambda: set(store_counts(config.database_path)["outbox"]) == {"DELIVERED"}, 5.0
        )
        assert sink.events.count(event_id) == 1
        assert executor.is_complete is True
        assert authority.is_alive() and authority.failures == []
    finally:
        writer.release()
        authority.close()


def test_sink_failure_after_commit_replies_committed_then_fails_closed(
    tmp_path, monkeypatch
) -> None:
    sink = recording_sink_class()
    authority, config, _raw = _start(tmp_path, monkeypatch, sink)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        sink.fail = True
        decision = executor.commit(request)
        # The caller learns the true, durable outcome first ...
        assert decision.outcome is CommitOutcome.COMMITTED
        counts = store_counts(config.database_path)
        assert counts["decisions"] == 1
        # ... and the authority then stops, exactly as a fatal tick would.
        authority.thread.join(5.0)
        assert not authority.is_alive()
        assert len(authority.failures) == 1
        failure = authority.failures[0]
        assert isinstance(failure, authority_service.AuthorityOutboxRecoveryError)
        assert isinstance(failure.__cause__, RuntimeError)
        assert set(store_counts(config.database_path)["outbox"]) <= {"PENDING", "DELIVERED"}
        assert store_counts(config.database_path)["outbox"].get("PENDING", 0) >= 1
    finally:
        authority.close()


def test_failure_before_commit_still_fails_without_a_decision(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config, _raw = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        writer.acquire()
        try:
            outcome = executor.commit(request)
        except GovernanceBypassDenied as exc:
            assert str(exc) != "authority_unavailable"
        else:
            assert outcome.outcome is CommitOutcome.DENIED
            assert outcome.reason == "persistence_error"
        assert store_counts(config.database_path)["decisions"] == 0
        assert authority.is_alive(), authority.failures
        writer.release()
        retried = authority.execution.commit(request)
        assert retried.outcome is CommitOutcome.COMMITTED
        assert store_counts(config.database_path)["decisions"] == 1
    finally:
        writer.release()
        authority.close()


def test_acknowledgement_failure_redelivers_at_most_once_after_lease(
    tmp_path, monkeypatch
) -> None:
    class SkewableClock:
        offset_ms = 0

        def now_ms(self) -> int:
            return int(time.time() * 1000) + SkewableClock.offset_ms

    monkeypatch.setattr(authority_child, "_Clock", SkewableClock)
    sink = recording_sink_class()
    authority, config, _raw = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    lock_once = threading.Event()

    def lock_before_finalize(_event_id: str) -> None:
        if not lock_once.is_set():
            lock_once.set()
            writer.acquire()

    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        sink.events.clear()
        sink.after_deliver = lock_before_finalize
        decision = executor.commit(request)
        assert decision.outcome is CommitOutcome.COMMITTED
        assert lock_once.is_set()
        (event_id,) = store_counts(config.database_path)["commit_events"]
        assert sink.events == [event_id]
        assert store_counts(config.database_path)["outbox"].get("CLAIMED") == 1
        writer.release()
        time.sleep(2.5)  # recovery ticks run but the 30 s lease still holds
        assert sink.events == [event_id]
        assert authority.is_alive(), authority.failures
        SkewableClock.offset_ms = 31_000
        assert wait_until(lambda: sink.events.count(event_id) == 2, 10.0)
        assert wait_until(
            lambda: set(store_counts(config.database_path)["outbox"]) == {"DELIVERED"}, 5.0
        )
        time.sleep(1.5)
        assert sink.events.count(event_id) == 2  # at-least-once, at most once more
        assert authority.admin.health()["outbox_recovery"] == "ok"
        assert authority.is_alive() and authority.failures == []
    finally:
        writer.release()
        authority.close()


def test_restart_delivers_pending_event_once_and_retry_is_idempotent(
    tmp_path, monkeypatch
) -> None:
    sink = recording_sink_class()
    first, config, raw = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    try:
        executor, request = prepare_commit(first, producer_key("agent"))
        _lock_after_commit(monkeypatch, writer)
        assert executor.commit(request).outcome is CommitOutcome.COMMITTED
        (event_id,) = store_counts(config.database_path)["commit_events"]
        first.close()
        assert not first.is_alive()
    finally:
        writer.release()
        first.close()
    assert event_id not in sink.events
    second, _config, _raw = _start(
        tmp_path, monkeypatch, sink, config=replace(config, provision=False), raw=raw
    )
    try:
        assert sink.events.count(event_id) == 1  # delivered by boot recovery
        retried = second.execution.commit(request)
        assert retried.outcome is CommitOutcome.COMMITTED
        counts = store_counts(config.database_path)
        assert counts["decisions"] == 1 and counts["commit_index"] == 1
        assert counts["commit_events"] == [event_id]
        assert set(counts["outbox"]) == {"DELIVERED"}
        time.sleep(1.5)
        assert sink.events.count(event_id) == 1
        assert second.is_alive() and second.failures == []
    finally:
        second.close()


# --------------------------------------------------------------------------
# SwarmExecutor post-commit refresh
# --------------------------------------------------------------------------


class _FlakyRefreshClient:
    """Delegate to a real execution client; fail only the post-commit refresh."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.refresh_failure: BaseException | None = None
        self.refresh_result = None
        self.before_refresh = None

    def __getattr__(self, name: str):
        return getattr(self._inner, name)

    def workflow_node_states(self, workflow_id, node_ids):
        if self.before_refresh is not None:
            hook, self.before_refresh = self.before_refresh, None
            hook()
        if self.refresh_failure is not None:
            failure, self.refresh_failure = self.refresh_failure, None
            raise failure
        if self.refresh_result is not None:
            result, self.refresh_result = self.refresh_result, None
            return result
        return self._inner.workflow_node_states(workflow_id, node_ids)


def _in_process_commit(tmp_path):
    key = producer_key("agent")
    bootstrap = typed_bootstrap(policy_versions=(("1", 1),), producers={"agent": key})
    admin = bootstrap.provision(tmp_path / "executor.db")
    dag = (
        TaskDAG(dag_id="wf")
        .add_node(TaskNode(node_id="root"))
        .add_node(TaskNode(node_id="child", depends_on=["root"]))
    )
    provision_executor_workflow(admin, dag, policy_version="1")
    admin.register_agent(
        workflow_id="wf", agent_id="agent", public_key=key.public_key(), capabilities=()
    )
    client = _FlakyRefreshClient(InProcessExecutionClientHarness(admin))
    client.admin = admin
    executor = compose_test_executor(
        CapabilityRegistry(), ArtifactStore(), client, policy_version="1"
    )
    executor.load_dag(dag)
    authorization = sign_attempt_authorization(executor.prepare_claim("root", "agent"), key)
    executor.claim("root", "agent", authorization)
    payload = executor.produce_result(
        "root",
        Artifact("artifact", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    request = admin.build_request(sign_governed_receipt(payload, key))
    return executor, client, request


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(ConnectionResetError(104, "reset"), id="transport"),
        pytest.param(GovernanceBypassDenied("authority_unavailable"), id="unavailable"),
        pytest.param(GovernanceBypassDenied("internal_error"), id="error-reply"),
    ],
)
def test_executor_commit_survives_failed_projection_refresh(tmp_path, failure) -> None:
    executor, client, request = _in_process_commit(tmp_path)
    client.refresh_failure = failure
    decision = executor.commit(request)
    assert decision.outcome is CommitOutcome.COMMITTED
    assert client.refresh_failure is None  # the refresh really ran and failed
    # The projection resynchronizes lazily from the authority on next read.
    assert executor.progress.get("governed_committed") == 1
    assert [node.node_id for node in executor.available_tasks("agent")] == ["child"]
    assert executor.is_complete is False


def test_executor_commit_still_raises_on_refresh_integrity_mismatch(tmp_path) -> None:
    executor, client, request = _in_process_commit(tmp_path)
    client.refresh_result = ()
    with pytest.raises(GovernanceBypassDenied, match="authority_status_batch_length_mismatch"):
        executor.commit(request)


def test_executor_commit_returns_committed_when_revoked_before_refresh(tmp_path) -> None:
    executor, client, request = _in_process_commit(tmp_path)
    # Another request revokes the node between the commit and the refresh.
    client.before_refresh = lambda: client.admin.revoke_root(
        workflow_id="wf", node_id="root", event_id="revoke", reason="operator"
    )
    decision = executor.commit(request)
    assert decision.outcome is CommitOutcome.COMMITTED
    assert client.before_refresh is None  # the revocation really landed first
    replay = client._inner.commit(request)
    assert replay.outcome is CommitOutcome.COMMITTED
    assert executor.available_tasks("agent") == []
