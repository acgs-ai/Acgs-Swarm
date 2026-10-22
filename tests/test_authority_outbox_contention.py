"""Regression tests: transient SQLite contention must not kill the authority.

The authority child retries outbox delivery on a timer. Before this fix a tick
that waited out the store's busy_timeout behind an outside writer raised, the
select loop re-raised, and the authority process died. A lock wait is now
classified: SQLITE_BUSY backs off and is reported through health; anything else
still fails closed.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from constitutional_swarm import authority_child, authority_service
from constitutional_swarm.apcc.ports import OutboxRecoveryResult
from constitutional_swarm.governance_errors import GovernanceBypassDenied
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
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    authority_child_config,
    producer_key,
    provision_executor_workflow,
)

# Foreground busy_timeout for in-thread authorities: shorter than the 5 s
# default so request-path lock waits fit comfortably inside these tests.
_IN_THREAD_BUSY_MS = 1_000


# --------------------------------------------------------------------------
# Classifier
# --------------------------------------------------------------------------


def _real_busy(tmp_path: Path) -> sqlite3.OperationalError:
    database = tmp_path / "busy.db"
    holder = sqlite3.connect(database, isolation_level=None)
    waiter = sqlite3.connect(database, isolation_level=None, timeout=0)
    try:
        holder.execute("BEGIN IMMEDIATE")
        try:
            waiter.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            return exc
        raise AssertionError("outside lock did not block")
    finally:
        holder.rollback()
        holder.close()
        waiter.close()


def _sqlite_error(kind: type, code: int | None) -> sqlite3.Error:
    error = kind("synthetic")
    if code is not None:
        error.sqlite_errorcode = code
    return error


def _wrapped(raiser) -> BaseException:
    def recover_outbox(_request) -> None:
        raiser()

    admin = SimpleNamespace(
        commit_port=SimpleNamespace(_apcc_store=SimpleNamespace(recover_outbox=recover_outbox))
    )
    try:
        authority_service._recover_outbox(admin)
    except BaseException as exc:
        return exc
    raise AssertionError("recovery did not fail")


def _raise(error: BaseException):
    def raiser() -> None:
        raise error

    return raiser


def _busy_masking_sink_failure(busy: sqlite3.OperationalError):
    def raiser() -> None:
        try:
            raise RuntimeError("outbox sink unavailable")
        except RuntimeError:
            raise busy

    return raiser


def test_classifier_accepts_only_unmasked_sqlite_busy(tmp_path) -> None:
    classify = authority_service._is_transient_contention
    busy = _real_busy(tmp_path)
    assert busy.sqlite_errorcode & 0xFF == sqlite3.SQLITE_BUSY
    assert classify(_wrapped(_raise(busy))) is True
    assert classify(_wrapped(_raise(_sqlite_error(sqlite3.OperationalError, 517)))) is True
    assert classify(_wrapped(_raise(_sqlite_error(sqlite3.OperationalError, 261)))) is True


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(lambda: _sqlite_error(sqlite3.OperationalError, 6), id="locked"),
        pytest.param(lambda: _sqlite_error(sqlite3.OperationalError, 10), id="ioerr"),
        pytest.param(lambda: _sqlite_error(sqlite3.OperationalError, 13), id="full"),
        pytest.param(lambda: _sqlite_error(sqlite3.OperationalError, 8), id="readonly"),
        pytest.param(lambda: _sqlite_error(sqlite3.DatabaseError, 11), id="corrupt"),
        pytest.param(lambda: _sqlite_error(sqlite3.DatabaseError, 26), id="notadb"),
        pytest.param(lambda: _sqlite_error(sqlite3.IntegrityError, 19), id="constraint"),
        pytest.param(lambda: _sqlite_error(sqlite3.OperationalError, None), id="no-code"),
        pytest.param(lambda: sqlite3.ProgrammingError("closed"), id="programming"),
        pytest.param(lambda: ValueError("checkpoint tampered"), id="checkpoint"),
        pytest.param(lambda: RuntimeError("outbox sink unavailable"), id="sink"),
    ],
)
def test_classifier_rejects_non_busy_failures(factory) -> None:
    assert authority_service._is_transient_contention(_wrapped(_raise(factory()))) is False


def test_classifier_rejects_sink_failure_masked_by_busy(tmp_path) -> None:
    error = _wrapped(_busy_masking_sink_failure(_real_busy(tmp_path)))
    assert isinstance(error.__cause__, sqlite3.OperationalError)
    assert authority_service._is_transient_contention(error) is False


def test_classifier_rejects_bare_busy_outside_recovery(tmp_path) -> None:
    assert authority_service._is_transient_contention(_real_busy(tmp_path)) is False


# --------------------------------------------------------------------------
# Busy-timeout scope
# --------------------------------------------------------------------------


def test_background_busy_timeout_is_scoped_and_default_unchanged(tmp_path) -> None:
    from constitutional_swarm.apcc import sqlite_store

    database = tmp_path / "scope.db"
    sqlite3.connect(database).close()
    connection = sqlite_store._connect(database)
    try:
        assert connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)
    finally:
        connection.close()
    writer = OutsideWriter(database)
    writer.acquire()
    try:
        with sqlite_store._scoped_busy_timeout(250):
            scoped = sqlite_store._connect(database)
        try:
            assert scoped.execute("PRAGMA busy_timeout").fetchone() == (250,)
            started = time.monotonic()
            with pytest.raises(sqlite3.OperationalError) as caught:
                scoped.execute("BEGIN IMMEDIATE")
            assert time.monotonic() - started < 2.0
            assert caught.value.sqlite_errorcode & 0xFF == sqlite3.SQLITE_BUSY
        finally:
            scoped.close()
    finally:
        writer.release()
    restored = sqlite_store._connect(database)
    try:
        assert restored.execute("PRAGMA busy_timeout").fetchone() == (5000,)
    finally:
        restored.close()


# --------------------------------------------------------------------------
# Recovery monitor
# --------------------------------------------------------------------------


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class _ScriptedStore:
    def __init__(self, busy: sqlite3.OperationalError) -> None:
        self.busy = busy
        self.failure: BaseException | None = busy
        self.timeouts: list[int] = []
        self.result = OutboxRecoveryResult("0", "0", "audit")

    def recover_outbox(self, _request) -> OutboxRecoveryResult:
        from constitutional_swarm.apcc import sqlite_store

        self.timeouts.append(sqlite_store._BUSY_TIMEOUT_MS.get())
        if self.failure is not None:
            raise self.failure
        return self.result


def _monitor_case(tmp_path):
    clock = _FakeClock()
    store = _ScriptedStore(_real_busy(tmp_path))
    admin = SimpleNamespace(commit_port=SimpleNamespace(_apcc_store=store))
    return authority_service._OutboxRecoveryMonitor(clock=clock), clock, store, admin


def test_monitor_backs_off_caps_escalates_once_and_resets(tmp_path, caplog) -> None:
    monitor, clock, store, admin = _monitor_case(tmp_path)
    assert monitor.health_fields() == {"outbox_recovery": "ok", "outbox_recovery_failures": 0}
    delays: list[float] = []
    caplog.set_level(logging.INFO, logger=authority_service.__name__)
    for attempt in range(1, 13):
        clock.now = monitor.next_due
        assert monitor.due()
        monitor.run(admin)
        delays.append(monitor.next_due - clock.now)
        assert monitor.health_fields()["outbox_recovery_failures"] == attempt
        expected = "escalated" if attempt >= 10 else "backing_off"
        assert monitor.health_fields()["outbox_recovery"] == expected
    assert delays == [1, 2, 4, 8, 16, 30, 30, 30, 30, 30, 30, 30]
    escalations = [
        record
        for record in caplog.records
        if record.levelno == logging.ERROR and "state=escalated" in record.getMessage()
    ]
    assert len(escalations) == 1
    assert store.timeouts and set(store.timeouts) == {250}

    store.failure = None
    clock.now = monitor.next_due
    monitor.run(admin)
    assert monitor.health_fields() == {"outbox_recovery": "ok", "outbox_recovery_failures": 0}
    assert monitor.next_due - clock.now == 1
    assert not monitor.due()


def test_monitor_reraises_non_transient_without_recording(tmp_path) -> None:
    monitor, clock, store, admin = _monitor_case(tmp_path)
    store.failure = ValueError("checkpoint tampered")
    clock.now = monitor.next_due
    with pytest.raises(authority_service.AuthorityOutboxRecoveryError) as caught:
        monitor.run(admin)
    assert isinstance(caught.value.__cause__, ValueError)
    assert monitor.health_fields() == {"outbox_recovery": "ok", "outbox_recovery_failures": 0}


def test_monitors_are_independent_per_run(tmp_path) -> None:
    first, clock, _store, admin = _monitor_case(tmp_path)
    clock.now = first.next_due
    first.run(admin)
    assert first.health_fields()["outbox_recovery_failures"] == 1
    assert authority_service._OutboxRecoveryMonitor().health_fields() == {
        "outbox_recovery": "ok",
        "outbox_recovery_failures": 0,
    }


# --------------------------------------------------------------------------
# Health wire contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"authority_pid": 1},
        {"authority_pid": 1, "outbox_recovery": "ok"},
        {"authority_pid": 1, "outbox_recovery": "ok", "outbox_recovery_failures": True},
        {"authority_pid": 1, "outbox_recovery": "ok", "outbox_recovery_failures": -1},
        {"authority_pid": 1, "outbox_recovery": "ok", "outbox_recovery_failures": "0"},
        {"authority_pid": 1, "outbox_recovery": "degraded", "outbox_recovery_failures": 0},
        {"authority_pid": 1, "outbox_recovery": 0, "outbox_recovery_failures": 0},
        {"authority_pid": "1", "outbox_recovery": "ok", "outbox_recovery_failures": 0},
        {"authority_pid": 1, "outbox_recovery": "ok", "outbox_recovery_failures": 0, "x": 1},
        None,
    ],
)
def test_health_decoder_fails_closed_on_malformed_reply(body) -> None:
    with pytest.raises((GovernanceBypassDenied, ValueError)):
        authority_service._decode_authority_health(body)


def test_health_decoder_accepts_exact_reply() -> None:
    body = {"authority_pid": 7, "outbox_recovery": "backing_off", "outbox_recovery_failures": 3}
    assert authority_service._decode_authority_health(dict(body)) == body


# --------------------------------------------------------------------------
# In-thread authority under contention
# --------------------------------------------------------------------------


def _start(tmp_path, monkeypatch, *, sink=None, provision=True, raw=None, config=None):
    no_process_hardening(monkeypatch)
    if sink is not None:
        monkeypatch.setattr(authority_child, "_DiscardSink", sink)
    if config is None:
        config = authority_child_config(
            tmp_path / "authority.db",
            tmp_path / "authority.keys",
            producers={"agent": producer_key("agent")},
            provision=provision,
        )
    raw = raw if raw is not None else read_key_bundle(config)
    authority = start_in_thread_authority(config, raw, busy_timeout_ms=_IN_THREAD_BUSY_MS)
    return authority, config, raw


def _recovery_state(authority) -> str:
    return authority.admin.health()["outbox_recovery"]


def test_idle_authority_survives_contention_beyond_busy_timeout(tmp_path, monkeypatch) -> None:
    authority, config, _raw = _start(tmp_path, monkeypatch)
    writer = OutsideWriter(config.database_path)
    try:
        writer.acquire()
        assert wait_until(lambda: _recovery_state(authority) == "backing_off", 5.0)
        time.sleep(2.0)  # several background ticks, each well past its 250 ms wait
        health = authority.execution.health()
        assert authority.is_alive(), authority.failures
        assert health["outbox_recovery"] == "backing_off"
        assert health["outbox_recovery_failures"] >= 2
        writer.release()
        assert wait_until(lambda: _recovery_state(authority) == "ok", 15.0)
        assert authority.admin.health()["outbox_recovery_failures"] == 0
        assert authority.is_alive() and authority.failures == []
    finally:
        writer.release()
        authority.close()


def test_pending_events_are_delivered_once_contention_clears(tmp_path, monkeypatch) -> None:
    from constitutional_swarm.governed_commit import GovernedCommitBoundary

    sink = recording_sink_class()
    authority, config, _raw = _start(tmp_path, monkeypatch, sink=sink)
    writer = OutsideWriter(config.database_path)
    original_commit = GovernedCommitBoundary.commit

    def commit_then_lock(self, request):
        decision = original_commit(self, request)
        writer.acquire()
        return decision

    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        monkeypatch.setattr(GovernedCommitBoundary, "commit", commit_then_lock)
        try:
            executor.commit(request)
        except GovernanceBypassDenied:
            pass  # the reply contract is covered by the publication tests
        monkeypatch.setattr(GovernedCommitBoundary, "commit", original_commit)
        counts = store_counts(config.database_path)
        assert counts["decisions"] == 1
        pending = counts["commit_events"]
        assert len(pending) == 1 and counts["outbox"].get("PENDING", 0) >= 1
        assert pending[0] not in sink.events
        assert wait_until(lambda: _recovery_state(authority) == "backing_off", 5.0)
        assert authority.is_alive(), authority.failures
        writer.release()
        assert wait_until(lambda: _recovery_state(authority) == "ok", 15.0)
        assert wait_until(lambda: pending[0] in sink.events, 5.0)
        counts = store_counts(config.database_path)
        assert set(counts["outbox"]) == {"DELIVERED"}
        assert sink.events.count(pending[0]) == 1
        assert authority.is_alive() and authority.failures == []
    finally:
        writer.release()
        authority.close()


def test_boot_continues_to_readiness_under_contention(tmp_path, monkeypatch) -> None:
    from constitutional_swarm.governed_commit import TrustedGovernanceBootstrap

    first, config, raw = _start(tmp_path, monkeypatch)
    first.close()
    assert not first.is_alive()
    writer = OutsideWriter(config.database_path)
    original_open = TrustedGovernanceBootstrap.open_admin

    def open_then_lock(self, path, *args, **kwargs):
        admin = original_open(self, path, *args, **kwargs)
        writer.acquire()
        return admin

    monkeypatch.setattr(TrustedGovernanceBootstrap, "open_admin", open_then_lock)
    second, _config, _raw = _start(
        tmp_path, monkeypatch, raw=raw, config=replace(config, provision=False)
    )
    try:
        health = second.admin.health()
        assert health["outbox_recovery"] == "backing_off"
        assert health["outbox_recovery_failures"] >= 1
        writer.release()
        assert wait_until(lambda: _recovery_state(second) == "ok", 15.0)
        assert second.is_alive() and second.failures == []
    finally:
        writer.release()
        second.close()


def test_non_transient_recovery_failure_still_kills_authority(tmp_path, monkeypatch) -> None:
    from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore

    authority, _config, _raw = _start(tmp_path, monkeypatch)
    original = SQLiteAuthorityStore.recover_outbox
    tampered = threading.Event()

    def tampered_recovery(self, request):
        if tampered.is_set():
            raise ValueError("APCC authority mutation checkpoint mismatch")
        return original(self, request)

    monkeypatch.setattr(SQLiteAuthorityStore, "recover_outbox", tampered_recovery)
    try:
        tampered.set()
        authority.thread.join(10.0)
        assert not authority.is_alive()
        assert len(authority.failures) == 1
        failure = authority.failures[0]
        assert isinstance(failure, authority_service.AuthorityOutboxRecoveryError)
        assert isinstance(failure.__cause__, ValueError)
    finally:
        authority.close()


def test_requests_on_every_channel_are_answered_during_contention(
    tmp_path, monkeypatch
) -> None:
    authority, config, _raw = _start(tmp_path, monkeypatch)
    writer = OutsideWriter(config.database_path)
    outcomes: dict[str, tuple[float, object]] = {}

    def timed(label: str, call) -> None:
        started = time.monotonic()
        try:
            result: object = call()
        except BaseException as exc:
            result = exc
        outcomes[label] = (time.monotonic() - started, result)

    calls = {
        "execution-health": authority.execution.health,
        "admin-health": authority.admin.health,
        "admin-write": lambda: provision_executor_workflow(
            authority.admin,
            TaskDAG(dag_id="contended").add_node(TaskNode(node_id="root")),
            policy_version="1",
        ),
        "status": lambda: authority.status.current_status("sha256:" + "0" * 64, "0" * 32),
    }
    try:
        writer.acquire()
        assert wait_until(lambda: _recovery_state(authority) == "backing_off", 5.0)
        threads = [
            threading.Thread(target=timed, args=(label, call)) for label, call in calls.items()
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(authority_service._AUTHORITY_RPC_TIMEOUT_S + 5.0)
        assert set(outcomes) == set(calls)
        for label, (elapsed, result) in outcomes.items():
            assert elapsed < authority_service._AUTHORITY_RPC_TIMEOUT_S, label
            if isinstance(result, BaseException):
                # A signed fail-closed reply, never a dead or poisoned channel.
                assert isinstance(result, GovernanceBypassDenied), (label, result)
                assert str(result) != "authority_unavailable", label
        assert isinstance(outcomes["execution-health"][1], dict)
        assert isinstance(outcomes["admin-health"][1], dict)
        assert authority.is_alive(), authority.failures
        writer.release()
        assert wait_until(lambda: _recovery_state(authority) == "ok", 15.0)
        assert authority.execution.health()["outbox_recovery"] == "ok"
    finally:
        writer.release()
        authority.close()


def test_shutdown_during_contention_exits_promptly(tmp_path, monkeypatch) -> None:
    authority, config, _raw = _start(tmp_path, monkeypatch)
    writer = OutsideWriter(config.database_path)
    try:
        writer.acquire()
        assert wait_until(lambda: _recovery_state(authority) == "backing_off", 5.0)
        started = time.monotonic()
        authority.close(timeout=5.0)
        assert not authority.is_alive()
        assert time.monotonic() - started < 2.0
        assert authority.failures == []
    finally:
        writer.release()
        authority.close()


# --------------------------------------------------------------------------
# Spawned smoke
# --------------------------------------------------------------------------


def test_spawned_authority_survives_seven_second_outside_lock(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    database = tmp_path / "authority.db"
    authority = start_authority(authority_child_config(database, tmp_path / "authority.keys"))
    writer = OutsideWriter(database)
    try:
        writer.acquire()
        deadline = time.monotonic() + 7.0
        worst = 0.0
        states: set[str] = set()
        while time.monotonic() < deadline:
            started = time.monotonic()
            health = authority.admin_client.health()
            worst = max(worst, time.monotonic() - started)
            states.add(health.get("outbox_recovery"))
            time.sleep(0.5)
        assert authority.is_alive()
        assert authority.controlled_boot.phase.value != "failed"
        assert "backing_off" in states
        # Background ticks wait at most 250 ms per transaction, so the loop
        # never sits on one long enough to threaten the 10 s client deadline.
        assert worst < 2.0
        started = time.monotonic()
        writer.release()
        authority.close()
        assert time.monotonic() - started < 5.0
    finally:
        writer.release()
        authority.close()
