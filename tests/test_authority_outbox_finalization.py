"""Regression tests: outbox writes after a sink delivery must not give up early.

Background recovery scopes a 250 ms lock wait so contention cannot stall the
serving loop. Once an event is with the sink, the finalize must wait the full
store default: giving up strands a live lease (head-of-line stall, then
redelivery). Each delivery is audited in the transaction that records it, so
no later failure can leave it unaudited. Health shows a head stuck behind a
live lease as "stalled" instead of "ok". A commit reply never waits for
publication.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from types import SimpleNamespace

from constitutional_swarm import authority_child, authority_service
from constitutional_swarm.apcc import sqlite_store
from constitutional_swarm.apcc.ports import OutboxRecoveryResult
from constitutional_swarm.governed_commit import CommitOutcome
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
from tests.gcb_apcc_support import authority_child_config, producer_key

_OUTSIDE_HOLD_S = 0.6  # longer than the 250 ms background wait, well under 5 s


def _start(tmp_path, monkeypatch, sink):
    no_process_hardening(monkeypatch)
    monkeypatch.setattr(authority_child, "_DiscardSink", sink)
    config = authority_child_config(
        tmp_path / "authority.db",
        tmp_path / "authority.keys",
        producers={"agent": producer_key("agent")},
        provision=True,
    )
    authority = start_in_thread_authority(config, read_key_bundle(config), busy_timeout_ms=1000)
    return authority, config


def _delivered_audits(database) -> list[str]:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        return [
            row[0]
            for row in connection.execute("SELECT event_json FROM audit_events")
            if "outbox_delivered" in row[0]
        ]
    finally:
        connection.close()


def _hold_lock_once(writer: OutsideWriter, seconds: float) -> threading.Timer:
    writer.acquire()
    timer = threading.Timer(seconds, writer.release)
    timer.start()
    return timer


def test_commit_reply_does_not_wait_for_publication(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    released = threading.Event()
    sink.after_deliver = staticmethod(lambda _event_id: released.wait(5.0))
    try:
        _executor, request = prepare_commit(authority, producer_key("agent"))
        started = time.monotonic()
        decision = authority.execution.commit(request)
        elapsed = time.monotonic() - started
        assert decision.outcome is CommitOutcome.COMMITTED
        # Publication runs after the reply, so a slow sink cannot delay it.
        assert elapsed < 2.0
        released.set()
        assert wait_until(
            lambda: store_counts(config.database_path)["outbox"] == {"DELIVERED": 1}, 5.0
        )
        assert authority.is_alive(), authority.failures
    finally:
        released.set()
        authority.close()


def test_finalize_after_delivery_waits_out_short_outside_write(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    armed = {"on": False}

    def after_deliver(_event_id) -> None:
        if armed["on"]:
            armed["on"] = False
            _hold_lock_once(writer, _OUTSIDE_HOLD_S)

    sink.after_deliver = staticmethod(after_deliver)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        before = len(_delivered_audits(config.database_path))
        armed["on"] = True
        executor.commit(request)
        event = store_counts(config.database_path)["commit_events"][0]
        assert wait_until(lambda: event in sink.events, 5.0)
        assert wait_until(
            lambda: store_counts(config.database_path)["outbox"] == {"DELIVERED": 1}, 5.0
        )
        time.sleep(1.5)
        assert sink.events.count(event) == 1
        assert len(_delivered_audits(config.database_path)) == before + 1
        assert authority.admin.health()["outbox_recovery"] == "ok"
        assert authority.is_alive(), authority.failures
    finally:
        writer.release()
        authority.close()


def test_lock_wait_after_delivery_keeps_its_audit(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    state = {"armed": False, "delivered": False}
    original_connect = sqlite_store._connect
    sink.after_deliver = staticmethod(lambda _event_id: state.update(delivered=True))

    def connect(path):
        connection = original_connect(path)
        # The first short-wait connection after a delivery is the next claim.
        if state["armed"] and state["delivered"] and sqlite_store._BUSY_TIMEOUT_MS.get() == 250:
            state["armed"] = False
            _hold_lock_once(writer, _OUTSIDE_HOLD_S)
        return connection

    monkeypatch.setattr(sqlite_store, "_connect", connect)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        before = len(_delivered_audits(config.database_path))
        state["armed"] = True
        executor.commit(request)
        assert wait_until(lambda: not state["armed"], 5.0)
        assert store_counts(config.database_path)["outbox"] == {"DELIVERED": 1}
        assert len(_delivered_audits(config.database_path)) == before + 1
        assert wait_until(lambda: authority.admin.health()["outbox_recovery"] == "ok", 5.0)
        assert authority.is_alive(), authority.failures
    finally:
        writer.release()
        authority.close()


def test_finalize_lock_timeout_leaves_event_claimed_and_unaudited(
    tmp_path, monkeypatch
) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    monkeypatch.setattr(sqlite_store, "_DEFAULT_BUSY_TIMEOUT_MS", 200)
    armed = {"on": False}

    def after_deliver(_event_id) -> None:
        if armed["on"]:
            armed["on"] = False
            writer.acquire()

    sink.after_deliver = staticmethod(after_deliver)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        before = len(_delivered_audits(config.database_path))
        armed["on"] = True
        executor.commit(request)
        assert wait_until(
            lambda: authority.admin.health()["outbox_recovery"] == "backing_off", 5.0
        )
        writer.release()
        # Delivered but not finalized: the lease holds it for redelivery, and
        # no audit claims a delivery the store has not recorded.
        assert store_counts(config.database_path)["outbox"] == {"CLAIMED": 1}
        assert len(_delivered_audits(config.database_path)) == before
        assert wait_until(lambda: authority.admin.health()["outbox_recovery"] == "stalled", 5.0)
        assert authority.is_alive(), authority.failures
    finally:
        writer.release()
        authority.close()


class _ResultStore:
    def __init__(self) -> None:
        self.result = OutboxRecoveryResult("0", "1", "audit")

    def recover_outbox(self, _request) -> OutboxRecoveryResult:
        return self.result


def test_monitor_reports_stalled_head_then_recovers(caplog) -> None:
    now = [1_000.0]
    monitor = authority_service._OutboxRecoveryMonitor(clock=lambda: now[0])
    store = _ResultStore()
    admin = SimpleNamespace(commit_port=SimpleNamespace(_apcc_store=store))
    caplog.set_level("INFO", logger=authority_service.__name__)

    now[0] = monitor.next_due
    monitor.run(admin)
    assert monitor.health_fields() == {
        "outbox_recovery": "stalled",
        "outbox_recovery_failures": 0,
    }
    assert monitor.next_due - now[0] == 1
    now[0] = monitor.next_due
    monitor.run(admin)
    stalls = [r for r in caplog.records if "state=stalled" in r.getMessage()]
    assert len(stalls) == 1

    store.result = OutboxRecoveryResult("1", "0", "audit")
    now[0] = monitor.next_due
    monitor.run(admin)
    assert monitor.health_fields()["outbox_recovery"] == "ok"


def test_health_decoder_accepts_stalled_state() -> None:
    body = {"authority_pid": 7, "outbox_recovery": "stalled", "outbox_recovery_failures": 0}
    assert authority_service._decode_authority_health(body)["outbox_recovery"] == "stalled"
