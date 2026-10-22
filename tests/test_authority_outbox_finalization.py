"""Regression tests: outbox writes after a sink delivery must not give up early.

Background recovery scopes a 250 ms lock wait so contention cannot stall the
serving loop. Once an event is with the sink, though, the finalize and the
delivery audit must wait the full store default: giving up strands a live
lease (head-of-line stall, then redelivery) or drops the audit for good.
Health must also show a head stuck behind a live lease instead of "ok".
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
        armed["on"] = True
        executor.commit(request)
        event = store_counts(config.database_path)["commit_events"][0]
        outbox = store_counts(config.database_path)["outbox"]
        assert outbox.get("CLAIMED", 0) == 0, outbox
        assert sink.events.count(event) == 1
        time.sleep(1.5)
        assert sink.events.count(event) == 1
        assert authority.admin.health()["outbox_recovery"] == "ok"
        assert authority.is_alive(), authority.failures
    finally:
        writer.release()
        authority.close()


def test_delivery_audit_waits_out_short_outside_write(tmp_path, monkeypatch) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    armed = {"on": False}
    original = sqlite_store._audit_id

    def audit_id(*parts):
        if armed["on"] and parts[:1] == ("outbox-delivered",) and parts[1:] != ("none",):
            armed["on"] = False
            _hold_lock_once(writer, _OUTSIDE_HOLD_S)
        return original(*parts)

    monkeypatch.setattr(sqlite_store, "_audit_id", audit_id)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        before = _delivered_audits(config.database_path)
        armed["on"] = True
        executor.commit(request)
        assert store_counts(config.database_path)["outbox"] == {"DELIVERED": 1}
        assert len(_delivered_audits(config.database_path)) == len(before) + 1
        assert authority.is_alive(), authority.failures
    finally:
        writer.release()
        authority.close()


def test_delivery_audit_lock_timeout_replies_committed_then_fails_closed(
    tmp_path, monkeypatch
) -> None:
    sink = recording_sink_class()
    authority, config = _start(tmp_path, monkeypatch, sink)
    writer = OutsideWriter(config.database_path)
    monkeypatch.setattr(sqlite_store, "_DEFAULT_BUSY_TIMEOUT_MS", 200)
    armed = {"on": False}
    original = sqlite_store._audit_id

    def audit_id(*parts):
        if armed["on"] and parts[:1] == ("outbox-delivered",) and parts[1:] != ("none",):
            armed["on"] = False
            writer.acquire()
        return original(*parts)

    monkeypatch.setattr(sqlite_store, "_audit_id", audit_id)
    try:
        executor, request = prepare_commit(authority, producer_key("agent"))
        armed["on"] = True
        decision = executor.commit(request)
        assert decision.outcome is CommitOutcome.COMMITTED
        # A delivery whose audit cannot be written is not a lock wait to ride
        # out: no later run could write it, so the authority stops.
        authority.thread.join(5.0)
        assert not authority.is_alive()
        assert len(authority.failures) == 1
        failure = authority.failures[0]
        assert isinstance(failure, authority_service.AuthorityOutboxRecoveryError)
        assert str(failure.__cause__) == "outbox_delivered_audit_not_recorded"
        assert not authority_service._is_transient_contention(failure)
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
