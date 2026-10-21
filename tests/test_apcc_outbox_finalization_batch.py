"""Terminal outbox audit shares durability with finalization, never delivery."""

from __future__ import annotations

from dataclasses import replace
import multiprocessing
import os
import sqlite3
import threading

import pytest

from constitutional_swarm.apcc import sqlite_store as module
from constitutional_swarm.apcc.ports import OutboxRecoveryRequest
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
from tests.test_apcc_sqlite import _open_store, _request, _advance_candidate


class Sink:
    def __init__(self):
        self.delivered = []

    def deliver(self, event_id, payload):
        self.delivered.append((event_id, payload))


def pending_store(tmp_path, count=1):
    store = _open_store(tmp_path / "outbox.db", None)
    sink = Sink()
    store._runtime = replace(store._runtime, outbox_sink=sink)
    for index in range(count):
        request = _request(
            commit_id=f"outbox-{index}",
            nonce_byte=120 + index,
            node_id=("node-1", "root")[index],
        )
        _advance_candidate(store, request)
        assert store.atomic_commit(request).decision.outcome.value == "COMMITTED"
    return store, sink


def facts(path):
    with sqlite3.connect(path) as conn:
        return {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in (
                "apcc_outbox",
                "semantic_checkpoint",
                "audit_events",
                "certificates",
                "trust_log",
                "logical_nodes",
                "apcc_decisions",
            )
        }


def old_recovery(store, maximum):
    """Original sequential success path with independently spelled audit phase."""
    delivered = []
    for _ in range(maximum):
        now = store._runtime.clock.now_ms()
        with store._transaction() as conn:
            head = conn.execute(
                "SELECT event_sequence,event_id,event_json FROM apcc_outbox WHERE state<>'DELIVERED' ORDER BY event_sequence LIMIT 1"
            ).fetchone()
            if head is None:
                break
            conn.execute(
                "UPDATE apcc_outbox SET state='CLAIMED',lease_token='token',lease_claimed_ms=?,lease_until_ms=?,delivered=0 WHERE event_sequence=?",
                (now, now + 30000, head[0]),
            )
        store._runtime.outbox_sink.deliver(head[1], bytes(head[2]))
        with store._transaction() as conn:
            conn.execute(
                "UPDATE apcc_outbox SET state='DELIVERED',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=1 WHERE event_id=? AND lease_token='token'",
                (head[1],),
            )
        delivered.append(head[1])
    audit = module._audit_id("outbox-delivered", *(delivered or ["none"]))
    with store._transaction() as conn:
        if (
            delivered
            and conn.execute(
                "SELECT 1 FROM audit_events WHERE audit_event_id=?", (audit,)
            ).fetchone()
            is None
        ):
            module._write_audit(conn, audit, "outbox_delivered", "outbox")
        pending = conn.execute(
            "SELECT COUNT(*) FROM apcc_outbox WHERE state<>'DELIVERED'"
        ).fetchone()[0]
    return str(len(delivered)), str(pending), audit


@pytest.mark.parametrize("count,maximum", [(1, 1), (1, 100), (2, 1), (2, 100)])
def test_exact_sequential_facts_checkpoint_and_result(tmp_path, count, maximum):
    store, _ = pending_store(tmp_path, count)
    path = tmp_path / "old.db"
    with (
        sqlite3.connect(store.database_path) as source,
        sqlite3.connect(path) as target,
    ):
        source.backup(target)
    old = SQLiteAuthorityStore.open(path, config=store._config, runtime=store._runtime)
    expected = old_recovery(old, maximum)
    result = store.recover_outbox(OutboxRecoveryRequest(str(maximum)))
    assert (
        result.delivered_count,
        result.pending_count,
        result.audit_event_id,
    ) == expected
    assert facts(store.database_path) == facts(path)


def test_one_event_uses_two_write_commits(tmp_path, monkeypatch):
    store, _ = pending_store(tmp_path)
    original = module._connect
    changes = []

    class Observe:
        def __init__(self, native):
            self.native = native

        def __getattr__(self, name):
            return getattr(self.native, name)

        def commit(self):
            changes.append(self.native.total_changes)
            self.native.commit()

    monkeypatch.setattr(module, "_connect", lambda path: Observe(original(path)))
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"
    assert changes == [3, 6]


@pytest.mark.parametrize("fault", ["audit", "seal", "commit"])
def test_fused_failure_preserves_prior_delivery_and_current_claim(
    tmp_path, monkeypatch, fault
):
    store, sink = pending_store(tmp_path, 2)
    old_audit = store._audit_outbox_recovery_at
    old_seal = store._seal_mutation_checkpoint
    original = module._connect
    failing = False

    def audit(connection, delivered):
        nonlocal failing
        failing = True
        result = old_audit(connection, delivered)
        if fault == "audit":
            raise sqlite3.OperationalError("injected audit failure")
        return result

    def seal(connection):
        if failing and fault == "seal":
            raise ValueError("injected seal failure")
        return old_seal(connection)

    class FailCommit:
        def __init__(self, native):
            self.native = native

        def __getattr__(self, name):
            return getattr(self.native, name)

        def commit(self):
            if failing and fault == "commit":
                raise sqlite3.OperationalError("injected commit failure")
            self.native.commit()

    with monkeypatch.context() as patch:
        patch.setattr(store, "_audit_outbox_recovery_at", audit)
        patch.setattr(store, "_seal_mutation_checkpoint", seal)
        patch.setattr(module, "_connect", lambda path: FailCommit(original(path)))
        with pytest.raises((ValueError, sqlite3.OperationalError), match="injected"):
            store.recover_outbox(OutboxRecoveryRequest("100"))
    rows = facts(store.database_path)["apcc_outbox"]
    assert [row[7] for row in rows] == ["DELIVERED", "CLAIMED"]
    reopened = SQLiteAuthorityStore.open(
        store.database_path, config=store._config, runtime=store._runtime
    )
    assert reopened.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "0"
    store._runtime.clock.set_sequence((store._runtime.clock.now_ms() + 30001,))
    assert reopened.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"
    assert sink.delivered[-1] == sink.delivered[-2]


def _crash_recovery(store, after):
    if not after:
        original = store._audit_outbox_recovery_at

        def crash(connection, delivered):
            original(connection, delivered)
            os._exit(27)

        store._audit_outbox_recovery_at = crash
    store.recover_outbox(OutboxRecoveryRequest("100"))
    os._exit(28)


@pytest.mark.parametrize("after", [False, True])
def test_process_exit_before_after_fused_commit(tmp_path, after):
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("POSIX fault injection")
    store, sink = pending_store(tmp_path)
    process = multiprocessing.get_context("fork").Process(
        target=_crash_recovery, args=(store, after)
    )
    process.start()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("recovery child did not terminate")
    assert process.exitcode == (28 if after else 27)
    reopened = SQLiteAuthorityStore.open(
        store.database_path, config=store._config, runtime=store._runtime
    )
    state = facts(store.database_path)["apcc_outbox"][0][7]
    assert state == ("DELIVERED" if after else "CLAIMED")
    store._runtime.clock.set_sequence((store._runtime.clock.now_ms() + 30001,))
    result = reopened.recover_outbox(OutboxRecoveryRequest("100"))
    assert result.delivered_count == ("0" if after else "1")
    assert len(sink.delivered) == (0 if after else 1)


def enqueue_second(store):
    request = _request(commit_id="enqueued", nonce_byte=180, node_id="root")
    _advance_candidate(store, request)
    assert store.atomic_commit(request).decision.outcome.value == "COMMITTED"


def test_enqueue_before_terminal_check_joins_same_recovery(tmp_path):
    store, sink = pending_store(tmp_path)
    original = sink.deliver

    def deliver(event_id, payload):
        original(event_id, payload)
        if len(sink.delivered) == 1:
            enqueue_second(store)

    sink.deliver = deliver
    result = store.recover_outbox(OutboxRecoveryRequest("100"))
    assert result.delivered_count == "2"
    assert result.pending_count == "0"
    assert len(sink.delivered) == 2


def test_enqueue_after_terminal_check_linearizes_after_recovery(tmp_path, monkeypatch):
    store, _ = pending_store(tmp_path)
    started, completed = threading.Event(), threading.Event()
    errors = []

    def writer():
        started.set()
        try:
            enqueue_second(store)
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()

    worker = threading.Thread(target=writer)
    original = store._audit_outbox_recovery_at

    def audit(connection, delivered):
        worker.start()
        assert started.wait(2)
        assert not completed.wait(0.02)
        return original(connection, delivered)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_audit_outbox_recovery_at", audit)
        result = store.recover_outbox(OutboxRecoveryRequest("100"))
    worker.join(timeout=5)
    assert not worker.is_alive() and not errors
    assert result.delivered_count == "1" and result.pending_count == "0"
    assert facts(store.database_path)["apcc_outbox"][1][7] == "PENDING"
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"


def test_expired_competing_lease_cannot_be_finalized_by_stale_owner(tmp_path):
    store, sink = pending_store(tmp_path)
    other_sink = Sink()
    other = SQLiteAuthorityStore.open(
        store.database_path,
        config=store._config,
        runtime=replace(store._runtime, outbox_sink=other_sink),
    )
    original = sink.deliver

    def deliver(event_id, payload):
        original(event_id, payload)
        store._runtime.clock.set_sequence((store._runtime.clock.now_ms() + 30001,))
        assert other.recover_outbox(OutboxRecoveryRequest("1")).delivered_count == "1"

    sink.deliver = deliver
    result = store.recover_outbox(OutboxRecoveryRequest("100"))
    assert result.delivered_count == "0" and result.pending_count == "0"
    assert sink.delivered == other_sink.delivered
    assert facts(store.database_path)["apcc_outbox"][0][7] == "DELIVERED"


def test_fused_audit_revalidates_checkpoint_and_rolls_back_tampering(
    tmp_path, monkeypatch
):
    store, _ = pending_store(tmp_path)
    original = store._seal_mutation_checkpoint
    calls = 0

    def seal(connection):
        nonlocal calls
        calls += 1
        original(connection)
        if calls == 2:
            connection.execute("UPDATE semantic_checkpoint SET signature='tampered'")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_seal_mutation_checkpoint", seal)
        with pytest.raises(ValueError, match="checkpoint validation failed"):
            store.recover_outbox(OutboxRecoveryRequest("100"))
    SQLiteAuthorityStore.open(
        store.database_path, config=store._config, runtime=store._runtime
    )
    assert facts(store.database_path)["apcc_outbox"][0][7] == "CLAIMED"
