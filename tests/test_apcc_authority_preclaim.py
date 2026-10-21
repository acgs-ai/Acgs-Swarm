"""Only fresh authority dispatch can carry a durable, single-use head claim."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import multiprocessing
import os
import sqlite3

import pytest

from constitutional_swarm.apcc import sqlite_store as module
from constitutional_swarm.apcc.ports import OutboxRecoveryRequest
from tests.test_apcc_gcb_preparation_batch import clone, facts, prepared


class Clock:
    def __init__(self, now):
        self.now = now

    def now_ms(self):
        return self.now


class Sink:
    def __init__(self):
        self.events = []

    def deliver(self, event_id, payload):
        self.events.append((event_id, payload))


def ready(tmp_path):
    store, request = prepared(tmp_path)
    clock = Clock(store._runtime.clock.now_ms())
    sink = Sink()
    store._runtime = replace(store._runtime, clock=clock, outbox_sink=sink)
    store._prepare_gcb_candidate(request)
    return store, request, clock, sink


def state(store):
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(
            "SELECT state FROM apcc_outbox ORDER BY event_sequence"
        ).fetchall()


def test_exact_sequential_claim_facts_and_one_commit_saved(tmp_path, monkeypatch):
    store, request, clock, sink = ready(tmp_path)
    old = clone(store, tmp_path / "sequential.db")
    original = module._connect
    commits = []

    def connect(path):
        connection = original(path)
        connection.set_trace_callback(
            lambda sql: commits.append(sql) if sql == "COMMIT" else None
        )
        return connection

    monkeypatch.setattr(module, "_connect", connect)
    monkeypatch.setattr(module.secrets, "token_hex", lambda n: "a" * (2 * n))
    expected = old.atomic_commit(request)
    with old._transaction() as connection:
        connection.execute(
            "UPDATE apcc_outbox SET state='CLAIMED',lease_token=?,lease_claimed_ms=?,lease_until_ms=?,delivered=0 WHERE state='PENDING'",
            ("a" * 64, clock.now, clock.now + 30000),
        )
    assert len(commits) == 2
    commits.clear()
    result, handle = store._atomic_commit_and_claim_head(request)
    assert result == expected
    assert handle is not None
    assert len(commits) == 1
    assert facts(store.database_path) == facts(old.database_path)
    recovered = store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)
    assert recovered.delivered_count == "1"
    assert len(sink.events) == 1
    assert state(store) == [("DELIVERED",)]
    assert not store._issued_outbox_claims


def test_public_commit_stays_pending_and_replay_never_preclaims(tmp_path):
    store, request, _, _ = ready(tmp_path)
    public = store.atomic_commit(request)
    replay, handle = store._atomic_commit_and_claim_head(request)
    assert replay == public
    assert handle is None
    assert state(store) == [("PENDING",)]
    assert not store._issued_outbox_claims


@pytest.mark.parametrize(
    "variant", ["forged", "copy", "deepcopy", "foreign", "thread", "pid"]
)
def test_unissued_or_wrong_owner_handles_fail_closed(tmp_path, monkeypatch, variant):
    store, request, _, sink = ready(tmp_path)
    _, handle = store._atomic_commit_and_claim_head(request)
    assert handle is not None
    target = store
    invalid = handle
    if variant == "forged":
        invalid = module._IssuedOutboxClaim()
    elif variant == "copy":
        invalid = copy.copy(handle)
    elif variant == "deepcopy":
        invalid = copy.deepcopy(handle)
    elif variant == "foreign":
        target = clone(store, tmp_path / "foreign.db")
    elif variant == "pid":
        monkeypatch.setattr(module.os, "getpid", lambda: -1)
    with pytest.raises(ValueError, match="outbox claim"):
        if variant == "thread":
            with ThreadPoolExecutor(1) as pool:
                pool.submit(target._consume_outbox_claim, invalid).result()
        else:
            target._consume_outbox_claim(invalid)
    assert not sink.events
    assert state(store) == [("CLAIMED",)]
    store._discard_outbox_claim(handle)
    assert not store._issued_outbox_claims


def test_handle_is_single_use_and_expired_claim_uses_normal_recovery(tmp_path):
    store, request, clock, sink = ready(tmp_path)
    _, handle = store._atomic_commit_and_claim_head(request)
    clock.now += 30001
    assert (
        store._recover_claimed_outbox(
            OutboxRecoveryRequest("1"), handle
        ).delivered_count
        == "1"
    )
    with pytest.raises(ValueError, match="unissued"):
        store._recover_claimed_outbox(OutboxRecoveryRequest("1"), handle)
    assert len(sink.events) == 1


@pytest.mark.parametrize(
    "fault", ["claim", "seal", "commit", "ambiguous", "aftercommit"]
)
def test_failure_never_issues_handle_and_preserves_correct_durable_boundary(
    tmp_path, monkeypatch, fault
):
    store, request, clock, sink = ready(tmp_path)
    before = facts(store.database_path)
    seal = store._seal_mutation_checkpoint
    seals = 0

    class Fail(sqlite3.Connection):
        def execute(self, sql, *args):
            if fault == "claim" and "SET state='CLAIMED'" in sql:
                raise sqlite3.OperationalError("claim failure")
            return super().execute(sql, *args)

        def commit(self):
            if fault == "ambiguous":
                super().commit()
            if fault in {"commit", "ambiguous"}:
                raise sqlite3.OperationalError("commit failure")
            super().commit()

    def fail_seal(connection):
        nonlocal seals
        seals += 1
        seal(connection)
        if fault == "seal" and seals == 2:
            raise RuntimeError("seal failure")

    def hit(point):
        if fault == "aftercommit" and point == "after_commit_before_response":
            raise RuntimeError("aftercommit failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            module,
            "_connect",
            lambda path: module._configure_connection(
                sqlite3.connect(path, isolation_level=None, factory=Fail)
            ),
        )
        patch.setattr(store, "_seal_mutation_checkpoint", fail_seal)
        patch.setattr(store, "_hit", hit)
        with pytest.raises((RuntimeError, sqlite3.OperationalError)):
            store._atomic_commit_and_claim_head(request)
    assert not store._issued_outbox_claims
    assert not sink.events
    if fault in {"ambiguous", "aftercommit"}:
        assert state(store) == [("CLAIMED",)]
        clock.now += 30001
        assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"
    else:
        assert facts(store.database_path) == before


def test_delivery_occurs_outside_writer_lock_and_failure_releases_token(tmp_path):
    store, request, _, sink = ready(tmp_path)
    _, handle = store._atomic_commit_and_claim_head(request)

    class FailingSink:
        def deliver(self, event_id, payload):
            with sqlite3.connect(store.database_path, timeout=0) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            raise RuntimeError("sink unavailable")

    store._runtime = replace(store._runtime, outbox_sink=FailingSink())
    with pytest.raises(RuntimeError, match="sink unavailable"):
        store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)
    assert not store._issued_outbox_claims
    assert state(store) == [("PENDING",)]
    store._runtime = replace(store._runtime, outbox_sink=sink)
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"


def test_live_checkpoint_tamper_rejects_claim_without_delivery(tmp_path):
    store, request, _, sink = ready(tmp_path)
    _, handle = store._atomic_commit_and_claim_head(request)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("UPDATE apcc_outbox SET lease_until_ms=lease_until_ms+1")
    with pytest.raises(ValueError):
        store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)
    assert not sink.events
    assert not store._issued_outbox_claims


@pytest.mark.parametrize("after", [False, True])
def test_process_death_on_each_side_of_commit_is_recoverable(tmp_path, after):
    store, request, clock, _ = ready(tmp_path)
    before = facts(store.database_path)

    def die():
        class Crash(sqlite3.Connection):
            def commit(self):
                if after:
                    super().commit()
                os._exit(67)

        module._connect = lambda path: module._configure_connection(
            sqlite3.connect(path, isolation_level=None, factory=Crash)
        )
        store._atomic_commit_and_claim_head(request)

    process = multiprocessing.get_context("fork").Process(target=die)
    process.start()
    process.join(10)
    assert process.exitcode == 67
    if after:
        assert state(store) == [("CLAIMED",)]
        clock.now += 30001
        assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"
    else:
        assert facts(store.database_path) == before
        _, handle = store._atomic_commit_and_claim_head(request)
        assert (
            store._recover_claimed_outbox(
                OutboxRecoveryRequest("100"), handle
            ).delivered_count
            == "1"
        )


@pytest.mark.parametrize("private", [False, True])
def test_request_identity_failure_precedes_storage_validation(
    tmp_path, monkeypatch, private
):
    store, request, _, _ = ready(tmp_path)

    def identity(*args):
        raise ValueError("malformed request identity")

    def unavailable(*args):
        raise AssertionError("storage must not open")

    monkeypatch.setattr(module, "_operation_identity", identity)
    monkeypatch.setattr(module, "_connect", unavailable)
    with pytest.raises(ValueError, match="malformed request identity"):
        if private:
            store._atomic_commit_and_claim_head(request)
        else:
            store.atomic_commit(request)


@pytest.mark.parametrize("claimed", [False, True])
def test_older_head_forces_normal_ordered_recovery(tmp_path, claimed):
    from constitutional_swarm.apcc.ports import RevocationRequest, RevocationScope

    store, request, clock, sink = ready(tmp_path)
    store.revoke(
        RevocationRequest(RevocationScope.ACTOR, "wf", "unrelated", "1", "other actor")
    )
    if claimed:
        with store._transaction() as connection:
            connection.execute(
                "UPDATE apcc_outbox SET state='CLAIMED',lease_token='older',lease_claimed_ms=?,lease_until_ms=? WHERE state='PENDING'",
                (clock.now, clock.now + 30000),
            )
    result, handle = store._atomic_commit_and_claim_head(request)
    assert result.decision.outcome.value == "COMMITTED"
    assert handle is None
    assert state(store) == [("CLAIMED" if claimed else "PENDING",), ("PENDING",)]
    if claimed:
        assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "0"
        clock.now += 30001
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "2"
    assert len(sink.events) == 2


@pytest.mark.parametrize("cause", ["expiry", "revocation"])
def test_denied_atomic_commit_never_claims(tmp_path, cause):
    from constitutional_swarm.apcc.ports import RevocationRequest, RevocationScope

    store, request, clock, _ = ready(tmp_path)
    if cause == "expiry":
        clock.now = int(request.evidence.producer_statement["expires_at_ms"]) + 1
    else:
        store.revoke(
            RevocationRequest(RevocationScope.ACTOR, "wf", "agent", "2", "deny actor")
        )
    result, handle = store._atomic_commit_and_claim_head(request)
    assert result.decision.outcome.value != "COMMITTED"
    assert handle is None
    assert all(row == ("PENDING",) for row in state(store))


def test_revocation_after_atomic_preserves_historical_delivery(tmp_path):
    from constitutional_swarm.apcc.ports import RevocationRequest, RevocationScope
    from tests.test_apcc_sqlite import _nonce

    store, request, _, sink = ready(tmp_path)
    result, handle = store._atomic_commit_and_claim_head(request)
    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "wf",
            result.certificate_digest,
            "1",
            "revoke after commit",
        )
    )
    assert (
        store.current_status(result.certificate_digest, _nonce(79)).status.value
        == "revoked"
    )
    assert (
        store._recover_claimed_outbox(
            OutboxRecoveryRequest("100"), handle
        ).delivered_count
        == "2"
    )
    assert len(sink.events) == 2


def test_concurrent_identical_atomic_calls_issue_one_handle(tmp_path):
    store, request, _, _ = ready(tmp_path)

    def commit_and_recover():
        result, handle = store._atomic_commit_and_claim_head(request)
        if handle is not None:
            store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)
        return result, handle is not None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: commit_and_recover(), range(2)))
    assert results[0][0] == results[1][0]
    assert sum(claimed for _, claimed in results) == 1
    assert state(store) == [("DELIVERED",)]
    assert not store._issued_outbox_claims


def test_replay_leaves_issued_claim_and_lease_unchanged(tmp_path):
    store, request, _, _ = ready(tmp_path)
    result, handle = store._atomic_commit_and_claim_head(request)
    before = facts(store.database_path)
    replay, repeated = store._atomic_commit_and_claim_head(request)
    assert replay == result
    assert repeated is None
    assert facts(store.database_path) == before
    assert len(store._issued_outbox_claims) == 1
    assert (
        store._recover_claimed_outbox(
            OutboxRecoveryRequest("100"), handle
        ).delivered_count
        == "1"
    )


def test_replaced_database_inode_rejects_issued_handle(tmp_path):
    store, request, _, sink = ready(tmp_path)
    _, handle = store._atomic_commit_and_claim_head(request)
    replacement = clone(store, tmp_path / "replacement.db")
    os.replace(replacement.database_path, store.database_path)
    with pytest.raises(ValueError, match="owner changed"):
        store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)
    assert not sink.events
    assert not store._issued_outbox_claims


def test_gcb_response_failure_discards_already_issued_handle(tmp_path, monkeypatch):
    from tests.test_governed_commit import _configured_boundary, _request

    admin, key, _ = _configured_boundary(tmp_path)
    request = _request(admin, key)
    boundary = admin.commit_port
    store = boundary._apcc_store

    def fail_mapping(request, result):
        assert len(store._issued_outbox_claims) == 1
        raise RuntimeError("response mapping fault")

    monkeypatch.setattr(boundary, "_map_apcc_commit_result", fail_mapping)
    with pytest.raises(RuntimeError, match="response mapping fault"):
        boundary._commit_for_authority(request)
    assert not store._issued_outbox_claims
    assert state(store) == [("CLAIMED",)]


@pytest.mark.parametrize("checkpoint", ["sink", "finalize"])
def test_process_death_during_delivery_replays_same_event_after_lease(
    tmp_path, checkpoint
):
    store, request, clock, sink = ready(tmp_path)

    def die():
        _, handle = store._atomic_commit_and_claim_head(request)
        if checkpoint == "sink":

            class CrashSink:
                def deliver(self, event_id, payload):
                    os._exit(68)

            store._runtime = replace(store._runtime, outbox_sink=CrashSink())
        else:
            original = store._seal_mutation_checkpoint

            def crash_seal(connection):
                original(connection)
                os._exit(68)

            store._seal_mutation_checkpoint = crash_seal
        store._recover_claimed_outbox(OutboxRecoveryRequest("100"), handle)

    process = multiprocessing.get_context("fork").Process(target=die)
    process.start()
    process.join(10)
    assert process.exitcode == 68
    assert state(store) == [("CLAIMED",)]
    with sqlite3.connect(store.database_path) as connection:
        expected = connection.execute(
            "SELECT event_id,event_json FROM apcc_outbox"
        ).fetchone()
    clock.now += 30001
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"
    assert sink.events == [expected]


def test_full_handle_registry_preserves_pending_fresh_commit_and_normal_recovery(
    tmp_path,
):
    store, request, _, sink = ready(tmp_path)
    # Seed a saturated registry with valid immutable record shapes. Its occupancy
    # is the branch input; actual identity issuance/consumption is tested above.
    reference = clone(store, tmp_path / "reference.db")
    _, reference_handle = reference._atomic_commit_and_claim_head(request)
    record = reference._issued_outbox_claims[id(reference_handle)][1]
    handles = [module._IssuedOutboxClaim() for _ in range(128)]
    with store._outbox_claim_lock:
        store._issued_outbox_claims.update(
            (id(handle), (handle, record)) for handle in handles
        )
    result, handle = store._atomic_commit_and_claim_head(request)
    assert result.decision.outcome.value == "COMMITTED"
    assert handle is None
    assert len(store._issued_outbox_claims) == 128
    assert state(store) == [("PENDING",)]
    assert not sink.events
    for issued in handles:
        store._discard_outbox_claim(issued)
    assert not store._issued_outbox_claims
    assert store.recover_outbox(OutboxRecoveryRequest("100")).delivered_count == "1"


def test_preclaim_clock_overflow_rolls_back_atomic_commit(tmp_path, monkeypatch):
    store, request, clock, sink = ready(tmp_path)
    before = facts(store.database_path)
    original = store._commit_at

    def advance_clock_after_atomic(*args):
        outcome = original(*args)
        assert outcome.fresh_event is not None
        # Atomic authorization used the valid clock. Claim arithmetic must check
        # its own newly read time, before computing a lease outside the profile.
        clock.now = module._MAX_SAFE_INTEGER - 29999
        return outcome

    monkeypatch.setattr(store, "_commit_at", advance_clock_after_atomic)
    with pytest.raises(ValueError, match="INVALID_DECIMAL_STRING"):
        store._atomic_commit_and_claim_head(request)
    assert facts(store.database_path) == before
    assert not store._issued_outbox_claims
    assert not sink.events
