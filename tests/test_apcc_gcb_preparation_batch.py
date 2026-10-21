"""Private GCB preparation preserves logical phases and durable error prefixes."""

from __future__ import annotations

import sqlite3
import multiprocessing
import os
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from constitutional_swarm.apcc import sqlite_store as module
from constitutional_swarm.apcc.model import CandidateLifecycle, FailureCode
from constitutional_swarm.apcc.ports import (
    StageResultRequest,
    AssembleEvidenceRequest,
    ProposeCommitRequest,
)
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
from tests.test_governed_commit import _configured_boundary, _request


def prepared(tmp_path):
    admin, key, _ = _configured_boundary(tmp_path)
    request = admin.commit_port._to_apcc_request(_request(admin, key))
    return admin.commit_port._apcc_store, request


def facts(path):
    with sqlite3.connect(path) as conn:
        return {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in (
                "logical_nodes",
                "candidates",
                "semantic_checkpoint",
                "audit_events",
                "certificates",
                "apcc_decisions",
                "apcc_outbox",
            )
        }


def clone(store, path):
    with (
        sqlite3.connect(store.database_path) as source,
        sqlite3.connect(path) as target,
    ):
        source.backup(target)
    return SQLiteAuthorityStore._open_gcb(path, store._config, store._runtime)


def sequential(store, request):
    with store._transaction() as conn:
        lifecycle = store._initialize_gcb_candidate_at(conn, request)
    if lifecycle is CandidateLifecycle.COMMIT_PENDING:
        return
    with sqlite3.connect(store.database_path) as conn:
        staged = conn.execute(
            "SELECT artifact_json FROM staged_artifacts WHERE workflow_id=? AND node_id=? AND attempt_id=?",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        ).fetchone()
    store.stage_result(
        StageResultRequest(
            request.subject, request.bindings.expected_node_version, staged[0].encode()
        )
    )
    store.assemble_evidence(AssembleEvidenceRequest(request))
    store.propose_commit(ProposeCommitRequest(request))


def test_batch_equals_sequential_exact_checkpoint_and_facts_with_one_commit(
    tmp_path, monkeypatch
):
    store, request = prepared(tmp_path)
    old = clone(store, tmp_path / "sequential.db")
    sequential(old, request)
    trace = []
    original = module._connect

    def connect(path):
        conn = original(path)
        conn.set_trace_callback(trace.append)
        return conn

    monkeypatch.setattr(module, "_connect", connect)
    assert store._prepare_gcb_candidate(request)
    assert facts(store.database_path) == facts(old.database_path)
    assert trace.count("COMMIT") == 1
    assert sum(line.startswith("SAVEPOINT ") for line in trace) == 4
    assert facts(store.database_path)["certificates"] == []
    # Already-pending requests keep their exact staged/checkpoint facts.
    before = facts(store.database_path)
    assert store._prepare_gcb_candidate(request)
    assert facts(store.database_path) == before


@pytest.mark.parametrize(
    "target,expected",
    [
        (CandidateLifecycle.EVIDENCE_ASSEMBLED, "RESULT_STAGED"),
        (CandidateLifecycle.COMMIT_PENDING, "EVIDENCE_ASSEMBLED"),
    ],
)
def test_expected_phase_error_commits_successful_prefix(
    tmp_path, monkeypatch, target, expected
):
    store, request = prepared(tmp_path)
    original = store._advance_at

    def reject(connection, proposal, source, destination, result_type):
        if destination is target:
            # A failed phase must not leak its partial writes or dirty seal.
            connection.execute("UPDATE candidates SET lifecycle='QUARANTINED'")
            raise ValueError(FailureCode.STAGED_RESULT_CONFLICT.value)
        return original(connection, proposal, source, destination, result_type)

    monkeypatch.setattr(store, "_advance_at", reject)
    with pytest.raises(ValueError, match="STAGED_RESULT_CONFLICT"):
        store._prepare_gcb_candidate(request)
    reopened = SQLiteAuthorityStore._open_gcb(
        store.database_path, store._config, store._runtime
    )
    assert facts(reopened.database_path)["candidates"][0][4] == expected


@pytest.mark.parametrize("fault", ["sql", "seal"])
def test_unexpected_failure_rolls_back_entire_unacknowledged_batch(
    tmp_path, monkeypatch, fault
):
    store, request = prepared(tmp_path)
    before = facts(store.database_path)
    if fault == "sql":

        def fail(*args):
            raise sqlite3.OperationalError("injected SQL failure")

        monkeypatch.setattr(store, "_advance_at", fail)
        error = sqlite3.OperationalError
    else:
        original = store._seal_mutation_checkpoint
        calls = 0

        def fail(connection):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("injected checkpoint signing failure")
            return original(connection)

        monkeypatch.setattr(store, "_seal_mutation_checkpoint", fail)
        error = ValueError
    with pytest.raises(error, match="injected"):
        store._prepare_gcb_candidate(request)
    assert facts(store.database_path) == before


def test_missing_staged_material_commits_initialized_prefix(tmp_path):
    store, request = prepared(tmp_path)
    with sqlite3.connect(store.database_path) as conn:
        conn.execute("DELETE FROM staged_artifacts")
    assert not store._prepare_gcb_candidate(request)
    reopened = SQLiteAuthorityStore._open_gcb(
        store.database_path, store._config, store._runtime
    )
    assert facts(reopened.database_path)["candidates"][0][4] == "EXECUTING"


def test_quarantine_phase_commits_before_conflict_is_reported(tmp_path, monkeypatch):
    store, request = prepared(tmp_path)
    with store._transaction() as conn:
        store._initialize_gcb_candidate_at(conn, request)
    with sqlite3.connect(store.database_path) as conn:
        staged = conn.execute("SELECT artifact_json FROM staged_artifacts").fetchone()[
            0
        ]
    store.stage_result(
        StageResultRequest(
            request.subject, request.bindings.expected_node_version, staged.encode()
        )
    )
    original = store._stage_result_at

    def conflict(connection, stage):
        return original(
            connection,
            StageResultRequest(
                stage.subject, stage.expected_node_version, b"conflicting bytes"
            ),
        )

    monkeypatch.setattr(store, "_stage_result_at", conflict)
    with pytest.raises(ValueError, match="STAGED_RESULT_CONFLICT"):
        store._prepare_gcb_candidate(request)
    SQLiteAuthorityStore._open_gcb(store.database_path, store._config, store._runtime)
    assert facts(store.database_path)["candidates"][0][4] == "QUARANTINED"


def test_commit_failure_leaves_no_preparation_prefix(tmp_path, monkeypatch):
    store, request = prepared(tmp_path)
    before = facts(store.database_path)
    original = module._connect

    class FailingCommit:
        def __init__(self, native):
            self.native = native

        def __getattr__(self, name):
            return getattr(self.native, name)

        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    monkeypatch.setattr(module, "_connect", lambda path: FailingCommit(original(path)))
    with pytest.raises(sqlite3.OperationalError, match="injected commit"):
        store._prepare_gcb_candidate(request)
    assert facts(store.database_path) == before


def _crash_preparation(store, request, after):
    if not after:
        seal = store._seal_mutation_checkpoint
        count = 0

        def crash(connection):
            nonlocal count
            seal(connection)
            count += 1
            if count == 4:
                os._exit(17)

        store._seal_mutation_checkpoint = crash
    store._prepare_gcb_candidate(request)
    os._exit(18)


@pytest.mark.parametrize("after", [False, True])
def test_process_exit_before_or_after_preparation_commit_is_retryable(tmp_path, after):
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork fault injection requires POSIX")
    store, request = prepared(tmp_path)
    before = facts(store.database_path)
    process = multiprocessing.get_context("fork").Process(
        target=_crash_preparation, args=(store, request, after)
    )
    process.start()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("preparation child did not finish")
    assert process.exitcode == (18 if after else 17)
    reopened = SQLiteAuthorityStore._open_gcb(
        store.database_path, store._config, store._runtime
    )
    if after:
        assert facts(store.database_path)["candidates"][0][4] == "COMMIT_PENDING"
    else:
        assert facts(store.database_path) == before
    assert reopened._prepare_gcb_candidate(request)
    assert reopened.atomic_commit(request).decision.outcome.value == "COMMITTED"


def test_identical_concurrent_preparations_serialize_and_commit_once(tmp_path):
    store, request = prepared(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(
            workers.map(lambda _: store._prepare_gcb_candidate(request), range(2))
        )
    assert results == [True, True]
    first = store.atomic_commit(request)
    second = store.atomic_commit(request)
    assert first == second
    assert first.decision.outcome.value == "COMMITTED"
    assert len(facts(store.database_path)["certificates"]) == 1


@pytest.mark.parametrize("statement", ["SAVEPOINT", "ROLLBACK TO", "RELEASE"])
def test_transaction_control_failure_rolls_back_batch(tmp_path, monkeypatch, statement):
    store, request = prepared(tmp_path)
    before = facts(store.database_path)
    original = module._connect
    if statement == "ROLLBACK TO":

        def reject(*args):
            raise ValueError(FailureCode.STAGED_RESULT_CONFLICT.value)

        monkeypatch.setattr(store, "_stage_result_at", reject)

    class FailingControl:
        def __init__(self, native):
            self.native = native
            self.matches = 0

        def __getattr__(self, name):
            return getattr(self.native, name)

        def execute(self, sql, *args):
            if sql.startswith(statement):
                self.matches += 1
                if statement != "SAVEPOINT" or self.matches == 2:
                    raise sqlite3.OperationalError(
                        "injected transaction control failure"
                    )
            return self.native.execute(sql, *args)

    monkeypatch.setattr(module, "_connect", lambda path: FailingControl(original(path)))
    with pytest.raises(sqlite3.OperationalError, match="transaction control"):
        store._prepare_gcb_candidate(request)
    assert facts(store.database_path) == before


def test_public_lifecycle_operations_are_separately_durable(tmp_path):
    store, request = prepared(tmp_path)
    with store._transaction() as conn:
        store._initialize_gcb_candidate_at(conn, request)
    with sqlite3.connect(store.database_path) as conn:
        staged = conn.execute("SELECT artifact_json FROM staged_artifacts").fetchone()[
            0
        ]
    steps = (
        (
            lambda: store.stage_result(
                StageResultRequest(
                    request.subject,
                    request.bindings.expected_node_version,
                    staged.encode(),
                )
            ),
            "RESULT_STAGED",
        ),
        (
            lambda: store.assemble_evidence(AssembleEvidenceRequest(request)),
            "EVIDENCE_ASSEMBLED",
        ),
        (lambda: store.propose_commit(ProposeCommitRequest(request)), "COMMIT_PENDING"),
    )
    for action, state in steps:
        action()
        reopened = SQLiteAuthorityStore._open_gcb(
            store.database_path, store._config, store._runtime
        )
        assert facts(reopened.database_path)["candidates"][0][4] == state


def test_expiry_after_preparation_is_checked_by_separate_atomic_commit(tmp_path):
    store, request = prepared(tmp_path)
    assert store._prepare_gcb_candidate(request)
    expiry = int(request.evidence.producer_statement["expires_at_ms"])

    class ExpiredClock:
        def now_ms(self):
            return expiry + 1

    store._runtime = replace(store._runtime, clock=ExpiredClock())
    result = store.atomic_commit(request)
    assert result.decision.outcome.value != "COMMITTED"
    assert facts(store.database_path)["certificates"] == []


def test_revocation_after_preparation_is_checked_by_separate_atomic_commit(tmp_path):
    admin, key, _ = _configured_boundary(tmp_path)
    request = admin.commit_port._to_apcc_request(_request(admin, key))
    store = admin.commit_port._apcc_store
    assert store._prepare_gcb_candidate(request)
    admin.revoke_agent(workflow_id="wf", agent_id="agent")
    result = store.atomic_commit(request)
    assert result.decision.outcome.value != "COMMITTED"
    assert facts(store.database_path)["certificates"] == []


def test_conflicting_concurrent_preparations_cannot_both_commit(tmp_path):
    admin, key, _ = _configured_boundary(tmp_path)
    requests = [
        admin.commit_port._to_apcc_request(_request(admin, key, commit_id=commit_id))
        for commit_id in ("competing-one", "competing-two")
    ]
    store = admin.commit_port._apcc_store
    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(store._prepare_gcb_candidate, requests)) == [True, True]
        results = list(workers.map(store.atomic_commit, requests))
    committed = sum(result.decision.outcome.value == "COMMITTED" for result in results)
    # A conflicting request can quarantine the shared candidate before its
    # competitor commits. Safety allows zero winners, never two.
    assert committed <= 1
    assert len(facts(store.database_path)["certificates"]) == committed
