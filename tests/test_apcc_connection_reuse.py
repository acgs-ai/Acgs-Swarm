"""Live APCC checks remain per transaction when native handles are reused."""

from pathlib import Path
import sqlite3

import pytest

from constitutional_swarm._sqlite_connections import _reuse_connections
from constitutional_swarm.apcc.model import RequestOutcome
from constitutional_swarm.apcc.ports import CommitContextRequest, CurrentStatusRequest
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityReader
from tests.test_apcc_sqlite import (
    _advance_candidate,
    _nonce,
    _open_store,
    _prepared_gcb_projection_case,
    _request,
)
from tests.gcb_apcc_support import typed_bootstrap


def test_scoped_gcb_control_creates_workflow_after_wal_pragma(tmp_path: Path):
    path = tmp_path / "control.db"
    admin = typed_bootstrap().provision(path)
    with _reuse_connections(path, maximum_idle=3):
        for index in range(2):
            admin.create_workflow(
                workflow_id=f"workflow-{index}",
                nodes={"root": ()},
                policy_version="1",
            )
            assert admin.node_state(f"workflow-{index}", "root").status == "ready"


def test_reused_handle_requires_fresh_exact_transaction_attestation(tmp_path: Path):
    path = tmp_path / "authority.db"
    store = _open_store(path, None)
    with _reuse_connections(path, maximum_idle=3):
        unattested = store._connection()
        with pytest.raises(ValueError, match="was not attested"):
            store._attest_batch_snapshot(unattested)
        unattested.close()
        with store._read_transaction() as first:
            store._attest_batch_snapshot(first)
        with store._read_transaction() as second:
            assert second is not first
            store._attest_batch_snapshot(second)
            # Even adversarial stale membership cannot revive a closed lease.
            store._attested_read_connections.add(first)
            try:
                with pytest.raises(ValueError, match="was not attested"):
                    store._attest_batch_snapshot(first)
            finally:
                store._attested_read_connections.discard(first)


@pytest.mark.parametrize("tamper", ("schema", "checkpoint"))
def test_warm_reused_handles_reject_external_tampering(tmp_path: Path, tamper: str):
    path = tmp_path / "authority.db"
    store = _open_store(path, None)
    reader = SQLiteAuthorityReader.open(path)
    request = CommitContextRequest("workflow-1", "node-1", "attempt-1", "agent-1")
    with _reuse_connections(path, maximum_idle=3):
        for _ in range(2):
            store.read_commit_context(request)
            reader.read_commit_context(request)
        with sqlite3.connect(path) as connection:
            if tamper == "schema":
                connection.execute("DROP TRIGGER certificate_dispositions_no_delete")
            else:
                connection.execute(
                    "INSERT INTO logical_nodes(workflow_id,node_id,version,certificate_digest) "
                    "VALUES ('forged','forged','0',NULL)"
                )
        for target in (store, reader):
            with pytest.raises(ValueError, match="validation failed"):
                target.read_commit_context(request)


def test_reused_store_commits_and_reads_new_signed_status(tmp_path: Path):
    path = tmp_path / "authority.db"
    store = _open_store(path, None)
    request = _request(commit_id="reused", nonce_byte=71)
    with _reuse_connections(path, maximum_idle=3):
        _advance_candidate(store, request)
        committed = store.atomic_commit(request)
        assert committed.decision.outcome is RequestOutcome.COMMITTED
        digest = committed.certificate_digest
        assert digest is not None
        results = store.current_status_batch(
            (
                CurrentStatusRequest(digest, _nonce(1)),
                CurrentStatusRequest(digest, _nonce(2)),
            )
        )
        assert tuple(row.status.request_nonce for row in results) == (
            _nonce(1),
            _nonce(2),
        )
    reopened = SQLiteAuthorityReader.open(path)
    assert reopened.get_certificate(request.commit_id) is not None


def test_reused_gcb_projection_remains_atomic_and_reopens(tmp_path: Path):
    bootstrap, admin, _, atomic, _, _ = _prepared_gcb_projection_case(tmp_path)
    path = Path(admin.commit_port.path)
    with _reuse_connections(path, maximum_idle=3):
        result = admin.commit_port._apcc_store.atomic_commit(atomic)
        assert result.decision.outcome is RequestOutcome.COMMITTED
        assert admin.node_state("dispatcher", "root").commit_id == atomic.commit_id
    reopened = bootstrap.open_admin(path)
    assert reopened.node_state("dispatcher", "root").commit_id == atomic.commit_id
