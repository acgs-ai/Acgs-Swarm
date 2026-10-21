"""GCB returns scoped leases while preserving native context lifetime."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import sqlite3

import pytest

from constitutional_swarm._sqlite_connections import _reuse_connections
from constitutional_swarm.governed_commit import GovernedCommitBoundary
from tests.gcb_apcc_support import typed_bootstrap


def _capture_connections(monkeypatch):
    connections = []
    original = GovernedCommitBoundary._connect

    def connect(self):
        connection = original(self)
        connections.append(connection)
        return connection

    monkeypatch.setattr(GovernedCommitBoundary, "_connect", connect)
    return connections


def _assert_closed(connections):
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def _assert_context_lifetime(connections, mode):
    assert connections
    if mode == "scoped":
        _assert_closed(connections)
        return
    try:
        for connection in connections:
            assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        for connection in connections:
            connection.close()


@pytest.fixture
def boundary(tmp_path):
    return typed_bootstrap().provision(tmp_path / "authority.sqlite3").commit_port


@pytest.fixture(params=["transient", "scoped"])
def connection_scope(boundary, request):
    scope = (
        _reuse_connections(Path(boundary.path), maximum_idle=3)
        if request.param == "scoped"
        else nullcontext()
    )
    with scope:
        yield request.param


@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        ("control_version", (), 0),
        ("pending_outbox", (), 0),
        ("pending_revocations", (), 0),
        ("authoritative_artifact", ("missing-workflow", "missing-artifact"), None),
    ],
)
def test_successful_public_reads_preserve_connection_lifetime(
    boundary, monkeypatch, connection_scope, method, args, expected
):
    connections = _capture_connections(monkeypatch)
    assert getattr(boundary, method)(*args) == expected
    _assert_context_lifetime(connections, connection_scope)


def test_failed_authorization_read_preserves_connection_lifetime(
    boundary, monkeypatch, connection_scope
):
    connections = _capture_connections(monkeypatch)
    with pytest.raises(KeyError, match="missing-workflow"):
        boundary.prepare_attempt_authorization(
            workflow_id="missing-workflow",
            node_id="node",
            attempt_id="attempt",
            agent_id="agent",
            nonce="nonce",
        )
    _assert_context_lifetime(connections, connection_scope)


def test_provisioning_and_reopening_preserve_native_context_lifetime(tmp_path, monkeypatch):
    bootstrap = typed_bootstrap()
    connections = _capture_connections(monkeypatch)
    path = tmp_path / "authority.sqlite3"
    bootstrap.provision(path)
    _assert_context_lifetime(connections, "transient")
    connections.clear()
    bootstrap.open_admin(path)
    _assert_context_lifetime(connections, "transient")


def _isolated_connection(boundary, monkeypatch, tmp_path):
    """Exercise only the resource helper against a separate nongovernance DB."""
    path = tmp_path / "lifecycle.sqlite3"
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE child (parent_id INTEGER REFERENCES parent(id) "
        "DEFERRABLE INITIALLY DEFERRED)"
    )
    monkeypatch.setattr(boundary, "_connect", lambda: connection)
    return path, connection


def _rows(path: Path, table: str):
    connection = sqlite3.connect(path)
    try:
        return connection.execute(f"SELECT * FROM {table}").fetchall()
    finally:
        connection.close()


def test_native_context_commits_without_closing(boundary, monkeypatch, tmp_path):
    path, connection = _isolated_connection(boundary, monkeypatch, tmp_path)
    try:
        with boundary._connection_context() as owned:
            assert owned is connection
            owned.execute("BEGIN")
            owned.execute("INSERT INTO parent VALUES (1)")
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert _rows(path, "parent") == [(1,)]
    finally:
        connection.close()


def test_native_context_rolls_back_body_failure_without_closing(
    boundary, monkeypatch, tmp_path
):
    path, connection = _isolated_connection(boundary, monkeypatch, tmp_path)
    error = RuntimeError("body failed")
    try:
        with pytest.raises(RuntimeError) as raised:
            with boundary._connection_context() as owned:
                owned.execute("BEGIN")
                owned.execute("INSERT INTO parent VALUES (1)")
                raise error
        assert raised.value is error
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert _rows(path, "parent") == []
    finally:
        connection.close()


def test_native_commit_failure_rolls_back_without_closing(boundary, monkeypatch, tmp_path):
    path, connection = _isolated_connection(boundary, monkeypatch, tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            with boundary._connection_context() as owned:
                owned.execute("BEGIN")
                owned.execute("INSERT INTO child VALUES (999)")
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert _rows(path, "child") == []
    finally:
        connection.close()


def test_raw_connect_retains_native_context_semantics(boundary):
    connection = boundary._connect()
    try:
        with connection:
            assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert connection.execute("SELECT 2").fetchone()[0] == 2
    finally:
        connection.close()
