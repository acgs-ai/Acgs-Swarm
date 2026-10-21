"""Connection reuse keeps native transaction and durable failure boundaries."""

import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from constitutional_swarm._sqlite_connections import (
    _ConnectionLease,
    _configured_connection,
    _connect_scoped,
    _is_sqlite_connection,
    _reuse_connections,
)


def database(tmp_path: Path) -> Path:
    path = tmp_path / "store.db"
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE records(value INTEGER UNIQUE)")
    return path


def connect(path: Path, kind: str = "writer"):
    return _configured_connection(
        _connect_scoped(path, kind=kind, database=str(path), isolation_level=None)
    )


def test_default_is_native(tmp_path):
    conn = connect(database(tmp_path))
    assert type(conn) is sqlite3.Connection
    conn.close()


def test_fresh_leases_retire_all_aliases_and_preserve_statements(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        first = connect(path)
        native = first._native
        cursor = first.execute("SELECT 1")
        assert cursor.connection is first
        assert _is_sqlite_connection(first)
        first.close()
        second = connect(path)
        assert second is not first
        assert second._native is native
        assert not _is_sqlite_connection(first)
        for action in (
            lambda: first.execute("SELECT 1"),
            cursor.fetchone,
            lambda: cursor.connection,
        ):
            with pytest.raises(sqlite3.ProgrammingError):
                action()
        assert second.execute("SELECT 2").fetchone() == (2,)
        second.close()


def test_dirty_and_failed_connections_are_discarded(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        dirty = connect(path)
        native = dirty._native
        dirty.execute("BEGIN")
        dirty.execute("INSERT INTO records VALUES(1)")
        dirty.close()
        clean = connect(path)
        assert clean._native is not native
        assert clean.execute("SELECT * FROM records").fetchall() == []
        clean.execute("INSERT INTO records VALUES(1)")
        with pytest.raises(sqlite3.IntegrityError):
            clean.execute("INSERT INTO records VALUES(1)")
        failed_native = clean._native
        clean.close()
        fresh = connect(path)
        assert fresh._native is not failed_native
        fresh.rollback()
        fresh_native = fresh._native
        fresh.close()
        final = connect(path)
        assert final._native is not fresh_native
        final.close()


def test_native_context_rollback_on_deferred_commit_failure(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = connect(path)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "CREATE TABLE child(value REFERENCES records(value) DEFERRABLE INITIALLY DEFERRED)"
        )
        with pytest.raises(sqlite3.IntegrityError), conn:
            conn.execute("BEGIN")
            conn.execute("INSERT INTO child VALUES(99)")
        assert not conn.in_transaction
        assert conn.execute("SELECT * FROM child").fetchall() == []
        conn.close()


def test_scope_exit_closes_active_and_idle_and_keeps_commit(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        active = connect(path)
        active.execute("BEGIN")
        active.execute("INSERT INTO records VALUES(42)")
        active.commit()
        idle = connect(path)
        idle.close()
    assert not _is_sqlite_connection(active)
    with pytest.raises(sqlite3.ProgrammingError):
        active.execute("SELECT 1")
    with sqlite3.connect(path) as reopened:
        assert reopened.execute("SELECT * FROM records").fetchall() == [(42,)]


def test_owner_and_file_identity_fail_closed(tmp_path, monkeypatch):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = connect(path)
        with ThreadPoolExecutor() as executor:
            with pytest.raises(sqlite3.ProgrammingError):
                executor.submit(conn.execute, "SELECT 1").result()
        real_pid = os.getpid()
        with monkeypatch.context() as patch:
            patch.setattr(os, "getpid", lambda: real_pid + 1)
            with pytest.raises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        path.rename(path.with_suffix(".old"))
        sqlite3.connect(path).close()
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")
        assert not _is_sqlite_connection(conn)


def test_idle_bound_and_option_separation(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        first, second = connect(path), connect(path)
        second_native = second._native
        first.close()
        second.close()
        with pytest.raises(sqlite3.ProgrammingError):
            second_native.execute("SELECT 1")
        reader = connect(path, "reader")
        assert reader._native is not first._native
        reader.close()


def test_script_discards_and_cursor_fetch_iteration(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = connect(path)
        conn.executescript(
            "INSERT INTO records VALUES(1); INSERT INTO records VALUES(2);"
        )
        cursor = conn.execute("SELECT value FROM records ORDER BY value")
        assert cursor.fetchone() == (1,)
        assert list(cursor) == [(2,)]
        native = conn._native
        conn.close()
        fresh = connect(path)
        assert fresh._native is not native
        fresh.close()


def test_database_argument_cannot_bypass_pin(tmp_path):
    path = database(tmp_path)
    other = tmp_path / "other.db"
    sqlite3.connect(other).close()
    with _reuse_connections(path, maximum_idle=1):
        with pytest.raises(sqlite3.ProgrammingError):
            _connect_scoped(path, kind="reader", database=":memory:")
        with pytest.raises(sqlite3.ProgrammingError):
            _connect_scoped(path, kind="reader", database=str(other))
        with pytest.raises(sqlite3.ProgrammingError):
            _connect_scoped(path, kind="reader", database=other.as_uri(), uri=True)
        conn = _connect_scoped(
            path, kind="reader", database=path.as_uri() + "?mode=ro", uri=True
        )
        assert conn.execute("SELECT * FROM records").fetchall() == []
        conn.close()


def test_abrupt_process_exit_keeps_durable_commit(tmp_path):
    path = database(tmp_path)
    script = """
import os, sys
from pathlib import Path
from constitutional_swarm._sqlite_connections import _reuse_connections, _connect_scoped
path = Path(sys.argv[1])
with _reuse_connections(path, maximum_idle=1):
    conn = _connect_scoped(path, kind='writer', database=str(path), isolation_level=None)
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('BEGIN IMMEDIATE')
    conn.execute('INSERT INTO records VALUES(7)')
    conn.commit()
    conn.close()
    os._exit(0)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=False,
        env={
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        },
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute("SELECT * FROM records").fetchall() == [(7,)]


def test_unissued_lease_is_not_a_connection():
    assert not _is_sqlite_connection(object.__new__(_ConnectionLease))


@pytest.mark.parametrize(
    "pragma",
    [
        "foreign_keys=ON",
        "query_only=ON",
        "synchronous=NORMAL",
        "busy_timeout=123",
        "wal_autocheckpoint=0",
    ],
)
def test_altered_configuration_is_discarded(tmp_path, pragma):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = _configured_connection(connect(path))
        native = conn._native
        conn.execute(f"PRAGMA {pragma}")
        conn.close()
        fresh = connect(path)
        assert fresh._native is not native
        fresh.close()


def test_configured_reuse_keeps_row_factory_contract(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = connect(path)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        _configured_connection(conn)
        native = conn._native
        conn.close()
        fresh = connect(path)
        assert fresh._native is native
        assert fresh.row_factory is None
        fresh.close()


def test_unconfigured_connection_is_never_reused(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = _connect_scoped(
            path, kind="writer", database=str(path), isolation_level=None
        )
        native = conn._native
        conn.close()
        fresh = connect(path)
        assert fresh._native is not native
        fresh.close()


def test_scoped_gcb_workflow_creation_commits(tmp_path):
    from tests.gcb_apcc_support import typed_bootstrap

    path = tmp_path / "authority.sqlite3"
    admin = typed_bootstrap().provision(path)
    with _reuse_connections(path, maximum_idle=3):
        admin.create_workflow(
            workflow_id="workflow", nodes={"node": []}, policy_version="1"
        )
        assert admin.commit_port.control_version() == 1
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_discarded_pragma_cursor_does_not_block_commit(tmp_path):
    path = database(tmp_path)
    with _reuse_connections(path, maximum_idle=1):
        conn = connect(path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO records VALUES (23)")
        conn.commit()
        conn.close()
