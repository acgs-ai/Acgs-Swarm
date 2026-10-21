"""Private, lexical SQLite connection reuse for trusted runtime children.

Only clean, explicitly closed leases are reusable. Transactions and durability
remain SQLite's responsibility; this module never inserts SQL or caches results.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, TypeGuard
from urllib.parse import unquote, urlsplit
from weakref import WeakSet

_SCOPE: ContextVar[_Scope | None] = ContextVar("sqlite_reuse_scope", default=None)


class _Scope:
    def __init__(self, path: Path, maximum_idle: int) -> None:
        self.path = path.resolve(strict=True)
        stat = self.path.stat()
        self.identity = (stat.st_dev, stat.st_ino)
        self.owner = (os.getpid(), threading.get_ident())
        self.maximum_idle = maximum_idle
        self.idle: list[tuple[tuple[Any, ...], sqlite3.Connection]] = []
        self.active: set[_ConnectionLease] = set()
        self.closed = False

    def check(self) -> None:
        if self.closed or _SCOPE.get() is not self:
            raise sqlite3.ProgrammingError("SQLite reuse scope is not active")
        if self.owner != (os.getpid(), threading.get_ident()):
            raise sqlite3.ProgrammingError("SQLite reuse scope owner changed")
        try:
            stat = self.path.stat()
        except OSError as exc:
            raise sqlite3.ProgrammingError("SQLite reuse database disappeared") from exc
        if self.identity != (stat.st_dev, stat.st_ino):
            raise sqlite3.ProgrammingError("SQLite reuse database identity changed")

    def close(self) -> None:
        self.closed = True
        error: BaseException | None = None
        for lease in tuple(self.active):
            try:
                lease._dispose()
            except BaseException as exc:
                error = error or exc
        for _, native in self.idle:
            try:
                native.close()
            except BaseException as exc:
                error = error or exc
        self.idle.clear()
        if error is not None:
            raise error


class _CursorLease:
    def __init__(self, lease: _ConnectionLease, native: sqlite3.Cursor) -> None:
        self._lease = lease
        self._native = native
        self._closed = False

    def _check(self) -> sqlite3.Cursor:
        self._lease._check()
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed cursor")
        return self._native

    def _call(self, name: str, *args: Any) -> Any:
        cursor = self._check()
        try:
            return getattr(cursor, name)(*args)
        except BaseException:
            self._lease._tainted = True
            raise

    @property
    def connection(self) -> _ConnectionLease:
        self._check()
        return self._lease

    @property
    def rowcount(self) -> int:
        return self._check().rowcount

    @property
    def lastrowid(self) -> int | None:
        return self._check().lastrowid

    @property
    def description(self) -> Any:
        return self._check().description

    def execute(self, sql: str, parameters: Any = ()) -> _CursorLease:
        self._call("execute", sql, parameters)
        return self

    def executemany(self, sql: str, parameters: Any) -> _CursorLease:
        self._call("executemany", sql, parameters)
        return self

    def executescript(self, sql: str) -> _CursorLease:
        self._lease._tainted = True
        self._call("executescript", sql)
        return self

    def fetchone(self) -> Any:
        return self._call("fetchone")

    def fetchmany(self, size: int = 1) -> Any:
        return self._call("fetchmany", size)

    def fetchall(self) -> Any:
        return self._call("fetchall")

    def __iter__(self) -> _CursorLease:
        self._check()
        return self

    def __next__(self) -> Any:
        cursor = self._check()
        try:
            return next(cursor)
        except StopIteration:
            raise
        except BaseException:
            self._lease._tainted = True
            raise

    def close(self) -> None:
        if not self._closed:
            self._lease._check()
            self._retire()

    def _retire(self) -> None:
        self._closed = True
        self._native.close()


class _ConnectionLease:
    def __init__(self, scope: _Scope, key: tuple[Any, ...], native: sqlite3.Connection):
        self._scope = scope
        self._key = key
        self._native = native
        self._closed = False
        self._tainted = False
        self._configuration: tuple[Any, ...] | None = None
        self._cursors: WeakSet[_CursorLease] = WeakSet()

    def _check(self) -> sqlite3.Connection:
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database")
        self._scope.check()
        if self not in self._scope.active:
            raise sqlite3.ProgrammingError("SQLite lease is not issued")
        return self._native

    def cursor(self) -> _CursorLease:
        native = self._check()
        cursor = _CursorLease(self, native.cursor())
        self._cursors.add(cursor)
        return cursor

    def execute(self, sql: str, parameters: Any = ()) -> _CursorLease:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, parameters: Any) -> _CursorLease:
        return self.cursor().executemany(sql, parameters)

    def executescript(self, sql: str) -> _CursorLease:
        return self.cursor().executescript(sql)

    @property
    def row_factory(self) -> Any:
        return self._check().row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        if value is not None and value is not sqlite3.Row:
            raise sqlite3.ProgrammingError(
                "Custom row factories are outside the reuse contract"
            )
        self._check().row_factory = value

    @property
    def in_transaction(self) -> bool:
        return self._check().in_transaction

    def commit(self) -> None:
        native = self._check()
        try:
            native.commit()
        except BaseException:
            self._tainted = True
            raise

    def rollback(self) -> None:
        native = self._check()
        self._tainted = True
        native.rollback()

    def __enter__(self) -> _ConnectionLease:
        self._check().__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        native = self._check()
        if args[0] is not None:
            self._tainted = True
        try:
            return native.__exit__(*args)
        except BaseException:
            self._tainted = True
            raise

    def _dispose(self) -> None:
        self._closed = True
        self._scope.active.discard(self)
        try:
            for cursor in self._cursors:
                if not cursor._closed:
                    cursor._retire()
        finally:
            self._cursors.clear()
            self._native.close()

    def close(self) -> None:
        if self._closed:
            return
        native = self._check()
        reusable = (
            not self._tainted
            and not native.in_transaction
            and self._configuration is not None
        )
        try:
            if self._configuration is not None:
                reusable = reusable and _settings(native) == self._configuration
            for cursor in self._cursors:
                if not cursor._closed:
                    cursor._retire()
        except BaseException:
            self._dispose()
            raise
        self._cursors.clear()
        self._closed = True
        self._scope.active.discard(self)
        if reusable and len(self._scope.idle) < self._scope.maximum_idle:
            native.row_factory = None
            self._scope.idle.append((self._key, native))
        else:
            native.close()


SQLiteConnection = sqlite3.Connection | _ConnectionLease


@contextmanager
def _reuse_connections(path: Path, *, maximum_idle: int) -> Iterator[None]:
    if type(maximum_idle) is not int or maximum_idle < 0:
        raise ValueError("maximum_idle must be a nonnegative integer")
    if _SCOPE.get() is not None:
        raise sqlite3.ProgrammingError("Nested SQLite reuse scopes are unsupported")
    scope = _Scope(path, maximum_idle)
    token = _SCOPE.set(scope)
    try:
        yield
    finally:
        body_failed = sys.exc_info()[0] is not None
        try:
            scope.close()
        except BaseException:
            if not body_failed:
                raise
        finally:
            _SCOPE.reset(token)


def _connect_scoped(
    path: Path, *, kind: str, database: str, **options: Any
) -> SQLiteConnection:
    scope = _SCOPE.get()
    if scope is None:
        return sqlite3.connect(database, **options)
    scope.check()
    if path.resolve(strict=True) != scope.path:
        raise sqlite3.ProgrammingError("SQLite reuse path mismatch")
    target = database
    if options.get("uri") and database.startswith("file:"):
        uri = urlsplit(database)
        if uri.netloc not in ("", "localhost"):
            raise sqlite3.ProgrammingError(
                "SQLite URI host is outside the reuse contract"
            )
        target = unquote(uri.path)
    try:
        actual_path = Path(target).resolve(strict=True)
    except OSError as exc:
        raise sqlite3.ProgrammingError(
            "SQLite connection target is unavailable"
        ) from exc
    if actual_path != scope.path:
        raise sqlite3.ProgrammingError("SQLite connection target mismatch")
    if "factory" in options:
        raise sqlite3.ProgrammingError("Custom connection factories cannot be reused")
    key = (kind, database, tuple((k, type(v), v) for k, v in sorted(options.items())))
    native = None
    for index, (idle_key, candidate) in enumerate(scope.idle):
        if idle_key == key:
            native = candidate
            del scope.idle[index]
            break
    if native is None:
        native = sqlite3.connect(database, **options)
    lease = _ConnectionLease(scope, key, native)
    scope.active.add(lease)
    return lease


def _is_sqlite_connection(value: object) -> TypeGuard[SQLiteConnection]:
    if isinstance(value, sqlite3.Connection):
        return True
    if type(value) is not _ConnectionLease:
        return False
    scope = _SCOPE.get()
    if type(scope) is not _Scope or value not in scope.active:
        return False
    try:
        if value._scope is not scope:
            return False
        value._check()
    except (sqlite3.Error, AttributeError):
        return False
    return True


def _settings(native: sqlite3.Connection) -> tuple[Any, ...]:
    values = []
    for pragma in (
        "foreign_keys",
        "query_only",
        "synchronous",
        "journal_mode",
        "busy_timeout",
        "wal_autocheckpoint",
    ):
        cursor = native.execute(f"PRAGMA {pragma}")
        try:
            values.append(cursor.fetchone()[0])
        finally:
            cursor.close()
    return tuple(values)


def _configured_connection(connection: SQLiteConnection) -> SQLiteConnection:
    """Record settings after the trusted connector has applied its configuration."""
    if type(connection) is _ConnectionLease:
        native = connection._check()
        connection._configuration = _settings(native)
    return connection
