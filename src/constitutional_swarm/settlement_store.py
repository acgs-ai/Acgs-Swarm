"""Settlement storage adapters for finalized mesh results.

The mesh only persists finalized assignment/result snapshots. Storage backends
implement a tiny append/load contract so future SQLite or object-store adapters
can slot in without changing mesh finality logic.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import warnings
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol

_RECEIPT_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

_fcntl: ModuleType | None
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None

_msvcrt: ModuleType | None
try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    _msvcrt = None


class DuplicateSettlementError(ValueError):
    """Raised when an append-only settlement store receives a duplicate key."""


@dataclass(frozen=True, slots=True)
class SettlementRecord:
    """Serialized settled assignment/result snapshot.

    ``constitutional_hash`` captures the governance document SHA256 that was
    active when the record was finalized.  This allows post-hoc audits to
    verify that each settlement operated under the correct constitutional
    version even if the constitution has been updated since.
    """

    assignment: dict[str, Any]
    result: dict[str, Any]
    constitutional_hash: str = ""
    schema_version: int = 1
    is_recovered: bool = False
    receipt_digest: str | None = None


def normalize_receipt_digest(value: str | None) -> str | None:
    """Accept a SHA-256 hex pointer or the absent-binding sentinel.

    Empty string and ``None`` mean "no completed receipt binding". Any other
    value must be a 64-character lowercase hex digest. This field is a pointer
    to a v0.1 receipt *payload digest*, not part of the settlement canonical
    digest.
    """

    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _RECEIPT_DIGEST_RE.fullmatch(value):
        raise ValueError(
            "receipt_digest must be a 64-character lowercase sha256 hex digest "
            f"or empty/None, got {value!r}"
        )
    return value


class SettlementStore(Protocol):
    """Minimal append/load interface for settled mesh records."""

    def append(self, record: SettlementRecord) -> None: ...

    def load_all(self) -> list[SettlementRecord]: ...

    def mark_pending(self, record: SettlementRecord) -> None: ...

    def clear_pending(self, assignment_id: str) -> None: ...

    def load_pending(self) -> list[SettlementRecord]: ...

    def pending_count(self) -> int: ...

    def describe(self) -> dict[str, Any]: ...


@dataclass(slots=True)
class _JsonlAssignmentIndex:
    """In-process cache of assignment IDs keyed to a file identity.

    Invalidated when inode, size, or mtime change so an external writer (or a
    second store instance) cannot hide a duplicate behind a stale set.
    """

    assignment_ids: set[str]
    inode: int | None
    size: int
    mtime_ns: int


class JSONLSettlementStore:
    """Append-only JSONL settlement store.

    Each line stores exactly one settled assignment/result snapshot. This is the
    default adapter for local development and single-node deployments.

    File-level locking (``fcntl.LOCK_EX``) serialises concurrent ``append``
    and pending-update calls so that duplicate-detection and read-modify-write
    operations are atomic.

    Duplicate detection uses an in-memory assignment-id index rebuilt under the
    same lock when the log's inode/size/mtime change. JSONL is therefore safe
    for cooperating processes that take the advisory lock; it is not a scale
    store. Multi-writer or large-volume deployments should use
    ``SQLiteSettlementStore``.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.pending_path = self.path.with_name(f"{self.path.name}.pending")
        self._lock_path = self.path.with_name(f"{self.path.name}.lock")
        self._index: _JsonlAssignmentIndex | None = None
        # Instrumentation for tests: whole-file scans and JSON object decodes.
        self.scan_passes = 0
        self.json_decode_count = 0

    @contextmanager
    def _file_lock(self) -> Generator[None, None, None]:
        """Acquire an exclusive advisory lock around the settlement log."""
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            elif _msvcrt is not None:
                if os.fstat(fd).st_size == 0:
                    # msvcrt.locking needs at least one byte to lock; write it once.
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_LOCK, 1)
            else:  # pragma: no cover - platform fallback of last resort
                warnings.warn(
                    "No supported file-locking primitive available; settlement log lock disabled",
                    RuntimeWarning,
                    stacklevel=2,
                )
            yield
        finally:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
            elif _msvcrt is not None:
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
            os.close(fd)

    def _file_signature(self) -> tuple[int | None, int, int]:
        if not self.path.exists():
            return (None, 0, 0)
        stat = self.path.stat()
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def _index_matches_file(self) -> bool:
        if self._index is None:
            return False
        inode, size, mtime_ns = self._file_signature()
        return (
            self._index.inode == inode
            and self._index.size == size
            and self._index.mtime_ns == mtime_ns
        )

    def _remember_index(self, assignment_ids: set[str]) -> None:
        inode, size, mtime_ns = self._file_signature()
        self._index = _JsonlAssignmentIndex(
            assignment_ids=assignment_ids,
            inode=inode,
            size=size,
            mtime_ns=mtime_ns,
        )

    def _known_assignment_ids_locked(self) -> set[str]:
        if self._index_matches_file():
            assert self._index is not None
            return self._index.assignment_ids
        ids = {
            str(record.assignment.get("assignment_id", ""))
            for record in self._load_all_unlocked()
        }
        ids.discard("")
        self._remember_index(ids)
        return ids

    def append(self, record: SettlementRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        assignment_id = str(record.assignment["assignment_id"])
        with self._file_lock():
            known_ids = self._known_assignment_ids_locked()
            if assignment_id in known_ids:
                raise DuplicateSettlementError(f"Settlement {assignment_id} already exists")
            payload = self._payload_from_record(record)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            known_ids.add(assignment_id)
            self._remember_index(known_ids)

    def load_all(self) -> list[SettlementRecord]:
        with self._file_lock():
            return self._load_all_unlocked()

    def _load_all_unlocked(self) -> list[SettlementRecord]:
        if not self.path.exists():
            return []

        self.scan_passes += 1
        records: list[SettlementRecord] = []
        with self.path.open(encoding="utf-8") as fh:
            lines = fh.readlines()

        for lineno, line in enumerate(lines, start=1):
            raw_line = line
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                self.json_decode_count += 1
            except json.JSONDecodeError:
                is_terminal_line = lineno == len(lines)
                # Salvage only the final truncated append. Earlier corruption
                # remains fail-loud because it indicates a damaged log, not an
                # interrupted final write.
                if is_terminal_line and not raw_line.endswith("\n"):
                    warnings.warn(
                        f"{self.path}:{lineno}: terminal truncated JSON line skipped",
                        stacklevel=2,
                    )
                    # Truncate the file to remove the partial line so the next
                    # append doesn't produce a permanently unreadable log.
                    with self.path.open("r+b") as fh_trunc:
                        fh_trunc.seek(-(len(raw_line.encode())), 2)
                        fh_trunc.truncate()
                    continue
                raise
            records.append(self._record_from_payload(payload))
        return records

    def mark_pending(self, record: SettlementRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        pending_record = replace(record, is_recovered=False)
        with self._file_lock():
            payloads = self._load_pending_payloads()
            assignment_id = str(pending_record.assignment["assignment_id"])
            payloads[assignment_id] = self._payload_from_record(pending_record)
            self._write_pending_payloads(payloads)

    def clear_pending(self, assignment_id: str) -> None:
        with self._file_lock():
            payloads = self._load_pending_payloads()
            if assignment_id not in payloads:
                return
            payloads.pop(assignment_id, None)
            self._write_pending_payloads(payloads)

    def load_pending(self) -> list[SettlementRecord]:
        return [
            self._record_from_payload(payload) for payload in self._load_pending_payloads().values()
        ]

    def pending_count(self) -> int:
        return len(self._load_pending_payloads())

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "jsonl",
            "path": str(self.path),
            "concurrency": "advisory-lock",
            "scale_default": "sqlite",
            "receipt_digest": True,
        }

    def get(self, assignment_id: str) -> SettlementRecord | None:
        for record in self.load_all():
            if str(record.assignment.get("assignment_id", "")) == assignment_id:
                return record
        return None

    def _load_pending_payloads(self) -> dict[str, dict[str, Any]]:
        if not self.pending_path.exists():
            return {}
        with self.pending_path.open(encoding="utf-8") as fh:
            payloads = json.load(fh)
        return {str(key): dict(value) for key, value in dict(payloads).items()}

    def _write_pending_payloads(self, payloads: dict[str, dict[str, Any]]) -> None:
        if not payloads:
            self.pending_path.unlink(missing_ok=True)
            return
        tmp_path = self.pending_path.with_name(f"{self.pending_path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payloads, fh, separators=(",", ":"))
        tmp_path.replace(self.pending_path)

    @staticmethod
    def _payload_from_record(record: SettlementRecord) -> dict[str, Any]:
        return {
            "assignment": record.assignment,
            "result": record.result,
            "constitutional_hash": record.constitutional_hash,
            "schema_version": record.schema_version,
            "is_recovered": record.is_recovered,
            "receipt_digest": normalize_receipt_digest(record.receipt_digest),
        }

    @classmethod
    def _record_from_payload(cls, payload: dict[str, Any]) -> SettlementRecord:
        record_kwargs: dict[str, Any] = {
            "assignment": dict(payload.get("assignment", {})),
            "result": dict(payload.get("result", {})),
            "constitutional_hash": payload.get("constitutional_hash", ""),
        }
        if "schema_version" in payload:
            record_kwargs["schema_version"] = int(payload["schema_version"])
        if "is_recovered" in payload:
            record_kwargs["is_recovered"] = bool(payload["is_recovered"])
        if "receipt_digest" in payload:
            record_kwargs["receipt_digest"] = normalize_receipt_digest(
                payload["receipt_digest"] if payload["receipt_digest"] is not None else None
            )
        return SettlementRecord(**record_kwargs)


class SQLiteSettlementStore:
    """SQLite-backed settlement store.

    Stores one row per settled assignment/result snapshot. Uses only the Python
    standard library so it remains available in minimal environments.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mesh_settlements (
                    assignment_id TEXT PRIMARY KEY,
                    assignment_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    constitutional_hash TEXT NOT NULL DEFAULT '',
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    is_recovered INTEGER NOT NULL DEFAULT 0,
                    receipt_digest TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_settlements (
                    assignment_id TEXT PRIMARY KEY,
                    assignment_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    constitutional_hash TEXT NOT NULL DEFAULT '',
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    is_recovered INTEGER NOT NULL DEFAULT 0,
                    receipt_digest TEXT
                )
                """
            )
            # Idempotently add constitutional_hash to databases created before
            # this column was introduced (ALTER TABLE IF NOT EXISTS requires
            # SQLite 3.37; use a try/except for broader compatibility).
            try:
                conn.execute(
                    "ALTER TABLE mesh_settlements ADD COLUMN "
                    "constitutional_hash TEXT NOT NULL DEFAULT ''"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE pending_settlements ADD COLUMN "
                    "constitutional_hash TEXT NOT NULL DEFAULT ''"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE mesh_settlements ADD COLUMN "
                    "schema_version INTEGER NOT NULL DEFAULT 1"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE pending_settlements ADD COLUMN "
                    "schema_version INTEGER NOT NULL DEFAULT 1"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE mesh_settlements ADD COLUMN "
                    "is_recovered INTEGER NOT NULL DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE pending_settlements ADD COLUMN "
                    "is_recovered INTEGER NOT NULL DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            # Nullable receipt pointer. Absent/NULL means the row has no
            # completed v0.1 receipt binding. Idempotent on existing DBs.
            try:
                conn.execute("ALTER TABLE mesh_settlements ADD COLUMN receipt_digest TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
            try:
                conn.execute("ALTER TABLE pending_settlements ADD COLUMN receipt_digest TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
            conn.commit()

    def _table_columns(self, table_name: str) -> set[str]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row[1]) for row in rows}

    def has_receipt_digest_column(self) -> bool:
        return "receipt_digest" in self._table_columns("mesh_settlements")

    def append(self, record: SettlementRecord) -> None:
        """Append a settlement record.

        Finalized records are immutable. Duplicate ``assignment_id`` values
        raise a deterministic error instead of replacing or silently ignoring
        the original settlement.
        """
        assignment_id = str(record.assignment["assignment_id"])
        digest = normalize_receipt_digest(record.receipt_digest)
        with sqlite3.connect(self.path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO mesh_settlements (
                        assignment_id,
                        assignment_json,
                        result_json,
                        constitutional_hash,
                        schema_version,
                        is_recovered,
                        receipt_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assignment_id,
                        json.dumps(record.assignment, separators=(",", ":")),
                        json.dumps(record.result, separators=(",", ":")),
                        record.constitutional_hash,
                        record.schema_version,
                        int(record.is_recovered),
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateSettlementError(
                    f"Settlement {assignment_id} already exists"
                ) from exc
            conn.commit()

    def load_all(self) -> list[SettlementRecord]:
        return self._load_records_from_table("mesh_settlements")

    def mark_pending(self, record: SettlementRecord) -> None:
        pending_record = replace(record, is_recovered=False)
        assignment_id = str(pending_record.assignment["assignment_id"])
        digest = normalize_receipt_digest(pending_record.receipt_digest)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_settlements (
                    assignment_id,
                    assignment_json,
                    result_json,
                    constitutional_hash,
                    schema_version,
                    is_recovered,
                    receipt_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assignment_id,
                    json.dumps(pending_record.assignment, separators=(",", ":")),
                    json.dumps(pending_record.result, separators=(",", ":")),
                    pending_record.constitutional_hash,
                    pending_record.schema_version,
                    int(pending_record.is_recovered),
                    digest,
                ),
            )
            conn.commit()

    def clear_pending(self, assignment_id: str) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "DELETE FROM pending_settlements WHERE assignment_id = ?",
                (assignment_id,),
            )
            conn.commit()

    def load_pending(self) -> list[SettlementRecord]:
        return self._load_records_from_table("pending_settlements")

    def _load_records_from_table(self, table_name: str) -> list[SettlementRecord]:
        if table_name not in {"mesh_settlements", "pending_settlements"}:
            raise ValueError(f"Unsupported settlement table: {table_name}")

        select_with_digest = f"""
            SELECT assignment_json, result_json, constitutional_hash,
                   schema_version, is_recovered, receipt_digest
            FROM {table_name}
            ORDER BY assignment_id
        """
        select_without_digest = f"""
            SELECT assignment_json, result_json, constitutional_hash,
                   schema_version, is_recovered, NULL
            FROM {table_name}
            ORDER BY assignment_id
        """
        select_without_is_recovered = f"""
            SELECT assignment_json, result_json, constitutional_hash, schema_version, 0, NULL
            FROM {table_name}
            ORDER BY assignment_id
        """
        select_without_schema_version = f"""
            SELECT assignment_json, result_json, constitutional_hash, 1, 0, NULL
            FROM {table_name}
            ORDER BY assignment_id
        """

        with sqlite3.connect(self.path) as conn:
            try:
                rows = conn.execute(select_with_digest).fetchall()
            except sqlite3.OperationalError as exc:
                if "no such column" not in str(exc).lower():
                    raise
                try:
                    rows = conn.execute(select_without_digest).fetchall()
                except sqlite3.OperationalError as inner:
                    if "no such column" not in str(inner).lower():
                        raise
                    try:
                        rows = conn.execute(select_without_is_recovered).fetchall()
                    except sqlite3.OperationalError as older:
                        if "no such column" not in str(older).lower():
                            raise
                        rows = conn.execute(select_without_schema_version).fetchall()
        return [
            SettlementRecord(
                assignment=dict(json.loads(assignment_json)),
                result=dict(json.loads(result_json)),
                constitutional_hash=constitutional_hash,
                schema_version=int(schema_version),
                is_recovered=bool(is_recovered),
                receipt_digest=normalize_receipt_digest(receipt_digest),
            )
            for (
                assignment_json,
                result_json,
                constitutional_hash,
                schema_version,
                is_recovered,
                receipt_digest,
            ) in rows
        ]

    def pending_count(self) -> int:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM pending_settlements").fetchone()
        return int(row[0]) if row is not None else 0

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "sqlite",
            "path": str(self.path),
            "receipt_digest": self.has_receipt_digest_column(),
            "columns": sorted(self._table_columns("mesh_settlements")),
        }

    def get(self, assignment_id: str) -> SettlementRecord | None:
        """Return one committed settlement, or None if absent."""
        for record in self.load_all():
            if str(record.assignment.get("assignment_id", "")) == assignment_id:
                return record
        return None


__all__ = [
    "DuplicateSettlementError",
    "JSONLSettlementStore",
    "SQLiteSettlementStore",
    "SettlementRecord",
    "SettlementStore",
    "normalize_receipt_digest",
]
