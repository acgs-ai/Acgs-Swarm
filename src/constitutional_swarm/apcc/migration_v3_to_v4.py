"""Offline, read-only-source SQLite APCC authority store migration (v3 -> v4).

Enforces ADR-0001:
- Never auto-migrates or mutates original v3 files in place.
- Copies candidate source databases to an isolated temporary directory before
  inspection so neither DB bytes nor ``-wal``/``-shm`` sidecars change.
- Distinguishes authentic pre-C32 v3 stores (cleanly refused) from authentic
  post-C32 v3 stores (migrated into a fresh schema v4 database).
- Chains ``semantic_checkpoint`` (``source.change_sequence + 1``,
  ``prior_digest = source.checkpoint_digest``) and emits an Ed25519-signed
  ``MigrationContinuityReceipt`` binding source and target hashes, fingerprints,
  checkpoint digests, and certificate sets.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..strict_json import StrictJSONError, loads as strict_loads
from .crypto import b64u_decode, b64u_encode, sha256_digest
from .model import Signature
from .ports import (
    APCCAuthorityConfig,
    AuthorityRuntime,
    AuthoritySigningRole,
    validate_runtime_signers,
)
from .sqlite_store import (
    _APCC_TABLES,
    _APPLICATION_ID,
    _AUTHORITY_SCHEMA_VERSION,
    _MAX_SAFE_INTEGER,
    _REQUIRED_SCHEMA_OBJECTS,
    _SCHEMA_FINGERPRINT,
    _SCHEMA_STATEMENTS,
    _SCHEMA_VERSION,
    _SEMANTIC_CHECKPOINT_TRIGGERS,
    SQLiteAuthorityReader,
    SQLiteAuthorityStore,
    _config_from_object,
    _config_object,
    _connect_create,
    _connect_reader,
    _json,
    _loads,
    _normalize_schema_sql,
    _schema,
    _seal_semantic_checkpoint,
    _semantic_checkpoint_row,
    _validate_schema,
    _validate_schema_manifest,
    _validate_semantic_integrity,
    _verify_semantic_checkpoint,
)

_MIGRATION_RECEIPT_DOMAIN = b"APCC-MIGRATION-CONTINUITY-V1"
_RECEIPT_PROTOCOL_VERSION = "APCC-1.0-draft"
_RECEIPT_TYPE = "apcc.migration-continuity-receipt"
_LIVE_WAL_DIAGNOSTIC = (
    "uncheckpointed WAL sidecar present; checkpoint source database before offline migration"
)
_V3_SCHEMA_VERSION = "3"
_V3_SCHEMA_INT = 3
_V3_SCHEMA_FINGERPRINT = sha256_digest(
    (
        f"schema-version={_V3_SCHEMA_VERSION}\n"
        + "\n".join(_normalize_schema_sql(item) for item in _SCHEMA_STATEMENTS)
    ).encode("utf-8")
)
_GCB_MARKER_TABLES = frozenset(
    {
        "agents",
        "decisions",
        "nodes",
        "outbox",
        "receipt_evidence",
        "staged_artifacts",
        "store_seal",
        "workflows",
    }
)
# Topological copy order respecting SQLite foreign-key references.
_ORDERED_DATA_TABLES: tuple[str, ...] = (
    "audit_events",
    "commit_index",
    "request_index",
    "nonce_ledger",
    "evidence_refs",
    "certificates",
    "logical_nodes",
    "candidates",
    "commit_output_refs",
    "apcc_decisions",
    "certificate_dispositions",
    "predecessor_edges",
    "supersession_edges",
    "workflow_revocations",
    "actor_revocations",
    "trust_log",
    "control_events",
    "apcc_outbox",
    "commit_conflicts",
)
_COUNTED_TABLES: tuple[str, ...] = (
    "logical_nodes",
    "candidates",
    "commit_index",
    "certificates",
    "certificate_dispositions",
    "audit_events",
    "trust_log",
    "control_events",
    "apcc_outbox",
    "predecessor_edges",
    "supersession_edges",
)


class StoreClassification(StrEnum):
    """Offline classification of an APCC SQLite database file."""

    V4_CURRENT = "v4_current"
    V3_POST_C32_MIGRATABLE = "v3_post_c32_migratable"
    V3_PRE_C32_INCOMPATIBLE = "v3_pre_c32_incompatible"
    V3_GCB_UNSUPPORTED = "v3_gcb_unsupported"
    V3_TAMPERED_OR_CORRUPT = "v3_tampered_or_corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


class APCCMigrationError(RuntimeError):
    """Fail-closed migration, inspection, or continuity-receipt error."""

    def __init__(
        self,
        reason: str,
        *,
        classification: StoreClassification | None = None,
        diagnostics: tuple[str, ...] = (),
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.classification = classification
        self.diagnostics = diagnostics


@dataclass(frozen=True, slots=True)
class StoreInspectionReport:
    """Read-only inspection summary for an APCC SQLite store file."""

    source_path: Path
    source_sha256: str
    classification: StoreClassification
    user_version: int | None
    metadata_schema_version: str | None
    schema_fingerprint: str | None
    authority_store_id: str | None
    source_change_sequence: int | None
    source_checkpoint_digest: str | None
    diagnostics: tuple[str, ...]
    table_counts: Mapping[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "source_path": str(self.source_path),
            "source_sha256": self.source_sha256,
            "classification": self.classification.value,
            "user_version": self.user_version,
            "metadata_schema_version": self.metadata_schema_version,
            "schema_fingerprint": self.schema_fingerprint,
            "authority_store_id": self.authority_store_id,
            "source_change_sequence": self.source_change_sequence,
            "source_checkpoint_digest": self.source_checkpoint_digest,
            "diagnostics": list(self.diagnostics),
            "table_counts": dict(self.table_counts),
        }


@dataclass(frozen=True, slots=True)
class MigrationContinuityReceipt:
    """Signed continuity proof linking an immutable v3 store to its fresh v4 copy."""

    protocol_version: str
    receipt_type: str
    authority_store_id: str
    source_sha256: str
    source_schema_version: str
    source_schema_fingerprint: str
    source_change_sequence: str
    source_checkpoint_digest: str
    target_sha256: str
    target_schema_version: str
    target_schema_fingerprint: str
    target_change_sequence: str
    target_prior_digest: str
    target_checkpoint_digest: str
    migrated_certificate_digests_sha256: str
    certificate_count: str
    migrated_counts: Mapping[str, int]
    migrated_at_ms: str
    signature: Signature

    def to_body_object(self) -> dict[str, object]:
        return {
            "protocol_version": self.protocol_version,
            "receipt_type": self.receipt_type,
            "authority_store_id": self.authority_store_id,
            "source_sha256": self.source_sha256,
            "source_schema_version": self.source_schema_version,
            "source_schema_fingerprint": self.source_schema_fingerprint,
            "source_change_sequence": self.source_change_sequence,
            "source_checkpoint_digest": self.source_checkpoint_digest,
            "target_sha256": self.target_sha256,
            "target_schema_version": self.target_schema_version,
            "target_schema_fingerprint": self.target_schema_fingerprint,
            "target_change_sequence": self.target_change_sequence,
            "target_prior_digest": self.target_prior_digest,
            "target_checkpoint_digest": self.target_checkpoint_digest,
            "migrated_certificate_digests_sha256": self.migrated_certificate_digests_sha256,
            "certificate_count": self.certificate_count,
            "migrated_counts": {k: self.migrated_counts[k] for k in sorted(self.migrated_counts)},
            "migrated_at_ms": self.migrated_at_ms,
        }

    def canonical_body_bytes(self) -> bytes:
        return _json(self.to_body_object()).encode("utf-8")

    def to_object(self) -> dict[str, object]:
        body = self.to_body_object()
        body["signature"] = self.signature.to_object()
        return body

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> MigrationContinuityReceipt:
        required_keys = {
            "protocol_version",
            "receipt_type",
            "authority_store_id",
            "source_sha256",
            "source_schema_version",
            "source_schema_fingerprint",
            "source_change_sequence",
            "source_checkpoint_digest",
            "target_sha256",
            "target_schema_version",
            "target_schema_fingerprint",
            "target_change_sequence",
            "target_prior_digest",
            "target_checkpoint_digest",
            "migrated_certificate_digests_sha256",
            "certificate_count",
            "migrated_counts",
            "migrated_at_ms",
            "signature",
        }
        if set(value) != required_keys:
            raise APCCMigrationError("migration continuity receipt has unexpected keys")
        counts_raw = value["migrated_counts"]
        if not isinstance(counts_raw, Mapping) or not all(
            isinstance(k, str) and type(v) is int and v >= 0
            for k, v in counts_raw.items()
        ):
            raise APCCMigrationError("migration continuity receipt counts are invalid")
        sig_raw = value["signature"]
        if not isinstance(sig_raw, Mapping):
            raise APCCMigrationError("migration continuity receipt signature is invalid")
        try:
            sig = Signature.from_object(cast("Mapping[str, object]", sig_raw))
        except Exception as error:
            raise APCCMigrationError(
                "migration continuity receipt signature record is invalid"
            ) from error
        str_fields = {
            k: value[k]
            for k in required_keys - {"migrated_counts", "signature"}
        }
        if not all(isinstance(v, str) for v in str_fields.values()):
            raise APCCMigrationError("migration continuity receipt fields must be strings")
        return cls(
            protocol_version=cast(str, str_fields["protocol_version"]),
            receipt_type=cast(str, str_fields["receipt_type"]),
            authority_store_id=cast(str, str_fields["authority_store_id"]),
            source_sha256=cast(str, str_fields["source_sha256"]),
            source_schema_version=cast(str, str_fields["source_schema_version"]),
            source_schema_fingerprint=cast(str, str_fields["source_schema_fingerprint"]),
            source_change_sequence=cast(str, str_fields["source_change_sequence"]),
            source_checkpoint_digest=cast(str, str_fields["source_checkpoint_digest"]),
            target_sha256=cast(str, str_fields["target_sha256"]),
            target_schema_version=cast(str, str_fields["target_schema_version"]),
            target_schema_fingerprint=cast(str, str_fields["target_schema_fingerprint"]),
            target_change_sequence=cast(str, str_fields["target_change_sequence"]),
            target_prior_digest=cast(str, str_fields["target_prior_digest"]),
            target_checkpoint_digest=cast(str, str_fields["target_checkpoint_digest"]),
            migrated_certificate_digests_sha256=cast(
                str, str_fields["migrated_certificate_digests_sha256"]
            ),
            certificate_count=cast(str, str_fields["certificate_count"]),
            migrated_counts=dict(counts_raw),
            migrated_at_ms=cast(str, str_fields["migrated_at_ms"]),
            signature=sig,
        )


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """Output bundle returned by :func:`migrate_sqlite_v3_to_v4`."""

    inspection: StoreInspectionReport
    target_path: Path
    receipt_path: Path | None
    receipt: MigrationContinuityReceipt


def _sha256_file_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _has_live_wal(database: Path) -> bool:
    """True when ``database`` has a non-empty ``-wal`` sidecar (uncheckpointed writes)."""
    sidecar = Path(f"{database}-wal")
    return sidecar.exists() and sidecar.stat().st_size > 0


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_new_file(destination: Path, content: bytes) -> None:
    if destination.exists():
        raise APCCMigrationError(f"refusing to overwrite existing path: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{secrets.token_hex(12)}.apcc-tmp"
    )
    try:
        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    existing = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for table in _COUNTED_TABLES:
        if table in existing:
            counts[table] = int(
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            )
    return counts


def _certificate_set_digest(connection: sqlite3.Connection) -> tuple[str, int]:
    digests = sorted(
        str(row[0])
        for row in connection.execute(
            "SELECT certificate_digest FROM certificates ORDER BY certificate_digest"
        ).fetchall()
    )
    return sha256_digest(_json(digests).encode("utf-8")), len(digests)


def _check_ddl_and_storage(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, ...], bool]:
    """Return ``(diagnostics, has_gcb_tables)`` for an offline copy; no diagnostics means OK."""
    diagnostics: list[str] = []
    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        diagnostics.append("sqlite quick_check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        diagnostics.append("sqlite foreign_key_check failed")
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','index','trigger') AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    table_names = {str(name) for kind, name, _table, _sql in rows if kind == "table"}
    has_gcb = _GCB_MARKER_TABLES.issubset(table_names)
    has_any_gcb = bool(table_names & _GCB_MARKER_TABLES)
    extra_tables = (
        table_names - _APCC_TABLES - _GCB_MARKER_TABLES
        if has_gcb
        else table_names - _APCC_TABLES
    )
    if has_any_gcb and not has_gcb:
        diagnostics.append("partial GCB table set present alongside APCC store")
    if extra_tables:
        diagnostics.append(
            f"unexpected non-APCC table(s) present: {', '.join(sorted(extra_tables))}"
        )
    actual = {
        (str(kind), str(name)): _normalize_schema_sql(str(sql))
        for kind, name, _table, sql in rows
        if sql is not None
    }
    if any(
        actual.get(key) != expected for key, expected in _REQUIRED_SCHEMA_OBJECTS.items()
    ):
        diagnostics.append("missing or modified APCC DDL object compared to schema manifest")
    if any(
        (kind == "trigger" and (str(kind), str(name)) not in _REQUIRED_SCHEMA_OBJECTS)
        or (
            kind == "index"
            and table in _APCC_TABLES
            and (str(kind), str(name)) not in _REQUIRED_SCHEMA_OBJECTS
            and not str(name).startswith("sqlite_autoindex_")
        )
        for kind, name, table, _sql in rows
    ):
        diagnostics.append("unexpected extra trigger or APCC table index present")
    return (tuple(diagnostics), has_gcb)


def _pre_c32_audit_id(kind: str, *parts: str) -> str:
    """Pre-C32 (schema v3 before framed_digest) NUL-joined audit/event identity."""
    return sha256_digest((kind + "\x00" + "\x00".join(parts)).encode("utf-8"))


def _diagnose_pre_c32_incompatibility(
    connection: sqlite3.Connection,
    config: APCCAuthorityConfig,
) -> tuple[bool, str]:
    """Return True iff the store passes full semantic validation under pre-C32 audit IDs."""
    try:
        _validate_semantic_integrity(
            connection, config, audit_id_fn=_pre_c32_audit_id
        )
    except ValueError:
        return (
            False,
            "semantic integrity validation failed under both post-C32 and pre-C32 rules",
        )
    return (
        True,
        "pre_c32_legacy_audit_ids: store passes full semantic validation only "
        "under pre-C32 NUL-joined audit_event_id derivation",
    )


def _parse_canonical_nonneg_decimal(value: str, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise APCCMigrationError(f"{label} is not a canonical decimal integer")
    parsed = int(value)
    if parsed < 0 or parsed > _MAX_SAFE_INTEGER:
        raise APCCMigrationError(f"{label} exceeds safe integer bounds")
    return parsed


def _early_reject_report(
    source_path: Path,
    source_sha256: str,
    classification: StoreClassification,
    *,
    diagnostics: tuple[str, ...],
    user_version: int | None = None,
    table_counts: Mapping[str, int] | None = None,
) -> StoreInspectionReport:
    """Report for a store rejected before its metadata and checkpoint were read."""
    return StoreInspectionReport(
        source_path=source_path,
        source_sha256=source_sha256,
        classification=classification,
        user_version=user_version,
        metadata_schema_version=None,
        schema_fingerprint=None,
        authority_store_id=None,
        source_change_sequence=None,
        source_checkpoint_digest=None,
        diagnostics=diagnostics,
        table_counts={} if table_counts is None else table_counts,
    )


def _inspect_temp_copy(
    tmp_db: Path, *, source_path: Path, source_sha256: str
) -> StoreInspectionReport:
    conn = sqlite3.connect(str(tmp_db))
    try:
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            journal_row = conn.execute("PRAGMA journal_mode").fetchone()
            app_row = conn.execute("PRAGMA application_id").fetchone()
            uv_row = conn.execute("PRAGMA user_version").fetchone()
        except sqlite3.DatabaseError as error:
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("file is not a valid SQLite database", str(error)),
            )
        user_version = int(uv_row[0]) if uv_row is not None else None
        if app_row is None or tuple(app_row) != (_APPLICATION_ID,):
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.UNSUPPORTED_SCHEMA,
                diagnostics=("SQLite application_id does not match APCC (0x41504343)",),
                user_version=user_version,
            )
        if journal_row is None or tuple(journal_row) != ("wal",):
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("APCC SQLite store requires WAL journal mode",),
                user_version=user_version,
            )

        try:
            counts = _table_counts(conn)
            has_metadata = (
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
                ).fetchone()
                is not None
            )
        except sqlite3.DatabaseError as error:
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("corrupt SQLite catalog in APCC store", str(error)),
                user_version=user_version,
            )
        if not has_metadata:
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.UNSUPPORTED_SCHEMA,
                diagnostics=("missing APCC metadata table",),
                user_version=user_version,
                table_counts=counts,
            )

        try:
            meta = {
                str(k): str(v)
                for k, v in conn.execute(
                    "SELECT key, value FROM metadata ORDER BY key"
                ).fetchall()
            }
        except sqlite3.DatabaseError as error:
            return _early_reject_report(
                source_path,
                source_sha256,
                StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("metadata table is corrupt or has unexpected columns", str(error)),
                user_version=user_version,
                table_counts=counts,
            )
        meta_ver = meta.get("schema_version")
        schema_fp = meta.get("schema_fingerprint")
        cfg_text = meta.get("config")
        parsed_config: APCCAuthorityConfig | None = None
        store_id: str | None = None
        if cfg_text is not None:
            try:
                cfg_obj = _loads(cfg_text)
                if _json(cfg_obj) == cfg_text:
                    parsed_config = _config_from_object(cfg_obj)
                    store_id = parsed_config.authority_store_id
            except Exception:
                parsed_config = None

        change_seq: int | None = None
        checkpoint_digest: str | None = None
        try:
            change_seq, _prior, checkpoint_digest, _kid, _sig = _semantic_checkpoint_row(conn)
        except Exception:
            pass

        # Every identifying field is final from here on; bind them once.
        full_report = partial(
            StoreInspectionReport,
            source_path=source_path,
            source_sha256=source_sha256,
            user_version=user_version,
            metadata_schema_version=meta_ver,
            schema_fingerprint=schema_fp,
            authority_store_id=store_id,
            source_change_sequence=change_seq,
            source_checkpoint_digest=checkpoint_digest,
            table_counts=counts,
        )

        ddl_diagnostics, has_gcb = _check_ddl_and_storage(conn)
        if user_version == _SCHEMA_VERSION and meta_ver == _AUTHORITY_SCHEMA_VERSION:
            try:
                conn.execute("BEGIN")
                _validate_schema(conn)
                conn.rollback()
                return full_report(
                    classification=StoreClassification.V4_CURRENT,
                    diagnostics=("store already validates cleanly under schema v4",),
                )
            except Exception as error:
                conn.rollback()
                return full_report(
                    classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
                    diagnostics=(
                        "store claims schema v4 metadata/user_version but failed v4 validation",
                        str(error),
                    ),
                )

        if user_version != _V3_SCHEMA_INT or meta_ver != _V3_SCHEMA_VERSION:
            if {user_version, meta_ver} & {_V3_SCHEMA_INT, _V3_SCHEMA_VERSION}:
                return full_report(
                    classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
                    diagnostics=(
                        f"PRAGMA user_version ({user_version}) and metadata.schema_version "
                        f"({meta_ver!r}) disagree",
                    ),
                )
            return full_report(
                classification=StoreClassification.UNSUPPORTED_SCHEMA,
                diagnostics=(
                    f"unsupported schema user_version={user_version} metadata={meta_ver!r}",
                ),
            )

        if has_gcb:
            return full_report(
                classification=StoreClassification.V3_GCB_UNSUPPORTED,
                diagnostics=(
                    "GCB-attached SQLite store migration is out of scope for flat APCC copy",
                ),
            )

        if ddl_diagnostics:
            return full_report(
                classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=ddl_diagnostics,
            )

        if (
            set(meta) != {"config", "schema_fingerprint", "schema_version"}
            or schema_fp != _V3_SCHEMA_FINGERPRINT
            or parsed_config is None
        ):
            return full_report(
                classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("v3 metadata, config, or schema_fingerprint is invalid",),
            )

        try:
            sealed = _verify_semantic_checkpoint(conn, parsed_config, _V3_SCHEMA_FINGERPRINT)
            if not sealed:
                raise APCCMigrationError("v3 semantic checkpoint is unsealed")
        except Exception as error:
            return full_report(
                classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
                diagnostics=("v3 semantic checkpoint verification failed", str(error)),
            )

        try:
            _validate_semantic_integrity(conn, parsed_config)
        except ValueError:
            is_pre_c32, detail = _diagnose_pre_c32_incompatibility(conn, parsed_config)
            classification = (
                StoreClassification.V3_PRE_C32_INCOMPATIBLE
                if is_pre_c32
                else StoreClassification.V3_TAMPERED_OR_CORRUPT
            )
            return full_report(
                classification=classification,
                diagnostics=(detail,),
            )

        return full_report(
            classification=StoreClassification.V3_POST_C32_MIGRATABLE,
            diagnostics=("authentic post-C32 schema v3 store ready for offline v4 migration",),
        )
    finally:
        conn.close()


def inspect_sqlite_store(source_path: Path) -> StoreInspectionReport:
    """Classify a SQLite APCC store without mutating source bytes or sidecars."""
    source = Path(source_path)
    if not source.is_file():
        raise APCCMigrationError(f"source database file does not exist: {source}")
    source_sha256 = _sha256_file_hex(source)
    if _has_live_wal(source):
        return _early_reject_report(
            source,
            source_sha256,
            StoreClassification.V3_TAMPERED_OR_CORRUPT,
            diagnostics=(_LIVE_WAL_DIAGNOSTIC,),
        )
    with tempfile.TemporaryDirectory(prefix="apcc-inspect-") as td:
        tmp_db = Path(td) / "source-copy.sqlite"
        shutil.copy2(source, tmp_db)
        return _inspect_temp_copy(
            tmp_db, source_path=source, source_sha256=source_sha256
        )


def _copy_all_apcc_tables(
    src_conn: sqlite3.Connection, dst_conn: sqlite3.Connection
) -> None:
    expected = set(_ORDERED_DATA_TABLES) | {"metadata", "semantic_checkpoint"}
    if expected != _APCC_TABLES:
        raise APCCMigrationError(
            "migration table list out of sync with SQLite store schema"
        )
    for table in _ORDERED_DATA_TABLES:
        cols = [
            str(row[1])
            for row in src_conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        ]
        if not cols:
            raise APCCMigrationError(f"missing columns when copying table {table}")
        col_list = ",".join(f'"{col}"' for col in cols)
        placeholders = ",".join("?" for _ in cols)
        # Stream rows across the two connections instead of buffering a whole table.
        dst_conn.executemany(
            f'INSERT INTO "{table}" ({col_list}) VALUES ({placeholders})',
            src_conn.execute(f'SELECT {col_list} FROM "{table}" ORDER BY rowid'),
        )


def _sign_migration_receipt(
    body: MigrationContinuityReceipt, runtime: AuthorityRuntime
) -> MigrationContinuityReceipt:
    signature = runtime.key_provider.sign(
        AuthoritySigningRole.COMMIT,
        body.signature.key_id,
        _MIGRATION_RECEIPT_DOMAIN,
        body.canonical_body_bytes(),
    )
    if signature.algorithm != "Ed25519" or signature.key_id != body.signature.key_id:
        raise APCCMigrationError("migration continuity receipt signing failed")
    return replace(body, signature=signature)


def _check_receipt_bound_file(path: Path, label: str, expected_sha256: str) -> None:
    """Fail closed unless ``path`` is a quiescent file matching the receipt hash."""
    if not path.is_file():
        raise APCCMigrationError(f"{label} path does not exist: {path}")
    if _has_live_wal(path):
        raise APCCMigrationError(f"{label} store has uncheckpointed WAL sidecar")
    if _sha256_file_hex(path) != expected_sha256:
        raise APCCMigrationError(f"migration receipt {label} SHA-256 mismatch")


def verify_migration_receipt(
    receipt: MigrationContinuityReceipt | Mapping[str, object] | bytes,
    *,
    config: APCCAuthorityConfig,
    target_path: Path | None = None,
    source_path: Path | None = None,
) -> MigrationContinuityReceipt:
    """Verify the Ed25519 signature and optional source/target bindings of a receipt."""
    if isinstance(receipt, (bytes, bytearray)):
        try:
            obj = strict_loads(bytes(receipt), max_bytes=1_048_576, allow_float=False)
        except (StrictJSONError, TypeError) as error:
            raise APCCMigrationError("migration receipt is not valid strict JSON") from error
        if not isinstance(obj, Mapping):
            raise APCCMigrationError("migration receipt JSON must be an object")
        parsed = MigrationContinuityReceipt.from_object(cast("Mapping[str, object]", obj))
    elif isinstance(receipt, MigrationContinuityReceipt):
        parsed = receipt
    elif isinstance(receipt, Mapping):
        parsed = MigrationContinuityReceipt.from_object(receipt)
    else:
        raise APCCMigrationError("unsupported migration receipt input")

    if parsed.protocol_version != _RECEIPT_PROTOCOL_VERSION:
        raise APCCMigrationError("unsupported migration receipt protocol version")
    if parsed.receipt_type != _RECEIPT_TYPE:
        raise APCCMigrationError("unsupported migration receipt type")
    if parsed.authority_store_id != config.authority_store_id:
        raise APCCMigrationError("migration receipt authority store id mismatch")
    if parsed.source_schema_version != _V3_SCHEMA_VERSION:
        raise APCCMigrationError("migration receipt source schema version must be 3")
    if parsed.source_schema_fingerprint != _V3_SCHEMA_FINGERPRINT:
        raise APCCMigrationError("migration receipt source schema fingerprint mismatch")
    if parsed.target_schema_version != _AUTHORITY_SCHEMA_VERSION:
        raise APCCMigrationError("migration receipt target schema version must be 4")
    if parsed.target_schema_fingerprint != _SCHEMA_FINGERPRINT:
        raise APCCMigrationError("migration receipt target schema fingerprint mismatch")
    src_seq = _parse_canonical_nonneg_decimal(
        parsed.source_change_sequence, "source_change_sequence"
    )
    tgt_seq = _parse_canonical_nonneg_decimal(
        parsed.target_change_sequence, "target_change_sequence"
    )
    _parse_canonical_nonneg_decimal(parsed.certificate_count, "certificate_count")
    _parse_canonical_nonneg_decimal(parsed.migrated_at_ms, "migrated_at_ms")
    if parsed.target_prior_digest != parsed.source_checkpoint_digest:
        raise APCCMigrationError("migration receipt checkpoint chain prior_digest mismatch")
    if tgt_seq != src_seq + 1:
        raise APCCMigrationError("migration receipt change sequence increment mismatch")
    if parsed.signature.key_id != config.commit_trust.key_id:
        raise APCCMigrationError("migration receipt commit key id mismatch")

    try:
        raw_sig = b64u_decode(parsed.signature.signature_b64u, expected_length=64)
        Ed25519PublicKey.from_public_bytes(config.commit_trust.public_key).verify(
            raw_sig, _MIGRATION_RECEIPT_DOMAIN + b"\x00" + parsed.canonical_body_bytes()
        )
    except (InvalidSignature, ValueError) as error:
        raise APCCMigrationError(
            "migration continuity receipt Ed25519 signature invalid"
        ) from error

    if source_path is not None:
        _check_receipt_bound_file(Path(source_path), "source", parsed.source_sha256)

    if target_path is not None:
        target_file = Path(target_path)
        _check_receipt_bound_file(target_file, "target", parsed.target_sha256)
        with tempfile.TemporaryDirectory(prefix="apcc-verify-target-") as td:
            verify_copy = Path(td) / "target-verify.sqlite"
            shutil.copy2(target_file, verify_copy)
            try:
                conn = _connect_reader(verify_copy)
            except (ValueError, sqlite3.DatabaseError) as error:
                raise APCCMigrationError(
                    "failed to open target store during receipt verification"
                ) from error
            try:
                conn.execute("BEGIN")
                cfg_text = _validate_schema(conn)
                if cfg_text != _json(_config_object(config)):
                    raise APCCMigrationError(
                        "target store configuration does not match pinned config"
                    )
                seq, prior_dig, ck_dig, _kid, _sig = _semantic_checkpoint_row(conn)
                fp = str(
                    conn.execute(
                        "SELECT value FROM metadata WHERE key='schema_fingerprint'"
                    ).fetchone()[0]
                )
                certs_digest, cert_count = _certificate_set_digest(conn)
                actual_counts = _table_counts(conn)
                conn.rollback()
            except APCCMigrationError:
                raise
            except (ValueError, sqlite3.DatabaseError) as error:
                raise APCCMigrationError(
                    "target store schema or semantic validation failed"
                ) from error
            finally:
                conn.close()
        if (
            fp != parsed.target_schema_fingerprint
            or str(seq) != parsed.target_change_sequence
            or prior_dig != parsed.target_prior_digest
            or ck_dig != parsed.target_checkpoint_digest
            or certs_digest != parsed.migrated_certificate_digests_sha256
            or str(cert_count) != parsed.certificate_count
            or actual_counts != dict(parsed.migrated_counts)
        ):
            raise APCCMigrationError("migration receipt target DB bindings mismatch")

    return parsed


def migrate_sqlite_v3_to_v4(
    source_path: Path,
    target_path: Path,
    *,
    config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
    receipt_path: Path | None = None,
) -> MigrationResult:
    """Migrate an authentic post-C32 v3 SQLite store into a fresh v4 DB."""
    source = Path(source_path)
    target = Path(target_path)
    receipt_file = Path(receipt_path) if receipt_path is not None else None
    if not source.is_file():
        raise APCCMigrationError(f"source database file does not exist: {source}")
    if target.exists():
        raise APCCMigrationError(f"target database path already exists: {target}")
    if receipt_file is not None and receipt_file.exists():
        raise APCCMigrationError(f"receipt path already exists: {receipt_file}")
    if target.resolve() == source.resolve():
        raise APCCMigrationError("in-place migration over source path is forbidden")

    try:
        validate_runtime_signers(config, runtime)
    except ValueError as error:
        raise APCCMigrationError(str(error)) from error

    if _has_live_wal(source):
        raise APCCMigrationError(
            "cannot migrate source store with uncheckpointed WAL sidecar",
            classification=StoreClassification.V3_TAMPERED_OR_CORRUPT,
            diagnostics=(_LIVE_WAL_DIAGNOSTIC,),
        )

    source_sha256_before = _sha256_file_hex(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(12)}.apcc-v4-tmp")
    target_published = False

    try:
        with tempfile.TemporaryDirectory(prefix="apcc-migrate-src-") as src_td:
            src_copy = Path(src_td) / "source-copy.sqlite"
            shutil.copy2(source, src_copy)
            staged_sha256 = _sha256_file_hex(src_copy)
            if staged_sha256 != source_sha256_before:
                raise APCCMigrationError(
                    "source store changed while staging offline migration copy"
                )
            inspection = _inspect_temp_copy(
                src_copy, source_path=source, source_sha256=staged_sha256
            )
            if inspection.classification is not StoreClassification.V3_POST_C32_MIGRATABLE:
                raise APCCMigrationError(
                    f"cannot migrate store with classification {inspection.classification.value}",
                    classification=inspection.classification,
                    diagnostics=inspection.diagnostics,
                )
            assert inspection.source_change_sequence is not None
            assert inspection.source_checkpoint_digest is not None
            if inspection.source_change_sequence >= _MAX_SAFE_INTEGER:
                raise APCCMigrationError(
                    "source semantic checkpoint change_sequence would overflow safe integer"
                )

            src_conn = _connect_reader(src_copy)
            try:
                src_cfg = src_conn.execute(
                    "SELECT value FROM metadata WHERE key='config'"
                ).fetchone()
                expected_cfg_text = _json(_config_object(config))
                if src_cfg is None or str(src_cfg[0]) != expected_cfg_text:
                    raise APCCMigrationError(
                        "supplied APCCAuthorityConfig does not match source store config"
                    )
                certs_digest, cert_count = _certificate_set_digest(src_conn)

                dst_conn = _connect_create(temporary)
                try:
                    dst_conn.execute("BEGIN IMMEDIATE")
                    _schema(dst_conn)
                    dst_conn.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                    dst_conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                    _copy_all_apcc_tables(src_conn, dst_conn)
                    if dst_conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise APCCMigrationError(
                            "foreign key check failed after copying APCC rows"
                        )
                    dst_conn.executemany(
                        "INSERT INTO metadata(key, value) VALUES (?, ?)",
                        (
                            ("config", expected_cfg_text),
                            ("schema_fingerprint", _SCHEMA_FINGERPRINT),
                            ("schema_version", _AUTHORITY_SCHEMA_VERSION),
                        ),
                    )
                    target_seq = inspection.source_change_sequence + 1
                    dst_conn.execute(
                        "INSERT INTO semantic_checkpoint(singleton,change_sequence,"
                        "prior_digest,checkpoint_digest,key_id,signature) "
                        "VALUES (1,?,?,'',?,'')",
                        (
                            target_seq,
                            inspection.source_checkpoint_digest,
                            config.commit_trust.key_id,
                        ),
                    )
                    for stmt in _SEMANTIC_CHECKPOINT_TRIGGERS:
                        dst_conn.execute(stmt)

                    cfg_text = _validate_schema_manifest(dst_conn, storage_checks=False)
                    if cfg_text != expected_cfg_text:
                        raise APCCMigrationError("migrated target config mismatch")
                    _validate_semantic_integrity(dst_conn, config)
                    _seal_semantic_checkpoint(
                        dst_conn, config, runtime, _SCHEMA_FINGERPRINT
                    )
                    _verify_semantic_checkpoint(dst_conn, config, _SCHEMA_FINGERPRINT)
                    dst_conn.commit()
                    _validate_schema(dst_conn)
                    ck = dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if ck != (0, 0, 0):
                        raise APCCMigrationError("target WAL checkpoint incomplete")
                    (
                        final_seq,
                        final_prior,
                        final_ck_digest,
                        _kid,
                        _sig,
                    ) = _semantic_checkpoint_row(dst_conn)
                except Exception:
                    dst_conn.rollback()
                    raise
                finally:
                    dst_conn.close()
            finally:
                src_conn.close()

        if Path(f"{temporary}-wal").exists() or Path(f"{temporary}-shm").exists():
            raise APCCMigrationError("migrated staging DB retained WAL/SHM sidecars")

        target_sha256 = _sha256_file_hex(temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.link(temporary, target)
        target_published = True
        _fsync_directory(target.parent)

        # Verify the exact published bytes pass SQLiteAuthorityReader.open and
        # SQLiteAuthorityStore.open on a staging copy (keeping published sidecar-free).
        with tempfile.TemporaryDirectory(prefix="apcc-verify-pub-") as pub_td:
            pub_copy = Path(pub_td) / "published-copy.sqlite"
            shutil.copy2(target, pub_copy)
            reader = SQLiteAuthorityReader.open(pub_copy)
            if reader.authority_store_id != config.authority_store_id:
                raise APCCMigrationError("verified target store id mismatch")
            store = SQLiteAuthorityStore.open(pub_copy, config=config, runtime=runtime)
            assert store.authority_store_id == config.authority_store_id

        if _sha256_file_hex(target) != target_sha256:
            raise APCCMigrationError("published target bytes changed unexpectedly")
        if _sha256_file_hex(source) != inspection.source_sha256:
            raise APCCMigrationError("source store bytes changed unexpectedly")

        placeholder_sig = Signature("Ed25519", config.commit_trust.key_id, "A" * 86)
        unsigned_receipt = MigrationContinuityReceipt(
            protocol_version=_RECEIPT_PROTOCOL_VERSION,
            receipt_type=_RECEIPT_TYPE,
            authority_store_id=config.authority_store_id,
            source_sha256=inspection.source_sha256,
            source_schema_version=_V3_SCHEMA_VERSION,
            source_schema_fingerprint=_V3_SCHEMA_FINGERPRINT,
            source_change_sequence=str(inspection.source_change_sequence),
            source_checkpoint_digest=inspection.source_checkpoint_digest,
            target_sha256=target_sha256,
            target_schema_version=_AUTHORITY_SCHEMA_VERSION,
            target_schema_fingerprint=_SCHEMA_FINGERPRINT,
            target_change_sequence=str(final_seq),
            target_prior_digest=final_prior,
            target_checkpoint_digest=final_ck_digest,
            migrated_certificate_digests_sha256=certs_digest,
            certificate_count=str(cert_count),
            migrated_counts=dict(inspection.table_counts),
            migrated_at_ms=str(int(runtime.clock.now_ms())),
            signature=placeholder_sig,
        )
        signed_receipt = _sign_migration_receipt(unsigned_receipt, runtime)
        verify_migration_receipt(
            signed_receipt, config=config, target_path=target, source_path=source
        )
        if receipt_file is not None:
            _atomic_write_new_file(
                receipt_file,
                (_json(signed_receipt.to_object()) + "\n").encode("utf-8"),
            )

        return MigrationResult(
            inspection=inspection,
            target_path=target,
            receipt_path=receipt_file,
            receipt=signed_receipt,
        )
    except Exception:
        if target_published:
            target.unlink(missing_ok=True)
        raise
    finally:
        for leftover in (
            temporary,
            Path(f"{temporary}-wal"),
            Path(f"{temporary}-shm"),
        ):
            leftover.unlink(missing_ok=True)


class _CliKeyProvider:
    def __init__(
        self,
        commit_key: Ed25519PrivateKey,
        status_key: Ed25519PrivateKey,
    ) -> None:
        self._keys = {
            AuthoritySigningRole.COMMIT: commit_key,
            AuthoritySigningRole.STATUS: status_key,
        }

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        del key_id
        return self._keys[role].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        raw_sig = self._keys[role].sign(domain + b"\x00" + canonical_body)
        return Signature("Ed25519", key_id, b64u_encode(raw_sig))


class _CliClock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class _CliDiscardSink:
    def deliver(self, event_id: str, payload: bytes) -> None:
        del event_id, payload


def _decode_b64u_key(raw_value: object, label: str) -> Ed25519PrivateKey:
    if not isinstance(raw_value, str) or not raw_value:
        raise APCCMigrationError(f"key bundle missing string {label} private key")
    try:
        decoded = base64.urlsafe_b64decode(raw_value + "=" * (-len(raw_value) % 4))
        return Ed25519PrivateKey.from_private_bytes(decoded)
    except Exception as error:
        raise APCCMigrationError(f"invalid {label} Ed25519 private key in bundle") from error


def _load_cli_runtime_and_config(
    source_path: Path, key_bundle_path: Path
) -> tuple[APCCAuthorityConfig, AuthorityRuntime]:
    if not key_bundle_path.is_file():
        raise APCCMigrationError(f"key bundle file does not exist: {key_bundle_path}")
    try:
        bundle = strict_loads(
            key_bundle_path.read_bytes(), max_bytes=1_048_576, allow_float=False
        )
    except (OSError, StrictJSONError, TypeError) as error:
        raise APCCMigrationError("failed to parse strict key bundle JSON") from error
    if not isinstance(bundle, Mapping):
        raise APCCMigrationError("key bundle JSON must be an object")

    commit_key = _decode_b64u_key(bundle.get("commit"), "commit")
    status_key = _decode_b64u_key(bundle.get("status"), "status")
    config = _read_config_from_source(source_path)
    runtime = AuthorityRuntime(
        _CliKeyProvider(commit_key, status_key),
        _CliClock(),
        _CliDiscardSink(),
    )
    return config, runtime


def _read_config_from_source(source_path: Path) -> APCCAuthorityConfig:
    if not source_path.is_file():
        raise APCCMigrationError(f"database file does not exist: {source_path}")
    with tempfile.TemporaryDirectory(prefix="apcc-cfg-read-") as td:
        copy_path = Path(td) / "copy.sqlite"
        shutil.copy2(source_path, copy_path)
        conn = sqlite3.connect(str(copy_path))
        try:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key='config'"
            ).fetchone()
            if row is None:
                raise APCCMigrationError("database metadata missing config entry")
            return _config_from_object(_loads(str(row[0])))
        except APCCMigrationError:
            raise
        except Exception as error:
            raise APCCMigrationError(
                "failed to decode APCCAuthorityConfig from database"
            ) from error
        finally:
            conn.close()


def _exit_code_for_classification(classification: StoreClassification) -> int:
    if classification in {
        StoreClassification.V4_CURRENT,
        StoreClassification.V3_POST_C32_MIGRATABLE,
    }:
        return 0
    if classification in {
        StoreClassification.V3_PRE_C32_INCOMPATIBLE,
        StoreClassification.V3_GCB_UNSUPPORTED,
        StoreClassification.UNSUPPORTED_SCHEMA,
    }:
        return 2
    return 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m constitutional_swarm.apcc.migration_v3_to_v4",
        description="Offline read-only-source v3 -> v4 APCC SQLite authority migration",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect", help="Inspect an APCC SQLite store offline")
    inspect_p.add_argument("source", type=Path, help="Path to SQLite store")
    inspect_p.add_argument("--json", action="store_true", help="Emit JSON output")

    migrate_p = sub.add_parser(
        "migrate", help="Migrate an authentic post-C32 v3 store to a fresh v4 store"
    )
    migrate_p.add_argument("source", type=Path, help="Read-only v3 SQLite path")
    migrate_p.add_argument("target", type=Path, help="Fresh non-existent v4 output path")
    migrate_p.add_argument(
        "--key-bundle",
        type=Path,
        required=True,
        help="JSON key bundle containing 'commit' and 'status' Ed25519 private seeds",
    )
    migrate_p.add_argument(
        "--receipt",
        type=Path,
        default=None,
        help="Optional output path for the signed MigrationContinuityReceipt JSON",
    )
    migrate_p.add_argument("--json", action="store_true", help="Emit JSON output")

    verify_p = sub.add_parser(
        "verify-receipt", help="Verify a signed MigrationContinuityReceipt"
    )
    verify_p.add_argument("receipt", type=Path, help="Receipt JSON file")
    verify_p.add_argument("target", type=Path, help="Migrated v4 SQLite store")
    verify_p.add_argument(
        "--commit-public-key",
        required=True,
        help="Pinned Ed25519 commit public key (canonical unpadded base64url, 32 bytes)",
    )
    verify_p.add_argument(
        "--source", type=Path, default=None, help="Optional v3 source SQLite store"
    )
    verify_p.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for offline APCC SQLite inspection, migration, and verification."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "inspect":
            report = inspect_sqlite_store(args.source)
            payload: Mapping[str, object] = report.to_dict()
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(
                    f"{report.source_path}: {report.classification.value} "
                    f"({'; '.join(report.diagnostics)})"
                )
            return _exit_code_for_classification(report.classification)

        if args.command == "migrate":
            config, runtime = _load_cli_runtime_and_config(args.source, args.key_bundle)
            result = migrate_sqlite_v3_to_v4(
                args.source,
                args.target,
                config=config,
                runtime=runtime,
                receipt_path=args.receipt,
            )
            out_obj = {
                "status": "migrated",
                "target_path": str(result.target_path),
                "receipt_path": str(result.receipt_path)
                if result.receipt_path is not None
                else None,
                "receipt": result.receipt.to_object(),
            }
            if args.json:
                print(json.dumps(out_obj, indent=2, sort_keys=True))
            else:
                print(
                    f"Migrated {args.source} -> {result.target_path} "
                    f"(target_sha256={result.receipt.target_sha256})"
                )
            return 0

        if args.command == "verify-receipt":
            try:
                pinned_commit_pk = b64u_decode(
                    args.commit_public_key, expected_length=32
                )
            except ValueError as error:
                raise APCCMigrationError(
                    "invalid pinned commit public key base64url"
                ) from error
            config = _read_config_from_source(args.target)
            if config.commit_trust.public_key != pinned_commit_pk:
                raise APCCMigrationError(
                    "target store commit public key does not match pinned key"
                )
            if args.source is not None:
                source_config = _read_config_from_source(args.source)
                if source_config != config:
                    raise APCCMigrationError(
                        "source and target APCC authority configurations differ"
                    )
            receipt_file = Path(args.receipt)
            if not receipt_file.is_file():
                raise APCCMigrationError(f"receipt file does not exist: {receipt_file}")
            raw_receipt = receipt_file.read_bytes()
            verified = verify_migration_receipt(
                raw_receipt,
                config=config,
                target_path=args.target,
                source_path=args.source,
            )
            if args.json:
                print(
                    json.dumps(
                        {
                            "verified": True,
                            "authority_store_id": verified.authority_store_id,
                            "source_sha256": verified.source_sha256,
                            "target_sha256": verified.target_sha256,
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(
                    f"Verified continuity receipt for store {verified.authority_store_id}"
                )
            return 0
    except APCCMigrationError as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "error": error.reason,
                        "classification": error.classification.value
                        if error.classification
                        else None,
                        "diagnostics": list(error.diagnostics),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(f"ERROR: {error.reason}", file=sys.stderr)
        if error.classification is not None:
            code = _exit_code_for_classification(error.classification)
            if args.command != "inspect" and code == 0:
                return 2
            return code
        return 3
    return 3


__all__ = [
    "APCCMigrationError",
    "MigrationContinuityReceipt",
    "MigrationResult",
    "StoreClassification",
    "StoreInspectionReport",
    "inspect_sqlite_store",
    "main",
    "migrate_sqlite_v3_to_v4",
    "verify_migration_receipt",
]


if __name__ == "__main__":
    raise SystemExit(main())
