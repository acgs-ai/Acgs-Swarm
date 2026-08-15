"""SQLite settlement store persists and migrates receipt_digest."""

from __future__ import annotations

import sqlite3

import pytest
from acgs_lite import Constitution
from constitutional_swarm import (
    ConstitutionalMesh,
    SQLiteSettlementStore,
    SettlementRecord,
    bundle_from_json,
    verify_bundle,
)
from constitutional_swarm.settlement_store import DuplicateSettlementError, normalize_receipt_digest
from cryptography.hazmat.primitives import serialization

_DIGEST = "ab" * 32


def _record(assignment_id: str, *, receipt_digest: str | None = None) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "producer_id": "p", "artifact_id": "a"},
        result={"accepted": True, "assignment_id": assignment_id},
        constitutional_hash="abc123",
        receipt_digest=receipt_digest,
    )


def _legacy_schema(path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE mesh_settlements (
                assignment_id TEXT PRIMARY KEY,
                assignment_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                constitutional_hash TEXT NOT NULL DEFAULT '',
                schema_version INTEGER NOT NULL DEFAULT 1,
                is_recovered INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE pending_settlements (
                assignment_id TEXT PRIMARY KEY,
                assignment_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                constitutional_hash TEXT NOT NULL DEFAULT '',
                schema_version INTEGER NOT NULL DEFAULT 1,
                is_recovered INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            INSERT INTO mesh_settlements (
                assignment_id, assignment_json, result_json, constitutional_hash
            ) VALUES ('old', '{"assignment_id":"old"}', '{"accepted":true}', 'abc123')
            """
        )
        conn.commit()


def test_new_database_has_nullable_receipt_digest(tmp_path) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    assert store.has_receipt_digest_column() is True
    assert store.describe()["receipt_digest"] is True
    assert "receipt_digest" in store.describe()["columns"]
    store.append(_record("n1", receipt_digest=_DIGEST))
    loaded = store.get("n1")
    assert loaded is not None
    assert loaded.receipt_digest == _DIGEST


def test_migrate_old_database_and_repeat(tmp_path) -> None:
    path = tmp_path / "legacy.db"
    _legacy_schema(path)
    store = SQLiteSettlementStore(path)
    assert store.has_receipt_digest_column() is True
    old = store.get("old")
    assert old is not None
    assert old.receipt_digest is None
    store2 = SQLiteSettlementStore(path)
    assert store2.get("old") is not None
    assert store2.get("old").receipt_digest is None


def test_new_row_after_migration_preserves_digest(tmp_path) -> None:
    path = tmp_path / "legacy.db"
    _legacy_schema(path)
    store = SQLiteSettlementStore(path)
    store.append(_record("n2", receipt_digest=_DIGEST))
    assert store.get("old").receipt_digest is None
    assert store.get("n2").receipt_digest == _DIGEST


def test_duplicate_after_migration(tmp_path) -> None:
    path = tmp_path / "legacy.db"
    _legacy_schema(path)
    store = SQLiteSettlementStore(path)
    with pytest.raises(DuplicateSettlementError):
        store.append(_record("old", receipt_digest=_DIGEST))


def test_malformed_and_overlong_digest_rejected(tmp_path) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    with pytest.raises(ValueError, match="receipt_digest"):
        store.append(_record("bad", receipt_digest="not-a-digest"))
    with pytest.raises(ValueError, match="receipt_digest"):
        store.append(_record("long", receipt_digest=_DIGEST + "aa"))
    with pytest.raises(ValueError, match="receipt_digest"):
        normalize_receipt_digest("AB" * 32)
    store.append(_record("empty", receipt_digest=None))
    assert store.get("empty").receipt_digest is None


def test_supplied_digest_is_not_silently_dropped(tmp_path) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    store.append(_record("keep", receipt_digest=_DIGEST))
    pending = _record("pend", receipt_digest=_DIGEST)
    store.mark_pending(pending)
    loaded_pending = store.load_pending()
    assert loaded_pending[0].receipt_digest == _DIGEST


def test_sqlite_settlement_receipt_verifies(tmp_path) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    mesh = ConstitutionalMesh(Constitution.default(), seed=42, settlement_store=store)
    for index in range(4):
        mesh.register_local_signer(f"agent-{index:02d}")
    assignment = mesh.request_validation("agent-00", "summarize notes", "art")
    for voter in assignment.peers[:2]:
        mesh.validate_and_vote(assignment.assignment_id, voter)
    loaded = store.get(assignment.assignment_id)
    assert loaded is not None
    assert loaded.receipt_digest
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    bundle = bundle_from_json(receipt_path.read_text(encoding="utf-8"))
    trusted = {
        "settlement-receipt": mesh._request_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    }
    assert bundle.receipts[0].payload_digest == loaded.receipt_digest
    assert verify_bundle(bundle, trusted_signers=trusted).valid
