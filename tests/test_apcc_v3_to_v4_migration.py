"""Offline APCC v3 -> v4 SQLite migration, inspection, and continuity-receipt tests."""

from __future__ import annotations

import gc
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from constitutional_swarm.apcc import sqlite_store as sqlite_store_module
from constitutional_swarm.apcc.crypto import b64u_encode
from constitutional_swarm.apcc.migration_v3_to_v4 import (
    APCCMigrationError,
    StoreClassification,
    _pre_c32_audit_id,
    inspect_sqlite_store,
    migrate_sqlite_v3_to_v4,
    verify_migration_receipt,
)
from constitutional_swarm.apcc.model import AuthorityStatusValue, RequestOutcome, SupersessionValue
from constitutional_swarm.apcc.ports import (
    OutboxRecoveryRequest,
    RevocationRequest,
    RevocationScope,
    SupersessionCommitted,
    SupersessionRequest,
)
from constitutional_swarm.apcc.sqlite_store import (
    SQLiteAuthorityReader,
    SQLiteAuthorityStore,
)
from constitutional_swarm.apcc.verifier import CausalClosureLimits, verify_causal_closure, verify_current
from tests.test_apcc_schema_v4_compat import (
    FIXTURE_PRE_C32_V3,
    _isolated_runtime,
    _rewrite_sqlite_to_authentic_post_c32_v3,
)
from tests.test_apcc_sqlite import (
    _advance_candidate,
    _config,
    _open_store,
    _predecessor,
    _request,
    _runtime,
)
from tests.test_apcc_verifier import SEEDS


def _b64u_nonce(byte: int) -> str:
    return b64u_encode(bytes([byte]) * 16)


def _sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dir_snapshot(directory: Path) -> dict[str, bytes]:
    return {
        p.name: p.read_bytes()
        for p in sorted(directory.iterdir())
        if p.is_file()
    }


def _cleanup_helper_sidecars(db_path: Path) -> None:
    # _rewrite_sqlite_to_authentic_post_c32_v3 leaves an unclosed sqlite3.Connection
    # until GC; collect before unlinking empty sidecars so snapshots are deterministic.
    gc.collect()
    with closing(sqlite3.connect(db_path)) as conn:
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    gc.collect()
    for sidecar in (Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        sidecar.unlink(missing_ok=True)


def _copy_pre_c32_fixture(tmp_path: Path, name: str = "pre-c32.sqlite") -> Path:
    dst = tmp_path / name
    shutil.copyfile(FIXTURE_PRE_C32_V3, dst)
    return dst


def _write_key_bundle(path: Path) -> Path:
    bundle = {
        "commit": b64u_encode(SEEDS["commit"]),
        "status": b64u_encode(SEEDS["status"]),
    }
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _populate_rich_post_c32_v3(v3_path: Path) -> dict[str, object]:
    """Create a populated post-C32 store (causal chain, supersession, revocation, outbox), then downgrade to v3."""
    store = _open_store(v3_path, None)

    # Node 1: parent commit + DELIVERED outbox event.
    req_parent = _request(commit_id="v3-parent", nonce_byte=31, node_id="node-1")
    _advance_candidate(store, req_parent)
    res_parent = store.atomic_commit(req_parent)
    assert res_parent.decision.outcome is RequestOutcome.COMMITTED
    assert res_parent.certificate_digest is not None
    rec = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert rec.delivered_count == "1"

    # Node 2 ("root"): committed then superseded.
    req_root = _request(commit_id="v3-root-1", nonce_byte=32, node_id="root")
    _advance_candidate(store, req_root)
    res_root = store.atomic_commit(req_root)
    assert res_root.certificate_digest is not None
    req_root_sup = _request(
        commit_id="v3-root-2",
        nonce_byte=33,
        node_id="root",
        expected_node_version="1",
        attempt_id="attempt-2",
    )
    _advance_candidate(store, req_root_sup)
    sup = store.supersede(SupersessionRequest(res_root.certificate_digest, req_root_sup))
    assert isinstance(sup, SupersessionCommitted)

    # Node 3 ("child"): causal child of parent, then child revoked (stays PENDING in outbox with rev).
    req_child = _request(
        commit_id="v3-child",
        nonce_byte=34,
        node_id="child",
        predecessors=[_predecessor(req_parent, res_parent)],
    )
    _advance_candidate(store, req_child)
    res_child = store.atomic_commit(req_child)
    assert res_child.decision.outcome is RequestOutcome.COMMITTED
    assert res_child.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            scope=RevocationScope.CERTIFICATE,
            workflow_id="workflow-1",
            target_id=res_child.certificate_digest,
            next_generation="1",
            reason="v3-child-revoked-before-migration",
        )
    )

    with closing(sqlite3.connect(v3_path)) as conn:
        src_ck = conn.execute(
            "SELECT change_sequence, checkpoint_digest FROM semantic_checkpoint WHERE singleton=1"
        ).fetchone()
        assert src_ck is not None

    _rewrite_sqlite_to_authentic_post_c32_v3(v3_path)
    with closing(sqlite3.connect(v3_path)) as conn:
        downgraded_ck = conn.execute(
            "SELECT change_sequence, checkpoint_digest FROM semantic_checkpoint WHERE singleton=1"
        ).fetchone()
        assert downgraded_ck is not None
    _cleanup_helper_sidecars(v3_path)

    return {
        "parent_commit_id": "v3-parent",
        "parent_digest": res_parent.certificate_digest,
        "parent_envelope": res_parent.certificate_envelope_bytes,
        "root_old_digest": res_root.certificate_digest,
        "root_new_commit_id": "v3-root-2",
        "root_new_digest": sup.new_certificate_digest,
        "root_new_envelope": sup.commit_result.certificate_envelope_bytes,
        "child_commit_id": "v3-child",
        "child_digest": res_child.certificate_digest,
        "child_envelope": res_child.certificate_envelope_bytes,
        "v3_change_sequence": int(downgraded_ck[0]),
        "v3_checkpoint_digest": str(downgraded_ck[1]),
    }


def test_pre_c32_fixture_inspected_read_only_and_classified_incompatible(
    tmp_path: Path,
) -> None:
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    src = _copy_pre_c32_fixture(src_dir, "apcc_pre_c32_v3.sqlite")
    before_files = _dir_snapshot(src_dir)
    before_sha = _sha256_hex(src)

    report = inspect_sqlite_store(src)
    assert report.classification is StoreClassification.V3_PRE_C32_INCOMPATIBLE
    assert report.user_version == 3
    assert report.metadata_schema_version == "3"
    assert report.authority_store_id == "store-1"
    assert report.source_sha256 == before_sha
    assert any("pre_c32_legacy_audit_ids" in d for d in report.diagnostics)
    assert report.table_counts["certificates"] == 1
    assert report.table_counts["candidates"] == 72

    # Source file and directory remain completely untouched (zero WAL/SHM sidecars).
    assert _dir_snapshot(src_dir) == before_files


def test_pre_c32_fixture_migration_fails_closed_without_sidecars_or_targets(
    tmp_path: Path,
) -> None:
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    src = _copy_pre_c32_fixture(src_dir, "apcc_pre_c32_v3.sqlite")
    target = tmp_path / "out" / "migrated.sqlite"
    receipt = tmp_path / "out" / "continuity.json"
    before_files = _dir_snapshot(src_dir)

    with pytest.raises(APCCMigrationError) as caught:
        migrate_sqlite_v3_to_v4(
            src,
            target,
            config=_config(),
            runtime=_runtime(),
            receipt_path=receipt,
        )
    assert caught.value.classification is StoreClassification.V3_PRE_C32_INCOMPATIBLE
    assert not target.exists()
    assert not receipt.exists()
    assert _dir_snapshot(src_dir) == before_files


@pytest.mark.parametrize("populate", [False, True])
def test_post_c32_v3_empty_and_rich_migrate_cleanly_to_v4(
    tmp_path: Path, populate: bool
) -> None:
    src_dir = tmp_path / "source"
    out_dir = tmp_path / "target"
    src_dir.mkdir()
    v3_path = src_dir / "post-c32-v3.sqlite"

    if populate:
        facts = _populate_rich_post_c32_v3(v3_path)
    else:
        _open_store(v3_path, None)
        _rewrite_sqlite_to_authentic_post_c32_v3(v3_path)
        with closing(sqlite3.connect(v3_path)) as conn:
            ck = conn.execute(
                "SELECT change_sequence, checkpoint_digest FROM semantic_checkpoint WHERE singleton=1"
            ).fetchone()
            assert ck is not None
        _cleanup_helper_sidecars(v3_path)
        facts = {"v3_change_sequence": int(ck[0]), "v3_checkpoint_digest": str(ck[1])}

    # v4 runtime store must still reject source directly.
    with pytest.raises(ValueError, match="APCC authority schema version is incompatible"):
        SQLiteAuthorityStore.open(v3_path, _config(), _runtime())
    _cleanup_helper_sidecars(v3_path)

    before_files = _dir_snapshot(src_dir)
    before_sha = _sha256_hex(v3_path)
    target_path = out_dir / "store-v4.sqlite"
    receipt_path = out_dir / "continuity-receipt.json"

    report = inspect_sqlite_store(v3_path)
    assert report.classification is StoreClassification.V3_POST_C32_MIGRATABLE
    assert _dir_snapshot(src_dir) == before_files

    runtime, sink = _isolated_runtime()
    result = migrate_sqlite_v3_to_v4(
        v3_path,
        target_path,
        config=_config(),
        runtime=runtime,
        receipt_path=receipt_path,
    )

    # Source completely unchanged; target clean and sidecar-free until opened by callers.
    assert _dir_snapshot(src_dir) == before_files
    assert result.receipt.source_sha256 == before_sha
    assert result.receipt.target_sha256 == _sha256_hex(target_path)
    assert result.receipt.source_schema_version == "3"
    assert result.receipt.target_schema_version == "4"
    assert result.receipt.source_change_sequence == str(facts["v3_change_sequence"])
    assert result.receipt.target_change_sequence == str(int(facts["v3_change_sequence"]) + 1)
    assert result.receipt.target_prior_digest == facts["v3_checkpoint_digest"]
    assert not Path(f"{target_path}-wal").exists()
    assert not Path(f"{target_path}-shm").exists()

    # Continuity receipt verifies independently on disk.
    verify_migration_receipt(
        receipt_path.read_bytes(),
        config=_config(),
        target_path=target_path,
        source_path=v3_path,
    )

    # Target opens cleanly as v4 reader and v4 writer.
    reader = SQLiteAuthorityReader.open(target_path)
    assert reader.authority_store_id == "store-1"
    store = SQLiteAuthorityStore.open(target_path, _config(), runtime)

    if populate:
        parent_dig = str(facts["parent_digest"])
        root_old_dig = str(facts["root_old_digest"])
        root_new_dig = str(facts["root_new_digest"])
        child_dig = str(facts["child_digest"])

        st_parent = store.current_status(parent_dig, _b64u_nonce(41))
        st_old = store.current_status(root_old_dig, _b64u_nonce(42))
        st_new = store.current_status(root_new_dig, _b64u_nonce(43))
        st_child = store.current_status(child_dig, _b64u_nonce(44))

        assert st_parent.status is AuthorityStatusValue.CURRENT
        assert st_old.status is AuthorityStatusValue.CURRENT
        assert st_old.superseded is SupersessionValue.YES
        assert st_new.status is AuthorityStatusValue.CURRENT
        assert st_new.superseded is SupersessionValue.NO
        assert st_child.status is AuthorityStatusValue.REVOKED

        # Pending v3 outbox items drain cleanly post-migration.
        drained = store.recover_outbox(OutboxRecoveryRequest("10"))
        assert drained.pending_count == "0"
        assert int(drained.delivered_count) >= 4
        assert len(sink.delivered) >= 4

    # Perform a brand-new commit on the migrated v4 store!
    req_new = _request(commit_id="v4-post-mig-1", nonce_byte=55, node_id="leaf")
    _advance_candidate(store, req_new)
    res_new = store.atomic_commit(req_new)
    assert res_new.decision.outcome is RequestOutcome.COMMITTED
    assert res_new.certificate_envelope_bytes is not None

    closure = verify_causal_closure(
        res_new.certificate_envelope_bytes,
        trust=store._scoped_trust,
        resolver=lambda _d: None,  # type: ignore[arg-type]
        limits=CausalClosureLimits(),
    )
    assert closure.ok
    st_leaf = store.current_status(str(res_new.certificate_digest), _b64u_nonce(56))
    verdict = verify_current(
        res_new.certificate_envelope_bytes,
        trust=store._scoped_trust,
        authority_status=st_leaf,
        request_nonce=st_leaf.request_nonce,
        now_ms=st_leaf.this_update_ms,
        highest_trust_log_sequence="0",
        highest_trust_log_head=st_leaf.trust_log_head,
        maximum_staleness_ms=_config().freshness.maximum_staleness_ms,
    )
    assert verdict.ok


def test_negative_tamper_mismatch_wal_gcb_and_existing_target_refusals(
    tmp_path: Path,
) -> None:
    cfg = _config()
    runtime = _runtime()

    # 1. Tampered v3 checkpoint signature -> V3_TAMPERED_OR_CORRUPT
    tampered_ck = tmp_path / "tampered-ck.sqlite"
    _open_store(tampered_ck, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(tampered_ck)
    with closing(sqlite3.connect(tampered_ck)) as conn:
        conn.execute(
            "UPDATE semantic_checkpoint SET signature=? WHERE singleton=1",
            (b64u_encode(bytes(64)),),
        )
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert (
        inspect_sqlite_store(tampered_ck).classification
        is StoreClassification.V3_TAMPERED_OR_CORRUPT
    )

    # 2. Tampered certificate payload in v3 with re-sealed checkpoint -> caught by semantic integrity!
    tampered_cert = tmp_path / "tampered-cert.sqlite"
    store = _open_store(tampered_cert, None)
    req = _request(commit_id="tamper-1", nonce_byte=61)
    _advance_candidate(store, req)
    assert store.atomic_commit(req).decision.outcome is RequestOutcome.COMMITTED
    with closing(sqlite3.connect(tampered_cert)) as conn:
        conn.execute("UPDATE certificates SET certificate_json=X'7b7d'")
        conn.commit()
    v3_fp = _rewrite_sqlite_to_authentic_post_c32_v3(tampered_cert)
    assert v3_fp
    assert (
        inspect_sqlite_store(tampered_cert).classification
        is StoreClassification.V3_TAMPERED_OR_CORRUPT
    )

    # 3. user_version=4 vs metadata.schema_version='3' mismatch -> V3_TAMPERED_OR_CORRUPT
    uv_mismatch = tmp_path / "uv-mismatch.sqlite"
    _open_store(uv_mismatch, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(uv_mismatch)
    with closing(sqlite3.connect(uv_mismatch)) as conn:
        conn.execute("PRAGMA user_version=4")
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert (
        inspect_sqlite_store(uv_mismatch).classification
        is StoreClassification.V3_TAMPERED_OR_CORRUPT
    )

    # 4. Non-empty uncheckpointed -wal sidecar -> V3_TAMPERED_OR_CORRUPT (untouched)
    uncheckpointed = tmp_path / "uncheckpointed.sqlite"
    _open_store(uncheckpointed, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(uncheckpointed)
    wal_path = Path(f"{uncheckpointed}-wal")
    wal_path.write_bytes(b"uncheckpointed-wal-bytes")
    rep_wal = inspect_sqlite_store(uncheckpointed)
    assert rep_wal.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT
    assert "uncheckpointed WAL sidecar" in rep_wal.diagnostics[0]
    assert wal_path.read_bytes() == b"uncheckpointed-wal-bytes"

    # 5. GCB-attached v3 tables -> V3_GCB_UNSUPPORTED
    gcb_v3 = tmp_path / "gcb-v3.sqlite"
    _open_store(gcb_v3, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(gcb_v3)
    with closing(sqlite3.connect(gcb_v3)) as conn:
        for tbl in (
            "agents",
            "decisions",
            "nodes",
            "outbox",
            "receipt_evidence",
            "staged_artifacts",
            "store_seal",
            "workflows",
        ):
            conn.execute(f"CREATE TABLE {tbl}(id TEXT PRIMARY KEY)")
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert (
        inspect_sqlite_store(gcb_v3).classification
        is StoreClassification.V3_GCB_UNSUPPORTED
    )

    # 6. Pre-existing target path & mismatched config -> fail closed
    good_v3 = tmp_path / "good-v3.sqlite"
    _open_store(good_v3, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(good_v3)
    existing_target = tmp_path / "existing.sqlite"
    existing_target.write_bytes(b"do-not-overwrite")
    with pytest.raises(APCCMigrationError, match="already exists"):
        migrate_sqlite_v3_to_v4(
            good_v3, existing_target, config=cfg, runtime=runtime
        )
    assert existing_target.read_bytes() == b"do-not-overwrite"

    with pytest.raises(APCCMigrationError, match="does not match source store config"):
        migrate_sqlite_v3_to_v4(
            good_v3,
            tmp_path / "never.sqlite",
            config=_config("other-store"),
            runtime=runtime,
        )
    assert not (tmp_path / "never.sqlite").exists()

    # 7. Valid v4 store classifies as V4_CURRENT and refuses unnecessary re-migration.
    v4_cur = tmp_path / "v4-cur.sqlite"
    _open_store(v4_cur, None)
    with closing(sqlite3.connect(v4_cur)) as conn:
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    for sidecar in (Path(f"{v4_cur}-wal"), Path(f"{v4_cur}-shm")):
        sidecar.unlink(missing_ok=True)
    assert sqlite_store_module._AUTHORITY_SCHEMA_VERSION == "4"
    rep_v4 = inspect_sqlite_store(v4_cur)
    assert rep_v4.classification is StoreClassification.V4_CURRENT


def test_continuity_receipt_tamper_detection(tmp_path: Path) -> None:
    v3_path = tmp_path / "v3.sqlite"
    _populate_rich_post_c32_v3(v3_path)
    target_path = tmp_path / "v4.sqlite"
    receipt_path = tmp_path / "receipt.json"

    res = migrate_sqlite_v3_to_v4(
        v3_path,
        target_path,
        config=_config(),
        runtime=_runtime(),
        receipt_path=receipt_path,
    )
    obj = res.receipt.to_object()

    for field_name, bad_value in (
        ("target_sha256", "0" * 64),
        ("source_sha256", "f" * 64),
        ("source_schema_fingerprint", b64u_encode(b"\x02" * 32)),
        ("source_change_sequence", "01"),
        ("source_change_sequence", "abc"),
        ("certificate_count", "999"),
        ("target_checkpoint_digest", b64u_encode(b"\x01" * 32)),
        ("signature", {"algorithm": "Ed25519", "key_id": "commit-key", "signature_b64u": b64u_encode(bytes(64))}),
    ):
        tampered = json.loads(json.dumps(obj))
        tampered[field_name] = bad_value
        with pytest.raises(APCCMigrationError):
            verify_migration_receipt(
                tampered, config=_config(), target_path=target_path, source_path=v3_path
            )

    # Duplicate JSON keys in serialized receipt must fail closed.
    raw_text = receipt_path.read_text(encoding="utf-8").strip()
    assert raw_text.endswith("}")
    dup_bytes = (
        raw_text[:-1] + f',"target_sha256":"{res.receipt.target_sha256}"}}'
    ).encode("utf-8")
    with pytest.raises(APCCMigrationError, match="strict JSON"):
        verify_migration_receipt(
            dup_bytes, config=_config(), target_path=target_path, source_path=v3_path
        )


def test_non_sqlite_file_classified_cleanly_without_unhandled_error(tmp_path: Path) -> None:
    garbage = tmp_path / "not-a-db.sqlite"
    garbage.write_bytes(b"not-a-sqlite-database" * 16)
    report = inspect_sqlite_store(garbage)
    assert report.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT
    assert any("not a valid SQLite" in d for d in report.diagnostics)


def test_partial_gcb_extra_tables_and_broken_metadata_classified_corrupt(
    tmp_path: Path,
) -> None:
    # Partial GCB table set (missing store_seal) must fail closed, never drop GCB data.
    partial_gcb = tmp_path / "partial-gcb.sqlite"
    _open_store(partial_gcb, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(partial_gcb)
    with closing(sqlite3.connect(partial_gcb)) as conn:
        for tbl in (
            "agents",
            "decisions",
            "nodes",
            "outbox",
            "receipt_evidence",
            "staged_artifacts",
            "workflows",
        ):
            conn.execute(f"CREATE TABLE {tbl}(id TEXT PRIMARY KEY)")
        conn.commit()
    _cleanup_helper_sidecars(partial_gcb)
    rep_partial = inspect_sqlite_store(partial_gcb)
    assert rep_partial.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT
    assert any("partial GCB" in d for d in rep_partial.diagnostics)

    # Extra arbitrary non-APCC table must fail closed as DDL tamper.
    extra_tbl = tmp_path / "extra-tbl.sqlite"
    _open_store(extra_tbl, None)
    _rewrite_sqlite_to_authentic_post_c32_v3(extra_tbl)
    with closing(sqlite3.connect(extra_tbl)) as conn:
        conn.execute("CREATE TABLE rogue_table(id TEXT PRIMARY KEY)")
        conn.commit()
    _cleanup_helper_sidecars(extra_tbl)
    rep_extra = inspect_sqlite_store(extra_tbl)
    assert rep_extra.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT
    assert any("rogue_table" in d for d in rep_extra.diagnostics)

    # Malformed metadata table columns must return V3_TAMPERED_OR_CORRUPT cleanly.
    broken_meta = tmp_path / "broken-meta.sqlite"
    with closing(sqlite3.connect(broken_meta)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA application_id=0x41504343")
        conn.execute("PRAGMA user_version=3")
        conn.execute("CREATE TABLE metadata(broken TEXT)")
        conn.commit()
    _cleanup_helper_sidecars(broken_meta)
    rep_broken = inspect_sqlite_store(broken_meta)
    assert rep_broken.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT
    assert any("metadata table is corrupt" in d for d in rep_broken.diagnostics)

    # Candidate row with tampered context_json + re-sealed checkpoint must be
    # classified as V3_TAMPERED_OR_CORRUPT, never V3_PRE_C32_INCOMPATIBLE.
    tampered_ctx = tmp_path / "tampered-context.sqlite"
    store_ctx = _open_store(tampered_ctx, None)
    req_ctx = _request(commit_id="ctx-1", nonce_byte=62)
    _advance_candidate(store_ctx, req_ctx)
    assert store_ctx.atomic_commit(req_ctx).decision.outcome is RequestOutcome.COMMITTED
    with closing(sqlite3.connect(tampered_ctx)) as conn:
        conn.execute("UPDATE candidates SET context_json='{}'")
        conn.commit()
    _rewrite_sqlite_to_authentic_post_c32_v3(tampered_ctx)
    _cleanup_helper_sidecars(tampered_ctx)
    rep_ctx = inspect_sqlite_store(tampered_ctx)
    assert rep_ctx.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT

    # Mixed pre/post-C32 store (valid pre-C32 candidate audit ID alongside
    # post-C32 outbox ID) must fail both validators -> V3_TAMPERED_OR_CORRUPT.
    mixed_c32 = tmp_path / "mixed-c32.sqlite"
    store_mix = _open_store(mixed_c32, None)
    req_mix = _request(commit_id="mix-1", nonce_byte=63)
    _advance_candidate(store_mix, req_mix)
    assert store_mix.atomic_commit(req_mix).decision.outcome is RequestOutcome.COMMITTED
    with closing(sqlite3.connect(mixed_c32)) as conn:
        legacy_audit = _pre_c32_audit_id(
            "COMMIT_PENDING",
            req_mix.commit_id,
            sqlite_store_module._proposal_identity(req_mix),
        )
        conn.execute("UPDATE candidates SET audit_event_id = ?", (legacy_audit,))
        conn.commit()
    _rewrite_sqlite_to_authentic_post_c32_v3(mixed_c32)
    _cleanup_helper_sidecars(mixed_c32)
    rep_mix = inspect_sqlite_store(mixed_c32)
    assert rep_mix.classification is StoreClassification.V3_TAMPERED_OR_CORRUPT


def test_continuity_receipt_rejects_source_wal_sidecar(tmp_path: Path) -> None:
    v3_path = tmp_path / "v3-wal.sqlite"
    _populate_rich_post_c32_v3(v3_path)
    target_path = tmp_path / "v4-wal.sqlite"
    receipt_path = tmp_path / "receipt-wal.json"
    migrate_sqlite_v3_to_v4(
        v3_path,
        target_path,
        config=_config(),
        runtime=_runtime(),
        receipt_path=receipt_path,
    )
    wal_sidecar = Path(f"{v3_path}-wal")
    wal_sidecar.write_bytes(b"post-migration-source-wal-frames")
    with pytest.raises(APCCMigrationError, match="uncheckpointed WAL sidecar"):
        verify_migration_receipt(
            receipt_path.read_bytes(),
            config=_config(),
            target_path=target_path,
            source_path=v3_path,
        )


def test_cli_inspect_migrate_verify_roundtrip(tmp_path: Path) -> None:
    pre_c32 = _copy_pre_c32_fixture(tmp_path, "pre.sqlite")
    v3_src = tmp_path / "post.sqlite"
    _populate_rich_post_c32_v3(v3_src)
    key_bundle = _write_key_bundle(tmp_path / "keys.json")
    v4_dst = tmp_path / "migrated-cli.sqlite"
    receipt = tmp_path / "receipt-cli.json"

    def _run_cli(*cli_args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        return subprocess.run(
            [sys.executable, "-m", "constitutional_swarm.apcc.migration_v3_to_v4", *cli_args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    # Pre-C32 inspect returns exit code 2 + JSON classification.
    pre_proc = _run_cli("inspect", str(pre_c32), "--json")
    assert pre_proc.returncode == 2
    assert json.loads(pre_proc.stdout)["classification"] == "v3_pre_c32_incompatible"

    # Pre-C32 migrate refuses with exit code 2.
    pre_mig = _run_cli(
        "migrate",
        str(pre_c32),
        str(tmp_path / "should-not-exist.sqlite"),
        "--key-bundle",
        str(key_bundle),
        "--json",
    )
    assert pre_mig.returncode == 2
    assert not (tmp_path / "should-not-exist.sqlite").exists()

    # Post-C32 inspect returns 0.
    post_proc = _run_cli("inspect", str(v3_src), "--json")
    assert post_proc.returncode == 0
    assert json.loads(post_proc.stdout)["classification"] == "v3_post_c32_migratable"

    # Post-C32 migrate + receipt verify return 0.
    mig_proc = _run_cli(
        "migrate",
        str(v3_src),
        str(v4_dst),
        "--key-bundle",
        str(key_bundle),
        "--receipt",
        str(receipt),
        "--json",
    )
    assert mig_proc.returncode == 0, mig_proc.stderr
    assert json.loads(mig_proc.stdout)["status"] == "migrated"

    pinned_pk = b64u_encode(_config().commit_trust.public_key)
    ver_proc = _run_cli(
        "verify-receipt",
        str(receipt),
        str(v4_dst),
        "--commit-public-key",
        pinned_pk,
        "--source",
        str(v3_src),
        "--json",
    )
    assert ver_proc.returncode == 0, ver_proc.stderr
    assert json.loads(ver_proc.stdout)["verified"] is True

    # Pinned key mismatch must fail closed with exit code 3.
    wrong_pk = b64u_encode(b"\x7f" * 32)
    bad_ver = _run_cli(
        "verify-receipt",
        str(receipt),
        str(v4_dst),
        "--commit-public-key",
        wrong_pk,
        "--json",
    )
    assert bad_ver.returncode == 3

    # CLI migrate on an already-v4 store must refuse with nonzero exit code (never 0).
    already_v4 = _run_cli(
        "migrate",
        str(v4_dst),
        str(tmp_path / "should-not-migrate-v4.sqlite"),
        "--key-bundle",
        str(key_bundle),
        "--json",
    )
    assert already_v4.returncode != 0
    assert not (tmp_path / "should-not-migrate-v4.sqlite").exists()
