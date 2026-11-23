"""C32 APCC authority schema v4 compatibility & 9-row acceptance matrix tests.

Exercises both SQLite (always executed, including the authentic pre-C32 v3 fixture from
commit ``8b80673``) and live PostgreSQL 17 (executed when ``APCC_POSTGRES_DSN`` is set).
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from constitutional_swarm.apcc import sqlite_store as sqlite_store_module
from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.model import RequestOutcome
from constitutional_swarm.apcc.ports import (
    AuthorityRuntime,
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
from constitutional_swarm.authority_service import (
    start_authority,
    start_authority_observer,
)
from tests.gcb_apcc_support import authority_child_config
from tests.test_apcc_observation import _observer_launch
from tests.test_apcc_postgres import (
    _advance as _pg_advance,
    _config as _pg_config,
    _initial_contexts as _pg_initial_contexts,
    _open_gcb_profile as _pg_open_gcb,
    _provision_gcb_profile as _pg_provision_gcb,
    _request as _pg_request,
    _runtime as _pg_runtime,
    _single_store as _pg_single_store,
    postgres_environment,  # noqa: F401
)
from tests.test_apcc_sqlite import (
    _advance_candidate,
    _assemble_evidence_request,
    _config,
    _database_file_state,
    _initial_contexts,
    _open_store,
    _propose_commit_request,
    _request,
    _runtime,
    _stage_request,
)

FIXTURE_PRE_C32_V3 = (
    Path(__file__).resolve().parent / "fixtures" / "apcc" / "apcc_pre_c32_v3.sqlite"
)


class _LocalOutboxSink:
    def __init__(self) -> None:
        self.delivered: list[tuple[str, bytes]] = []

    def deliver(self, event_id: str, payload: bytes) -> None:
        self.delivered.append((event_id, payload))


def _isolated_runtime() -> tuple[AuthorityRuntime, _LocalOutboxSink]:
    sink = _LocalOutboxSink()
    runtime = _runtime()
    return replace(runtime, outbox_sink=sink), sink


def _sqlite_v3_fingerprint() -> str:
    return sha256_digest(
        (
            "schema-version=3\n"
            + "\n".join(
                sqlite_store_module._normalize_schema_sql(item)
                for item in sqlite_store_module._SCHEMA_STATEMENTS
            )
        ).encode("utf-8")
    )


def _copy_pre_c32_v3_fixture(tmp_path: Path, name: str = "pre-c32-v3.sqlite") -> Path:
    assert FIXTURE_PRE_C32_V3.is_file()
    target = tmp_path / name
    shutil.copyfile(FIXTURE_PRE_C32_V3, target)
    return target


def _seal_sqlite_checkpoint(connection: sqlite3.Connection, fingerprint: str) -> None:
    sqlite_store_module._seal_semantic_checkpoint(
        connection,
        _config(),
        _runtime(),
        fingerprint,
    )


def _rewrite_sqlite_to_authentic_post_c32_v3(path: Path) -> str:
    """Downgrade a newly provisioned post-C32 SQLite DB to authentic v3 metadata/checkpoint."""
    v3_fp = _sqlite_v3_fingerprint()
    with sqlite3.connect(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("PRAGMA user_version=3")
        connection.execute(
            "UPDATE metadata SET value='3' WHERE key='schema_version'"
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='schema_fingerprint'",
            (v3_fp,),
        )
        _seal_sqlite_checkpoint(connection, v3_fp)
        connection.commit()
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    for sidecar in (Path(f"{path}-wal"), Path(f"{path}-shm")):
        if sidecar.exists():
            sidecar.unlink()
    return v3_fp


def _pg_schema_snapshot(env: Any, schema: str) -> dict[str, tuple[str, ...]]:
    with env.modules.psycopg.connect(env.dsn, autocommit=True) as conn:
        tables = [
            str(r[0])
            for r in conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=%s ORDER BY table_name",
                (schema,),
            ).fetchall()
        ]
        return {
            table: tuple(
                repr(row)
                for row in conn.execute(
                    f'SELECT * FROM "{schema}"."{table}" ORDER BY ctid'
                ).fetchall()
            )
            for table in tables
        }


def _make_authentic_pg_post_c32_v3_schema(
    env: Any,
    label: str,
    *,
    populate: bool,
    gcb: bool = False,
) -> str:
    """Create a schema that authentically matches post-C32 schema v3 (or downgraded v3)."""
    if gcb:
        schema, config, runtime = _pg_provision_gcb(env, label)
    else:
        schema, store = _pg_single_store(env, label)
        config = _pg_config(env)
        runtime = _pg_runtime(env)
        if populate:
            req = _pg_request(env, commit_id=f"{label}-c1", nonce_byte=93)
            _pg_advance(env, store, req)
            store.atomic_commit(req)
        store.close()

    with env.modules.psycopg.connect(env.dsn, autocommit=True) as conn:
        if gcb:
            # Drop gcb_store_meta v4 constraint and install v3 constraint + value
            conn.execute(
                f'ALTER TABLE "{schema}"."gcb_store_meta" '
                "DROP CONSTRAINT gcb_store_meta_schema_version_check"
            )
            conn.execute(
                f"UPDATE \"{schema}\".\"gcb_store_meta\" SET schema_version='3'"
            )
            conn.execute(
                f'ALTER TABLE "{schema}"."gcb_store_meta" '
                "ADD CONSTRAINT gcb_store_meta_schema_version_check "
                "CHECK (schema_version='3')"
            )
        conn.execute(
            f"UPDATE \"{schema}\".\"metadata\" SET value='3' WHERE key='schema_version'"
        )
    return schema


# ---------------------------------------------------------------------------
# Row 1: Fresh v4 SQLite & PG17 (base & GCB) full roundtrip
# ---------------------------------------------------------------------------


def test_matrix_1_fresh_v4_sqlite_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh-v4.sqlite"
    runtime, sink = _isolated_runtime()
    config = _config()
    SQLiteAuthorityStore.provision(
        db_path,
        config=config,
        initial_contexts=_initial_contexts(),
        runtime=runtime,
    )
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone() == (4,)
        assert conn.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone() == ("4",)

    store = SQLiteAuthorityStore.open(db_path, config=config, runtime=runtime)
    req1 = _request(commit_id="v4-c1", nonce_byte=41, node_id="node-1")
    _advance_candidate(store, req1)
    c1 = store.atomic_commit(req1)
    assert c1.decision.outcome is RequestOutcome.COMMITTED
    assert c1.certificate_digest is not None

    recovered = store.recover_outbox(OutboxRecoveryRequest(max_items="10"))
    assert recovered.delivered_count == "1"
    assert len(sink.delivered) == 1

    # Supersession on another logical node ("root")
    req_root = _request(commit_id="v4-root", nonce_byte=42, node_id="root")
    _advance_candidate(store, req_root)
    root_res = store.atomic_commit(req_root)
    assert root_res.certificate_digest is not None
    rep = _request(
        commit_id="v4-root-sup",
        nonce_byte=43,
        node_id="root",
        expected_node_version="1",
        attempt_id="attempt-2",
    )
    _advance_candidate(store, rep)
    sup_res = store.supersede(SupersessionRequest(root_res.certificate_digest, rep))
    assert isinstance(sup_res, SupersessionCommitted)

    # Certificate revocation
    rev = store.revoke(
        RevocationRequest(
            scope=RevocationScope.CERTIFICATE,
            workflow_id="workflow-1",
            target_id=c1.certificate_digest,
            next_generation="1",
            reason="v4-roundtrip-revoke",
        )
    )
    assert rev.audit_event_id

    reopened = SQLiteAuthorityStore.open(db_path, config=config, runtime=runtime)
    assert reopened.get_certificate(c1.decision.commit_id) == c1.certificate_envelope_bytes
    reader = SQLiteAuthorityReader.open(db_path)
    assert reader.authority_store_id == config.authority_store_id


def test_matrix_1_fresh_v4_postgres_base_and_gcb_roundtrip(
    postgres_environment: Any,
) -> None:
    schema, store = _pg_single_store(postgres_environment, "v4_matrix1_base")
    runtime = _pg_runtime(postgres_environment)
    config = _pg_config(postgres_environment)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as conn:
        row = conn.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=\'schema_version\''
        ).fetchone()
    assert row == ("4",)

    req = _pg_request(postgres_environment, commit_id="pg-v4-1", nonce_byte=51)
    _pg_advance(postgres_environment, store, req)
    res = store.atomic_commit(req)
    assert res.decision.outcome is RequestOutcome.COMMITTED
    assert res.certificate_digest is not None
    rec = store.recover_outbox(OutboxRecoveryRequest(max_items="10"))
    assert rec.delivered_count == "1"
    store.revoke(
        RevocationRequest(
            scope=RevocationScope.CERTIFICATE,
            workflow_id="workflow-1",
            target_id=res.certificate_digest,
            next_generation="1",
            reason="pg-v4-revoke",
        )
    )
    store.close()

    reopened = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=config,
        runtime=runtime,
    )
    assert reopened.get_certificate(res.decision.commit_id) == res.certificate_envelope_bytes
    reopened.close()
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert reader.authority_store_id == config.authority_store_id
    reader.close()

    gcb_schema, gcb_config, gcb_runtime = _pg_provision_gcb(
        postgres_environment, "v4_matrix1_gcb"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as conn:
        gcb_meta = conn.execute(
            f'SELECT schema_version FROM "{gcb_schema}"."gcb_store_meta" WHERE singleton=1'
        ).fetchone()
    assert gcb_meta == ("4",)
    gcb_store = _pg_open_gcb(
        postgres_environment, gcb_schema, gcb_config, gcb_runtime
    )
    assert gcb_store.authority_store_id == gcb_config.authority_store_id
    gcb_store.close()


# ---------------------------------------------------------------------------
# Row 2: Authentic pre-C32 v3 fixture fails closed without byte mutation
# ---------------------------------------------------------------------------


def _assert_sqlite_unchanged(path: Path, before_db_bytes: bytes) -> None:
    """Assert main DB file bytes are untouched and zero WAL frames (0 bytes) were written."""
    assert path.read_bytes() == before_db_bytes
    wal = Path(f"{path}-wal")
    assert not wal.exists() or wal.stat().st_size == 0


def test_matrix_2_pre_c32_v3_sqlite_fixture_rejected_immutably(tmp_path: Path) -> None:
    path = _copy_pre_c32_v3_fixture(tmp_path, "pre-c32.sqlite")
    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        assert conn.execute("PRAGMA user_version").fetchone() == (3,)
        assert conn.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone() == ("3",)
        audit_ids = [r[0] for r in conn.execute("SELECT audit_event_id FROM candidates")]
        assert audit_ids, "fixture must contain populated candidate rows"
    finally:
        conn.close()

    before_bytes = path.read_bytes()
    before_sha = hashlib.sha256(before_bytes).hexdigest()
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()

    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, _config(), _runtime()),
        lambda: SQLiteAuthorityStore._open_gcb(path, _config(), _runtime()),
    ):
        with pytest.raises(
            ValueError, match=r"^APCC authority schema version is incompatible$"
        ):
            opener()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before_sha
        _assert_sqlite_unchanged(path, before_bytes)


# ---------------------------------------------------------------------------
# Row 3 & Row 4: Post-C32 v3 (populated and empty) rejected cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("populate", [True, False])
def test_matrix_3_4_post_c32_v3_sqlite_populated_and_empty_rejected(
    tmp_path: Path, populate: bool
) -> None:
    path = tmp_path / f"post-c32-v3-{'pop' if populate else 'empty'}.sqlite"
    store = _open_store(path, None)
    if populate:
        req = _request(commit_id="v3-pop-1", nonce_byte=61)
        _advance_candidate(store, req)
        assert store.atomic_commit(req).decision.outcome is RequestOutcome.COMMITTED
    _rewrite_sqlite_to_authentic_post_c32_v3(path)
    before_bytes = path.read_bytes()

    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, _config(), _runtime()),
    ):
        with pytest.raises(
            ValueError, match=r"^APCC authority schema version is incompatible$"
        ):
            opener()
        _assert_sqlite_unchanged(path, before_bytes)


@pytest.mark.parametrize("populate", [True, False])
def test_matrix_3_4_post_c32_v3_postgres_populated_and_empty_rejected(
    postgres_environment: Any, populate: bool
) -> None:
    schema = _make_authentic_pg_post_c32_v3_schema(
        postgres_environment,
        f"post_c32_v3_{'pop' if populate else 'empty'}",
        populate=populate,
    )
    before = _pg_schema_snapshot(postgres_environment, schema)
    for opener in (
        lambda: postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ),
        lambda: postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_pg_config(postgres_environment),
            runtime=_pg_runtime(postgres_environment),
        ),
    ):
        with pytest.raises(
            ValueError, match=r"^APCC authority schema version is incompatible$"
        ):
            opener()
        assert _pg_schema_snapshot(postgres_environment, schema) == before


# ---------------------------------------------------------------------------
# Row 5: SQLite metadata vs PRAGMA user_version mismatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("user_version", "meta_version"),
    [(4, "3"), (3, "4")],
)
def test_matrix_5_sqlite_user_version_and_metadata_mismatch(
    tmp_path: Path, user_version: int, meta_version: str
) -> None:
    path = tmp_path / f"mismatch-u{user_version}-m{meta_version}.sqlite"
    _open_store(path, None)
    with sqlite3.connect(path) as conn:
        conn.execute(f"PRAGMA user_version={user_version}")
        conn.execute(
            "UPDATE metadata SET value=? WHERE key='schema_version'",
            (meta_version,),
        )
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    before = _database_file_state(path)

    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, _config(), _runtime()),
    ):
        with pytest.raises(
            ValueError, match=r"^APCC authority schema version is incompatible$"
        ):
            opener()
        assert _database_file_state(path) == before


# ---------------------------------------------------------------------------
# Row 6: PG17 metadata / gcb_store_meta / CHECK / catalog mismatch
# ---------------------------------------------------------------------------


def test_matrix_6_postgres_gcb_and_catalog_version_mismatches_fail_closed(
    postgres_environment: Any,
) -> None:
    # 6a. GCB store with schema_version='3' -> incompatible error
    gcb_v3 = _make_authentic_pg_post_c32_v3_schema(
        postgres_environment, "matrix6_gcb_v3", populate=False, gcb=True
    )
    before_v3 = _pg_schema_snapshot(postgres_environment, gcb_v3)
    with pytest.raises(
        ValueError, match=r"^APCC authority schema version is incompatible$"
    ):
        _pg_open_gcb(
            postgres_environment,
            gcb_v3,
            _pg_config(postgres_environment),
            _pg_runtime(postgres_environment),
        )
    assert _pg_schema_snapshot(postgres_environment, gcb_v3) == before_v3

    # 6b. Spoofed GCB metadata.schema_version='4' while gcb_store_meta/CHECK remain v3 -> fails closed
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as conn:
        conn.execute(
            f"UPDATE \"{gcb_v3}\".\"metadata\" SET value='4' WHERE key='schema_version'"
        )
    before_spoof = _pg_schema_snapshot(postgres_environment, gcb_v3)
    with pytest.raises(ValueError, match="schema validation failed"):
        _pg_open_gcb(
            postgres_environment,
            gcb_v3,
            _pg_config(postgres_environment),
            _pg_runtime(postgres_environment),
        )
    assert _pg_schema_snapshot(postgres_environment, gcb_v3) == before_spoof


# ---------------------------------------------------------------------------
# Row 7: Spoofed v4 SQLite (bumping v3 -> 4 manually without valid v4 fingerprint)
# ---------------------------------------------------------------------------


def test_matrix_7_spoofed_v4_metadata_on_pre_c32_sqlite_fails_closed(
    tmp_path: Path,
) -> None:
    path = _copy_pre_c32_v3_fixture(tmp_path, "spoofed-v4.sqlite")
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version=4")
        conn.execute("UPDATE metadata SET value='4' WHERE key='schema_version'")
        conn.commit()
    before = _database_file_state(path)

    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, _config(), _runtime()),
    ):
        with pytest.raises(ValueError, match="schema validation failed"):
            opener()
        assert _database_file_state(path) == before


# ---------------------------------------------------------------------------
# Row 8: provision() on existing v3 or v4 refuses overwrite without mutation
# ---------------------------------------------------------------------------


def test_matrix_8_provision_refuses_overwrite_on_existing_v3_and_v4_sqlite(
    tmp_path: Path,
) -> None:
    v3_copy = _copy_pre_c32_v3_fixture(tmp_path, "existing-v3.sqlite")
    v3_before = hashlib.sha256(v3_copy.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        SQLiteAuthorityStore.provision(
            v3_copy, _config(), _initial_contexts(), _runtime()
        )
    assert hashlib.sha256(v3_copy.read_bytes()).hexdigest() == v3_before

    v4_path = tmp_path / "existing-v4.sqlite"
    SQLiteAuthorityStore.provision(
        v4_path, _config(), _initial_contexts(), _runtime()
    )
    v4_before_bytes = v4_path.read_bytes()
    with pytest.raises(ValueError, match="already provisioned"):
        SQLiteAuthorityStore.provision(
            v4_path, _config(), _initial_contexts(), _runtime()
        )
    _assert_sqlite_unchanged(v4_path, v4_before_bytes)


def test_matrix_8_provision_refuses_overwrite_on_existing_v3_and_v4_postgres(
    postgres_environment: Any,
) -> None:
    v4_schema, _ = _pg_single_store(postgres_environment, "matrix8_existing_v4")
    v4_before = _pg_schema_snapshot(postgres_environment, v4_schema)
    with pytest.raises(ValueError, match="already provisioned"):
        postgres_environment.modules.store_factory.provision(
            postgres_environment.dsn,
            schema=v4_schema,
            config=_pg_config(postgres_environment),
            initial_contexts=_pg_initial_contexts(postgres_environment),
            runtime_role=postgres_environment.runtime_role,
            observer_role=postgres_environment.observer_role,
            runtime=_pg_runtime(postgres_environment),
        )
    assert _pg_schema_snapshot(postgres_environment, v4_schema) == v4_before

    v3_schema = _make_authentic_pg_post_c32_v3_schema(
        postgres_environment, "matrix8_existing_v3", populate=False
    )
    v3_before = _pg_schema_snapshot(postgres_environment, v3_schema)
    with pytest.raises(ValueError, match="already provisioned"):
        postgres_environment.modules.store_factory.provision(
            postgres_environment.dsn,
            schema=v3_schema,
            config=_pg_config(postgres_environment),
            initial_contexts=_pg_initial_contexts(postgres_environment),
            runtime_role=postgres_environment.runtime_role,
            observer_role=postgres_environment.observer_role,
            runtime=_pg_runtime(postgres_environment),
        )
    assert _pg_schema_snapshot(postgres_environment, v3_schema) == v3_before


# ---------------------------------------------------------------------------
# Row 9: Decision families (COMMITTED / DENIED / CONFLICTED) + launch attestation v4
# ---------------------------------------------------------------------------


def test_matrix_9_decision_families_and_authority_launch_attestation_v4(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "decisions-v4.sqlite"
    store = _open_store(db_path, None)

    # COMMITTED (ACCEPT)
    req_ok = _request(commit_id="dec-ok", nonce_byte=81)
    _advance_candidate(store, req_ok)
    ok_res = store.atomic_commit(req_ok)
    assert ok_res.decision.outcome is RequestOutcome.COMMITTED

    # CONFLICTED (commit_id equivocation: same commit_id, different operation/nonce)
    req_conf = _request(commit_id="dec-ok", nonce_byte=82, node_id="root")
    conf_res = store.atomic_commit(req_conf)
    assert conf_res.decision.outcome is RequestOutcome.CONFLICTED

    # DENIED (invalid producer signature on fresh commit_id)
    req_bad_base = _request(commit_id="dec-deny", nonce_byte=83, node_id="child")
    _advance_candidate(store, req_bad_base)
    req_deny = replace(
        req_bad_base,
        signatures=replace(
            req_bad_base.signatures,
            producer=replace(
                req_bad_base.signatures.producer,
                signature_b64u=b64u_encode(bytes(64)),
            ),
        ),
    )
    deny_res = store.atomic_commit(req_deny)
    assert deny_res.decision.outcome is RequestOutcome.DENIED

    # authority_service launch attestation & observation contract bind schema_version == "4"
    svc_cfg = authority_child_config(
        tmp_path / "service-v4.db",
        tmp_path / "service-v4.keys",
    )
    authority = start_authority(svc_cfg)
    observer = start_authority_observer(
        authority, _observer_launch(svc_cfg, tmp_path)
    )
    try:
        assert observer.launch_attestation.schema_version == "4"
        assert observer.launch_attestation.schema_fingerprint == sqlite_store_module._SCHEMA_FINGERPRINT
    finally:
        observer.close()
        authority.close()


def test_postgres_module_fingerprint_matches_schema_version_4(
    postgres_environment: Any,
) -> None:
    import importlib

    postgres_store_module = importlib.import_module(
        "constitutional_swarm.apcc.postgres_store"
    )
    assert sqlite_store_module._AUTHORITY_SCHEMA_VERSION == "4"
    assert (
        postgres_store_module._POSTGRES_GCB_CATALOG_FINGERPRINT
        == "boKYmnLfKZ0KaZ81HwsAJ6e8hURsyEkqGaIpg9E2lPc"
    )
    assert (
        postgres_store_module._POSTGRES_CATALOG_FINGERPRINT
        == "s-gycb2MocWE-vCFg3fyKw9tSRPK0ayWSKxg9dMfU9w"
    )
