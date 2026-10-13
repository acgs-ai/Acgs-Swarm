"""Paired real-storage T6 fixtures; never qualify a mock or skip a missing DB."""

import copy
import os
import random
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg2
import pytest

from offline_foundations.evidence import Access, EvidenceError, EvidenceStore
from offline_foundations.postgres_evidence import PostgresEvidenceStore
from offline_foundations.tests import test_evidence as corpus


@pytest.fixture
def pair(tmp_path):
    dsn = os.environ.get("ACGS_T6_TEST_DSN")
    if not dsn:
        pytest.fail("Real PostgreSQL DSN required; no mock/skip qualification")
    return (
        EvidenceStore(tmp_path / "sqlite.db"),
        PostgresEvidenceStore(dsn, "t6_" + uuid.uuid4().hex),
    )


def reopen(store):
    if isinstance(store, PostgresEvidenceStore):
        return PostgresEvidenceStore(store.dsn, store.schema)
    return EvidenceStore(store.path)


@pytest.mark.parametrize("family", range(36))
def test_shared_authored_corpus(pair, family, monkeypatch):
    outputs = []
    for store in pair:
        results = []
        query = store.query

        def capture(*args, query=query, results=results, **kwargs):
            selected = query(*args, **kwargs)
            results.append(selected.serialized)
            return selected

        with monkeypatch.context() as patch:
            patch.setattr(store, "query", capture)
            corpus.test_authored_synthetic_family_queries(store, family)
        outputs.append(results)
    assert len(outputs[0]) == len(outputs[1]) == 4
    assert outputs[0] == outputs[1]
    assert pair[0].audit()["revisions"] == pair[1].audit()["revisions"]
    assert pair[0].audit()["events"] == pair[1].audit()["events"]


EDGE_CASES = [
    corpus.test_conflicting_sources_and_equal_revision_conflicts_retained,
    corpus.test_scope_collision_and_no_implicit_project_promotion,
    corpus.test_revocation_between_retrieval_and_consumption_blocks_history_too,
    corpus.test_hash_current_access_and_derived_provenance_rechecked,
    corpus.test_new_successor_does_not_fall_back_when_revoked_or_unverifiable,
    corpus.test_plan_not_completed_fact_and_source_instructions_are_data,
    corpus.test_explicit_validity_and_dependency_adjacency,
    corpus.test_same_revision_fork_cannot_be_hidden_by_current_hash,
    corpus.test_expired_successor_does_not_resurrect_old_revision,
]


@pytest.mark.parametrize("case", EDGE_CASES, ids=lambda case: case.__name__)
def test_shared_edge_contract(pair, case):
    for store in pair:
        case(store)


def test_observation_validity_restart_and_exact_output(pair):
    sc = corpus.scope()
    records = [
        corpus.revision("a"),
        corpus.revision("b", order=2, observed=30, start=20, value="new"),
        corpus.revision("late", order=0, observed=90, value="older"),
    ]
    ctx = corpus.access(sc, *records)
    outputs = []
    for store in pair:
        for record in records:
            store.append(sc, record)
        checks = []
        for cutoff, valid_at, expected in [
            (15, 10, "old"),
            (40, 30, "new"),
            (100, 95, "new"),
        ]:
            selected = store.query(ctx, "setting", cutoff, valid_at)
            assert selected.data["records"][0]["claim_value"] == expected
            assert (
                reopen(store).query(ctx, "setting", cutoff, valid_at).serialized
                == selected.serialized
            )
            checks.append(selected.serialized)
        outputs.append(checks)
    assert outputs[0] == outputs[1]


def test_blob_revision_event_append_only_and_idempotency(pair):
    record = corpus.revision("a")
    for store in pair:
        store.append(corpus.scope(), record)
        store.append(corpus.scope(), record)
        assert store.audit()["revisions"] == 1 and store.audit()["events"] == 1
        for table in ("revisions", "events", "blobs"):
            column = "bytes" if table == "blobs" else "body"
            for statement in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
            ):
                with (
                    pytest.raises((sqlite3.IntegrityError, psycopg2.IntegrityError)),
                    store.connect(True) as db,
                ):
                    db.execute(statement)
            if isinstance(store, PostgresEvidenceStore):
                with pytest.raises(psycopg2.IntegrityError), store.connect(True) as db:
                    db.execute(f"TRUNCATE {table}")
        changed = copy.deepcopy(record)
        changed["claim_value"] = "fork"
        with pytest.raises(EvidenceError):
            store.append(corpus.scope(), changed)
        assert reopen(store).audit()["revisions"] == 1


def test_rollback_after_real_blob_and_revision_write(pair, monkeypatch):
    for store in pair:

        def fail_event(*args):
            raise EvidenceError("Injected failure before event")

        with monkeypatch.context() as patch:
            patch.setattr(store, "event", fail_event)
            with pytest.raises(EvidenceError, match="Injected"):
                store.append(corpus.scope(), corpus.revision("a"))
        with store.connect() as db:
            for table in ("blobs", "revisions", "events"):
                assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        store.append(corpus.scope(), corpus.revision("a"))
        assert store.audit()["events"] == 1


def test_concurrent_duplicate_and_conflicting_identity(pair):
    for store in pair:
        sc = corpus.scope()
        record = corpus.revision("a")
        with ThreadPoolExecutor(max_workers=8) as pool:
            outputs = list(
                pool.map(
                    lambda _, store=store, sc=sc, record=record: (
                        store.append(sc, record).serialized
                    ),
                    range(8),
                )
            )
        assert len(set(outputs)) == 1
        assert store.audit()["revisions"] == 1 and store.audit()["events"] == 1
        first, second = (
            corpus.revision("collision", value="one"),
            corpus.revision("collision", value="two"),
        )
        barrier = threading.Barrier(2)

        def compete(record, barrier=barrier, store=store, sc=sc):
            barrier.wait(timeout=5)
            try:
                store.append(sc, record)
                return "accepted"
            except EvidenceError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(compete, [first, second])) == [
                "accepted",
                "conflict",
            ]
        assert store.audit()["revisions"] == 2 and store.audit()["events"] == 2


def test_reader_snapshot_and_no_partial_transaction(pair, monkeypatch):
    for store in pair:
        entered, finish = threading.Event(), threading.Event()
        event = store.event

        def delayed_event(*args, entered=entered, finish=finish, event=event):
            entered.set()
            assert finish.wait(timeout=10)
            return event(*args)

        with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=1) as pool:
            patch.setattr(store, "event", delayed_event)
            writer = pool.submit(store.append, corpus.scope(), corpus.revision("a"))
            assert entered.wait(timeout=5)
            try:
                with store.connect() as db:
                    assert (
                        db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
                    )
                    finish.set()
                    writer.result(timeout=5)
                    assert (
                        db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
                    )
                    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
            finally:
                finish.set()
        assert store.audit()["revisions"] == 1 and store.audit()["events"] == 1


def test_current_consume_successor_and_access_between_connections(pair):
    for store in pair:
        sc = corpus.scope()
        a, b = (
            corpus.revision("a"),
            corpus.revision("b", order=2, observed=30, start=20, value="new"),
        )
        store.append(sc, a)
        selected = store.query(corpus.access(sc, a), "setting", 100, 50)
        reopen(store).append(sc, b)
        assert (
            store.consume(selected, corpus.access(sc, a, b)).data["status"] == "abstain"
        )
        current = store.query(corpus.access(sc, a, b), "setting", 100, 50)
        denied = Access(sc, 100, frozenset(), {})
        assert reopen(store).consume(current, denied).data["status"] == "abstain"


def test_null_unicode_and_reserved_prefix_identities(pair):
    sc = corpus.scope(tenant="tenant\0雪", task="t\0", run="\\0")
    record = corpus.revision("id\0雪", source="source\0λ", value={"text": "雪\0\\0"})
    record["claim_key"] = "\x1eT6:claim\0"
    outputs = []
    for store in pair:
        store.append(sc, record)
        ctx = corpus.access(sc, record)
        selected = store.query(ctx, record["claim_key"], 100, 50)
        assert selected.data["status"] == "available"
        outputs.append(selected.serialized)
    assert outputs[0] == outputs[1]


def test_postgres_schema_and_authority_separation(pair):
    pg = pair[1]
    with pg.connect() as db:
        assert db.execute("SELECT current_schema()").fetchone()[0] == pg.schema
    for forbidden in ("public", "apcc", "pg_catalog", "t6_bad;DROP SCHEMA public"):
        with pytest.raises(EvidenceError):
            PostgresEvidenceStore(pg.dsn, forbidden)


def test_maximum_valid_unicode_scope_and_index_identities(pair):
    rng = random.Random(13)

    def text(length):
        return "".join(chr(rng.randrange(0x10000, 0x10FFFF)) for _ in range(length))

    sc = corpus.scope(
        tenant=text(512), project=text(512), task=text(512), run=text(512)
    )
    record = corpus.revision(text(511) + "\0", source=text(512))
    record["claim_key"] = "\x1eT6:" + text(507) + "\0"
    assert len(record["evidence_id"]) == len(record["claim_key"]) == 512
    outputs = []
    for store in pair:
        store.append(sc, record)
        selected = store.query(corpus.access(sc, record), record["claim_key"], 100, 50)
        assert selected.data["status"] == "available"
        store.revoke(sc, text(511) + "\0", record["evidence_id"], 60, 60, "synthetic")
        assert (
            store.consume(selected, corpus.access(sc, record)).data["status"]
            == "abstain"
        )
        outputs.append(selected.serialized)
    assert outputs[0] == outputs[1]
