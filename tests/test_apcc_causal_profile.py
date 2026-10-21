"""Explicit W2 authority limits retain default bytes and durable trust binding."""

from dataclasses import replace

import pytest

from constitutional_swarm.apcc import sqlite_store as sql
from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import FailureCode, RequestOutcome
from constitutional_swarm.apcc.ports import (
    AuthorityCausalProfile,
    CurrentStatusRequest,
    LogicalNodeStatusRequest,
    RevocationRequest,
    RevocationScope,
)
from constitutional_swarm.apcc.verifier import (
    CausalClosureLimits,
    verify_causal_closure,
)
from tests import test_apcc_sqlite as fixture
from tests.apcc_conformance import _predecessor


def config():
    return replace(
        fixture._config(), causal_profile=AuthorityCausalProfile.W2_LINEAR_100
    )


def test_default_bytes_and_w2_signed_binding():
    default = fixture._config()
    obj = sql._config_object(default)
    assert set(obj) == {"authority_store_id", "bindings", "freshness"}
    expected = {
        "profile": "APCC-1.0-draft",
        "kind": "apcc.semantic-checkpoint",
        "authority_store_id": "store-1",
        "schema_fingerprint": "schema",
        "change_sequence": "7",
        "prior_digest": "prior",
    }
    assert (
        sql._semantic_checkpoint_body(default, "schema", 7, "prior")
        == sql._json(expected).encode()
    )
    assert default.causal_limits == CausalClosureLimits()
    w2 = config()
    assert w2.causal_limits == CausalClosureLimits(max_depth=99)
    assert sql._config_from_object(sql._config_object(w2)) == w2
    expected["authority_config_digest"] = sha256_digest(
        sql._json(sql._config_object(w2)).encode()
    )
    assert (
        sql._semantic_checkpoint_body(w2, "schema", 7, "prior")
        == sql._json(expected).encode()
    )


@pytest.mark.parametrize("value", ["w2-linear-100", "default", None, True, 99])
def test_config_profile_requires_enum(value):
    with pytest.raises(ValueError):
        replace(fixture._config(), causal_profile=value)


@pytest.mark.parametrize("value", ["default", "W2_LINEAR_100", None, True, 99, {}, []])
def test_persisted_profile_is_canonical(value):
    obj = sql._config_object(fixture._config())
    obj["causal_profile"] = value
    with pytest.raises(ValueError):
        sql._config_from_object(obj)


@pytest.mark.parametrize(
    "profile,maximum",
    [(AuthorityCausalProfile.DEFAULT, 64), (AuthorityCausalProfile.W2_LINEAR_100, 99)],
)
def test_signed_chain_admission_status_reopen_and_boundary(
    tmp_path, profile, maximum, monkeypatch
):
    cfg = replace(fixture._config(), causal_profile=profile)
    path = tmp_path / "chain.db"
    template = fixture._initial_contexts()[-1]
    contexts = tuple(
        replace(
            template,
            subject=replace(template.subject, node_id=f"depth-node-{index}"),
            candidate_state=replace(
                template.candidate_state, node_id=f"depth-node-{index}"
            ),
            logical_node_state=replace(
                template.logical_node_state, node_id=f"depth-node-{index}"
            ),
            audit_event_id=f"bootstrap-{index}",
        )
        for index in range(maximum + 2)
    )
    sql.SQLiteAuthorityStore.provision(
        path,
        config=cfg,
        initial_contexts=contexts,
        runtime=fixture._runtime(),
    )
    store = sql.SQLiteAuthorityStore.open(path, config=cfg, runtime=fixture._runtime())
    predecessor = None
    for index in range(maximum + 2):
        request = fixture._request(
            commit_id=f"depth-{index}",
            nonce_byte=index + 1,
            node_id=f"depth-node-{index}",
            attempt_id=f"attempt-{index}",
            predecessors=[] if predecessor is None else [predecessor],
        )
        fixture._advance_candidate(store, request)
        result = store.atomic_commit(request)
        if index == maximum + 1:
            assert result.decision.outcome is RequestOutcome.DENIED
            assert result.decision.reason is FailureCode.DEPTH_LIMIT_EXCEEDED
            assert store.get_certificate(request.commit_id) is None
            break
        assert result.decision.outcome is RequestOutcome.COMMITTED
        predecessor = _predecessor(request, result)
        if index == 0:
            ancestor_digest = result.certificate_digest
        last = result
        last_request = request
    store = sql.SQLiteAuthorityStore.open(path, config=cfg, runtime=fixture._runtime())
    digest = last.certificate_digest
    nonce = fixture._nonce(220)
    status = store.current_status(digest, nonce)
    assert status.status.value == "current"
    assert (
        store.current_status_batch((CurrentStatusRequest(digest, nonce),))[0].status
        == status
    )
    logical = store.logical_node_status_batch(
        (LogicalNodeStatusRequest("workflow-1", last_request.subject.node_id, nonce),)
    )[0]
    assert logical.status == status
    with store._read_transaction() as connection:
        assert store._persisted_causal_error(connection, digest) is None
        resolver = sql._AuthorityPredecessorResolver(connection)
        assert verify_causal_closure(
            last.certificate_envelope_bytes,
            trust=sql._trust(cfg),
            resolver=resolver,
            limits=cfg.causal_limits,
        ).ok
        if profile is AuthorityCausalProfile.W2_LINEAR_100:
            assert not verify_causal_closure(
                last.certificate_envelope_bytes,
                trust=sql._trust(cfg),
                resolver=resolver,
            ).ok
            with pytest.raises(ValueError):
                sql.SQLiteAuthorityStore.open(
                    path, config=fixture._config(), runtime=fixture._runtime()
                )

    if profile is AuthorityCausalProfile.W2_LINEAR_100:
        for constrained in (
            CausalClosureLimits(max_depth=99, max_certificates=1),
            CausalClosureLimits(max_depth=99, max_total_bytes=1),
        ):
            with monkeypatch.context() as patch:
                patch.setattr(
                    sql.APCCAuthorityConfig,
                    "causal_limits",
                    property(lambda self: constrained),
                )
                with store._read_transaction() as connection:
                    assert (
                        store._persisted_causal_error(connection, digest)
                        is FailureCode.SIZE_LIMIT_EXCEEDED
                    )
                    certificate = sql.decode_certificate(
                        sql.decode_envelope(last.certificate_envelope_bytes).payload
                    )
                    assert (
                        store._request_causal_error(connection, certificate)
                        is FailureCode.SIZE_LIMIT_EXCEEDED
                    )
                assert store.current_status(digest, nonce).status.value == "revoked"
                assert (
                    store.logical_node_status_batch(
                        (
                            LogicalNodeStatusRequest(
                                "workflow-1", last_request.subject.node_id, nonce
                            ),
                        )
                    )[0].status.status.value
                    == "revoked"
                )

    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "workflow-1",
            ancestor_digest,
            "1",
            "ancestor revoked",
        )
    )
    assert store.current_status(digest, nonce).status.value == "revoked"
    assert (
        store.current_status_batch((CurrentStatusRequest(digest, nonce),))[
            0
        ].status.status.value
        == "revoked"
    )
    assert (
        store.logical_node_status_batch(
            (
                LogicalNodeStatusRequest(
                    "workflow-1", last_request.subject.node_id, nonce
                ),
            )
        )[0].status.status.value
        == "revoked"
    )


def test_pg_rejects_before_connection(monkeypatch):
    pg = pytest.importorskip("constitutional_swarm.apcc.postgres_store")

    def no_connect(*args, **kwargs):
        raise AssertionError("must reject before connecting")

    monkeypatch.setattr(pg, "_connect", no_connect)
    cfg = config()
    with pytest.raises(ValueError, match="default causal profile"):
        pg.PostgresAuthorityStore.open(
            "invalid", schema="test", config=cfg, runtime=fixture._runtime()
        )
    with pytest.raises(ValueError, match="default causal profile"):
        pg.PostgresAuthorityStore.provision(
            "invalid",
            schema="test",
            config=cfg,
            initial_contexts=fixture._initial_contexts(),
            runtime=fixture._runtime(),
            runtime_role="writer",
            observer_role="reader",
        )
    with pytest.raises(ValueError, match="default causal profile"):
        pg.PostgresAuthorityReader("invalid", "test", cfg)
    with pytest.raises(ValueError, match="default causal profile"):
        pg.PostgresAuthorityStore(
            "invalid", "test", cfg, fixture._runtime(), pg.PostgresRetryPolicy(), None
        )


@pytest.mark.parametrize(
    "original", [AuthorityCausalProfile.DEFAULT, AuthorityCausalProfile.W2_LINEAR_100]
)
def test_persisted_profile_substitution_invalidates_signed_checkpoint(
    tmp_path, original
):
    import sqlite3

    path = tmp_path / "tamper.db"
    cfg = replace(fixture._config(), causal_profile=original)
    sql.SQLiteAuthorityStore.provision(
        path,
        config=cfg,
        initial_contexts=fixture._initial_contexts(),
        runtime=fixture._runtime(),
    )
    store = sql.SQLiteAuthorityStore.open(path, config=cfg, runtime=fixture._runtime())
    changed = (
        fixture._config()
        if original is AuthorityCausalProfile.W2_LINEAR_100
        else config()
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='config'",
            (sql._json(sql._config_object(changed)),),
        )
    with pytest.raises(ValueError):
        sql.SQLiteAuthorityStore.open(path, config=changed, runtime=fixture._runtime())
    with pytest.raises(ValueError):
        sql.SQLiteAuthorityReader.open(path)
    with pytest.raises(ValueError):
        store.logical_node_status_batch(
            (LogicalNodeStatusRequest("workflow-1", "node-1", fixture._nonce(22)),)
        )


def test_pg_persisted_w2_rejected_after_exact_decode(monkeypatch):
    pg = pytest.importorskip("constitutional_swarm.apcc.postgres_store")
    values = {
        "config": sql._json(sql._config_object(config())),
        "postgres_owner_role": "owner",
        "postgres_runtime_role": "writer",
        "postgres_observer_role": "reader",
        "schema_fingerprint": pg._POSTGRES_SCHEMA_FINGERPRINT,
        "schema_version": pg._AUTHORITY_SCHEMA_VERSION,
    }

    class Connection:
        def execute(self, query):
            assert query == "SELECT key,value FROM metadata ORDER BY key"
            return sorted(values.items())

    for name in (
        "_validate_role_contract",
        "_validate_parameter_contract",
        "_validate_external_capability_contract",
        "_validate_logical_replication_contract",
        "_validate_foreign_key_integrity",
    ):
        monkeypatch.setattr(pg, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(
        pg, "_catalog_fingerprint", lambda *args: pg._POSTGRES_CATALOG_FINGERPRINT
    )
    decoded = []
    original = pg._config_from_object

    def decode(value):
        result = original(value)
        decoded.append(result)
        return result

    monkeypatch.setattr(pg, "_config_from_object", decode)
    with pytest.raises(ValueError):
        pg._semantic_config(Connection(), "test")
    assert decoded == [config()]


def test_old_default_checkpoint_cannot_attest_w2_config(tmp_path):
    import sqlite3

    default_path, w2_path = tmp_path / "default.db", tmp_path / "w2.db"
    for path, cfg in ((default_path, fixture._config()), (w2_path, config())):
        sql.SQLiteAuthorityStore.provision(
            path,
            config=cfg,
            initial_contexts=fixture._initial_contexts(),
            runtime=fixture._runtime(),
        )
    with sqlite3.connect(default_path) as connection:
        old = connection.execute(
            "SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature FROM semantic_checkpoint"
        ).fetchone()
    with sqlite3.connect(w2_path) as connection:
        connection.execute(
            "UPDATE semantic_checkpoint SET change_sequence=?,prior_digest=?,checkpoint_digest=?,key_id=?,signature=?",
            old,
        )
    with pytest.raises(ValueError):
        sql.SQLiteAuthorityStore.open(
            w2_path, config=config(), runtime=fixture._runtime()
        )
