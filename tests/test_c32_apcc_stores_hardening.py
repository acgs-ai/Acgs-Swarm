"""C32 regression tests: APCC authority store hardening (apcc-stores-1..10).

Backend-neutral checks live in ``tests/apcc_conformance.py`` and run here on the
SQLite harness and, when ``APCC_POSTGRES_TEST_DSN``-style prerequisites exist, on
the PostgreSQL harness. SQLite-only checks cover file-level tampering.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from tests.apcc_conformance import (
    _stage,
    assert_certificate_revocation_binds_owning_workflow_conforms,
    assert_new_candidate_stage_binds_node_version_conforms,
)
from tests.test_apcc_postgres import (
    _harness as _postgres_harness,
)
from tests.test_apcc_postgres import (
    postgres_environment,  # noqa: F401  (pytest fixture re-export)
)
from tests.test_apcc_sqlite import _config as _sqlite_config
from tests.test_apcc_sqlite import _config_with_mutated_binding, _runtime
from tests.test_apcc_sqlite import _harness as _sqlite_harness
from tests.test_apcc_sqlite import _reseal_test_checkpoint

from constitutional_swarm.apcc import sqlite_store as sqlite_store_module
from constitutional_swarm.apcc.crypto import b64u_decode, sha256_digest
from constitutional_swarm.apcc.ports import (
    AuthorityRuntime,
    CommitContextRequest,
    RevocationRequest,
    RevocationScope,
    StageResultRequest,
    SupersessionCommitted,
    SupersessionRequest,
    validate_runtime_signers,
)
from constitutional_swarm.apcc.service import APCCCommitService
from constitutional_swarm.apcc.sqlite_store import (
    SQLiteAuthorityReader,
    SQLiteAuthorityStore,
)
from constitutional_swarm.apcc.verifier import TrustRole


# --- apcc-stores-1: fresh-attempt stage must not brick the store -----------------


def test_c32_stage_fresh_attempt_with_wrong_version_is_rejected_sqlite(
    tmp_path: Path,
) -> None:
    assert_new_candidate_stage_binds_node_version_conforms(_sqlite_harness(), tmp_path)
    SQLiteAuthorityReader.open(tmp_path / "stage-node-version-binding")


def test_c32_stage_fresh_attempt_with_wrong_version_is_rejected_postgres(
    postgres_environment: object,  # noqa: F811
    tmp_path: Path,
) -> None:
    assert_new_candidate_stage_binds_node_version_conforms(
        _postgres_harness(postgres_environment),  # type: ignore[arg-type]
        tmp_path,
    )


# --- apcc-stores-2: supersede replay must go through attested reads --------------


def test_c32_supersede_replay_rejects_tampered_store(tmp_path: Path) -> None:
    harness = _sqlite_harness()
    path = tmp_path / "supersede-tampered-replay"
    store = harness.open_store(path, None)
    old_request = harness.make_request(commit_id="supersede-tamper-old", nonce_byte=73)
    _stage(store, harness, old_request)
    old = store.atomic_commit(old_request)
    assert old.certificate_digest is not None
    proposal = harness.make_request(
        commit_id="supersede-tamper-new",
        nonce_byte=74,
        expected_node_version="1",
        attempt_id="supersede-tamper-replacement",
    )
    _stage(store, harness, proposal)
    request = SupersessionRequest(old.certificate_digest, proposal)
    assert isinstance(store.supersede(request), SupersessionCommitted)
    assert isinstance(store, SQLiteAuthorityStore)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE semantic_checkpoint SET checkpoint_digest=? WHERE singleton=1",
            ("A" * 43,),
        )
    with pytest.raises(ValueError):
        store.supersede(request)


# --- apcc-stores-3: certificate revocation is bound to its own workflow ---------


def test_c32_certificate_revocation_rejects_foreign_workflow_sqlite(
    tmp_path: Path,
) -> None:
    assert_certificate_revocation_binds_owning_workflow_conforms(_sqlite_harness(), tmp_path)


def test_c32_certificate_revocation_rejects_foreign_workflow_postgres(
    postgres_environment: object,  # noqa: F811
    tmp_path: Path,
) -> None:
    assert_certificate_revocation_binds_owning_workflow_conforms(
        _postgres_harness(postgres_environment),  # type: ignore[arg-type]
        tmp_path,
    )


class _OwnerLookupHidingConnection:
    """Test-only proxy that hides the certificate owner from the write-side check."""

    def __init__(self, inner: sqlite3.Connection) -> None:
        self._inner = inner

    def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> object:
        if sql.startswith("SELECT workflow_id FROM certificates WHERE"):
            return self._inner.execute("SELECT 1 WHERE 0")
        return self._inner.execute(sql, parameters)


def test_c32_reopen_rejects_certificate_control_event_for_foreign_workflow(
    tmp_path: Path,
) -> None:
    harness = _sqlite_harness()
    path = tmp_path / "forged-cross-workflow-control"
    store = harness.open_store(path, None)
    request = harness.make_request(commit_id="forged-control", nonce_byte=75)
    _stage(store, harness, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    assert isinstance(store, SQLiteAuthorityStore)
    forged = RevocationRequest(
        RevocationScope.CERTIFICATE,
        request.subject.workflow_id + "-foreign",
        committed.certificate_digest,
        "1",
        "forged cross-workflow control event",
    )
    with store._transaction() as connection:
        store._revoke_on_connection(
            _OwnerLookupHidingConnection(connection),  # type: ignore[arg-type]
            forged,
        )
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)
    with pytest.raises(ValueError, match="semantic validation failed"):
        harness.reopen_store(path)


# --- apcc-stores-4: audit identities are unambiguous ------------------------------------------


@pytest.mark.parametrize(
    ("workflow_id", "target_id"),
    (("w\x00a", "b"), ("w", "a\x00b"), ("w/a", "b"), ("", "b"), ("w", "a b")),
)
def test_c32_revocation_request_rejects_non_plain_ids(workflow_id: str, target_id: str) -> None:
    with pytest.raises(ValueError):
        RevocationRequest(RevocationScope.ACTOR, workflow_id, target_id, "2", "r")


def test_c32_certificate_revocation_target_keeps_digest_grammar() -> None:
    digest = "-" + "A" * 42
    request = RevocationRequest(RevocationScope.CERTIFICATE, "workflow-1", digest, "1", "reason")
    assert request.target_id == digest
    with pytest.raises(ValueError):
        RevocationRequest(RevocationScope.CERTIFICATE, "w\x00", digest, "1", "r")


@pytest.mark.parametrize("field", ("workflow_id", "node_id", "attempt_id", "agent_id"))
def test_c32_context_and_stage_requests_reject_non_plain_ids(field: str) -> None:
    ids = {
        "workflow_id": "workflow-1",
        "node_id": "node-1",
        "attempt_id": "attempt-1",
        "agent_id": "agent-1",
    }
    ids[field] = "bad\x00id"
    with pytest.raises(ValueError):
        CommitContextRequest(**ids)
    request = _sqlite_harness().make_request(commit_id="plain-id", nonce_byte=76)
    with pytest.raises(ValueError):
        StageResultRequest(
            replace(request.subject, **{field: "bad/id"}),
            request.bindings.expected_node_version,
            b"output",
        )


def test_c32_audit_id_is_injective_over_nul_bearing_parts() -> None:
    first = sqlite_store_module._audit_id("revoke", "ACTOR", "w\x00a", "b", "2")
    second = sqlite_store_module._audit_id("revoke", "ACTOR", "w", "a\x00b", "2")
    assert first != second
    assert len(b64u_decode(first, expected_length=32)) == 32
    assert sqlite_store_module._audit_id(
        "outbox-delivered", "a", "b"
    ) != sqlite_store_module._audit_id("outbox-delivered", "a\x00b")


@pytest.mark.parametrize("kind", ("commit", "DENIED", "CONFLICTED", "conflict"))
def test_c32_decision_audit_ids_keep_observation_encoding(kind: str) -> None:
    # observation.py recomputes these ids independently (v1 encoding).
    parts = ("commit-1", "A" * 43)
    assert sqlite_store_module._audit_id(kind, *parts) == sha256_digest(
        (kind + "\x00" + "\x00".join(parts)).encode("utf-8")
    )


def test_c32_store_with_legacy_encoded_audit_id_fails_closed_on_reopen(
    tmp_path: Path,
) -> None:
    """A row carrying the pre-C32 NUL-joined stage audit id is refused on reopen.

    The schema version is unchanged (orchestrator: schema v4 deferred), so such
    stores fail closed via the generic semantic validator, not an explicit
    schema-incompatibility message.
    """
    harness = _sqlite_harness()
    path = tmp_path / "legacy-audit-encoding"
    store = harness.open_store(path, None)
    request = harness.make_request(commit_id="legacy-audit", nonce_byte=78)
    staged = store.stage_result(harness.stage_request(request))
    subject = request.subject
    legacy = sha256_digest(
        "\x00".join(
            (
                "stage",
                subject.workflow_id,
                subject.node_id,
                subject.attempt_id,
                subject.output_digest,
                request.bindings.expected_node_version,
            )
        ).encode("utf-8")
    )
    assert legacy != staged.audit_event_id
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE candidates SET audit_event_id=? WHERE audit_event_id=?",
            (legacy, staged.audit_event_id),
        )
        _reseal_test_checkpoint(connection)
    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: harness.reopen_store(path),
    ):
        with pytest.raises(ValueError, match="semantic validation failed"):
            opener()


# --- apcc-stores-7: one signer check; service bound to the store's config -------


def test_c32_service_rejects_config_that_differs_from_store(tmp_path: Path) -> None:
    store = _sqlite_harness().open_store(tmp_path / "service-config.db", None)
    assert isinstance(store, SQLiteAuthorityStore)
    foreign_config, runtime = _config_with_mutated_binding(TrustRole.PRODUCER, "key_id")
    assert foreign_config.authority_store_id == store.authority_store_id
    assert foreign_config != store.authority_config
    with pytest.raises(ValueError, match="does not match the store"):
        APCCCommitService(store=store, config=foreign_config, runtime=runtime)
    APCCCommitService(store=store, config=store.authority_config, runtime=_runtime())


def test_c32_runtime_signer_check_is_shared_and_fails_closed() -> None:
    def unavailable(role: object, key_id: object) -> bytes:
        raise KeyError(key_id)

    runtime = _runtime()
    broken = AuthorityRuntime(
        type("Unavailable", (), {"public_key": staticmethod(unavailable)})(),  # type: ignore[arg-type]
        runtime.clock,
        runtime.outbox_sink,
    )
    with pytest.raises(ValueError, match="runtime signer is unavailable"):
        validate_runtime_signers(_sqlite_config(), broken)
    validate_runtime_signers(_sqlite_config(), runtime)


def test_c32_sqlite_store_and_service_share_one_signer_check() -> None:
    # postgres_store.py keeps its own copy (frozen B2 bytes; follow-up).
    from constitutional_swarm.apcc import service as service_module

    assert sqlite_store_module.validate_runtime_signers is validate_runtime_signers
    assert service_module.validate_runtime_signers is validate_runtime_signers


# --- apcc-stores-6/8/9/10: dead code removed, identities computed once ----------


def test_c32_dead_helpers_are_removed() -> None:
    for name in (
        "_outbox_id",
        "_request_identity",
        "_validate_runtime_signers",
        "verify_causal_closure",
    ):
        assert not hasattr(sqlite_store_module, name), name
    assert not hasattr(sqlite_store_module._AuthorityStoreCore, "_persisted_causal_error")


def test_c32_semantic_validation_builds_scoped_trust_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _sqlite_harness()
    path = tmp_path / "trust-once"
    store = harness.open_store(path, None)
    request = harness.make_request(commit_id="trust-once", nonce_byte=80)
    _stage(store, harness, request)
    store.atomic_commit(request)
    calls = 0
    original = sqlite_store_module._trust

    def counting(config: object) -> object:
        nonlocal calls
        calls += 1
        return original(config)  # type: ignore[arg-type]

    monkeypatch.setattr(sqlite_store_module, "_trust", counting)
    with sqlite3.connect(path) as connection:
        sqlite_store_module._validate_semantic_integrity(connection, _sqlite_config())
    assert calls == 1


def test_c32_proposal_identity_is_request_json_digest() -> None:
    request = _sqlite_harness().make_request(commit_id="identity", nonce_byte=77)
    assert sqlite_store_module._proposal_identity(request) == sha256_digest(
        sqlite_store_module._authority_request_json(request).encode("utf-8")
    )
