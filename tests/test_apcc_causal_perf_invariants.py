"""Regression tests for APCC codec, verifier, and SQLite causal optimizations."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from constitutional_swarm.apcc import sqlite_store as sqlite_store_module, verifier
from constitutional_swarm.apcc.codec import (
    CodecError,
    _B64U_ALPHABET,
    _decode_b64u,
    _parse,
    _scan_depth,
    decode_authority_status,
)
from constitutional_swarm.apcc.model import AuthorityStatusValue, FailureCode, RequestOutcome
from constitutional_swarm.apcc.observation import AuthorityObservationRequest
from constitutional_swarm.apcc.ports import (
    RevocationRequest,
    RevocationScope,
    StatusFreshnessPolicy,
)
from constitutional_swarm.apcc.sqlite_store import (
    _VerifiedEnvelopeCache,
    _VerifiedEnvelopeEntry,
    _operation_identity,
    _public_request_digest,
)
from constitutional_swarm.apcc.verifier import (
    CausalClosureLimits,
    ScopedTrust,
    verify_causal_closure,
    verify_historical,
)
from tests import test_apcc_observation as obs_fixture
from tests import test_apcc_sqlite as sql_fixture
from tests.test_apcc_verifier import (
    _Resolver,
    _canonical,
    _digest,
    _leaf_for_parent,
    _parent_vector,
    valid_vector,
)


def test_decode_b64u_exhaustive_trailing_bits_and_rejections() -> None:
    def reference(value: str, length: int | None = None) -> bytes:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if canonical != value or (length is not None and len(raw) != length):
            raise ValueError("noncanonical")
        return raw

    assert _decode_b64u("") == b""
    assert _decode_b64u("", 0) == b""
    with pytest.raises(CodecError) as exc:
        _decode_b64u("", 1)
    assert exc.value.code is FailureCode.INVALID_BASE64URL

    for ch in _B64U_ALPHABET:
        # Remainder 1 is always invalid.
        with pytest.raises(CodecError) as exc:
            _decode_b64u(ch)
        assert exc.value.code is FailureCode.INVALID_BASE64URL

        # Remainder 2: second character has 4 unused trailing bits.
        s2 = "A" + ch
        try:
            expected = reference(s2)
        except ValueError:
            with pytest.raises(CodecError) as exc:
                _decode_b64u(s2)
            assert exc.value.code is FailureCode.INVALID_BASE64URL
        else:
            assert _decode_b64u(s2) == expected
            assert _decode_b64u(s2, 1) == expected
            with pytest.raises(CodecError):
                _decode_b64u(s2, 2)

        # Remainder 3: third character has 2 unused trailing bits.
        s3 = "AA" + ch
        try:
            expected = reference(s3)
        except ValueError:
            with pytest.raises(CodecError) as exc:
                _decode_b64u(s3)
            assert exc.value.code is FailureCode.INVALID_BASE64URL
        else:
            assert _decode_b64u(s3) == expected
            assert _decode_b64u(s3, 2) == expected

    for bad in ("AAAA=", "AAA+", "AAA/", "AAAA\n", "AA A", "éééé"):
        with pytest.raises(CodecError) as exc:
            _decode_b64u(bad)
        assert exc.value.code is FailureCode.INVALID_BASE64URL


def test_scan_depth_and_unicode_escape_equivalence() -> None:
    _scan_depth('{"a":"\\\\","b":"\\\\\\"[[[[[[[[[[","c":["x"]}')
    _scan_depth('{"a":[' * 4 + '""' + "]}" * 4)
    _scan_depth('"[[[[[[[[[[[[')  # Unclosed string ignored by scanner, fails in raw_decode.

    with pytest.raises(CodecError) as exc:
        _scan_depth("[" * 9)
    assert exc.value.code is FailureCode.DEPTH_LIMIT_EXCEEDED

    with pytest.raises(CodecError) as exc:
        _parse(b"[" * 2000)
    assert exc.value.code is FailureCode.DEPTH_LIMIT_EXCEEDED

    # Pure ASCII JSON with \uXXXX escapes must still enforce UTF-8 & NFC validation.
    assert _parse(b'{"a":"\\u00e9"}') == {"a": "é"}
    for bad in (b'{"a":"e\\u0301"}', b'{"a":"\\ud800"}'):
        with pytest.raises(CodecError) as exc:
            _parse(bad)
        assert exc.value.code is FailureCode.INVALID_UNICODE


def _build_chain(
    store: sqlite_store_module.SQLiteAuthorityStore,
    length: int,
    *,
    prefix: str = "chain",
    agent_revocation_generation: str = "3",
    workflow_revocation_generation: str = "4",
) -> list[tuple[sqlite_store_module.AtomicCommitRequest, sqlite_store_module.CommitResult]]:
    chain: list[tuple[sqlite_store_module.AtomicCommitRequest, sqlite_store_module.CommitResult]] = []
    predecessor: dict[str, str] | None = None
    for index in range(length):
        request = sql_fixture._request(
            commit_id=f"{prefix}-{index}",
            nonce_byte=index + 1,
            node_id=f"depth-node-{index}",
            attempt_id=f"{prefix}-attempt-{index}",
            predecessors=[] if predecessor is None else [predecessor],
            agent_revocation_generation=agent_revocation_generation,
            workflow_revocation_generation=workflow_revocation_generation,
        )
        sql_fixture._advance_candidate(store, request)
        result = store.atomic_commit(request)
        assert result.decision.outcome is RequestOutcome.COMMITTED
        assert result.certificate_digest is not None
        chain.append((request, result))
        predecessor = sql_fixture._predecessor(request, result)
    return chain


def _clone_db(src: Path, dst: Path) -> None:
    with sqlite3.connect(src) as source, sqlite3.connect(dst) as target:
        source.backup(target)


@pytest.mark.parametrize(
    "tamper_mode",
    (
        "tamper_payload",
        "tamper_envelope",
        "tamper_edges_missing",
        "tamper_edges_cycle",
        "revoke_cert",
        "revoke_actor_gen",
        "revoke_workflow_gen",
    ),
)
def test_deep_chain_tamper_and_revocation_fail_closed_under_warm_cache(
    tmp_path: Path, tamper_mode: str
) -> None:
    base_path = tmp_path / "base.db"
    base_store = sql_fixture._open_store(base_path, None)
    chain = _build_chain(
        base_store,
        31,
        prefix="deep",
        agent_revocation_generation="2" if tamper_mode == "revoke_actor_gen" else "3",
        workflow_revocation_generation="3" if tamper_mode == "revoke_workflow_gen" else "4",
    )
    root_req, root_res = chain[0]
    mid_req, mid_res = chain[15]
    tip_req, tip_res = chain[-1]
    assert root_res.certificate_digest and mid_res.certificate_digest and tip_res.certificate_digest

    # Keep a live store with warm _verified_envelopes for deep commits too.
    if tamper_mode == "revoke_cert":
        base_store.revoke(
            RevocationRequest(
                RevocationScope.CERTIFICATE,
                "workflow-1",
                root_res.certificate_digest,
                "1",
                "root revoked",
            )
        )
    elif tamper_mode == "revoke_actor_gen":
        base_store.revoke(
            RevocationRequest(
                RevocationScope.ACTOR,
                "workflow-1",
                root_req.subject.agent_id,
                "3",
                "actor revoked",
            )
        )
    elif tamper_mode == "revoke_workflow_gen":
        base_store.revoke(
            RevocationRequest(
                RevocationScope.WORKFLOW,
                "workflow-1",
                "workflow-1",
                "4",
                "workflow revoked",
            )
        )
    else:
        with sqlite3.connect(base_path) as connection:
            if tamper_mode == "tamper_payload":
                payload = bytes(
                    connection.execute(
                        "SELECT certificate_json FROM certificates WHERE certificate_digest=?",
                        (root_res.certificate_digest,),
                    ).fetchone()[0]
                )
                cert = sqlite_store_module.decode_certificate(payload)
                tampered = replace(cert, context=replace(cert.context, policy_version="999"))
                connection.execute(
                    "UPDATE certificates SET certificate_json=? WHERE certificate_digest=?",
                    (sqlite_store_module.encode_certificate(tampered), root_res.certificate_digest),
                )
            elif tamper_mode == "tamper_envelope":
                envelope = bytearray(
                    bytes(
                        connection.execute(
                            "SELECT envelope FROM certificates WHERE certificate_digest=?",
                            (mid_res.certificate_digest,),
                        ).fetchone()[0]
                    )
                )
                envelope[10] ^= 0x01
                connection.execute(
                    "UPDATE certificates SET envelope=? WHERE certificate_digest=?",
                    (bytes(envelope), mid_res.certificate_digest),
                )
            elif tamper_mode == "tamper_edges_missing":
                connection.execute(
                    "DELETE FROM predecessor_edges WHERE child_commit_id=?",
                    (chain[10][0].commit_id,),
                )
            elif tamper_mode == "tamper_edges_cycle":
                connection.execute(
                    "INSERT INTO predecessor_edges(child_commit_id, predecessor_digest) VALUES (?, ?)",
                    (root_req.commit_id, mid_res.certificate_digest),
                )
            sql_fixture._reseal_test_checkpoint(connection)
            connection.commit()

    assert base_store._verified_envelopes.info().entries >= 31

    leaf_req = sql_fixture._request(
        commit_id="deep-leaf-after-tamper",
        nonce_byte=120,
        node_id="depth-node-31",
        attempt_id="deep-attempt-31",
        predecessors=[sql_fixture._predecessor(tip_req, tip_res)],
        agent_revocation_generation="4" if tamper_mode == "revoke_actor_gen" else "3",
        workflow_revocation_generation="5" if tamper_mode == "revoke_workflow_gen" else "4",
    )
    sql_fixture._advance_candidate(base_store, leaf_req)
    denied = base_store.atomic_commit(leaf_req)
    assert denied.decision.outcome is RequestOutcome.DENIED
    assert denied.decision.reason is FailureCode.INVALID_PREDECESSOR
    assert denied.certificate_digest is None

    if tamper_mode.startswith("revoke_"):
        status = base_store.current_status(tip_res.certificate_digest, sql_fixture._nonce(201))
        assert status.status is AuthorityStatusValue.REVOKED
        observer = obs_fixture._open_observer(base_path)
        target = AuthorityObservationRequest(
            protocol_version="APCC-1.0-draft",
            statement_type="apcc.authority-observation-request",
            authority_store_id="store-1",
            workflow_id=tip_req.subject.workflow_id,
            node_id=tip_req.subject.node_id,
            attempt_id=tip_req.subject.attempt_id,
            expected_commit_id=tip_req.commit_id,
            expected_operation_digest=_operation_identity(tip_req, None),
            public_request_digest=_public_request_digest(tip_req),
            request_nonce=sql_fixture._nonce(202),
        )
        observed = observer.observe_authority(target)
        assert observed.current_status_evidence is not None
        assert decode_authority_status(observed.current_status_evidence).status == "revoked"
        assert observed._legacy_visibility_hint is False


def test_deep_chain_depth_64_boundary_and_limits_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "depth64.db"
    store = sql_fixture._open_store(path, None)
    chain = _build_chain(store, 65, prefix="max")
    tip_req, tip_res = chain[-1]

    # Copy DB before tampering limits for clean checks.
    sub_path = tmp_path / "limits.db"
    _clone_db(path, sub_path)
    sub_store = sql_fixture._reopen_store(sub_path)

    # Default max_depth=64 rejects depth 65.
    beyond_req = sql_fixture._request(
        commit_id="beyond-64",
        nonce_byte=200,
        node_id="depth-node-65",
        attempt_id="max-attempt-65",
        predecessors=[sql_fixture._predecessor(tip_req, tip_res)],
    )
    sql_fixture._advance_candidate(store, beyond_req)
    denied = store.atomic_commit(beyond_req)
    assert denied.decision.outcome is RequestOutcome.DENIED
    assert denied.decision.reason is FailureCode.DEPTH_LIMIT_EXCEEDED

    # Constrained CausalClosureLimits are still honored precisely.
    sub_res_cert = chain[30][1].certificate_envelope_bytes
    assert sub_res_cert is not None
    for limits, expected_code in (
        (CausalClosureLimits(max_depth=10), FailureCode.DEPTH_LIMIT_EXCEEDED),
        (CausalClosureLimits(max_certificates=10), FailureCode.SIZE_LIMIT_EXCEEDED),
        (CausalClosureLimits(max_total_bytes=20_000), FailureCode.SIZE_LIMIT_EXCEEDED),
    ):
        with monkeypatch.context() as patch:
            patch.setattr(sqlite_store_module, "CausalClosureLimits", lambda _l=limits: _l)
            with sub_store._read_transaction() as conn:
                cert = sqlite_store_module.decode_certificate(
                    sqlite_store_module.decode_envelope(sub_res_cert).payload
                )
                assert sub_store._request_causal_error(conn, cert) is expected_code


def test_verified_envelope_cache_bounds_failure_isolation_and_trust_swap(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _VerifiedEnvelopeCache(max_entries=0, max_envelope_bytes=100)
    with pytest.raises(ValueError):
        _VerifiedEnvelopeCache(max_entries=1, max_envelope_bytes=0)

    vector = valid_vector()
    entry = _VerifiedEnvelopeEntry(b"p", "d", vector.envelope and sqlite_store_module.decode_envelope(vector.envelope) and verify_historical(vector.envelope, trust=vector.trust).certificate)  # type: ignore[arg-type]
    cache = _VerifiedEnvelopeCache(max_entries=2, max_envelope_bytes=20)
    cache.put(b"a" * 21, entry)  # Oversize not retained.
    assert cache.info().entries == 0
    cache.put(b"a" * 10, entry)
    cache.put(b"b" * 10, entry)
    assert cache.get(b"a" * 10) is entry  # Touch 'a' -> 'b' is LRU.
    cache.put(b"c" * 10, entry)  # Evicts 'b'.
    assert cache.get(b"b" * 10) is None
    assert cache.get(b"a" * 10) is entry
    assert cache.get(b"c" * 10) is entry
    assert cache.info().entries == 2 and cache.info().envelope_bytes == 20

    # Corrupt envelopes never enter cache; swapping _scoped_trust bypasses store cache.
    path = tmp_path / "cache-trust.db"
    store = sql_fixture._open_store(path, None)
    chain = _build_chain(store, 2, prefix="ct")
    env0 = chain[0][1].certificate_envelope_bytes
    assert env0 is not None
    assert store._verify_stored_envelope(b"corrupt") is None
    assert store._verify_stored_envelope(env0) is not None
    entries_before = store._verified_envelopes.info().entries
    corrupt = bytearray(env0)
    corrupt[15] ^= 0x01
    assert store._verify_stored_envelope(bytes(corrupt)) is None
    assert store._verified_envelopes.info().entries == entries_before

    # Replace trust on store with mismatched key -> cached entry must NOT authorize!
    alt_cfg = replace(
        store._config,
        freshness=StatusFreshnessPolicy("60000", "60000"),
    )
    empty_trust = ScopedTrust(
        tuple(
            b for b in store._config.trust_bindings if b.role is not verifier.TrustRole.COMMIT
        )
        + (
            verifier.TrustBinding(
                verifier.TrustRole.COMMIT,
                (alt_cfg.authority_store_id,),
                "other-commit-key",
                sql_fixture._public_key(b"\x99" * 32),
            ),
        )
    )
    store._scoped_trust = empty_trust
    assert store._verify_stored_envelope(env0) is None


def test_external_verifier_remains_uncached(monkeypatch: pytest.MonkeyPatch) -> None:
    vector = valid_vector()
    decodes = 0
    original = verifier._decode_envelope_certificate

    def counting(raw: bytes):
        nonlocal decodes
        decodes += 1
        return original(raw)

    monkeypatch.setattr(verifier, "_decode_envelope_certificate", counting)
    assert verify_historical(vector.envelope, trust=vector.trust).ok
    assert verify_historical(vector.envelope, trust=vector.trust).ok
    assert decodes == 2

    decodes = 0
    parent = _parent_vector()
    leaf = _leaf_for_parent(parent)
    parent_digest = _digest(_canonical(parent.payload))
    resolver = _Resolver({parent_digest: parent.envelope})
    assert verify_causal_closure(leaf.envelope, trust=leaf.trust, resolver=resolver).ok
    assert verify_causal_closure(leaf.envelope, trust=leaf.trust, resolver=resolver).ok
    assert decodes == 4
