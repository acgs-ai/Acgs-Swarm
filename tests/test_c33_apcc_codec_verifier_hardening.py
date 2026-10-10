"""C33 regression tests: APCC codec, verifier and observation hardening."""

from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc import codec, crypto, observation, sqlite_store, verifier
from constitutional_swarm.apcc.codec import (
    canonical_predecessors,
    canonical_statement,
    decode_envelope,
    encode_authority_status,
    encode_authority_status_body,
    encode_certificate,
    encode_envelope,
    encode_payload,
    normalize_authority_status,
)
from constitutional_swarm.apcc.gcb_projection import (
    _GCBProjectionDenied,
    _validate_gcb_projection,
)
from constitutional_swarm.apcc.model import FailureCode, LogicalNodeState
from constitutional_swarm.apcc.observation import (
    AuthorityObservationSnapshot,
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    _nullable_outbox_record,
    _operation_object,
    decode_authority_observation_request,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    verify_authority_observation,
)
from constitutional_swarm.apcc.verifier import (
    CausalClosureLimits,
    ScopedTrust,
    verify_causal_closure,
    verify_current,
)
from tests.test_apcc_model import _certificate
from tests.test_apcc_observation import (
    _advance_candidate,
    _config,
    _launch_expectations,
    _launch_for_observer_key,
    _open_observer,
    _open_store,
    _request,
    _sign_snapshot,
    _target_for,
    commit_request,
)
from tests.test_apcc_verifier import (
    _canonical,
    _child_for_parents,
    _current,
    _digest,
    _leaf_for_parent,
    _parent_vector,
    _Resolver,
    valid_vector,
)

# ---------------------------------------------------------------------------
# Golden bytes: recorded on the pre-C33 base. The canonical encoder output must
# remain byte-identical across the refactor.
# ---------------------------------------------------------------------------

_GOLDEN = {
    "certificate": (3717, "20e1ca2a58271b2a3e312e65e09c960aa13dae42927210ce3ab94901c6a415ca"),
    "envelope": (5250, "76976ac644b933a5974d86da6f450babc46b558f52aabd8ebad7e5e38040476c"),
    "status": (710, "2fa6ed3e4338bbaa84a101c3b5c75632b560141b5051c43f61d957660348fe22"),
    "status_body": (537, "c569a253c2b4e528183d47cf3489686520923345b91508c71cc19d6b615686f5"),
    "payload": (30, "cb605a9630ca68bb71baa2ab90414f36e652ae48d1cc0fb937d4f3561163936b"),
    "statement": (581, "dcfe6f331b2f626a9eb0ff8dbcfcad714ba6e6c38670c79ae0863fe086eb491f"),
    "predecessors": (230, "cada3fceda16332dcaedce5fee92022c960eb06569a1e801c1414cc9c07b7279"),
}


def test_codec_canonical_encoder_output_is_byte_identical_to_golden() -> None:
    vector = valid_vector()
    status = normalize_authority_status(vector.status)
    detached = decode_envelope(vector.envelope)
    encoded = {
        "certificate": encode_certificate(_certificate()),
        "envelope": encode_envelope(
            detached.payload,
            seal_key_id=detached.seal.key_id,
            seal_signature_b64u=detached.seal.signature_b64u,
        ),
        "status": encode_authority_status(status),
        "status_body": encode_authority_status_body(status),
        "payload": encode_payload({"b": ["é", {"a": "x"}], "a": "z"}),
        "statement": canonical_statement(vector.payload["evidence"]["producer_statement"]),
        "predecessors": canonical_predecessors(vector.payload["bindings"]["predecessors"]),
    }
    assert encoded["envelope"] == vector.envelope
    for name, raw in encoded.items():
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == _GOLDEN[name], name


# ---------------------------------------------------------------------------
# apcc-core-1: deep nesting must fail as ValueError, never RecursionError.
# ---------------------------------------------------------------------------


def _deep(levels: int) -> bytes:
    return b"[" * levels + b"]" * levels


@pytest.mark.parametrize(
    "decode",
    (
        lambda: decode_signed_authority_observation(_deep(200_000)),
        lambda: decode_authority_observation_request(_deep(2_000)),
        lambda: decode_observer_launch_attestation(_deep(4_000)),
        lambda: _nullable_outbox_record(_deep(4_000)),
        lambda: _operation_object(_deep(200_000)),
    ),
    ids=("signed-observation", "request", "launch", "outbox", "operation"),
)
def test_observation_decoders_reject_deep_nesting_as_value_error(decode) -> None:
    with pytest.raises(ValueError):
        decode()


# ---------------------------------------------------------------------------
# apcc-core-2 (P1): the expected request comes from the caller, never the
# verified observation.
# ---------------------------------------------------------------------------


def _keys() -> tuple[Ed25519PrivateKey, bytes, Ed25519PrivateKey, bytes]:
    observer = Ed25519PrivateKey.generate()
    controller = Ed25519PrivateKey.generate()
    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (
        observer,
        observer.public_key().public_bytes(*raw),
        controller,
        controller.public_key().public_bytes(*raw),
    )


def _absent_snapshot(request) -> AuthorityObservationSnapshot:
    return AuthorityObservationSnapshot(
        request,
        AuthorityObservationState.ABSENT,
        None,
        None,
        None,
        None,
        None,
        LogicalNodeState(request.workflow_id, request.node_id, "0", None),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )


def _verify_kwargs(launch, controller_public: bytes) -> dict[str, object]:
    return {
        "launch": launch,
        "pinned_controller_public_key": controller_public,
        "expected_experiment_id": launch.experiment_id,
        "expected_run_id": launch.run_id,
        "expected_launch": _launch_expectations(launch),
        "trust": ScopedTrust(_config().trust_bindings),
        "now_ms": int(time.time() * 1000),
        "maximum_staleness_ms": 5000,
    }


def test_offline_observation_verifier_rejects_validly_signed_other_request() -> None:
    observer, observer_public, controller, controller_public = _keys()
    launch = _launch_for_observer_key(observer_public, controller)
    pinned = _request()
    other = replace(pinned, expected_commit_id="commit-other")
    signed, _ = _sign_snapshot(
        _absent_snapshot(other), observer, launch_digest=launch.canonical_digest
    )
    kwargs = _verify_kwargs(launch, controller_public)
    with pytest.raises(ValueError, match="request"):
        verify_authority_observation(
            signed,
            expected_request=pinned,
            **kwargs,
            highest_trust_log_sequence=launch.initial_trust_sequence,
            highest_trust_log_head=launch.initial_trust_head,
        )
    # The same signed observation verifies against its own request, and the
    # result is tied to the caller's request identity.
    result = verify_authority_observation(
        signed,
        expected_request=other,
        **kwargs,
        highest_trust_log_sequence=launch.initial_trust_sequence,
        highest_trust_log_head=launch.initial_trust_head,
    )
    assert result.state == "ABSENT"
    assert result.request_digest == other.canonical_digest


def test_offline_observation_verifier_requires_expected_request() -> None:
    observer, observer_public, controller, controller_public = _keys()
    launch = _launch_for_observer_key(observer_public, controller)
    signed, _ = _sign_snapshot(
        _absent_snapshot(_request()), observer, launch_digest=launch.canonical_digest
    )
    with pytest.raises(TypeError):
        verify_authority_observation(  # type: ignore[call-arg]
            signed,
            **_verify_kwargs(launch, controller_public),
            highest_trust_log_sequence=launch.initial_trust_sequence,
            highest_trust_log_head=launch.initial_trust_head,
        )


def test_observation_stream_rejects_other_request_without_advancing() -> None:
    observer, observer_public, controller, controller_public = _keys()
    launch = _launch_for_observer_key(observer_public, controller)
    pinned = _request()
    other = replace(pinned, node_id="node-other")
    signed, _ = _sign_snapshot(
        _absent_snapshot(other), observer, launch_digest=launch.canonical_digest
    )
    stream = AuthorityObservationVerificationStream(launch.session_id)
    with pytest.raises(ValueError, match="request"):
        stream.consume(signed, expected_request=pinned, **_verify_kwargs(launch, controller_public))
    assert stream.next_sequence == 1
    assert stream.launch_attestation_digest == ""


# ---------------------------------------------------------------------------
# apcc-core-3: GCB receipt/verdict material must not accept float/bool aliases
# of integer fields.
# ---------------------------------------------------------------------------


@pytest.fixture
def gcb_projection_inputs(tmp_path, monkeypatch):
    from tests.test_governed_commit import _configured_boundary, _request as gcb_request

    captured: list[tuple[object, ...]] = []
    original = sqlite_store._validate_gcb_projection

    def spy(config, request, plan, facts):
        captured.append((config, request, plan, facts))
        return original(config, request, plan, facts)

    monkeypatch.setattr(sqlite_store, "_validate_gcb_projection", spy)
    boundary, private_key, _ = _configured_boundary(tmp_path)
    boundary.commit(gcb_request(boundary, private_key))
    assert captured
    return captured[0]


def _swap(material: str, old: str, new: str) -> str:
    assert material.count(old) == 1, old
    return material.replace(old, new)


def test_gcb_projection_inputs_validate_unchanged(gcb_projection_inputs) -> None:
    config, request, plan, facts = gcb_projection_inputs
    _validate_gcb_projection(config, request, plan, facts)


def test_gcb_verdict_rejects_boolean_alias_of_integer_field(
    gcb_projection_inputs,
) -> None:
    config, request, plan, facts = gcb_projection_inputs
    forged = replace(
        plan,
        verdict_material=_swap(plan.verdict_material, '"policy_epoch":1', '"policy_epoch":true'),
    )
    with pytest.raises(_GCBProjectionDenied) as error:
        _validate_gcb_projection(config, request, forged, facts)
    assert error.value.reason == "projection_verdict_mismatch"


def test_gcb_receipt_rejects_boolean_alias_of_integer_field(
    gcb_projection_inputs,
) -> None:
    config, request, plan, facts = gcb_projection_inputs
    forged = replace(
        plan,
        receipt_material=_swap(
            plan.receipt_material, '"authority_epoch":1', '"authority_epoch":true'
        ),
    )
    with pytest.raises(_GCBProjectionDenied) as error:
        _validate_gcb_projection(config, request, forged, facts)
    assert error.value.reason == "projection_receipt_mismatch"


def test_gcb_material_rejects_float_alias_of_integer_field(
    gcb_projection_inputs,
) -> None:
    config, request, plan, facts = gcb_projection_inputs
    forged = replace(
        plan,
        receipt_material=_swap(
            plan.receipt_material, '"authority_epoch":1', '"authority_epoch":1.0'
        ),
    )
    with pytest.raises(_GCBProjectionDenied) as error:
        _validate_gcb_projection(config, request, forged, facts)
    assert error.value.reason == "invalid_receipt_material"


@pytest.mark.parametrize(
    "raw",
    ('{"a":1.0}', '{"a":1e3}', '{"a":NaN}', '{"a":"x","a":"y"}', "[" * 5000 + "]" * 5000),
)
def test_gcb_material_parser_fails_closed_with_projection_denial(raw: str) -> None:
    from constitutional_swarm.apcc.gcb_projection import _gcb_material_object

    with pytest.raises(_GCBProjectionDenied) as error:
        _gcb_material_object(raw, label="receipt")
    assert error.value.reason == "invalid_receipt_material"


# ---------------------------------------------------------------------------
# apcc-core-9: caller-supplied causal depth is bounded.
# ---------------------------------------------------------------------------


def test_causal_closure_rejects_depth_limit_above_recursion_safe_cap() -> None:
    vector = valid_vector()
    verdict = verify_causal_closure(
        vector.envelope,
        trust=vector.trust,
        resolver=_Resolver({}),
        limits=CausalClosureLimits(max_depth=513),
    )
    assert verdict.code is FailureCode.SIZE_LIMIT_EXCEEDED


def test_causal_closure_accepts_depth_limit_at_cap() -> None:
    parent = _parent_vector()
    leaf = _leaf_for_parent(parent)
    verdict = verify_causal_closure(
        leaf.envelope,
        trust=leaf.trust,
        resolver=_Resolver({_digest(_canonical(parent.payload)): parent.envelope}),
        limits=CausalClosureLimits(max_depth=512),
    )
    assert verdict.ok


# ---------------------------------------------------------------------------
# apcc-opt-1/2/3: each envelope and certificate is decoded and each signature
# verified once per verification.
# ---------------------------------------------------------------------------


def _count(monkeypatch, module, name: str) -> list[int]:
    calls = [0]
    original = getattr(module, name)

    def counting(*args, **kwargs):
        calls[0] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, counting)
    return calls


def test_causal_closure_parses_each_certificate_and_envelope_once(monkeypatch) -> None:
    grandparent = _parent_vector()
    parent = _leaf_for_parent(grandparent)
    leaf = _child_for_parents(
        (parent,),
        node_id="node-2",
        attempt_id="attempt-2",
        commit_id="commit-2",
        expected_version="8",
        output_digest=_digest(b"output-2"),
    )
    resolver = _Resolver(
        {
            _digest(_canonical(parent.payload)): parent.envelope,
            _digest(_canonical(grandparent.payload)): grandparent.envelope,
        }
    )
    parses = _count(monkeypatch, codec, "_parse")
    verdict = verify_causal_closure(leaf.envelope, trust=leaf.trust, resolver=resolver)
    assert verdict.ok
    # One envelope parse plus one certificate parse for each of three certificates.
    assert parses[0] == 6
    assert verdict.certificate_digest == _digest(_canonical(leaf.payload))


def test_current_verifier_does_not_reencode_certificate(monkeypatch) -> None:
    vector = valid_vector()
    encodes = _count(monkeypatch, codec, "encode_certificate")
    verdict = _current(vector)
    assert verdict.ok
    assert encodes[0] == 0


def test_current_verifier_still_rejects_status_for_other_certificate() -> None:
    vector = valid_vector()
    status = dict(vector.status)
    body = dict(status["body"])
    body["certificate_digest"] = _digest(b"other-certificate")
    from tests.test_apcc_verifier import DOMAINS, SEEDS, _signature

    status = {
        "body": body,
        "signature": _signature(SEEDS["status"], DOMAINS["status"], _canonical(body), "status-key"),
    }
    verdict = verify_current(
        vector.envelope,
        trust=vector.trust,
        authority_status=status,
        request_nonce=body["request_nonce"],
        now_ms="1760000001000",
        highest_trust_log_sequence="42",
        highest_trust_log_head=body["trust_log_head"],
        maximum_staleness_ms="5000",
    )
    assert verdict.code is FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH


def test_committed_observation_verifies_certificate_signatures_once(tmp_path, monkeypatch) -> None:
    path = tmp_path / "c33-commit.db"
    store = _open_store(path, None)
    request = commit_request(commit_id="c33-once", nonce_byte=233)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    target = _target_for(request)
    snapshot = _open_observer(path).observe_authority(target)
    observer, observer_public, controller, controller_public = _keys()
    launch = _launch_for_observer_key(observer_public, controller)
    signed, _ = _sign_snapshot(snapshot, observer, launch_digest=launch.canonical_digest)
    signatures = _count(monkeypatch, verifier, "verify_detached")
    result = verify_authority_observation(
        signed,
        expected_request=target,
        **_verify_kwargs(launch, controller_public),
        highest_trust_log_sequence=launch.initial_trust_sequence,
        highest_trust_log_head=launch.initial_trust_head,
    )
    assert result.state == "COMMITTED"
    assert result.consumable is True
    assert result.request_digest == target.canonical_digest
    # Commit seal + three evidence signatures + one status signature.
    assert signatures[0] == 5


# ---------------------------------------------------------------------------
# apcc-opt-5/6/7: single sources of truth.
# ---------------------------------------------------------------------------


def test_observation_reuses_codec_identifier_and_decimal_grammar() -> None:
    assert observation._IDENTIFIER is codec._IDENTIFIER
    assert observation._DECIMAL is codec._DECIMAL


def test_b6_signature_domains_are_registered_apcc_domains() -> None:
    for domain in (
        observation.AUTHORITY_OBSERVATION_DOMAIN,
        observation.CONTROLLER_LAUNCH_DOMAIN,
    ):
        assert domain in crypto._DOMAINS
        assert crypto.domain_preimage(domain, b"body") == domain + b"\x00body"
    assert observation.AUTHORITY_OBSERVATION_DOMAIN is crypto.AUTHORITY_OBSERVATION_DOMAIN
    assert observation.CONTROLLER_LAUNCH_DOMAIN is crypto.CONTROLLER_LAUNCH_DOMAIN


def test_observer_launch_rejects_signature_under_another_registered_domain() -> None:
    _, observer_public, controller, controller_public = _keys()
    launch = _launch_for_observer_key(observer_public, controller)
    forged_signature = crypto.b64u_encode(
        controller.sign(
            crypto.domain_preimage(
                crypto.AUTHORITY_OBSERVATION_DOMAIN,
                encode_payload(launch.unsigned_object()),
            )
        )
    )
    forged = replace(launch, controller_signature=forged_signature)
    with pytest.raises(ValueError, match="signature"):
        forged.verify(
            pinned_controller_public_key=controller_public,
            expected=_launch_expectations(forged),
            now_ms=int(time.time() * 1000),
        )


@pytest.mark.parametrize(
    "name",
    (
        "validate_authority_observation_request",
        "encode_authority_observation_request",
        "decode_authority_observation_request",
        "encode_observer_launch_attestation",
        "decode_observer_launch_attestation",
    ),
)
def test_codec_has_no_observation_compatibility_delegates(name: str) -> None:
    assert not hasattr(codec, name)
    assert callable(getattr(observation, name, None)) or name.startswith("validate_")
