"""Strict, independent renewal wire object regressions (not qualification)."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import encode_payload
from constitutional_swarm.apcc.crypto import b64u_encode
from constitutional_swarm.apcc_empirical import w2_renewal_protocol as p


def fixtures():
    commit = Ed25519PrivateKey.generate()
    renewal = Ed25519PrivateKey.generate()
    body = dict.fromkeys(p.DELEGATION_FIELDS, "scope")
    for field in p.DELEGATION_FIELDS:
        if field.endswith("_digest"):
            body[field] = b64u_encode(bytes(32))
    body.update(
        protocol=p.DELEGATION_DOMAIN.decode(),
        role="observer-renewal-v1",
        renewal_key_id="renewal",
        renewal_public_key=b64u_encode(renewal.public_key().public_bytes_raw()),
        not_before_ms="100",
        not_after_ms="1100",
        nonce=b64u_encode(bytes(16)),
    )
    return commit, renewal, body


def test_roundtrip_and_external_hex():
    commit, _, body = fixtures()
    raw = p.sign_delegation(body, "commit", commit)
    binding = p.SignerBinding("commit", commit.public_key().public_bytes_raw())
    assert (
        p.verify_delegation(raw, binding, body, forbidden_public_keys=(), now_ms=100)
        == body
    )
    assert p.signed_digest(raw) == b64u_encode(hashlib.sha256(raw).digest())
    assert p.plan_digest_from_hex("00" * 32) == b64u_encode(bytes(32))


@pytest.mark.parametrize(
    "field,value",
    [
        ("nonce", "AA"),
        ("plan_digest", "00" * 32),
        ("not_after_ms", "01"),
        ("not_after_ms", str(2**53)),
        ("not_after_ms", "-1"),
        ("not_after_ms", None),
        ("not_after_ms", 1.5),
        ("role", "commit"),
        ("extra", "x"),
    ],
)
def test_bad_body(field, value):
    commit, _, body = fixtures()
    body[field] = value
    with pytest.raises(ValueError):
        p.sign_delegation(body, "commit", commit)


@pytest.mark.parametrize("suffix", [b" ", b"\n", b"{}"])
def test_trailing(suffix):
    commit, _, body = fixtures()
    with pytest.raises(ValueError):
        p.decode_delegation(p.sign_delegation(body, "commit", commit) + suffix)


def test_duplicate_unknown_and_signature_substitution():
    commit, renewal, body = fixtures()
    raw = p.sign_delegation(body, "commit", commit)
    binding = p.SignerBinding("commit", commit.public_key().public_bytes_raw())
    with pytest.raises(ValueError):
        p.decode_delegation(
            raw.replace(b'"key_id":"commit"', b'"key_id":"commit","key_id":"commit"')
        )
    for wrong in [
        p.SignerBinding("other", binding.public_key),
        p.SignerBinding("commit", renewal.public_key().public_bytes_raw()),
    ]:
        with pytest.raises(ValueError):
            p.verify_delegation(raw, wrong, body, forbidden_public_keys=(), now_ms=100)
    with pytest.raises(ValueError):
        p.verify_delegation(
            raw,
            binding,
            body,
            forbidden_public_keys=(renewal.public_key().public_bytes_raw(),),
            now_ms=100,
        )
    for now in [99, 1101]:
        with pytest.raises(ValueError):
            p.verify_delegation(
                raw, binding, body, forbidden_public_keys=(), now_ms=now
            )
    with pytest.raises(ValueError):
        p.verify_delegation(
            raw,
            binding,
            {**body, "repetition_id": "other"},
            forbidden_public_keys=(),
            now_ms=100,
        )
    parsed = p.decode_delegation(raw)
    parsed["algorithm"] = "Ed25519"
    with pytest.raises(ValueError):
        p.decode_delegation(encode_payload(parsed))


def continuity_fixture():
    commit, renewal, delegation = fixtures()
    delegated = p.sign_delegation(delegation, "commit", commit)
    body = dict.fromkeys(p.CONTINUITY_FIELDS, "scope")
    for field in p.CONTINUITY_FIELDS:
        if field.endswith("_digest") or field == "trust_log_head":
            body[field] = b64u_encode(bytes(32))
    body.update(
        protocol=p.CONTINUITY_DOMAIN.decode(),
        delegation_digest=p.signed_digest(delegated),
        renewal_index="1",
        prior_final_observation_sequence="4",
        trust_change_sequence="3",
        issued_at_ms="200",
        successor_not_after_ms="900",
        cumulative_elapsed_ms="100",
        nonce=b64u_encode(bytes(16)),
        prior_observer_session_id="old",
        successor_observer_session_id="new",
        successor_launch_digest=b64u_encode(bytes([1]) * 32),
    )
    args = dict(
        now_ms=200,
        original_not_before_ms=100,
        maximum_total_lifetime_ms=1000,
        maximum_single_launch_ms=800,
        successor_not_before_ms=200,
        prior_not_after_ms=300,
        prior_cumulative_elapsed_ms=99,
        maximum_renewals=2,
    )
    return renewal, delegated, body, args


def test_continuity_roundtrip():
    key, delegation, body, args = continuity_fixture()
    raw = p.sign_continuity(body, "renewal", key)
    assert p.verify_continuity(raw, delegation, body, **args) == body


@pytest.mark.parametrize("successor_start,cap", [(100, 700), (99, 900), (201, 800)])
def test_cap_uses_actual_signed_successor_interval(successor_start, cap):
    key, delegation, body, args = continuity_fixture()
    args.update(successor_not_before_ms=successor_start, maximum_single_launch_ms=cap)
    with pytest.raises(ValueError):
        p.verify_continuity(p.sign_continuity(body, "renewal", key), delegation, body, **args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("now_ms", 300),
        ("now_ms", 1101),
        ("maximum_total_lifetime_ms", 99),
        ("maximum_single_launch_ms", 699),
        ("maximum_single_launch_ms", 1200001),
        ("prior_cumulative_elapsed_ms", 101),
        ("maximum_renewals", 0),
    ],
)
def test_continuity_limits(field, value):
    key, delegation, body, args = continuity_fixture()
    args[field] = value
    with pytest.raises(ValueError):
        p.verify_continuity(
            p.sign_continuity(body, "renewal", key), delegation, body, **args
        )


@pytest.mark.parametrize("replacement", [b"null", b"1", b"1.0", b"true", b"NaN"])
def test_raw_nonstrings_reject(replacement):
    commit, _, body = fixtures()
    raw = p.sign_delegation(body, "commit", commit)
    with pytest.raises(ValueError):
        p.decode_delegation(
            raw.replace(b'"not_after_ms":"1100"', b'"not_after_ms":' + replacement)
        )


@pytest.mark.parametrize("value", ["AB" * 32, "00" * 31, "0x" + "00" * 32, "g" * 64])
def test_external_hex_reject(value):
    with pytest.raises(ValueError):
        p.plan_digest_from_hex(value)


@pytest.mark.parametrize(
    "field",
    [
        "authority_store_id",
        "authority_session_id",
        "repetition_id",
        "plan_digest",
        "config_digest",
        "delegation_digest",
    ],
)
def test_continuity_cannot_broaden_delegation_even_when_expected_matches(field):
    key, delegation, body, args = continuity_fixture()
    body[field] = b64u_encode(bytes([2]) * 32) if field.endswith("_digest") else "other"
    with pytest.raises(ValueError):
        p.verify_continuity(
            p.sign_continuity(body, "renewal", key), delegation, body, **args
        )


def test_continuity_key_id_and_domain_separation():
    key, delegation, body, args = continuity_fixture()
    raw = p.sign_continuity(body, "wrong", key)
    with pytest.raises(ValueError):
        p.verify_continuity(raw, delegation, body, **args)
    raw = p.sign_continuity(body, "renewal", key)
    parsed = p.decode_continuity(raw)
    parsed["signature"] = b64u_encode(
        key.sign(p.DELEGATION_DOMAIN + b"\0" + encode_payload(body))
    )
    with pytest.raises(ValueError):
        p.verify_continuity(encode_payload(parsed), delegation, body, **args)


def test_missing_fields_and_noncanonical_json():
    commit, _, body = fixtures()
    raw = p.sign_delegation(body, "commit", commit)
    parsed = p.decode_delegation(raw)
    del parsed["body"]["nonce"]
    with pytest.raises(ValueError):
        p.decode_delegation(encode_payload(parsed))
    with pytest.raises(ValueError):
        p.decode_delegation(raw.replace(b'"body":', b'"body": '))
    with pytest.raises(ValueError):
        p.decode_delegation(
            raw.replace(
                b'"role":"observer-renewal-v1"',
                b'"role":"observer-renewal-v1","role":"observer-renewal-v1"',
            )
        )
