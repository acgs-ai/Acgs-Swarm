"""Adversarial portable transcript checks, independent of live renewal state."""

import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc_empirical import qualification_v3 as q
from constitutional_swarm.apcc_empirical import w2_renewal_codec as c


def bodies():
    commit = Ed25519PrivateKey.generate()
    renewal = Ed25519PrivateKey.generate()
    common = dict(
        authority_store_id="store",
        authority_session_id="authority-session",
        repetition_id="repetition",
        plan_digest=sha256_digest(b"plan"),
        config_digest=sha256_digest(b"config"),
        checkpoint_digest=sha256_digest(b"checkpoint"),
        nonce=b64u_encode(bytes(16)),
    )
    delegation = dict(
        common,
        protocol=c.DELEGATION_DOMAIN.decode(),
        renewal_key_id="renewal-key",
        renewal_public_key=b64u_encode(renewal.public_key().public_bytes_raw()),
        role="observer-renewal-v1",
        initial_launch_digest=sha256_digest(b"initial"),
        not_before_ms="100",
        not_after_ms="10000",
    )
    continuity = dict(
        common,
        protocol=c.CONTINUITY_DOMAIN.decode(),
        experiment_id="experiment",
        run_id="run",
        delegation_digest=sha256_digest(
            c.encode_delegation(delegation, "commit-key", commit)
        ),
        renewal_index="1",
        prior_launch_digest=sha256_digest(b"initial"),
        successor_launch_digest=sha256_digest(b"successor"),
        prior_observer_session_id="prior",
        successor_observer_session_id="successor",
        prior_final_observation_sequence="100",
        prior_final_observation_digest=sha256_digest(b"observation"),
        trust_change_sequence="0",
        trust_log_head=sha256_digest(b"trust"),
        issued_at_ms="200",
        successor_not_after_ms="1000",
        cumulative_elapsed_ms="100",
    )
    return commit, renewal, delegation, continuity


def delegation_args(commit, body):
    return dict(
        commit_key_id="commit-key",
        commit_public_key=commit.public_key().public_bytes_raw(),
        expected={key: body[key] for key in c.DELEGATION_BINDINGS},
        forbidden_public_keys=[],
        now_ms=200,
    )


def continuity_args(renewal, body):
    return dict(
        renewal_key_id="renewal-key",
        renewal_public_key=renewal.public_key().public_bytes_raw(),
        expected={key: body[key] for key in c.CONTINUITY_BINDINGS},
        original_not_before_ms=100,
        prior_not_after_ms=500,
        successor_not_before_ms=200,
        delegation_not_after_ms=10000,
        maximum_total_lifetime_ms=9900,
        maximum_single_launch_ms=1200,
        previous_elapsed_ms=0,
        maximum_renewals=3,
    )


def test_valid_scoped_transcripts():
    commit, renewal, delegation, continuity = bodies()
    raw = c.encode_delegation(delegation, "commit-key", commit)
    assert c.verify_delegation(raw, **delegation_args(commit, delegation)) == delegation
    raw = c.encode_continuity(continuity, "renewal-key", renewal)
    assert (
        c.verify_continuity(raw, **continuity_args(renewal, continuity)) == continuity
    )


@pytest.mark.parametrize("kind", ["delegation", "continuity"])
@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "extra",
        "missing",
        "space",
        "trailing",
        "null",
        "float",
        "number",
        "padded",
        "nonce32",
        "signature32",
        "protocol",
        "overflow",
        "leading-zero",
        "negative",
    ],
)
def test_strict_wire_rejection(kind, mutation):
    commit, renewal, delegation, continuity = bodies()
    body, signer, key_id = (
        (delegation, commit, "commit-key")
        if kind == "delegation"
        else (continuity, renewal, "renewal-key")
    )
    encode, decode = (
        (c.encode_delegation, c.decode_delegation)
        if kind == "delegation"
        else (c.encode_continuity, c.decode_continuity)
    )
    raw = encode(body, key_id, signer)
    value = json.loads(raw)
    field = "not_before_ms" if kind == "delegation" else "issued_at_ms"
    if mutation == "duplicate":
        raw = raw.replace(b'{"body":{', b'{"body":{"protocol":"duplicate",', 1)
    elif mutation == "space":
        raw = json.dumps(value).encode()
    elif mutation == "trailing":
        raw += b"\n"
    else:
        if mutation == "extra":
            value["body"]["algorithm"] = "Ed25519"
        elif mutation == "missing":
            del value["body"]["plan_digest"]
        elif mutation == "null":
            value["body"][field] = None
        elif mutation == "float":
            value["body"][field] = 1.5
        elif mutation == "number":
            value["body"][field] = 200
        elif mutation == "padded":
            value["body"]["plan_digest"] += "="
        elif mutation == "nonce32":
            value["body"]["nonce"] = b64u_encode(bytes(32))
        elif mutation == "signature32":
            value["signature"] = b64u_encode(bytes(32))
        elif mutation == "protocol":
            value["body"]["protocol"] = "APCC-COMMIT-V1"
        elif mutation == "overflow":
            value["body"][field] = str(2**53)
        elif mutation == "leading-zero":
            value["body"][field] = "0200"
        elif mutation == "negative":
            value["body"][field] = "-1"
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError):
        decode(raw)


@pytest.mark.parametrize("kind", ["delegation", "continuity"])
@pytest.mark.parametrize(
    "mutation", ["key-id", "wrong-key", "incomplete-pins", "wrong-plan", "signature"]
)
def test_signature_and_external_bindings(kind, mutation):
    commit, renewal, delegation, continuity = bodies()
    if kind == "delegation":
        raw = c.encode_delegation(delegation, "commit-key", commit)
        args = delegation_args(commit, delegation)
        verify, prefix = c.verify_delegation, "commit"
    else:
        raw = c.encode_continuity(continuity, "renewal-key", renewal)
        args = continuity_args(renewal, continuity)
        verify, prefix = c.verify_continuity, "renewal"
    if mutation == "key-id":
        args[prefix + "_key_id"] = "alias-same-key"
    elif mutation == "wrong-key":
        args[prefix + "_public_key"] = (
            Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        )
    elif mutation == "incomplete-pins":
        del args["expected"]["config_digest"]
    elif mutation == "wrong-plan":
        args["expected"]["plan_digest"] = sha256_digest(b"substitute")
    elif mutation == "signature":
        value = json.loads(raw)
        value["signature"] = b64u_encode(bytes(64))
        raw = c.canonical_object(value)
    with pytest.raises(ValueError):
        verify(raw, **args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("prior_not_after_ms", 200),
        ("successor_not_before_ms", 201),
        ("original_not_before_ms", 201),
        ("delegation_not_after_ms", 999),
        ("maximum_total_lifetime_ms", 899),
        ("maximum_single_launch_ms", 799),
        ("maximum_single_launch_ms", 1200001),
        ("previous_elapsed_ms", 101),
        ("maximum_renewals", 0),
        ("maximum_renewals", True),
    ],
)
def test_lifetime_fences(field, value):
    _, renewal, _, body = bodies()
    args = continuity_args(renewal, body)
    args[field] = value
    with pytest.raises(ValueError):
        c.verify_continuity(c.encode_continuity(body, "renewal-key", renewal), **args)


def test_role_alias_and_expiry_rejected():
    commit, renewal, body, _ = bodies()
    args = delegation_args(commit, body)
    args["forbidden_public_keys"] = [renewal.public_key().public_bytes_raw()]
    raw = c.encode_delegation(body, "commit-key", commit)
    with pytest.raises(ValueError, match="aliases"):
        c.verify_delegation(raw, **args)
    args["forbidden_public_keys"] = []
    args["now_ms"] = 10001
    with pytest.raises(ValueError, match="validity"):
        c.verify_delegation(raw, **args)


def test_external_plan_pin_exact_bytes():
    raw = b'{"plan":"approved"}'
    pin = hashlib.sha256(raw).hexdigest()
    assert c.external_plan_digest(raw, pin) == sha256_digest(raw)
    for wrong in (pin.upper(), sha256_digest(raw), "0" * 64):
        with pytest.raises(ValueError):
            c.external_plan_digest(raw, wrong)
    with pytest.raises(ValueError):
        c.external_plan_digest(raw + b"\n", pin)


def test_configuration_digest_preserves_existing_encoding(tmp_path):
    child, *_ = q._configuration(tmp_path, "renewal-test")
    with pytest.raises(ValueError):
        c.w2_config_digest(child.authority)
    config = replace(
        child.authority, causal_profile=AuthorityCausalProfile.W2_LINEAR_100
    )
    assert c.w2_config_digest(config) == sha256_digest(
        c._json(c._config_object(config)).encode()
    )


def test_explicit_plan_limits():
    limits = dict(
        maximum_renewals="3",
        maximum_total_lifetime_ms="5000000",
        handover_timeout_ms="10000",
        maximum_single_launch_ms="1200000",
    )
    assert c.validate_plan_limits(limits)["maximum_renewals"] == 3
    for update in (
        {"maximum_single_launch_ms": "1200001"},
        {"maximum_renewals": "03"},
        {"handover_timeout_ms": "0"},
    ):
        with pytest.raises(ValueError):
            c.validate_plan_limits(dict(limits, **update))
    del limits["handover_timeout_ms"]
    with pytest.raises(ValueError):
        c.validate_plan_limits(limits)


@pytest.mark.parametrize("kind", ["delegation", "continuity"])
def test_every_pinned_field_is_enforced(kind):
    commit, renewal, delegation, continuity = bodies()
    if kind == "delegation":
        raw = c.encode_delegation(delegation, "commit-key", commit)
        args, verify = delegation_args(commit, delegation), c.verify_delegation
    else:
        raw = c.encode_continuity(continuity, "renewal-key", renewal)
        args, verify = continuity_args(renewal, continuity), c.verify_continuity
    for key in args["expected"]:
        changed = dict(args, expected=dict(args["expected"]))
        changed["expected"][key] += "substituted"
        with pytest.raises(ValueError, match="scope"):
            verify(raw, **changed)


def test_commit_key_cannot_double_as_renewal_key():
    commit, _, body, _ = bodies()
    body["renewal_public_key"] = b64u_encode(commit.public_key().public_bytes_raw())
    with pytest.raises(ValueError, match="aliases"):
        c.verify_delegation(
            c.encode_delegation(body, "commit-key", commit),
            **delegation_args(commit, body),
        )


@pytest.mark.parametrize("field", ["prior_launch_digest", "prior_observer_session_id"])
def test_same_launch_or_session_is_not_renewal(field):
    _, renewal, _, body = bodies()
    body[field] = body[field.replace("prior_", "successor_")]
    with pytest.raises(ValueError, match="fresh"):
        c.encode_continuity(body, "renewal-key", renewal)


def test_existing_authority_signature_domain_set_is_not_broadened():
    from constitutional_swarm.apcc.crypto import domain_preimage

    for domain in (c.DELEGATION_DOMAIN, c.CONTINUITY_DOMAIN):
        with pytest.raises(ValueError, match="unknown"):
            domain_preimage(domain, b"payload")


def test_delegation_expiry_is_exclusive():
    commit, _, body, _ = bodies()
    raw = c.encode_delegation(body, "commit-key", commit)
    args = delegation_args(commit, body)
    args["now_ms"] = int(body["not_after_ms"]) - 1
    assert c.verify_delegation(raw, **args) == body
    args["now_ms"] += 1
    with pytest.raises(ValueError, match="validity"):
        c.verify_delegation(raw, **args)


def test_zero_terminal_observation_sequence_rejected():
    _, renewal, _, body = bodies()
    raw = c.encode_continuity(body, "renewal-key", renewal)
    value = json.loads(raw)
    value["body"]["prior_final_observation_sequence"] = "0"
    with pytest.raises(ValueError, match="canonical decimal"):
        c.decode_continuity(c.canonical_object(value))
    body["prior_final_observation_sequence"] = "0"
    with pytest.raises(ValueError, match="canonical decimal"):
        c.encode_continuity(body, "renewal-key", renewal)
