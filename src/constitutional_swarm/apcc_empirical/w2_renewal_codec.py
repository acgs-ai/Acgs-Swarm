"""Strict, separately domain-signed W2 renewal transcripts.

Callers independently verify checkpoint, launch and observation proofs before
providing their exact pinned bindings. This module grants no live authority.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.codec import MAX_SAFE_INTEGER, _parse, encode_payload
from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    _canonical_decimal,
    _canonical_identifier,
)
from constitutional_swarm.apcc.ports import APCCAuthorityConfig, AuthorityCausalProfile
from constitutional_swarm.apcc.sqlite_store import _config_object, _json

DELEGATION_DOMAIN = b"APCC-W2-OBSERVER-RENEWAL-DELEGATION-V1"
CONTINUITY_DOMAIN = b"APCC-W2-OBSERVER-RENEWAL-CONTINUITY-V1"
_COMMON = frozenset(
    {
        "protocol",
        "authority_store_id",
        "authority_session_id",
        "repetition_id",
        "plan_digest",
        "config_digest",
        "checkpoint_digest",
        "nonce",
    }
)
DELEGATION_FIELDS = _COMMON | {
    "renewal_key_id",
    "renewal_public_key",
    "role",
    "initial_launch_digest",
    "not_before_ms",
    "not_after_ms",
}
CONTINUITY_FIELDS = _COMMON | {
    "experiment_id",
    "run_id",
    "delegation_digest",
    "renewal_index",
    "prior_launch_digest",
    "successor_launch_digest",
    "prior_observer_session_id",
    "successor_observer_session_id",
    "prior_final_observation_sequence",
    "prior_final_observation_digest",
    "trust_change_sequence",
    "trust_log_head",
    "issued_at_ms",
    "successor_not_after_ms",
    "cumulative_elapsed_ms",
}
_TIMES = frozenset(
    {
        "not_before_ms",
        "not_after_ms",
        "renewal_index",
        "prior_final_observation_sequence",
        "trust_change_sequence",
        "issued_at_ms",
        "successor_not_after_ms",
        "cumulative_elapsed_ms",
    }
)
DELEGATION_BINDINGS = DELEGATION_FIELDS - {
    "protocol",
    "role",
    "nonce",
    "not_before_ms",
    "not_after_ms",
}
CONTINUITY_BINDINGS = CONTINUITY_FIELDS - {
    "protocol",
    "nonce",
    "issued_at_ms",
    "successor_not_after_ms",
    "cumulative_elapsed_ms",
}
PLAN_LIMIT_FIELDS = frozenset(
    {
        "maximum_renewals",
        "maximum_total_lifetime_ms",
        "handover_timeout_ms",
        "maximum_single_launch_ms",
    }
)


def canonical_object(value: object) -> bytes:
    """Use the unchanged APCC-CJ1 object encoder."""
    return encode_payload(value)


def _body(body: Mapping[str, str], domain: bytes) -> dict[str, str]:
    fields = DELEGATION_FIELDS if domain == DELEGATION_DOMAIN else CONTINUITY_FIELDS
    if domain not in {DELEGATION_DOMAIN, CONTINUITY_DOMAIN} or set(body) != fields:
        raise ValueError("renewal body has unknown or missing fields")
    result = dict(body)
    for name, value in result.items():
        if type(value) is not str:
            raise ValueError(f"renewal {name} must be a string")
        if name == "protocol":
            if value != domain.decode("ascii"):
                raise ValueError("renewal protocol/domain mismatch")
        elif name == "role":
            if value != "observer-renewal-v1":
                raise ValueError("invalid renewal role")
        elif name in _TIMES:
            _canonical_decimal(
                value, name=name, positive=name == "prior_final_observation_sequence"
            )
        elif name == "nonce":
            b64u_decode(value, expected_length=16)
        elif name.endswith("_digest") or name in {
            "trust_log_head",
            "renewal_public_key",
        }:
            b64u_decode(value, expected_length=32)
        else:
            _canonical_identifier(value, name=name)
    encode_payload(result)
    if domain == DELEGATION_DOMAIN and int(result["not_before_ms"]) >= int(
        result["not_after_ms"]
    ):
        raise ValueError("empty delegation validity interval")
    if domain == CONTINUITY_DOMAIN:
        if result["renewal_index"] == "0":
            raise ValueError("renewal index must advance from zero")
        if result["prior_launch_digest"] == result["successor_launch_digest"]:
            raise ValueError("successor launch must be fresh")
        if (
            result["prior_observer_session_id"]
            == result["successor_observer_session_id"]
        ):
            raise ValueError("successor observer session must be fresh")
    return result


def _encode(
    body: Mapping[str, str], key_id: str, signer: Ed25519PrivateKey, domain: bytes
) -> bytes:
    checked = _body(body, domain)
    _canonical_identifier(key_id, name="signer key ID")
    signature = signer.sign(domain + b"\x00" + encode_payload(checked))
    return encode_payload(
        {"body": checked, "key_id": key_id, "signature": b64u_encode(signature)}
    )


def _decode(raw: bytes, domain: bytes) -> dict[str, object]:
    value = _parse(raw)
    if type(value) is not dict or set(value) != {"body", "key_id", "signature"}:
        raise ValueError("invalid renewal signature object fields")
    if encode_payload(value) != raw:
        raise ValueError("noncanonical renewal transcript")
    if type(value["body"]) is not dict:
        raise ValueError("renewal body must be an object")
    _body(value["body"], domain)
    _canonical_identifier(value["key_id"], name="signer key ID")
    if type(value["signature"]) is not str:
        raise ValueError("signature must be a string")
    b64u_decode(value["signature"], expected_length=64)
    return cast(dict[str, object], value)


def encode_delegation(
    body: Mapping[str, str], key_id: str, signer: Ed25519PrivateKey
) -> bytes:
    """Sign a delegation with the exact store-scoped COMMIT key."""
    return _encode(body, key_id, signer, DELEGATION_DOMAIN)


def decode_delegation(raw: bytes) -> dict[str, object]:
    """Decode only; signature verification is a separate mandatory step."""
    return _decode(raw, DELEGATION_DOMAIN)


def encode_continuity(
    body: Mapping[str, str], key_id: str, signer: Ed25519PrivateKey
) -> bytes:
    """Sign continuity with the dedicated renewal key."""
    return _encode(body, key_id, signer, CONTINUITY_DOMAIN)


def decode_continuity(raw: bytes) -> dict[str, object]:
    """Decode only; signature verification is a separate mandatory step."""
    return _decode(raw, CONTINUITY_DOMAIN)


def _verify(
    raw: bytes,
    domain: bytes,
    key_id: str,
    public_key: bytes,
    expected: Mapping[str, str],
    required: frozenset[str],
) -> dict[str, str]:
    value = _decode(raw, domain)
    body = cast(dict[str, str], value["body"])
    if set(expected) != required or any(
        body[name] != item for name, item in expected.items()
    ):
        raise ValueError(
            "renewal pinned scope mismatch or incomplete expected bindings"
        )
    if value["key_id"] != key_id:
        raise ValueError("renewal exact signer key ID mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            b64u_decode(cast(str, value["signature"]), expected_length=64),
            domain + b"\x00" + encode_payload(body),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("renewal signature mismatch") from exc
    return body


def _integer(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{name} must be a bounded nonnegative integer")
    return value


def verify_delegation(
    raw: bytes,
    *,
    commit_key_id: str,
    commit_public_key: bytes,
    expected: Mapping[str, str],
    forbidden_public_keys: Sequence[bytes],
    now_ms: int,
) -> dict[str, str]:
    """Verify complete scoped authorization and separation from other role keys."""
    body = _verify(
        raw,
        DELEGATION_DOMAIN,
        commit_key_id,
        commit_public_key,
        expected,
        DELEGATION_BINDINGS,
    )
    renewal_key = b64u_decode(body["renewal_public_key"], expected_length=32)
    if renewal_key == commit_public_key or renewal_key in forbidden_public_keys:
        raise ValueError("renewal key aliases another protocol role")
    if (
        not int(body["not_before_ms"])
        <= _integer(now_ms, "now_ms")
        < int(body["not_after_ms"])
    ):
        raise ValueError("delegation outside validity interval")
    return body


def verify_continuity(
    raw: bytes,
    *,
    renewal_key_id: str,
    renewal_public_key: bytes,
    expected: Mapping[str, str],
    original_not_before_ms: int,
    prior_not_after_ms: int,
    successor_not_before_ms: int,
    delegation_not_after_ms: int,
    maximum_total_lifetime_ms: int,
    maximum_single_launch_ms: int,
    previous_elapsed_ms: int,
    maximum_renewals: int,
) -> dict[str, str]:
    """Verify complete scope and both wall-clock and monotonic lifetime fences."""
    body = _verify(
        raw,
        CONTINUITY_DOMAIN,
        renewal_key_id,
        renewal_public_key,
        expected,
        CONTINUITY_BINDINGS,
    )
    values = {
        "original_not_before_ms": original_not_before_ms,
        "prior_not_after_ms": prior_not_after_ms,
        "successor_not_before_ms": successor_not_before_ms,
        "delegation_not_after_ms": delegation_not_after_ms,
        "maximum_total_lifetime_ms": maximum_total_lifetime_ms,
        "maximum_single_launch_ms": maximum_single_launch_ms,
        "previous_elapsed_ms": previous_elapsed_ms,
        "maximum_renewals": maximum_renewals,
    }
    for name, value in values.items():
        _integer(value, name)
    issued = int(body["issued_at_ms"])
    expiry = int(body["successor_not_after_ms"])
    elapsed = int(body["cumulative_elapsed_ms"])
    bound = min(
        delegation_not_after_ms, original_not_before_ms + maximum_total_lifetime_ms
    )
    if (
        not 0 < maximum_single_launch_ms <= 1_200_000
        or not original_not_before_ms
        <= successor_not_before_ms
        <= issued
        < prior_not_after_ms
        or not issued < expiry <= bound
        or expiry - successor_not_before_ms > maximum_single_launch_ms
        or not previous_elapsed_ms <= elapsed <= maximum_total_lifetime_ms
        or int(body["renewal_index"]) > maximum_renewals
    ):
        raise ValueError("renewal lifetime, monotonic budget or count exhausted")
    return body


def external_plan_digest(raw: bytes, expected_sha256: str) -> str:
    """Convert an exact external lowercase hexadecimal SHA256 pin to APCC digest."""
    if (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("external plan SHA256 must be lowercase hexadecimal")
    actual = hashlib.sha256(raw).digest()
    if actual != bytes.fromhex(expected_sha256):
        raise ValueError("external plan SHA256 mismatch")
    return b64u_encode(actual)


def w2_config_digest(config: APCCAuthorityConfig) -> str:
    """Hash unchanged SQLite config bytes; reject the default64 profile."""
    if (
        type(config) is not APCCAuthorityConfig
        or config.causal_profile is not AuthorityCausalProfile.W2_LINEAR_100
    ):
        raise ValueError("renewal requires exact W2_LINEAR_100 configuration")
    return sha256_digest(_json(_config_object(config)).encode("utf-8"))


def validate_plan_limits(limits: Mapping[str, str]) -> dict[str, int]:
    """Validate mandatory explicit budgets without operational defaults."""
    if set(limits) != PLAN_LIMIT_FIELDS:
        raise ValueError("missing or unknown renewal plan limits")
    parsed = {
        name: _canonical_decimal(value, name=name, positive=name != "maximum_renewals")
        for name, value in limits.items()
    }
    if (
        parsed["maximum_single_launch_ms"] > 1_200_000
        or parsed["maximum_single_launch_ms"] > parsed["maximum_total_lifetime_ms"]
        or parsed["handover_timeout_ms"] > parsed["maximum_total_lifetime_ms"]
    ):
        raise ValueError("invalid renewal plan lifetime limits")
    return parsed
