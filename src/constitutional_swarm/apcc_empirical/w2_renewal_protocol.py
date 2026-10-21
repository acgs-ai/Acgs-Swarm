"""Exact-field W2 renewal wire objects; no runtime or qualification authority.

Expected bodies must come from independently authenticated launch/checkpoint/plan
bindings, never from echoing the decoded transcript. Continuity verification must
follow verification of its delegation against the original COMMIT trust binding.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.codec import _IDENTIFIER, _parse, encode_payload
from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest

DELEGATION_DOMAIN = b"APCC-W2-OBSERVER-RENEWAL-DELEGATION-V1"
CONTINUITY_DOMAIN = b"APCC-W2-OBSERVER-RENEWAL-CONTINUITY-V1"
DELEGATION_FIELDS = frozenset(
    """protocol authority_store_id authority_session_id repetition_id
renewal_key_id renewal_public_key role initial_launch_digest plan_digest config_digest
checkpoint_digest not_before_ms not_after_ms nonce""".split()
)
CONTINUITY_FIELDS = frozenset(
    """protocol experiment_id run_id authority_store_id authority_session_id
repetition_id delegation_digest plan_digest renewal_index prior_launch_digest successor_launch_digest
prior_observer_session_id successor_observer_session_id prior_final_observation_sequence
prior_final_observation_digest trust_change_sequence trust_log_head config_digest checkpoint_digest
issued_at_ms successor_not_after_ms cumulative_elapsed_ms nonce""".split()
)
_COUNTERS = frozenset(
    """not_before_ms not_after_ms renewal_index prior_final_observation_sequence
trust_change_sequence issued_at_ms successor_not_after_ms cumulative_elapsed_ms""".split()
)
MAX_SAFE_INTEGER = 2**53 - 1


@dataclass(frozen=True)
class SignerBinding:
    """Exact key ID plus raw Ed25519 public key, obtained out of band."""

    key_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        _identity(self.key_id)
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise ValueError("invalid public key")


def _identity(value: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("invalid authority identity")


def _integer(value: int) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError("invalid safe integer")
    return value


def _body(value: object, domain: bytes) -> dict[str, str]:
    fields = DELEGATION_FIELDS if domain == DELEGATION_DOMAIN else CONTINUITY_FIELDS
    if type(value) is not dict or set(value) != fields:
        raise ValueError("renewal body requires exact fields")
    result = cast("dict[str, str]", value)
    for name, item in result.items():
        if type(item) is not str:
            raise ValueError("renewal fields must be strings")
        if name in _COUNTERS:
            if re.fullmatch(r"0|[1-9][0-9]{0,15}", item) is None:
                raise ValueError("noncanonical decimal")
            _integer(int(item))
        elif name.endswith("_digest") or name == "trust_log_head":
            b64u_decode(item, expected_length=32)
        elif name == "nonce":
            b64u_decode(item, expected_length=16)
        elif name == "renewal_public_key":
            b64u_decode(item, expected_length=32)
        elif name not in {"protocol", "role"}:
            _identity(item)
    if result["protocol"] != domain.decode():
        raise ValueError("wrong renewal protocol")
    if domain == DELEGATION_DOMAIN:
        if result["role"] != "observer-renewal-v1":
            raise ValueError("wrong delegated role")
        if int(result["not_before_ms"]) >= int(result["not_after_ms"]):
            raise ValueError("empty delegation interval")
    else:
        if (
            int(result["renewal_index"]) == 0
            or int(result["prior_final_observation_sequence"]) == 0
        ):
            raise ValueError("missing predecessor or renewal index")
        if (
            result["prior_observer_session_id"]
            == result["successor_observer_session_id"]
        ):
            raise ValueError("observer session must be fresh")
        if result["prior_launch_digest"] == result["successor_launch_digest"]:
            raise ValueError("successor launch must be fresh")
        if int(result["issued_at_ms"]) >= int(result["successor_not_after_ms"]):
            raise ValueError("empty successor interval")
    encode_payload(result)
    return dict(result)


def _decode(raw: bytes, domain: bytes) -> dict[str, object]:
    value = _parse(raw)
    if type(value) is not dict or set(value) != {"body", "key_id", "signature"}:
        raise ValueError("signed renewal requires exact fields")
    _body(value["body"], domain)
    _identity(value["key_id"])
    if type(value["signature"]) is not str:
        raise ValueError("signature must be a string")
    b64u_decode(value["signature"], expected_length=64)
    if encode_payload(value) != raw:
        raise ValueError("noncanonical renewal encoding")
    return cast("dict[str, object]", value)


def decode_delegation(raw: bytes) -> dict[str, object]:
    """Decode canonical delegation; this alone does not authenticate it."""
    return _decode(raw, DELEGATION_DOMAIN)


def decode_continuity(raw: bytes) -> dict[str, object]:
    """Decode canonical continuity; this alone does not authenticate it."""
    return _decode(raw, CONTINUITY_DOMAIN)


def _sign(
    body: Mapping[str, str], key_id: str, key: Ed25519PrivateKey, domain: bytes
) -> bytes:
    checked = _body(dict(body), domain)
    _identity(key_id)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Ed25519 signing key required")
    return encode_payload(
        {
            "body": checked,
            "key_id": key_id,
            "signature": b64u_encode(
                key.sign(domain + b"\0" + encode_payload(checked))
            ),
        }
    )


def sign_delegation(
    body: Mapping[str, str], key_id: str, key: Ed25519PrivateKey
) -> bytes:
    """Sign only the new delegation domain; caller owns COMMIT-purpose policy."""
    return _sign(body, key_id, key, DELEGATION_DOMAIN)


def sign_continuity(
    body: Mapping[str, str], key_id: str, key: Ed25519PrivateKey
) -> bytes:
    """Sign continuity; caller must durably reserve/seal before release."""
    return _sign(body, key_id, key, CONTINUITY_DOMAIN)


def _verify(
    raw: bytes, binding: SignerBinding, expected_body: Mapping[str, str], domain: bytes
) -> dict[str, str]:
    obj = _decode(raw, domain)
    body = _body(obj["body"], domain)
    if obj["key_id"] != binding.key_id or body != _body(dict(expected_body), domain):
        raise ValueError("signer or independently pinned scope mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(binding.public_key).verify(
            b64u_decode(cast("str", obj["signature"]), expected_length=64),
            domain + b"\0" + encode_payload(body),
        )
    except InvalidSignature as exc:
        raise ValueError("invalid renewal signature") from exc
    return body


def verify_delegation(
    raw: bytes,
    commit_binding: SignerBinding,
    expected_body: Mapping[str, str],
    *,
    forbidden_public_keys: Sequence[bytes],
    now_ms: int,
) -> dict[str, str]:
    """Authenticate scope, validity and separation from ALL other role keys.

    Caller supplies controller, every observer and every APCC role public key.
    COMMIT itself is always excluded even if omitted from that sequence.
    """
    body = _verify(raw, commit_binding, expected_body, DELEGATION_DOMAIN)
    key = b64u_decode(body["renewal_public_key"], expected_length=32)
    if key == commit_binding.public_key or key in forbidden_public_keys:
        raise ValueError("renewal key overlaps another signing role")
    if not int(body["not_before_ms"]) <= _integer(now_ms) <= int(body["not_after_ms"]):
        raise ValueError("delegation outside validity interval")
    return body


def verify_continuity(
    raw: bytes,
    delegation_raw: bytes,
    expected_body: Mapping[str, str],
    *,
    now_ms: int,
    original_not_before_ms: int,
    maximum_total_lifetime_ms: int,
    maximum_single_launch_ms: int,
    successor_not_before_ms: int,
    prior_not_after_ms: int,
    prior_cumulative_elapsed_ms: int,
    maximum_renewals: int,
) -> dict[str, str]:
    """Verify a successor against a PREVIOUSLY authenticated delegation and plan.

    Expected body pins exact prior index+1, trust position, final observation,
    checkpoints and prepared launch. Durable single-successor/nonce uniqueness,
    process liveness, and independent launch signature checks belong to caller.
    """
    for value in (
        now_ms,
        original_not_before_ms,
        maximum_total_lifetime_ms,
        maximum_single_launch_ms,
        successor_not_before_ms,
        prior_not_after_ms,
        prior_cumulative_elapsed_ms,
        maximum_renewals,
    ):
        _integer(value)
    delegation = _body(decode_delegation(delegation_raw)["body"], DELEGATION_DOMAIN)
    binding = SignerBinding(
        delegation["renewal_key_id"],
        b64u_decode(delegation["renewal_public_key"], expected_length=32),
    )
    body = _verify(raw, binding, expected_body, CONTINUITY_DOMAIN)
    for field in (
        "authority_store_id",
        "authority_session_id",
        "repetition_id",
        "plan_digest",
        "config_digest",
    ):
        if body[field] != delegation[field]:
            raise ValueError("continuity exceeds delegated scope")
    if body["delegation_digest"] != signed_digest(delegation_raw):
        raise ValueError("delegation digest mismatch")
    end = min(
        int(delegation["not_after_ms"]),
        original_not_before_ms + maximum_total_lifetime_ms,
    )
    issued = int(body["issued_at_ms"])
    successor_end = int(body["successor_not_after_ms"])
    if (
        not max(original_not_before_ms, int(delegation["not_before_ms"]))
        <= successor_not_before_ms
        <= issued
        <= now_ms
        <= end
    ):
        raise ValueError("activation outside delegation or plan lifetime")
    if now_ms >= prior_not_after_ms or now_ms >= successor_end:
        raise ValueError("expired prior or successor launch")
    if not 0 < maximum_single_launch_ms <= 1_200_000:
        raise ValueError("invalid single-launch lifetime bound")
    if not issued < successor_end <= min(end, successor_not_before_ms + maximum_single_launch_ms):
        raise ValueError("successor interval exceeds plan")
    if (
        not prior_cumulative_elapsed_ms
        <= int(body["cumulative_elapsed_ms"])
        <= maximum_total_lifetime_ms
    ):
        raise ValueError("monotonic elapsed budget violated")
    if not 1 <= int(body["renewal_index"]) <= maximum_renewals:
        raise ValueError("renewal count exhausted")
    return body


def plan_digest_from_hex(external_sha256: str) -> str:
    """Explicitly convert external lowercase SHA256SUMS into protocol digest."""
    if (
        type(external_sha256) is not str
        or re.fullmatch("[0-9a-f]{64}", external_sha256) is None
    ):
        raise ValueError("external SHA256 must be lowercase hex")
    return b64u_encode(bytes.fromhex(external_sha256))


def signed_digest(raw: bytes) -> str:
    """Digest the exact signed object bytes, not merely its body."""
    return sha256_digest(raw)
