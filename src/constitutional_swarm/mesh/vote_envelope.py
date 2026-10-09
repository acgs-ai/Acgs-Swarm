"""Canonical signed vote evidence shared by mesh protocol consumers."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

VOTE_ENVELOPE_PROTOCOL_VERSION = 2
_VOTE_DOMAIN = b"constitutional-swarm.vote-envelope.v2\x00"
_ROOT_DOMAIN = b"constitutional-swarm.vote-envelope-root.v2\x00"
_ASSIGNED_PEERS_DOMAIN = b"constitutional-swarm.assigned-peers.v1\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_FIELDS = (
    "protocol_version",
    "voter_id",
    "key_id",
    "task_id",
    "assignment_id",
    "producer_id",
    "artifact_id",
    "content_hash",
    "constitutional_hash",
    "assigned_peers_hash",
    "assigned_peer_count",
    "quorum",
    "evidence_mode",
    "decision",
    "reason",
    "nonce",
    "issued_at",
    "signature",
)


@dataclass(frozen=True, slots=True)
class VoteEnvelope:
    protocol_version: int
    voter_id: str
    key_id: str
    task_id: str
    assignment_id: str
    producer_id: str
    artifact_id: str
    content_hash: str
    constitutional_hash: str
    assigned_peers_hash: str
    assigned_peer_count: int
    quorum: int
    evidence_mode: Literal["independent", "single_operator_dev"]
    decision: Literal["approved", "denied"]
    reason: str
    nonce: str
    issued_at: float
    signature: str

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def approved(self) -> bool:
        return self.decision == "approved"


def normalize_voter_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("voter_id must be a string")
    value = unicodedata.normalize("NFKC", value)
    value = (
        "".join(c for c in value if unicodedata.category(c) != "Cf").strip().casefold()
    )
    if not value:
        raise ValueError("voter_id must not be empty after normalization")
    return value


def _hex(value: str, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} must be canonical lowercase hex")
    return value


def _public(value: Ed25519PublicKey | bytes | str) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    raw = (
        bytes.fromhex(_hex(value, _HEX64, "public key"))
        if isinstance(value, str)
        else value
    )
    if not isinstance(raw, bytes):
        raise TypeError("invalid public key type")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ValueError("public key must contain exactly 32 Ed25519 bytes") from exc


def _private(value: Ed25519PrivateKey | bytes | str) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    raw = (
        bytes.fromhex(_hex(value, _HEX64, "private key"))
        if isinstance(value, str)
        else value
    )
    if not isinstance(raw, bytes):
        raise TypeError("invalid private key type")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise ValueError("private key must contain exactly 32 Ed25519 bytes") from exc


def key_id_for_public_key(value: Ed25519PublicKey | bytes | str) -> str:
    raw = _public(value).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class _Grant:
    identity: str
    key_id: str
    key: Ed25519PublicKey
    roles: frozenset[str]


class VoteSignerRegistry:
    def __init__(self, *, frozen: bool = False) -> None:
        self._identities: dict[str, _Grant] = {}
        self._keys: dict[str, str] = {}
        self._lock = threading.RLock()
        self._frozen = frozen

    @property
    def frozen(self) -> bool:
        return self._frozen

    def _require_mutable(self) -> None:
        if self._frozen:
            raise ValueError("vote signer registry is frozen")

    def register(
        self,
        voter_id: str,
        public_key: Ed25519PublicKey | bytes | str,
        *,
        roles: Collection[str] = frozenset({"voter"}),
    ) -> str:
        self._require_mutable()
        if isinstance(roles, (str, bytes)):
            raise TypeError("roles must be a collection of role names")
        if any(not isinstance(role, str) or not role.strip() for role in roles):
            raise ValueError("signer roles must be non-empty strings")
        identity, key = normalize_voter_id(voter_id), _public(public_key)
        key_id = key_id_for_public_key(key)
        role_set = frozenset(
            role.strip().casefold()
            for role in roles
            if role.strip()
        )
        if not role_set:
            raise ValueError("signer roles must not be empty")
        with self._lock:
            old, owner = self._identities.get(identity), self._keys.get(key_id)
            if old is not None and (old.key_id != key_id or old.roles != role_set):
                raise ValueError("voter identity is already registered")
            if owner is not None and owner != identity:
                raise ValueError(
                    "public key is already registered to another voter identity"
                )
            self._identities[identity] = _Grant(identity, key_id, key, role_set)
            self._keys[key_id] = identity
        return key_id

    def authorize(
        self, voter_id: str, key_id: str, *, role: str = "voter"
    ) -> Ed25519PublicKey:
        identity, role = normalize_voter_id(voter_id), role.strip().casefold()
        _hex(key_id, _HEX64, "key_id")
        with self._lock:
            grant = self._identities.get(identity)
            if grant is None or grant.key_id != key_id:
                raise ValueError("vote signer identity and key are not authorized")
            if role not in grant.roles:
                raise ValueError(f"vote signer is not authorized for role {role!r}")
            return grant.key

    def unregister(self, voter_id: str) -> None:
        """Remove one explicitly managed signer identity."""
        self._require_mutable()
        identity = normalize_voter_id(voter_id)
        with self._lock:
            grant = self._identities.pop(identity, None)
            if grant is not None:
                self._keys.pop(grant.key_id, None)

    def replace(
        self,
        voter_id: str,
        public_key: Ed25519PublicKey | bytes | str,
        *,
        roles: Collection[str] = frozenset({"voter"}),
    ) -> str:
        """Atomically install or rotate one identity after all checks pass."""
        self._require_mutable()
        if isinstance(roles, (str, bytes)):
            raise TypeError("roles must be a collection of role names")
        if any(not isinstance(role, str) or not role.strip() for role in roles):
            raise ValueError("signer roles must be non-empty strings")
        identity, key = normalize_voter_id(voter_id), _public(public_key)
        key_id = key_id_for_public_key(key)
        role_set = frozenset(role.strip().casefold() for role in roles)
        if not role_set:
            raise ValueError("signer roles must not be empty")
        with self._lock:
            owner = self._keys.get(key_id)
            if owner is not None and owner != identity:
                raise ValueError(
                    "public key is already registered to another voter identity"
                )
            old = self._identities.get(identity)
            if old is not None and old.key_id != key_id:
                self._keys.pop(old.key_id, None)
            self._identities[identity] = _Grant(identity, key_id, key, role_set)
            self._keys[key_id] = identity
        return key_id

    def trust_grants(self, *, role: str = "validator") -> dict[str, dict[str, object]]:
        """Export immutable public grants for consumers of verified vote evidence."""
        required = role.strip().casefold()
        with self._lock:
            grants = tuple(self._identities.values())
        return {
            grant.key_id: {
                "identity_id": grant.identity,
                "public_key_hex": grant.key.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ).hex(),
                "roles": [required],
            }
            for grant in grants
            if required in grant.roles
        }

    def frozen_copy(self) -> VoteSignerRegistry:
        """Return an immutable public-key-only snapshot of this trust root."""
        snapshot = VoteSignerRegistry()
        with self._lock:
            grants = tuple(self._identities.values())
        for grant in grants:
            snapshot.register(grant.identity, grant.key, roles=grant.roles)
        snapshot._frozen = True
        return snapshot


def _canonical_assigned_peers(peers: Sequence[str]) -> tuple[str, ...]:
    if isinstance(peers, (str, bytes)):
        raise TypeError("assigned_peers must be a sequence of voter identities")
    normalized = tuple(normalize_voter_id(peer) for peer in peers)
    if not normalized:
        raise ValueError("assigned_peers must not be empty")
    if len(set(normalized)) != len(normalized):
        raise ValueError("assigned_peers must contain distinct voter identities")
    return tuple(sorted(normalized))


def canonical_assigned_peers_hash(peers: Sequence[str]) -> str:
    """Hash a canonical sorted validator roster for signed electorate binding."""
    roster = _canonical_assigned_peers(peers)
    payload = json.dumps(
        roster, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(_ASSIGNED_PEERS_DOMAIN + payload).hexdigest()


def _validate(item: VoteEnvelope) -> VoteEnvelope:
    if type(item.protocol_version) is not int or item.protocol_version != 2:
        raise ValueError("unsupported vote envelope protocol version")
    if item.voter_id != normalize_voter_id(item.voter_id):
        raise ValueError("voter_id must use its canonical normalized form")
    _hex(item.key_id, _HEX64, "key_id")
    _hex(item.assigned_peers_hash, _HEX64, "assigned_peers_hash")
    if type(item.assigned_peer_count) is not int or item.assigned_peer_count < 1:
        raise ValueError("assigned_peer_count must be a positive integer")
    if type(item.quorum) is not int or not 1 <= item.quorum <= item.assigned_peer_count:
        raise ValueError("quorum must be within the assigned electorate")
    if item.quorum <= item.assigned_peer_count // 2:
        raise ValueError("quorum must be a strict majority of assigned_peer_count")
    if item.evidence_mode not in {"independent", "single_operator_dev"}:
        raise ValueError("invalid vote envelope evidence_mode")
    for name in (
        "task_id",
        "assignment_id",
        "producer_id",
        "artifact_id",
        "content_hash",
        "constitutional_hash",
        "nonce",
    ):
        if not isinstance(getattr(item, name), str) or not getattr(item, name):
            raise ValueError(f"{name} must be a non-empty string")
    if item.decision not in {"approved", "denied"}:
        raise ValueError("invalid decision")
    if not isinstance(item.reason, str):
        raise TypeError("reason must be a string")
    if type(item.issued_at) is not float or not math.isfinite(item.issued_at):
        raise ValueError("issued_at must be a finite float")
    _hex(item.signature, _HEX128, "signature")
    return item


def vote_envelope_to_dict(item: VoteEnvelope) -> dict[str, object]:
    _validate(item)
    return {name: getattr(item, name) for name in _FIELDS}


def vote_envelope_from_dict(data: Mapping[str, object]) -> VoteEnvelope:
    if set(data) != set(_FIELDS):
        raise ValueError("vote envelope schema fields mismatch")
    values: dict[str, Any] = dict(data)
    for name in set(_FIELDS) - {
        "protocol_version",
        "issued_at",
        "assigned_peer_count",
        "quorum",
    }:
        if not isinstance(values[name], str):
            raise TypeError(f"{name} must be a string")
    if (
        type(values["protocol_version"]) is not int
        or type(values["issued_at"]) is not float
        or type(values["assigned_peer_count"]) is not int
        or type(values["quorum"]) is not int
    ):
        raise TypeError("invalid vote envelope scalar type")
    return _validate(VoteEnvelope(**values))


def canonical_vote_envelope_bytes(
    item: VoteEnvelope, *, include_signature: bool = False
) -> bytes:
    payload = vote_envelope_to_dict(item)
    if not include_signature:
        payload.pop("signature")
    return (
        _VOTE_DOMAIN
        + json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
    )


def sign_vote_envelope(
    private_key: Ed25519PrivateKey | bytes | str,
    *,
    voter_id: str,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    decision: Literal["approved", "denied"],
    reason: str,
    nonce: str,
    issued_at: float,
    assigned_peers: Sequence[str],
    quorum: int,
    evidence_mode: Literal["independent", "single_operator_dev"] = "independent",
    key_id: str | None = None,
    protocol_version: int = VOTE_ENVELOPE_PROTOCOL_VERSION,
) -> VoteEnvelope:
    key = _private(private_key)
    derived = key_id_for_public_key(key.public_key())
    if key_id is not None and _hex(key_id, _HEX64, "key_id") != derived:
        raise ValueError("key_id does not match the signing key")
    roster = _canonical_assigned_peers(assigned_peers)
    unsigned = VoteEnvelope(
        protocol_version,
        normalize_voter_id(voter_id),
        derived,
        task_id,
        assignment_id,
        producer_id,
        artifact_id,
        content_hash,
        constitutional_hash,
        canonical_assigned_peers_hash(roster),
        len(roster),
        quorum,
        evidence_mode,
        decision,
        reason,
        nonce,
        issued_at,
        "0" * 128,
    )
    signature = key.sign(canonical_vote_envelope_bytes(unsigned)).hex()
    return VoteEnvelope(
        protocol_version,
        unsigned.voter_id,
        derived,
        task_id,
        assignment_id,
        producer_id,
        artifact_id,
        content_hash,
        constitutional_hash,
        unsigned.assigned_peers_hash,
        unsigned.assigned_peer_count,
        unsigned.quorum,
        unsigned.evidence_mode,
        decision,
        reason,
        nonce,
        issued_at,
        signature,
    )


def verify_vote_envelope(
    envelope: VoteEnvelope | Mapping[str, object],
    registry: VoteSignerRegistry,
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    required_role: str = "voter",
    replay_guard: Any | None = None,
) -> VoteEnvelope:
    item = (
        vote_envelope_from_dict(envelope)
        if isinstance(envelope, Mapping)
        else _validate(envelope)
    )
    key = registry.authorize(item.voter_id, item.key_id, role=required_role)
    for name, expected in {
        "task_id": task_id,
        "assignment_id": assignment_id,
        "producer_id": producer_id,
        "artifact_id": artifact_id,
        "content_hash": content_hash,
        "constitutional_hash": constitutional_hash,
    }.items():
        if getattr(item, name) != expected:
            raise ValueError(f"vote envelope {name} binding does not match")
    try:
        key.verify(bytes.fromhex(item.signature), canonical_vote_envelope_bytes(item))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("vote envelope signature is invalid") from exc
    if replay_guard is not None:
        replay_guard.admit(item.voter_id, item.nonce, item.issued_at)
    return item


def verify_vote_envelopes(
    envelopes: Sequence[VoteEnvelope | Mapping[str, object]],
    registry: VoteSignerRegistry,
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    required_role: str = "voter",
    expected_assigned_peers: Sequence[str] | None = None,
    expected_quorum: int | None = None,
    require_independent: bool = True,
) -> tuple[VoteEnvelope, ...]:
    decoded = tuple(
        vote_envelope_from_dict(item) if isinstance(item, Mapping) else _validate(item)
        for item in envelopes
    )
    if len({item.voter_id for item in decoded}) != len(decoded):
        raise ValueError("vote envelopes must contain distinct voter identities")
    if len({item.key_id for item in decoded}) != len(decoded):
        raise ValueError("duplicate signer key in vote envelopes")
    if not decoded:
        raise ValueError("signed vote envelope evidence is required")
    electorate = {
        (
            item.assigned_peers_hash,
            item.assigned_peer_count,
            item.quorum,
            item.evidence_mode,
        )
        for item in decoded
    }
    if len(electorate) != 1:
        raise ValueError("vote envelopes disagree on assigned electorate metadata")
    assigned_hash, assigned_count, quorum, evidence_mode = next(iter(electorate))
    if len(decoded) != assigned_count:
        raise ValueError("vote envelopes do not contain the complete assigned electorate")
    actual_peers = tuple(item.voter_id for item in decoded)
    if canonical_assigned_peers_hash(actual_peers) != assigned_hash:
        raise ValueError("vote envelope voter set does not match assigned_peers_hash")
    if expected_assigned_peers is not None:
        expected = _canonical_assigned_peers(expected_assigned_peers)
        if len(expected) != assigned_count or canonical_assigned_peers_hash(expected) != assigned_hash:
            raise ValueError("vote envelope assigned electorate does not match expected peers")
    if expected_quorum is not None and quorum != expected_quorum:
        raise ValueError("vote envelope quorum does not match expected quorum")
    if require_independent and evidence_mode != "independent":
        raise ValueError("independent vote evidence is required")
    producer_identity = normalize_voter_id(producer_id)
    if any(item.voter_id == producer_identity for item in decoded):
        raise ValueError("producer identity cannot submit a validation vote")
    result = tuple(
        verify_vote_envelope(
            e,
            registry,
            task_id=task_id,
            assignment_id=assignment_id,
            producer_id=producer_id,
            artifact_id=artifact_id,
            content_hash=content_hash,
            constitutional_hash=constitutional_hash,
            required_role=required_role,
        )
        for e in decoded
    )
    return result


def vote_envelope_hash(envelope: VoteEnvelope | Mapping[str, object]) -> str:
    item = (
        vote_envelope_from_dict(envelope) if isinstance(envelope, Mapping) else envelope
    )
    return hashlib.sha256(
        canonical_vote_envelope_bytes(item, include_signature=True)
    ).hexdigest()


def compute_vote_envelope_root(
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    accepted: bool,
    envelopes: Sequence[VoteEnvelope | Mapping[str, object]],
) -> str:
    items = [
        vote_envelope_from_dict(e) if isinstance(e, Mapping) else _validate(e)
        for e in envelopes
    ]
    items.sort(key=lambda e: (e.voter_id, e.key_id))
    return compute_vote_envelope_root_from_hashes(
        task_id=task_id,
        assignment_id=assignment_id,
        producer_id=producer_id,
        artifact_id=artifact_id,
        content_hash=content_hash,
        constitutional_hash=constitutional_hash,
        accepted=accepted,
        envelope_hashes=tuple(vote_envelope_hash(e) for e in items),
    )


def compute_vote_envelope_root_from_hashes(
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    accepted: bool,
    envelope_hashes: Sequence[str],
) -> str:
    payload = {
        "accepted": accepted,
        "artifact_id": artifact_id,
        "assignment_id": assignment_id,
        "constitutional_hash": constitutional_hash,
        "content_hash": content_hash,
        "envelope_hashes": list(envelope_hashes),
        "producer_id": producer_id,
        "task_id": task_id,
    }
    return hashlib.sha256(
        _ROOT_DOMAIN
        + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


__all__ = [
    "VOTE_ENVELOPE_PROTOCOL_VERSION",
    "VoteEnvelope",
    "VoteSignerRegistry",
    "canonical_assigned_peers_hash",
    "canonical_vote_envelope_bytes",
    "compute_vote_envelope_root",
    "compute_vote_envelope_root_from_hashes",
    "key_id_for_public_key",
    "normalize_voter_id",
    "sign_vote_envelope",
    "verify_vote_envelope",
    "verify_vote_envelopes",
    "vote_envelope_from_dict",
    "vote_envelope_hash",
    "vote_envelope_to_dict",
]
