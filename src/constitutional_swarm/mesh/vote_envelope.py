"""Canonical signed vote evidence shared by mesh protocol consumers."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Literal, Protocol
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNED_ASSIGNMENT_PROTOCOL_VERSION = 1
VOTE_ENVELOPE_PROTOCOL_VERSION = 3
_ASSIGNMENT_DOMAIN = b"constitutional-swarm.signed-assignment.v1\x00"
_ASSIGNMENT_DIGEST_DOMAIN = b"constitutional-swarm.signed-assignment-digest.v1\x00"
_VOTE_DOMAIN_V2 = b"constitutional-swarm.vote-envelope.v2\x00"
_VOTE_DOMAIN_V3 = b"constitutional-swarm.vote-envelope.v3\x00"
_ROOT_DOMAIN = b"constitutional-swarm.vote-envelope-root.v2\x00"
_ASSIGNED_PEERS_DOMAIN = b"constitutional-swarm.assigned-peers.v1\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_V2_FIELDS = (
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
_V3_FIELDS = (*_V2_FIELDS[:-1], "assignment_digest", "signature")
_ASSIGNMENT_FIELDS = (
    "protocol_version", "task_id", "assignment_id", "assigner_id", "key_id",
    "producer_id", "artifact_id", "content_hash", "constitutional_hash",
    "assigned_peers", "quorum", "selection_seed", "issued_at", "signature",
)


@dataclass(frozen=True, slots=True)
class SignedAssignment:
    """Authority-signed, immutable electorate selection."""

    protocol_version: int
    task_id: str
    assignment_id: str
    assigner_id: str
    key_id: str
    producer_id: str
    artifact_id: str
    content_hash: str
    constitutional_hash: str
    assigned_peers: tuple[str, ...]
    quorum: int
    selection_seed: str
    issued_at: float
    signature: str

    def __post_init__(self) -> None:
        _validate_assignment(self)


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
    assignment_digest: str = ""

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def approved(self) -> bool:
        return self.decision == "approved"


def normalize_voter_id(value: str) -> str:
    if type(value) is not str:
        raise TypeError("voter_id must be a string")
    value = unicodedata.normalize("NFKC", value)
    value = (
        "".join(c for c in value if unicodedata.category(c) != "Cf").strip().casefold()
    )
    if not value:
        raise ValueError("voter_id must not be empty after normalization")
    return value


def _hex(value: str, pattern: re.Pattern[str], name: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} must be canonical lowercase hex")
    return value


def _public(value: Ed25519PublicKey | bytes | str) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        raw = value.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    elif isinstance(value, str):
        raw = bytes.fromhex(_hex(str.__str__(value), _HEX64, "public key"))
    else:
        raw = value
    if not isinstance(raw, bytes):
        raise TypeError("invalid public key type")
    try:
        return Ed25519PublicKey.from_public_bytes(bytes(raw))
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


class VoteSignerRegistryView(Protocol):
    """Read-only trust-root surface required by vote evidence verifiers."""

    def authorize(
        self, voter_id: str, key_id: str, *, role: str = "voter"
    ) -> Ed25519PublicKey: ...

    def public_key_for_identity(
        self, identity: str
    ) -> Ed25519PublicKey | None: ...

    def trust_grants(self, *, role: str = "validator") -> dict[str, dict[str, object]]: ...

    def validate_trust_root(self) -> None: ...


_VOTING_ROLES = frozenset({"voter", "validator"})


def _validate_registry_grants(grants: Sequence[_Grant]) -> tuple[_Grant, ...]:
    """Validate canonical registry state and assignment-authority separation."""
    copied = tuple(grants)
    identities: dict[str, _Grant] = {}
    key_material: dict[bytes, _Grant] = {}
    canonical: list[_Grant] = []
    for grant in copied:
        if type(grant) is not _Grant:
            raise TypeError("vote signer grants must be exact registry grants")
        if type(grant.roles) is not frozenset:
            raise TypeError("vote signer grant roles must be an immutable frozenset")
        if (
            type(grant.identity) is not str
            or type(grant.key_id) is not str
            or any(type(role) is not str for role in grant.roles)
        ):
            raise TypeError("vote signer identity, key ID, and roles must be exact strings")
        grant = _Grant(grant.identity, grant.key_id, _public(grant.key), grant.roles)
        if grant.identity != normalize_voter_id(grant.identity):
            raise ValueError("vote signer identity must use its canonical normalized form")
        if grant.key_id != key_id_for_public_key(grant.key):
            raise ValueError("vote signer key ID must equal the public-key fingerprint")
        if not grant.roles or any(
            not role.strip() or role != role.strip().casefold()
            for role in grant.roles
        ):
            raise ValueError("vote signer roles must be non-empty canonical strings")
        if "assigner" in grant.roles and grant.roles & _VOTING_ROLES:
            raise ValueError(
                "assigner and voter/validator roles are mutually exclusive"
            )
        if grant.identity in identities:
            raise ValueError("vote signer identities must be unique")
        raw_key = grant.key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        existing = key_material.get(raw_key)
        if existing is not None:
            crosses_authority_boundary = (
                "assigner" in existing.roles and bool(grant.roles & _VOTING_ROLES)
            ) or (
                "assigner" in grant.roles and bool(existing.roles & _VOTING_ROLES)
            )
            if crosses_authority_boundary:
                raise ValueError(
                    "assigner key must not be used by a voter/validator identity"
                )
            raise ValueError("vote signer public keys must be unique")
        identities[grant.identity] = grant
        key_material[raw_key] = grant
        canonical.append(grant)
    return tuple(canonical)


def _validate_registry_indexes(
    grants: Sequence[_Grant],
    identities: Mapping[str, _Grant],
    keys: Mapping[str, str],
) -> None:
    validated = _validate_registry_grants(grants)
    expected_identities = {grant.identity: grant for grant in validated}
    expected_keys = {grant.key_id: grant.identity for grant in validated}
    if dict(identities) != expected_identities:
        raise ValueError("vote signer identity index does not match registry grants")
    if dict(keys) != expected_keys:
        raise ValueError("vote signer key index does not match registry grants")


def _export_trust_grants(
    grants: Sequence[_Grant], *, role: str
) -> dict[str, dict[str, object]]:
    required = role.strip().casefold()
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


@dataclass(frozen=True, slots=True, init=False)
class FrozenVoteSignerRegistry:
    """Immutable public-key trust-root snapshot with no mutation capability."""

    _grants: tuple[_Grant, ...]
    _identities: Mapping[str, _Grant]
    _keys: Mapping[str, str]

    def __init__(self, grants: Sequence[_Grant]) -> None:
        copied = _validate_registry_grants(grants)
        identities = {grant.identity: grant for grant in copied}
        keys = {grant.key_id: grant.identity for grant in copied}
        object.__setattr__(self, "_grants", copied)
        object.__setattr__(self, "_identities", MappingProxyType(identities))
        object.__setattr__(self, "_keys", MappingProxyType(keys))

    @property
    def frozen(self) -> bool:
        return True

    def authorize(
        self, voter_id: str, key_id: str, *, role: str = "voter"
    ) -> Ed25519PublicKey:
        identity, role = normalize_voter_id(voter_id), role.strip().casefold()
        _hex(key_id, _HEX64, "key_id")
        grant = self._identities.get(identity)
        if grant is None or grant.key_id != key_id:
            raise ValueError("vote signer identity and key are not authorized")
        if role not in grant.roles:
            raise ValueError(f"vote signer is not authorized for role {role!r}")
        return grant.key

    def public_key_for_identity(self, identity: str) -> Ed25519PublicKey | None:
        grant = self._identities.get(normalize_voter_id(identity))
        return None if grant is None else grant.key

    def trust_grants(self, *, role: str = "validator") -> dict[str, dict[str, object]]:
        return _export_trust_grants(self._grants, role=role)

    def validate_trust_root(self) -> None:
        _validate_registry_indexes(self._grants, self._identities, self._keys)

    def frozen_copy(self) -> FrozenVoteSignerRegistry:
        """Return this immutable snapshot for safe snapshot chaining."""
        return self


class VoteSignerRegistry:
    def __init__(self) -> None:
        self._identities: dict[str, _Grant] = {}
        self._keys: dict[str, str] = {}
        self._lock = threading.RLock()

    @property
    def frozen(self) -> bool:
        return False

    def register(
        self,
        voter_id: str,
        public_key: Ed25519PublicKey | bytes | str,
        *,
        roles: Collection[str] = frozenset({"voter"}),
    ) -> str:
        if isinstance(roles, (str, bytes)):
            raise TypeError("roles must be a collection of role names")
        role_values = tuple(roles)
        if any(type(role) is not str or not role.strip() for role in role_values):
            raise ValueError("signer roles must be non-empty strings")
        identity, key = normalize_voter_id(voter_id), _public(public_key)
        key_id = key_id_for_public_key(key)
        role_set = frozenset(
            role.strip().casefold()
            for role in role_values
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
            candidate = _Grant(identity, key_id, key, role_set)
            _validate_registry_grants(
                tuple(
                    candidate if grant.identity == identity else grant
                    for grant in self._identities.values()
                )
                + (() if old is not None else (candidate,))
            )
            self._identities[identity] = candidate
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

    def public_key_for_identity(self, identity: str) -> Ed25519PublicKey | None:
        normalized = normalize_voter_id(identity)
        with self._lock:
            grant = self._identities.get(normalized)
            return None if grant is None else grant.key

    def unregister(self, voter_id: str) -> None:
        """Remove one explicitly managed signer identity."""
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
        if isinstance(roles, (str, bytes)):
            raise TypeError("roles must be a collection of role names")
        role_values = tuple(roles)
        if any(type(role) is not str or not role.strip() for role in role_values):
            raise ValueError("signer roles must be non-empty strings")
        identity, key = normalize_voter_id(voter_id), _public(public_key)
        key_id = key_id_for_public_key(key)
        role_set = frozenset(role.strip().casefold() for role in role_values)
        if not role_set:
            raise ValueError("signer roles must not be empty")
        with self._lock:
            owner = self._keys.get(key_id)
            if owner is not None and owner != identity:
                raise ValueError(
                    "public key is already registered to another voter identity"
                )
            old = self._identities.get(identity)
            candidate = _Grant(identity, key_id, key, role_set)
            _validate_registry_grants(
                tuple(
                    candidate if grant.identity == identity else grant
                    for grant in self._identities.values()
                )
                + (() if old is not None else (candidate,))
            )
            if old is not None and old.key_id != key_id:
                self._keys.pop(old.key_id, None)
            self._identities[identity] = candidate
            self._keys[key_id] = identity
        return key_id

    def trust_grants(self, *, role: str = "validator") -> dict[str, dict[str, object]]:
        """Export immutable public grants for consumers of verified vote evidence."""
        with self._lock:
            grants = tuple(self._identities.values())
        return _export_trust_grants(grants, role=role)

    def validate_trust_root(self) -> None:
        with self._lock:
            grants = tuple(self._identities.values())
            identities = dict(self._identities)
            keys = dict(self._keys)
        _validate_registry_indexes(grants, identities, keys)

    def frozen_copy(self) -> FrozenVoteSignerRegistry:
        """Return an immutable public-key-only snapshot of this trust root."""
        with self._lock:
            grants = tuple(self._identities.values())
        return FrozenVoteSignerRegistry(grants)


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


def _validate_assignment(item: object) -> SignedAssignment:
    if not isinstance(item, SignedAssignment):
        raise ValueError("signed assignment is required")
    if type(item.protocol_version) is not int or item.protocol_version != 1:
        raise ValueError("unsupported signed assignment protocol version")
    if item.assigner_id != normalize_voter_id(item.assigner_id):
        raise ValueError("assigner_id must use its canonical normalized form")
    _hex(item.key_id, _HEX64, "key_id")
    for name in (
        "task_id", "assignment_id", "producer_id", "artifact_id", "content_hash",
        "constitutional_hash", "selection_seed",
    ):
        if not isinstance(getattr(item, name), str) or not getattr(item, name):
            raise ValueError(f"{name} must be a non-empty string")
    canonical_peers = _canonical_assigned_peers(item.assigned_peers)
    if item.assigned_peers != canonical_peers:
        raise ValueError("assigned_peers must be normalized and sorted")
    if item.producer_id != normalize_voter_id(item.producer_id):
        raise ValueError("producer_id must use its canonical normalized form")
    if item.producer_id in canonical_peers:
        raise ValueError("producer_id must not be included in assigned_peers")
    if item.assigner_id in canonical_peers:
        raise ValueError("assigner_id must not be included in assigned_peers")
    if type(item.quorum) is not int or not 1 <= item.quorum <= len(canonical_peers):
        raise ValueError("quorum must be within the assigned electorate")
    if item.quorum <= len(canonical_peers) // 2:
        raise ValueError("quorum must be a strict majority of assigned_peers")
    if type(item.issued_at) is not float or not math.isfinite(item.issued_at):
        raise ValueError("issued_at must be a finite float")
    _hex(item.signature, _HEX128, "signature")
    return item


def signed_assignment_to_dict(item: SignedAssignment) -> dict[str, object]:
    _validate_assignment(item)
    result = {name: getattr(item, name) for name in _ASSIGNMENT_FIELDS}
    result["assigned_peers"] = list(item.assigned_peers)
    return result


def signed_assignment_from_dict(data: Mapping[str, object]) -> SignedAssignment:
    if set(data) != set(_ASSIGNMENT_FIELDS):
        raise ValueError("signed assignment schema fields mismatch")
    values: dict[str, Any] = dict(data)
    peers = values["assigned_peers"]
    if not isinstance(peers, (list, tuple)) or any(not isinstance(peer, str) for peer in peers):
        raise TypeError("assigned_peers must be a sequence of strings")
    values["assigned_peers"] = tuple(peers)
    for name in set(_ASSIGNMENT_FIELDS) - {"protocol_version", "assigned_peers", "quorum", "issued_at"}:
        if not isinstance(values[name], str):
            raise TypeError(f"{name} must be a string")
    if type(values["protocol_version"]) is not int or type(values["quorum"]) is not int or type(values["issued_at"]) is not float:
        raise TypeError("invalid signed assignment scalar type")
    return _validate_assignment(SignedAssignment(**values))


def canonical_signed_assignment_bytes(item: SignedAssignment, *, include_signature: bool = False) -> bytes:
    payload = signed_assignment_to_dict(item)
    if not include_signature:
        payload.pop("signature")
    return _ASSIGNMENT_DOMAIN + json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def signed_assignment_digest(assignment: SignedAssignment | Mapping[str, object]) -> str:
    item = signed_assignment_from_dict(assignment) if isinstance(assignment, Mapping) else _validate_assignment(assignment)
    return hashlib.sha256(_ASSIGNMENT_DIGEST_DOMAIN + canonical_signed_assignment_bytes(item, include_signature=True)).hexdigest()


def sign_assignment(
    private_key: Ed25519PrivateKey | bytes | str, *, task_id: str,
    assignment_id: str, assigner_id: str, producer_id: str, artifact_id: str,
    content_hash: str, constitutional_hash: str, assigned_peers: Sequence[str],
    quorum: int, selection_seed: str, issued_at: float, key_id: str | None = None,
    protocol_version: int = SIGNED_ASSIGNMENT_PROTOCOL_VERSION,
) -> SignedAssignment:
    key = _private(private_key)
    derived = key_id_for_public_key(key.public_key())
    if key_id is not None and _hex(key_id, _HEX64, "key_id") != derived:
        raise ValueError("key_id does not match the assignment signing key")
    unsigned = SignedAssignment(
        protocol_version, task_id, assignment_id, normalize_voter_id(assigner_id),
        derived, normalize_voter_id(producer_id), artifact_id, content_hash, constitutional_hash,
        _canonical_assigned_peers(assigned_peers), quorum, selection_seed, issued_at,
        "0" * 128,
    )
    return replace(
        unsigned,
        signature=key.sign(canonical_signed_assignment_bytes(unsigned)).hex(),
    )


def verify_signed_assignment(
    assignment: SignedAssignment | Mapping[str, object], registry: VoteSignerRegistryView,
    *, task_id: str, assignment_id: str, producer_id: str, artifact_id: str,
    content_hash: str, constitutional_hash: str,
) -> SignedAssignment:
    item = signed_assignment_from_dict(assignment) if isinstance(assignment, Mapping) else _validate_assignment(assignment)
    registry.validate_trust_root()
    key = _public(registry.authorize(item.assigner_id, item.key_id, role="assigner"))
    if item.assigner_id == normalize_voter_id(item.producer_id):
        raise ValueError(
            "signed assignment assigner identity must differ from producer identity"
        )
    producer_key = registry.public_key_for_identity(item.producer_id)
    if producer_key is not None:
        producer_key = _public(producer_key)
    if producer_key is not None and producer_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ):
        raise ValueError("signed assignment assigner and producer keys must differ")
    for name, expected in {
        "task_id": task_id, "assignment_id": assignment_id, "producer_id": producer_id,
        "artifact_id": artifact_id, "content_hash": content_hash,
        "constitutional_hash": constitutional_hash,
    }.items():
        if getattr(item, name) != expected:
            raise ValueError(f"signed assignment {name} binding does not match")
    try:
        key.verify(bytes.fromhex(item.signature), canonical_signed_assignment_bytes(item))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("signed assignment signature is invalid") from exc
    return item


def _validate(item: VoteEnvelope) -> VoteEnvelope:
    if type(item.protocol_version) is not int or item.protocol_version not in {2, 3}:
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
    if item.protocol_version == 3:
        _hex(item.assignment_digest, _HEX64, "assignment_digest")
    elif item.assignment_digest:
        raise ValueError("legacy vote envelope must not contain assignment_digest")
    return item


def vote_envelope_to_dict(item: VoteEnvelope) -> dict[str, object]:
    _validate(item)
    fields = _V3_FIELDS if item.protocol_version == 3 else _V2_FIELDS
    return {name: getattr(item, name) for name in fields}


def vote_envelope_from_dict(data: Mapping[str, object]) -> VoteEnvelope:
    fields = _V3_FIELDS if data.get("protocol_version") == 3 else _V2_FIELDS
    if set(data) != set(fields):
        raise ValueError("vote envelope schema fields mismatch")
    values: dict[str, Any] = dict(data)
    values.setdefault("assignment_digest", "")
    for name in set(fields) - {
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
        (_VOTE_DOMAIN_V3 if item.protocol_version == 3 else _VOTE_DOMAIN_V2)
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
    assignment_digest: str = "",
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
        assignment_digest,
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
        assignment_digest,
    )


def verify_vote_envelope(
    envelope: VoteEnvelope | Mapping[str, object],
    registry: VoteSignerRegistryView,
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    required_role: str = "voter",
    replay_guard: Any | None = None,
    expected_assignment_digest: str | None = None,
) -> VoteEnvelope:
    item = (
        vote_envelope_from_dict(envelope)
        if isinstance(envelope, Mapping)
        else _validate(envelope)
    )
    key = _public(registry.authorize(item.voter_id, item.key_id, role=required_role))
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
    if expected_assignment_digest is not None and item.assignment_digest != expected_assignment_digest:
        raise ValueError("vote envelope assignment digest does not match")
    try:
        key.verify(bytes.fromhex(item.signature), canonical_vote_envelope_bytes(item))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("vote envelope signature is invalid") from exc
    if replay_guard is not None:
        replay_guard.admit(item.voter_id, item.nonce, item.issued_at)
    return item


def verify_vote_envelopes(
    envelopes: Sequence[VoteEnvelope | Mapping[str, object]],
    registry: VoteSignerRegistryView,
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
    """Verify raw signatures and self-described electorate metadata.

    This is a low-level historical primitive, not proof-grade authorization.
    Public consumers must use :func:`verify_assignment_vote_envelopes` so the
    electorate and quorum come from a trusted assignment authority.
    """
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


def verify_assignment_vote_envelopes(
    signed_assignment: SignedAssignment | Mapping[str, object],
    envelopes: Sequence[VoteEnvelope | Mapping[str, object]],
    registry: VoteSignerRegistryView, *, task_id: str, assignment_id: str,
    producer_id: str, artifact_id: str, content_hash: str, constitutional_hash: str,
    require_independent: bool = True, required_role: str = "voter",
    expected_assigned_peers: Sequence[str] | None = None,
    expected_quorum: int | None = None,
) -> tuple[VoteEnvelope, ...]:
    assignment = verify_signed_assignment(
        signed_assignment, registry, task_id=task_id, assignment_id=assignment_id,
        producer_id=producer_id, artifact_id=artifact_id, content_hash=content_hash,
        constitutional_hash=constitutional_hash,
    )
    decoded = tuple(vote_envelope_from_dict(item) if isinstance(item, Mapping) else _validate(item) for item in envelopes)
    if any(item.protocol_version != 3 for item in decoded):
        raise ValueError("proof-grade vote evidence requires protocol version 3")
    digest = signed_assignment_digest(assignment)
    if any(item.assignment_digest != digest for item in decoded):
        raise ValueError("vote envelope assignment digest does not match")
    if expected_assigned_peers is not None and _canonical_assigned_peers(expected_assigned_peers) != assignment.assigned_peers:
        raise ValueError("signed assignment electorate does not match expected peers")
    if expected_quorum is not None and expected_quorum != assignment.quorum:
        raise ValueError("signed assignment quorum does not match expected quorum")
    verified = verify_vote_envelopes(
        decoded, registry, task_id=task_id, assignment_id=assignment_id,
        producer_id=producer_id, artifact_id=artifact_id, content_hash=content_hash,
        constitutional_hash=constitutional_hash, required_role=required_role,
        expected_assigned_peers=assignment.assigned_peers,
        expected_quorum=assignment.quorum, require_independent=require_independent,
    )
    assigner_key = registry.authorize(
        assignment.assigner_id,
        assignment.key_id,
        role="assigner",
    )
    assigner_key_bytes = assigner_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    for item in verified:
        voter_key = registry.authorize(
            item.voter_id,
            item.key_id,
            role=required_role,
        )
        if item.key_id == assignment.key_id or voter_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ) == assigner_key_bytes:
            raise ValueError("assigner key must not be used by a voter identity")
    return verified


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
    "SIGNED_ASSIGNMENT_PROTOCOL_VERSION",
    "VOTE_ENVELOPE_PROTOCOL_VERSION",
    "FrozenVoteSignerRegistry",
    "SignedAssignment",
    "VoteEnvelope",
    "VoteSignerRegistry",
    "VoteSignerRegistryView",
    "canonical_assigned_peers_hash",
    "canonical_signed_assignment_bytes",
    "canonical_vote_envelope_bytes",
    "compute_vote_envelope_root",
    "compute_vote_envelope_root_from_hashes",
    "key_id_for_public_key",
    "normalize_voter_id",
    "sign_assignment",
    "sign_vote_envelope",
    "signed_assignment_digest",
    "signed_assignment_from_dict",
    "signed_assignment_to_dict",
    "verify_assignment_vote_envelopes",
    "verify_signed_assignment",
    "verify_vote_envelope",
    "verify_vote_envelopes",
    "vote_envelope_from_dict",
    "vote_envelope_hash",
    "vote_envelope_to_dict",
]
