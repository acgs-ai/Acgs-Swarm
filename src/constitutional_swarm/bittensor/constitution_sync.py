"""Constitution Sync — constitution distribution to subnet nodes.

The SN Owner is the authoritative source of the active constitution.
Every miner and validator must independently verify their constitution
hash matches the SN Owner's before accepting any governance task.

Three components:
  ConstitutionDistributor  — SN Owner side: serialize + version-stamp
  ConstitutionReceiver     — Miner/Validator side: receive, verify, activate
  ConstitutionVersionRecord — Immutable version history entry

Design invariants:
  • Hash verification is mandatory — no silent drift between nodes
  • Version history is append-only — old versions never overwritten
  • Sync is pull-based by default — nodes request from SN Owner
  • No Bittensor SDK required — transport is pluggable via callback
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..epoch_reconfig import (
    ConstitutionVersion,
    InvalidTransitionError,
    TransitionCertificate,
    TransitionVerificationPolicy,
    compute_validator_set_digest,
    verify_transition,
)
from ..framing import framed_digest, require_plain_id
from ..validator_set import ValidatorSet

_SYNC_WIRE_VERSION = 2
_LEGACY_WIRE_VERSION = 1
_SYNC_SIGNATURE_DOMAIN = b"constitutional-swarm/constitution-sync/v2"
_SYNC_COMMITMENT_DOMAIN = b"constitutional-swarm/constitution-sync/commitment/v2"
_NANOSECONDS_PER_SECOND = 1_000_000_000
_MAX_TIMESTAMP_NS = (1 << 63) - 1


def _seconds_to_nanoseconds(
    value: object,
    *,
    field_name: str,
    allow_zero: bool,
) -> int:
    """Convert bounded seconds to nanoseconds without float overflow."""
    if type(value) not in (int, float):
        raise ValueError(f"{field_name} must be a finite non-negative number")
    numeric_value = cast(int | float, value)
    if type(numeric_value) is float and not math.isfinite(numeric_value):
        raise ValueError(f"{field_name} must be a finite non-negative number")
    if numeric_value < 0 or (not allow_zero and numeric_value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{field_name} must be a finite {qualifier} number")
    if type(numeric_value) is int:
        nanoseconds = numeric_value * _NANOSECONDS_PER_SECOND
    else:
        product = numeric_value * _NANOSECONDS_PER_SECOND
        if not math.isfinite(product):
            raise ValueError(f"{field_name} is outside the nanosecond range")
        nanoseconds = int(product)
    if nanoseconds > _MAX_TIMESTAMP_NS or (not allow_zero and nanoseconds == 0):
        raise ValueError(f"{field_name} is outside the nanosecond range")
    return nanoseconds

# ---------------------------------------------------------------------------
# Version record (immutable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConstitutionVersionRecord:
    """Immutable record of a specific constitution version.

    Each version is identified by its hash (content-addressed).
    Block height is set when anchored to chain; None until then.
    """

    version_id: str
    constitution_hash: str
    yaml_content: str
    activated_at: float
    version: int = 1
    block_height: int | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version <= 0
        ):
            raise ValueError("version must be a positive integer")

    @classmethod
    def create(
        cls,
        yaml_content: str,
        version: int = 1,
        description: str = "",
        block_height: int | None = None,
    ) -> ConstitutionVersionRecord:
        if type(yaml_content) is not str:
            raise TypeError("yaml_content must be an exact string")
        content_hash = hashlib.sha256(yaml_content.encode()).hexdigest()[:16]
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("version must be a positive integer")
        return cls(
            version_id=uuid.uuid4().hex[:8],
            version=version,
            constitution_hash=content_hash,
            yaml_content=yaml_content,
            activated_at=time.time(),
            block_height=block_height,
            description=description,
        )

    @property
    def age_seconds(self) -> float:
        return time.time() - self.activated_at


# ---------------------------------------------------------------------------
# Sync message
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConstitutionSyncMessage:
    """Broadcast message from SN Owner carrying the active constitution.

    Nodes verify `expected_hash` matches their locally computed hash
    of `yaml_content` before activating the constitution.
    """

    version_id: str
    expected_hash: str
    yaml_content: str
    issued_at: int | float
    version: int = 0
    issuer_id: str = "subnet-owner"
    block_height: int | None = None
    description: str = ""
    signature: bytes | None = None
    wire_version: int = _SYNC_WIRE_VERSION
    content_digest: bytes = b""

    def __post_init__(self) -> None:
        if type(self.yaml_content) is not str:
            raise ValueError("Invalid yaml_content: exact string required")
        error = _message_shape_error(self, allow_legacy_v1=True)
        if error is not None:
            raise ValueError(error)

    def verify(self) -> bool:
        """Verify the embedded hash matches the content."""
        digest = hashlib.sha256(self.yaml_content.encode()).digest()
        if self.wire_version == _LEGACY_WIRE_VERSION:
            return digest.hex()[:16] == self.expected_hash
        return digest == self.content_digest and digest.hex()[:16] == self.expected_hash

    def signing_payload(self) -> bytes:
        if self.wire_version == _LEGACY_WIRE_VERSION:
            return self._legacy_v1_signing_payload()
        block_height_present = self.block_height is not None
        return framed_digest(
            _SYNC_SIGNATURE_DOMAIN,
            self.wire_version,
            self.version_id,
            self.version,
            self.content_digest,
            self.yaml_content,
            cast(int, self.issued_at),
            self.issuer_id,
            int(block_height_present),
            cast(int, self.block_height) if block_height_present else 0,
            self.description,
        )

    def _legacy_v1_signing_payload(self) -> bytes:
        """Return the historical v1 payload byte-for-byte."""
        payload = {
            "version_id": self.version_id,
            "version": self.version,
            "expected_hash": self.expected_hash,
            "yaml_content": self.yaml_content,
            "issued_at": self.issued_at,
            "issuer_id": self.issuer_id,
            "block_height": self.block_height,
            "description": self.description,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def commitment_digest(self) -> bytes:
        """Return the canonical digest bound by governed transition certificates."""
        if self.wire_version == _LEGACY_WIRE_VERSION:
            return hashlib.sha256(self.signing_payload()).digest()
        return framed_digest(_SYNC_COMMITMENT_DOMAIN, self.signing_payload())

    def verify_signature(self, trusted_issuer_keys: dict[str, bytes]) -> bool:
        if type(self.signature) is not bytes or len(self.signature) != 64:
            return False
        key_bytes = trusted_issuer_keys.get(self.issuer_id)
        if type(key_bytes) is not bytes or len(key_bytes) != 32:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                self.signature, self.signing_payload()
            )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, Any]:
        if self.wire_version == _LEGACY_WIRE_VERSION:
            return {
                "version_id": self.version_id,
                "version": self.version,
                "expected_hash": self.expected_hash,
                "yaml_content": self.yaml_content,
                "issued_at": self.issued_at,
                "issuer_id": self.issuer_id,
                "block_height": self.block_height,
                "description": self.description,
                "signature": self.signature.hex() if self.signature is not None else None,
            }
        return {
            "wire_version": self.wire_version,
            "version_id": self.version_id,
            "version": self.version,
            "expected_hash": self.expected_hash,
            "content_digest": self.content_digest.hex(),
            "yaml_content": self.yaml_content,
            "issued_at": self.issued_at,
            "issuer_id": self.issuer_id,
            "block_height": self.block_height,
            "description": self.description,
            "signature": self.signature.hex() if self.signature is not None else None,
        }

    @classmethod
    def from_dict(
        cls, d: dict[str, Any], *, allow_legacy_v1: bool = False
    ) -> ConstitutionSyncMessage:
        if type(d) is not dict:
            raise TypeError("sync message must be an exact dictionary")
        wire_version = d.get("wire_version", _LEGACY_WIRE_VERSION)
        if type(wire_version) is not int:
            raise TypeError("wire_version must be an integer")
        if wire_version == _LEGACY_WIRE_VERSION and not allow_legacy_v1:
            raise ValueError("legacy wire version requires explicit opt-in")
        required = {
            "version_id",
            "version",
            "expected_hash",
            "yaml_content",
            "issued_at",
            "issuer_id",
            "block_height",
            "description",
            "signature",
        }
        if wire_version == _SYNC_WIRE_VERSION:
            required |= {"wire_version", "content_digest"}
        elif "wire_version" in d:
            required.add("wire_version")
        if set(d) != required:
            raise ValueError("sync message fields do not match the wire version")
        signature_hex = d["signature"]
        if signature_hex is not None and type(signature_hex) is not str:
            raise TypeError("signature must be a hexadecimal string or null")
        digest_hex = d.get("content_digest", "")
        if type(digest_hex) is not str:
            raise TypeError("content_digest must be a hexadecimal string")
        try:
            signature = bytes.fromhex(signature_hex) if signature_hex is not None else None
            content_digest = bytes.fromhex(digest_hex) if digest_hex else b""
        except ValueError as exc:
            raise ValueError("signature and content_digest must be hexadecimal") from exc
        return cls(
            version_id=d["version_id"],
            version=d["version"],
            expected_hash=d["expected_hash"],
            content_digest=content_digest,
            yaml_content=d["yaml_content"],
            issued_at=d["issued_at"],
            issuer_id=d["issuer_id"],
            block_height=d["block_height"],
            description=d["description"],
            signature=signature,
            wire_version=wire_version,
        )


def _message_shape_error(msg: object, *, allow_legacy_v1: bool) -> str | None:
    """Validate concrete message fields without invoking message-controlled code."""
    if type(msg) is not ConstitutionSyncMessage:
        return "Invalid sync message type"
    try:
        wire_version = msg.wire_version
        version_id = msg.version_id
        version = msg.version
        expected_hash = msg.expected_hash
        content_digest = msg.content_digest
        yaml_content = msg.yaml_content
        issued_at = msg.issued_at
        issuer_id = msg.issuer_id
        block_height = msg.block_height
        description = msg.description
        signature = msg.signature
    except AttributeError:
        return "Invalid sync message: required field is missing"
    if type(wire_version) is not int or wire_version not in (
        _LEGACY_WIRE_VERSION,
        _SYNC_WIRE_VERSION,
    ):
        return "Invalid wire version"
    if wire_version == _LEGACY_WIRE_VERSION and not allow_legacy_v1:
        return "Legacy wire version requires explicit opt-in"
    for name, value in (
        ("version_id", version_id),
        ("expected_hash", expected_hash),
        ("yaml_content", yaml_content),
        ("issuer_id", issuer_id),
        ("description", description),
    ):
        if type(value) is not str:
            return f"Invalid {name}: exact string required"
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return f"Invalid {name}: valid UTF-8 required"
    try:
        require_plain_id(version_id)
        require_plain_id(issuer_id)
    except ValueError as exc:
        return f"Invalid message identifier: {exc}"
    if len(expected_hash) != 16 or any(
        char not in "0123456789abcdef" for char in expected_hash
    ):
        return "Invalid expected_hash: 16 lowercase hexadecimal characters required"
    if type(version) is not int or version <= 0:
        return "Version must be a positive integer"
    if block_height is not None and (
        type(block_height) is not int or block_height < 0
    ):
        return "Invalid block_height: non-negative integer or null required"
    if signature is not None and (
        type(signature) is not bytes or len(signature) != 64
    ):
        return "Invalid signature: 64 bytes required"
    if wire_version == _SYNC_WIRE_VERSION:
        if type(issued_at) is not int or issued_at <= 0:
            return "Invalid issued_at: positive integer nanoseconds required"
        if type(content_digest) is not bytes or len(content_digest) != 32:
            return "Invalid content_digest: 32 bytes required"
    else:
        try:
            _seconds_to_nanoseconds(
                issued_at,
                field_name="issued_at",
                allow_zero=False,
            )
        except ValueError as exc:
            return f"Invalid issued_at: {exc}"
        if content_digest != b"":
            return "Invalid legacy content_digest"
    return None


# ---------------------------------------------------------------------------
# Distributor (SN Owner side)
# ---------------------------------------------------------------------------


class ConstitutionDistributor:
    """SN Owner-side constitution broadcaster.

    Maintains an ordered version history and produces
    ConstitutionSyncMessages for distribution to miners/validators.

    Usage::

        signing_key = Ed25519PrivateKey.generate()
        dist = ConstitutionDistributor(
            initial_yaml=open("constitution.yaml").read(),
            signing_key=signing_key,
        )

        # Get the sync message to broadcast
        msg = dist.broadcast_message()

        # Later: update to a new constitution
        dist.update(new_yaml_content, description="Added HIPAA rule")

        # Version history
        for version in dist.version_history:
            print(version.constitution_hash, version.activated_at)
    """

    def __init__(
        self,
        initial_yaml: str,
        signing_key: Ed25519PrivateKey,
        issuer_id: str = "subnet-owner",
        description: str = "initial",
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("signing_key must be an Ed25519PrivateKey")
        require_plain_id(issuer_id)
        self._issuer_id = issuer_id
        self._signing_key = signing_key
        self._lock = threading.RLock()
        self._history: list[ConstitutionVersionRecord] = []
        self._last_issued_at = 0
        self._activate(initial_yaml, description)

    @property
    def active_version(self) -> ConstitutionVersionRecord:
        with self._lock:
            return self._history[-1]

    @property
    def active_hash(self) -> str:
        with self._lock:
            return self._history[-1].constitution_hash

    @property
    def version_history(self) -> list[ConstitutionVersionRecord]:
        with self._lock:
            return list(self._history)

    def update(
        self,
        new_yaml: str,
        description: str = "",
        block_height: int | None = None,
    ) -> ConstitutionVersionRecord:
        """Activate a new constitution version.

        Raises ValueError if the content is identical to the active version
        (no-op updates are rejected to keep the history clean).
        """
        with self._lock:
            if type(new_yaml) is not str:
                raise TypeError("new_yaml must be an exact string")
            new_digest = hashlib.sha256(new_yaml.encode()).digest()
            active_digest = hashlib.sha256(
                self._history[-1].yaml_content.encode()
            ).digest()
            if new_digest == active_digest:
                raise ValueError(
                    "Constitution unchanged. No update recorded."
                )
            return self._activate(new_yaml, description, block_height)

    def broadcast_message(self) -> ConstitutionSyncMessage:
        """Produce a sync message for the active version."""
        with self._lock:
            v = self._history[-1]
            issued_at = time.time_ns()
            if issued_at <= self._last_issued_at:
                issued_at = self._last_issued_at + 1
            self._last_issued_at = issued_at
            unsigned = ConstitutionSyncMessage(
                version_id=v.version_id,
                version=v.version,
                expected_hash=v.constitution_hash,
                content_digest=hashlib.sha256(v.yaml_content.encode()).digest(),
                yaml_content=v.yaml_content,
                issued_at=issued_at,
                issuer_id=self._issuer_id,
                block_height=v.block_height,
                description=v.description,
            )
            return ConstitutionSyncMessage(
                version_id=unsigned.version_id,
                version=unsigned.version,
                expected_hash=unsigned.expected_hash,
                content_digest=unsigned.content_digest,
                yaml_content=unsigned.yaml_content,
                issued_at=unsigned.issued_at,
                issuer_id=unsigned.issuer_id,
                block_height=unsigned.block_height,
                description=unsigned.description,
                signature=self._signing_key.sign(unsigned.signing_payload()),
                wire_version=unsigned.wire_version,
            )

    def _activate(
        self,
        yaml_content: str,
        description: str,
        block_height: int | None = None,
    ) -> ConstitutionVersionRecord:
        version = len(self._history) + 1
        record = ConstitutionVersionRecord.create(
            yaml_content,
            version=version,
            description=description,
            block_height=block_height,
        )
        self._history.append(record)
        return record


# ---------------------------------------------------------------------------
# Receiver (Miner / Validator side)
# ---------------------------------------------------------------------------


@dataclass
class SyncResult:
    """Result of a constitution sync attempt on the receiver side."""

    success: bool
    message: str
    new_hash: str = ""
    old_hash: str = ""
    version_id: str = ""


class ConstitutionReceiver:
    """Miner/Validator-side constitution sync handler.

    Receives ConstitutionSyncMessages from the SN Owner,
    verifies the hash, and activates the new constitution.

    The receiver tracks its version history independently and
    refuses to downgrade to a previously seen constitution version.

    Replay hashes and issuer high-water marks are held in memory and are lost on restart.
    Governed nodes must restore authority through constructor anchors. Deployments should
    persist and restore the high-water mark when replay protection must survive restarts.

    Usage::

        receiver = ConstitutionReceiver(node_id="miner-01")

        # On startup: request initial constitution from SN Owner
        msg = distributor.broadcast_message()
        result = receiver.apply(msg)
        assert result.success

        # Constitution YAML now available
        yaml = receiver.active_yaml
        hash_ = receiver.active_hash
    """

    def __init__(
        self,
        node_id: str,
        *,
        trusted_issuer_keys: dict[str, bytes] | None = None,
        allow_legacy_v1: bool = False,
        max_message_age_seconds: float = 300.0,
        max_future_skew_seconds: float = 30.0,
        governed_validator_set: ValidatorSet | None = None,
        governed_policy: TransitionVerificationPolicy | None = None,
        governed_version: ConstitutionVersion | None = None,
    ) -> None:
        time_limits_ns: dict[str, int] = {}
        for name, value in (
            ("max_message_age_seconds", max_message_age_seconds),
            ("max_future_skew_seconds", max_future_skew_seconds),
        ):
            time_limits_ns[name] = _seconds_to_nanoseconds(
                value,
                field_name=name,
                allow_zero=True,
            )
        require_plain_id(node_id)
        if type(allow_legacy_v1) is not bool:
            raise TypeError("allow_legacy_v1 must be a boolean")
        trusted_keys = dict(trusted_issuer_keys or {})
        for issuer_id, key_bytes in trusted_keys.items():
            require_plain_id(issuer_id)
            if type(key_bytes) is not bytes or len(key_bytes) != 32:
                raise ValueError("trusted issuer public keys must be exactly 32 bytes")
        self._node_id = node_id
        self._trusted_issuer_keys = trusted_keys
        self._allow_legacy_v1 = allow_legacy_v1
        self._max_message_age_ns = time_limits_ns["max_message_age_seconds"]
        self._max_future_skew_ns = time_limits_ns["max_future_skew_seconds"]
        self._lock = threading.RLock()
        self._active: ConstitutionVersionRecord | None = None
        self._history: list[ConstitutionVersionRecord] = []
        self._seen_hashes: set[bytes] = set()
        self._seen_version_ids: set[tuple[str, str]] = set()
        self._issuer_versions: dict[str, int] = {}
        self._issuer_issued_at_ns: dict[str, int] = {}
        # Phase 7.5 governed path: construction-time trust anchors advance
        # atomically after each certificate-ratified transition.
        self._active_epoch: int | None = None
        anchors = (governed_validator_set, governed_policy, governed_version)
        if any(anchor is not None for anchor in anchors) and not all(
            anchor is not None for anchor in anchors
        ):
            raise ValueError(
                "governed validator set, policy, and version must be provided together"
            )
        if governed_validator_set is not None and type(governed_validator_set) is not ValidatorSet:
            raise ValueError("governed_validator_set must be a concrete ValidatorSet")
        if governed_policy is not None:
            if type(governed_policy) is not TransitionVerificationPolicy:
                raise ValueError("governed_policy must be a TransitionVerificationPolicy")
            governed_policy.old_certificate.__post_init__()
            governed_policy.new_certificate.__post_init__()
            TransitionVerificationPolicy.__post_init__(governed_policy)
        if governed_version is not None:
            if type(governed_version) is not ConstitutionVersion:
                raise ValueError("governed_version must be a ConstitutionVersion")
            ConstitutionVersion.__post_init__(governed_version)
        self._governed_validator_set = (
            self._snapshot_validator_set(governed_validator_set)
            if governed_validator_set is not None
            else None
        )
        self._governed_policy = (
            TransitionVerificationPolicy(
                old_certificate=governed_policy.old_certificate,
                new_certificate=governed_policy.new_certificate,
                max_rule_delta=governed_policy.max_rule_delta,
            )
            if governed_policy is not None
            else None
        )
        self._governed_version = (
            ConstitutionVersion(
                epoch=governed_version.epoch,
                rules=tuple(governed_version.rules),
                parent_digest=bytes(governed_version.parent_digest),
            )
            if governed_version is not None
            else None
        )

    @staticmethod
    def _snapshot_validator_set(validator_set: ValidatorSet) -> ValidatorSet:
        snapshot = ValidatorSet(validator_set.snapshot(), policy=validator_set.policy)
        compute_validator_set_digest(snapshot)
        return snapshot

    @property
    def node_id(self) -> str:
        with self._lock:
            return self._node_id

    @property
    def is_initialised(self) -> bool:
        with self._lock:
            return self._active is not None

    @property
    def active_hash(self) -> str:
        with self._lock:
            if self._active is None:
                return ""
            return self._active.constitution_hash

    @property
    def active_yaml(self) -> str:
        with self._lock:
            if self._active is None:
                return ""
            return self._active.yaml_content

    @property
    def active_epoch(self) -> int | None:
        """Epoch of the last certificate-ratified update, or ``None`` if
        no governed update has succeeded yet. Ungoverned :meth:`apply`
        calls never set this value.
        """
        with self._lock:
            return self._active_epoch

    @property
    def version_history(self) -> list[ConstitutionVersionRecord]:
        with self._lock:
            return list(self._history)

    @staticmethod
    def _version_from_yaml(
        yaml_content: str,
        *,
        epoch: int,
        parent_digest: bytes,
    ) -> ConstitutionVersion:
        """Build a canonical ConstitutionVersion from YAML content."""
        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            raise InvalidTransitionError(
                "constitution payload is not valid YAML"
            ) from exc
        if not isinstance(parsed, dict):
            raise InvalidTransitionError(
                "constitution payload must decode to a mapping"
            )
        raw_rules = parsed.get("rules", [])
        if raw_rules is None:
            raw_rules = []
        if not isinstance(raw_rules, (list, tuple)):
            raise InvalidTransitionError("constitution rules must be a list of strings")
        if not all(isinstance(rule, str) for rule in raw_rules):
            raise InvalidTransitionError("constitution rules must be strings")
        try:
            return ConstitutionVersion(
                epoch=epoch,
                rules=tuple(sorted(raw_rules)),
                parent_digest=parent_digest,
            )
        except ValueError as exc:
            raise InvalidTransitionError(
                f"invalid constitution version: {exc}"
            ) from exc

    def apply(self, msg: ConstitutionSyncMessage) -> SyncResult:
        """Apply a sync message from the SN Owner.

        Verification order:
          1. Issuer signature
          2. Hash integrity and replay/freshness policy
          3. Atomic activation

        Returns SyncResult with success flag and human-readable message.
        """
        with self._lock:
            old_hash = (
                self._active.constitution_hash if self._active is not None else ""
            )
            if self._active_epoch is not None:
                return SyncResult(
                    success=False,
                    message="Governed transition required after governed sync activation",
                    old_hash=old_hash,
                )
            authentication_error = self._authentication_error(msg)
            if authentication_error is not None:
                return SyncResult(
                    success=False,
                    message=authentication_error,
                    old_hash=old_hash,
                )
            return self._apply_verified_locked(msg, now_ns=time.time_ns())

    def _authentication_error(self, msg: object) -> str | None:
        """Return an error unless ``msg`` is concrete and issuer-authenticated."""
        shape_error = _message_shape_error(
            msg, allow_legacy_v1=self._allow_legacy_v1
        )
        if shape_error is not None:
            return shape_error
        concrete_msg = cast(ConstitutionSyncMessage, msg)
        if not concrete_msg.verify_signature(self._trusted_issuer_keys):
            return "Invalid issuer signature for constitution sync"
        return None

    def _apply_verified_locked(
        self,
        msg: ConstitutionSyncMessage,
        *,
        now_ns: int,
        enforce_max_age: bool = True,
        enforce_issued_at_order: bool = True,
    ) -> SyncResult:
        """Validate and atomically activate an authenticated message."""
        old_hash = self._active.constitution_hash if self._active is not None else ""
        rejection = self._validate_message_locked(
            msg,
            now_ns=now_ns,
            enforce_max_age=enforce_max_age,
            enforce_issued_at_order=enforce_issued_at_order,
        )
        if rejection is not None:
            return SyncResult(success=False, message=rejection, old_hash=old_hash)

        return self._activate_message_locked(msg, old_hash=old_hash)

    def _validate_message_locked(
        self,
        msg: ConstitutionSyncMessage,
        *,
        now_ns: int,
        enforce_max_age: bool = True,
        enforce_issued_at_order: bool = True,
    ) -> str | None:
        if not msg.verify():
            computed = hashlib.sha256(msg.yaml_content.encode()).hexdigest()[:16]
            return f"Hash mismatch: expected={msg.expected_hash} computed={computed}"
        active_version = self._issuer_versions.get(msg.issuer_id, 0)
        if msg.version <= active_version:
            return (
                f"Replay/downgrade rejected: version={msg.version} "
                f"<= issuer_version={active_version}"
            )
        content_digest = hashlib.sha256(msg.yaml_content.encode()).digest()
        if content_digest in self._seen_hashes:
            return "Replay/downgrade rejected: constitution content was already accepted"
        if (msg.issuer_id, msg.version_id) in self._seen_version_ids:
            return "Replay/downgrade rejected: version_id was already accepted"
        try:
            issued_at_ns = (
                cast(int, msg.issued_at)
                if msg.wire_version == _SYNC_WIRE_VERSION
                else _seconds_to_nanoseconds(
                    msg.issued_at,
                    field_name="issued_at",
                    allow_zero=False,
                )
            )
        except ValueError as exc:
            return f"Invalid issued_at: {exc}"
        if issued_at_ns > now_ns + self._max_future_skew_ns:
            return "Invalid issued_at: message is from the future"
        if enforce_max_age and now_ns - issued_at_ns > self._max_message_age_ns:
            return "Invalid issued_at: message is stale"
        last_issued_at = self._issuer_issued_at_ns.get(msg.issuer_id)
        if enforce_issued_at_order and last_issued_at is not None and (
            issued_at_ns <= last_issued_at
        ):
            return "Replay rejected: issued_at is not strictly increasing"
        return None

    def _activate_message_locked(
        self, msg: ConstitutionSyncMessage, *, old_hash: str
    ) -> SyncResult:
        """Commit a previously validated message while holding ``self._lock``."""

        # 3. Activate
        record = ConstitutionVersionRecord(
            version_id=msg.version_id,
            version=msg.version,
            constitution_hash=msg.expected_hash,
            yaml_content=msg.yaml_content,
            activated_at=time.time(),
            block_height=msg.block_height,
            description=msg.description,
        )
        self._active = record
        self._history.append(record)
        self._seen_hashes.add(hashlib.sha256(msg.yaml_content.encode()).digest())
        self._seen_version_ids.add((msg.issuer_id, msg.version_id))
        self._issuer_versions[msg.issuer_id] = msg.version
        self._issuer_issued_at_ns[msg.issuer_id] = (
            cast(int, msg.issued_at)
            if msg.wire_version == _SYNC_WIRE_VERSION
            else _seconds_to_nanoseconds(
                msg.issued_at,
                field_name="issued_at",
                allow_zero=False,
            )
        )

        return SyncResult(
            success=True,
            message=f"Constitution updated {old_hash or '(none)'} → {msg.expected_hash}",
            new_hash=msg.expected_hash,
            old_hash=old_hash,
            version_id=msg.version_id,
        )

    def verify_task_hash(self, task_constitution_hash: str) -> bool:
        """Check that a task's constitution hash matches the active version.

        Miners/validators call this before accepting any governance task.
        """
        with self._lock:
            if (
                type(task_constitution_hash) is not str
                or len(task_constitution_hash) != 64
                or any(
                    char not in "0123456789abcdef"
                    for char in task_constitution_hash
                )
                or self._active is None
            ):
                return False
            active_digest = hashlib.sha256(
                self._active.yaml_content.encode()
            ).hexdigest()
            return active_digest == task_constitution_hash

    def apply_governed(
        self,
        msg: ConstitutionSyncMessage,
        *,
        certificate: TransitionCertificate,
        old_validator_set: ValidatorSet,
        new_validator_set: ValidatorSet,
        current_version: ConstitutionVersion,
        policy: TransitionVerificationPolicy,
    ) -> SyncResult:
        """Apply a sync message gated by a joint-consensus transition
        certificate (Phase 7.5).

        The receiver compares caller inputs with its construction-time validator,
        policy, and version anchors, then advances the version and validator
        snapshot atomically. Both quorum certificates bind the complete canonical
        sync-message payload and both validator registries.

        On success, bumps :attr:`active_epoch` to the certificate's
        proposed epoch. On any failure returns a ``SyncResult`` with
        ``success=False`` and does not mutate receiver state.
        """
        with self._lock:
            old_hash = (
                self._active.constitution_hash if self._active is not None else ""
            )
            authentication_error = self._authentication_error(msg)
            if authentication_error is not None:
                return SyncResult(
                    success=False,
                    message=authentication_error,
                    old_hash=old_hash,
                )
            rejection = self._validate_message_locked(
                msg,
                now_ns=time.time_ns(),
                enforce_max_age=False,
                enforce_issued_at_order=False,
            )
            if rejection is not None:
                return SyncResult(success=False, message=rejection, old_hash=old_hash)

            if self._active is None:
                return SyncResult(
                    success=False,
                    message="Governed bootstrap requires an active trusted constitution",
                    old_hash=old_hash,
                )
            if (
                self._governed_validator_set is None
                or self._governed_policy is None
                or self._governed_version is None
            ):
                return SyncResult(
                    success=False,
                    message="Governed validator registry, policy, and version anchors are required",
                    old_hash=old_hash,
                )
            if policy != self._governed_policy:
                return SyncResult(
                    success=False,
                    message="Transition policy does not match pinned governed policy",
                    old_hash=old_hash,
                )
            if current_version != self._governed_version:
                return SyncResult(
                    success=False,
                    message="Trusted current version does not match pinned governed state",
                    old_hash=old_hash,
                )

            try:
                if type(certificate) is not TransitionCertificate:
                    raise InvalidTransitionError(
                        "certificate must be a TransitionCertificate"
                    )
                pinned_registry_digest = compute_validator_set_digest(
                    self._governed_validator_set
                )
                if (
                    compute_validator_set_digest(old_validator_set)
                    != pinned_registry_digest
                ):
                    raise InvalidTransitionError(
                        "old validator registry does not match pinned governed registry"
                    )
                old_validator_snapshot = self._governed_validator_set
                new_validator_snapshot = self._snapshot_validator_set(new_validator_set)
                proposal = certificate.proposal
                if proposal.binding_digest != msg.commitment_digest():
                    raise InvalidTransitionError(
                        "certificate is not bound to the complete sync message"
                    )
                active_version = self._version_from_yaml(
                    self._active.yaml_content,
                    epoch=current_version.epoch,
                    parent_digest=current_version.parent_digest,
                )
                if active_version != current_version:
                    raise InvalidTransitionError(
                        "trusted current version does not match the active constitution"
                    )
                verify_transition(
                    certificate,
                    old_validator_set=old_validator_snapshot,
                    new_validator_set=new_validator_snapshot,
                    current_version=current_version,
                    policy=self._governed_policy,
                )
                proposed_version = self._version_from_yaml(
                    msg.yaml_content,
                    epoch=proposal.proposed.epoch,
                    parent_digest=proposal.proposed.parent_digest,
                )
                if proposed_version != proposal.proposed:
                    raise InvalidTransitionError(
                        "sync message does not match certificate proposal"
                    )
            except (InvalidTransitionError, TypeError, ValueError) as exc:
                return SyncResult(
                    success=False,
                    message=f"Certificate rejected: {exc}",
                    old_hash=old_hash,
                )

            result = self._activate_message_locked(msg, old_hash=old_hash)
            self._active_epoch = proposal.proposed.epoch
            self._governed_version = proposal.proposed
            self._governed_validator_set = new_validator_snapshot
            return result

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "node_id": self._node_id,
                "is_initialised": self._active is not None,
                "active_hash": (
                    self._active.constitution_hash if self._active is not None else ""
                ),
                "active_epoch": self._active_epoch,
                "active_version": self._active.version if self._active is not None else 0,
                "versions_seen": len(self._history),
            }
