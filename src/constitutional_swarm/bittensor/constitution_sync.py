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
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..epoch_reconfig import (
    ConstitutionVersion,
    InvalidTransitionError,
    TransitionCertificate,
    TransitionVerificationPolicy,
    compute_validator_set_digest,
    verify_transition,
)
from ..validator_set import ValidatorSet

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
    issued_at: float
    version: int = 0
    issuer_id: str = "subnet-owner"
    block_height: int | None = None
    description: str = ""
    signature: bytes | None = None

    def verify(self) -> bool:
        """Verify the embedded hash matches the content."""
        computed = hashlib.sha256(self.yaml_content.encode()).hexdigest()[:16]
        return computed == self.expected_hash

    def signing_payload(self) -> bytes:
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
        return hashlib.sha256(self.signing_payload()).digest()

    def verify_signature(self, trusted_issuer_keys: dict[str, bytes]) -> bool:
        if self.signature is None:
            return False
        key_bytes = trusted_issuer_keys.get(self.issuer_id)
        if key_bytes is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                self.signature, self.signing_payload()
            )
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, Any]:
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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ConstitutionSyncMessage:
        return cls(
            version_id=d["version_id"],
            version=d.get("version", 0),
            expected_hash=d["expected_hash"],
            yaml_content=d["yaml_content"],
            issued_at=d["issued_at"],
            issuer_id=d.get("issuer_id", "subnet-owner"),
            block_height=d.get("block_height"),
            description=d.get("description", ""),
            signature=(
                bytes.fromhex(d["signature"])
                if isinstance(d.get("signature"), str) and d.get("signature")
                else None
            ),
        )


# ---------------------------------------------------------------------------
# Distributor (SN Owner side)
# ---------------------------------------------------------------------------


class ConstitutionDistributor:
    """SN Owner-side constitution broadcaster.

    Maintains an ordered version history and produces
    ConstitutionSyncMessages for distribution to miners/validators.

    Usage::

        dist = ConstitutionDistributor(initial_yaml=open("constitution.yaml").read())

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
        issuer_id: str = "subnet-owner",
        description: str = "initial",
    ) -> None:
        self._issuer_id = issuer_id
        self._lock = threading.RLock()
        self._history: list[ConstitutionVersionRecord] = []
        self._last_issued_at = 0.0
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
            new_hash = hashlib.sha256(new_yaml.encode()).hexdigest()[:16]
            active_hash = self._history[-1].constitution_hash
            if new_hash == active_hash:
                raise ValueError(
                    f"Constitution unchanged (hash={active_hash}). No update recorded."
                )
            return self._activate(new_yaml, description, block_height)

    def broadcast_message(self) -> ConstitutionSyncMessage:
        """Produce a sync message for the active version."""
        with self._lock:
            v = self._history[-1]
            issued_at = time.time()
            if issued_at <= self._last_issued_at:
                issued_at = math.nextafter(self._last_issued_at, math.inf)
            self._last_issued_at = issued_at
            return ConstitutionSyncMessage(
                version_id=v.version_id,
                version=v.version,
                expected_hash=v.constitution_hash,
                yaml_content=v.yaml_content,
                issued_at=issued_at,
                issuer_id=self._issuer_id,
                block_height=v.block_height,
                description=v.description,
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
        allow_unsigned: bool = False,
        max_message_age_seconds: float = 300.0,
        max_future_skew_seconds: float = 30.0,
        governed_validator_set: ValidatorSet | None = None,
        governed_policy: TransitionVerificationPolicy | None = None,
        governed_version: ConstitutionVersion | None = None,
    ) -> None:
        for name, value in (
            ("max_message_age_seconds", max_message_age_seconds),
            ("max_future_skew_seconds", max_future_skew_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(f"{name} must be a finite non-negative number")
        self._node_id = node_id
        self._trusted_issuer_keys = dict(trusted_issuer_keys or {})
        self._allow_unsigned = allow_unsigned
        self._max_message_age_seconds = float(max_message_age_seconds)
        self._max_future_skew_seconds = float(max_future_skew_seconds)
        self._lock = threading.RLock()
        self._active: ConstitutionVersionRecord | None = None
        self._history: list[ConstitutionVersionRecord] = []
        self._seen_hashes: set[str] = set()
        self._seen_version_ids: set[str] = set()
        self._active_version = 0
        self._last_issued_at = 0.0
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
        self._governed_validator_set = (
            self._snapshot_validator_set(governed_validator_set)
            if governed_validator_set is not None
            else None
        )
        self._governed_policy = governed_policy
        self._governed_version = governed_version

    @staticmethod
    def _snapshot_validator_set(validator_set: ValidatorSet) -> ValidatorSet:
        return ValidatorSet(validator_set.snapshot(), policy=validator_set.policy)

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
          1. Issuer signature (unless the development override is enabled)
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
            if not self._allow_unsigned and not msg.verify_signature(
                self._trusted_issuer_keys
            ):
                return SyncResult(
                    success=False,
                    message="Signature or governed transition required for constitution sync",
                    old_hash=old_hash,
                )
            return self._apply_verified_locked(msg, now=time.time())

    def _apply_verified(self, msg: ConstitutionSyncMessage) -> SyncResult:
        """Apply a message after authentication/governance has already succeeded."""
        with self._lock:
            return self._apply_verified_locked(msg, now=time.time())

    def _apply_verified_locked(
        self,
        msg: ConstitutionSyncMessage,
        *,
        now: float,
        allow_seen_hash: bool = False,
        enforce_max_age: bool = True,
        enforce_issued_at_order: bool = True,
    ) -> SyncResult:
        """Validate and atomically activate an authenticated message."""
        old_hash = self._active.constitution_hash if self._active is not None else ""
        rejection = self._validate_message_locked(
            msg,
            now=now,
            allow_seen_hash=allow_seen_hash,
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
        now: float,
        allow_seen_hash: bool = False,
        enforce_max_age: bool = True,
        enforce_issued_at_order: bool = True,
    ) -> str | None:
        if not msg.verify():
            computed = hashlib.sha256(msg.yaml_content.encode()).hexdigest()[:16]
            return f"Hash mismatch: expected={msg.expected_hash} computed={computed}"
        if not isinstance(msg.version_id, str) or not msg.version_id:
            return "Invalid version_id: a non-empty string is required"
        if (
            isinstance(msg.version, bool)
            or not isinstance(msg.version, int)
            or msg.version <= 0
        ):
            return "Version must be a positive integer"
        if msg.version <= self._active_version:
            return (
                f"Replay or rollback rejected: version={msg.version} "
                f"<= active_version={self._active_version}"
            )
        if (
            (not allow_seen_hash and msg.expected_hash in self._seen_hashes)
            or msg.version_id in self._seen_version_ids
        ):
            return (
                "Replay rejected: constitution hash or version_id was already accepted"
            )
        if (
            isinstance(msg.issued_at, bool)
            or not isinstance(msg.issued_at, (int, float))
            or not math.isfinite(msg.issued_at)
        ):
            return "Invalid issued_at: timestamp must be finite"
        if msg.issued_at <= 0:
            return "Invalid issued_at: timestamp must be positive"
        if msg.issued_at > now + self._max_future_skew_seconds:
            return "Invalid issued_at: message is from the future"
        if enforce_max_age and now - msg.issued_at > self._max_message_age_seconds:
            return "Invalid issued_at: message is stale"
        if (
            enforce_issued_at_order
            and self._last_issued_at
            and msg.issued_at <= self._last_issued_at
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
        self._seen_hashes.add(msg.expected_hash)
        self._seen_version_ids.add(msg.version_id)
        self._active_version = msg.version
        self._last_issued_at = float(msg.issued_at)

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
            return (
                self._active is not None
                and self._active.constitution_hash == task_constitution_hash
            )

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
            rejection = self._validate_message_locked(
                msg,
                now=time.time(),
                allow_seen_hash=True,
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
                "active_version": self._active_version,
                "versions_seen": len(self._history),
            }
