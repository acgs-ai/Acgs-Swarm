"""Spawn-only child loader for the APCC authority service."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import select
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.model import FailureCode, Signature
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AuthorityRuntime,
    AuthoritySigningRole,
)
from constitutional_swarm.authority_ipc import (
    FrameProtocolError,
    FrameSizeError,
    PROTOCOL,
    b64u,
    canonical_json,
    digest,
    recv_frame,
    send_frame,
    signed_response,
)
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import TrustedGovernanceBootstrap
from constitutional_swarm.strict_json import loads as strict_loads

logger = logging.getLogger(__name__)

_MAX_KEY_BUNDLE_BYTES = 1_048_576
_SUPPORTED_KEY_SOURCE_KINDS = frozenset({"file", "consumed"})
# Fixed allowlist of the protocol codes handlers raise on purpose (literal codes in
# authority_service.py, governed_commit.py and apcc/*.py, plus FailureCode values).
# Any other exception text, however code-shaped, collapses to its category code.
# tests/test_c23_authority_child_hardening.py re-scans those modules for drift.
_NODE_STATUSES = (
    "blocked",
    "ready",
    "claimed",
    "result_produced",
    "governed_committed",
    "denied",
    "revoked",
    "superseded",
)
_ATTEMPT_FIELDS = (
    "store_id",
    "workflow_id",
    "node_id",
    "attempt_id",
    "agent_id",
    "key_id",
    "expected_node_state_version",
    "policy_epoch",
    "authority_epoch",
    "agent_revocation_epoch",
    "workflow_revocation_generation",
    "workflow_generation",
)
_PROTOCOL_ERROR_CODES: frozenset[str] = frozenset(
    {
        "INVALID_DECIMAL_STRING",
        "ISOLATION_UNAVAILABLE",
        "agent_revoked",
        "attempt_authorization_expired_or_invalid",
        "authority_anchor_integrity_failure",
        "authority_anchor_mismatch",
        "authority_foreign_key_check_failed",
        "authority_integrity_check_failed",
        "authority_or_capability_denied",
        "authority_schema_shape_mismatch",
        "authority_status_batch_length_mismatch",
        "authority_status_batch_order_mismatch",
        "authority_status_nonce_collision",
        "authority_store_already_exists",
        "authority_store_not_sealed",
        "authority_unavailable",
        "bootstrap_store_identity_mismatch",
        "canonical_certificate_identity_mismatch",
        "canonical_certificate_missing",
        "controller_signer_already_used",
        "empty_node_status_batch",
        "execution_channel_already_composed",
        "invalid_admin_request",
        "invalid_apcc_nonce",
        "invalid_artifact",
        "invalid_attempt_authorization_signature",
        "invalid_capabilities",
        "invalid_capability",
        "invalid_field_type",
        "invalid_node_ids",
        "invalid_observation_request",
        "invalid_observation_response",
        "invalid_predecessor_bindings",
        "invalid_receipt",
        "invalid_registry_snapshot",
        "invalid_request",
        "invalid_required_capabilities",
        "invalid_scheduler_request",
        "invalid_scheduler_sequence",
        "invalid_status_parameters",
        "invalid_task_dag",
        "invalid_task_node",
        "invalid_work_receipt",
        "invalid_workflow_definition",
        "legacy_projection_missing",
        "metadata_nesting_too_deep",
        "missing_staged_result",
        "node_status_batch_length_mismatch",
        "node_status_batch_too_large",
        "node_tainted_by_revocation",
        "nonfinite_number",
        "observer_already_started",
        "observer_must_precede_scheduler",
        "observer_starting",
        "predecessor_not_governed_committed",
        "projection_artifact_conflict",
        "recovery_evidence_binding_mismatch",
        "recovery_evidence_context_mismatch",
        "recovery_evidence_missing",
        "recovery_policy_mismatch",
        "recovery_predecessor_evidence_mismatch",
        "recovery_receipt_digest_mismatch",
        "recovery_signature_invalid",
        "recovery_topology_mismatch",
        "recovery_verdict_digest_mismatch",
        "result_not_produced",
        "revocation_root_not_governed_committed",
        "scheduler_rebootstrap_required",
        "sealed_authority_store_required",
        "signed_attempt_authorization_required",
        "staging_context_mismatch",
        "task_node_identity_mismatch",
        "unknown_admin_operation",
        "unknown_control_action",
        "unknown_node",
        "unknown_observer_operation",
        "unknown_operation",
        "unknown_predecessor",
        "unknown_scheduler_operation",
        "unknown_status_signing_operation",
        "unsealed_verifier_policy",
        "untrusted_policy_binding",
        "untrusted_producer_key",
        "workflow_topology_integrity_failure",
        *(code.value for code in FailureCode),
        *(f"node_not_ready:{status}" for status in _NODE_STATUSES),
        *(f"stale_or_mismatched_attempt_{name}" for name in _ATTEMPT_FIELDS),
    }
)


@dataclass(frozen=True, slots=True)
class KeySourceRef:
    """Public reference and pinned public identity for child-held signing keys."""

    kind: Literal["file", "consumed"]
    location: str
    expected_identity_public_key: bytes

    def __post_init__(self) -> None:
        if self.kind not in _SUPPORTED_KEY_SOURCE_KINDS:
            raise ValueError("unsupported key source kind")
        if not self.location or len(self.expected_identity_public_key) != 32:
            raise ValueError("invalid key source reference")


@dataclass(frozen=True, slots=True)
class OutboxSinkRef:
    """Public reference to an authority-side outbox delivery adapter."""

    kind: Literal["discard"] = "discard"


@dataclass(frozen=True, slots=True)
class AuthorityChildConfig:
    """Public-only, spawn-serializable authority child configuration."""

    database_path: str
    authority: APCCAuthorityConfig
    key_source: KeySourceRef
    outbox_sink: OutboxSinkRef = OutboxSinkRef()
    provision: bool = False
    max_frame_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not self.database_path or self.max_frame_bytes <= 0:
            raise ValueError("invalid authority child configuration")


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class _DetachedSigner:
    __slots__ = ("_key",)

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    def public_key_bytes(self) -> bytes:
        return _public_bytes(self._key)

    def sign(self, domain: bytes, canonical_body: bytes) -> bytes:
        return self._key.sign(domain + b"\x00" + canonical_body)


class _PolicySigner:
    __slots__ = ("_keys",)

    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        self._keys = keys

    def public_key_bytes(self, version: str | None = None) -> bytes:
        # ValueError, not TypeError: governed_commit retries TypeError without a version.
        if type(version) is not str or version not in self._keys:
            raise ValueError("explicit configured policy version required")
        return _public_bytes(self._keys[version])

    def sign(self, domain: bytes, canonical_body: bytes) -> bytes:
        body = json.loads(canonical_body)
        return self._keys[str(body["policy_version"])].sign(
            domain + b"\x00" + canonical_body
        )


class _KeyProvider:
    __slots__ = ("_keys",)

    def __init__(self, keys: dict[AuthoritySigningRole, Ed25519PrivateKey]) -> None:
        self._keys = keys

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        del key_id
        return _public_bytes(self._keys[role])

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        return Signature(
            "Ed25519",
            key_id,
            b64u(self._keys[role].sign(domain + b"\x00" + canonical_body)),
        )


class _Clock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class _DiscardSink:
    def deliver(self, event_id: str, payload: bytes) -> None:
        del event_id, payload


@dataclass(frozen=True, slots=True)
class _LoadedKeys:
    policy: dict[str, Ed25519PrivateKey]
    registry: Ed25519PrivateKey
    control: Ed25519PrivateKey
    commit: Ed25519PrivateKey
    status: Ed25519PrivateKey
    identity: Ed25519PrivateKey


def _load_file_keys_raw(raw: bytes | bytearray, reference: KeySourceRef) -> _LoadedKeys:
    body = strict_loads(raw, max_bytes=_MAX_KEY_BUNDLE_BYTES, allow_float=False)
    if not isinstance(body, dict) or set(body) != {
        "policy",
        "registry",
        "control",
        "commit",
        "status",
        "identity",
    }:
        raise ValueError("invalid authority key bundle")

    def key(value: Any) -> Ed25519PrivateKey:
        if type(value) is not str:
            raise ValueError("invalid authority private key")
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return Ed25519PrivateKey.from_private_bytes(decoded)

    if not isinstance(body["policy"], dict):
        raise ValueError("invalid policy key bundle")
    loaded = _LoadedKeys(
        policy={str(version): key(value) for version, value in body["policy"].items()},
        registry=key(body["registry"]),
        control=key(body["control"]),
        commit=key(body["commit"]),
        status=key(body["status"]),
        identity=key(body["identity"]),
    )
    if _public_bytes(loaded.identity) != reference.expected_identity_public_key:
        raise PermissionError("authority persistent identity mismatch")
    return loaded


def _validate_keys(config: APCCAuthorityConfig, keys: _LoadedKeys) -> None:
    policy_by_version = {binding.scope[1]: binding for binding in config.policy_trust}
    if set(policy_by_version) != set(keys.policy):
        raise PermissionError("policy key set mismatch")
    for version, binding in policy_by_version.items():
        if binding.public_key != _public_bytes(keys.policy[version]):
            raise PermissionError("policy public key mismatch")
    registry_public = _public_bytes(keys.registry)
    if any(binding.public_key != registry_public for binding in config.registry_trust):
        raise PermissionError("registry public key mismatch")
    if config.commit_trust.public_key != _public_bytes(keys.commit):
        raise PermissionError("commit public key mismatch")
    if config.status_trust.public_key != _public_bytes(keys.status):
        raise PermissionError("status public key mismatch")
    loaded = [
        _public_bytes(key)
        for key in (
            keys.identity,
            keys.control,
            keys.registry,
            keys.commit,
            keys.status,
            *keys.policy.values(),
        )
    ]
    # Producer keys belong to agents; none may double as an authority-held key.
    producer_keys = {binding.public_key for binding in config.producer_trust}
    if len(set(loaded)) != len(loaded) or not producer_keys.isdisjoint(loaded):
        raise PermissionError("authority role keys must be pairwise distinct")


def _request_error_code(exc: BaseException, channel: str) -> str:
    """Map a request failure to a stable wire code; never forward free text."""
    if isinstance(exc, LookupError):
        fallback = (
            "unknown_operation"
            if channel == "execution"
            else "unknown_admin_operation"
            if channel == "admin"
            else "unknown_status_signing_operation"
        )
    elif isinstance(exc, GovernanceBypassDenied):
        fallback = "governance_denied"
    elif isinstance(exc, PermissionError):
        fallback = "permission_denied"
    elif isinstance(exc, (TypeError, ValueError)):
        fallback = "invalid_request"
    else:
        return "internal_error"
    if isinstance(exc, KeyError) or not exc.args:
        return fallback
    reason = exc.args[0]
    if type(reason) is str and reason in _PROTOCOL_ERROR_CODES:
        return reason
    return fallback


def _bootstrap(
    config: AuthorityChildConfig, keys: _LoadedKeys
) -> TrustedGovernanceBootstrap:
    _validate_keys(config.authority, keys)
    if config.outbox_sink.kind != "discard":
        raise RuntimeError("unsupported outbox sink")
    return TrustedGovernanceBootstrap(
        config=config.authority,
        runtime=AuthorityRuntime(
            _KeyProvider(
                {
                    AuthoritySigningRole.COMMIT: keys.commit,
                    AuthoritySigningRole.STATUS: keys.status,
                }
            ),
            _Clock(),
            _DiscardSink(),
        ),
        policy_signer=_PolicySigner(keys.policy),
        registry_signer=_DetachedSigner(keys.registry),
        control_signer=_DetachedSigner(keys.control),
    )


def authority_child_main(
    config: AuthorityChildConfig,
    execution: socket.socket,
    admin_channel: socket.socket,
    status_channel: socket.socket,
    readiness: Any,
) -> None:
    """Load authority secrets after spawn and serve two exclusive channels."""
    from constitutional_swarm.authority_isolation import (
        erase_secret,
        harden_current_process,
    )

    try:
        harden_current_process()
        from constitutional_swarm.authority_service import (
            _handle_admin_request,
            _handle_execution_request,
            _handle_status_sign_request,
            _recover_outbox,
        )

        readiness.send({"stage": "HARDENED_READY", "pid": os.getpid(), "dumpable": 0})
        try:
            raw_keys = bytearray(readiness.recv_bytes(1_048_577))
        except (EOFError, OSError) as error:
            raise RuntimeError("authority bootstrap secret unavailable") from error
        try:
            keys = _load_file_keys_raw(raw_keys, config.key_source)
        finally:
            erase_secret(raw_keys)
        bootstrap = _bootstrap(config, keys)
        path = Path(config.database_path)
        admin = (
            bootstrap.provision(path)
            if config.provision
            else bootstrap.open_admin(path)
        )
        _recover_outbox(admin)
        ephemeral = Ed25519PrivateKey.generate()
        session = secrets.token_urlsafe(24)
        ready_body = {
            "protocol": PROTOCOL,
            "authority_pid": os.getpid(),
            "key_loader_pid": os.getpid(),
            "session": session,
            "ipc_public_key": b64u(_public_bytes(ephemeral)),
        }
        readiness.send(
            {
                **ready_body,
                "signature": b64u(keys.identity.sign(canonical_json(ready_body))),
            }
        )
        readiness.close()
        execution.settimeout(2.0)
        admin_channel.settimeout(2.0)
        status_channel.settimeout(2.0)
        channels = {
            execution: "execution",
            admin_channel: "admin",
            status_channel: "status-signing",
        }
        sequences = {"execution": 0, "admin": 0, "status-signing": 0}
        last_recovery = time.monotonic()
        while channels:
            readable, _, _ = select.select(list(channels), [], [], 0.25)
            for connection in readable:
                channel = channels[connection]
                try:
                    request = recv_frame(connection, config.max_frame_bytes)
                except FrameProtocolError as exc:
                    sequences[channel] += 1
                    try:
                        send_frame(
                            connection,
                            signed_response(
                                key=ephemeral,
                                session=session,
                                channel=channel,
                                sequence=sequences[channel],
                                authority_pid=os.getpid(),
                                request_digest=digest(
                                    {
                                        "invalid_frame": exc.code,
                                        "sequence": sequences[channel],
                                    }
                                ),
                                error={"code": exc.code, "message": ""},
                            ),
                            config.max_frame_bytes,
                        )
                    except (ConnectionError, OSError, ValueError):
                        channels.pop(connection, None)
                        connection.close()
                    if exc.code == "frame_too_large":
                        channels.pop(connection, None)
                        connection.close()
                    continue
                except (ConnectionError, OSError, ValueError):
                    channels.pop(connection, None)
                    connection.close()
                    continue
                sequences[channel] += 1
                request_digest = digest(request)
                try:
                    if channel == "execution":
                        result = _handle_execution_request(admin, request)
                    elif channel == "admin":
                        result = _handle_admin_request(admin, request)
                    else:
                        result = _handle_status_sign_request(request, admin)
                except Exception as exc:
                    code = _request_error_code(exc, channel)
                    logger.warning(
                        "authority %s request failed with %s: %s: %s",
                        channel,
                        code,
                        type(exc).__name__,
                        exc,
                    )
                    response = signed_response(
                        key=ephemeral,
                        session=session,
                        channel=channel,
                        sequence=sequences[channel],
                        authority_pid=os.getpid(),
                        request_digest=request_digest,
                        error={"code": code, "message": code},
                    )
                else:
                    response = signed_response(
                        key=ephemeral,
                        session=session,
                        channel=channel,
                        sequence=sequences[channel],
                        authority_pid=os.getpid(),
                        request_digest=request_digest,
                        result=result,
                    )
                try:
                    send_frame(connection, response, config.max_frame_bytes)
                except FrameSizeError:
                    try:
                        send_frame(
                            connection,
                            signed_response(
                                key=ephemeral,
                                session=session,
                                channel=channel,
                                sequence=sequences[channel],
                                authority_pid=os.getpid(),
                                request_digest=request_digest,
                                error={
                                    "code": "response_too_large",
                                    "message": "response_too_large",
                                },
                            ),
                            config.max_frame_bytes,
                        )
                    except (ConnectionError, OSError, FrameSizeError, ValueError):
                        channels.pop(connection, None)
                        connection.close()
                except (ConnectionError, OSError):
                    channels.pop(connection, None)
                    connection.close()
            if time.monotonic() - last_recovery >= 1:
                _recover_outbox(admin)
                last_recovery = time.monotonic()
    except BaseException as exc:
        logger.error(
            "authority child terminated with %s: %s", type(exc).__name__, exc
        )
        try:
            try:
                readiness.send({"startup_error": type(exc).__name__})
            except (OSError, BrokenPipeError):
                pass
        finally:
            readiness.close()
        raise
