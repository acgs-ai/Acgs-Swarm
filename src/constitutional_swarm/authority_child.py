"""Spawn-only child loader for the APCC authority service."""

from __future__ import annotations

import base64
import json
import os
import secrets
import select
import socket
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm._sqlite_connections import _reuse_connections
from constitutional_swarm.apcc.model import Signature
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
from constitutional_swarm.governed_commit import TrustedGovernanceBootstrap
from constitutional_swarm.workflow_profile import (
    WorkflowProfile,
    require_workflow_profile,
)


@dataclass(frozen=True, slots=True)
class KeySourceRef:
    """Public reference and pinned public identity for child-held signing keys."""

    kind: Literal["file", "kms", "pkcs11", "consumed"]
    location: str
    expected_identity_public_key: bytes

    def __post_init__(self) -> None:
        if not self.location or len(self.expected_identity_public_key) != 32:
            raise ValueError("invalid key source reference")


@dataclass(frozen=True, slots=True)
class OutboxSinkRef:
    """Public reference to an authority-side outbox delivery adapter."""

    kind: Literal["discard"] = "discard"
    location: str = ""


@dataclass(frozen=True, slots=True)
class AuthorityChildConfig:
    """Public-only, spawn-serializable authority child configuration."""

    database_path: str
    authority: APCCAuthorityConfig
    key_source: KeySourceRef
    outbox_sink: OutboxSinkRef = OutboxSinkRef()
    provision: bool = False
    max_frame_bytes: int | None = None
    workflow_profile: WorkflowProfile = WorkflowProfile.DEFAULT

    def __post_init__(self) -> None:
        require_workflow_profile(self.workflow_profile)
        if self.max_frame_bytes is None:
            object.__setattr__(
                self, "max_frame_bytes", self.workflow_profile.max_frame_bytes
            )
        if (
            not self.database_path
            or type(self.max_frame_bytes) is not int
            or self.max_frame_bytes <= 0
        ):
            raise ValueError("invalid authority child configuration")
        if self.workflow_profile is WorkflowProfile.W6_INDEPENDENT_10000:
            if self.max_frame_bytes > self.workflow_profile.max_frame_bytes:
                raise ValueError("workflow profile frame budget exceeded")

    @property
    def frame_limit(self) -> int:
        """Resolved finite frame ceiling after profile default selection."""
        assert self.max_frame_bytes is not None
        return self.max_frame_bytes


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
        return _public_bytes(self._keys[version or next(iter(self._keys))])

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
    if len(raw) > 1_048_576:
        raise ValueError("authority key bundle too large")
    body = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate authority key")
        result[key] = value
    return result


def _validate_keys(config: APCCAuthorityConfig, keys: _LoadedKeys) -> None:
    policy_by_version = {binding.scope[1]: binding for binding in config.policy_trust}
    if set(policy_by_version) != set(keys.policy):
        raise PermissionError("policy key set mismatch")
    for version, binding in policy_by_version.items():
        if binding.public_key != _public_bytes(keys.policy[version]):
            raise PermissionError("policy public key mismatch")
    if config.registry_trust[0].public_key != _public_bytes(keys.registry):
        raise PermissionError("registry public key mismatch")
    if config.commit_trust.public_key != _public_bytes(keys.commit):
        raise PermissionError("commit public key mismatch")
    if config.status_trust.public_key != _public_bytes(keys.status):
        raise PermissionError("status public key mismatch")


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
        workflow_profile=config.workflow_profile,
    )


def authority_child_main(
    config: AuthorityChildConfig,
    execution: socket.socket,
    admin_channel: socket.socket,
    status_channel: socket.socket,
    readiness: Any,
    w2_renewal: Any = None,
    renewal_channels: list[socket.socket] | None = None,
) -> None:
    """Load authority secrets after spawn and serve two exclusive channels."""
    from constitutional_swarm.authority_isolation import (
        erase_secret,
        harden_current_process,
    )

    connections = ExitStack()
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
        connections.enter_context(_reuse_connections(path, maximum_idle=3))
        if w2_renewal is None:
            _recover_outbox(admin)
        ephemeral = Ed25519PrivateKey.generate()
        session = secrets.token_urlsafe(24)
        if w2_renewal is not None:
            session = "w2-" + session
        renewal = None
        if w2_renewal is not None:
            from constitutional_swarm.apcc_empirical.w2_renewal_runtime import (
                _RenewalOwner,
            )

            renewal = _RenewalOwner(w2_renewal, config, keys, admin, session)
            connections.callback(renewal.close)
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
        execution.settimeout(config.workflow_profile.control_timeout_seconds)
        admin_channel.settimeout(config.workflow_profile.control_timeout_seconds)
        status_channel.settimeout(2.0)
        channels = {
            execution: "execution",
            admin_channel: "admin",
            status_channel: "status-signing",
        }
        status_epochs = {status_channel: 0}
        if renewal is not None:
            assert renewal_channels is not None
            control, *successor_status = renewal_channels
            channels[control] = "w2-renewal-control"
            for epoch, endpoint in enumerate(successor_status, start=1):
                endpoint.settimeout(2.0)
                channels[endpoint] = "status-signing"
                status_epochs[endpoint] = epoch
        sequences = {endpoint: 0 for endpoint in channels}
        last_recovery = time.monotonic()
        while channels:
            readable, _, _ = select.select(list(channels), [], [], 0.25)
            for connection in readable:
                channel = channels[connection]
                try:
                    request = recv_frame(connection, config.frame_limit)
                except FrameProtocolError as exc:
                    sequences[connection] += 1
                    try:
                        send_frame(
                            connection,
                            signed_response(
                                key=ephemeral,
                                session=session,
                                channel=channel,
                                sequence=sequences[connection],
                                authority_pid=os.getpid(),
                                request_digest=digest(
                                    {
                                        "invalid_frame": exc.code,
                                        "sequence": sequences[connection],
                                    }
                                ),
                                error={"code": exc.code, "message": ""},
                            ),
                            config.frame_limit,
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
                sequences[connection] += 1
                request_digest = digest(request)
                frame_budget = config.workflow_profile.frame_budget(
                    request.get("operation", "") if isinstance(request, dict) else "",
                    config.frame_limit,
                )
                try:
                    if len(canonical_json(request)) > frame_budget:
                        raise ValueError("request_frame_too_large")
                    if renewal is not None:
                        request = renewal.route(
                            channel, request, status_epochs.get(connection)
                        )
                    if channel == "w2-renewal-control":
                        assert renewal is not None
                        result = renewal.control(request)
                    elif (
                        channel == "execution"
                        and request["operation"] == "check_w2_admission_epoch"
                        and renewal is not None
                    ):
                        if request["request"] != {}:
                            raise ValueError("invalid W2 admission check fields")
                        result = {
                            "epoch": renewal.epoch,
                            "plan_digest": renewal.config.plan_digest,
                        }
                    elif channel == "execution":
                        result = _handle_execution_request(admin, request)
                    elif channel == "admin":
                        result = _handle_admin_request(admin, request)
                    else:
                        result = _handle_status_sign_request(
                            request, admin.commit_port._apcc_store
                        )
                    if renewal is not None:
                        renewal.after_request(channel, request, result)
                except Exception as exc:
                    if isinstance(exc, LookupError):
                        code = (
                            "unknown_operation"
                            if channel == "execution"
                            else "unknown_admin_operation"
                            if channel == "admin"
                            else "unknown_status_signing_operation"
                        )
                    elif isinstance(exc, (TypeError, ValueError)):
                        code = "invalid_request"
                    else:
                        code = type(exc).__name__
                    response = signed_response(
                        key=ephemeral,
                        session=session,
                        channel=channel,
                        sequence=sequences[connection],
                        authority_pid=os.getpid(),
                        request_digest=request_digest,
                        error={"code": code, "message": str(exc)},
                    )
                else:
                    response = signed_response(
                        key=ephemeral,
                        session=session,
                        channel=channel,
                        sequence=sequences[connection],
                        authority_pid=os.getpid(),
                        request_digest=request_digest,
                        result=result,
                    )
                try:
                    send_frame(connection, response, frame_budget)
                except FrameSizeError:
                    try:
                        send_frame(
                            connection,
                            signed_response(
                                key=ephemeral,
                                session=session,
                                channel=channel,
                                sequence=sequences[connection],
                                authority_pid=os.getpid(),
                                request_digest=request_digest,
                                error={
                                    "code": "response_too_large",
                                    "message": "response_too_large",
                                },
                            ),
                            config.frame_limit,
                        )
                    except (ConnectionError, OSError, FrameSizeError, ValueError):
                        channels.pop(connection, None)
                        connection.close()
                except (ConnectionError, OSError):
                    channels.pop(connection, None)
                    connection.close()
            if time.monotonic() - last_recovery >= 1:
                if renewal is None or renewal.mutations_enabled:
                    _recover_outbox(admin)
                last_recovery = time.monotonic()
    except BaseException as exc:
        try:
            try:
                readiness.send(
                    {"startup_error": type(exc).__name__, "message": str(exc)}
                )
            except (OSError, BrokenPipeError):
                pass
        finally:
            readiness.close()
        raise
    finally:
        connections.__exit__(*sys.exc_info())
