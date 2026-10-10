"""C22 regression tests: authority supervisor, IPC and observer hardening.

Each test feeds invalid or adversarial input and expects fail-closed rejection.
"""

from __future__ import annotations

import ast
import multiprocessing
import socket
import struct
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import authority_ipc
from constitutional_swarm import authority_service as service_module
from constitutional_swarm import strict_json
from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.authority_isolation import IsolationUnavailable
from constitutional_swarm.authority_observer import (
    AuthorityObserverLaunchConfig,
    ControllerKeySourceRef,
    sign_launch_candidate,
)
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from tests.gcb_apcc_support import authority_child_config

_SRC = Path(service_module.__file__).resolve().parent
_OWNED = ("authority_service.py", "authority_ipc.py", "authority_observer.py")


def _tree(name: str) -> ast.Module:
    return ast.parse((_SRC / name).read_text(encoding="utf-8"))


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# --------------------------------------------------------------------------- observer-1


@pytest.mark.parametrize(
    ("field", "forged"),
    [("session_id", "session-forged"), ("initial_trust_sequence", "999")],
)
def test_supervisor_rejects_controller_signed_attestation_with_unpinned_fields(
    tmp_path, monkeypatch: pytest.MonkeyPatch, field: str, forged: str
) -> None:
    """P1: expectations come from supervisor state, never from the attestation.

    The substituted attestation carries a valid controller signature and a fresh
    validity window, so only the pinned-field comparison can reject it.
    """
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(tmp_path / "c22.db", tmp_path / "c22.keys")
    controller = Ed25519PrivateKey.generate()
    public = _raw(controller)
    location = tmp_path / "c22-controller.key"
    location.write_text(
        b64u_encode(
            controller.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ),
        encoding="ascii",
    )
    location.chmod(0o600)
    launch = AuthorityObserverLaunchConfig(
        experiment_id="experiment-1",
        run_id="run-1",
        authority_store_id=config.authority.authority_store_id,
        backend_kind="sqlite",
        backend_instance="sqlite-test-instance",
        backend_schema=None,
        controller_key_id=sha256_digest(public),
        controller_key_source=ControllerKeySourceRef(str(location), public),
    )
    genuine_decode = service_module.decode_observer_launch_attestation
    substituted: list[str] = []

    def forged_decode(raw: bytes):
        genuine = genuine_decode(raw)
        candidate: dict[str, object] = dict(genuine.unsigned_object())
        assert candidate[field] != forged
        candidate[field] = forged
        signed = sign_launch_candidate(candidate, controller, sha256_digest(public))
        substituted.append(field)
        return genuine_decode(authority_ipc.canonical_json(signed))

    monkeypatch.setattr(
        service_module, "decode_observer_launch_attestation", forged_decode
    )
    authority = start_authority(config)
    try:
        with pytest.raises(ValueError, match="trust binding"):
            start_authority_observer(authority, launch)
        assert substituted == [field]
        assert all(
            child.name != "apcc-authority-observer-child" or not child.is_alive()
            for child in multiprocessing.active_children()
        )
    finally:
        authority.close()


# --------------------------------------------------------------------------- observer-2


def test_observe_holds_rpc_lock_until_sequence_is_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A concurrent RPC must not move ``_sequence`` between call and check."""
    client = service_module.AuthorityObserverClient(1024)
    client._ipc_public_key = b"\x01" * 32
    observed: dict[str, object] = {}

    def fake_rpc(self, operation, request):
        with self._rpc_lock:
            self._sequence += 1
        return {"observation_b64u": b64u_encode(b"observation")}

    def fake_verify(observation, **kwargs) -> None:
        outcome: list[bool] = []

        def try_lock() -> None:
            acquired = client._rpc_lock.acquire(blocking=False)
            outcome.append(acquired)
            if acquired:
                client._rpc_lock.release()

        probe = threading.Thread(target=try_lock)
        probe.start()
        probe.join()
        observed["lock_free_for_other_thread"] = outcome[0]
        observed["expected_sequence"] = kwargs["expected_sequence"]

    monkeypatch.setattr(service_module.AuthorityObserverClient, "_rpc", fake_rpc)
    monkeypatch.setattr(
        service_module, "encode_authority_observation_request", lambda _r: b"req"
    )
    monkeypatch.setattr(
        service_module, "decode_signed_authority_observation", lambda _b: "signed"
    )
    monkeypatch.setattr(
        service_module, "verify_signed_authority_observation", fake_verify
    )

    assert client.observe(object()) == "signed"  # type: ignore[arg-type]
    assert observed == {"lock_free_for_other_thread": False, "expected_sequence": "1"}


# --------------------------------------------------------------------------- opt-1


def test_authority_ipc_reexports_the_single_strict_json_policy() -> None:
    assert authority_ipc.reject_duplicate_keys is strict_json.reject_duplicate_keys
    assert authority_ipc.strict_loads is strict_json.loads
    for name in ("authority_ipc.py", "authority_observer.py"):
        assert "_reject_duplicate_keys" not in {
            node.name
            for node in ast.walk(_tree(name))
            if isinstance(node, ast.FunctionDef)
        }


@pytest.mark.parametrize("module", _OWNED)
def test_owned_modules_have_no_unbounded_plain_json_loads(module: str) -> None:
    offenders = [
        node.lineno
        for node in ast.walk(_tree(module))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "loads"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
    ]
    assert offenders == []


@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1,"a":2}',
        b'{"text":"\\ud800"}',
        b'{"value":NaN}',
    ],
)
def test_ipc_frame_with_ambiguous_json_is_malformed(body: bytes) -> None:
    left, right = socket.socketpair(socket.AF_UNIX)
    try:
        left.sendall(struct.pack("!I", len(body)) + body)
        with pytest.raises(authority_ipc.FrameProtocolError) as caught:
            authority_ipc.recv_frame(right, 1024)
        assert caught.value.code == "malformed_json"
    finally:
        left.close()
        right.close()


def test_ipc_frame_nesting_beyond_bound_is_malformed() -> None:
    body = b"[" * 66 + b"]" * 66
    left, right = socket.socketpair(socket.AF_UNIX)
    try:
        left.sendall(struct.pack("!I", len(body)) + body)
        with pytest.raises(authority_ipc.FrameProtocolError):
            authority_ipc.recv_frame(right, 1024)
    finally:
        left.close()
        right.close()


def test_controller_signer_response_with_duplicate_keys_is_rejected() -> None:
    sent: list[bytes] = []
    channel = SimpleNamespace(
        send_bytes=sent.append,
        poll=lambda _timeout: True,
        recv_bytes=lambda _limit: b'{"controller_key_id":"evil","controller_key_id":"ok"}',
        close=lambda: None,
    )
    signer = service_module._ControllerSigner(SimpleNamespace(pid=None), channel)
    with pytest.raises(RuntimeError, match="invalid controller signer response"):
        signer.sign({"candidate": "1"})
    assert sent


def test_signed_scheduler_readiness_with_duplicate_keys_is_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    domain = b"C22-TEST-DOMAIN"
    body = {"stage": "READY", "pid": 7}
    signature = b64u_encode(
        key.sign(domain + b"\x00" + authority_ipc.canonical_json(body))
    )
    raw = (
        '{"stage":"FORGED","stage":"READY","pid":7,"signature":"%s"}' % signature
    ).encode()
    with pytest.raises(IsolationUnavailable, match="invalid scheduler readiness"):
        service_module._verify_scheduler_signed_message(
            raw,
            expected_body=body,
            public_key=key.public_key(),
            domain=domain,
        )


# --------------------------------------------------------------------------- opt-2


def test_raw_public_bytes_rejects_non_ed25519_public_keys() -> None:
    key = Ed25519PrivateKey.generate()
    assert authority_ipc.raw_public_bytes(key.public_key()) == _raw(key)
    with pytest.raises(TypeError):
        authority_ipc.raw_public_bytes(key)  # type: ignore[arg-type]


@pytest.mark.parametrize("module", ("authority_service.py", "authority_observer.py"))
def test_owned_modules_have_no_inline_key_or_base64url_encoding(module: str) -> None:
    offenders = [
        (node.lineno, node.attr)
        for node in ast.walk(_tree(module))
        if isinstance(node, ast.Attribute)
        and (
            (node.attr == "Raw" and getattr(node.value, "attr", None) == "PublicFormat")
            or node.attr == "urlsafe_b64encode"
        )
    ]
    assert offenders == []


# --------------------------------------------------------------------------- opt-5


def test_authenticated_rpc_does_not_reparse_the_bound_public_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    client_socket, server_socket = socket.socketpair(socket.AF_UNIX)

    def serve() -> None:
        for sequence in (1, 2):
            envelope = authority_ipc.recv_frame(server_socket, 4096)
            authority_ipc.send_frame(
                server_socket,
                authority_ipc.signed_response(
                    key=key,
                    session="session-c22",
                    channel="admin",
                    sequence=sequence,
                    authority_pid=4242,
                    request_digest=authority_ipc.digest(envelope),
                    result={"ok": sequence},
                ),
                4096,
            )

    server = threading.Thread(target=serve)
    server.start()
    client = service_module._bind_verified_child_channel(
        service_module._JSONClient,
        client_socket,
        channel_role="admin",
        session="session-c22",
        authority_pid=4242,
        ipc_public_key=key.public_key(),
        max_frame_bytes=4096,
    )
    parses: list[bytes] = []

    def counting_from_public_bytes(data: bytes):
        parses.append(data)
        raise AssertionError("public key re-parsed on the RPC hot path")

    monkeypatch.setattr(
        service_module,
        "Ed25519PublicKey",
        SimpleNamespace(from_public_bytes=counting_from_public_bytes),
    )
    try:
        assert client._rpc("health", {}) == {"ok": 1}
        assert client._rpc("health", {}) == {"ok": 2}
    finally:
        server.join(5)
        client.close()
        server_socket.close()
    assert parses == []
    assert client._ipc_public_key == _raw(key)


def test_unbound_client_rpc_fails_closed() -> None:
    client = service_module._JSONClient(1024)
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        client._rpc("health", {})
