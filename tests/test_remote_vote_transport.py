"""Tests for remote_vote_transport.py — remote peer vote collection/runtime."""

from __future__ import annotations

import builtins
import json
import ssl
from dataclasses import replace
from typing import Any

import pytest
from acgs_lite import Constitution
from constitutional_swarm import (
    ConstitutionalMesh,
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteRequest,
    RemoteVoteResponse,
    RemoteVoteServer,
)
from constitutional_swarm.remote_vote_transport import (
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.mesh.vote_envelope import (
    sign_vote_envelope,
    signed_assignment_digest,
)

websockets = pytest.importorskip(
    "websockets", reason="websockets not installed — skip remote vote transport tests"
)


def _standalone_request() -> RemoteVoteRequest:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=1,
        quorum=1,
        seed=19,
        evidence_mode="single_operator_dev",
    )
    mesh.register_local_signer("producer")
    mesh.register_local_signer("peer-1")
    assignment = mesh.request_validation("producer", "safe content", "art-1")
    return mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")


def _signed_response(
    request: RemoteVoteRequest,
    *,
    assignment_id: str | None = None,
    voter_id: str | None = None,
) -> RemoteVoteResponse:
    envelope = sign_vote_envelope(
        Ed25519PrivateKey.generate(),
        voter_id=voter_id or request.voter_id,
        task_id=request.task_id or request.artifact_id,
        assignment_id=assignment_id or request.assignment_id,
        producer_id=request.producer_id,
        artifact_id=request.artifact_id,
        content_hash=request.content_hash,
        constitutional_hash=request.constitutional_hash,
        decision="approved",
        reason="ok",
        nonce=request.nonce,
        issued_at=request.timestamp,
        assigned_peers=request.assigned_peers or (voter_id or request.voter_id,),
        quorum=request.quorum or 1,
        evidence_mode=request.evidence_mode,
        assignment_digest=(
            signed_assignment_digest(request.signed_assignment)
            if request.signed_assignment is not None
            else ""
        ),
    )
    return RemoteVoteResponse(envelope)


@pytest.fixture
def remote_transport_context() -> dict[str, Any]:
    """Remote-vote setup with one local signer and one remote peer."""
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=2,
        quorum=2,
        seed=23,
        evidence_mode="single_operator_dev",
    )
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=remote_peer.public_key_hex)
    mesh.register_local_signer("peer-local")
    assignment = mesh.request_validation("producer", "fixture content", "art-fixture")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-remote")
    return {
        "mesh": mesh,
        "peer": remote_peer,
        "assignment": assignment,
        "request": request,
    }


class _FakeServerWebSocket:
    def __init__(self, incoming: list[str]) -> None:
        self._incoming = list(incoming)
        self.sent: list[str] = []

    def __aiter__(self) -> _FakeServerWebSocket:
        return self

    async def __anext__(self) -> str:
        if self._incoming:
            return self._incoming.pop(0)
        raise StopAsyncIteration

    async def send(self, message: str) -> None:
        self.sent.append(message)


class _FakeClientWebSocket:
    def __init__(
        self, *, recv_value: str | None = None, recv_error: BaseException | None = None
    ) -> None:
        self.sent: list[str] = []
        self._recv_value = recv_value
        self._recv_error = recv_error

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str:
        if self._recv_error is not None:
            raise self._recv_error
        assert self._recv_value is not None
        return self._recv_value


class _FakeConnectContext:
    def __init__(self, websocket: _FakeClientWebSocket) -> None:
        self.websocket = websocket

    async def __aenter__(self) -> _FakeClientWebSocket:
        return self.websocket

    async def __aexit__(self, *_: Any) -> None:
        return None


def test_remote_vote_request_round_trip() -> None:
    request = _standalone_request()
    decoded = decode_remote_vote_request(encode_remote_vote_request(request))
    assert decoded == request


def test_remote_vote_response_round_trip() -> None:
    request = _standalone_request()
    response = _signed_response(request)
    decoded = decode_remote_vote_response(encode_remote_vote_response(response))
    assert decoded == response


def test_remote_vote_response_rejects_legacy_unsigned_shape() -> None:
    with pytest.raises(ValueError, match="exact envelope required"):
        decode_remote_vote_response(
            '{"assignment_id":"assign-1","voter_id":"peer-1","approved":"false",'
            '"reason":"ok","constitutional_hash":"const-hash","content_hash":"abc123",'
            '"signature":"cafebabe"}'
        )


@pytest.mark.asyncio
async def test_remote_vote_server_round_trip() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=7, evidence_mode="single_operator_dev")
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-1")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket([encode_remote_vote_request(request)])
    await server._handle_connection(websocket)
    response = decode_remote_vote_response(websocket.sent[0])

    assert response.assignment_id == request.assignment_id
    assert response.voter_id == "peer-1"
    assert response.approved is True
    assert response.envelope.task_id == request.task_id


@pytest.mark.asyncio
async def test_full_validation_remote_collects_remote_and_local_votes() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=11, evidence_mode="single_operator_dev")
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )

    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=remote_peer.public_key_hex)
    mesh.register_local_signer("peer-local-1")
    mesh.register_local_signer("peer-local-2")

    class InMemoryRemoteVoteClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return remote_peer.handle_vote_request(request)

    result = await mesh.full_validation_remote(
        "producer",
        "safe remote-reviewed content",
        "art-remote",
        peer_routes={"peer-remote": ("localhost", 1)},
        client=InMemoryRemoteVoteClient(),
    )

    assert result.accepted is True
    assert result.quorum_met is True
    assert result.proof is not None
    assert result.proof.verify() is True


def test_remote_peer_rejects_tampered_content_hash() -> None:
    constitution = Constitution.default()
    request_signer = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        constitution,
        seed=13,
        request_signing_private_key=request_signer,
        evidence_mode="single_operator_dev",
    )
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-2")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    tampered_content = "tampered content"
    tampered = replace(
        request,
        content=tampered_content,
        request_signature=request_signer.sign(
            ConstitutionalMesh.build_remote_vote_request_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                producer_id=request.producer_id,
                artifact_id=request.artifact_id,
                content=tampered_content,
                content_hash=request.content_hash,
                constitutional_hash=request.constitutional_hash,
                voter_public_key=request.voter_public_key,
                nonce=request.nonce,
                timestamp=request.timestamp,
                task_id=request.task_id,
                assigned_peers=request.assigned_peers,
                quorum=request.quorum,
                evidence_mode=request.evidence_mode,
                protocol_version=request.protocol_version,
                signed_assignment=request.signed_assignment,
            )
        ).hex(),
    )
    with pytest.raises(ValueError, match="content does not match"):
        peer.handle_vote_request(tampered)


def test_remote_peer_rejects_untrusted_request_signer() -> None:
    constitution = Constitution.default()
    trusted_mesh = ConstitutionalMesh(
        constitution, seed=17, evidence_mode="single_operator_dev"
    )
    untrusted_mesh = ConstitutionalMesh(
        constitution, seed=18, evidence_mode="single_operator_dev"
    )
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={trusted_mesh.get_request_signing_public_key()},
        trusted_assigners=untrusted_mesh.vote_registry.frozen_copy(),
    )
    untrusted_mesh.register_local_signer("producer")
    untrusted_mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    untrusted_mesh.register_local_signer("peer-2")
    untrusted_mesh.register_local_signer("peer-3")
    assignment = untrusted_mesh.request_validation("producer", "safe content", "art-3")
    request = untrusted_mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    with pytest.raises(ValueError, match="not trusted"):
        peer.handle_vote_request(request)


# ---------------------------------------------------------------------------
# Phase 6: Remote vote transport failure-path tests
# ---------------------------------------------------------------------------


class TestDecodeRemoteVoteRequestErrors:
    """Failure paths in decode_remote_vote_request (lines 50-71)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote request"):
            decode_remote_vote_request("{not-json!")

    def test_non_dict_json_array(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request("[1,2,3]")

    def test_non_dict_json_string(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request('"just a string"')

    @pytest.mark.parametrize(
        "missing_field",
        [
            "assignment_id",
            "voter_id",
            "producer_id",
            "artifact_id",
            "content",
            "content_hash",
            "constitutional_hash",
            "voter_public_key",
            "nonce",
            "timestamp",
            "request_signer_public_key",
            "request_signature",
            "task_id",
            "assigned_peers",
            "quorum",
            "evidence_mode",
            "protocol_version",
            "signed_assignment",
        ],
    )
    def test_missing_required_field(self, missing_field: str) -> None:
        full_payload = json.loads(encode_remote_vote_request(_standalone_request()))
        del full_payload[missing_field]

        with pytest.raises(ValueError, match=f"missing {missing_field}"):
            decode_remote_vote_request(json.dumps(full_payload))


class TestDecodeRemoteVoteResponseErrors:
    """Failure paths in decode_remote_vote_response (lines 78-99)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote response"):
            decode_remote_vote_response("not-json{")

    def test_non_dict_json(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_response("[1]")

    def test_rejects_legacy_unsigned_response(self) -> None:
        import json

        payload = {
            "assignment_id": "a",
            "voter_id": "v",
            "approved": True,
            "reason": "ok",
            "constitutional_hash": "ch",
            # missing content_hash
            "signature": "sig",
        }
        with pytest.raises(ValueError, match="exact envelope required"):
            decode_remote_vote_response(json.dumps(payload))


class TestLocalRemotePeerValidation:
    """Explicit tests for LocalRemotePeer.handle_vote_request guard clauses."""

    def _make_peer_and_request(self) -> tuple[LocalRemotePeer, RemoteVoteRequest]:
        """Create a valid peer + request pair for mutation tests."""
        constitution = Constitution.default()
        mesh = ConstitutionalMesh(
            constitution, seed=42, evidence_mode="single_operator_dev"
        )
        peer = LocalRemotePeer(
            agent_id="peer-1",
            constitution=constitution,
            trusted_request_signers={mesh.get_request_signing_public_key()},
            trusted_assigners=mesh.vote_registry.frozen_copy(),
        )
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
        mesh.register_local_signer("peer-2")
        mesh.register_local_signer("peer-3")
        assignment = mesh.request_validation("producer", "safe content", "art-val")
        request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
        return peer, request

    def test_rejects_wrong_voter_id(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_voter = replace(request, voter_id="wrong-peer")
        with pytest.raises(ValueError, match="intended for wrong-peer"):
            peer.handle_vote_request(wrong_voter)

    def test_rejects_mismatched_pubkey(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_key = replace(
            request,
            voter_public_key="0000000000000000000000000000000000000000000000000000000000000000",
        )
        with pytest.raises(ValueError, match="public key does not match"):
            peer.handle_vote_request(wrong_key)


@pytest.mark.asyncio
async def test_remote_vote_client_connection_timeout_propagates() -> None:
    """RemoteVoteClient.request_vote() must propagate TimeoutError when the server is unresponsive.
    """
    import asyncio

    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution, seed=42, evidence_mode="single_operator_dev"
    )
    mesh.register_local_signer("producer")
    mesh.register_local_signer("peer-1")
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "content", "art-timeout")

    # Build a valid request (voter_id is just needed for the dataclass; server ignores it here).
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")

    fake_ws = _FakeClientWebSocket(recv_error=TimeoutError())
    client = RemoteVoteClient()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            websockets,
            "connect",
            lambda uri, ssl=None: _FakeConnectContext(fake_ws),
        )
        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await client.request_vote("localhost", 9999, request, timeout=0.1)


@pytest.mark.asyncio
async def test_remote_vote_server_malformed_json_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    peer = remote_transport_context["peer"]
    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket(["{not-json!"])

    with pytest.raises(ValueError, match="Malformed remote vote request"):
        await server._handle_connection(websocket)


@pytest.mark.asyncio
async def test_remote_vote_client_malformed_response_json_raises_value_error(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = remote_transport_context["request"]
    fake_ws = _FakeClientWebSocket(recv_value="{not-json!")
    monkeypatch.setattr(
        websockets,
        "connect",
        lambda uri, ssl=None: _FakeConnectContext(fake_ws),
    )

    client = RemoteVoteClient()
    with pytest.raises(ValueError, match="Malformed remote vote response"):
        await client.request_vote("localhost", 9999, request)


@pytest.mark.asyncio
async def test_remote_vote_server_pubkey_mismatch_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    peer = remote_transport_context["peer"]
    request = remote_transport_context["request"]
    bad_request = replace(
        request,
        voter_public_key="00" * 32,
    )

    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket([encode_remote_vote_request(bad_request)])

    with pytest.raises(ValueError, match="public key does not match"):
        await server._handle_connection(websocket)


@pytest.mark.asyncio
async def test_collect_remote_votes_missing_route_raises_key_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    with pytest.raises(KeyError, match="No route found for remote peer 'peer-remote'"):
        await mesh.collect_remote_votes(assignment.assignment_id, peer_routes={})


@pytest.mark.asyncio
async def test_collect_remote_votes_wrong_assignment_id_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class WrongAssignmentClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return _signed_response(request, assignment_id="wrong-assignment")

    with pytest.raises(ValueError, match="assignment mismatch"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=WrongAssignmentClient(),
        )


@pytest.mark.asyncio
async def test_collect_remote_votes_wrong_voter_id_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class WrongVoterClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return _signed_response(request, voter_id="wrong-peer")

    with pytest.raises(ValueError, match="voter mismatch"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=WrongVoterClient(),
        )


@pytest.mark.asyncio
async def test_collect_remote_votes_timeout_propagates(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class TimeoutClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            raise TimeoutError("timed out")

    with pytest.raises(TimeoutError, match="timed out"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=TimeoutClient(),
            timeout=0.1,
        )


@pytest.mark.asyncio
async def test_remote_vote_client_missing_websockets_dependency_raises_import_error(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = remote_transport_context["request"]
    original_import = builtins.__import__

    def _missing_websockets(
        name: str,
        globals_: dict[str, Any] | None = None,
        locals_: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "websockets":
            raise ImportError("No module named 'websockets'")
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _missing_websockets)

    client = RemoteVoteClient()
    with pytest.raises(
        ImportError,
        match=r"Remote vote transport requires 'websockets>=12\.0'",
    ):
        await client.request_vote("localhost", 9000, request)


def test_transport_security_plaintext_rejects_explicit_ssl_context() -> None:
    with pytest.raises(ValueError, match="plaintext transport cannot use TLS material"):
        RemoteVoteServer(
            lambda request: _signed_response(request),
            transport_security="plaintext",
            ssl_context=ssl.create_default_context(),
        )


def test_transport_security_tls_accepts_supplied_server_context() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server = RemoteVoteServer(
        lambda request: _signed_response(request),
        transport_security="tls",
        ssl_context=context,
    )

    assert server.ssl_context is context


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "expects_tls"),
    [
        ("ws://localhost", False),
        ("wss://localhost", True),
    ],
)
async def test_transport_security_auto_derives_from_endpoint_scheme(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    expects_tls: bool,
) -> None:
    request = remote_transport_context["request"]
    response = _signed_response(request)
    fake_ws = _FakeClientWebSocket(recv_value=encode_remote_vote_response(response))
    captured: dict[str, Any] = {}

    def _connect(uri: str, ssl: Any = None) -> _FakeConnectContext:
        captured["uri"] = uri
        captured["ssl"] = ssl
        return _FakeConnectContext(fake_ws)

    monkeypatch.setattr(websockets, "connect", _connect)

    client = RemoteVoteClient(transport_security="auto")
    await client.request_vote(host, 9443, request)

    assert captured["uri"] == f"{host}:9443"
    assert (captured["ssl"] is not None) is expects_tls


def test_remote_vote_server_auto_derives_ssl_context_from_host_scheme() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_server = RemoteVoteServer(
        lambda request: _signed_response(request),
        host="wss://localhost",
        transport_security="auto",
        ssl_context=context,
    )
    plaintext_server = RemoteVoteServer(
        lambda request: _signed_response(request),
        host="ws://localhost",
        transport_security="auto",
    )

    assert tls_server.ssl_context is context
    assert plaintext_server.ssl_context is None
