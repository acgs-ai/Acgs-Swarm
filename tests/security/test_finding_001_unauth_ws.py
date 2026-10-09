"""Regression test for security finding SEC-001: unauthenticated WebSocket transport.

Origin
------
- First audited: security-audit-report.md (HIGH finding)
- Remediation claim: SYSTEMIC_IMPROVEMENT.md — non-loopback transport defaults to TLS
- Status as of this test's existence: REMEDIATED (asserted here)

Contract
--------
- `RemoteVoteClient(transport_security="auto")` must default non-loopback hosts to
  TLS and therefore pass a real `ssl.SSLContext` into the websocket connector.
- Loopback addresses (`127.0.0.1`, `localhost`, `::1`) may still proceed without
  TLS for dev use and therefore pass `ssl=None`.
- If anyone changes the auto-derived default back to plaintext for non-loopback
  hosts, this test turns red and the security audit should be considered open again.
"""

from __future__ import annotations

import ssl

import pytest
from constitutional_swarm.mesh import RemoteVoteRequest
from constitutional_swarm.mesh.vote_envelope import VoteEnvelope, canonical_assigned_peers_hash
from constitutional_swarm.remote_vote_transport import (
    RemoteVoteClient,
    RemoteVoteResponse,
    encode_remote_vote_response,
)

FINDING_ID = "SEC-001"
SEVERITY = "HIGH"
STATUS = "remediated"
TITLE = "Unauthenticated WebSocket transport"

websockets = pytest.importorskip(
    "websockets", reason="websockets not installed — skip remote vote transport security tests"
)


def _minimal_request() -> RemoteVoteRequest:
    return RemoteVoteRequest(
        assignment_id="test-assignment",
        voter_id="test-voter",
        producer_id="test-producer",
        artifact_id="test-artifact",
        content="",
        content_hash="0" * 64,
        constitutional_hash="0" * 16,
        voter_public_key="",
        nonce="nonce-security",
        timestamp=1234.5,
        request_signer_public_key="",
        request_signature="",
        task_id="test-task",
        assigned_peers=("test-voter",),
        quorum=1,
    )


class _FakeClientWebSocket:
    def __init__(self, recv_value: str) -> None:
        self._recv_value = recv_value

    async def send(self, _message: str) -> None:
        return None

    async def recv(self) -> str:
        return self._recv_value


class _FakeConnectContext:
    def __init__(self, websocket: _FakeClientWebSocket) -> None:
        self.websocket = websocket

    async def __aenter__(self) -> _FakeClientWebSocket:
        return self.websocket

    async def __aexit__(self, *_: object) -> None:
        return None


def _ok_response(request: RemoteVoteRequest) -> str:
    response = RemoteVoteResponse(
        VoteEnvelope(
            protocol_version=2,
            voter_id=request.voter_id,
            key_id="00" * 32,
            task_id=request.task_id or request.artifact_id,
            assignment_id=request.assignment_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            decision="approved",
            reason="ok",
            nonce=request.nonce,
            issued_at=request.timestamp,
            signature="00" * 64,
            assigned_peers_hash=canonical_assigned_peers_hash((request.voter_id,)),
            assigned_peer_count=1,
            quorum=1,
            evidence_mode="independent",
        )
    )
    return encode_remote_vote_response(response)


@pytest.mark.security
class TestFindingSEC001:
    async def test_auto_non_localhost_uses_tls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = RemoteVoteClient(transport_security="auto")
        request = _minimal_request()
        captured: dict[str, object] = {}

        def _connect(uri: str, ssl: object = None) -> _FakeConnectContext:
            captured["uri"] = uri
            captured["ssl"] = ssl
            return _FakeConnectContext(_FakeClientWebSocket(_ok_response(request)))

        monkeypatch.setattr(websockets, "connect", _connect)

        await client.request_vote(host="peer.example.com", port=8443, request=request)

        assert captured["uri"] == "wss://peer.example.com:8443"
        assert isinstance(captured["ssl"], ssl.SSLContext)

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
    async def test_auto_loopback_stays_plaintext(
        self,
        monkeypatch: pytest.MonkeyPatch,
        host: str,
    ) -> None:
        client = RemoteVoteClient(transport_security="auto")
        request = _minimal_request()
        captured: dict[str, object] = {}

        def _connect(uri: str, ssl: object = None) -> _FakeConnectContext:
            captured["uri"] = uri
            captured["ssl"] = ssl
            return _FakeConnectContext(_FakeClientWebSocket(_ok_response(request)))

        monkeypatch.setattr(websockets, "connect", _connect)

        await client.request_vote(host=host, port=8443, request=request)

        assert captured["uri"] == f"ws://{host}:8443"
        assert captured["ssl"] is None

    def test_ipv6_loopback_is_kept_local(self) -> None:
        from constitutional_swarm.remote_vote_transport import _LOOPBACK_HOSTS

        assert "::1" in _LOOPBACK_HOSTS
