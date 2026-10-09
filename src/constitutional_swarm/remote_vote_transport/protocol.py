"""Wire schema and transport helpers for remote vote exchange."""

from __future__ import annotations

import json
import math
import os
import ssl
from dataclasses import asdict, dataclass

from constitutional_swarm.mesh.vote_envelope import (
    VoteEnvelope,
    vote_envelope_from_dict,
    vote_envelope_to_dict,
)
from typing import Literal
from urllib.parse import urlsplit

from constitutional_swarm.mesh import RemoteVoteRequest

TransportSecurity = Literal["plaintext", "tls", "auto"]

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _is_loopback_host(host: str) -> bool:
    return host in _LOOPBACK_HOSTS


def _format_uri_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _parse_ws_endpoint(host: str) -> tuple[str | None, str, int | None]:
    if "://" not in host:
        return None, host, None
    parsed = urlsplit(host)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError(f"Unsupported remote vote URL scheme: {parsed.scheme!r}")
    if parsed.hostname is None:
        raise ValueError("Remote vote URL must include a hostname")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Remote vote URL may not include a path, query, or fragment")
    return parsed.scheme, parsed.hostname, parsed.port


def _resolve_transport_security(
    *,
    transport_security: TransportSecurity,
    scheme: str | None,
    host: str,
) -> Literal["plaintext", "tls"]:
    if transport_security == "auto":
        if scheme == "wss":
            return "tls"
        if scheme == "ws":
            return "plaintext"
        return "plaintext" if _is_loopback_host(host) else "tls"
    return transport_security


def _build_ssl_context(
    mode: Literal["plaintext", "tls"],
    *,
    server_side: bool = False,
    ssl_context: ssl.SSLContext | None = None,
    certfile: str | os.PathLike[str] | None = None,
    keyfile: str | os.PathLike[str] | None = None,
) -> ssl.SSLContext | None:
    """Validate TLS configuration and return the context used by the transport."""
    if ssl_context is not None and (certfile is not None or keyfile is not None):
        raise ValueError("cannot combine ssl_context with certfile or keyfile")
    if keyfile is not None and certfile is None:
        raise ValueError("keyfile requires certfile")
    if mode == "plaintext":
        if ssl_context is not None or certfile is not None or keyfile is not None:
            raise ValueError("plaintext transport cannot use TLS material")
        return None
    if ssl_context is not None:
        expected_protocol = (
            ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
        )
        if ssl_context.protocol != expected_protocol:
            expected_name = (
                "PROTOCOL_TLS_SERVER" if server_side else "PROTOCOL_TLS_CLIENT"
            )
            raise ValueError(f"TLS context must use {expected_name}")
        return ssl_context
    if not server_side:
        return ssl.create_default_context()
    if certfile is None:
        raise ValueError("TLS server requires ssl_context or certfile")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


@dataclass(frozen=True, slots=True)
class RemoteVoteResponse:
    """Original signed vote envelope returned unchanged by a remote peer."""

    envelope: VoteEnvelope

    @property
    def assignment_id(self) -> str:
        return self.envelope.assignment_id

    @property
    def voter_id(self) -> str:
        return self.envelope.voter_id

    @property
    def approved(self) -> bool:
        return self.envelope.approved

    @property
    def reason(self) -> str:
        return self.envelope.reason

    @property
    def constitutional_hash(self) -> str:
        return self.envelope.constitutional_hash

    @property
    def content_hash(self) -> str:
        return self.envelope.content_hash

    @property
    def signature(self) -> str:
        return self.envelope.signature


def encode_remote_vote_request(request: RemoteVoteRequest) -> str:
    return json.dumps(asdict(request), separators=(",", ":"), allow_nan=False)


def decode_remote_vote_request(message: str) -> RemoteVoteRequest:
    try:
        payload = json.loads(message)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed remote vote request: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Malformed remote vote request: expected object, got {type(payload)}")
    expected = {
        "assignment_id", "voter_id", "producer_id", "artifact_id", "content",
        "content_hash", "constitutional_hash", "voter_public_key", "nonce",
        "timestamp", "request_signer_public_key", "request_signature", "task_id",
        "assigned_peers", "quorum", "evidence_mode", "protocol_version",
    }
    missing = expected - set(payload)
    extra = set(payload) - expected
    if missing:
        raise ValueError(
            f"Malformed remote vote request: missing {sorted(missing)[0]}"
        )
    if extra:
        raise ValueError("Malformed remote vote request: exact versioned schema required")
    string_fields = expected - {
        "timestamp", "assigned_peers", "quorum", "protocol_version"
    }
    if any(not isinstance(payload[name], str) for name in string_fields):
        raise ValueError("Malformed remote vote request: string field has invalid type")
    if type(payload["timestamp"]) is not float or not math.isfinite(payload["timestamp"]):
        raise ValueError("Malformed remote vote request: timestamp must be a finite float")
    if not isinstance(payload["assigned_peers"], list) or any(
        not isinstance(peer, str) for peer in payload["assigned_peers"]
    ):
        raise ValueError("Malformed remote vote request: assigned_peers must be strings")
    if type(payload["quorum"]) is not int:
        raise ValueError("Malformed remote vote request: quorum must be an integer")
    if type(payload["protocol_version"]) is not int or payload["protocol_version"] != 2:
        raise ValueError("Malformed remote vote request: unsupported protocol version")
    try:
        return RemoteVoteRequest(
            assignment_id=payload["assignment_id"], voter_id=payload["voter_id"],
            producer_id=payload["producer_id"], artifact_id=payload["artifact_id"],
            content=payload["content"], content_hash=payload["content_hash"],
            constitutional_hash=payload["constitutional_hash"],
            voter_public_key=payload["voter_public_key"], nonce=payload["nonce"],
            timestamp=payload["timestamp"],
            request_signer_public_key=payload["request_signer_public_key"],
            request_signature=payload["request_signature"], task_id=payload["task_id"],
            assigned_peers=tuple(payload["assigned_peers"]), quorum=payload["quorum"],
            evidence_mode=payload["evidence_mode"],
            protocol_version=payload["protocol_version"],
        )
    except KeyError as exc:
        raise ValueError(f"Malformed remote vote request: missing {exc.args[0]}") from exc


def encode_remote_vote_response(response: RemoteVoteResponse) -> str:
    return json.dumps(
        {"envelope": vote_envelope_to_dict(response.envelope)},
        sort_keys=True,
        separators=(",", ":"),
    )


def decode_remote_vote_response(message: str) -> RemoteVoteResponse:
    try:
        payload = json.loads(message)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed remote vote response: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Malformed remote vote response: expected object, got {type(payload)}")
    try:
        if set(payload) != {"envelope"} or not isinstance(payload["envelope"], dict):
            raise ValueError("Malformed remote vote response: exact envelope required")
        return RemoteVoteResponse(vote_envelope_from_dict(payload["envelope"]))
    except KeyError as exc:
        raise ValueError(f"Malformed remote vote response: missing {exc.args[0]}") from exc


__all__ = [
    "_LOOPBACK_HOSTS",
    "RemoteVoteResponse",
    "TransportSecurity",
    "_build_ssl_context",
    "_format_uri_host",
    "_is_loopback_host",
    "_parse_ws_endpoint",
    "_resolve_transport_security",
    "decode_remote_vote_request",
    "decode_remote_vote_response",
    "encode_remote_vote_request",
    "encode_remote_vote_response",
]
