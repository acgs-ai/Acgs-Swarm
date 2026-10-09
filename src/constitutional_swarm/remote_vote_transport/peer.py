"""Peer-side validation and signing for remote vote requests."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
import threading

from acgs_lite import Constitution
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteRequest
from constitutional_swarm.mesh.vote_envelope import (
    FrozenVoteSignerRegistry,
    VoteSignerRegistryView,
    key_id_for_public_key,
    normalize_voter_id,
    sign_vote_envelope,
    signed_assignment_digest,
    verify_signed_assignment,
)
from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse


def _constitution_fingerprint(constitution: Constitution) -> str:
    payload = json.dumps(
        constitution.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class LocalRemotePeer:
    """Runtime for a public-key-only remote peer that validates/signs votes."""

    def __init__(
        self,
        *,
        agent_id: str,
        constitution: Constitution,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
        strict: bool = False,
        trusted_request_signers: set[str] | None = None,
        trusted_assigners: VoteSignerRegistryView,
        allow_untrusted_request_signers: bool = False,
        replay_window_seconds: float = 300.0,
    ) -> None:
        if allow_untrusted_request_signers:
            raise ValueError(
                "allow_untrusted_request_signers is insecure; configure trusted_request_signers"
            )
        self.agent_id = normalize_voter_id(agent_id)
        self.strict = strict
        self._constitution = constitution.model_copy(deep=True)
        self._constitutional_hash = self._constitution.hash
        self._constitution_fingerprint = _constitution_fingerprint(self._constitution)
        self._dna = AgentDNA(
            constitution=self._constitution,
            agent_id=self.agent_id,
            strict=strict,
        )
        self._private_key = self._coerce_private_key(vote_private_key)
        self._public_key = self._private_key.public_key()
        self._trusted_request_signers = set()
        for public_key in trusted_request_signers or set():
            key_id_for_public_key(public_key)
            self._trusted_request_signers.add(public_key)
        if not isinstance(trusted_assigners, FrozenVoteSignerRegistry):
            raise TypeError("trusted_assigners must be an immutable registry snapshot")
        self._trusted_assigners = trusted_assigners
        self._replay_window_seconds = replay_window_seconds
        self._request_nonce_caches: dict[str, OrderedDict[str, float]] = {}
        self._request_nonce_cache: OrderedDict[str, float] = OrderedDict()
        self._nonce_lock = threading.Lock()

    @property
    def public_key_hex(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @property
    def constitution(self) -> Constitution:
        """Return a detached view of the constitution evaluated by this peer."""
        return self._constitution.model_copy(deep=True)

    def _assert_constitution_unchanged(self) -> None:
        if (
            self._dna.constitution is not self._constitution
            or _constitution_fingerprint(self._constitution) != self._constitution_fingerprint
        ):
            raise RuntimeError("Remote peer constitution changed after initialization")

    def handle_vote_request(self, request: RemoteVoteRequest) -> RemoteVoteResponse:
        if request.voter_id != self.agent_id:
            raise ValueError(
                f"Vote request intended for {request.voter_id}, but peer is {self.agent_id}"
            )
        if request.voter_public_key != self.public_key_hex:
            raise ValueError("Vote request public key does not match remote peer identity")
        self._assert_constitution_unchanged()
        local_constitutional_hash = self._constitutional_hash
        if request.constitutional_hash != local_constitutional_hash:
            raise ValueError("Remote vote request constitutional hash does not match local constitution")
        if request.signed_assignment is None:
            raise ValueError("Remote vote request is missing its signed assignment")
        assignment = verify_signed_assignment(
            request.signed_assignment,
            self._trusted_assigners,
            task_id=request.task_id or request.artifact_id,
            assignment_id=request.assignment_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
        )
        if self.agent_id not in assignment.assigned_peers:
            raise ValueError("Remote peer is not a member of the signed assignment")
        if request.assigned_peers != assignment.assigned_peers:
            raise ValueError("Remote vote request electorate does not match signed assignment")
        if request.quorum != assignment.quorum:
            raise ValueError("Remote vote request quorum does not match signed assignment")
        if (
            request.request_signer_public_key not in self._trusted_request_signers
        ):
            raise ValueError("Remote vote request signer is not trusted")
        ConstitutionalMesh.verify_remote_vote_request(
            request,
            replay_window_seconds=self._replay_window_seconds,
        )
        with self._nonce_lock:
            signer_cache = self._request_nonce_caches.setdefault(
                request.request_signer_public_key, OrderedDict()
            )
            ConstitutionalMesh.verify_remote_vote_request(
                request,
                replay_window_seconds=self._replay_window_seconds,
                nonce_cache=signer_cache,
            )
            self._request_nonce_cache = signer_cache
        if hashlib.sha256(request.content.encode("utf-8")).hexdigest()[:32] != request.content_hash:
            raise ValueError("Remote vote request content does not match content hash")

        result = self._dna.validate(request.content)
        self._assert_constitution_unchanged()
        if result.constitutional_hash != local_constitutional_hash:
            raise RuntimeError("Remote peer validator used an unexpected constitution")
        approved = result.valid
        reason = "constitutional check passed" if result.valid else "; ".join(result.violations)
        envelope = sign_vote_envelope(
            self._private_key,
            voter_id=request.voter_id,
            task_id=request.task_id or request.artifact_id,
            assignment_id=request.assignment_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content_hash=request.content_hash,
            constitutional_hash=local_constitutional_hash,
            decision="approved" if approved else "denied",
            reason=reason,
            nonce=request.nonce,
            issued_at=request.timestamp,
            assigned_peers=request.assigned_peers,
            quorum=request.quorum,
            evidence_mode=request.evidence_mode,
            assignment_digest=signed_assignment_digest(assignment),
        )
        return RemoteVoteResponse(envelope)

    @staticmethod
    def _coerce_private_key(
        value: Ed25519PrivateKey | bytes | str | None,
    ) -> Ed25519PrivateKey:
        if value is None:
            return Ed25519PrivateKey.generate()
        if isinstance(value, Ed25519PrivateKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PrivateKey.from_private_bytes(raw)


__all__ = ["LocalRemotePeer"]
