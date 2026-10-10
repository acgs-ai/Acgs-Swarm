"""Voting payload types for the Constitutional Mesh."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from constitutional_swarm.mesh.vote_envelope import SignedAssignment


@dataclass(frozen=True, slots=True)
class ValidationVote:
    """A peer's Ed25519-signed vote on a producer's output."""

    assignment_id: str
    voter_id: str
    approved: bool
    reason: str
    signature: str
    constitutional_hash: str
    content_hash: str
    timestamp: float

    @property
    def vote_hash(self) -> str:
        """Deterministic hash of this vote for proof chain."""
        payload = {
            "approved": self.approved,
            "assignment_id": self.assignment_id,
            "constitutional_hash": self.constitutional_hash,
            "content_hash": self.content_hash,
            "reason": self.reason,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "voter_id": self.voter_id,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(b"constitutional-swarm.validation-vote.v2\x00" + encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RemoteVoteRequest:
    """Signable vote request for a public-key-only remote peer."""

    assignment_id: str
    voter_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    constitutional_hash: str
    voter_public_key: str
    nonce: str
    timestamp: float
    request_signer_public_key: str
    request_signature: str
    task_id: str = ""
    assigned_peers: tuple[str, ...] = ()
    quorum: int = 0
    evidence_mode: Literal["independent", "single_operator_dev"] = "independent"
    protocol_version: int = 3
    signed_assignment: SignedAssignment | None = None
