"""Bittensor synapse definitions for constitutional governance subnet.

Three message types:
  1. DeliberationSynapse: SN Owner → Miner (escalated governance case)
  2. JudgmentSynapse: Miner → Validator (deliberation result + DNA pre-check)
  3. ValidationSynapse: Validator → SN Owner (grading + Merkle proof)

These are protocol-level data structures. The actual bittensor.Synapse
base class is lazy-imported so the package works without bittensor installed.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from constitutional_swarm.mesh.vote_envelope import (
    SignedAssignment,
    VoteEnvelope,
    normalize_voter_id,
    vote_envelope_hash,
)

_SYNAPSE_HASH_DOMAIN = b"constitutional-swarm.bittensor-synapse.v1\x00"


def _canonical_synapse_hash(kind: str, payload: dict[str, str]) -> str:
    encoded = json.dumps(
        {"kind": kind, "protocol_version": 1, **payload},
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_SYNAPSE_HASH_DOMAIN + encoded).hexdigest()[:32]


def judgment_content_hash(judgment: str) -> str:
    """Return the content hash that signed vote evidence binds for *judgment*.

    Single definition shared by the validator, owner, precedent store and cascade.
    """
    if type(judgment) is not str:
        raise TypeError("judgment must be a string")
    return hashlib.sha256(judgment.encode("utf-8")).hexdigest()[:32]


def ordered_vote_hashes(envelopes: Iterable[VoteEnvelope]) -> tuple[str, ...]:
    """Return vote envelope hashes in the canonical proof order.

    The order key is ``(normalized voter_id, key_id)``. Valid envelopes already carry a
    canonical voter_id, so this matches the mesh proof ordering exactly.
    """
    ordered = sorted(
        envelopes,
        key=lambda envelope: (normalize_voter_id(envelope.voter_id), envelope.key_id),
    )
    return tuple(vote_envelope_hash(envelope) for envelope in ordered)


@dataclass(frozen=True, slots=True)
class DeliberationSynapse:
    """SN Owner → Miner: an escalated governance case requiring human judgment.

    Contains the serialized TaskDAG, constitutional hash for verification,
    domain/capability requirements for routing, and a deadline.
    """

    task_id: str
    task_dag_json: str
    constitution_hash: str
    domain: str
    required_capabilities: tuple[str, ...] = ()
    deadline_seconds: int = 3600
    escalation_type: str = ""
    impact_score: float = 0.0
    impact_vector: dict[str, float] = field(default_factory=dict)
    context: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def content_hash(self) -> str:
        """Deterministic hash of the deliberation request."""
        return _canonical_synapse_hash(
            "deliberation",
            {
                "task_id": self.task_id,
                "constitutional_hash": self.constitution_hash,
                "task_dag_json": self.task_dag_json,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class JudgmentSynapse:
    """Miner → Validator: deliberation result with DNA pre-validation.

    Contains the miner's governance judgment, written reasoning,
    the artifact hash for integrity, and the DNA pre-check result.
    The constitutional_hash must match the validator's constitution.
    """

    task_id: str
    miner_uid: str
    judgment: str
    reasoning: str
    artifact_hash: str
    constitutional_hash: str
    dna_valid: bool = True
    dna_violations: tuple[str, ...] = ()
    dna_latency_ns: int = 0
    domain: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def content_hash(self) -> str:
        """Deterministic hash of the judgment."""
        return _canonical_synapse_hash(
            "judgment",
            {
                "task_id": self.task_id,
                "miner_uid": self.miner_uid,
                "judgment": self.judgment,
                "constitutional_hash": self.constitutional_hash,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ValidationSynapse:
    """Validator → SN Owner: grading result with cryptographic proof.

    Contains the MeshResult (accepted/rejected, vote counts, quorum),
    the MeshProof (Merkle chain), and optional manifold trust update.
    """

    task_id: str
    assignment_id: str
    accepted: bool
    votes_for: int
    votes_against: int
    quorum_met: bool
    proof_root_hash: str = ""
    proof_vote_hashes: tuple[str, ...] = ()
    proof_content_hash: str = ""
    constitutional_hash: str = ""
    trust_update: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    vote_envelopes: tuple[VoteEnvelope, ...] = ()
    signed_assignment: SignedAssignment | None = None

    @property
    def is_verified(self) -> bool:
        """Report whether all structural proof components are present."""
        return bool(
            self.proof_root_hash
            and self.proof_vote_hashes
            and self.vote_envelopes
            and self.signed_assignment is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
