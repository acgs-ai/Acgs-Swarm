"""Precedent Store — constitutional case law with 7-vector retrieval.

Phase 3.1 of the subnet implementation roadmap.

Stores validated miner judgments as constitutional precedent and provides
k-nearest-neighbour retrieval by 7-vector governance score similarity.
When a new ambiguous case arrives, the store retrieves the k most similar
precedents. If the top match exceeds an auto-resolve confidence threshold,
the system returns an auto-resolution — no miner needed.

Zero-retraining architecture (as specified in §5 of the Q&A doc):
  • Embeddings (the 7-vector governance scores) are never retrained
  • Only the precedent index grows as new cases are resolved
  • Every retrieval and auto-resolution is fully traceable to source cases
  • Bayesian weight updates are separate from the retrieval index

Key invariants:
  • PrecedentRecord is stored only after at least five distinct authorized
    voter envelopes verify, with at least three approvals and a strict majority
  • Tallies and acceptance are recomputed from signatures bound to the task,
    artifact, producer, judgment content, and constitutional hash
  • Rollback: any precedent can be revoked by marking it inactive

Trust boundary: voter keys and roles come only from an independently
provisioned VoteSignerRegistry. Unsigned or aggregate-only evidence fails
closed, and caller-supplied counts and proof roots are checked against the
verified envelopes.

Roadmap reference: 08-subnet-implementation-roadmap.md § Phase 3
Q&A reference:    07-subnet-concept-qa-responses.md § 5
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from constitutional_swarm.bittensor.protocol import EscalationType
from constitutional_swarm.mesh.vote_envelope import (
    FrozenVoteSignerRegistry,
    SignedAssignment,
    VoteEnvelope,
    VoteSignerRegistry,
    compute_vote_envelope_root,
    normalize_voter_id,
    verify_assignment_vote_envelopes,
)

# ---------------------------------------------------------------------------
# Vector utilities
# ---------------------------------------------------------------------------

_GOVERNANCE_DIMENSIONS = (
    "safety",
    "security",
    "privacy",
    "fairness",
    "reliability",
    "transparency",
    "efficiency",
)


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine similarity between two 7-vector governance score dicts.

    Missing dimensions default to 0.0.
    Returns value in [0.0, 1.0] (inputs are non-negative governance scores).
    """
    dims = _GOVERNANCE_DIMENSIONS
    dot = sum(a.get(d, 0.0) * b.get(d, 0.0) for d in dims)
    norm_a = math.sqrt(sum(a.get(d, 0.0) ** 2 for d in dims))
    norm_b = math.sqrt(sum(b.get(d, 0.0) ** 2 for d in dims))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _euclidean_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Euclidean distance between two 7-vector dicts."""
    dims = _GOVERNANCE_DIMENSIONS
    return math.sqrt(sum((a.get(d, 0.0) - b.get(d, 0.0)) ** 2 for d in dims))


# ---------------------------------------------------------------------------
# Precedent record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrecedentRecord:
    """A single validated miner judgment recorded as constitutional precedent.

    Immutable. All three party perspectives are stored:
      miner   — judgment + written rationale
      validator — acceptance + votes + proof
      sn_owner  — escalation type + impact vector (scoring weights at time)

    The impact_vector stores the 7 governance dimension scores that caused
    the escalation — this is the "embedding" used for retrieval.
    """

    precedent_id: str
    case_id: str
    task_id: str
    miner_uid: str

    # Miner perspective
    judgment: str
    reasoning: str

    # Validator perspective
    validation_accepted: bool
    votes_for: int
    votes_against: int
    proof_root_hash: str
    validator_grade: float  # 0.0-1.0; votes_for / total_votes

    # SN Owner perspective
    escalation_type: EscalationType
    impact_vector: dict[str, float]  # 7-dim governance scores at escalation time
    ambiguous_dimensions: tuple[str, ...]  # which vectors triggered escalation
    constitutional_hash: str

    # Metadata
    recorded_at: float
    is_active: bool = True  # False = revoked/rolled back
    assignment_id: str = ""
    artifact_id: str = ""
    content_hash: str = ""
    vote_envelopes: tuple[VoteEnvelope, ...] = ()
    signed_assignment: SignedAssignment | None = None

    @classmethod
    def create(
        cls,
        case_id: str,
        task_id: str,
        miner_uid: str,
        judgment: str,
        reasoning: str,
        votes_for: int,
        votes_against: int,
        proof_root_hash: str,
        escalation_type: EscalationType,
        impact_vector: dict[str, float],
        constitutional_hash: str,
        ambiguous_dimensions: tuple[str, ...] = (),
        assignment_id: str = "",
        artifact_id: str = "",
        content_hash: str = "",
        vote_envelopes: tuple[VoteEnvelope, ...] = (),
        signed_assignment: SignedAssignment | None = None,
    ) -> PrecedentRecord:
        total_votes = votes_for + votes_against
        grade = votes_for / total_votes if total_votes > 0 else 0.0
        return cls(
            precedent_id=uuid.uuid4().hex[:12],
            case_id=case_id,
            task_id=task_id,
            miner_uid=miner_uid,
            judgment=judgment,
            reasoning=reasoning,
            validation_accepted=True,  # only accepted judgments become precedent
            votes_for=votes_for,
            votes_against=votes_against,
            proof_root_hash=proof_root_hash,
            validator_grade=grade,
            escalation_type=escalation_type,
            impact_vector=impact_vector,
            ambiguous_dimensions=ambiguous_dimensions,
            constitutional_hash=constitutional_hash,
            recorded_at=time.time(),
            assignment_id=assignment_id,
            artifact_id=artifact_id,
            content_hash=content_hash,
            vote_envelopes=tuple(vote_envelopes),
            signed_assignment=signed_assignment,
        )


# ---------------------------------------------------------------------------
# Retrieval result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrecedentMatch:
    """A single precedent retrieved by similarity search."""

    precedent: PrecedentRecord
    similarity: float  # cosine similarity to the query vector
    rank: int  # 1 = best match

    @property
    def is_high_confidence(self) -> bool:
        return self.similarity >= 0.85


@dataclass
class RetrievalResult:
    """Result of a precedent retrieval operation.

    If auto_resolution is set, the store recommends resolving the case
    without human deliberation (similarity exceeded the threshold).
    """

    query_vector: dict[str, float]
    matches: list[PrecedentMatch]
    auto_resolution: str | None = None  # judgment text if auto-resolving
    auto_resolution_confidence: float = 0.0
    auto_resolution_source: str = ""  # precedent_id of the source

    @property
    def can_auto_resolve(self) -> bool:
        return self.auto_resolution is not None

    @property
    def top_match(self) -> PrecedentMatch | None:
        return self.matches[0] if self.matches else None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class PrecedentRevokedError(RuntimeError):
    """Raised when trying to use a revoked precedent."""


# ---------------------------------------------------------------------------
# Precedent Store
# ---------------------------------------------------------------------------


class PrecedentStore:
    """Constitutional case law database with 7-vector similarity retrieval.

    Stores validated miner judgments and supports k-NN retrieval by
    7-vector governance score similarity. When a new ambiguous case
    arrives, call retrieve() to find similar past cases and optionally
    get an auto-resolution if confidence is high enough.

    Admission independently authenticates voter identities and signatures,
    verifies every evidence binding, recomputes tallies and acceptance, and
    rejects proof roots that do not match the verified envelopes.

    Usage::

        store = PrecedentStore(
            constitutional_hash="608508a9bd224290",
            auto_resolve_threshold=0.85,
        )

        # Record a validated judgment
        record = PrecedentRecord.create(
            case_id="...", task_id="...", miner_uid="miner-01",
            judgment="Privacy takes precedence",
            reasoning="ECHR Article 8 applies",
            votes_for=3, votes_against=2,
            proof_root_hash="abc123",
            escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
            impact_vector={"privacy": 0.9, "transparency": 0.6, ...},
            constitutional_hash="608508a9bd224290",
        )
        store.add(record)

        # Retrieve similar precedents for a new case
        result = store.retrieve(
            impact_vector={"privacy": 0.88, "transparency": 0.62, ...},
            k=5,
        )
        if result.can_auto_resolve:
            # No miner needed for this case
            judgment = result.auto_resolution

        # Revoke a bad precedent (Governor action)
        store.revoke("precedent_id_here", reason="Contradicts new rule HEALTH-SEC-047")
    """

    def __init__(
        self,
        constitutional_hash: str,
        auto_resolve_threshold: float = 0.85,
        min_votes_for_precedent: int = 3,
        min_total_validators: int = 5,
        vote_registry: VoteSignerRegistry | FrozenVoteSignerRegistry | None = None,
    ) -> None:
        if (
            isinstance(min_votes_for_precedent, bool)
            or not isinstance(min_votes_for_precedent, int)
            or min_votes_for_precedent < 3
        ):
            raise ValueError("min_votes_for_precedent cannot be lower than 3")
        if (
            isinstance(min_total_validators, bool)
            or not isinstance(min_total_validators, int)
            or min_total_validators < 5
        ):
            raise ValueError("min_total_validators cannot be lower than 5")
        if min_votes_for_precedent > min_total_validators:
            raise ValueError("min_votes_for_precedent cannot exceed min_total_validators")
        if min_votes_for_precedent * 5 < 3 * min_total_validators:
            raise ValueError(
                "Configured precedent quorum cannot weaken the 3/5 super-majority ratio"
            )
        self._constitutional_hash = constitutional_hash
        self._auto_resolve_threshold = auto_resolve_threshold
        self._min_votes = min_votes_for_precedent
        self._min_total_validators = min_total_validators
        self._vote_registry = (
            None if vote_registry is None else vote_registry.frozen_copy()
        )
        self._records: dict[str, PrecedentRecord] = {}
        self._revocation_log: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    @property
    def constitutional_hash(self) -> str:
        return self._constitutional_hash

    @property
    def vote_registry(self) -> FrozenVoteSignerRegistry | None:
        """Return the independently provisioned voter trust registry."""
        return self._vote_registry

    def _validate_tally(self, record: PrecedentRecord) -> int:
        for name, value in (
            ("votes_for", record.votes_for),
            ("votes_against", record.votes_against),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} vote count must be an integer")
            if value < 0:
                raise ValueError(f"{name} vote count cannot be negative")
        total_votes = record.votes_for + record.votes_against
        if record.votes_for < self._min_votes:
            raise ValueError(
                f"Insufficient validator votes: got={record.votes_for} required={self._min_votes}"
            )
        if total_votes < self._min_total_validators:
            raise ValueError(
                f"Insufficient total validators: got={total_votes} "
                f"required={self._min_total_validators}"
            )
        if record.votes_for <= record.votes_against:
            raise ValueError(
                "Precedent admission requires a strict majority: more validator votes "
                "for than against"
            )
        if record.votes_for * self._min_total_validators < self._min_votes * total_votes:
            raise ValueError(
                "Insufficient validator super-majority: "
                f"got={record.votes_for}/{total_votes} "
                f"required={self._min_votes}/{self._min_total_validators}"
            )
        return total_votes

    def verify_evidence(self, record: PrecedentRecord) -> tuple[VoteEnvelope, ...]:
        """Verify signer authorization, bindings, tallies, and the proof root."""
        self._validate_tally(record)
        return self.verify_validation_evidence(
            task_id=record.task_id,
            producer_id=record.miner_uid,
            judgment=record.judgment,
            votes_for=record.votes_for,
            votes_against=record.votes_against,
            accepted=record.validation_accepted,
            proof_root_hash=record.proof_root_hash,
            assignment_id=record.assignment_id,
            artifact_id=record.artifact_id,
            content_hash=record.content_hash,
            constitutional_hash=record.constitutional_hash,
            vote_envelopes=record.vote_envelopes,
            signed_assignment=record.signed_assignment,
        )

    def verify_validation_evidence(
        self,
        *,
        task_id: str,
        producer_id: str,
        judgment: str,
        votes_for: int,
        votes_against: int,
        accepted: bool,
        proof_root_hash: str,
        assignment_id: str,
        artifact_id: str,
        content_hash: str,
        constitutional_hash: str,
        vote_envelopes: Sequence[VoteEnvelope],
        signed_assignment: SignedAssignment | None,
    ) -> tuple[VoteEnvelope, ...]:
        """Verify complete signed evidence for either validation outcome."""
        if self._vote_registry is None:
            raise ValueError("signed vote envelope admission requires a trust registry")
        if not vote_envelopes:
            raise ValueError("signed vote envelope evidence is required")
        if signed_assignment is None:
            raise ValueError("signed assignment evidence is required")
        if not assignment_id:
            raise ValueError("vote envelope assignment ID is required")
        if not artifact_id:
            raise ValueError("vote envelope artifact ID is required")
        if not content_hash:
            raise ValueError("vote envelope content hash is required")
        expected_content_hash = hashlib.sha256(judgment.encode("utf-8")).hexdigest()[:32]
        if content_hash != expected_content_hash:
            raise ValueError("precedent content hash does not bind the recorded judgment")

        verified = verify_assignment_vote_envelopes(
            signed_assignment,
            vote_envelopes,
            self._vote_registry,
            task_id=task_id,
            assignment_id=assignment_id,
            producer_id=normalize_voter_id(producer_id),
            artifact_id=artifact_id,
            content_hash=content_hash,
            constitutional_hash=constitutional_hash,
        )
        electorate_size = len(signed_assignment.assigned_peers)
        signed_quorum = signed_assignment.quorum
        if electorate_size < self._min_total_validators:
            raise ValueError(
                "signed electorate is too small for precedent admission: "
                f"got={electorate_size} required={self._min_total_validators}"
            )
        if signed_quorum < self._min_votes:
            raise ValueError(
                "signed quorum is too small for precedent admission: "
                f"got={signed_quorum} required={self._min_votes}"
            )
        if signed_quorum <= electorate_size // 2:
            raise ValueError("signed precedent quorum must be a strict majority")
        verified_votes_for = sum(
            envelope.decision == "approved" for envelope in verified
        )
        verified_votes_against = len(verified) - verified_votes_for
        if (votes_for, votes_against) != (
            verified_votes_for,
            verified_votes_against,
        ):
            raise ValueError(
                "supplied vote tally does not match verified vote envelope count"
            )
        verified_accepted = (
            verified_votes_for >= signed_quorum
            and verified_votes_for > verified_votes_against
        )
        verified_rejected = (
            verified_votes_against >= signed_quorum
            and verified_votes_against > verified_votes_for
        )
        if not (verified_accepted or verified_rejected):
            raise ValueError("verified vote tally has no strict-majority outcome")
        if accepted != verified_accepted:
            raise ValueError("validation acceptance does not match verified vote tally")
        expected_root = compute_vote_envelope_root(
            task_id=task_id,
            assignment_id=assignment_id,
            producer_id=normalize_voter_id(producer_id),
            artifact_id=artifact_id,
            content_hash=content_hash,
            constitutional_hash=constitutional_hash,
            accepted=verified_accepted,
            envelopes=verified,
        )
        if proof_root_hash != expected_root:
            raise ValueError("validation proof root does not match signed vote envelopes")
        return verified

    @property
    def size(self) -> int:
        """Number of active precedents."""
        with self._lock:
            return sum(1 for r in self._records.values() if r.is_active)

    @property
    def total_stored(self) -> int:
        """Total records including revoked."""
        with self._lock:
            return len(self._records)

    def add(self, record: PrecedentRecord) -> None:
        """Add a validated precedent record.

        Thread-safe: holds ``_lock`` for validation + insert to prevent
        TOCTOU races on duplicate-ID checks.

        Validates:
          • Constitutional hash match
          • Minimum validator votes
          • Not already present (idempotent add raises ValueError)
        """
        self._admit(record, exact_repeat_ok=False)

    def admit(self, record: PrecedentRecord) -> PrecedentRecord:
        """Admit *record*, treating an exact repeated observation as idempotent."""
        return self._admit(record, exact_repeat_ok=True)

    def _admit(
        self,
        record: PrecedentRecord,
        *,
        exact_repeat_ok: bool,
    ) -> PrecedentRecord:
        if record.constitutional_hash != self._constitutional_hash:
            raise ValueError(
                f"Constitutional hash mismatch: "
                f"expected={self._constitutional_hash} "
                f"got={record.constitutional_hash}"
            )
        if not record.validation_accepted:
            raise ValueError(
                f"Precedent {record.precedent_id} was not accepted by validators. "
                "Only accepted judgments may be stored."
            )
        if not record.is_active:
            raise ValueError(f"Precedent {record.precedent_id} is inactive or revoked")
        total_votes = self._validate_tally(record)
        verified = self.verify_evidence(record)
        canonical = dataclasses.replace(
            record,
            validator_grade=record.votes_for / total_votes,
            impact_vector=dict(record.impact_vector),
            ambiguous_dimensions=tuple(record.ambiguous_dimensions),
            miner_uid=normalize_voter_id(record.miner_uid),
            vote_envelopes=tuple(verified),
            signed_assignment=record.signed_assignment,
        )
        with self._lock:
            existing = self._records.get(record.precedent_id)
            if existing is not None:
                if exact_repeat_ok and existing == canonical:
                    return self._copy_record(existing)
                raise ValueError(f"Precedent {record.precedent_id} already stored.")
            if any(stored.case_id == canonical.case_id for stored in self._records.values()):
                raise ValueError(
                    f"Precedent source case already stored: case_id={canonical.case_id!r}"
                )
            if any(stored.task_id == canonical.task_id for stored in self._records.values()):
                raise ValueError(
                    f"Precedent source task already stored: task_id={canonical.task_id!r}"
                )
            self._records[canonical.precedent_id] = canonical
            return self._copy_record(canonical)

    def active_records(self) -> tuple[PrecedentRecord, ...]:
        """Return defensive snapshots of all currently active precedents."""
        with self._lock:
            return tuple(self._copy_record(r) for r in self._records.values() if r.is_active)

    def active_records_by_id(self, precedent_ids: list[str]) -> tuple[PrecedentRecord, ...]:
        """Resolve source IDs to active snapshots, failing closed on stale sources."""
        with self._lock:
            return self._active_records_by_id_locked(precedent_ids)

    def require_canonical_records(
        self,
        records: Sequence[PrecedentRecord],
    ) -> tuple[PrecedentRecord, ...]:
        """Resolve records already admitted to this store and reject altered copies."""
        precedent_ids = [record.precedent_id for record in records]
        if len(set(precedent_ids)) != len(precedent_ids):
            raise ValueError("Duplicate precedent source IDs are not canonical input")
        with self._lock:
            canonical = self._active_records_by_id_locked(precedent_ids)
            for supplied, admitted in zip(records, canonical, strict=True):
                if supplied != admitted:
                    raise ValueError(
                        f"Precedent source {supplied.precedent_id!r} does not match its "
                        "canonical admitted record"
                    )
            return canonical

    @contextmanager
    def guard_active_sources(
        self,
        precedent_ids: Sequence[str],
    ) -> Iterator[tuple[PrecedentRecord, ...]]:
        """Hold the store lock while a consumer validates and uses active sources."""
        self._lock.acquire()
        try:
            yield self._active_records_by_id_locked(precedent_ids)
        finally:
            self._lock.release()

    def retrieve(
        self,
        impact_vector: dict[str, float],
        k: int = 5,
        escalation_type: EscalationType | None = None,
        min_similarity: float = 0.0,
    ) -> RetrievalResult:
        """Retrieve k most similar precedents to the query vector.

        Filters:
          • Only active (non-revoked) records
          • Optionally filter by escalation_type
          • Only records with similarity >= min_similarity

        Auto-resolution: if the top match exceeds auto_resolve_threshold,
        the result includes an auto_resolution suggestion.

        Args:
            impact_vector: 7-dimensional governance score dict for the query
            k: maximum number of results to return
            escalation_type: optional filter by escalation category
            min_similarity: minimum cosine similarity to include

        Returns:
            RetrievalResult with ranked matches and optional auto-resolution
        """
        with self._lock:
            candidates = [
                self._copy_record(r)
                for r in self._records.values()
                if r.is_active
                and (escalation_type is None or r.escalation_type == escalation_type)
            ]

        # Score all candidates
        scored = [(r, _cosine_similarity(impact_vector, r.impact_vector)) for r in candidates]

        # Filter and sort
        filtered = [(r, sim) for r, sim in scored if sim >= min_similarity]
        filtered.sort(key=lambda x: x[1], reverse=True)

        # Build matches
        matches = [
            PrecedentMatch(precedent=r, similarity=sim, rank=i + 1)
            for i, (r, sim) in enumerate(filtered[:k])
        ]

        # Check for auto-resolution
        auto_resolution = None
        auto_confidence = 0.0
        auto_source = ""
        if matches and matches[0].similarity >= self._auto_resolve_threshold:
            best = matches[0].precedent
            auto_resolution = best.judgment
            auto_confidence = matches[0].similarity
            auto_source = best.precedent_id

        return RetrievalResult(
            query_vector=impact_vector,
            matches=matches,
            auto_resolution=auto_resolution,
            auto_resolution_confidence=auto_confidence,
            auto_resolution_source=auto_source,
        )

    def revoke(self, precedent_id: str, reason: str = "") -> None:
        """Revoke a precedent (Governor action).

        The record is kept in the store (for audit purposes) but
        marked inactive so it will not be returned in future retrievals.
        Revoked precedents are tracked in the revocation log.

        Raises KeyError if the precedent_id is not found.
        """
        with self._lock:
            if precedent_id not in self._records:
                raise KeyError(f"Precedent {precedent_id!r} not found.")

            record = self._records[precedent_id]
            # Replace with an inactive copy (PrecedentRecord is frozen)
            inactive = dataclasses.replace(record, is_active=False)
            self._records[precedent_id] = inactive

            self._revocation_log.append(
                {
                    "precedent_id": precedent_id,
                    "revoked_at": time.time(),
                    "reason": reason,
                }
            )

    # ------------------------------------------------------------------
    # Statistics and reporting
    # ------------------------------------------------------------------

    def escalation_distribution(self) -> dict[str, int]:
        """Count active precedents by escalation type."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records.values():
                if r.is_active:
                    key = r.escalation_type.value
                    counts[key] = counts.get(key, 0) + 1
        return counts

    def miner_contribution_counts(self) -> dict[str, int]:
        """Count active precedents contributed by each miner."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records.values():
                if r.is_active:
                    counts[r.miner_uid] = counts.get(r.miner_uid, 0) + 1
        return counts

    def escalation_rate_projection(
        self,
        baseline_rate: float = 0.03,
        decay_per_1k: float = 0.005,
    ) -> float:
        """Estimate current escalation rate given precedent accumulation.

        As precedents accumulate, the auto-resolution rate increases
        and effective escalation rate decreases.

        baseline_rate: starting escalation rate (default 3%)
        decay_per_1k:  reduction per 1,000 active precedents (default 0.5%)
        """
        active = self.size
        thousands = active / 1000.0
        projected = baseline_rate - (thousands * decay_per_1k)
        return max(0.005, projected)  # floor at 0.5% — some cases always novel

    def summary(self) -> dict[str, Any]:
        with self._lock:
            records = tuple(self._records.values())
            active = sum(1 for record in records if record.is_active)
            total = len(records)
            distribution: dict[str, int] = {}
            for record in records:
                if record.is_active:
                    key = record.escalation_type.value
                    distribution[key] = distribution.get(key, 0) + 1
            revocation_entries = len(self._revocation_log)
        projected = max(0.005, 0.03 - ((active / 1000.0) * 0.005))
        return {
            "constitutional_hash": self._constitutional_hash,
            "active_precedents": active,
            "total_stored": total,
            "revoked": total - active,
            "auto_resolve_threshold": self._auto_resolve_threshold,
            "min_votes_required": self._min_votes,
            "escalation_distribution": distribution,
            "revocation_log_entries": revocation_entries,
            "projected_escalation_rate": projected,
        }

    @staticmethod
    def _copy_record(record: PrecedentRecord) -> PrecedentRecord:
        return dataclasses.replace(
            record,
            impact_vector=dict(record.impact_vector),
            vote_envelopes=tuple(record.vote_envelopes),
            signed_assignment=record.signed_assignment,
        )

    def _active_records_by_id_locked(
        self,
        precedent_ids: Sequence[str],
    ) -> tuple[PrecedentRecord, ...]:
        records: list[PrecedentRecord] = []
        for precedent_id in precedent_ids:
            record = self._records.get(precedent_id)
            if record is None or not record.is_active:
                raise ValueError(
                    f"Precedent source {precedent_id!r} is not active or was revoked"
                )
            records.append(self._copy_record(record))
        return tuple(records)
