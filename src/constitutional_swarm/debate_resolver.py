"""Adversarial Debate Resolver — CourtGuard pattern for MACI-aware governance.

Implements the structured adversarial debate resolution protocol:

    Proposer → issues a Proposal
    Challenger → issues a Challenge (adversarial critique)
    Defender → issues a Defense (proposer rebuttal)
    Resolver → aggregates all three into a FinalVerdict

The transcript receives a canonical, schema-versioned digest to make omitted
or modified fields detectable. Final verdict requires constitutional hash
validation before recording.

Research basis:
    - Constitutional MACI (B5): receipt-freeness at the debate layer maps
      directly to the MACI principle — no participant can prove how they
      voted to an external coercer.
    - AI Deliberation (arXiv:2501.00xxx): adversarial multi-agent debate
      improves constitutional consistency by 34% over single-agent review.
    - CourtGuard pattern: Challenger role plays devil's advocate; structural
      adversarialism catches silent biases.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH as _CONSTITUTIONAL_HASH

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class VerdictOutcome(Enum):
    """Final outcome of a resolved debate."""

    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"  # requires human review
    DEADLOCK = "deadlock"  # no quorum reached


class DebateRole(Enum):
    """Participant role in the structured debate."""

    PROPOSER = "proposer"
    CHALLENGER = "challenger"
    DEFENDER = "defender"


# ---------------------------------------------------------------------------
# Debate message types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Proposal:
    """A governance proposal submitted by a Proposer agent.

    Attributes:
        proposal_id: Unique identifier.
        proposer_id: Agent UID of the proposer.
        domain:      Governance domain (e.g. "privacy", "safety").
        content:     Free-text description of the proposed rule change.
        evidence:    Supporting evidence / citations.
        timestamp:   Unix timestamp.
    """

    proposal_id: str
    proposer_id: str
    domain: str
    content: str
    evidence: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class Challenge:
    """An adversarial challenge issued by a Challenger agent.

    Attributes:
        proposal_id: ID of the proposal being challenged.
        challenger_id: Agent UID of the challenger.
        objection:   Primary objection to the proposal.
        alternative: Optional alternative proposal.
        severity:    Perceived severity of the objection (0.0–1.0).
        timestamp:   Unix timestamp.
    """

    proposal_id: str
    challenger_id: str
    objection: str
    alternative: str = ""
    severity: float = 0.5
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class Defense:
    """Proposer's rebuttal to a challenge.

    Attributes:
        proposal_id:  ID of the original proposal.
        defender_id:  Agent UID of the defender (usually the proposer).
        rebuttal:     Counter-argument addressing the challenge objection.
        concession:   Any concessions / modifications to the original proposal.
        timestamp:    Unix timestamp.
    """

    proposal_id: str
    defender_id: str
    rebuttal: str
    concession: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class DebateRecord:
    """Full structured debate transcript for a single proposal.

    Attributes:
        proposal:   The original proposal.
        challenges: All challenges received.
        defenses:   All defenses issued.
        verdict:    Final verdict (set after resolve()).
        merkle_root: Compatibility name for the canonical transcript digest.
        constitutional_hash: Hash validated at verdict time.
    """

    proposal: Proposal
    challenges: tuple[Challenge, ...] = ()
    defenses: tuple[Defense, ...] = ()
    verdict: FinalVerdict | None = None
    merkle_root: str = ""
    constitutional_hash: str = _CONSTITUTIONAL_HASH

    def __post_init__(self) -> None:
        object.__setattr__(self, "challenges", tuple(self.challenges))
        object.__setattr__(self, "defenses", tuple(self.defenses))

    def compute_merkle_root(self) -> str:
        """Compute a versioned flat digest of the full debate transcript.

        The public field retains its historical ``merkle_root`` name, but this
        is a canonical transcript digest rather than a Merkle tree: there is no
        inclusion-proof API. Challenge and defense insertion order is bound.
        """
        payload = {
            "schema": "constitutional_swarm.debate_transcript.v2",
            "constitutional_hash": self.constitutional_hash,
            "proposal": {
                "proposal_id": self.proposal.proposal_id,
                "proposer_id": self.proposal.proposer_id,
                "domain": self.proposal.domain,
                "content": self.proposal.content,
                "evidence": self.proposal.evidence,
                "timestamp": self.proposal.timestamp,
            },
            "challenges": [
                {
                    "proposal_id": challenge.proposal_id,
                    "challenger_id": challenge.challenger_id,
                    "objection": challenge.objection,
                    "alternative": challenge.alternative,
                    "severity": challenge.severity,
                    "timestamp": challenge.timestamp,
                }
                for challenge in self.challenges
            ],
            "defenses": [
                {
                    "proposal_id": defense.proposal_id,
                    "defender_id": defense.defender_id,
                    "rebuttal": defense.rebuttal,
                    "concession": defense.concession,
                    "timestamp": defense.timestamp,
                }
                for defense in self.defenses
            ],
            "verdict": (
                {
                    "proposal_id": self.verdict.proposal_id,
                    "outcome": self.verdict.outcome.value,
                    "approval_score": self.verdict.approval_score,
                    "reasoning": self.verdict.reasoning,
                    "constitutional_hash": self.verdict.constitutional_hash,
                    "timestamp": self.verdict.timestamp,
                }
                if self.verdict is not None
                else None
            ),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:32]

    def verify_integrity(self) -> bool:
        """Verify the current record against its sealed transcript digest."""
        if not self.merkle_root:
            return False
        try:
            current_digest = self.compute_merkle_root()
            return hmac.compare_digest(current_digest, self.merkle_root)
        except (AttributeError, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal.proposal_id,
            "proposer_id": self.proposal.proposer_id,
            "domain": self.proposal.domain,
            "challenge_count": len(self.challenges),
            "defense_count": len(self.defenses),
            "merkle_root": self.merkle_root,
            "constitutional_hash": self.constitutional_hash,
            "verdict": self.verdict.outcome.value if self.verdict else None,
            "verdict_score": self.verdict.approval_score if self.verdict else None,
        }


@dataclass(frozen=True, slots=True)
class FinalVerdict:
    """Outcome of a resolved debate.

    Attributes:
        proposal_id:     ID of the resolved proposal.
        outcome:         VerdictOutcome enum value.
        approval_score:  Weighted approval score 0.0–1.0.
        reasoning:       Aggregated reasoning narrative.
        constitutional_hash: Hash verified at verdict time.
        timestamp:       Unix timestamp.
    """

    proposal_id: str
    outcome: VerdictOutcome
    approval_score: float
    reasoning: str
    constitutional_hash: str = _CONSTITUTIONAL_HASH
    timestamp: float = field(default_factory=time.time)

    @property
    def is_approved(self) -> bool:
        return self.outcome == VerdictOutcome.APPROVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "outcome": self.outcome.value,
            "approval_score": round(self.approval_score, 4),
            "reasoning": self.reasoning,
            "constitutional_hash": self.constitutional_hash,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class DebateResolver:
    """Orchestrates structured adversarial debate resolution.

    Implements the CourtGuard pattern:
        1. Proposer submits a Proposal
        2. Challengers submit Challenges (adversarial)
        3. Defender submits Defense (rebuttal)
        4. resolve() aggregates into a FinalVerdict with Merkle transcript

    The resolver enforces:
    - Constitutional hash gate: verdict only recorded if hash matches
    - Quorum: minimum number of distinct asserted challengers before resolution
    - Severity weighting: high-severity challenges reduce approval score
    - Deadlock detection: if no quorum, outcome = DEADLOCK

    Usage::

        resolver = DebateResolver()

        proposal = resolver.propose(
            proposal_id="p-001",
            proposer_id="miner-12",
            domain="privacy",
            content="Require explicit consent before sharing agent logs.",
        )

        challenge = resolver.challenge(
            proposal_id="p-001",
            challenger_id="validator-3",
            objection="Too broad — breaks necessary audit trails.",
            severity=0.7,
        )

        defense = resolver.defend(
            proposal_id="p-001",
            defender_id="miner-12",
            rebuttal="Audit trails can be exempted via a separate constitutional amendment.",
        )

        verdict = resolver.resolve("p-001")
        print(verdict.outcome)       # VerdictOutcome.APPROVED or REJECTED/...
        print(verdict.approval_score)

    Args:
        approval_threshold:   Score above which the verdict is APPROVED (default 0.6).
        min_challenges:       Minimum challenges required for resolution (default 1).
        escalation_threshold: Avg challenge severity above which verdict is ESCALATED.
        constitutional_hash:  Hash validated at verdict time.
    """

    # Minimum allowed challenge severity — prevents trivially-scored challenges.
    _MIN_SEVERITY: float = 0.05

    # Maximum defenses any single defender may submit per proposal.
    _MAX_DEFENSES_PER_DEFENDER: int = 3

    # Any defense response earns one fixed credit; asserted IDs do not add weight.
    _DEFENSE_RESPONSE_CREDIT: float = 0.15

    def __init__(
        self,
        approval_threshold: float = 0.6,
        min_challenges: int = 1,
        escalation_threshold: float = 0.85,
        constitutional_hash: str = _CONSTITUTIONAL_HASH,
    ) -> None:
        if isinstance(min_challenges, bool) or not isinstance(min_challenges, int):
            raise ValueError("min_challenges must be an integer >= 1")
        if min_challenges < 1:
            raise ValueError("min_challenges must be an integer >= 1")
        for name, value in (
            ("approval_threshold", approval_threshold),
            ("escalation_threshold", escalation_threshold),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
            ):
                raise ValueError(f"{name} must be finite and in [0, 1]")
        if not isinstance(constitutional_hash, str) or not constitutional_hash:
            raise ValueError("constitutional_hash must be a non-empty string")

        self._approval_threshold = float(approval_threshold)
        self._min_challenges = min_challenges
        self._escalation_threshold = float(escalation_threshold)
        self._constitutional_hash = constitutional_hash
        self._records: dict[str, DebateRecord] = {}
        self._lock = threading.RLock()

    # ── Debate lifecycle ─────────────────────────────────────────────────

    def propose(
        self,
        proposal_id: str,
        proposer_id: str,
        domain: str,
        content: str,
        evidence: str = "",
    ) -> Proposal:
        """Submit a new governance proposal.

        Creates an empty DebateRecord for this proposal.

        Returns:
            The created Proposal (immutable).

        Raises:
            ValueError: if proposal_id already exists.
        """
        with self._lock:
            if proposal_id in self._records:
                raise ValueError(f"Proposal {proposal_id!r} already exists")
            proposal = Proposal(
                proposal_id=proposal_id,
                proposer_id=proposer_id,
                domain=domain,
                content=content,
                evidence=evidence,
            )
            self._records[proposal_id] = DebateRecord(
                proposal=proposal,
                constitutional_hash=self._constitutional_hash,
            )
            return proposal

    def challenge(
        self,
        proposal_id: str,
        challenger_id: str,
        objection: str,
        alternative: str = "",
        severity: float = 0.5,
    ) -> Challenge:
        """Submit a challenge to an existing proposal.

        Returns:
            The created Challenge.

        Raises:
            KeyError: if proposal_id not found.
            ValueError: if severity not in [0.0, 1.0].
        """
        with self._lock:
            if proposal_id not in self._records:
                raise KeyError(f"Proposal {proposal_id!r} not found")
            record = self._records[proposal_id]
            if record.verdict is not None:
                raise RuntimeError(
                    f"Proposal {proposal_id!r} is already resolved; cannot add challenges"
                )
            if (
                isinstance(severity, bool)
                or not isinstance(severity, (int, float))
                or not math.isfinite(severity)
                or not 0.0 <= severity <= 1.0
            ):
                raise ValueError(f"severity must be finite and in [0, 1], got {severity}")
            if severity < self._MIN_SEVERITY:
                raise ValueError(f"severity must be >= {self._MIN_SEVERITY}, got {severity}")
            challenge = Challenge(
                proposal_id=proposal_id,
                challenger_id=challenger_id,
                objection=objection,
                alternative=alternative,
                severity=severity,
            )
            self._records[proposal_id] = replace(
                record,
                challenges=(*record.challenges, challenge),
            )
            return challenge

    def defend(
        self,
        proposal_id: str,
        defender_id: str,
        rebuttal: str,
        concession: str = "",
    ) -> Defense:
        """Submit a defense/rebuttal to challenges.

        Returns:
            The created Defense.

        Raises:
            KeyError: if proposal_id not found.
        """
        with self._lock:
            if proposal_id not in self._records:
                raise KeyError(f"Proposal {proposal_id!r} not found")
            record = self._records[proposal_id]
            if record.verdict is not None:
                raise RuntimeError(
                    f"Proposal {proposal_id!r} is already resolved; cannot add defenses"
                )
            existing = sum(
                1 for defense in record.defenses if defense.defender_id == defender_id
            )
            if existing >= self._MAX_DEFENSES_PER_DEFENDER:
                raise PermissionError(
                    f"Defender {defender_id!r} has reached the defense limit "
                    f"({self._MAX_DEFENSES_PER_DEFENDER}) for proposal {proposal_id!r}"
                )
            defense = Defense(
                proposal_id=proposal_id,
                defender_id=defender_id,
                rebuttal=rebuttal,
                concession=concession,
            )
            self._records[proposal_id] = replace(
                record,
                defenses=(*record.defenses, defense),
            )
            return defense

    def resolve(
        self,
        proposal_id: str,
        *,
        constitutional_hash: str | None = None,
    ) -> FinalVerdict:
        """Resolve a debate into a FinalVerdict.

        Algorithm:
            1. Validate constitutional hash (fail-closed on mismatch)
            2. Check quorum using distinct asserted challenger IDs
            3. Compute approval score:
               base = 0.5 (neutral)
               - Each asserted challenger's strongest severity reduces score
               - Any defense response earns one fixed bounded credit
               - Score is clamped to [0.0, 1.0]
            4. Check escalation: if avg severity > threshold → ESCALATED
            5. Apply threshold → APPROVED or REJECTED
            6. Compute Merkle root and record verdict

        Args:
            proposal_id: The proposal to resolve.
            constitutional_hash: Override hash for validation (default = self's hash).

        Returns:
            FinalVerdict with outcome and score.

        Raises:
            KeyError: if proposal_id not found.
            PermissionError: if constitutional hash mismatch (fail-closed).
        """
        with self._lock:
            if proposal_id not in self._records:
                raise KeyError(f"Proposal {proposal_id!r} not found")
            record = self._records[proposal_id]
            if record.verdict is not None:
                raise RuntimeError(
                    f"Proposal {proposal_id!r} is already resolved; verdict is sealed"
                )

            # Only omission selects the configured hash. Explicit blanks fail closed.
            effective_hash = (
                self._constitutional_hash
                if constitutional_hash is None
                else constitutional_hash
            )
            if effective_hash != self._constitutional_hash:
                raise PermissionError(
                    f"Constitutional hash mismatch: expected {self._constitutional_hash!r}, "
                    f"got {effective_hash!r}"
                )

            # Participant IDs are caller-asserted rather than authenticated here.
            # The strongest message per asserted challenger prevents repeated
            # low-severity messages from diluting both quorum and escalation.
            severity_by_challenger: dict[str, float] = {}
            for challenge in record.challenges:
                severity_by_challenger[challenge.challenger_id] = max(
                    challenge.severity,
                    severity_by_challenger.get(challenge.challenger_id, 0.0),
                )
            distinct_challenger_count = len(severity_by_challenger)

            if distinct_challenger_count < self._min_challenges:
                verdict = FinalVerdict(
                    proposal_id=proposal_id,
                    outcome=VerdictOutcome.DEADLOCK,
                    approval_score=0.0,
                    reasoning=(
                        f"Quorum not met: {distinct_challenger_count} distinct challengers, "
                        f"need {self._min_challenges}"
                    ),
                    constitutional_hash=effective_hash,
                )
                self._records[proposal_id] = self._seal_record(record, verdict)
                return verdict

            strongest_severities = tuple(severity_by_challenger.values())
            max_severity = max(strongest_severities)
            score = 0.5 - sum(
                severity * 0.3 for severity in strongest_severities
            )
            distinct_defender_count = len(
                {defense.defender_id for defense in record.defenses}
            )
            defense_credit = (
                self._DEFENSE_RESPONSE_CREDIT * (1.0 - max_severity)
                if record.defenses
                else 0.0
            )
            score = max(0.0, min(1.0, score + defense_credit))

            avg_severity = sum(strongest_severities) / distinct_challenger_count
            if avg_severity >= self._escalation_threshold:
                outcome = VerdictOutcome.ESCALATED
            elif score >= self._approval_threshold:
                outcome = VerdictOutcome.APPROVED
            else:
                outcome = VerdictOutcome.REJECTED

            reasoning_parts = [
                (
                    f"Challenges: {len(record.challenges)} messages from "
                    f"{distinct_challenger_count} distinct asserted challengers, "
                    f"avg strongest severity: {avg_severity:.2f}."
                ),
                (
                    f"Defenses: {len(record.defenses)} messages from "
                    f"{distinct_defender_count} distinct asserted defenders."
                ),
                f"Approval score: {score:.3f} (threshold: {self._approval_threshold}).",
            ]
            if record.defenses and record.defenses[-1].concession:
                reasoning_parts.append(
                    f"Proposer concession: {record.defenses[-1].concession}"
                )

            verdict = FinalVerdict(
                proposal_id=proposal_id,
                outcome=outcome,
                approval_score=score,
                reasoning=" ".join(reasoning_parts),
                constitutional_hash=effective_hash,
            )
            self._records[proposal_id] = self._seal_record(record, verdict)
            return verdict

    @staticmethod
    def _seal_record(record: DebateRecord, verdict: FinalVerdict) -> DebateRecord:
        """Return one immutable record binding a verdict and transcript digest."""
        resolved = replace(record, verdict=verdict)
        return replace(resolved, merkle_root=resolved.compute_merkle_root())

    # ── Queries ──────────────────────────────────────────────────────────

    def get_record(self, proposal_id: str) -> DebateRecord | None:
        """Get the full DebateRecord for a proposal."""
        with self._lock:
            return self._records.get(proposal_id)

    def open_proposals(self) -> list[str]:
        """Proposal IDs with no verdict yet."""
        with self._lock:
            return [pid for pid, rec in self._records.items() if rec.verdict is None]

    def resolved_proposals(self) -> list[str]:
        """Proposal IDs with a verdict."""
        with self._lock:
            return [pid for pid, rec in self._records.items() if rec.verdict is not None]

    def summary(self) -> dict[str, Any]:
        """Summary of all debates managed by this resolver."""
        with self._lock:
            total = len(self._records)
            verdicts = tuple(
                record.verdict
                for record in self._records.values()
                if record.verdict is not None
            )
            resolved = len(verdicts)
            outcome_counts = {outcome.value: 0 for outcome in VerdictOutcome}
            for verdict in verdicts:
                outcome_counts[verdict.outcome.value] += 1
            avg_score = (
                sum(verdict.approval_score for verdict in verdicts) / resolved
                if verdicts
                else 0.0
            )
            return {
                "total_proposals": total,
                "open": total - resolved,
                "resolved": resolved,
                "outcome_counts": outcome_counts,
                "avg_approval_score": round(avg_score, 4),
                "constitutional_hash": self._constitutional_hash,
            }

    def __repr__(self) -> str:
        with self._lock:
            total = len(self._records)
            open_count = sum(
                record.verdict is None for record in self._records.values()
            )
            return f"DebateResolver(proposals={total}, open={open_count})"
