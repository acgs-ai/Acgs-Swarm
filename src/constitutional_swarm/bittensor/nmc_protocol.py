"""NMC Protocol — Phase 2.4: anti-collusion multi-miner deliberation.

When multiple miners contribute to a single governance case, they must not
be able to copy each other's reasoning. The NMC (Nil Message Compute)
pattern solves this via a commit-reveal scheme:

    Phase 1 — COMMIT:
        Each miner independently forms a judgment, then hashes it with a
        nonce and submits only the hash (commitment). No content is revealed.

    Phase 2 — REVEAL:
        After all miners commit (or deadline passes), each reveals their
        (judgment, nonce) pair. The coordinator verifies the commitment
        matches, then synthesizes a consensus judgment.

    Phase 3 — SYNTHESIZE:
        Combine revealed judgments into a single ConsensusJudgment using
        majority vote (categorical) or weighted vote (with tier weights).
        Miners with identical judgments are flagged as potential Sybils.

Anti-Sybil Guarantees:
  • Commitment phase: miners can't see others' work → can't copy
  • Commitments bind session_id, case_id and miner_uid, so a commitment (and
    its reveal) cannot be copied to another identity or replayed in another
    session; duplicate commitment hashes are rejected outright
  • Every session has a mandatory, caller-supplied roster of required miners
  • Sybil detection: identical judgment texts → SybilFlag (automatic)
  • Consensus tallies each committed identity once; flags remain telemetry
  • The chain of commitments + reveals is a tamper-evident audit log

Pluggability:
  • Real NMC (multi-party computation): replace synthesize() backend
  • Real Noir ZKP: prover reveals without exposing content to coordinator
    (currently: plaintext reveal for practicality)

Roadmap: 08-subnet-implementation-roadmap.md § Phase 2.3 NMC
Q&A §3:  docs/strategy/07-subnet-concept-qa-responses.md
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
import warnings
from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from constitutional_swarm.bittensor._validation import _validate_count, _validate_finite
from constitutional_swarm.framing import framed_digest

_COMMITMENT_DOMAIN = b"constitutional-swarm:nmc-commitment:v2"
_HEX_DIGITS = frozenset("0123456789abcdef")


def compute_commitment_hash(
    judgment_text: str,
    nonce: str,
    *,
    session_id: str,
    case_id: str,
    miner_uid: str,
) -> str:
    """Return the canonical commitment for an NMC reveal.

    The pre-image is a typed, length-prefixed :func:`framed_digest` over
    ``(session_id, case_id, miner_uid, judgment_text, nonce)``, so a
    commitment is bound to one miner identity in one session of one case and
    cannot be copied to another identity or replayed elsewhere.
    """
    return framed_digest(
        _COMMITMENT_DOMAIN, session_id, case_id, miner_uid, judgment_text, nonce
    ).hex()


def _require_commitment_hash(commitment_hash: object) -> str:
    if type(commitment_hash) is not str:
        raise TypeError("commitment_hash must be a string")
    if len(commitment_hash) != 64 or not _HEX_DIGITS.issuperset(commitment_hash):
        raise ValueError("commitment_hash must be 64 lowercase hex characters")
    return commitment_hash


def _require_roster(required_miners: Collection[str]) -> frozenset[str]:
    if isinstance(required_miners, str) or not isinstance(required_miners, Collection):
        raise TypeError("required_miners must be a collection of miner identifiers")
    roster = frozenset(required_miners)
    if not roster:
        raise ValueError("required_miners must name at least one miner")
    for miner_uid in roster:
        if type(miner_uid) is not str or not miner_uid:
            raise ValueError("required_miners entries must be non-empty strings")
    return roster


def _deterministic_winner(scores: Mapping[str, int | float]) -> str:
    """Return the lexically first judgment among those with the top score."""
    top_score = max(scores.values())
    return min(judgment for judgment, score in scores.items() if score == top_score)


def _warn_deprecated_exclude_sybils(exclude_sybils: bool | None) -> None:
    if exclude_sybils is not None:
        warnings.warn(
            "exclude_sybils is deprecated; duplicate-content flags are "
            "telemetry and never remove independently identified miners",
            DeprecationWarning,
            stacklevel=3,
        )

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NMCSessionState(Enum):
    OPEN = "open"  # accepting commitments
    REVEALING = "revealing"  # commit phase closed; accepting reveals
    SYNTHESIZED = "synthesized"  # consensus produced
    TIMED_OUT = "timed_out"  # deadline passed without full consensus
    FAILED = "failed"  # too few reveals to synthesize


class SynthesisMethod(Enum):
    MAJORITY_VOTE = "majority_vote"  # most common judgment text wins
    WEIGHTED_VOTE = "weighted_vote"  # weight by trusted coordinator tier map
    UNANIMOUS = "unanimous"  # all miners must agree (strictest)


# ---------------------------------------------------------------------------
# Immutable records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NMCCommitment:
    """A miner's blind commitment to a judgment.

    Use :func:`compute_commitment_hash` to construct ``commitment_hash``.
    """

    commitment_id: str
    miner_uid: str
    commitment_hash: str
    submitted_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "miner_uid": self.miner_uid,
            "commitment_hash": self.commitment_hash,
            "submitted_at": self.submitted_at,
        }


@dataclass(frozen=True, slots=True)
class NMCReveal:
    """A miner's reveal of their committed judgment.

    The coordinator verifies the canonical commitment encoding.
    """

    reveal_id: str
    miner_uid: str
    judgment_text: str  # the actual governance decision
    nonce: str  # random nonce used in commitment
    weight: float  # voting weight (e.g. tier TAO multiplier)
    revealed_at: float

    def verify_commitment(self, commitment_hash: str, *, session_id: str, case_id: str) -> bool:
        """Verify this reveal opens ``commitment_hash`` in the given session."""
        expected = compute_commitment_hash(
            self.judgment_text,
            self.nonce,
            session_id=session_id,
            case_id=case_id,
            miner_uid=self.miner_uid,
        )
        return hmac.compare_digest(expected, commitment_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reveal_id": self.reveal_id,
            "miner_uid": self.miner_uid,
            "judgment_text": self.judgment_text,
            "nonce": self.nonce,
            "weight": self.weight,
            "revealed_at": self.revealed_at,
        }


@dataclass(frozen=True, slots=True)
class SybilFlag:
    """Indicates a potential Sybil attack: two miners submitted identical judgments.

    When two miners produce exactly the same judgment text after independently
    committing (without seeing each other's work), it is highly suspicious.
    The commit phase makes copying impossible — so identical text is likely
    coordination outside the protocol or a Sybil identity.
    """

    flag_id: str
    flagged_miner: str
    reference_miner: str  # the miner whose judgment was copied
    judgment_hash: str  # SHA-256 of the duplicated judgment
    confidence: float  # 1.0 = exact match; <1.0 = near-match (future use)
    reason: str

    @property
    def is_exact_duplicate(self) -> bool:
        return self.confidence >= 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "flag_id": self.flag_id,
            "flagged_miner": self.flagged_miner,
            "reference_miner": self.reference_miner,
            "judgment_hash": self.judgment_hash,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ConsensusJudgment:
    """The synthesized output of an NMC session.

    confidence: ratio of miners that agreed with the winning judgment.
    sybil_flags: miners suspected of Sybil behavior in this session.
    excluded_miners: retained for wire compatibility; duplicate-content flags
        are telemetry and do not remove independently identified miners.
    """

    session_id: str
    case_id: str
    judgment_text: str
    confidence: float  # 0.0-1.0 (fraction agreeing)
    method: SynthesisMethod
    committed_count: int  # how many miners committed
    reveal_count: int  # how many miners revealed
    valid_reveal_count: int  # unique committed identities included in tally
    sybil_flags: tuple[SybilFlag, ...]
    excluded_miners: tuple[str, ...]
    synthesized_at: float

    @property
    def has_sybil_activity(self) -> bool:
        return len(self.sybil_flags) > 0

    @property
    def is_high_confidence(self) -> bool:
        """True if ≥ 2/3 of valid miners agreed."""
        return self.confidence >= 2 / 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "judgment_text": self.judgment_text,
            "confidence": round(self.confidence, 4),
            "method": self.method.value,
            "committed_count": self.committed_count,
            "reveal_count": self.reveal_count,
            "valid_reveal_count": self.valid_reveal_count,
            "sybil_flags": [f.to_dict() for f in self.sybil_flags],
            "excluded_miners": list(self.excluded_miners),
            "synthesized_at": self.synthesized_at,
            "has_sybil_activity": self.has_sybil_activity,
        }


# ---------------------------------------------------------------------------
# NMC Session
# ---------------------------------------------------------------------------


class NMCSession:
    """Commit-reveal session for a single governance case.

    Lifecycle::

        session = NMCSession(
            case_id="ESC-2026-042",
            required_miners={"miner-01", "miner-02", "miner-03"},
            deadline_seconds=300,
        )

        # Phase 1: commit (miners do this independently, bound to the session)
        nonce = uuid.uuid4().hex
        commitment_hash = compute_commitment_hash(
            judgment,
            nonce,
            session_id=session.session_id,
            case_id=session.case_id,
            miner_uid="miner-01",
        )
        session.accept_commitment("miner-01", commitment_hash)

        # Phase 2: reveal (after all commit or deadline)
        session.close_commits()
        session.accept_reveal("miner-01", judgment, nonce, weight=1.5)

        # Phase 3: synthesize
        consensus = session.synthesize()
        print(consensus.judgment_text, consensus.confidence)

    ``required_miners`` is mandatory and non-empty: only rostered identities
    may commit. ``exclude_sybils`` is deprecated. Duplicate-content detection
    is telemetry; every independently committed miner identity remains in the
    tally.
    """

    def __init__(
        self,
        case_id: str,
        required_miners: Collection[str],
        min_reveals: int = 2,
        deadline_seconds: float = 300.0,
        exclude_sybils: bool | None = None,
        miner_weights: Mapping[str, float] | None = None,
        trust_supplied_weights: bool = False,
    ) -> None:
        self._required = _require_roster(required_miners)
        self._min_reveals = _validate_count("min_reveals", min_reveals, minimum=1)
        deadline = _validate_finite("deadline_seconds", deadline_seconds)
        if deadline <= 0.0:
            raise ValueError("deadline_seconds must be positive")
        self.session_id = uuid.uuid4().hex[:12]
        self.case_id = case_id
        self._deadline_at = time.time() + deadline
        _warn_deprecated_exclude_sybils(exclude_sybils)
        self._miner_weights = dict(miner_weights) if miner_weights is not None else {}
        self._trust_supplied_weights = trust_supplied_weights

        self._commitments: dict[str, NMCCommitment] = {}  # miner_uid → commitment
        self._reveals: dict[str, NMCReveal] = {}  # miner_uid → reveal
        self._state = NMCSessionState.OPEN
        self._consensus: ConsensusJudgment | None = None

    # ------------------------------------------------------------------
    # State & properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> NMCSessionState:
        if self._state == NMCSessionState.OPEN and self._is_deadline_passed():
            return NMCSessionState.TIMED_OUT
        return self._state

    @property
    def is_complete(self) -> bool:
        return self._state in (
            NMCSessionState.SYNTHESIZED,
            NMCSessionState.TIMED_OUT,
            NMCSessionState.FAILED,
        )

    @property
    def committed_miners(self) -> set[str]:
        return set(self._commitments)

    @property
    def revealed_miners(self) -> set[str]:
        return set(self._reveals)

    @property
    def pending_reveal_miners(self) -> set[str]:
        """Miners who committed but haven't revealed yet."""
        return self.committed_miners - self.revealed_miners

    @property
    def consensus(self) -> ConsensusJudgment | None:
        return self._consensus

    # ------------------------------------------------------------------
    # Phase 1: Commit
    # ------------------------------------------------------------------

    def accept_commitment(self, miner_uid: str, commitment_hash: str) -> bool:
        """Accept a miner's commitment.

        Returns True if accepted.
        Raises ValueError if the session is not in OPEN state, the miner is
        not on the roster or already committed, or the hash is malformed or
        duplicates another miner's commitment.
        """
        _require_commitment_hash(commitment_hash)
        if self._state != NMCSessionState.OPEN:
            raise ValueError(f"Session {self.session_id} is {self._state.value}, not OPEN")
        if self._is_deadline_passed():
            self._state = NMCSessionState.TIMED_OUT
            raise ValueError(f"Session {self.session_id} deadline passed")
        if miner_uid in self._commitments:
            raise ValueError(f"Miner {miner_uid} already committed")
        if miner_uid not in self._required:
            raise ValueError(f"Miner {miner_uid} is not required for this session")
        if any(
            hmac.compare_digest(existing.commitment_hash, commitment_hash)
            for existing in self._commitments.values()
        ):
            raise ValueError("duplicate commitment hash rejected")

        c = NMCCommitment(
            commitment_id=uuid.uuid4().hex[:8],
            miner_uid=miner_uid,
            commitment_hash=commitment_hash,
            submitted_at=time.time(),
        )
        self._commitments[miner_uid] = c

        # Auto-transition when all required miners committed
        if self._required.issubset(self._commitments):
            self._state = NMCSessionState.REVEALING

        return True

    def close_commits(self) -> int:
        """Manually close the commit phase (e.g. on partial timeout).

        Returns the number of commitments received.
        """
        if self._state == NMCSessionState.OPEN:
            self._state = NMCSessionState.REVEALING
        return len(self._commitments)

    # ------------------------------------------------------------------
    # Phase 2: Reveal
    # ------------------------------------------------------------------

    def accept_reveal(
        self,
        miner_uid: str,
        judgment_text: str,
        nonce: str,
        weight: float = 1.0,
    ) -> bool:
        """Accept a miner's reveal.

        Returns True if the reveal is valid (matches commitment).
        Raises ValueError if:
          - session is not in REVEALING state
          - miner did not commit
          - commitment hash doesn't match
        """
        if self._state not in (NMCSessionState.REVEALING,):
            raise ValueError(f"Session {self.session_id} is {self._state.value}, not REVEALING")
        if miner_uid not in self._commitments:
            raise ValueError(f"Miner {miner_uid} never committed")
        if miner_uid in self._reveals:
            raise ValueError(f"Miner {miner_uid} already revealed")

        rev = NMCReveal(
            reveal_id=uuid.uuid4().hex[:8],
            miner_uid=miner_uid,
            judgment_text=judgment_text,
            nonce=nonce,
            weight=self._trusted_weight(miner_uid, weight),
            revealed_at=time.time(),
        )
        # Verify commitment (bound to this session, case and miner identity)
        if not rev.verify_commitment(
            self._commitments[miner_uid].commitment_hash,
            session_id=self.session_id,
            case_id=self.case_id,
        ):
            raise ValueError(f"Miner {miner_uid} reveal does not match commitment")
        self._reveals[miner_uid] = rev
        return True

    def _trusted_weight(self, miner_uid: str, supplied_weight: float) -> float:
        if self._miner_weights:
            if miner_uid not in self._miner_weights:
                raise ValueError(f"Miner {miner_uid} has no trusted weight")
            trusted = self._miner_weights[miner_uid]
        elif self._trust_supplied_weights:
            # Legacy/local simulation escape hatch. Production sessions should
            # pass miner_weights from the validator/metagraph tier registry.
            trusted = supplied_weight
        else:
            trusted = 1.0
        if trusted < 0.0:
            raise ValueError("miner weight must be non-negative")
        return trusted

    # ------------------------------------------------------------------
    # Phase 3: Synthesize
    # ------------------------------------------------------------------

    def synthesize(
        self,
        method: SynthesisMethod = SynthesisMethod.MAJORITY_VOTE,
        require_min_reveals: bool = True,
    ) -> ConsensusJudgment:
        """Synthesize a consensus judgment from all reveals.

        Synthesis is final: once SYNTHESIZED, calling again with the same
        method returns the stored consensus, and a different method raises
        (a caller cannot shop for the method that yields a preferred winner).

        Raises TypeError if ``method`` is not a :class:`SynthesisMethod`.
        Raises ValueError if:
          - session not in REVEALING state
          - already synthesized with a different method
          - fewer than min_reveals valid reveals
        """
        if not isinstance(method, SynthesisMethod):
            raise TypeError("method must be a SynthesisMethod")
        if self._state == NMCSessionState.SYNTHESIZED and self._consensus is not None:
            if method is not self._consensus.method:
                raise ValueError(
                    f"Session {self.session_id} already synthesized with "
                    f"{self._consensus.method.value}"
                )
            return self._consensus
        if self._state != NMCSessionState.REVEALING:
            raise ValueError(f"Cannot synthesize: session is {self._state.value}")
        if require_min_reveals and len(self._reveals) < self._min_reveals:
            self._state = NMCSessionState.FAILED
            raise ValueError(f"Insufficient reveals: {len(self._reveals)} < {self._min_reveals}")

        reveals = list(self._reveals.values())
        sybil_flags = self._detect_sybils(reveals)
        # Each entry in ``_reveals`` already represents one unique committed
        # miner identity. Duplicate content is useful collusion telemetry, but
        # removing agreeing identities here makes the result order-dependent
        # and can invert an honest majority. Keep ``exclude_sybils`` as an API
        # deprecated compatibility argument while treating flags as flag-only
        # evidence.
        valid_reveals = reveals

        # Apply synthesis strategy
        judgment_text, confidence = self._synthesize(valid_reveals, method)

        self._consensus = ConsensusJudgment(
            session_id=self.session_id,
            case_id=self.case_id,
            judgment_text=judgment_text,
            confidence=confidence,
            method=method,
            committed_count=len(self._commitments),
            reveal_count=len(reveals),
            valid_reveal_count=len(valid_reveals),
            sybil_flags=tuple(sybil_flags),
            excluded_miners=(),
            synthesized_at=time.time(),
        )
        self._state = NMCSessionState.SYNTHESIZED
        return self._consensus

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _synthesize(
        self,
        reveals: list[NMCReveal],
        method: SynthesisMethod,
    ) -> tuple[str, float]:
        """Return (winning_judgment, confidence).

        MAJORITY_VOTE:  most common text; confidence = votes_for / total
        WEIGHTED_VOTE:  most weighted text; confidence = weight_for / total_weight
        UNANIMOUS:      all must agree; confidence = 1.0 or 0.0
        """
        if method == SynthesisMethod.MAJORITY_VOTE:
            counts = Counter(r.judgment_text for r in reveals)
            winner = _deterministic_winner(counts)
            return winner, counts[winner] / len(reveals)

        if method == SynthesisMethod.WEIGHTED_VOTE:
            weighted: dict[str, float] = {}
            total_weight = 0.0
            for r in sorted(reveals, key=lambda reveal: (reveal.judgment_text, reveal.miner_uid)):
                weighted[r.judgment_text] = weighted.get(r.judgment_text, 0.0) + r.weight
                total_weight += r.weight
            winner = _deterministic_winner(weighted)
            if total_weight == 0:
                return winner, 0.0
            return winner, weighted[winner] / total_weight

        if method == SynthesisMethod.UNANIMOUS:
            texts = {r.judgment_text for r in reveals}
            if len(texts) == 1:
                return texts.pop(), 1.0
            # No consensus — return most common with low confidence
            counts = Counter(r.judgment_text for r in reveals)
            winner = _deterministic_winner(counts)
            return winner, 0.0

        raise AssertionError(f"Unhandled synthesis method: {method!r}")

    def _detect_sybils(self, reveals: list[NMCReveal]) -> list[SybilFlag]:
        """Flag miners with exactly duplicate judgment texts.

        The commit phase prevents miners from seeing each other's work, so
        identical judgments after blind commitment are highly suspicious.
        """
        if len(reveals) < 2:
            return []

        # Group by judgment hash
        judgment_hash_map: dict[str, list[str]] = {}
        for r in reveals:
            j_hash = hashlib.sha256(r.judgment_text.encode()).hexdigest()
            judgment_hash_map.setdefault(j_hash, []).append(r.miner_uid)

        flags: list[SybilFlag] = []
        for j_hash, miners in judgment_hash_map.items():
            if len(miners) >= 2:
                # First miner is the "reference" — rest are flagged
                reference = miners[0]
                for flagged in miners[1:]:
                    flags.append(
                        SybilFlag(
                            flag_id=uuid.uuid4().hex[:8],
                            flagged_miner=flagged,
                            reference_miner=reference,
                            judgment_hash=j_hash,
                            confidence=1.0,
                            reason=(
                                f"Exact duplicate of {reference}'s judgment after blind commitment"
                            ),
                        )
                    )
        return flags

    def _is_deadline_passed(self) -> bool:
        return time.time() > self._deadline_at

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "state": self.state.value,
            "committed": len(self._commitments),
            "revealed": len(self._reveals),
            "pending_reveals": len(self.pending_reveal_miners),
            "has_consensus": self._consensus is not None,
        }


# ---------------------------------------------------------------------------
# NMC Coordinator — manages multiple sessions
# ---------------------------------------------------------------------------


class NMCCoordinator:
    """Manages NMC sessions across all active governance cases.

    Usage::

        coordinator = NMCCoordinator(default_min_reveals=2)

        # SN Owner creates a session for a new escalated case
        session = coordinator.create_session(
            case_id="ESC-2026-042",
            required_miners={"miner-01", "miner-02", "miner-03"},
            deadline_seconds=300,
        )

        # Each miner commits (independently, can't see others); each
        # commitment is compute_commitment_hash(..., session_id=session.session_id,
        # case_id=session.case_id, miner_uid=<miner>)
        session.accept_commitment("miner-01", commitment_01)
        session.accept_commitment("miner-02", commitment_02)
        session.accept_commitment("miner-03", commitment_03)

        # All committed → auto-moved to REVEALING
        # Miners reveal; weights come from the trusted tier map supplied as
        # create_session(..., miner_weights={"miner-01": 1.5, ...})
        session.accept_reveal("miner-01", judgment_01, nonce_01)
        session.accept_reveal("miner-02", judgment_02, nonce_02)
        session.accept_reveal("miner-03", judgment_03, nonce_03)

        # Synthesize
        consensus = session.synthesize(SynthesisMethod.WEIGHTED_VOTE)

        # Log outcome
        outcome = coordinator.get_session_outcome("ESC-2026-042")

    ``exclude_sybils`` is deprecated and has no effect on created sessions.
    """

    def __init__(
        self,
        default_min_reveals: int = 2,
        default_deadline_seconds: float = 300.0,
        exclude_sybils: bool | None = None,
    ) -> None:
        _warn_deprecated_exclude_sybils(exclude_sybils)
        self._default_min = _validate_count("default_min_reveals", default_min_reveals, minimum=1)
        self._default_deadline = _validate_finite(
            "default_deadline_seconds", default_deadline_seconds
        )
        if self._default_deadline <= 0.0:
            raise ValueError("default_deadline_seconds must be positive")
        self._sessions: dict[str, NMCSession] = {}  # case_id → session

    def create_session(
        self,
        case_id: str,
        required_miners: Collection[str],
        min_reveals: int | None = None,
        deadline_seconds: float | None = None,
        miner_weights: Mapping[str, float] | None = None,
        trust_supplied_weights: bool = False,
    ) -> NMCSession:
        """Create and register a new NMC session for a governance case.

        ``required_miners`` (the session roster) is mandatory. ``miner_weights``
        should come from the validator/metagraph tier registry; omitted
        ``min_reveals`` / ``deadline_seconds`` use the coordinator defaults,
        while explicit values (including invalid ones such as ``0``) are
        validated, never silently replaced.

        Raises ValueError if a session for case_id already exists or any
        parameter is invalid.
        """
        if case_id in self._sessions:
            raise ValueError(f"NMC session for case {case_id!r} already exists")
        session = NMCSession(
            case_id=case_id,
            required_miners=required_miners,
            min_reveals=self._default_min if min_reveals is None else min_reveals,
            deadline_seconds=(
                self._default_deadline if deadline_seconds is None else deadline_seconds
            ),
            miner_weights=miner_weights,
            trust_supplied_weights=trust_supplied_weights,
        )
        self._sessions[case_id] = session
        return session

    def get_session(self, case_id: str) -> NMCSession | None:
        return self._sessions.get(case_id)

    def get_session_outcome(self, case_id: str) -> ConsensusJudgment | None:
        """Return the ConsensusJudgment for a completed session, or None."""
        session = self._sessions.get(case_id)
        if session is None:
            return None
        return session.consensus

    def active_sessions(self) -> list[NMCSession]:
        return [s for s in self._sessions.values() if not s.is_complete]

    def completed_sessions(self) -> list[NMCSession]:
        return [s for s in self._sessions.values() if s.is_complete]

    def sybil_report(self) -> list[dict[str, Any]]:
        """Aggregate Sybil flags across all completed sessions."""
        report: list[dict[str, Any]] = []
        for session in self._sessions.values():
            if session.consensus and session.consensus.has_sybil_activity:
                report.append(
                    {
                        "case_id": session.case_id,
                        "session_id": session.session_id,
                        "flags": [f.to_dict() for f in session.consensus.sybil_flags],
                    }
                )
        return report

    def summary(self) -> dict[str, Any]:
        total = len(self._sessions)
        synthesized = sum(
            1 for s in self._sessions.values() if s.state == NMCSessionState.SYNTHESIZED
        )
        timed_out = sum(1 for s in self._sessions.values() if s.state == NMCSessionState.TIMED_OUT)
        sybil_cases = sum(
            1 for s in self._sessions.values() if s.consensus and s.consensus.has_sybil_activity
        )
        return {
            "total_sessions": total,
            "synthesized": synthesized,
            "active": total - len(self.completed_sessions()),
            "timed_out": timed_out,
            "sybil_cases": sybil_cases,
        }
