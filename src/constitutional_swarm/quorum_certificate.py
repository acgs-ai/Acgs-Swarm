"""Quorum certificates with accountable safety (slashable conflicting votes).

Phase 7.1 breakthrough: a :class:`QuorumCertificate` bundles signed
votes from a committee on a single artifact. Two conflicting QCs over
the same (assignment_id, epoch) constitute slashable evidence — the
signers in the intersection equivocated.

Accountable safety: if safety is violated (two conflicting artifacts
finalize in the same epoch), the protocol can identify a set of
validators whose signatures prove the equivocation, and slash them.
This is the Byzantine-safe fallback when the 1/3 bound is crossed —
we cannot prevent conflicting finalizations under majority adversary,
but we *can* guarantee there is always a slashable proof.

References
----------
- HotStuff (Yin et al. 2019) — accountable safety via quorum certificates
- Casper FFG (Buterin & Griffith 2017) — slashing conditions
- Ethereum 2.0 accountable safety spec

This module is transport-agnostic: QCs are built from Ed25519-signed
votes and can be serialized to JSON for wire / merkle_crdt storage.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.validator_set import (
    CommitteeSelection,
    CommitteeSelector,
    ValidatorSet,
)

_BASE_THRESHOLD_FRACTION = 2 / 3

__all__ = [
    "CertificateVerificationPolicy",
    "ConflictEvidence",
    "InsufficientQuorumError",
    "InvalidCertificateError",
    "QuorumCertificate",
    "SignedVote",
    "build_certificate",
    "detect_conflict",
    "verify_certificate",
]


class InvalidCertificateError(ValueError):
    """Raised when a certificate fails verification (bad signature, etc.)."""


class InsufficientQuorumError(InvalidCertificateError):
    """Raised when votes do not meet the quorum threshold."""


def _validate_epoch(epoch: object) -> None:
    if type(epoch) is not int or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")


@dataclass(frozen=True)
class CertificateVerificationPolicy:
    """Verifier-owned policy for reconstructing and checking a QC committee.

    ``committee_size=None`` deliberately means the full eligible validator set.
    A verifier accepting a subset committee must pin its expected size; the
    certificate is never allowed to select its own committee size or threshold.
    """

    committee_size: int | None = None
    threshold_fraction: float = _BASE_THRESHOLD_FRACTION
    unsafe_allow_sub_two_thirds: bool = False
    expected_committee_seed: str | None = None
    excluded_voter_ids: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.committee_size is not None and (
            type(self.committee_size) is not int or self.committee_size <= 0
        ):
            raise ValueError("committee_size must be positive when provided")
        if self.committee_size is not None and not self.expected_committee_seed:
            raise ValueError("an explicit committee_size requires a non-empty expected seed")
        if isinstance(self.threshold_fraction, bool) or not math.isfinite(
            self.threshold_fraction
        ) or not (0.0 < self.threshold_fraction <= 1.0):
            raise ValueError("threshold_fraction must be finite and in (0, 1]")
        if type(self.unsafe_allow_sub_two_thirds) is not bool:
            raise ValueError("unsafe_allow_sub_two_thirds must be a bool")
        if (
            self.threshold_fraction < _BASE_THRESHOLD_FRACTION
            and not self.unsafe_allow_sub_two_thirds
        ):
            raise ValueError(
                "threshold_fraction below 2/3 requires "
                "unsafe_allow_sub_two_thirds=True"
            )
        object.__setattr__(self, "excluded_voter_ids", frozenset(self.excluded_voter_ids))
        if any(not isinstance(voter_id, str) for voter_id in self.excluded_voter_ids):
            raise ValueError("excluded_voter_ids must contain only strings")


@dataclass(frozen=True)
class SignedVote:
    """An Ed25519-signed vote on ``(assignment_id, artifact_hash, epoch)``.

    The tuple is the vote's domain-separated payload: a single signer
    cannot produce two votes with the same ``(assignment_id, epoch)``
    but different ``artifact_hash`` without exposing themselves to
    slashing.
    """

    voter_id: str
    assignment_id: str
    artifact_hash: str
    epoch: int
    signature: bytes
    public_key_bytes: bytes  # raw Ed25519 public key (32 bytes)

    def __post_init__(self) -> None:
        _validate_epoch(self.epoch)

    def message(self) -> bytes:
        """Canonical signable message for this vote."""
        return build_vote_message(self.assignment_id, self.artifact_hash, self.epoch)

    def verify(self) -> bool:
        """Verify the Ed25519 signature. Returns False on any failure."""
        try:
            pk = Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
            pk.verify(self.signature, self.message())
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False


def build_vote_message(assignment_id: str, artifact_hash: str, epoch: int) -> bytes:
    """Canonical signable message.

    Domain-separated: the ``"cs-qc-v1"`` prefix prevents replay of
    signatures into other protocols. Epoch is included so the same
    artifact in a later epoch requires a fresh signature.
    """
    _validate_epoch(epoch)
    payload = {
        "v": 1,
        "kind": "cs-qc-v1",
        "assignment_id": assignment_id,
        "artifact_hash": artifact_hash,
        "epoch": epoch,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class QuorumCertificate:
    """Immutable bundle of signed votes meeting a weight threshold.

    Attributes
    ----------
    assignment_id, artifact_hash, epoch:
        Identify the vote subject.
    votes:
        Tuple of :class:`SignedVote` entries (one per signer).
    threshold_weight, achieved_weight:
        Threshold required, and total capped weight achieved.
    committee_seed:
        The VRF seed that selected the committee — required for
        independent verifiers to reconstruct the expected committee.
    """

    assignment_id: str
    artifact_hash: str
    epoch: int
    votes: tuple[SignedVote, ...]
    threshold_weight: float
    achieved_weight: float
    committee_seed: str = ""

    def __post_init__(self) -> None:
        _validate_epoch(self.epoch)

    @property
    def voter_ids(self) -> frozenset[str]:
        return frozenset(v.voter_id for v in self.votes)

    def qc_id(self) -> str:
        """Stable SHA-256 hash identifying the QC (for dedup / indexing)."""
        body = json.dumps(
            {
                "assignment_id": self.assignment_id,
                "artifact_hash": self.artifact_hash,
                "epoch": self.epoch,
                "voters": sorted(self.voter_ids),
                "seed": self.committee_seed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation (for merkle_crdt storage)."""
        return {
            "v": 1,
            "assignment_id": self.assignment_id,
            "artifact_hash": self.artifact_hash,
            "epoch": self.epoch,
            "threshold_weight": self.threshold_weight,
            "achieved_weight": self.achieved_weight,
            "committee_seed": self.committee_seed,
            "votes": [
                {
                    "voter_id": v.voter_id,
                    "signature": v.signature.hex(),
                    "public_key": v.public_key_bytes.hex(),
                }
                for v in self.votes
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QuorumCertificate:
        """Inverse of :meth:`to_dict`."""
        assignment_id = data["assignment_id"]
        artifact_hash = data["artifact_hash"]
        epoch = data["epoch"]
        votes = tuple(
            SignedVote(
                voter_id=v["voter_id"],
                assignment_id=assignment_id,
                artifact_hash=artifact_hash,
                epoch=epoch,
                signature=bytes.fromhex(v["signature"]),
                public_key_bytes=bytes.fromhex(v["public_key"]),
            )
            for v in data["votes"]
        )
        return cls(
            assignment_id=assignment_id,
            artifact_hash=artifact_hash,
            epoch=epoch,
            votes=votes,
            threshold_weight=float(data["threshold_weight"]),
            achieved_weight=float(data["achieved_weight"]),
            committee_seed=str(data.get("committee_seed", "")),
        )


@dataclass(frozen=True)
class ConflictEvidence:
    """Slashable evidence: two QCs with same (assignment, epoch) but different hashes.

    ``equivocators`` is the set of voter_ids that signed both
    conflicting QCs — these are the slashable parties. ``qc_a`` and
    ``qc_b`` are the two certificates; exactly one artifact_hash of
    each is legitimate, the other is the equivocating claim.
    """

    qc_a: QuorumCertificate
    qc_b: QuorumCertificate
    equivocators: frozenset[str]

    def is_slashable(
        self,
        *,
        validator_set: ValidatorSet,
        policy: CertificateVerificationPolicy | None = None,
        policy_a: CertificateVerificationPolicy | None = None,
        policy_b: CertificateVerificationPolicy | None = None,
    ) -> bool:
        """Return whether both authenticated QCs prove an equivocation."""
        verified = detect_conflict(
            self.qc_a,
            self.qc_b,
            validator_set=validator_set,
            policy=policy,
            policy_a=policy_a,
            policy_b=policy_b,
        )
        return (
            verified is not None
            and bool(verified.equivocators)
            and self.equivocators == verified.equivocators
        )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def build_certificate(
    votes: Iterable[SignedVote],
    *,
    committee: CommitteeSelection,
    validator_set: ValidatorSet,
    threshold_fraction: float = 2 / 3,
    verification_policy: CertificateVerificationPolicy | None = None,
) -> QuorumCertificate:
    """Build a :class:`QuorumCertificate` from committee votes.

    Validates:
      1. Every vote's signature verifies.
      2. Every voter is a member of ``committee``.
      3. All votes share the same ``(assignment_id, artifact_hash, epoch)``.
      4. Total capped weight meets ``threshold_fraction * committee.weight``.

    Raises
    ------
    InsufficientQuorumError
        If accumulated capped weight does not reach the threshold.
    InvalidCertificateError
        On signature or membership mismatch.
    """
    vote_list = list(votes)
    if not vote_list:
        raise InsufficientQuorumError("no votes supplied")

    first = vote_list[0]
    ordered_votes = tuple(sorted(vote_list, key=lambda vote: vote.voter_id))
    provisional = QuorumCertificate(
        assignment_id=first.assignment_id,
        artifact_hash=first.artifact_hash,
        epoch=first.epoch,
        votes=ordered_votes,
        threshold_weight=0.0,
        achieved_weight=0.0,
        committee_seed=committee.seed,
    )
    policy = verification_policy or CertificateVerificationPolicy(
        committee_size=len(committee.members),
        threshold_fraction=threshold_fraction,
        expected_committee_seed=committee.seed,
    )
    if policy.committee_size != len(committee.members):
        raise InvalidCertificateError("builder policy committee size does not match committee")
    achieved_weight, threshold_weight = _verify_certificate_core(
        provisional,
        validator_set=validator_set,
        policy=policy,
        expected_committee=committee,
        check_metadata=False,
    )
    return QuorumCertificate(
        assignment_id=provisional.assignment_id,
        artifact_hash=provisional.artifact_hash,
        epoch=provisional.epoch,
        votes=provisional.votes,
        threshold_weight=threshold_weight,
        achieved_weight=achieved_weight,
        committee_seed=provisional.committee_seed,
    )


# ---------------------------------------------------------------------------
# Verification & conflict detection
# ---------------------------------------------------------------------------


def _verify_certificate_core(
    qc: QuorumCertificate,
    *,
    validator_set: ValidatorSet,
    policy: CertificateVerificationPolicy,
    expected_committee: CommitteeSelection | None = None,
    check_metadata: bool = True,
) -> tuple[float, float]:
    """Canonical QC verification used by every construction and evidence path.

    Raises ``InvalidCertificateError`` for malformed or unauthenticated data and
    ``InsufficientQuorumError`` when authentic votes do not meet trusted policy.
    """
    if not qc.votes:
        raise InvalidCertificateError("empty QC")
    if policy.expected_committee_seed is not None and (
        qc.committee_seed != policy.expected_committee_seed
    ):
        raise InvalidCertificateError("committee seed does not match verifier policy")

    validator_snapshot = validator_set.snapshot()
    snapshot_set = ValidatorSet(validator_snapshot, policy=validator_set.policy)
    all_validator_ids = frozenset(identity.agent_id for identity in validator_snapshot)
    eligible_count = len(all_validator_ids - policy.excluded_voter_ids)
    committee_size = policy.committee_size if policy.committee_size is not None else eligible_count
    if committee_size <= 0:
        raise InvalidCertificateError("verification policy has no eligible validators")
    if policy.committee_size is not None and committee_size > eligible_count:
        raise InvalidCertificateError("validator set cannot satisfy pinned committee size")
    committee = CommitteeSelector(snapshot_set).select(
        qc.committee_seed,
        committee_size,
        exclude=tuple(policy.excluded_voter_ids),
    )
    if expected_committee is not None and expected_committee.members != committee.members:
        raise InvalidCertificateError("provided committee does not match deterministic selection")
    if committee.seed != qc.committee_seed:
        raise InvalidCertificateError("committee seed mismatch")
    committee_ids = frozenset(committee.members)
    if len(committee_ids) != len(committee.members):
        raise InvalidCertificateError("committee contains duplicate members")
    identities = {identity.agent_id: identity for identity in validator_snapshot}
    domain_policy = snapshot_set.policy
    seen_voters: set[str] = set()
    per_domain: dict[str, float] = {}
    for sv in qc.votes:
        if sv.voter_id in seen_voters:
            raise InvalidCertificateError(f"duplicate voter {sv.voter_id!r} in QC")
        if (
            sv.assignment_id != qc.assignment_id
            or sv.artifact_hash != qc.artifact_hash
            or sv.epoch != qc.epoch
        ):
            raise InvalidCertificateError("vote/QC subject mismatch")
        ident = identities.get(sv.voter_id)
        if ident is None:
            raise InvalidCertificateError(f"voter {sv.voter_id!r} not in validator set")
        if sv.voter_id not in committee_ids:
            raise InvalidCertificateError(f"voter {sv.voter_id!r} is not a member of committee")
        if ident.public_key_bytes is None:
            raise InvalidCertificateError(
                f"registered public key missing for voter {sv.voter_id!r}"
            )
        if sv.public_key_bytes != ident.public_key_bytes:
            raise InvalidCertificateError(
                f"embedded public key for voter {sv.voter_id!r} does not match registry"
            )
        try:
            registry_key = Ed25519PublicKey.from_public_bytes(ident.public_key_bytes)
            registry_key.verify(sv.signature, sv.message())
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise InvalidCertificateError(
                f"signature from {sv.voter_id!r} failed against registry key"
            ) from exc
        if not math.isfinite(ident.effective_weight) or ident.effective_weight < 0.0:
            raise InvalidCertificateError(f"non-finite weight for voter {sv.voter_id!r}")
        domain = domain_policy.resolve_domain(ident)
        per_domain[domain] = per_domain.get(domain, 0.0) + ident.effective_weight
        seen_voters.add(sv.voter_id)

    try:
        committee_identities = tuple(identities[voter_id] for voter_id in committee.members)
    except KeyError as exc:
        raise InvalidCertificateError(f"committee member {exc.args[0]!r} not in validator set") from exc
    raw_committee_weight = sum(identity.effective_weight for identity in committee_identities)
    if not math.isfinite(raw_committee_weight) or raw_committee_weight <= 0.0:
        raise InvalidCertificateError("committee weight must be finite and positive")
    ceiling = domain_policy.max_fraction * raw_committee_weight
    recomputed = sum(min(w, ceiling) for w in per_domain.values())
    policy_threshold = policy.threshold_fraction * raw_committee_weight
    artifact_threshold = qc.threshold_weight if check_metadata else policy_threshold
    if check_metadata and (
        not math.isfinite(artifact_threshold)
        or artifact_threshold <= 0.0
        or (
            artifact_threshold > raw_committee_weight
            and not math.isclose(
                artifact_threshold,
                raw_committee_weight,
                rel_tol=1e-12,
                abs_tol=0.0,
            )
        )
    ):
        raise InvalidCertificateError("stored threshold is outside canonical bounds")
    trusted_threshold = policy_threshold
    if not math.isfinite(recomputed) or (
        recomputed < trusted_threshold
        and not math.isclose(recomputed, trusted_threshold, rel_tol=1e-12, abs_tol=0.0)
    ):
        raise InsufficientQuorumError(
            f"achieved capped weight {recomputed:.6f} < trusted threshold "
            f"{trusted_threshold:.6f}"
        )
    if check_metadata:
        if not math.isfinite(qc.achieved_weight) or not math.isclose(
            qc.achieved_weight, recomputed, rel_tol=1e-12, abs_tol=0.0
        ):
            raise InvalidCertificateError("stored achieved weight does not match verifier result")
    return recomputed, trusted_threshold


def verify_certificate(
    qc: QuorumCertificate,
    *,
    validator_set: ValidatorSet,
    policy: CertificateVerificationPolicy | None = None,
    threshold_fraction: float | None = None,
    expected_threshold_weight: float | None = None,
) -> None:
    """Re-verify a QC under verifier-owned committee and threshold policy.

    The legacy numeric arguments are retained as strengthening-only controls.
    They cannot replace committee reconstruction or lower ``policy``.
    """
    effective_policy = policy or CertificateVerificationPolicy()
    if threshold_fraction is not None:
        if (
            isinstance(threshold_fraction, bool)
            or not math.isfinite(threshold_fraction)
            or not effective_policy.threshold_fraction <= threshold_fraction <= 1.0
        ):
            raise ValueError("threshold_fraction must be finite and strengthen policy")
        effective_policy = CertificateVerificationPolicy(
            committee_size=effective_policy.committee_size,
            threshold_fraction=max(effective_policy.threshold_fraction, threshold_fraction),
            unsafe_allow_sub_two_thirds=effective_policy.unsafe_allow_sub_two_thirds,
            expected_committee_seed=effective_policy.expected_committee_seed,
            excluded_voter_ids=effective_policy.excluded_voter_ids,
        )
    achieved, _ = _verify_certificate_core(
        qc,
        validator_set=validator_set,
        policy=effective_policy,
    )
    if expected_threshold_weight is not None:
        if not math.isfinite(expected_threshold_weight) or expected_threshold_weight <= 0.0:
            raise ValueError("expected_threshold_weight must be finite and positive")
        if achieved < expected_threshold_weight and not math.isclose(
            achieved,
            expected_threshold_weight,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise InsufficientQuorumError(
                f"achieved weight {achieved:.6f} below strengthened threshold "
                f"{expected_threshold_weight:.6f}"
            )


def detect_conflict(
    qc_a: QuorumCertificate,
    qc_b: QuorumCertificate,
    *,
    validator_set: ValidatorSet,
    policy: CertificateVerificationPolicy | None = None,
    policy_a: CertificateVerificationPolicy | None = None,
    policy_b: CertificateVerificationPolicy | None = None,
) -> ConflictEvidence | None:
    """Return slashable evidence iff two QCs conflict.

    A conflict exists when both QCs are for the same
    ``(assignment_id, epoch)`` but different ``artifact_hash``. The
    equivocators are the voter_ids that signed both.

    Returns ``None`` if there is no conflict (same artifact or
    different assignment/epoch — the latter is not a safety issue).
    """
    common_policy = policy or CertificateVerificationPolicy()
    _verify_certificate_core(
        qc_a,
        validator_set=validator_set,
        policy=policy_a or common_policy,
    )
    _verify_certificate_core(
        qc_b,
        validator_set=validator_set,
        policy=policy_b or common_policy,
    )
    if qc_a.assignment_id != qc_b.assignment_id:
        return None
    if qc_a.epoch != qc_b.epoch:
        return None
    if qc_a.artifact_hash == qc_b.artifact_hash:
        return None
    equivocators = qc_a.voter_ids & qc_b.voter_ids
    return ConflictEvidence(qc_a=qc_a, qc_b=qc_b, equivocators=equivocators)
