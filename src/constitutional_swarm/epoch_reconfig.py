"""Phase 7.5 — versioned constitutional reconfiguration.

Replaces hash-equality sync with epoch-stamped constitutions and
joint-consensus transition certificates. Gives the swarm a safe,
auditable way to evolve its constitution without fracturing the
network into permanent hash forks.

Design
------
A ``ConstitutionVersion`` is a content-addressed snapshot of the
constitution at a specific epoch. Each version points backward at its
parent via ``parent_digest`` so the chain of amendments is a Merkle
chain; replay attacks at an old epoch cannot disguise themselves as
fresh transitions.

An ``AmendmentProposal`` is a typed diff that carries:

* the intended transition ``(from_epoch -> to_epoch)``
* the full target ``ConstitutionVersion``
* an optional ``drift_budget`` capping how far a single amendment may
  move the governance surface (number of rules changed, numeric
  threshold deltas, etc.).

A ``TransitionCertificate`` ratifies the proposal. The certificate is
valid only when it carries **joint consensus**: quorum from BOTH the
pre-transition validator set and the post-transition validator set.
This mirrors Raft joint consensus (see ``specs/constitution_reconfig.tla``)
and prevents a retiring validator set from committing their successor
unilaterally, or vice versa.

The module is transport-agnostic. Integration with
``bittensor/constitution_sync.py`` is a follow-up wire-up; the
primitives and invariants live here so the logic can be tested
without a bittensor runtime.
"""

from __future__ import annotations

import hashlib
import math
from numbers import Real
from dataclasses import dataclass, field, replace

from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    InsufficientQuorumError,
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    verify_certificate,
)
from constitutional_swarm.framing import framed_digest
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    ValidatorIdentity,
    ValidatorSet,
)

__all__ = [
    "AmendmentProposal",
    "ConstitutionVersion",
    "DriftBudget",
    "DriftBudgetExceeded",
    "EpochMismatchError",
    "InvalidTransitionError",
    "JointQuorumNotMetError",
    "TransitionCertificate",
    "TransitionVerificationPolicy",
    "build_transition_message",
    "build_transition_side_certificate",
    "compute_transition_threshold",
    "compute_validator_set_digest",
    "compute_version_digest",
    "evaluate_drift",
    "transition_vote_subject",
    "verify_transition",
]


_DOMAIN = b"acgs-swarm/epoch-reconfig/v2"
_TRANSITION_SUBJECT_DOMAIN = b"acgs-swarm/epoch-reconfig/transition/v3"
_TRANSITION_ASSIGNMENT_ID = "constitutional-transition-v3"


class InvalidTransitionError(ValueError):
    """Transition metadata is internally inconsistent."""


class EpochMismatchError(InvalidTransitionError):
    """Proposal epoch does not match the expected predecessor."""


class JointQuorumNotMetError(InvalidTransitionError):
    """Either the old or new validator set failed to ratify."""


class DriftBudgetExceeded(InvalidTransitionError):
    """Amendment diff exceeds the declared drift budget."""


def compute_version_digest(
    *,
    epoch: int,
    rules: tuple[str, ...],
    parent_digest: bytes,
) -> bytes:
    """Deterministic content digest for a ConstitutionVersion.

    ``rules`` is the canonical sorted tuple of rule strings; callers are
    responsible for sorting and deduplicating before calling.
    """
    if type(epoch) is not int or not 0 <= epoch < 2**64:
        raise ValueError(f"epoch must be non-negative, got {epoch}")
    if len(parent_digest) not in (0, 32):
        raise ValueError(f"parent_digest must be 0 or 32 bytes, got {len(parent_digest)}")
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(b"version")
    h.update(epoch.to_bytes(8, "big"))
    h.update(len(parent_digest).to_bytes(1, "big"))
    h.update(parent_digest)
    h.update(len(rules).to_bytes(4, "big"))
    for rule in rules:
        data = rule.encode("utf-8")
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
    return h.digest()


@dataclass(frozen=True)
class ConstitutionVersion:
    """Content-addressed snapshot of the constitution at one epoch."""

    epoch: int
    rules: tuple[str, ...]
    parent_digest: bytes = b""

    def __post_init__(self) -> None:
        if type(self.epoch) is not int or not 0 <= self.epoch < 2**64:
            raise ValueError("epoch must be a non-negative 64-bit integer")
        if type(self.rules) is not tuple or any(type(rule) is not str for rule in self.rules):
            raise ValueError("rules must be a tuple of strings")
        if tuple(sorted(self.rules)) != self.rules:
            raise ValueError("rules must be sorted (canonical form)")
        if len(set(self.rules)) != len(self.rules):
            raise ValueError("rules must not contain duplicates")
        if type(self.parent_digest) is not bytes or len(self.parent_digest) not in (0, 32):
            raise ValueError("parent_digest must be 0 or 32 bytes")

    @property
    def digest(self) -> bytes:
        return compute_version_digest(
            epoch=self.epoch,
            rules=self.rules,
            parent_digest=self.parent_digest,
        )


@dataclass(frozen=True)
class DriftBudget:
    """Per-amendment governance-drift cap.

    The budget is a safety rail: an amendment that adds or removes more
    than ``max_rule_delta`` rules in a single step is auto-rejected
    even if it carries a valid joint-consensus certificate. This makes
    "boiling-frog" governance capture materially harder — attacking the
    constitution requires multiple detectable transitions, not one
    sweeping rewrite.
    """

    max_rule_delta: int = 16

    def __post_init__(self) -> None:
        if type(self.max_rule_delta) is not int or self.max_rule_delta < 0:
            raise ValueError("max_rule_delta must be a non-negative integer")


def evaluate_drift(
    prior: ConstitutionVersion,
    proposed: ConstitutionVersion,
) -> int:
    """Return symmetric-difference rule count between two versions."""
    prior_set = set(prior.rules)
    proposed_set = set(proposed.rules)
    added = proposed_set - prior_set
    removed = prior_set - proposed_set
    return len(added) + len(removed)


def _validated_validator_snapshot(
    validator_set: ValidatorSet,
) -> tuple[ValidatorIdentity, ...]:
    """Return a concrete registry snapshot with unique authentication keys."""
    if type(validator_set) is not ValidatorSet:
        raise InvalidTransitionError("validator_set must be a concrete ValidatorSet snapshot")
    snapshot = validator_set.snapshot()
    seen_public_keys: set[bytes] = set()
    for identity in snapshot:
        if type(identity) is not ValidatorIdentity:
            raise InvalidTransitionError("validator registry contains a malformed identity")
        public_key = identity.public_key_bytes
        if public_key is not None:
            if type(public_key) is not bytes or len(public_key) != 32:
                raise InvalidTransitionError(
                    f"{identity.agent_id}.public_key_bytes must be a raw Ed25519 key"
                )
            if public_key in seen_public_keys:
                raise InvalidTransitionError("validator registry reuses a public key")
            seen_public_keys.add(public_key)
    return snapshot


def compute_validator_set_digest(validator_set: ValidatorSet) -> bytes:
    """Commit to a complete validator registry and its fault-domain policy."""
    snapshot = _validated_validator_snapshot(validator_set)

    def canonical_real(value: object, name: str) -> bytes:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise InvalidTransitionError(f"{name} must be a finite real number")
        normalized = float(value)
        if not math.isfinite(normalized):
            raise InvalidTransitionError(f"{name} must be a finite real number")
        return normalized.hex().encode()

    message = bytearray(_DOMAIN)
    _append_length_prefixed(message, b"validator-set")
    _append_length_prefixed(
        message,
        canonical_real(validator_set.policy.max_fraction, "policy.max_fraction"),
    )
    _append_length_prefixed(message, validator_set.policy.untagged_policy.encode())
    message.extend(len(snapshot).to_bytes(4, "big"))
    for identity in snapshot:
        if not isinstance(identity.agent_id, str) or not identity.agent_id:
            raise InvalidTransitionError("validator agent_id must be a non-empty string")
        if not isinstance(identity.fault_domain, str):
            raise InvalidTransitionError(
                f"{identity.agent_id}.fault_domain must be a string"
            )
        if identity.public_key_bytes is not None and (
            not isinstance(identity.public_key_bytes, bytes)
            or len(identity.public_key_bytes) != 32
        ):
            raise InvalidTransitionError(
                f"{identity.agent_id}.public_key_bytes must be a raw Ed25519 key"
            )
        _append_length_prefixed(message, identity.agent_id.encode())
        _append_length_prefixed(
            message, canonical_real(identity.stake, f"{identity.agent_id}.stake")
        )
        _append_length_prefixed(
            message,
            canonical_real(identity.reputation, f"{identity.agent_id}.reputation"),
        )
        _append_length_prefixed(message, identity.fault_domain.encode())
        _append_length_prefixed(message, identity.public_key_bytes or b"")
    return hashlib.sha256(message).digest()


@dataclass(frozen=True)
class AmendmentProposal:
    """Typed diff from ``prior`` to ``proposed`` at ``to_epoch``."""

    prior: ConstitutionVersion
    proposed: ConstitutionVersion
    drift_budget: DriftBudget = field(default_factory=DriftBudget)
    binding_digest: bytes = b""
    old_validator_set_digest: bytes = b""
    new_validator_set_digest: bytes = b""

    def __post_init__(self) -> None:
        if type(self.prior) is not ConstitutionVersion:
            raise InvalidTransitionError("prior must be a ConstitutionVersion")
        if type(self.proposed) is not ConstitutionVersion:
            raise InvalidTransitionError("proposed must be a ConstitutionVersion")
        if type(self.drift_budget) is not DriftBudget:
            raise InvalidTransitionError("drift_budget must be a DriftBudget")
        for name, version in (("prior", self.prior), ("proposed", self.proposed)):
            try:
                ConstitutionVersion.__post_init__(version)
            except ValueError as exc:
                raise InvalidTransitionError(f"{name} version is invalid: {exc}") from exc
        try:
            DriftBudget.__post_init__(self.drift_budget)
        except ValueError as exc:
            raise InvalidTransitionError(f"drift_budget is invalid: {exc}") from exc
        if self.proposed.epoch != self.prior.epoch + 1:
            raise EpochMismatchError(
                "proposed epoch must be prior.epoch + 1 "
                f"(prior={self.prior.epoch}, proposed={self.proposed.epoch})"
            )
        if self.proposed.parent_digest != self.prior.digest:
            raise InvalidTransitionError("proposed.parent_digest must equal prior.digest")
        if type(self.binding_digest) is not bytes or len(self.binding_digest) not in (0, 32):
            raise InvalidTransitionError("binding_digest must be 0 or 32 bytes")
        for name, digest in (
            ("old_validator_set_digest", self.old_validator_set_digest),
            ("new_validator_set_digest", self.new_validator_set_digest),
        ):
            if type(digest) is not bytes or len(digest) not in (0, 32):
                raise InvalidTransitionError(f"{name} must be 0 or 32 bytes")

    @property
    def drift(self) -> int:
        return evaluate_drift(self.prior, self.proposed)


@dataclass(frozen=True)
class TransitionCertificate:
    """Joint-consensus ratification of an AmendmentProposal.

    Each side carries a normal quorum certificate over one identical,
    domain-separated transition subject. The registry and threshold policy are
    supplied by the verifier, never by this artifact.
    """

    proposal: AmendmentProposal
    old_side_certificate: QuorumCertificate
    new_side_certificate: QuorumCertificate

    def __post_init__(self) -> None:
        _validate_transition_certificate(self)


@dataclass(frozen=True)
class TransitionVerificationPolicy:
    """Verifier-owned joint-consensus and drift policy.

    For each transition side, the verifier-pinned committee must have enough
    effective weight to carry the rounded full-registry raw-stake threshold.
    Registry-dependent viability is checked by :func:`verify_transition`.
    """

    old_certificate: CertificateVerificationPolicy = field(
        default_factory=CertificateVerificationPolicy
    )
    new_certificate: CertificateVerificationPolicy = field(
        default_factory=CertificateVerificationPolicy
    )
    max_rule_delta: int = 16

    def __post_init__(self) -> None:
        if type(self.old_certificate) is not CertificateVerificationPolicy:
            raise ValueError("old_certificate must be a CertificateVerificationPolicy")
        if type(self.new_certificate) is not CertificateVerificationPolicy:
            raise ValueError("new_certificate must be a CertificateVerificationPolicy")
        for name, certificate_policy in (
            ("old_certificate", self.old_certificate),
            ("new_certificate", self.new_certificate),
        ):
            try:
                CertificateVerificationPolicy.__post_init__(certificate_policy)
            except ValueError as exc:
                raise ValueError(f"{name} is invalid: {exc}") from exc
        if type(self.max_rule_delta) is not int or self.max_rule_delta < 0:
            raise ValueError("max_rule_delta must be a non-negative integer")


def _validate_quorum_certificate(
    certificate: object,
    *,
    name: str,
) -> QuorumCertificate:
    if type(certificate) is not QuorumCertificate:
        raise InvalidTransitionError(f"{name} must be a QuorumCertificate")
    if (
        type(certificate.assignment_id) is not str
        or type(certificate.artifact_hash) is not str
        or type(certificate.committee_seed) is not str
    ):
        raise InvalidTransitionError(f"{name} subject fields must be concrete strings")
    try:
        QuorumCertificate.__post_init__(certificate)
    except ValueError as exc:
        raise InvalidTransitionError(f"{name} is invalid: {exc}") from exc
    if type(certificate.votes) is not tuple or any(
        type(vote) is not SignedVote for vote in certificate.votes
    ):
        raise InvalidTransitionError(f"{name} votes must be concrete SignedVote records")
    for vote in certificate.votes:
        if (
            type(vote.voter_id) is not str
            or type(vote.assignment_id) is not str
            or type(vote.artifact_hash) is not str
        ):
            raise InvalidTransitionError(f"{name} vote subject fields must be strings")
        try:
            SignedVote.__post_init__(vote)
        except ValueError as exc:
            raise InvalidTransitionError(f"{name} vote is invalid: {exc}") from exc
        if type(vote.signature) is not bytes or len(vote.signature) != 64:
            raise InvalidTransitionError(f"{name} vote signature must be 64 bytes")
        if type(vote.public_key_bytes) is not bytes or len(vote.public_key_bytes) != 32:
            raise InvalidTransitionError(f"{name} vote public key must be 32 bytes")
    return certificate


def _validate_transition_certificate(certificate: object) -> TransitionCertificate:
    """Validate concrete transition records at construction and trust boundaries."""
    if type(certificate) is not TransitionCertificate:
        raise InvalidTransitionError("certificate must be a TransitionCertificate")
    proposal = certificate.proposal
    if type(proposal) is not AmendmentProposal:
        raise InvalidTransitionError("proposal must be an AmendmentProposal")
    AmendmentProposal.__post_init__(proposal)
    for name, quorum_certificate in (
        ("old_side_certificate", certificate.old_side_certificate),
        ("new_side_certificate", certificate.new_side_certificate),
    ):
        _validate_quorum_certificate(quorum_certificate, name=name)
    return certificate


def _append_length_prefixed(buffer: bytearray, value: bytes) -> None:
    buffer.extend(len(value).to_bytes(4, "big"))
    buffer.extend(value)


def build_transition_message(proposal: AmendmentProposal) -> bytes:
    """Return the legacy v2 length-prefixed transition commitment.

    This byte contract is retained for persisted records. New signatures use
    :func:`transition_vote_subject`, which binds the complete v3 policy subject.
    """
    message = bytearray(_DOMAIN)
    _append_length_prefixed(message, b"transition")
    _append_length_prefixed(message, proposal.prior.epoch.to_bytes(8, "big"))
    _append_length_prefixed(message, proposal.prior.digest)
    _append_length_prefixed(message, proposal.proposed.epoch.to_bytes(8, "big"))
    _append_length_prefixed(message, proposal.proposed.digest)
    _append_length_prefixed(message, proposal.binding_digest)
    _append_length_prefixed(message, proposal.old_validator_set_digest)
    _append_length_prefixed(message, proposal.new_validator_set_digest)
    return bytes(message)


def _transition_subject_digest(proposal: AmendmentProposal) -> bytes:
    """Return the v3 digest signed by both validator sides."""
    return framed_digest(
        _TRANSITION_SUBJECT_DOMAIN,
        proposal.prior.digest,
        proposal.proposed.digest,
        proposal.drift_budget.max_rule_delta,
        proposal.proposed.epoch,
        proposal.binding_digest,
        proposal.old_validator_set_digest,
        proposal.new_validator_set_digest,
    )


def transition_vote_subject(proposal: AmendmentProposal) -> tuple[str, str, int]:
    """Return the exact QC subject both validator sets must sign."""
    if type(proposal) is not AmendmentProposal:
        raise InvalidTransitionError("proposal must be an AmendmentProposal")
    AmendmentProposal.__post_init__(proposal)
    return (
        _TRANSITION_ASSIGNMENT_ID,
        _transition_subject_digest(proposal).hex(),
        proposal.proposed.epoch,
    )


def compute_transition_threshold(
    validator_set: ValidatorSet,
    threshold_fraction: float,
) -> int:
    """Return the verifier-owned rounded quorum over full-side raw stake."""
    if isinstance(threshold_fraction, bool) or not isinstance(threshold_fraction, Real):
        raise InvalidTransitionError("threshold_fraction must be a finite real number")
    normalized_fraction = float(threshold_fraction)
    if not math.isfinite(normalized_fraction) or not 0.0 < normalized_fraction <= 1.0:
        raise InvalidTransitionError("threshold_fraction must be finite and in (0, 1]")

    total_stake = 0.0
    for identity in _validated_validator_snapshot(validator_set):
        if isinstance(identity.stake, bool) or not isinstance(identity.stake, Real):
            raise InvalidTransitionError("validator stake must be a finite real number")
        stake = float(identity.stake)
        if not math.isfinite(stake) or stake < 0.0:
            raise InvalidTransitionError("validator stake must be finite and non-negative")
        total_stake += stake
    if not math.isfinite(total_stake) or total_stake <= 0.0:
        raise InvalidTransitionError("validator side must have positive finite raw stake")
    return math.ceil(normalized_fraction * total_stake)


def build_transition_side_certificate(
    certificate: QuorumCertificate,
    *,
    validator_set: ValidatorSet,
    threshold_fraction: float,
) -> QuorumCertificate:
    """Bind verifier-derived full-side raw stake metadata to a side QC."""
    certificate = _validate_quorum_certificate(certificate, name="certificate")
    return replace(
        certificate,
        threshold_weight=compute_transition_threshold(validator_set, threshold_fraction),
    )


def _signed_raw_stake(
    certificate: QuorumCertificate,
    validator_set: ValidatorSet,
) -> float:
    identities = {identity.agent_id: identity for identity in validator_set.snapshot()}
    return sum(float(identities[vote.voter_id].stake) for vote in certificate.votes)


def _validate_policy_can_ratify(
    *,
    side: str,
    certificate: QuorumCertificate,
    validator_set: ValidatorSet,
    policy: CertificateVerificationPolicy,
    expected_threshold: int,
) -> None:
    """Reject verifier policy that cannot encode the full-side threshold."""
    validator_ids = {
        identity.agent_id for identity in _validated_validator_snapshot(validator_set)
    }
    eligible_count = len(validator_ids - policy.excluded_voter_ids)
    committee_size = (
        policy.committee_size
        if policy.committee_size is not None
        else eligible_count
    )
    if committee_size <= 0 or committee_size > eligible_count:
        raise InvalidTransitionError(
            f"{side}-side policy can never ratify: no viable pinned committee"
        )
    committee_seed = (
        policy.expected_committee_seed
        if policy.expected_committee_seed is not None
        else certificate.committee_seed
    )
    committee = CommitteeSelector(validator_set).select(
        committee_seed,
        committee_size,
        exclude=tuple(policy.excluded_voter_ids),
    )
    if expected_threshold > committee.weight and not math.isclose(
        expected_threshold,
        committee.weight,
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        raise InvalidTransitionError(
            f"{side}-side policy can never ratify: full-side raw-stake threshold "
            f"{expected_threshold} exceeds selected effective capacity "
            f"{committee.weight:.6f}"
        )


def verify_transition(
    certificate: TransitionCertificate,
    *,
    old_validator_set: ValidatorSet,
    new_validator_set: ValidatorSet,
    current_version: ConstitutionVersion,
    policy: TransitionVerificationPolicy,
) -> None:
    """Validate a transition certificate under joint consensus.

    Raises one of the :class:`InvalidTransitionError` subclasses if the
    certificate is not admissible. Returns ``None`` on success.
    """
    certificate = _validate_transition_certificate(certificate)
    if type(current_version) is not ConstitutionVersion:
        raise InvalidTransitionError("current_version must be a ConstitutionVersion")
    ConstitutionVersion.__post_init__(current_version)
    if type(policy) is not TransitionVerificationPolicy:
        raise InvalidTransitionError("policy must be a TransitionVerificationPolicy")
    try:
        TransitionVerificationPolicy.__post_init__(policy)
    except ValueError as exc:
        raise InvalidTransitionError(f"verifier policy is invalid: {exc}") from exc
    if type(old_validator_set) is not ValidatorSet:
        raise InvalidTransitionError("old_validator_set must be a concrete ValidatorSet")
    if type(new_validator_set) is not ValidatorSet:
        raise InvalidTransitionError("new_validator_set must be a concrete ValidatorSet")
    proposal = certificate.proposal
    old_validator_snapshot = ValidatorSet(
        _validated_validator_snapshot(old_validator_set), policy=old_validator_set.policy
    )
    new_validator_snapshot = ValidatorSet(
        _validated_validator_snapshot(new_validator_set), policy=new_validator_set.policy
    )

    if proposal.prior != current_version:
        raise EpochMismatchError("proposal prior does not match trusted current version")

    if not proposal.old_validator_set_digest or not proposal.new_validator_set_digest:
        raise InvalidTransitionError(
            "transition proposal must bind both validator registries"
        )
    if proposal.old_validator_set_digest != compute_validator_set_digest(
        old_validator_snapshot
    ):
        raise InvalidTransitionError("old validator registry commitment mismatch")
    if proposal.new_validator_set_digest != compute_validator_set_digest(
        new_validator_snapshot
    ):
        raise InvalidTransitionError("new validator registry commitment mismatch")

    if proposal.drift_budget.max_rule_delta != policy.max_rule_delta:
        raise InvalidTransitionError("embedded drift budget does not match verifier policy")

    drift = proposal.drift
    if drift > policy.max_rule_delta:
        raise DriftBudgetExceeded(
            f"rule drift {drift} exceeds verifier budget {policy.max_rule_delta}"
        )

    expected_subject = transition_vote_subject(proposal)
    for side, qc in (
        ("old", certificate.old_side_certificate),
        ("new", certificate.new_side_certificate),
    ):
        actual_subject = (qc.assignment_id, qc.artifact_hash, qc.epoch)
        if actual_subject != expected_subject:
            raise InvalidTransitionError(f"{side}-side certificate subject mismatch")

    for side, qc, validator_snapshot, certificate_policy in (
        (
            "old",
            certificate.old_side_certificate,
            old_validator_snapshot,
            policy.old_certificate,
        ),
        (
            "new",
            certificate.new_side_certificate,
            new_validator_snapshot,
            policy.new_certificate,
        ),
    ):
        expected_threshold = compute_transition_threshold(
            validator_snapshot,
            certificate_policy.threshold_fraction,
        )
        _validate_policy_can_ratify(
            side=side,
            certificate=qc,
            validator_set=validator_snapshot,
            policy=certificate_policy,
            expected_threshold=expected_threshold,
        )
        if qc.threshold_weight != expected_threshold:
            raise InvalidTransitionError(
                f"{side}-side embedded threshold does not match verifier policy"
            )
        try:
            verify_certificate(
                qc,
                validator_set=validator_snapshot,
                policy=certificate_policy,
            )
        except (InvalidCertificateError, InsufficientQuorumError) as exc:
            raise JointQuorumNotMetError(
                f"{side}-side certificate verification failed: {exc}"
            ) from exc
        signed_stake = _signed_raw_stake(qc, validator_snapshot)
        if signed_stake < expected_threshold:
            raise JointQuorumNotMetError(
                f"{side}-side full-side raw stake {signed_stake:.6f} "
                f"is below threshold {expected_threshold}"
            )
