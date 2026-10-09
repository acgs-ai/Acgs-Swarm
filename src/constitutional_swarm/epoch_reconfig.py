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
from dataclasses import dataclass, field

from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    InsufficientQuorumError,
    InvalidCertificateError,
    QuorumCertificate,
    verify_certificate,
)
from constitutional_swarm.validator_set import ValidatorSet

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
    "compute_validator_set_digest",
    "compute_version_digest",
    "evaluate_drift",
    "transition_vote_subject",
    "verify_transition",
]


_DOMAIN = b"acgs-swarm/epoch-reconfig/v2"
_TRANSITION_ASSIGNMENT_ID = "constitutional-transition-v2"


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
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, str) for rule in self.rules
        ):
            raise ValueError("rules must be a tuple of strings")
        if tuple(sorted(self.rules)) != self.rules:
            raise ValueError("rules must be sorted (canonical form)")
        if len(set(self.rules)) != len(self.rules):
            raise ValueError("rules must not contain duplicates")
        if len(self.parent_digest) not in (0, 32):
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


def compute_validator_set_digest(validator_set: ValidatorSet) -> bytes:
    """Commit to a complete validator registry and its fault-domain policy."""
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
    snapshot = validator_set.snapshot()
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
        if self.proposed.epoch != self.prior.epoch + 1:
            raise EpochMismatchError(
                "proposed epoch must be prior.epoch + 1 "
                f"(prior={self.prior.epoch}, proposed={self.proposed.epoch})"
            )
        if self.proposed.parent_digest != self.prior.digest:
            raise InvalidTransitionError("proposed.parent_digest must equal prior.digest")
        if not isinstance(self.binding_digest, bytes) or len(self.binding_digest) not in (0, 32):
            raise InvalidTransitionError("binding_digest must be 0 or 32 bytes")
        for name, digest in (
            ("old_validator_set_digest", self.old_validator_set_digest),
            ("new_validator_set_digest", self.new_validator_set_digest),
        ):
            if not isinstance(digest, bytes) or len(digest) not in (0, 32):
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


@dataclass(frozen=True)
class TransitionVerificationPolicy:
    """Verifier-owned joint-consensus and drift policy."""

    old_certificate: CertificateVerificationPolicy = field(
        default_factory=CertificateVerificationPolicy
    )
    new_certificate: CertificateVerificationPolicy = field(
        default_factory=CertificateVerificationPolicy
    )
    max_rule_delta: int = 16

    def __post_init__(self) -> None:
        if type(self.max_rule_delta) is not int or self.max_rule_delta < 0:
            raise ValueError("max_rule_delta must be a non-negative integer")


def _append_length_prefixed(buffer: bytearray, value: bytes) -> None:
    buffer.extend(len(value).to_bytes(4, "big"))
    buffer.extend(value)


def build_transition_message(proposal: AmendmentProposal) -> bytes:
    """Return the canonical, length-prefixed transition commitment."""
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


def transition_vote_subject(proposal: AmendmentProposal) -> tuple[str, str, int]:
    """Return the exact QC subject both validator sets must sign."""
    return (
        _TRANSITION_ASSIGNMENT_ID,
        hashlib.sha256(build_transition_message(proposal)).hexdigest(),
        proposal.proposed.epoch,
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
    proposal = certificate.proposal
    old_validator_snapshot = ValidatorSet(
        old_validator_set.snapshot(), policy=old_validator_set.policy
    )
    new_validator_snapshot = ValidatorSet(
        new_validator_set.snapshot(), policy=new_validator_set.policy
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

    # The proposal's drift_budget is compatibility metadata. Only verifier policy
    # can authorize governance drift.
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

    try:
        verify_certificate(
            certificate.old_side_certificate,
            validator_set=old_validator_snapshot,
            policy=policy.old_certificate,
        )
        verify_certificate(
            certificate.new_side_certificate,
            validator_set=new_validator_snapshot,
            policy=policy.new_certificate,
        )
    except (InvalidCertificateError, InsufficientQuorumError) as exc:
        raise JointQuorumNotMetError(f"joint certificate verification failed: {exc}") from exc
