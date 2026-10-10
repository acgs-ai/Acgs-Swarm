"""Tests for Phase 7.5 versioned constitutional reconfiguration."""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    DriftBudgetExceeded,
    EpochMismatchError,
    InvalidTransitionError,
    JointQuorumNotMetError,
    TransitionCertificate,
    TransitionVerificationPolicy,
    build_transition_side_certificate,
    compute_validator_set_digest,
    compute_version_digest,
    evaluate_drift,
    transition_vote_subject,
    verify_transition,
)
from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    SignedVote,
    build_certificate,
    build_vote_message_v2,
)
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    FaultDomainPolicy,
    ValidatorIdentity,
    ValidatorSet,
)


def _v(epoch: int, rules: tuple[str, ...], parent: bytes = b"") -> ConstitutionVersion:
    return ConstitutionVersion(epoch=epoch, rules=tuple(sorted(rules)), parent_digest=parent)


class TestConstitutionVersion:
    def test_digest_is_deterministic(self) -> None:
        v1 = _v(1, ("a", "b"))
        v2 = _v(1, ("a", "b"))
        assert v1.digest == v2.digest

    def test_digest_separates_epoch(self) -> None:
        v1 = _v(1, ("a",))
        v2 = _v(2, ("a",))
        assert v1.digest != v2.digest

    def test_digest_separates_rules(self) -> None:
        v1 = _v(1, ("a",))
        v2 = _v(1, ("a", "b"))
        assert v1.digest != v2.digest

    def test_digest_separates_parent(self) -> None:
        v1 = _v(1, ("a",), parent=b"\x00" * 32)
        v2 = _v(1, ("a",), parent=b"\xff" * 32)
        assert v1.digest != v2.digest

    def test_rules_must_be_sorted(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=0, rules=("b", "a"))

    def test_negative_epoch_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=-1, rules=())

    def test_bad_parent_length_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=0, rules=(), parent_digest=b"\x00" * 16)

    def test_compute_version_digest_requires_nonneg_epoch(self) -> None:
        with pytest.raises(ValueError):
            compute_version_digest(epoch=-1, rules=(), parent_digest=b"")


class TestAmendmentProposal:
    def test_happy_path(self) -> None:
        v0 = _v(0, ("a",))
        v1 = _v(1, ("a", "b"), parent=v0.digest)
        proposal = AmendmentProposal(prior=v0, proposed=v1)
        assert proposal.drift == 1

    def test_rejects_non_adjacent_epoch(self) -> None:
        v0 = _v(0, ("a",))
        v2 = _v(2, ("a",), parent=v0.digest)
        with pytest.raises(EpochMismatchError):
            AmendmentProposal(prior=v0, proposed=v2)

    def test_rejects_bad_parent_pointer(self) -> None:
        v0 = _v(0, ("a",))
        bad_parent = b"\x00" * 32
        v1 = _v(1, ("a",), parent=bad_parent)
        with pytest.raises(InvalidTransitionError):
            AmendmentProposal(prior=v0, proposed=v1)


class TestEvaluateDrift:
    def test_drift_counts_add_and_remove(self) -> None:
        v0 = _v(0, ("a", "b"))
        v1 = _v(1, ("b", "c", "d"), parent=v0.digest)
        # removed: a; added: c, d → drift = 3
        assert evaluate_drift(v0, v1) == 3


class TestTransitionCertificate:
    @staticmethod
    def _validator_set(prefix: str, count: int = 3, stake: float = 1.0):
        keys = {f"{prefix}{index}": Ed25519PrivateKey.generate() for index in range(count)}
        validators = ValidatorSet(
            (
                ValidatorIdentity(
                    agent_id,
                    stake,
                    fault_domain=agent_id,
                    public_key_bytes=key.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    ),
                )
                for agent_id, key in keys.items()
            ),
            policy=FaultDomainPolicy(max_fraction=1.0),
        )
        return validators, keys

    @staticmethod
    def _qc(proposal, validators, keys, seed):
        assignment_id, artifact_hash, epoch = transition_vote_subject(proposal)
        committee = CommitteeSelector(validators).select(seed, len(validators))
        votes = [
            SignedVote(
                voter_id,
                assignment_id,
                artifact_hash,
                epoch,
                keys[voter_id].sign(
                    build_vote_message_v2(assignment_id, artifact_hash, epoch, voter_id)
                ),
                validators.get(voter_id).public_key_bytes,
            )
            for voter_id in committee.members
        ]
        certificate = build_certificate(
            votes,
            committee=committee,
            validator_set=validators,
        )
        return build_transition_side_certificate(
            certificate,
            validator_set=validators,
            threshold_fraction=2 / 3,
        )

    def _make(self, *, binding_digest: bytes = b"", drift_budget=DriftBudget()):
        v0 = _v(0, ("a", "b"))
        v1 = _v(1, ("a", "b", "c"), parent=v0.digest)
        old_set, old_keys = self._validator_set("v")
        new_set, new_keys = self._validator_set("w")
        proposal = AmendmentProposal(
            prior=v0,
            proposed=v1,
            drift_budget=drift_budget,
            binding_digest=binding_digest,
            old_validator_set_digest=compute_validator_set_digest(old_set),
            new_validator_set_digest=compute_validator_set_digest(new_set),
        )
        old_qc = self._qc(proposal, old_set, old_keys, "old-seed")
        new_qc = self._qc(proposal, new_set, new_keys, "new-seed")
        certificate = TransitionCertificate(proposal, old_qc, new_qc)
        policy = TransitionVerificationPolicy(
            old_certificate=CertificateVerificationPolicy(
                expected_committee_seed="old-seed"
            ),
            new_certificate=CertificateVerificationPolicy(
                expected_committee_seed="new-seed"
            ),
        )
        return certificate, old_set, new_set, policy

    def test_happy_path(self) -> None:
        cert, old_set, new_set, policy = self._make()
        verify_transition(
            cert,
            old_validator_set=old_set,
            new_validator_set=new_set,
            current_version=cert.proposal.prior,
            policy=policy,
        )

    def test_rejects_insufficient_old_side(self) -> None:
        cert, old_set, new_set, policy = self._make()
        cert = replace(
            cert,
            old_side_certificate=replace(
                cert.old_side_certificate,
                votes=cert.old_side_certificate.votes[:1],
            ),
        )
        with pytest.raises(JointQuorumNotMetError):
            verify_transition(
                cert,
                old_validator_set=old_set,
                new_validator_set=new_set,
                current_version=cert.proposal.prior,
                policy=policy,
            )

    def test_rejects_insufficient_new_side(self) -> None:
        cert, old_set, new_set, policy = self._make()
        cert = replace(
            cert,
            new_side_certificate=replace(
                cert.new_side_certificate,
                votes=cert.new_side_certificate.votes[:1],
            ),
        )
        with pytest.raises(JointQuorumNotMetError):
            verify_transition(
                cert,
                old_validator_set=old_set,
                new_validator_set=new_set,
                current_version=cert.proposal.prior,
                policy=policy,
            )

    def test_drift_budget_exceeded(self) -> None:
        cert, old_set, new_set, policy = self._make(
            drift_budget=DriftBudget(max_rule_delta=0)
        )
        policy = replace(policy, max_rule_delta=0)
        with pytest.raises(DriftBudgetExceeded):
            verify_transition(
                cert,
                old_validator_set=old_set,
                new_validator_set=new_set,
                current_version=cert.proposal.prior,
                policy=policy,
            )
