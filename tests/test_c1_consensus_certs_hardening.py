"""Security regressions for C1 consensus certificate hardening."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

import constitutional_swarm.bittensor.constitution_sync as sync_module
from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionDistributor,
    ConstitutionReceiver,
    ConstitutionSyncMessage,
)
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
    build_transition_message,
    build_transition_side_certificate,
    compute_validator_set_digest,
    transition_vote_subject,
    verify_transition,
)
from constitutional_swarm.node_admission import (
    AbliterationAdmissionGate,
    ActivationAdmissionGate,
    AdmissionDecision,
    RefusalDistributionGate,
    _select_with_exclusions,
)
from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    ConflictEvidence,
    InsufficientQuorumError,
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    build_certificate,
    build_vote_message,
    detect_conflict,
    verify_certificate,
)
from constitutional_swarm.validator_set import (
    CommitteeSelection,
    CommitteeSelector,
    FaultDomainPolicy,
    ValidatorIdentity,
    ValidatorSet,
)
from tests.test_constitution_sync_governed import (
    _SYNC_SIGNING_KEY,
    YAML_BOOT as _SYNC_YAML_BOOT,
    YAML_E1 as _SYNC_YAML_E1,
    YAML_E2 as _SYNC_YAML_E2,
    _apply as _sync_apply,
    _certificate as _sync_certificate,
    _policy,
    _setup as _sync_setup,
    _validator_set,
    _version as _sync_version,
)


def _public_key(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _vote(
    key: Ed25519PrivateKey,
    voter_id: str,
    artifact_hash: str,
    *,
    assignment_id: str = "assignment",
    epoch: int = 1,
) -> SignedVote:
    message = build_vote_message(assignment_id, artifact_hash, epoch)
    return SignedVote(
        voter_id=voter_id,
        assignment_id=assignment_id,
        artifact_hash=artifact_hash,
        epoch=epoch,
        signature=key.sign(message),
        public_key_bytes=_public_key(key),
    )


def _validators(count: int) -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey]]:
    keys = {f"v{index}": Ed25519PrivateKey.generate() for index in range(count)}
    validator_set = ValidatorSet(
        (
            ValidatorIdentity(
                agent_id,
                1.0,
                fault_domain=agent_id,
                public_key_bytes=_public_key(key),
            )
            for agent_id, key in keys.items()
        ),
        policy=FaultDomainPolicy(max_fraction=1.0),
    )
    return validator_set, keys


@pytest.mark.parametrize("epoch", [1.5, True, -1])
def test_qc_epoch_must_be_a_non_negative_integer(epoch) -> None:
    key = Ed25519PrivateKey.generate()
    signature = key.sign(build_vote_message("assignment", "artifact", 1))

    with pytest.raises(ValueError, match="non-negative integer"):
        SignedVote(
            voter_id="v0",
            assignment_id="assignment",
            artifact_hash="artifact",
            epoch=epoch,
            signature=signature,
            public_key_bytes=_public_key(key),
        )

    with pytest.raises(ValueError, match="non-negative integer"):
        build_vote_message("assignment", "artifact", epoch)

    with pytest.raises(ValueError, match="non-negative integer"):
        QuorumCertificate(
            assignment_id="assignment",
            artifact_hash="artifact",
            epoch=epoch,
            votes=(),
            threshold_weight=1.0,
            achieved_weight=0.0,
        )

    with pytest.raises(ValueError, match="non-negative integer"):
        QuorumCertificate.from_dict(
            {
                "assignment_id": "assignment",
                "artifact_hash": "artifact",
                "epoch": epoch,
                "votes": [],
                "threshold_weight": 1.0,
                "achieved_weight": 0.0,
            }
        )


def _transition_qc(proposal, validator_set, keys, seed, voter_ids=None):
    committee = CommitteeSelector(validator_set).select(seed, len(validator_set))
    assignment_id, artifact_hash, epoch = transition_vote_subject(proposal)
    selected_voters = voter_ids or committee.members
    qc = build_certificate(
        [
            _vote(
                keys[voter_id],
                voter_id,
                artifact_hash,
                assignment_id=assignment_id,
                epoch=epoch,
            )
            for voter_id in selected_voters
        ],
        committee=committee,
        validator_set=validator_set,
    )
    return build_transition_side_certificate(
        qc,
        validator_set=validator_set,
        threshold_fraction=2 / 3,
    )


def _proposal(
    prior: ConstitutionVersion,
    proposed: ConstitutionVersion,
    old_validator_set: ValidatorSet,
    new_validator_set: ValidatorSet,
    drift_budget: DriftBudget = DriftBudget(),
    *,
    binding_digest: bytes = b"",
) -> AmendmentProposal:
    return AmendmentProposal(
        prior,
        proposed,
        drift_budget,
        binding_digest,
        compute_validator_set_digest(old_validator_set),
        compute_validator_set_digest(new_validator_set),
    )


def test_builder_rejects_vote_signed_by_unregistered_embedded_key() -> None:
    validator_set, _ = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    attacker = Ed25519PrivateKey.generate()
    forged = [_vote(attacker, voter_id, "artifact") for voter_id in committee.members]

    with pytest.raises(InvalidCertificateError, match="registry|registered public key"):
        build_certificate(forged, committee=committee, validator_set=validator_set)


def test_forged_conflict_cannot_create_slashable_evidence() -> None:
    validator_set, _ = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    attacker = Ed25519PrivateKey.generate()
    forged_votes_a = tuple(
        _vote(attacker, voter_id, "artifact-a") for voter_id in committee.members
    )
    forged_votes_b = tuple(
        _vote(attacker, voter_id, "artifact-b") for voter_id in committee.members
    )
    qc_a = QuorumCertificate(
        "assignment", "artifact-a", 1, forged_votes_a, 2.0, 3.0, "seed"
    )
    qc_b = QuorumCertificate(
        "assignment", "artifact-b", 1, forged_votes_b, 2.0, 3.0, "seed"
    )

    with pytest.raises(InvalidCertificateError):
        detect_conflict(qc_a, qc_b, validator_set=validator_set)


def test_manual_conflict_evidence_cannot_add_innocent_validator() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    qc_a = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact-a") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )
    qc_b = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact-b") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )
    forged = ConflictEvidence(qc_a, qc_b, frozenset({"innocent"}))

    assert not forged.is_slashable(validator_set=validator_set)


def test_cross_seed_conflict_uses_each_qcs_pinned_policy() -> None:
    validator_set, keys = _validators(8)
    selector = CommitteeSelector(validator_set)
    committee_a = selector.select("seed-a", committee_size=5)
    seed_b = next(
        f"seed-b-{index}"
        for index in range(100)
        if set(committee_a.members)
        & set(selector.select(f"seed-b-{index}", committee_size=5).members)
    )
    committee_b = selector.select(seed_b, committee_size=5)

    def certificate(committee: CommitteeSelection, artifact: str) -> QuorumCertificate:
        votes = [
            _vote(keys[voter_id], voter_id, artifact)
            for voter_id in committee.members
        ]
        return build_certificate(
            votes, committee=committee, validator_set=validator_set
        )

    qc_a = certificate(committee_a, "hash-A")
    qc_b = certificate(committee_b, "hash-B")
    policy_a = CertificateVerificationPolicy(
        committee_size=5,
        expected_committee_seed="seed-a",
    )
    policy_b = CertificateVerificationPolicy(
        committee_size=5,
        expected_committee_seed=seed_b,
    )

    evidence = detect_conflict(
        qc_a,
        qc_b,
        validator_set=validator_set,
        policy_a=policy_a,
        policy_b=policy_b,
    )

    assert evidence is not None
    assert evidence.equivocators == set(committee_a.members) & set(
        committee_b.members
    )
    assert evidence.is_slashable(
        validator_set=validator_set,
        policy_a=policy_a,
        policy_b=policy_b,
    )
    with pytest.raises(InvalidCertificateError, match="seed"):
        detect_conflict(
            qc_a,
            qc_b,
            validator_set=validator_set,
            policy_a=policy_b,
            policy_b=policy_a,
        )


def test_cross_seed_disjoint_committees_are_not_slashable() -> None:
    validator_set, keys = _validators(8)
    selector = CommitteeSelector(validator_set)
    committee_a = selector.select("seed-a", committee_size=4)
    seed_b = next(
        f"disjoint-{index}"
        for index in range(10_000)
        if not set(committee_a.members)
        & set(selector.select(f"disjoint-{index}", committee_size=4).members)
    )
    committee_b = selector.select(seed_b, committee_size=4)

    def certificate(committee: CommitteeSelection, artifact: str) -> QuorumCertificate:
        votes = [
            _vote(keys[voter_id], voter_id, artifact)
            for voter_id in committee.members
        ]
        return build_certificate(
            votes, committee=committee, validator_set=validator_set
        )

    policy_a = CertificateVerificationPolicy(
        committee_size=4,
        expected_committee_seed="seed-a",
    )
    policy_b = CertificateVerificationPolicy(
        committee_size=4,
        expected_committee_seed=seed_b,
    )
    evidence = detect_conflict(
        certificate(committee_a, "hash-A"),
        certificate(committee_b, "hash-B"),
        validator_set=validator_set,
        policy_a=policy_a,
        policy_b=policy_b,
    )

    assert evidence is not None
    assert evidence.equivocators == frozenset()
    assert not evidence.is_slashable(
        validator_set=validator_set,
        policy_a=policy_a,
        policy_b=policy_b,
    )


def test_transition_enforces_pinned_drift_budget_and_fails_closed() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(
        1,
        tuple(sorted(("rule-0", *(f"rule-{index}" for index in range(1, 30))))),
        prior.digest,
    )
    validator_set, keys = _validators(3)
    proposal = _proposal(
        prior, proposed, validator_set, validator_set, DriftBudget(1)
    )
    committee = CommitteeSelector(validator_set).select("transition-seed", 3)
    assignment_id, artifact_hash, epoch = transition_vote_subject(proposal)
    qc = build_certificate(
        [
            _vote(
                keys[voter_id],
                voter_id,
                artifact_hash,
                assignment_id=assignment_id,
                epoch=epoch,
            )
            for voter_id in committee.members
        ],
        committee=committee,
        validator_set=validator_set,
    )
    qc = build_transition_side_certificate(
        qc,
        validator_set=validator_set,
        threshold_fraction=2 / 3,
    )
    certificate = TransitionCertificate(proposal, qc, qc)
    qc_policy = CertificateVerificationPolicy(
        committee_size=3,
        expected_committee_seed="transition-seed",
    )

    with pytest.raises(DriftBudgetExceeded):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=prior,
            policy=TransitionVerificationPolicy(
                old_certificate=qc_policy,
                new_certificate=qc_policy,
                max_rule_delta=1,
            ),
        )


def test_constitution_version_rejects_duplicate_rules() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        ConstitutionVersion(epoch=0, rules=("rule", "rule"))


def test_transition_binding_digest_changes_canonical_subject() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0",), prior.digest)
    proposal_a = AmendmentProposal(prior, proposed, binding_digest=b"\x01" * 32)
    proposal_b = AmendmentProposal(prior, proposed, binding_digest=b"\x02" * 32)

    assert build_transition_message(proposal_a) != build_transition_message(proposal_b)
    assert transition_vote_subject(proposal_a) != transition_vote_subject(proposal_b)


def test_transition_rejects_reused_old_qc_for_substituted_successor() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    old_set, old_keys = _validator_set("old-")
    legitimate_new_set, legitimate_new_keys = _validator_set("new-")
    evil_new_set, evil_new_keys = _validator_set("evil-")
    legitimate = _proposal(prior, proposed, old_set, legitimate_new_set)
    old_qc = _transition_qc(legitimate, old_set, old_keys, "old-seed")
    legitimate_new_qc = _transition_qc(
        legitimate, legitimate_new_set, legitimate_new_keys, "new-seed"
    )
    policy = TransitionVerificationPolicy(
        old_certificate=CertificateVerificationPolicy(
            expected_committee_seed="old-seed"
        ),
        new_certificate=CertificateVerificationPolicy(
            expected_committee_seed="new-seed"
        ),
    )
    verify_transition(
        TransitionCertificate(legitimate, old_qc, legitimate_new_qc),
        old_validator_set=old_set,
        new_validator_set=legitimate_new_set,
        current_version=prior,
        policy=policy,
    )

    substituted = _proposal(prior, proposed, old_set, evil_new_set)
    evil_new_qc = _transition_qc(substituted, evil_new_set, evil_new_keys, "new-seed")
    with pytest.raises(InvalidTransitionError, match="subject mismatch"):
        verify_transition(
            TransitionCertificate(substituted, old_qc, evil_new_qc),
            old_validator_set=old_set,
            new_validator_set=evil_new_set,
            current_version=prior,
            policy=policy,
        )


def test_transition_verification_rejects_registry_subclasses() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    trusted_old, _ = _validator_set("old-")
    trusted_new, _ = _validator_set("new-")
    evil_old, evil_old_keys = _validator_set("evil-old-")
    evil_new, evil_new_keys = _validator_set("evil-new-")
    proposal = _proposal(prior, proposed, trusted_old, trusted_new)
    old_qc = _transition_qc(proposal, evil_old, evil_old_keys, "old-seed")
    new_qc = _transition_qc(proposal, evil_new, evil_new_keys, "new-seed")

    class ChangingValidatorSet(ValidatorSet):
        def __init__(self, trusted: ValidatorSet, substituted: ValidatorSet) -> None:
            super().__init__(trusted.snapshot(), policy=trusted.policy)
            self._snapshots = iter((trusted.snapshot(), substituted.snapshot()))

        def snapshot(self):
            return next(self._snapshots)

    policy = TransitionVerificationPolicy(
        old_certificate=CertificateVerificationPolicy(
            expected_committee_seed="old-seed"
        ),
        new_certificate=CertificateVerificationPolicy(
            expected_committee_seed="new-seed"
        ),
    )
    with pytest.raises(InvalidTransitionError, match="concrete ValidatorSet"):
        verify_transition(
            TransitionCertificate(proposal, old_qc, new_qc),
            old_validator_set=ChangingValidatorSet(trusted_old, evil_old),
            new_validator_set=ChangingValidatorSet(trusted_new, evil_new),
            current_version=prior,
            policy=policy,
        )


def test_validator_registry_digest_accepts_integer_real_values() -> None:
    validator_set = ValidatorSet(
        (ValidatorIdentity("validator", 1, reputation=1, fault_domain="domain"),),
        policy=FaultDomainPolicy(max_fraction=1),
    )

    assert len(compute_validator_set_digest(validator_set)) == 32


def test_validator_registry_digest_normalizes_malformed_key_type() -> None:
    validator_set = ValidatorSet(
        (
            ValidatorIdentity(
                "validator",
                1.0,
                fault_domain="domain",
                public_key_bytes="x" * 32,  # type: ignore[arg-type]
            ),
        )
    )

    with pytest.raises(InvalidTransitionError, match="public_key_bytes"):
        compute_validator_set_digest(validator_set)


def test_certificate_policy_requires_explicit_unsafe_opt_in_below_two_thirds() -> None:
    with pytest.raises(ValueError, match="unsafe_allow_sub_two_thirds"):
        CertificateVerificationPolicy(threshold_fraction=0.5)

    policy = CertificateVerificationPolicy(
        threshold_fraction=0.5,
        unsafe_allow_sub_two_thirds=True,
    )
    assert policy.threshold_fraction == 0.5


def test_non_bytes_vote_crypto_fields_fail_closed() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    votes = [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members]
    malformed_signature = replace(votes[0], signature=None)
    malformed_key = replace(votes[0], public_key_bytes="not-bytes")

    assert not malformed_signature.verify()
    assert not malformed_key.verify()
    with pytest.raises(InvalidCertificateError, match="signature"):
        build_certificate(
            [malformed_signature, *votes[1:]],
            committee=committee,
            validator_set=validator_set,
        )
    with pytest.raises(InvalidCertificateError, match="public key|registry"):
        build_certificate(
            [malformed_key, *votes[1:]],
            committee=committee,
            validator_set=validator_set,
        )


@pytest.mark.parametrize("budget", [True, 1.0, float("nan"), float("inf"), -1])
def test_transition_policy_rejects_non_integer_or_negative_budget(budget) -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        TransitionVerificationPolicy(max_rule_delta=budget)


def test_transition_rejects_same_epoch_alternate_predecessor() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    validator_set, keys = _validators(3)
    proposal = _proposal(prior, proposed, validator_set, validator_set)
    qc = _transition_qc(proposal, validator_set, keys, "seed")

    with pytest.raises(EpochMismatchError):
        verify_transition(
            TransitionCertificate(proposal, qc, qc),
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=ConstitutionVersion(0, ("alternate",)),
            policy=TransitionVerificationPolicy(),
        )


def test_transition_rejects_unknown_signed_old_side_claim() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    validator_set, keys = _validators(3)
    proposal = _proposal(prior, proposed, validator_set, validator_set)
    qc = _transition_qc(proposal, validator_set, keys, "seed")
    forged_vote = replace(qc.votes[0], voter_id="ghost")
    forged_old = replace(qc, votes=(forged_vote, *qc.votes[1:]))

    with pytest.raises(JointQuorumNotMetError):
        verify_transition(
            TransitionCertificate(proposal, forged_old, qc),
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=prior,
            policy=TransitionVerificationPolicy(),
        )


def test_transition_checks_drift_before_invalid_joint_quorum() -> None:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    validator_set, keys = _validators(3)
    proposal = _proposal(
        prior, proposed, validator_set, validator_set, DriftBudget(0)
    )
    qc = _transition_qc(proposal, validator_set, keys, "seed")
    empty_qc = replace(qc, votes=())

    with pytest.raises(DriftBudgetExceeded):
        verify_transition(
            TransitionCertificate(proposal, empty_qc, empty_qc),
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=prior,
            policy=TransitionVerificationPolicy(max_rule_delta=0),
        )


def test_transition_joint_quorum_remains_stake_weighted() -> None:
    keys = {f"v{index}": Ed25519PrivateKey.generate() for index in range(3)}
    weights = {"v0": 5.0, "v1": 5.0, "v2": 1.0}
    validator_set = ValidatorSet(
        (
            ValidatorIdentity(
                voter_id,
                weights[voter_id],
                fault_domain=voter_id,
                public_key_bytes=_public_key(key),
            )
            for voter_id, key in keys.items()
        ),
        policy=FaultDomainPolicy(max_fraction=1.0),
    )
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    proposal = _proposal(prior, proposed, validator_set, validator_set)
    heavy_voters = tuple(
        voter_id for voter_id in committee.members if weights[voter_id] == 5.0
    )
    qc = _transition_qc(
        proposal,
        validator_set,
        keys,
        "seed",
        voter_ids=heavy_voters,
    )

    verify_transition(
        TransitionCertificate(proposal, qc, qc),
        old_validator_set=validator_set,
        new_validator_set=validator_set,
        current_version=prior,
        policy=TransitionVerificationPolicy(),
    )


def test_admission_selection_excludes_unscreened_validators() -> None:
    validator_set = ValidatorSet(
        ValidatorIdentity(agent_id, 1.0, fault_domain=agent_id) for agent_id in "abc"
    )
    decision = AdmissionDecision(admitted=("a",), rejected=(), reports={"a": object()})

    selected = _select_with_exclusions(
        CommitteeSelector(validator_set),
        "seed",
        3,
        decision,
        exclude=(),
        require_independent=False,
        threshold_fraction=2 / 3,
        max_retries=8,
    )

    assert set(selected.members) == {"a"}


def test_admission_selection_does_not_enumerate_via_sentinel_select() -> None:
    validator_set, _ = _validators(3)
    selector = CommitteeSelector(validator_set)
    calls: list[int] = []
    original_select = selector.select

    def recording_select(seed, committee_size, *, exclude=()):
        calls.append(committee_size)
        return original_select(seed, committee_size, exclude=exclude)

    selector.select = recording_select  # type: ignore[method-assign]
    decision = AdmissionDecision(
        admitted=("v0", "v1"), rejected=("v2",), reports={}
    )

    selection = _select_with_exclusions(
        selector,
        "seed",
        2,
        decision,
        exclude=(),
        require_independent=False,
        threshold_fraction=2 / 3,
        max_retries=8,
    )

    assert calls == [2]
    assert set(selection.members) == {"v0", "v1"}


def test_subset_committee_certificate_verifies_from_seed() -> None:
    validator_set, keys = _validators(30)
    committee = CommitteeSelector(validator_set).select("committee-seed", 7)
    qc = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )

    verify_certificate(
        qc,
        validator_set=validator_set,
        policy=CertificateVerificationPolicy(
            committee_size=7,
            expected_committee_seed="committee-seed",
        ),
    )


def test_subset_policy_requires_verifier_pinned_seed() -> None:
    with pytest.raises(ValueError, match="expected seed"):
        CertificateVerificationPolicy(committee_size=7)


@pytest.mark.parametrize("threshold", [True, float("nan"), float("inf"), -1.0, 0.0])
def test_certificate_policy_rejects_nonfinite_or_nonpositive_threshold(threshold) -> None:
    with pytest.raises(ValueError, match="threshold_fraction"):
        CertificateVerificationPolicy(threshold_fraction=threshold)


def test_unknown_exclusion_does_not_shrink_full_committee() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    qc = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )

    verify_certificate(
        qc,
        validator_set=validator_set,
        policy=CertificateVerificationPolicy(excluded_voter_ids=frozenset({"ghost"})),
    )


def test_builder_rejects_fabricated_registered_subgroup() -> None:
    validator_set, keys = _validators(4)
    expected = CommitteeSelector(validator_set).select("seed", 2)
    alternate_members = tuple(
        voter_id
        for voter_id in sorted(keys)
        if voter_id not in expected.members
    )[:2]
    fabricated = CommitteeSelection(
        members=alternate_members,
        weight=2.0,
        capped_weight=2.0,
        domain_weights={voter_id: 1.0 for voter_id in alternate_members},
        seed="seed",
    )

    with pytest.raises(InvalidCertificateError, match="deterministic selection"):
        build_certificate(
            [_vote(keys[voter_id], voter_id, "artifact") for voter_id in alternate_members],
            committee=fabricated,
            validator_set=validator_set,
        )


@pytest.mark.parametrize("threshold", [True, float("nan"), float("inf"), -1.0, 0.5])
def test_malformed_or_weakened_threshold_override_rejected(threshold) -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    qc = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )

    with pytest.raises(ValueError, match="threshold_fraction"):
        verify_certificate(qc, validator_set=validator_set, threshold_fraction=threshold)


def test_stronger_legacy_threshold_accepts_sufficient_votes() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    qc = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members],
        committee=committee,
        validator_set=validator_set,
    )

    verify_certificate(qc, validator_set=validator_set, threshold_fraction=0.9)


def test_explicit_trusted_policy_may_choose_lower_threshold() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    policy = CertificateVerificationPolicy(
        committee_size=3,
        threshold_fraction=0.5,
        unsafe_allow_sub_two_thirds=True,
        expected_committee_seed="seed",
    )
    qc = build_certificate(
        [_vote(keys[voter_id], voter_id, "artifact") for voter_id in committee.members[:2]],
        committee=committee,
        validator_set=validator_set,
        verification_policy=policy,
    )

    verify_certificate(qc, validator_set=validator_set, policy=policy)


def test_artifact_threshold_cannot_weaken_verifier_policy() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    voter_id = committee.members[0]
    qc = QuorumCertificate(
        "assignment",
        "artifact",
        1,
        (_vote(keys[voter_id], voter_id, "artifact"),),
        threshold_weight=0.1,
        achieved_weight=1.0,
        committee_seed="seed",
    )

    with pytest.raises(InsufficientQuorumError, match="trusted threshold"):
        verify_certificate(qc, validator_set=validator_set)


def test_artifact_threshold_cannot_strengthen_verifier_policy() -> None:
    validator_set, keys = _validators(3)
    committee = CommitteeSelector(validator_set).select("seed", 3)
    voter_id = committee.members[0]
    qc = QuorumCertificate(
        "assignment",
        "artifact",
        1,
        (_vote(keys[voter_id], voter_id, "artifact"),),
        threshold_weight=3.0,
        achieved_weight=1.0,
        committee_seed="seed",
    )
    policy = CertificateVerificationPolicy(
        committee_size=3,
        threshold_fraction=0.25,
        unsafe_allow_sub_two_thirds=True,
        expected_committee_seed="seed",
    )

    verify_certificate(qc, validator_set=validator_set, policy=policy)


def test_tiny_weights_do_not_bypass_quorum_with_absolute_tolerance() -> None:
    keys = {f"v{index}": Ed25519PrivateKey.generate() for index in range(3)}
    validator_set = ValidatorSet(
        (
            ValidatorIdentity(
                voter_id,
                1e-20,
                fault_domain=voter_id,
                public_key_bytes=_public_key(key),
            )
            for voter_id, key in keys.items()
        ),
        policy=FaultDomainPolicy(max_fraction=1.0),
    )
    committee = CommitteeSelector(validator_set).select("seed", 3)

    with pytest.raises(InsufficientQuorumError):
        build_certificate(
            [_vote(keys[committee.members[0]], committee.members[0], "artifact")],
            committee=committee,
            validator_set=validator_set,
        )


def test_absolute_threshold_override_cannot_bypass_committee_membership() -> None:
    validator_set, keys = _validators(4)
    committee = CommitteeSelector(validator_set).select("seed", 2)
    outsider = next(voter_id for voter_id in keys if voter_id not in committee.members)
    votes = (
        _vote(keys[committee.members[0]], committee.members[0], "artifact"),
        _vote(keys[outsider], outsider, "artifact"),
    )
    qc = QuorumCertificate(
        "assignment",
        "artifact",
        1,
        votes,
        threshold_weight=4 / 3,
        achieved_weight=2.0,
        committee_seed="seed",
    )

    with pytest.raises(InvalidCertificateError, match="committee"):
        verify_certificate(
            qc,
            validator_set=validator_set,
            policy=CertificateVerificationPolicy(
                committee_size=2,
                expected_committee_seed="seed",
            ),
            expected_threshold_weight=1.0,
        )


def test_independent_admission_selection_excludes_unscreened_validators() -> None:
    validator_set = ValidatorSet(
        ValidatorIdentity(agent_id, 1.0, fault_domain=agent_id) for agent_id in "abc"
    )
    decision = AdmissionDecision(
        admitted=("a", "b"),
        rejected=(),
        reports={"a": object(), "b": object()},
    )
    selection = _select_with_exclusions(
        CommitteeSelector(validator_set),
        "seed",
        3,
        decision,
        exclude=(),
        require_independent=True,
        threshold_fraction=2 / 3,
        max_retries=8,
    )

    assert set(selection.members) == {"a", "b"}


@pytest.mark.parametrize(
    "gate",
    [
        AbliterationAdmissionGate([1.0, 0.0]),
        ActivationAdmissionGate(1.0),
        RefusalDistributionGate(),
    ],
)
def test_all_admission_gates_select_only_explicitly_admitted(monkeypatch, gate) -> None:
    validator_set = ValidatorSet(
        ValidatorIdentity(agent_id, 1.0, fault_domain=agent_id) for agent_id in "abc"
    )
    decision = AdmissionDecision(admitted=("a", "b"), rejected=(), reports={})
    monkeypatch.setattr(gate, "screen", lambda _candidates: decision)

    selection, returned_decision = gate.select_admissible(
        CommitteeSelector(validator_set),
        "seed",
        3,
        {},
    )

    assert returned_decision is decision
    assert set(selection.members) == {"a", "b"}


def test_sync_rejects_replay_of_old_signed_message_after_newer_version() -> None:
    key = Ed25519PrivateKey.generate()
    trusted_keys = {"owner": _public_key(key)}
    distributor = ConstitutionDistributor(
        "rules:\n  - first\n", key, issuer_id="owner"
    )
    receiver = ConstitutionReceiver("validator", trusted_issuer_keys=trusted_keys)

    first = distributor.broadcast_message()
    first = replace(first, signature=key.sign(first.signing_payload()))
    assert receiver.apply(first).success

    distributor.update("rules:\n  - second\n")
    second = distributor.broadcast_message()
    second = replace(second, signature=key.sign(second.signing_payload()))
    assert receiver.apply(second).success

    state_before_replay = (
        receiver.active_hash,
        receiver.active_yaml,
        tuple(receiver.version_history),
    )
    replay = receiver.apply(first)

    assert not replay.success
    assert "replay" in replay.message.lower() or "version" in replay.message.lower()
    assert (
        receiver.active_hash,
        receiver.active_yaml,
        tuple(receiver.version_history),
    ) == state_before_replay


def test_sync_rejects_seen_hash_with_new_sequence_and_signature() -> None:
    key = Ed25519PrivateKey.generate()
    trusted_keys = {"owner": _public_key(key)}
    distributor = ConstitutionDistributor(
        "rules:\n  - first\n", key, issuer_id="owner"
    )
    receiver = ConstitutionReceiver("validator", trusted_issuer_keys=trusted_keys)

    first = distributor.broadcast_message()
    first = replace(first, signature=key.sign(first.signing_payload()))
    assert receiver.apply(first).success

    replay = replace(
        first,
        version_id="new-id",
        version=first.version + 1,
        issued_at=first.issued_at + 1,
        signature=None,
    )
    replay = replace(replay, signature=key.sign(replay.signing_payload()))

    result = receiver.apply(replay)
    assert not result.success
    assert "replay" in result.message.lower()
    assert len(receiver.version_history) == 1


def test_sync_rejects_non_increasing_sequence_with_fresh_content() -> None:
    key = Ed25519PrivateKey.generate()
    trusted_keys = {"owner": _public_key(key)}
    distributor = ConstitutionDistributor(
        "rules:\n  - first\n", key, issuer_id="owner"
    )
    receiver = ConstitutionReceiver("validator", trusted_issuer_keys=trusted_keys)

    first = distributor.broadcast_message()
    first = replace(first, signature=key.sign(first.signing_payload()))
    assert receiver.apply(first).success

    distributor.update("rules:\n  - second\n")
    rollback = replace(
        distributor.broadcast_message(), version=first.version, signature=None
    )
    rollback = replace(rollback, signature=key.sign(rollback.signing_payload()))

    result = receiver.apply(rollback)
    assert not result.success
    assert "version" in result.message.lower() or "rollback" in result.message.lower()
    assert receiver.active_hash == first.expected_hash


def test_sync_sequence_is_covered_by_issuer_signature() -> None:
    key = Ed25519PrivateKey.generate()
    public_key = _public_key(key)
    distributor = ConstitutionDistributor(
        "rules:\n  - first\n", key, issuer_id="owner"
    )
    msg = distributor.broadcast_message()
    signed = replace(msg, signature=key.sign(msg.signing_payload()))

    assert signed.verify_signature({"owner": public_key})
    assert not replace(signed, version=signed.version + 1).verify_signature(
        {"owner": public_key}
    )


@pytest.mark.parametrize(
    ("issued_at_case", "error_fragment"),
    [
        ("nan", "integer"),
        ("infinite", "integer"),
        ("negative", "positive"),
        ("boolean", "integer"),
        ("stale", "stale"),
        ("future", "future"),
    ],
)
def test_sync_rejects_invalid_stale_or_future_issued_at(
    monkeypatch: pytest.MonkeyPatch, issued_at_case: str, error_fragment: str
) -> None:
    fixed_now = 1_000_000_000_000_000
    monkeypatch.setattr(sync_module.time, "time_ns", lambda: fixed_now)
    issued_at = {
        "nan": float("nan"),
        "infinite": float("inf"),
        "negative": -1,
        "boolean": True,
        "stale": fixed_now - 60_000_000_000,
        "future": fixed_now + 60_000_000_000,
    }[issued_at_case]
    key = Ed25519PrivateKey.generate()
    trusted_keys = {"owner": _public_key(key)}
    distributor = ConstitutionDistributor(
        "rules:\n  - first\n", key, issuer_id="owner"
    )
    valid = distributor.broadcast_message()
    msg = object.__new__(ConstitutionSyncMessage)
    for field in ConstitutionSyncMessage.__slots__:
        object.__setattr__(
            msg,
            field,
            issued_at if field == "issued_at" else getattr(valid, field),
        )
    if type(issued_at) is int and issued_at > 0:
        object.__setattr__(msg, "signature", key.sign(msg.signing_payload()))
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys=trusted_keys,
        max_message_age_seconds=10.0,
        max_future_skew_seconds=10.0,
    )

    result = receiver.apply(msg)
    assert not result.success
    assert error_fragment in result.message.lower()
    assert not receiver.is_initialised


def test_governed_concurrent_successors_commit_at_most_one() -> None:
    sync_key = Ed25519PrivateKey.generate()
    distributor = ConstitutionDistributor("rules:\n  - base\n", sync_key)
    current = ConstitutionVersion(0, ("base",))
    old_set, old_keys = _validators(3)
    new_set, new_keys = _validators(3)
    policy = TransitionVerificationPolicy(
        old_certificate=CertificateVerificationPolicy(
            expected_committee_seed="old-seed"
        ),
        new_certificate=CertificateVerificationPolicy(
            expected_committee_seed="new-seed"
        ),
    )
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys={"subnet-owner": _public_key(sync_key)},
        governed_validator_set=old_set,
        governed_policy=policy,
        governed_version=current,
    )
    assert receiver.apply(distributor.broadcast_message()).success

    distributor.update("rules:\n  - base\n  - successor-a\n")
    msg_a = distributor.broadcast_message()
    yaml_b = "rules:\n  - base\n  - successor-b\n"
    msg_b = replace(
        msg_a,
        version_id="successor-b",
        expected_hash=hashlib.sha256(yaml_b.encode()).hexdigest()[:16],
        yaml_content=yaml_b,
        issued_at=msg_a.issued_at + 1,
    )

    def certificate_for(msg, rule: str) -> TransitionCertificate:
        proposed = ConstitutionVersion(1, ("base", rule), current.digest)
        proposal = AmendmentProposal(
            current,
            proposed,
            binding_digest=msg.commitment_digest(),
            old_validator_set_digest=compute_validator_set_digest(old_set),
            new_validator_set_digest=compute_validator_set_digest(new_set),
        )
        assignment_id, artifact_hash, epoch = transition_vote_subject(proposal)

        def qc_for(validator_set, keys, seed):
            committee = CommitteeSelector(validator_set).select(
                seed, len(validator_set)
            )
            votes = [
                _vote(
                    keys[voter_id],
                    voter_id,
                    artifact_hash,
                    assignment_id=assignment_id,
                    epoch=epoch,
                )
                for voter_id in committee.members
            ]
            return build_certificate(
                votes, committee=committee, validator_set=validator_set
            )

        return TransitionCertificate(
            proposal,
            qc_for(old_set, old_keys, "old-seed"),
            qc_for(new_set, new_keys, "new-seed"),
        )

    cert_a = certificate_for(msg_a, "successor-a")
    cert_b = certificate_for(msg_b, "successor-b")
    barrier = threading.Barrier(3)
    results = []

    def apply(msg, certificate) -> None:
        barrier.wait()
        results.append(
            receiver.apply_governed(
                msg,
                certificate=certificate,
                old_validator_set=old_set,
                new_validator_set=new_set,
                current_version=current,
                policy=policy,
            )
        )

    threads = [
        threading.Thread(target=apply, args=(msg_a, cert_a)),
        threading.Thread(target=apply, args=(msg_b, cert_b)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sum(result.success for result in results) == 1
    assert len(receiver.version_history) == 2
    assert receiver.active_epoch == 1


@pytest.mark.parametrize(
    "invalid_yaml",
    [
        "rules: [unterminated",
        "rules:\n  - safety-01\n  - safety-01\n",
    ],
)
def test_invalid_governed_yaml_fails_closed(invalid_yaml: str) -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    original_history = receiver.version_history
    dist.update(invalid_yaml)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )

    result = _sync_apply(receiver, msg, cert, old_set, new_set, prior)

    assert not result.success
    assert "certificate rejected" in result.message.lower()
    assert receiver.version_history == original_history
    assert receiver.active_epoch is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda msg: replace(msg, version_id="tampered-id"),
        lambda msg: replace(msg, version=msg.version + 1),
        lambda msg: replace(msg, issued_at=msg.issued_at + 1),
        lambda msg: replace(msg, issuer_id="tampered-owner"),
        lambda msg: replace(msg, block_height=999),
        lambda msg: replace(msg, description="tampered-description"),
        lambda msg: replace(msg, expected_hash="0" * 16),
        lambda msg: replace(
            msg,
            yaml_content=msg.yaml_content.replace("ctx-v1", "tampered"),
            expected_hash=hashlib.sha256(
                msg.yaml_content.replace("ctx-v1", "tampered").encode()
            ).hexdigest()[:16],
        ),
    ],
)
def test_transition_certificate_binds_complete_sync_message(mutation) -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1, description="governed")
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )

    result = _sync_apply(receiver, mutation(msg), cert, old_set, new_set, prior)

    assert not result.success
    assert receiver.active_epoch is None
    assert receiver.active_yaml == _SYNC_YAML_BOOT


def test_ungoverned_apply_cannot_bypass_governed_mode() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(receiver, msg, cert, old_set, new_set, prior).success

    dist.update(_SYNC_YAML_E2)
    bypass = receiver.apply(dist.broadcast_message())

    assert not bypass.success
    assert "governed" in bypass.message.lower()
    assert receiver.active_epoch == 1
    assert receiver.active_yaml == _SYNC_YAML_E1


@pytest.mark.parametrize("delivery_delay", [301.0, 86_400.0])
def test_governed_sync_accepts_certified_late_delivery(
    monkeypatch: pytest.MonkeyPatch, delivery_delay: float
) -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )
    monkeypatch.setattr(sync_module.time, "time", lambda: msg.issued_at + delivery_delay)

    result = _sync_apply(receiver, msg, cert, old_set, new_set, prior)

    assert result.success
    replay = _sync_apply(receiver, msg, cert, old_set, new_set, proposed)
    assert not replay.success
    assert "replay" in replay.message.lower() or "version" in replay.message.lower()


def test_governed_sync_rejects_certified_content_reversion_at_higher_version() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    first = dist.broadcast_message()
    version1 = _sync_version(1, ("safety-01",), prior.digest)
    cert1 = _sync_certificate(
        prior, version1, first, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(receiver, first, cert1, old_set, new_set, prior).success

    next_set, next_keys = _validators(3)
    dist.update(_SYNC_YAML_BOOT)
    reverted = dist.broadcast_message()
    version2 = _sync_version(2, (), version1.digest)
    cert2 = _sync_certificate(
        version1, version2, reverted, new_set, new_keys, next_set, next_keys
    )

    result = _sync_apply(receiver, reverted, cert2, new_set, next_set, version1)

    assert not result.success
    assert "replay" in result.message.lower() or "downgrade" in result.message.lower()
    assert receiver.active_yaml == _SYNC_YAML_E1
    assert receiver.active_epoch == 1


def test_governed_sync_uses_version_order_when_timestamp_moves_backward() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    first = dist.broadcast_message()
    version1 = _sync_version(1, ("safety-01",), prior.digest)
    cert1 = _sync_certificate(
        prior, version1, first, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(receiver, first, cert1, old_set, new_set, prior).success

    next_set, next_keys = _validators(3)
    dist.update(_SYNC_YAML_E2)
    unsigned_second = replace(
        dist.broadcast_message(),
        issued_at=first.issued_at - 1,
        signature=None,
    )
    second = replace(
        unsigned_second,
        signature=_SYNC_SIGNING_KEY.sign(unsigned_second.signing_payload()),
    )
    version2 = _sync_version(2, ("privacy-01", "safety-01"), version1.digest)
    cert2 = _sync_certificate(
        version1, version2, second, new_set, new_keys, next_set, next_keys
    )

    result = _sync_apply(receiver, second, cert2, new_set, next_set, version1)

    assert result.success
    assert receiver.active_epoch == 2


def test_governed_sync_fails_closed_without_registry_and_policy_anchors() -> None:
    sync_key = Ed25519PrivateKey.generate()
    dist = ConstitutionDistributor(_SYNC_YAML_BOOT, sync_key)
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys={"subnet-owner": _public_key(sync_key)},
    )
    assert receiver.apply(dist.broadcast_message()).success
    prior = _sync_version(0, ())
    old_set, old_keys = _validators(3)
    new_set, new_keys = _validators(3)
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )

    result = _sync_apply(receiver, msg, cert, old_set, new_set, prior)

    assert not result.success
    assert "anchor" in result.message.lower()


def test_governed_sync_rejects_self_consistent_untrusted_initial_lineage() -> None:
    dist, receiver, _prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    forged_prior = _sync_version(41, ())
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    forged_proposed = _sync_version(42, ("safety-01",), forged_prior.digest)
    cert = _sync_certificate(
        forged_prior,
        forged_proposed,
        msg,
        old_set,
        old_keys,
        new_set,
        new_keys,
    )

    result = _sync_apply(
        receiver, msg, cert, old_set, new_set, forged_prior
    )

    assert not result.success
    assert "current version" in result.message.lower()
    assert receiver.active_epoch is None


def test_governed_sync_rejects_first_transition_registry_substitution() -> None:
    dist, receiver, prior, _old_set, _old_keys, _new_set, _new_keys = _sync_setup()
    evil_set, evil_keys = _validator_set("evil-")
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, evil_set, evil_keys, evil_set, evil_keys
    )

    result = _sync_apply(receiver, msg, cert, evil_set, evil_set, prior)

    assert not result.success
    assert "validator" in result.message.lower() or "registry" in result.message.lower()


def test_governed_sync_rejects_later_transition_registry_substitution() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    first = dist.broadcast_message()
    version1 = _sync_version(1, ("safety-01",), prior.digest)
    cert1 = _sync_certificate(
        prior, version1, first, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(receiver, first, cert1, old_set, new_set, prior).success

    evil_set, evil_keys = _validator_set("evil-")
    dist.update(_SYNC_YAML_E2)
    second = dist.broadcast_message()
    version2 = _sync_version(2, ("privacy-01", "safety-01"), version1.digest)
    cert2 = _sync_certificate(
        version1, version2, second, evil_set, evil_keys, evil_set, evil_keys
    )

    result = _sync_apply(receiver, second, cert2, evil_set, evil_set, version1)

    assert not result.success
    assert "validator" in result.message.lower() or "registry" in result.message.lower()


def test_governed_sync_snapshots_constructor_registry() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    attacker = Ed25519PrivateKey.generate()
    old_set.add(
        ValidatorIdentity(
            "injected",
            1.0,
            fault_domain="injected",
            public_key_bytes=_public_key(attacker),
        )
    )
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, {**old_keys, "injected": attacker}, new_set, new_keys
    )

    result = _sync_apply(receiver, msg, cert, old_set, new_set, prior)

    assert not result.success
    assert "validator" in result.message.lower() or "registry" in result.message.lower()


def test_governed_sync_snapshots_successor_registry_before_pinning() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    first = dist.broadcast_message()
    version1 = _sync_version(1, ("safety-01",), prior.digest)
    cert1 = _sync_certificate(
        prior, version1, first, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(receiver, first, cert1, old_set, new_set, prior).success
    new_set.remove(next(iter(new_keys)))

    next_set, next_keys = _validators(3)
    dist.update(_SYNC_YAML_E2)
    second = dist.broadcast_message()
    version2 = _sync_version(2, ("privacy-01", "safety-01"), version1.digest)
    cert2 = _sync_certificate(
        version1, version2, second, new_set, new_keys, next_set, next_keys
    )

    result = _sync_apply(receiver, second, cert2, new_set, next_set, version1)

    assert not result.success
    assert "validator" in result.message.lower() or "registry" in result.message.lower()


def test_governed_sync_rejects_policy_weakening() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )
    weakened = replace(_policy(), max_rule_delta=_policy().max_rule_delta + 1)

    result = _sync_apply(
        receiver, msg, cert, old_set, new_set, prior, policy=weakened
    )

    assert not result.success
    assert "policy" in result.message.lower()


def test_governed_sync_still_rejects_future_timestamp() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    unsigned = replace(
        dist.broadcast_message(),
        issued_at=time.time_ns() + 31_000_000_000,
        signature=None,
    )
    msg = replace(
        unsigned,
        signature=_SYNC_SIGNING_KEY.sign(unsigned.signing_payload()),
    )
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )

    result = _sync_apply(receiver, msg, cert, old_set, new_set, prior)

    assert not result.success
    assert "future" in result.message.lower()


@pytest.mark.parametrize("side", ["old", "new"])
def test_governed_sync_rejects_malformed_qc_signatures_at_construction(
    side: str,
) -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    msg = dist.broadcast_message()
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    cert = _sync_certificate(
        prior, proposed, msg, old_set, old_keys, new_set, new_keys
    )
    qc = cert.old_side_certificate if side == "old" else cert.new_side_certificate
    malformed_vote = replace(qc.votes[0], signature="not-bytes")
    malformed_qc = replace(qc, votes=(malformed_vote, *qc.votes[1:]))
    with pytest.raises(InvalidTransitionError, match="signature must be 64 bytes"):
        replace(
            cert,
            old_side_certificate=(
                malformed_qc if side == "old" else cert.old_side_certificate
            ),
            new_side_certificate=(
                malformed_qc if side == "new" else cert.new_side_certificate
            ),
        )


def test_sync_normalizes_malformed_issuer_signature() -> None:
    key = Ed25519PrivateKey.generate()
    dist = ConstitutionDistributor(_SYNC_YAML_BOOT, key, issuer_id="owner")
    valid = dist.broadcast_message()
    msg = object.__new__(ConstitutionSyncMessage)
    for field in ConstitutionSyncMessage.__slots__:
        object.__setattr__(
            msg,
            field,
            "not-bytes" if field == "signature" else getattr(valid, field),
        )
    receiver = ConstitutionReceiver(
        "validator", trusted_issuer_keys={"owner": _public_key(key)}
    )

    result = receiver.apply(msg)

    assert not result.success
    assert "signature" in result.message.lower()
