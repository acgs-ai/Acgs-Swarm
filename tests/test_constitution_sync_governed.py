"""Governed constitution sync integration tests."""

from __future__ import annotations

from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionDistributor,
    ConstitutionReceiver,
    ConstitutionSyncMessage,
)
from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    TransitionCertificate,
    TransitionVerificationPolicy,
    build_transition_side_certificate,
    compute_validator_set_digest,
    transition_vote_subject,
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

YAML_BOOT = "name: boot\nrules: []\n"
YAML_E1 = "name: ctx-v1\nrules:\n  - safety-01\n"
YAML_E2 = "name: ctx-v2\nrules:\n  - privacy-01\n  - safety-01\n"
_SYNC_SIGNING_KEY = Ed25519PrivateKey.generate()
_SYNC_TRUSTED_KEYS = {
    "subnet-owner": _SYNC_SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
}


def _version(
    epoch: int, rules: tuple[str, ...], parent: bytes = b""
) -> ConstitutionVersion:
    return ConstitutionVersion(epoch, tuple(sorted(rules)), parent)


def _validator_set(
    prefix: str,
) -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey]]:
    keys = {f"{prefix}{index}": Ed25519PrivateKey.generate() for index in range(3)}
    validators = ValidatorSet(
        (
            ValidatorIdentity(
                voter_id,
                1.0,
                fault_domain=voter_id,
                public_key_bytes=key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ),
            )
            for voter_id, key in keys.items()
        ),
        policy=FaultDomainPolicy(max_fraction=1.0),
    )
    return validators, keys


def _qc(
    proposal: AmendmentProposal,
    validators: ValidatorSet,
    keys: dict[str, Ed25519PrivateKey],
    seed: str,
):
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
    return build_certificate(votes, committee=committee, validator_set=validators)


def _certificate(
    prior: ConstitutionVersion,
    proposed: ConstitutionVersion,
    msg: ConstitutionSyncMessage,
    old_validators: ValidatorSet,
    old_keys: dict[str, Ed25519PrivateKey],
    new_validators: ValidatorSet,
    new_keys: dict[str, Ed25519PrivateKey],
    *,
    drift_budget: DriftBudget = DriftBudget(),
) -> TransitionCertificate:
    proposal = AmendmentProposal(
        prior,
        proposed,
        drift_budget=drift_budget,
        binding_digest=msg.commitment_digest(),
        old_validator_set_digest=compute_validator_set_digest(old_validators),
        new_validator_set_digest=compute_validator_set_digest(new_validators),
    )
    return TransitionCertificate(
        proposal,
        build_transition_side_certificate(
            _qc(proposal, old_validators, old_keys, "old-seed"),
            validator_set=old_validators,
            threshold_fraction=_policy().old_certificate.threshold_fraction,
        ),
        build_transition_side_certificate(
            _qc(proposal, new_validators, new_keys, "new-seed"),
            validator_set=new_validators,
            threshold_fraction=_policy().new_certificate.threshold_fraction,
        ),
    )


def _policy(*, max_rule_delta: int = 16) -> TransitionVerificationPolicy:
    return TransitionVerificationPolicy(
        old_certificate=CertificateVerificationPolicy(
            expected_committee_seed="old-seed"
        ),
        new_certificate=CertificateVerificationPolicy(
            expected_committee_seed="new-seed"
        ),
        max_rule_delta=max_rule_delta,
    )


def _apply(
    receiver: ConstitutionReceiver,
    msg: ConstitutionSyncMessage,
    certificate: TransitionCertificate,
    old_validators: ValidatorSet,
    new_validators: ValidatorSet,
    current_version: ConstitutionVersion,
    *,
    policy: TransitionVerificationPolicy | None = None,
):
    return receiver.apply_governed(
        msg,
        certificate=certificate,
        old_validator_set=old_validators,
        new_validator_set=new_validators,
        current_version=current_version,
        policy=policy or _policy(),
    )


def _setup(*, policy: TransitionVerificationPolicy | None = None):
    distributor = ConstitutionDistributor(YAML_BOOT, _SYNC_SIGNING_KEY)
    prior = _version(0, ())
    old_validators, old_keys = _validator_set("old-")
    new_validators, new_keys = _validator_set("new-")
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys=_SYNC_TRUSTED_KEYS,
        governed_validator_set=old_validators,
        governed_policy=policy or _policy(),
        governed_version=prior,
    )
    assert receiver.apply(distributor.broadcast_message()).success
    return (
        distributor,
        receiver,
        prior,
        old_validators,
        old_keys,
        new_validators,
        new_keys,
    )


def test_successful_governed_update_pins_full_current_version() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)

    result = _apply(receiver, msg, cert, old_set, new_set, prior)

    assert result.success
    assert receiver.active_epoch == 1
    assert receiver.active_hash == msg.expected_hash


def test_second_governed_update_uses_pinned_predecessor() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    first = dist.broadcast_message()
    version1 = _version(1, ("safety-01",), prior.digest)
    cert1 = _certificate(prior, version1, first, old_set, old_keys, new_set, new_keys)
    assert _apply(receiver, first, cert1, old_set, new_set, prior).success

    next_set, next_keys = _validator_set("next-")
    dist.update(YAML_E2)
    second = dist.broadcast_message()
    version2 = _version(2, ("privacy-01", "safety-01"), version1.digest)
    cert2 = _certificate(
        version1, version2, second, new_set, new_keys, next_set, next_keys
    )

    result = _apply(receiver, second, cert2, new_set, next_set, version1)
    assert result.success
    assert receiver.active_epoch == 2


def test_bootstrap_rejects_untrusted_current_version() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)
    untrusted = _version(41, ())

    result = _apply(receiver, msg, cert, old_set, new_set, untrusted)

    assert not result.success
    assert receiver.active_epoch is None
    assert receiver.active_yaml == YAML_BOOT


def test_verifier_policy_rejects_artifact_drift_override() -> None:
    policy = _policy(max_rule_delta=2)
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup(
        policy=policy
    )
    changed = "name: large\nrules:\n  - a\n  - b\n  - c\n"
    dist.update(changed)
    msg = dist.broadcast_message()
    proposed = _version(1, ("a", "b", "c"), prior.digest)
    cert = _certificate(
        prior,
        proposed,
        msg,
        old_set,
        old_keys,
        new_set,
        new_keys,
        drift_budget=DriftBudget(10_000),
    )

    result = _apply(
        receiver, msg, cert, old_set, new_set, prior, policy=policy
    )

    assert not result.success
    assert "drift" in result.message.lower()
    assert receiver.active_epoch is None


def test_rejects_incomplete_joint_quorum() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)
    cert = replace(
        cert,
        old_side_certificate=replace(
            cert.old_side_certificate,
            votes=cert.old_side_certificate.votes[:1],
        ),
    )

    result = _apply(receiver, msg, cert, old_set, new_set, prior)

    assert not result.success
    assert "certificate rejected" in result.message.lower()
    assert receiver.active_epoch is None


def test_rejects_stale_epoch_certificate() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    first = dist.broadcast_message()
    version1 = _version(1, ("safety-01",), prior.digest)
    cert1 = _certificate(prior, version1, first, old_set, old_keys, new_set, new_keys)
    assert _apply(receiver, first, cert1, old_set, new_set, prior).success

    state_before = (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    )
    dist.update(YAML_E2)
    fresh_message = dist.broadcast_message()
    next_set, next_keys = _validator_set("next-")
    stale_cert = _certificate(
        prior,
        version1,
        fresh_message,
        new_set,
        new_keys,
        next_set,
        next_keys,
    )

    result = _apply(receiver, fresh_message, stale_cert, new_set, next_set, version1)

    assert not result.success
    assert "current version" in result.message.lower()
    assert (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    ) == state_before


def test_rejects_unknown_signers() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)
    attacker = Ed25519PrivateKey.generate()
    original_vote = cert.old_side_certificate.votes[0]
    forged_vote = replace(
        original_vote,
        signature=attacker.sign(original_vote.message()),
        public_key_bytes=attacker.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
    )
    forged_cert = replace(
        cert,
        old_side_certificate=replace(
            cert.old_side_certificate,
            votes=(forged_vote, *cert.old_side_certificate.votes[1:]),
        ),
    )

    result = _apply(receiver, msg, forged_cert, old_set, new_set, prior)

    assert not result.success
    assert "certificate rejected" in result.message.lower()
    assert receiver.active_epoch is None
    assert receiver.active_yaml == YAML_BOOT


def test_failed_cert_leaves_state_untouched() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    initial_state = (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    )
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)
    failed_cert = replace(
        cert,
        new_side_certificate=replace(
            cert.new_side_certificate,
            votes=cert.new_side_certificate.votes[:1],
        ),
    )

    result = _apply(receiver, msg, failed_cert, old_set, new_set, prior)

    assert not result.success
    assert (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    ) == initial_state


def test_hash_mismatch_after_valid_cert_still_rejects() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    initial_state = (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    )
    dist.update(YAML_E1)
    legitimate = dist.broadcast_message()
    mismatched = replace(legitimate, expected_hash="0" * 16)
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(
        prior, proposed, mismatched, old_set, old_keys, new_set, new_keys
    )

    result = _apply(receiver, mismatched, cert, old_set, new_set, prior)

    assert not result.success
    assert "hash mismatch" in result.message.lower()
    assert (
        receiver.active_hash,
        receiver.active_epoch,
        receiver.version_history,
    ) == initial_state


def test_summary_includes_active_epoch() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _setup()
    assert receiver.summary()["active_epoch"] is None
    dist.update(YAML_E1)
    msg = dist.broadcast_message()
    proposed = _version(1, ("safety-01",), prior.digest)
    cert = _certificate(prior, proposed, msg, old_set, old_keys, new_set, new_keys)

    assert _apply(receiver, msg, cert, old_set, new_set, prior).success
    assert receiver.summary()["active_epoch"] == 1


def test_legacy_apply_does_not_set_governed_epoch() -> None:
    dist = ConstitutionDistributor(YAML_E1, _SYNC_SIGNING_KEY)
    receiver = ConstitutionReceiver(
        "validator", trusted_issuer_keys=_SYNC_TRUSTED_KEYS
    )
    assert receiver.apply(dist.broadcast_message()).success
    assert receiver.active_epoch is None
