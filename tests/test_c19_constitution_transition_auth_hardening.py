"""Security regressions for C19 constitution transition authentication."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    InvalidTransitionError,
    JointQuorumNotMetError,
    TransitionCertificate,
    TransitionVerificationPolicy,
    build_transition_side_certificate,
    compute_transition_threshold,
    compute_validator_set_digest,
    transition_vote_subject,
    verify_transition,
)
from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionDistributor,
    ConstitutionReceiver,
    ConstitutionSyncMessage,
)
from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    SignedVote,
    build_certificate,
    build_vote_message,
)
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    FaultDomainPolicy,
    ValidatorIdentity,
    ValidatorSet,
)
from tests.test_constitution_sync_governed import (
    YAML_BOOT as _SYNC_YAML_BOOT,
    YAML_E1 as _SYNC_YAML_E1,
    _apply as _sync_apply,
    _certificate as _sync_certificate,
    _policy as _sync_policy,
    _setup as _sync_setup,
    _validator_set as _sync_validator_set,
    _version as _sync_version,
)


def _public_key(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _validator_set(
    prefix: str,
    count: int,
) -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey]]:
    keys = {f"{prefix}{index}": Ed25519PrivateKey.generate() for index in range(count)}
    validators = ValidatorSet(
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
    return validators, keys


def _validator_set_with_reused_key(
    prefix: str,
    count: int = 4,
) -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey]]:
    keys = {f"{prefix}{index}": Ed25519PrivateKey.generate() for index in range(count)}
    identities = []
    for index, (agent_id, key) in enumerate(keys.items()):
        public_key = _public_key(keys[f"{prefix}0"] if index == 1 else key)
        identities.append(
            ValidatorIdentity(
                agent_id,
                1.0,
                fault_domain=agent_id,
                public_key_bytes=public_key,
            )
        )
    return ValidatorSet(identities, policy=FaultDomainPolicy(max_fraction=1.0)), keys


def _proposal(
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    *,
    drift_budget: DriftBudget = DriftBudget(),
) -> AmendmentProposal:
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-0", "rule-1"), prior.digest)
    return AmendmentProposal(
        prior=prior,
        proposed=proposed,
        drift_budget=drift_budget,
        old_validator_set_digest=compute_validator_set_digest(old_set),
        new_validator_set_digest=compute_validator_set_digest(new_set),
    )


def _certificate(
    proposal: AmendmentProposal,
    validator_set: ValidatorSet,
    keys: dict[str, Ed25519PrivateKey],
    *,
    seed: str,
    committee_size: int,
) -> TransitionCertificate:
    committee = CommitteeSelector(validator_set).select(seed, committee_size)
    assignment_id, artifact_hash, epoch = transition_vote_subject(proposal)
    message = build_vote_message(assignment_id, artifact_hash, epoch)
    votes = tuple(
        SignedVote(
            voter_id=voter_id,
            assignment_id=assignment_id,
            artifact_hash=artifact_hash,
            epoch=epoch,
            signature=keys[voter_id].sign(message),
            public_key_bytes=_public_key(keys[voter_id]),
        )
        for voter_id in committee.members
    )
    qc = build_transition_side_certificate(
        build_certificate(votes, committee=committee, validator_set=validator_set),
        validator_set=validator_set,
        threshold_fraction=2 / 3,
    )
    return TransitionCertificate(proposal, qc, qc)


def _policy(*, committee_size: int | None = None, max_rule_delta: int = 16):
    certificate_policy = CertificateVerificationPolicy(
        committee_size=committee_size,
        expected_committee_seed="seed",
    )
    return TransitionVerificationPolicy(
        old_certificate=certificate_policy,
        new_certificate=certificate_policy,
        max_rule_delta=max_rule_delta,
    )


# Epoch transition authentication regressions.


def test_rejects_unpinned_drift_budget() -> None:
    validator_set, keys = _validator_set("v", 3)
    proposal = _proposal(
        validator_set,
        validator_set,
        drift_budget=DriftBudget(max_rule_delta=17),
    )
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )

    with pytest.raises(InvalidTransitionError, match="drift budget"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(max_rule_delta=16),
        )


def test_rejects_changed_signed_budget() -> None:
    validator_set, keys = _validator_set("v", 3)
    signed_proposal = _proposal(
        validator_set,
        validator_set,
        drift_budget=DriftBudget(max_rule_delta=16),
    )
    signed_certificate = _certificate(
        signed_proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )
    changed_proposal = replace(
        signed_proposal,
        drift_budget=DriftBudget(max_rule_delta=17),
    )

    with pytest.raises(InvalidTransitionError, match="subject mismatch"):
        verify_transition(
            replace(signed_certificate, proposal=changed_proposal),
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=signed_proposal.prior,
            policy=_policy(max_rule_delta=17),
        )


def test_rejects_unpinned_threshold() -> None:
    validator_set, keys = _validator_set("v", 3)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )
    unpinned = replace(
        certificate,
        old_side_certificate=replace(
            certificate.old_side_certificate,
            threshold_weight=1.0,
        ),
    )

    with pytest.raises(InvalidTransitionError, match="threshold"):
        verify_transition(
            unpinned,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(),
        )


def test_rejects_insufficient_full_side_quorum() -> None:
    validator_set, keys = _validator_set("v", 4)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )
    full_side_threshold = 3.0
    certificate = replace(
        certificate,
        old_side_certificate=replace(
            certificate.old_side_certificate,
            votes=certificate.old_side_certificate.votes[:2],
            threshold_weight=full_side_threshold,
            achieved_weight=2.0,
        ),
        new_side_certificate=replace(
            certificate.new_side_certificate,
            votes=certificate.new_side_certificate.votes[:2],
            threshold_weight=full_side_threshold,
            achieved_weight=2.0,
        ),
    )

    with pytest.raises(JointQuorumNotMetError, match="full-side"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(committee_size=3),
        )


def test_rejects_spoofed_transition_certificate() -> None:
    validator_set, _ = _validator_set("v", 3)

    with pytest.raises(InvalidTransitionError, match="certificate"):
        verify_transition(
            object(),  # type: ignore[arg-type]
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=ConstitutionVersion(0, ("rule-0",)),
            policy=_policy(),
        )


def test_rejects_spoofed_nested_transition_record() -> None:
    validator_set, keys = _validator_set("v", 3)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )
    object.__setattr__(certificate, "proposal", object())

    with pytest.raises(InvalidTransitionError, match="proposal"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(),
        )


def test_rejects_malformed_nested_transition_fields() -> None:
    validator_set, keys = _validator_set("v", 3)
    prior = ConstitutionVersion(0, ("rule-0",))
    proposed = ConstitutionVersion(1, ("rule-a", "rule-b"), prior.digest)
    object.__setattr__(proposed, "rules", ("rule-b", "rule-a"))

    with pytest.raises(InvalidTransitionError, match="proposed"):
        proposal = AmendmentProposal(
            prior=prior,
            proposed=proposed,
            old_validator_set_digest=compute_validator_set_digest(validator_set),
            new_validator_set_digest=compute_validator_set_digest(validator_set),
        )
        certificate = _certificate(
            proposal,
            validator_set,
            keys,
            seed="seed",
            committee_size=3,
        )
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(),
        )


def test_rejects_malformed_nested_verifier_policy() -> None:
    validator_set, keys = _validator_set("v", 3)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )
    policy = _policy()
    object.__setattr__(policy.old_certificate, "threshold_fraction", 1 / 3)
    certificate = replace(
        certificate,
        old_side_certificate=replace(
            certificate.old_side_certificate,
            votes=certificate.old_side_certificate.votes[:1],
            threshold_weight=1.0,
            achieved_weight=1.0,
        ),
        new_side_certificate=replace(
            certificate.new_side_certificate,
            votes=certificate.new_side_certificate.votes[:1],
            threshold_weight=1.0,
            achieved_weight=1.0,
        ),
    )

    with pytest.raises(InvalidTransitionError, match="old_certificate"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=policy,
        )


def test_rejects_spoofed_validator_registry() -> None:
    validator_set, keys = _validator_set("v", 3)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )

    class RegistryLookalike(ValidatorSet):
        pass

    spoofed = RegistryLookalike(validator_set.snapshot(), policy=validator_set.policy)
    with pytest.raises(InvalidTransitionError, match="concrete ValidatorSet"):
        verify_transition(
            certificate,
            old_validator_set=spoofed,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(),
        )


@pytest.mark.parametrize("reused_side", ["old", "new"])
def test_rejects_reused_validator_key_on_each_transition_side(
    reused_side: str,
) -> None:
    validator_set, keys = _validator_set("v", 4)
    reused_set, _ = _validator_set_with_reused_key("v")
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )

    old_set = reused_set if reused_side == "old" else validator_set
    new_set = reused_set if reused_side == "new" else validator_set
    with pytest.raises(
        InvalidTransitionError,
        match="^validator registry reuses a public key$",
    ):
        verify_transition(
            certificate,
            old_validator_set=old_set,
            new_validator_set=new_set,
            current_version=proposal.prior,
            policy=_policy(committee_size=3),
        )


def test_rejects_reused_validator_key_at_threshold_boundary() -> None:
    validator_set, _ = _validator_set_with_reused_key("v")

    with pytest.raises(
        InvalidTransitionError,
        match="^validator registry reuses a public key$",
    ):
        compute_transition_threshold(validator_set, 2 / 3)


def test_rejects_reused_validator_key_in_receiver_anchor() -> None:
    validator_set, _ = _validator_set_with_reused_key("v")

    with pytest.raises(
        InvalidTransitionError,
        match="^validator registry reuses a public key$",
    ):
        ConstitutionReceiver(
            "validator",
            governed_validator_set=validator_set,
            governed_policy=_policy(committee_size=3),
            governed_version=ConstitutionVersion(0, ("rule-0",)),
        )


def test_rejects_transition_policy_that_cannot_reach_raw_threshold() -> None:
    validator_set, keys = _validator_set("v", 5)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )

    with pytest.raises(InvalidTransitionError, match="policy can never ratify"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(committee_size=3),
        )


def test_rejects_transition_policy_with_insufficient_effective_capacity() -> None:
    keys = {f"v{index}": Ed25519PrivateKey.generate() for index in range(3)}
    validator_set = ValidatorSet(
        (
            ValidatorIdentity(
                agent_id,
                1.0,
                reputation=0.5,
                fault_domain=agent_id,
                public_key_bytes=_public_key(key),
            )
            for agent_id, key in keys.items()
        ),
        policy=FaultDomainPolicy(max_fraction=1.0),
    )
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=3,
    )

    with pytest.raises(InvalidTransitionError, match="policy can never ratify"):
        verify_transition(
            certificate,
            old_validator_set=validator_set,
            new_validator_set=validator_set,
            current_version=proposal.prior,
            policy=_policy(committee_size=3),
        )


@pytest.mark.parametrize(("validator_count", "committee_size"), [(4, 3), (6, 4)])
def test_accepts_transition_policy_with_sufficient_committee_capacity(
    validator_count: int,
    committee_size: int,
) -> None:
    validator_set, keys = _validator_set("v", validator_count)
    proposal = _proposal(validator_set, validator_set)
    certificate = _certificate(
        proposal,
        validator_set,
        keys,
        seed="seed",
        committee_size=committee_size,
    )

    verify_transition(
        certificate,
        old_validator_set=validator_set,
        new_validator_set=validator_set,
        current_version=proposal.prior,
        policy=_policy(committee_size=committee_size),
    )


# Constitution sync authentication regressions.


def test_rejects_legacy_wire_message_without_opt_in() -> None:
    yaml_content = "rules:\n  - safety-01\n"
    legacy_message = {
        "version_id": "legacy-v1",
        "version": 1,
        "expected_hash": hashlib.sha256(yaml_content.encode()).hexdigest()[:16],
        "yaml_content": yaml_content,
        "issued_at": time.time(),
        "issuer_id": "owner",
        "block_height": None,
        "description": "legacy",
        "signature": None,
    }

    with pytest.raises(ValueError, match="legacy|wire version"):
        ConstitutionSyncMessage.from_dict(legacy_message)


def test_rejects_non_integer_v2_timestamp() -> None:
    yaml_content = "rules:\n  - safety-01\n"
    digest = hashlib.sha256(yaml_content.encode()).digest()
    malformed_message = {
        "wire_version": 2,
        "version_id": "v2",
        "version": 1,
        "expected_hash": digest.hex()[:16],
        "content_digest": digest.hex(),
        "yaml_content": yaml_content,
        "issued_at": time.time(),
        "issuer_id": "owner",
        "block_height": None,
        "description": "malformed timestamp",
        "signature": None,
    }

    with pytest.raises((TypeError, ValueError), match="issued_at|integer"):
        ConstitutionSyncMessage.from_dict(malformed_message)


def test_rejects_empty_v2_content_digest() -> None:
    yaml_content = "rules:\n  - safety-01\n"
    malformed_message = {
        "wire_version": 2,
        "version_id": "v2",
        "version": 1,
        "expected_hash": hashlib.sha256(yaml_content.encode()).hexdigest()[:16],
        "content_digest": "",
        "yaml_content": yaml_content,
        "issued_at": time.time_ns(),
        "issuer_id": "owner",
        "block_height": None,
        "description": "missing digest",
        "signature": None,
    }

    with pytest.raises(ValueError, match="content_digest"):
        ConstitutionSyncMessage.from_dict(malformed_message)


def test_rejects_spoofed_sync_message() -> None:
    yaml_content = "rules:\n  - safety-01\n"
    digest = hashlib.sha256(yaml_content.encode()).hexdigest()[:16]

    class SpoofedMessage:
        def __init__(self) -> None:
            self.version_id = "spoofed"
            self.version = 1
            self.expected_hash = digest
            self.yaml_content = yaml_content
            self.issued_at = time.time()
            self.issuer_id = "owner"
            self.block_height = None
            self.description = "spoofed"

        @staticmethod
        def verify() -> bool:
            return True

        @staticmethod
        def verify_signature(_trusted_keys: dict[str, bytes]) -> bool:
            return True

    receiver = ConstitutionReceiver("validator")

    result = receiver.apply(SpoofedMessage())  # type: ignore[arg-type]

    assert not result.success
    assert "message" in result.message.lower() or "type" in result.message.lower()
    assert not receiver.is_initialised


@pytest.mark.parametrize(
    "spoofed_anchor",
    ["validator_set", "policy", "version"],
)
def test_rejects_spoofed_governed_anchor(spoofed_anchor: str) -> None:
    validator_set, _ = _validator_set("anchor-", 3)
    version = ConstitutionVersion(0, ())
    policy = _policy()
    anchors: dict[str, object] = {
        "governed_validator_set": validator_set,
        "governed_policy": policy,
        "governed_version": version,
    }
    anchors[f"governed_{spoofed_anchor}"] = object()

    with pytest.raises(ValueError, match="governed"):
        ConstitutionReceiver("validator", **anchors)  # type: ignore[arg-type]


def test_rejects_historical_content_in_governed_transition() -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    first = dist.broadcast_message()
    version1 = _sync_version(1, ("safety-01",), prior.digest)
    certificate1 = _sync_certificate(
        prior, version1, first, old_set, old_keys, new_set, new_keys
    )
    assert _sync_apply(
        receiver, first, certificate1, old_set, new_set, prior
    ).success

    next_set, next_keys = _sync_validator_set("next-")
    dist.update(_SYNC_YAML_BOOT)
    historical = dist.broadcast_message()
    version2 = _sync_version(2, (), version1.digest)
    certificate2 = _sync_certificate(
        version1,
        version2,
        historical,
        new_set,
        new_keys,
        next_set,
        next_keys,
    )

    result = _sync_apply(
        receiver, historical, certificate2, new_set, next_set, version1
    )

    assert not result.success
    assert "replay" in result.message.lower() or "downgrade" in result.message.lower()
    assert receiver.active_yaml == _SYNC_YAML_E1


def test_rejects_unsigned_distributor_message() -> None:
    key = Ed25519PrivateKey.generate()
    distributor = ConstitutionDistributor(_SYNC_YAML_BOOT, key, issuer_id="owner")
    unsigned = replace(distributor.broadcast_message(), signature=None)
    receiver = ConstitutionReceiver(
        "validator", trusted_issuer_keys={"owner": _public_key(key)}
    )

    result = receiver.apply(unsigned)

    assert not result.success
    assert "signature" in result.message.lower()


@pytest.mark.parametrize("invalid_issuer", ["unsigned", "wrong-key", "unknown"])
def test_rejects_unauthenticated_governed_message(invalid_issuer: str) -> None:
    dist, receiver, prior, old_set, old_keys, new_set, new_keys = _sync_setup()
    dist.update(_SYNC_YAML_E1)
    signed = dist.broadcast_message()
    attacker = Ed25519PrivateKey.generate()
    if invalid_issuer == "unsigned":
        message = replace(signed, signature=None)
    elif invalid_issuer == "wrong-key":
        message = replace(signed, signature=attacker.sign(signed.signing_payload()))
    else:
        unsigned = replace(signed, issuer_id="unknown-owner", signature=None)
        message = replace(
            unsigned,
            signature=attacker.sign(unsigned.signing_payload()),
        )
    proposed = _sync_version(1, ("safety-01",), prior.digest)
    certificate = _sync_certificate(
        prior,
        proposed,
        message,
        old_set,
        old_keys,
        new_set,
        new_keys,
    )

    result = _sync_apply(
        receiver,
        message,
        certificate,
        old_set,
        new_set,
        prior,
    )

    assert not result.success
    assert "signature" in result.message.lower() or "issuer" in result.message.lower()
    assert receiver.active_yaml == _SYNC_YAML_BOOT
    assert receiver.active_epoch is None


def test_rejects_replay_per_issuer_without_cross_issuer_collision() -> None:
    first_key = Ed25519PrivateKey.generate()
    second_key = Ed25519PrivateKey.generate()
    first_distributor = ConstitutionDistributor(
        _SYNC_YAML_BOOT, first_key, issuer_id="first-owner"
    )
    second_distributor = ConstitutionDistributor(
        _SYNC_YAML_E1, second_key, issuer_id="second-owner"
    )
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys={
            "first-owner": _public_key(first_key),
            "second-owner": _public_key(second_key),
        },
    )
    first = first_distributor.broadcast_message()
    second = second_distributor.broadcast_message()

    assert receiver.apply(first).success
    assert receiver.apply(second).success
    replay = receiver.apply(first)

    assert not replay.success
    assert "replay" in replay.message.lower() or "downgrade" in replay.message.lower()


def test_rejects_legacy_wire_message_without_receiver_opt_in() -> None:
    key = Ed25519PrivateKey.generate()
    issued_at = time.time()
    legacy = ConstitutionSyncMessage(
        version_id="legacy-v1",
        version=1,
        expected_hash=hashlib.sha256(_SYNC_YAML_BOOT.encode()).hexdigest()[:16],
        yaml_content=_SYNC_YAML_BOOT,
        issued_at=issued_at,
        issuer_id="owner",
        wire_version=1,
    )
    signed = replace(legacy, signature=key.sign(legacy.signing_payload()))
    parsed = ConstitutionSyncMessage.from_dict(
        signed.to_dict(), allow_legacy_v1=True
    )
    receiver = ConstitutionReceiver(
        "validator", trusted_issuer_keys={"owner": _public_key(key)}
    )

    result = receiver.apply(parsed)

    assert not result.success
    assert "legacy" in result.message.lower()


def test_rejects_legacy_timestamp_outside_nanosecond_range() -> None:
    key = Ed25519PrivateKey.generate()
    legacy = ConstitutionSyncMessage(
        version_id="legacy-large-time",
        version=1,
        expected_hash=hashlib.sha256(_SYNC_YAML_BOOT.encode()).hexdigest()[:16],
        yaml_content=_SYNC_YAML_BOOT,
        issued_at=time.time(),
        issuer_id="owner",
        wire_version=1,
    )
    object.__setattr__(legacy, "issued_at", 1e308)
    object.__setattr__(legacy, "signature", key.sign(legacy.signing_payload()))
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys={"owner": _public_key(key)},
        allow_legacy_v1=True,
    )

    result = receiver.apply(legacy)

    assert not result.success
    assert "issued_at" in result.message.lower()


@pytest.mark.parametrize(
    "seconds",
    [1e308, 10**10_000],
    ids=["large-float", "large-int"],
)
def test_rejects_sync_time_limit_outside_nanosecond_range(
    seconds: int | float,
) -> None:
    with pytest.raises(ValueError, match="max_future_skew_seconds"):
        ConstitutionReceiver(
            "validator",
            max_future_skew_seconds=seconds,
        )


def test_rejects_short_task_constitution_digest() -> None:
    distributor, receiver, *_ = _sync_setup()

    assert not receiver.verify_task_hash(distributor.active_hash)


@pytest.mark.parametrize("certificate", [object(), None], ids=["object", "none"])
def test_governed_apply_returns_failure_for_invalid_certificate(
    certificate: object,
) -> None:
    distributor, receiver, prior, old_set, _, new_set, _ = _sync_setup()
    distributor.update(_SYNC_YAML_E1)
    message = distributor.broadcast_message()
    active_yaml = receiver.active_yaml

    result = receiver.apply_governed(
        message,
        certificate=certificate,  # type: ignore[arg-type]
        old_validator_set=old_set,
        new_validator_set=new_set,
        current_version=prior,
        policy=_sync_policy(),
    )

    assert not result.success
    assert "certificate" in result.message.lower()
    assert receiver.active_yaml == active_yaml
    assert receiver.active_epoch is None


def test_receiver_documents_replay_state_durability() -> None:
    doc = ConstitutionReceiver.__doc__ or ""

    assert "in memory" in doc
    assert "lost on restart" in doc
    assert "constructor anchors" in doc
    assert "persist" in doc
    assert "high-water" in doc


def test_receiver_exposes_only_authenticated_apply_path() -> None:
    key = Ed25519PrivateKey.generate()
    distributor = ConstitutionDistributor(_SYNC_YAML_BOOT, key, issuer_id="owner")
    receiver = ConstitutionReceiver(
        "validator",
        trusted_issuer_keys={"owner": _public_key(key)},
    )

    assert not hasattr(receiver, "_apply_verified")
    assert receiver.apply(distributor.broadcast_message()).success
