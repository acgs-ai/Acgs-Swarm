"""C20 regression tests: validator set and quorum certificate hardening.

Each test feeds invalid or adversarial input and expects rejection:

- qc-2: a vote signature must bind the voter identity (vote message v2), so a
  signature from a key shared by two registered ids cannot be relabelled; v1
  messages are only accepted when the *verifier* opts in.
- validator-1: opt-in enforcement of the per-domain raw share bound.
- validator-2: ``ValidatorSet.add`` never silently replaces an identity or
  re-keys a validator.
- validator-3: VRF and retry-seed inputs are length-framed; NUL ids rejected.
"""

from __future__ import annotations

import inspect

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import constitutional_swarm.quorum_certificate as qcm
from constitutional_swarm.quorum_certificate import (
    CertificateVerificationPolicy,
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    build_certificate,
    build_vote_message,
    verify_certificate,
)
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    FaultDomainPolicy,
    ValidatorIdentity,
    ValidatorSet,
)

ASSIGNMENT = "assignment-c20"
ARTIFACT = "artifact-c20"
EPOCH = 3


def _pk(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _v2_vote(key: Ed25519PrivateKey, voter_id: str, *, signer_id: str | None = None) -> SignedVote:
    message = qcm.build_vote_message_v2(ASSIGNMENT, ARTIFACT, EPOCH, signer_id or voter_id)
    return SignedVote(voter_id, ASSIGNMENT, ARTIFACT, EPOCH, key.sign(message), _pk(key))


def _v1_vote(key: Ed25519PrivateKey, voter_id: str) -> SignedVote:
    message = build_vote_message(ASSIGNMENT, ARTIFACT, EPOCH)
    return SignedVote(voter_id, ASSIGNMENT, ARTIFACT, EPOCH, key.sign(message), _pk(key))


def _keyed_set(
    ids: list[str],
    *,
    shared: dict[str, str] | None = None,
    domains: dict[str, str] | None = None,
    max_fraction: float = 1.0,
) -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey]]:
    keys: dict[str, Ed25519PrivateKey] = {}
    for agent_id in ids:
        source = (shared or {}).get(agent_id)
        keys[agent_id] = keys[source] if source else Ed25519PrivateKey.generate()
    validators = ValidatorSet(
        (
            ValidatorIdentity(
                agent_id,
                1.0,
                fault_domain=(domains or {}).get(agent_id, f"org:{agent_id}"),
                public_key_bytes=_pk(keys[agent_id]),
            )
            for agent_id in ids
        ),
        policy=FaultDomainPolicy(max_fraction=max_fraction),
    )
    return validators, keys


# ---------------------------------------------------------------------------
# qc-2: voter identity is bound into the signed vote message
# ---------------------------------------------------------------------------


def test_signature_relabelled_to_other_id_sharing_the_key_is_rejected() -> None:
    """P1: the vote names voter "b" but the signature binds "a"; reject."""
    ids = ["a", "b", "c", "d"]
    validators, keys = _keyed_set(ids, shared={"b": "a"})
    committee = CommitteeSelector(validators).select("seed", len(ids))
    votes = [_v2_vote(keys[i], i) for i in ("a", "c", "d")]
    votes.append(_v2_vote(keys["b"], "b", signer_id="a"))

    with pytest.raises(InvalidCertificateError, match="'b'"):
        build_certificate(votes, committee=committee, validator_set=validators)


def test_v1_signed_votes_are_rejected_unless_verifier_opts_in() -> None:
    ids = ["a", "b", "c"]
    validators, keys = _keyed_set(ids)
    committee = CommitteeSelector(validators).select("seed", len(ids))
    votes = [_v1_vote(keys[i], i) for i in ids]

    with pytest.raises(InvalidCertificateError, match="signature"):
        build_certificate(votes, committee=committee, validator_set=validators)

    legacy = CertificateVerificationPolicy(
        committee_size=len(ids),
        expected_committee_seed="seed",
        allow_legacy_v1=True,
    )
    qc = build_certificate(
        votes,
        committee=committee,
        validator_set=validators,
        verification_policy=legacy,
    )
    # A serialized v1 certificate stays readable, but only verifies when the
    # verifier (not the certificate) allows the legacy format.
    restored = QuorumCertificate.from_dict(qc.to_dict())
    with pytest.raises(InvalidCertificateError, match="signature"):
        verify_certificate(restored, validator_set=validators)
    verify_certificate(
        restored,
        validator_set=validators,
        policy=CertificateVerificationPolicy(allow_legacy_v1=True),
    )


def test_v2_votes_verify_and_bind_every_subject_field() -> None:
    base = qcm.build_vote_message_v2(ASSIGNMENT, ARTIFACT, EPOCH, "a")
    assert base != qcm.build_vote_message_v2(ASSIGNMENT, ARTIFACT, EPOCH, "b")
    assert base != qcm.build_vote_message_v2(ASSIGNMENT, ARTIFACT, EPOCH + 1, "a")
    assert base != build_vote_message(ASSIGNMENT, ARTIFACT, EPOCH)

    ids = ["a", "b", "c"]
    validators, keys = _keyed_set(ids)
    committee = CommitteeSelector(validators).select("seed", len(ids))
    qc = build_certificate(
        [_v2_vote(keys[i], i) for i in ids], committee=committee, validator_set=validators
    )
    verify_certificate(QuorumCertificate.from_dict(qc.to_dict()), validator_set=validators)
    assert all(vote.verify() for vote in qc.votes)


def test_legacy_policy_flag_must_be_a_bool() -> None:
    with pytest.raises(ValueError, match="allow_legacy_v1"):
        CertificateVerificationPolicy(allow_legacy_v1=1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# validator-1: opt-in raw domain-share enforcement
# ---------------------------------------------------------------------------


def _concentrated_set() -> tuple[ValidatorSet, dict[str, Ed25519PrivateKey], list[str]]:
    ids = [f"evil{i}" for i in range(6)] + [f"honest{i}" for i in range(4)]
    domains = {agent_id: "as:evil" for agent_id in ids if agent_id.startswith("evil")}
    validators, keys = _keyed_set(ids, domains=domains, max_fraction=0.2)
    return validators, keys, ids


def test_has_quorum_can_reject_a_domain_holding_more_than_max_fraction() -> None:
    validators, _, ids = _concentrated_set()
    committee = CommitteeSelector(validators).select("seed", len(ids))

    assert committee.has_quorum(0.5)  # documented cap-vs-raw semantics
    assert not committee.has_quorum(0.5, enforce_domain_share=True)
    assert committee.raw_domain_weights["as:evil"] == pytest.approx(6.0)
    assert committee.max_fraction == pytest.approx(0.2)


def test_has_quorum_enforcement_fails_closed_without_raw_domain_data() -> None:
    validators, _, ids = _concentrated_set()
    committee = CommitteeSelector(validators).select("seed", len(ids))
    stripped = type(committee)(
        members=committee.members,
        weight=committee.weight,
        capped_weight=committee.capped_weight,
        domain_weights=committee.domain_weights,
        seed=committee.seed,
    )
    assert not stripped.has_quorum(0.5, enforce_domain_share=True)


def test_qc_verifier_can_enforce_domain_share_bound() -> None:
    validators, keys, ids = _concentrated_set()
    committee = CommitteeSelector(validators).select("seed", len(ids))
    votes = [_v2_vote(keys[i], i) for i in ids]
    lenient = CertificateVerificationPolicy(
        threshold_fraction=0.5, unsafe_allow_sub_two_thirds=True
    )
    qc = build_certificate(
        votes,
        committee=committee,
        validator_set=validators,
        verification_policy=CertificateVerificationPolicy(
            committee_size=len(ids),
            threshold_fraction=0.5,
            unsafe_allow_sub_two_thirds=True,
            expected_committee_seed="seed",
        ),
    )
    verify_certificate(qc, validator_set=validators, policy=lenient)

    enforcing = CertificateVerificationPolicy(
        threshold_fraction=0.5,
        unsafe_allow_sub_two_thirds=True,
        enforce_domain_share=True,
    )
    with pytest.raises(InvalidCertificateError, match="fault domain"):
        verify_certificate(qc, validator_set=validators, policy=enforcing)
    # Strengthening the threshold must not drop the enforcement flag.
    with pytest.raises(InvalidCertificateError, match="fault domain"):
        verify_certificate(
            qc, validator_set=validators, policy=enforcing, threshold_fraction=0.5
        )


def test_select_until_independent_honours_domain_share_enforcement() -> None:
    validators, _, ids = _concentrated_set()
    selector = CommitteeSelector(validators)
    selector.select_until_independent("seed", len(ids), threshold_fraction=0.5)
    from constitutional_swarm.validator_set import SybilBoundViolation

    with pytest.raises(SybilBoundViolation):
        selector.select_until_independent(
            "seed", len(ids), threshold_fraction=0.5, enforce_domain_share=True
        )


# ---------------------------------------------------------------------------
# validator-2: no silent replacement / re-keying
# ---------------------------------------------------------------------------


def test_add_rejects_existing_agent_id_without_explicit_replace() -> None:
    validators = ValidatorSet([ValidatorIdentity("a", 1.0, fault_domain="x")])
    with pytest.raises(ValueError, match="already registered"):
        validators.add(ValidatorIdentity("a", 1000.0, fault_domain="y"))
    assert validators.get("a").stake == 1.0  # type: ignore[union-attr]


def test_constructor_rejects_duplicate_agent_ids() -> None:
    with pytest.raises(ValueError, match="already registered"):
        ValidatorSet([ValidatorIdentity("a", 1.0), ValidatorIdentity("a", 2.0)])


def test_replace_cannot_change_or_drop_a_registered_public_key() -> None:
    old_key = _pk(Ed25519PrivateKey.generate())
    validators = ValidatorSet([ValidatorIdentity("a", 1.0, public_key_bytes=old_key)])
    with pytest.raises(ValueError, match="public key"):
        validators.add(
            ValidatorIdentity("a", 1.0, public_key_bytes=_pk(Ed25519PrivateKey.generate())),
            replace=True,
        )
    with pytest.raises(ValueError, match="public key"):
        validators.add(ValidatorIdentity("a", 1.0), replace=True)
    assert validators.get("a").public_key_bytes == old_key  # type: ignore[union-attr]

    validators.add(ValidatorIdentity("a", 5.0, public_key_bytes=old_key), replace=True)
    assert validators.total_weight() == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# validator-3: framed VRF input, framed retry seeds, NUL-free ids
# ---------------------------------------------------------------------------


def test_vrf_score_does_not_collide_on_nul_shifted_inputs() -> None:
    assert CommitteeSelector._score("a\x00b", "c", 1.0) != CommitteeSelector._score(
        "a", "b\x00c", 1.0
    )


def test_retry_seeds_do_not_collide_with_caller_seeds(monkeypatch) -> None:
    validators, _, ids = _concentrated_set()
    selector = CommitteeSelector(validators)
    seen: list[str] = []
    original = CommitteeSelector.select

    def recording(self, seed, committee_size, *, exclude=()):
        seen.append(seed)
        return original(self, seed, committee_size, exclude=exclude)

    monkeypatch.setattr(CommitteeSelector, "select", recording)
    from constitutional_swarm.validator_set import SybilBoundViolation

    for seed in ("s", "s\x001"):
        with pytest.raises(SybilBoundViolation):
            selector.select_until_independent(
                seed, len(ids), threshold_fraction=1.0, max_retries=3, enforce_domain_share=True
            )
    assert len(seen) == 6
    assert len(set(seen)) == 6


@pytest.mark.parametrize("agent_id", ["b\x00c", "\x00", "a\x00"])
def test_agent_id_containing_nul_is_rejected(agent_id: str) -> None:
    with pytest.raises(ValueError, match="agent_id"):
        ValidatorIdentity(agent_id, 1.0)


def test_non_string_agent_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="agent_id"):
        ValidatorIdentity(b"a", 1.0)  # type: ignore[arg-type]


def test_score_does_not_import_per_call() -> None:
    assert "import" not in inspect.getsource(CommitteeSelector._score)


# ---------------------------------------------------------------------------
# Rework r1: legacy-mode key sharing, re-registration re-keying
# ---------------------------------------------------------------------------


def test_legacy_mode_rejects_one_v1_signature_relabelled_across_shared_key() -> None:
    """One v1 signature cannot count for every id registered with its key."""
    ids = ["a", "b", "c"]
    validators, keys = _keyed_set(ids, shared={"b": "a", "c": "a"})
    committee = CommitteeSelector(validators).select("seed", len(ids))
    signature = keys["a"].sign(build_vote_message(ASSIGNMENT, ARTIFACT, EPOCH))
    votes = [
        SignedVote(i, ASSIGNMENT, ARTIFACT, EPOCH, signature, _pk(keys["a"])) for i in ids
    ]
    legacy = CertificateVerificationPolicy(
        committee_size=len(ids), expected_committee_seed="seed", allow_legacy_v1=True
    )
    with pytest.raises(InvalidCertificateError, match="share a registered public key"):
        build_certificate(
            votes, committee=committee, validator_set=validators, verification_policy=legacy
        )
    qc = QuorumCertificate(
        assignment_id=ASSIGNMENT,
        artifact_hash=ARTIFACT,
        epoch=EPOCH,
        votes=tuple(sorted(votes, key=lambda vote: vote.voter_id)),
        threshold_weight=2.0,
        achieved_weight=3.0,
        committee_seed="seed",
    )
    with pytest.raises(InvalidCertificateError, match="share a registered public key"):
        verify_certificate(
            qc,
            validator_set=validators,
            policy=CertificateVerificationPolicy(allow_legacy_v1=True),
        )


def test_v2_mode_still_counts_distinct_signatures_from_shared_key() -> None:
    """v2 binds voter_id, so per-voter signatures under a shared key stay valid."""
    ids = ["a", "b", "c"]
    validators, keys = _keyed_set(ids, shared={"b": "a"})
    committee = CommitteeSelector(validators).select("seed", len(ids))
    build_certificate(
        [_v2_vote(keys[i], i) for i in ids], committee=committee, validator_set=validators
    )


def test_reregistration_after_remove_cannot_silently_rekey() -> None:
    old_key = _pk(Ed25519PrivateKey.generate())
    new_key = _pk(Ed25519PrivateKey.generate())
    validators = ValidatorSet([ValidatorIdentity("a", 1.0, public_key_bytes=old_key)])
    validators.remove("a")
    with pytest.raises(ValueError, match="rekey=True"):
        validators.add(ValidatorIdentity("a", 1.0, public_key_bytes=new_key))
    with pytest.raises(ValueError, match="rekey=True"):
        validators.add(ValidatorIdentity("a", 1.0))
    assert "a" not in validators

    validators.add(ValidatorIdentity("a", 2.0, public_key_bytes=old_key))  # same key: ok
    validators.remove("a")
    validators.add(ValidatorIdentity("a", 1.0, public_key_bytes=new_key), rekey=True)
    assert validators.get("a").public_key_bytes == new_key  # type: ignore[union-attr]


def test_rekey_flag_does_not_permit_rekeying_a_live_identity() -> None:
    old_key = _pk(Ed25519PrivateKey.generate())
    validators = ValidatorSet([ValidatorIdentity("a", 1.0, public_key_bytes=old_key)])
    with pytest.raises(ValueError, match="public key"):
        validators.add(
            ValidatorIdentity("a", 1.0, public_key_bytes=_pk(Ed25519PrivateKey.generate())),
            replace=True,
            rekey=True,
        )
