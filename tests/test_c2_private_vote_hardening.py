"""Security regressions for eligibility-bound, voter-bound private ballots."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.private_vote import (
    BallotChoice,
    DoubleVoteError,
    HashCommitmentProver,
    InvalidCommitError,
    MissingRevealError,
    PrivateBallotBox,
    ValidityStatement,
    ValidityWitness,
    _commit_digest,
    _signing_payload_commit,
    build_commit,
    compute_nullifier,
    tally,
)

EPOCH = b"epoch-c2"
SUBJECT = b"subject-c2"
NONCE = b"n" * 32


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _vote(
    key: Ed25519PrivateKey,
    choice: BallotChoice = BallotChoice.YEA,
    *,
    nonce: bytes | None = None,
    prover=None,
):
    return build_commit(
        voter_private_key=key,
        voter_secret=_pub(key),
        epoch=EPOCH,
        subject=SUBJECT,
        choice=choice,
        nonce=nonce,
        prover=prover,
    )


def _resign(key: Ed25519PrivateKey, record):
    return replace(
        record,
        signature=key.sign(
            _signing_payload_commit(
                record.version,
                record.epoch,
                record.subject,
                record.voter,
                record.commit,
                record.nullifier,
                record.proof_scheme,
                record.validity_proof,
            )
        ),
    )


class OpeningValidityProver:
    """Test verifier whose proof exposes and checks the actual opening."""

    scheme_id = "test-opening-v1"
    provides_validity_assurance = True

    def prove(self, statement: ValidityStatement, witness: ValidityWitness) -> bytes:
        return witness.choice.value.encode("ascii") + b"\x00" + witness.nonce

    def verify(self, statement: ValidityStatement, proof: bytes) -> bool:
        try:
            raw_choice, nonce = proof.split(b"\x00", 1)
            choice = BallotChoice(raw_choice.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return False
        return _commit_digest(choice, nonce, statement.epoch, statement.subject, statement.voter) == (
            statement.commit
        )


class MissingAssuranceProver(OpeningValidityProver):
    scheme_id = "missing-assurance-v1"
    provides_validity_assurance = None


class EmptyAcceptingProver(OpeningValidityProver):
    scheme_id = "empty-accepting-v1"

    def verify(self, statement: ValidityStatement, proof: bytes) -> bool:
        return True


class NonBooleanVerifier(OpeningValidityProver):
    scheme_id = "nonboolean-verifier-v1"

    def verify(self, statement: ValidityStatement, proof: bytes):
        return "verification error"


class AlternateOpeningValidityProver(OpeningValidityProver):
    scheme_id = "test-opening-v2"


class UnicodeOpeningValidityProver(OpeningValidityProver):
    scheme_id = "test-opening-π"


class PermissiveAssuringProver(OpeningValidityProver):
    scheme_id = "test-permissive-v1"

    def verify(self, statement: ValidityStatement, proof: bytes) -> bool:
        return bool(proof)


class MaliciousEligibleVoters(frozenset):
    def __new__(cls, enrolled: bytes, injected: bytes):
        instance = super().__new__(cls, {enrolled})
        instance.injected = injected
        return instance

    def __contains__(self, item) -> bool:
        return True

    def __iter__(self):
        enrolled = next(frozenset.__iter__(self))
        return iter((enrolled, self.injected))


def test_same_opening_is_voter_bound() -> None:
    alice = Ed25519PrivateKey.generate()
    bob = Ed25519PrivateKey.generate()

    alice_commit, _ = _vote(alice, nonce=NONCE)
    bob_commit, _ = _vote(bob, nonce=NONCE)

    assert alice_commit.commit != bob_commit.commit
    assert alice_commit.nullifier != bob_commit.nullifier


def test_only_registered_keys_can_contribute_to_tally() -> None:
    keys = [Ed25519PrivateKey.generate() for _ in range(5)]
    ballots = [_vote(key) for key in keys]

    result = tally(
        [commit for commit, _ in ballots],
        [reveal for _, reveal in ballots],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(keys[0])}),
        strict_v2=False,
    )

    assert result.total_valid == 1
    assert [reason for _, reason in result.rejected].count("ineligible voter") == 4


def test_eligibility_membership_uses_normalized_builtin_frozenset() -> None:
    alice = Ed25519PrivateKey.generate()
    outsider = Ed25519PrivateKey.generate()
    alice_commit, alice_reveal = _vote(alice)
    outsider_commit, outsider_reveal = _vote(outsider)
    malicious = MaliciousEligibleVoters(_pub(alice), _pub(outsider))

    direct = tally(
        [alice_commit, outsider_commit],
        [alice_reveal, outsider_reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=malicious,
        strict_v2=False,
    )
    assert direct.total_valid == 1
    assert any(reason == "ineligible voter" for _, reason in direct.rejected)

    box = PrivateBallotBox(
        epoch=EPOCH, subject=SUBJECT, eligible_voters=malicious, strict_v2=False
    )
    box.submit_commit(alice_commit)
    with pytest.raises(InvalidCommitError, match="ineligible voter"):
        box.submit_commit(outsider_commit)


def test_forged_noncanonical_nullifier_is_rejected() -> None:
    alice = Ed25519PrivateKey.generate()
    commit, reveal = _vote(alice)
    forged = _resign(alice, replace(commit, nullifier=b"x" * 32))

    result = tally(
        [forged],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        strict_v2=False,
    )

    assert result.total_valid == 0
    assert any(reason == "noncanonical nullifier" for _, reason in result.rejected)


def _copied_digest_ballots():
    alice = Ed25519PrivateKey.generate()
    mallory = Ed25519PrivateKey.generate()
    alice_commit, alice_reveal = _vote(alice)
    mallory_nullifier = compute_nullifier(
        voter_pub=_pub(mallory), epoch=EPOCH, subject=SUBJECT
    )
    copied = replace(
        alice_commit,
        voter=_pub(mallory),
        nullifier=mallory_nullifier,
    )
    return alice, mallory, alice_commit, alice_reveal, _resign(mallory, copied)


def test_copied_digest_cannot_reserve_legitimate_ballot() -> None:
    alice, mallory, alice_commit, alice_reveal, copied = _copied_digest_ballots()
    eligible = frozenset({_pub(alice), _pub(mallory)})
    box = PrivateBallotBox(
        epoch=EPOCH, subject=SUBJECT, eligible_voters=eligible, strict_v2=False
    )

    box.submit_commit(copied)
    box.submit_commit(alice_commit)
    box.close_commit_phase()
    box.submit_reveal(alice_reveal)

    result = box.tally()
    assert result.total_valid == 1
    assert result.totals[BallotChoice.YEA] == 1
    assert any(
        reason == f"reveal does not open the commit for voter {_pub(mallory).hex()}"
        for _, reason in result.rejected
    )


def test_require_all_revealed_tracks_voter_commit_tuple() -> None:
    alice, mallory, alice_commit, alice_reveal, copied = _copied_digest_ballots()
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice), _pub(mallory)}),
        strict_v2=False,
    )
    box.submit_commit(copied)
    box.submit_commit(alice_commit)
    box.close_commit_phase()
    box.submit_reveal(alice_reveal)

    with pytest.raises(MissingRevealError, match="1 accepted ballots"):
        box.tally(require_all_revealed=True)


def test_ballot_box_rejects_ineligible_commit_at_admission() -> None:
    alice = Ed25519PrivateKey.generate()
    outsider = Ed25519PrivateKey.generate()
    outsider_commit, _ = _vote(outsider)
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        strict_v2=False,
    )

    with pytest.raises(InvalidCommitError, match="ineligible voter"):
        box.submit_commit(outsider_commit)


def test_concurrent_same_voter_submissions_store_only_one_ballot() -> None:
    alice = Ed25519PrivateKey.generate()
    first, _ = _vote(alice, BallotChoice.YEA, nonce=b"a" * 32)
    second, _ = _vote(alice, BallotChoice.NAY, nonce=b"b" * 32)
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        strict_v2=False,
    )
    barrier = Barrier(2)

    def submit(record):
        barrier.wait()
        try:
            box.submit_commit(record)
        except (DoubleVoteError, InvalidCommitError) as exc:
            return exc
        return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(submit, (first, second)))

    assert sum(outcome is None for outcome in outcomes) == 1
    assert sum(type(outcome).__name__ == "DoubleVoteError" for outcome in outcomes) == 1
    box.close_commit_phase()
    result = box.tally()
    assert len(result.rejected) == 1
    assert result.rejected[0][1] == "missing reveal"


def test_ballot_box_configuration_and_internal_state_are_not_injectable() -> None:
    alice = Ed25519PrivateKey.generate()
    eligible = frozenset({_pub(alice)})
    box = PrivateBallotBox(epoch=EPOCH, subject=SUBJECT, eligible_voters=eligible)

    with pytest.raises(AttributeError):
        box.eligible_voters = frozenset()  # type: ignore[misc]
    with pytest.raises(TypeError):
        box.provers["injected"] = OpeningValidityProver()  # type: ignore[index]
    with pytest.raises(TypeError, match="unexpected keyword"):
        PrivateBallotBox(
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=eligible,
            _commits={},  # type: ignore[call-arg]
        )


def test_ballot_box_accepts_none_provers() -> None:
    alice = Ed25519PrivateKey.generate()
    eligible = frozenset({_pub(alice)})
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        strict_v2=False,
        provers=None,
    )

    assert dict(box.provers) == {}


def test_ballot_box_uses_identity_equality_and_hashing() -> None:
    alice = Ed25519PrivateKey.generate()
    eligible = frozenset({_pub(alice)})
    commit, _ = _vote(alice)
    first = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        strict_v2=False,
    )
    second = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        strict_v2=False,
    )

    original_hash = hash(first)
    first.submit_commit(commit)
    assert isinstance(original_hash, int)
    assert hash(first) == original_hash
    assert first != second


@pytest.mark.parametrize("strict_v2", [False, True])
def test_commit_signature_binds_version_and_proof_envelope(strict_v2: bool) -> None:
    alice = Ed25519PrivateKey.generate()
    prover = OpeningValidityProver()
    alternate = AlternateOpeningValidityProver()
    permissive = PermissiveAssuringProver()
    commit, reveal = _vote(alice, prover=prover)
    eligible = frozenset({_pub(alice)})
    policy = {
        prover.scheme_id: prover,
        alternate.scheme_id: alternate,
        permissive.scheme_id: permissive,
    }

    round_tripped = type(commit).from_dict(commit.to_dict())
    positive = tally(
        [round_tripped],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=strict_v2,
    )
    assert positive.total_valid == 1
    positive_box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=strict_v2,
    )
    positive_box.submit_commit(round_tripped)

    attacks = (
        replace(commit, proof_scheme=None, validity_proof=None),
        replace(commit, version=1, proof_scheme=None, validity_proof=None),
        replace(commit, version=1),
        replace(commit, proof_scheme=alternate.scheme_id),
        replace(commit, validity_proof=b"replacement-proof"),
        replace(commit, proof_scheme=permissive.scheme_id, validity_proof=b"replacement-proof"),
    )
    for attack in attacks:
        direct = tally(
            [attack],
            [reveal],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=eligible,
            provers=policy,
            strict_v2=strict_v2,
        )
        assert direct.total_valid == 0
        assert any(reason == "bad commit signature" for _, reason in direct.rejected)

        box = PrivateBallotBox(
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=eligible,
            provers=policy,
            strict_v2=strict_v2,
        )
        with pytest.raises(InvalidCommitError, match="bad commit signature"):
            box.submit_commit(attack)


@pytest.mark.parametrize(
    ("prover", "provers", "reason"),
    [
        (None, {}, "requires proof_scheme and validity_proof"),
        (HashCommitmentProver(scheme_id="renamed-placeholder"), None, "validity assurance"),
        (MissingAssuranceProver(), None, "validity assurance"),
    ],
)
def test_strict_v2_rejects_proofless_or_nonassuring_verifiers(prover, provers, reason) -> None:
    alice = Ed25519PrivateKey.generate()
    commit, _ = _vote(alice, prover=prover)
    if prover is None:
        commit = _resign(alice, replace(commit, version=2))
    configured = provers if provers is not None else {prover.scheme_id: prover}
    direct = tally(
        [commit],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers=configured,
        strict_v2=True,
    )
    assert any(reason in rejected_reason for _, rejected_reason in direct.rejected)
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers=configured,
        strict_v2=True,
    )

    with pytest.raises(InvalidCommitError, match=reason):
        box.submit_commit(commit)


def test_strict_v2_rejects_unknown_or_mismatched_verifier() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = OpeningValidityProver()
    commit, _ = _vote(alice, prover=prover)

    unknown = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        strict_v2=True,
    )
    with pytest.raises(InvalidCommitError, match="no verifier"):
        unknown.submit_commit(commit)

    direct_unknown = tally(
        [commit],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        strict_v2=True,
    )
    assert any("no verifier" in reason for _, reason in direct_unknown.rejected)

    mismatched = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: replace(HashCommitmentProver(), scheme_id="other")},
        strict_v2=True,
    )
    with pytest.raises(InvalidCommitError, match="scheme mismatch"):
        mismatched.submit_commit(commit)

    direct_mismatch = tally(
        [commit],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: replace(HashCommitmentProver(), scheme_id="other")},
        strict_v2=True,
    )
    assert any("scheme mismatch" in reason for _, reason in direct_mismatch.rejected)


def test_strict_v2_rejects_empty_proof_before_verifier_callback() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = EmptyAcceptingProver()
    commit, _ = _vote(alice, prover=prover)
    empty_proof = _resign(alice, replace(commit, validity_proof=b""))
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=True,
    )

    with pytest.raises(InvalidCommitError, match="non-empty"):
        box.submit_commit(empty_proof)

    direct = tally(
        [empty_proof],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=True,
    )
    assert any("non-empty" in reason for _, reason in direct.rejected)


def test_strict_v2_rejects_truthy_nonboolean_verifier_result() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = NonBooleanVerifier()
    commit, _ = _vote(alice, prover=prover)
    policy = {prover.scheme_id: prover}
    eligible = frozenset({_pub(alice)})

    direct = tally(
        [commit],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=True,
    )
    assert any(reason == "invalid validity proof" for _, reason in direct.rejected)

    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=True,
    )
    with pytest.raises(InvalidCommitError, match="invalid validity proof"):
        box.submit_commit(commit)


def test_strict_v2_accepts_explicit_assuring_opening_verifier() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = OpeningValidityProver()
    commit, reveal = _vote(alice, prover=prover)
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=True,
    )

    box.submit_commit(commit)
    box.close_commit_phase()
    box.submit_reveal(reveal)

    assert box.tally().total_valid == 1


def test_malformed_wire_proof_scheme_is_rejected_as_invalid_commit() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = OpeningValidityProver()
    commit, _ = _vote(alice, prover=prover)
    wire_record = commit.to_dict()
    wire_record["proof_scheme"] = "\ud800"
    wire_record["signature"] = (b"arbitrary attacker signature".ljust(64, b"!")).hex()
    attack = type(commit).from_dict(wire_record)
    eligible = frozenset({_pub(alice)})

    direct = tally(
        [attack],
        [],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers={prover.scheme_id: prover},
    )
    assert direct.total_valid == 0
    assert any("proof_scheme must be valid UTF-8" in reason for _, reason in direct.rejected)

    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers={prover.scheme_id: prover},
    )
    with pytest.raises(InvalidCommitError, match="proof_scheme must be valid UTF-8"):
        box.submit_commit(attack)


def test_valid_unicode_proof_scheme_round_trips_and_verifies() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = UnicodeOpeningValidityProver()
    commit, reveal = _vote(alice, prover=prover)
    round_tripped = type(commit).from_dict(commit.to_dict())
    eligible = frozenset({_pub(alice)})
    policy = {prover.scheme_id: prover}

    direct = tally(
        [round_tripped],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=True,
    )
    assert direct.total_valid == 1

    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=eligible,
        provers=policy,
        strict_v2=True,
    )
    box.submit_commit(round_tripped)
    box.close_commit_phase()
    box.submit_reveal(reveal)
    assert box.tally().total_valid == 1
