"""Tests for private_vote.py — commit-reveal + nullifier voting."""

from __future__ import annotations

import pytest
from constitutional_swarm.private_vote import (
    BallotChoice,
    CommitRecord,
    DoubleVoteError,
    InvalidCommitError,
    InvalidRevealError,
    MissingRevealError,
    PrivateBallotBox,
    RevealRecord,
    _signing_payload_commit,
    build_commit,
    build_reveal,
    compute_nullifier,
    tally,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EPOCH = bytes.fromhex("00" * 16)
SUBJECT = bytes.fromhex("11" * 16)


def _kp():
    sk = Ed25519PrivateKey.generate()
    return sk


def _pub(sk):
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


class TestNullifier:
    def test_deterministic(self):
        voter_pub = _pub(_kp())
        n1 = compute_nullifier(voter_pub=voter_pub, epoch=EPOCH, subject=SUBJECT)
        n2 = compute_nullifier(voter_pub=voter_pub, epoch=EPOCH, subject=SUBJECT)
        assert n1 == n2

    def test_epoch_separation(self):
        voter_pub = _pub(_kp())
        n1 = compute_nullifier(voter_pub=voter_pub, epoch=EPOCH, subject=SUBJECT)
        n2 = compute_nullifier(
            voter_pub=voter_pub, epoch=bytes.fromhex("ff" * 16), subject=SUBJECT
        )
        n3 = compute_nullifier(
            voter_pub=voter_pub, epoch=EPOCH, subject=bytes.fromhex("ff" * 16)
        )
        assert len({n1, n2, n3}) == 3

    def test_invalid_public_key_rejected(self):
        with pytest.raises(ValueError):
            compute_nullifier(voter_pub=b"", epoch=EPOCH, subject=SUBJECT)


# ---------------------------------------------------------------------------
# Build + verify
# ---------------------------------------------------------------------------


class TestBuildCommit:
    def test_round_trip_via_dict(self):
        sk = _kp()
        c, r = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs-1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        c2 = CommitRecord.from_dict(c.to_dict())
        r2 = RevealRecord.from_dict(r.to_dict())
        assert c2 == c
        assert r2 == r

    def test_nonce_too_short(self):
        sk = _kp()
        with pytest.raises(ValueError, match="nonce"):
            build_commit(
                voter_private_key=sk,
                voter_secret=b"vs-1",
                epoch=EPOCH,
                subject=SUBJECT,
                choice=BallotChoice.YEA,
                nonce=b"short",
            )

    def test_commit_hides_choice(self):
        sk = _kp()
        nonce = b"\x42" * 32
        c_yea, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
            nonce=nonce,
        )
        c_nay, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.NAY,
            nonce=nonce,
        )
        assert c_yea.commit != c_nay.commit
        # Nullifier is deterministic from (secret, epoch, subject)
        assert c_yea.nullifier == c_nay.nullifier


class TestBallotBox:
    def _fresh(self, *keys):
        return PrivateBallotBox(
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset(_pub(key) for key in keys),
        )

    def _voter(self, box, choice, secret, sk=None):
        if sk is None:
            raise AssertionError("tests must register the voter key before creating the box")
        c, r = build_commit(
            voter_private_key=sk,
            voter_secret=secret,
            epoch=box.epoch,
            subject=box.subject,
            choice=choice,
        )
        box.submit_commit(c)
        return c, r, sk

    def test_happy_path_tally(self):
        keys = [_kp(), _kp(), _kp()]
        box = self._fresh(*keys)
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1", keys[0])
        _, r2, _ = self._voter(box, BallotChoice.YEA, b"s2", keys[1])
        _, r3, _ = self._voter(box, BallotChoice.NAY, b"s3", keys[2])
        box.close_commit_phase()
        box.submit_reveal(r1)
        box.submit_reveal(r2)
        box.submit_reveal(r3)
        result = box.tally(require_all_revealed=True)
        assert result.totals[BallotChoice.YEA] == 2
        assert result.totals[BallotChoice.NAY] == 1
        assert result.totals[BallotChoice.ABSTAIN] == 0
        assert result.total_valid == 3
        assert len(result.accepted) == 3
        assert result.rejected == ()

    def test_reveal_before_close_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1", sk)
        with pytest.raises(InvalidRevealError, match="phase"):
            box.submit_reveal(r1)

    def test_commit_after_close_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"sX",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        box.close_commit_phase()
        with pytest.raises(InvalidCommitError, match="closed"):
            box.submit_commit(c)

    def test_missing_reveal_returns_rejected(self):
        sk1, sk2 = _kp(), _kp()
        box = self._fresh(sk1, sk2)
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1", sk1)
        _, _, _ = self._voter(box, BallotChoice.NAY, b"s2", sk2)
        box.close_commit_phase()
        box.submit_reveal(r1)
        result = box.tally()
        assert result.totals[BallotChoice.YEA] == 1
        assert result.totals[BallotChoice.NAY] == 0
        assert any(reason == "missing reveal" for _, reason in result.rejected)

    def test_require_all_revealed_raises(self):
        sk = _kp()
        box = self._fresh(sk)
        self._voter(box, BallotChoice.YEA, b"s1", sk)
        box.close_commit_phase()
        with pytest.raises(MissingRevealError):
            box.tally(require_all_revealed=True)

    def test_double_vote_same_key_with_rotated_secret_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        self._voter(box, BallotChoice.YEA, b"secret-one", sk)
        with pytest.raises(DoubleVoteError):
            self._voter(box, BallotChoice.NAY, b"secret-two", sk)

    def test_epoch_mismatch_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=bytes.fromhex("ff" * 16),
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        with pytest.raises(InvalidCommitError, match="mismatch"):
            box.submit_commit(c)

    def test_tampered_reveal_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        _, r, _ = self._voter(box, BallotChoice.YEA, b"s1", sk)
        box.close_commit_phase()
        # Swap the choice in the reveal (signature will not match)
        forged = RevealRecord(
            version=r.version,
            commit=r.commit,
            choice=BallotChoice.NAY,
            nonce=r.nonce,
            signature=r.signature,
        )
        with pytest.raises(InvalidRevealError):
            box.submit_reveal(forged)

    def test_tampered_commit_signature_rejected(self):
        sk = _kp()
        box = self._fresh(sk)
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        bad = CommitRecord(
            version=c.version,
            epoch=c.epoch,
            subject=c.subject,
            voter=c.voter,
            commit=c.commit,
            nullifier=c.nullifier,
            signature=bytes(64),  # zeroed sig
        )
        with pytest.raises(InvalidCommitError):
            box.submit_commit(bad)


class TestTallyFunction:
    def test_deterministic_across_input_order(self):
        sk1, sk2, sk3 = _kp(), _kp(), _kp()
        triples = []
        for sk, choice, secret in [
            (sk1, BallotChoice.YEA, b"a"),
            (sk2, BallotChoice.NAY, b"b"),
            (sk3, BallotChoice.YEA, b"c"),
        ]:
            c, r = build_commit(
                voter_private_key=sk,
                voter_secret=secret,
                epoch=EPOCH,
                subject=SUBJECT,
                choice=choice,
            )
            triples.append((c, r))
        commits1 = [c for c, _ in triples]
        commits2 = list(reversed(commits1))
        reveals1 = [r for _, r in triples]
        reveals2 = list(reversed(reveals1))
        eligible = frozenset(_pub(sk) for sk in (sk1, sk2, sk3))
        t1 = tally(
            commits1, reveals1, epoch=EPOCH, subject=SUBJECT, eligible_voters=eligible
        )
        t2 = tally(
            commits2, reveals2, epoch=EPOCH, subject=SUBJECT, eligible_voters=eligible
        )
        assert t1.accepted == t2.accepted
        assert dict(t1.totals) == dict(t2.totals)

    def test_voter_first_wins(self):
        # Two commits from the same eligible key → only one tallied.
        sk1 = _kp()
        c1, r1 = build_commit(
            voter_private_key=sk1,
            voter_secret=b"shared",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        c2, r2 = build_commit(
            voter_private_key=sk1,
            voter_secret=b"rotated-secret",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.NAY,
        )
        assert c1.nullifier == c2.nullifier
        result = tally(
            [c1, c2],
            [r1, r2],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({_pub(sk1)}),
        )
        assert result.total_valid == 1
        assert any(reason == "duplicate voter" for _, reason in result.rejected)

    def test_reveal_opens_wrong_commit_rejected(self):
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        # Build an independent reveal with a mismatched nonce
        bad_reveal = build_reveal(
            voter_private_key=sk,
            commit=c.commit,
            choice=BallotChoice.YEA,
            nonce=b"\x00" * 32,  # different nonce → won't open
        )
        result = tally(
            [c],
            [bad_reveal],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({_pub(sk)}),
        )
        assert result.total_valid == 0
        assert any("does not open" in reason for _, reason in result.rejected)

    def test_require_all_revealed_rejects_present_but_invalid_reveal(self):
        """A present-but-invalid reveal must not satisfy require_all_revealed.

        Regression: the gate checked reveal *presence* keyed by commit digest,
        not reveal *validity*. A reveal whose .commit matches but does not open
        the commit (wrong nonce, valid signature) passed the gate, then got
        silently dropped in the tally loop — so a ballot vanished without the
        promised MissingRevealError.
        """
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        bad_reveal = build_reveal(
            voter_private_key=sk,
            commit=c.commit,
            choice=BallotChoice.YEA,
            nonce=b"\x00" * 32,  # wrong nonce → won't open, but signature is valid
        )
        with pytest.raises(MissingRevealError):
            tally(
                [c],
                [bad_reveal],
                epoch=EPOCH,
                subject=SUBJECT,
                eligible_voters=frozenset({_pub(sk)}),
                require_all_revealed=True,
            )


# ── Security regression tests ─────────────────────────────────────────────────


class TestMultipleRevealsProtection:
    """P1: tally() must try all reveals for a commit, not just the first."""

    def _make_vote(self, choice=None):
        """Helper: build signed commit + matching reveal for given choice."""
        from constitutional_swarm.private_vote import (
            BallotChoice,
            build_commit,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sk = Ed25519PrivateKey.generate()
        choice = choice or BallotChoice.YEA
        commit, reveal = build_commit(
            voter_private_key=sk,
            voter_secret=b"secret",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=choice,
        )
        return commit, reveal

    def test_invalid_first_reveal_falls_back_to_valid(self):
        """An attacker-injected bad reveal must not block the valid reveal."""
        from constitutional_swarm.private_vote import (
            BallotChoice,
            RevealRecord,
            tally,
        )

        commit, valid_reveal = self._make_vote(BallotChoice.YEA)

        # Build an invalid reveal for the same commit (tampered choice, wrong sig)
        bad_reveal = RevealRecord(
            version=valid_reveal.version,
            commit=valid_reveal.commit,
            choice=BallotChoice.NAY,
            nonce=valid_reveal.nonce,
            signature=b"\xff" * 64,  # invalid signature
        )

        result = tally(
            [commit],
            [bad_reveal, valid_reveal],  # bad first
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({commit.voter}),
        )
        assert result.totals[BallotChoice.YEA] == 1, (
            "valid reveal should be found even when preceded by an invalid reveal"
        )
        assert result.totals[BallotChoice.NAY] == 0

    def test_only_invalid_reveals_causes_rejection(self):
        """If ALL reveals for a commit are invalid, the commit must be rejected."""
        from constitutional_swarm.private_vote import (
            BallotChoice,
            RevealRecord,
            tally,
        )

        commit, valid_reveal = self._make_vote(BallotChoice.YEA)
        bad_reveal = RevealRecord(
            version=valid_reveal.version,
            commit=valid_reveal.commit,
            choice=BallotChoice.NAY,
            nonce=valid_reveal.nonce,
            signature=b"\x00" * 64,
        )

        result = tally(
            [commit],
            [bad_reveal],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({commit.voter}),
        )
        assert result.totals[BallotChoice.YEA] == 0
        assert len(result.rejected) == 1


class TestSubmitCommitV2Validation:
    """P2: PrivateBallotBox.submit_commit must validate v2 field consistency."""

    def _box(self, commit):
        from constitutional_swarm.private_vote import PrivateBallotBox

        return PrivateBallotBox(
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({commit.voter}),
        )

    def _commit(self, proof_scheme=None, validity_proof=None):
        from constitutional_swarm.private_vote import (
            _V2_VERSION,
            BallotChoice,
            CommitRecord,
            build_commit,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sk = Ed25519PrivateKey.generate()
        commit, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        # Rebuild as v2 with custom proof fields
        version = _V2_VERSION
        signature = sk.sign(
            _signing_payload_commit(
                version,
                commit.epoch,
                commit.subject,
                commit.voter,
                commit.commit,
                commit.nullifier,
                proof_scheme,
                validity_proof,
            )
        )
        return CommitRecord(
            version=version,
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
            signature=signature,
            proof_scheme=proof_scheme,
            validity_proof=validity_proof,
        )

    def test_v2_proof_scheme_without_validity_proof_rejected(self):
        from constitutional_swarm.private_vote import InvalidCommitError

        bad = self._commit(proof_scheme="zkp_v1", validity_proof=None)
        box = self._box(bad)
        with pytest.raises(InvalidCommitError, match="both be set or both absent"):
            box.submit_commit(bad)

    def test_v2_validity_proof_without_proof_scheme_rejected(self):
        from constitutional_swarm.private_vote import InvalidCommitError

        bad = self._commit(proof_scheme=None, validity_proof=b"proof_bytes")
        box = self._box(bad)
        with pytest.raises(InvalidCommitError, match="both be set or both absent"):
            box.submit_commit(bad)

    def test_v2_both_none_accepted(self):
        """v2 with both fields None is valid (backward-compatible)."""
        valid = self._commit(proof_scheme=None, validity_proof=None)
        box = self._box(valid)
        box.submit_commit(valid)  # must not raise

    def test_v2_both_set_requires_registered_verifier_at_admission(self):
        commit = self._commit(proof_scheme="zkp_v1", validity_proof=b"proof")
        box = self._box(commit)
        with pytest.raises(InvalidCommitError, match="no verifier"):
            box.submit_commit(commit)
