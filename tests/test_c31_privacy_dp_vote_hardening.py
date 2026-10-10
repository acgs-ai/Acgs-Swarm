"""C31 regressions: private voting, DP accounting and swarm_ode noise/beacon paths.

Every test is phrased as an invalid-input regression: the hostile or
unsafe input must be rejected (or recorded as not BODES-checked).
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from importlib.util import find_spec
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.privacy_accountant import (
    PrivacyAccountant,
    PrivacyBudgetExhausted,
    _rdp_to_epsilon_balle2020,
)
from constitutional_swarm.private_vote import (
    BallotChoice,
    DoubleVoteError,
    HashCommitmentProver,
    InvalidCommitError,
    PrivateBallotBox,
    ValidityStatement,
    ValidityWitness,
    _commit_digest,
    _signing_payload_commit,
    build_commit,
    compute_nullifier,
    tally,
)

EPOCH = b"epoch-c31"
SUBJECT = b"subject-c31"

_TORCH_AVAILABLE = find_spec("torch") is not None
requires_torch = pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _vote(
    key: Ed25519PrivateKey,
    *,
    prover=None,
    epoch: bytes = EPOCH,
    subject: bytes = SUBJECT,
    choice: BallotChoice = BallotChoice.YEA,
    nonce: bytes | None = None,
):
    return build_commit(
        voter_private_key=key,
        voter_secret=_pub(key),
        epoch=epoch,
        subject=subject,
        choice=choice,
        nonce=nonce,
        prover=prover,
    )


def _resign(key: Ed25519PrivateKey, record):
    payload = _signing_payload_commit(
        record.version,
        record.epoch,
        record.subject,
        record.voter,
        record.commit,
        record.nullifier,
        record.proof_scheme,
        record.validity_proof,
    )
    return replace(record, signature=key.sign(payload))


class _AssuringOpeningProver:
    """Test-only verifier that checks the opening (stands in for a real SNARK)."""

    scheme_id = "c31-opening-v1"
    provides_validity_assurance = True

    def prove(self, statement: ValidityStatement, witness: ValidityWitness) -> bytes:
        return witness.choice.value.encode("ascii") + b"\x00" + witness.nonce

    def verify(self, statement: ValidityStatement, proof: bytes) -> bool:
        try:
            raw_choice, nonce = proof.split(b"\x00", 1)
            choice = BallotChoice(raw_choice.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return False
        expected = _commit_digest(
            choice, nonce, statement.epoch, statement.subject, statement.voter
        )
        return expected == statement.commit


# ---------------------------------------------------------------------------
# pvote-1: strict_v2 is the fail-closed default; roster is caller-pinned (P1)
# ---------------------------------------------------------------------------


def test_default_tally_rejects_proofless_v1_ballot() -> None:
    alice = Ed25519PrivateKey.generate()
    commit, reveal = _vote(alice)

    result = tally(
        [commit], [reveal], epoch=EPOCH, subject=SUBJECT, eligible_voters=frozenset({_pub(alice)})
    )

    assert result.total_valid == 0
    assert any("strict_v2" in reason for _, reason in result.rejected)


def test_default_ballot_box_rejects_proofless_v1_ballot() -> None:
    alice = Ed25519PrivateKey.generate()
    commit, _ = _vote(alice)
    box = PrivateBallotBox(epoch=EPOCH, subject=SUBJECT, eligible_voters=frozenset({_pub(alice)}))

    assert box.strict_v2 is True
    with pytest.raises(InvalidCommitError, match="strict_v2"):
        box.submit_commit(commit)


def test_default_tally_counts_ballot_with_assuring_verifier() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = _AssuringOpeningProver()
    commit, reveal = _vote(alice, prover=prover)

    result = tally(
        [commit],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
    )

    assert result.totals[BallotChoice.YEA] == 1


def test_p1_ballot_carrying_unpinned_voter_or_context_is_rejected() -> None:
    """P1: roster/epoch/subject come from the caller, never from the ballot."""
    alice = Ed25519PrivateKey.generate()
    mallory = Ed25519PrivateKey.generate()
    prover = _AssuringOpeningProver()
    provers = {prover.scheme_id: prover}
    roster = frozenset({_pub(alice)})

    sybil, sybil_reveal = _vote(mallory, prover=prover)
    other_epoch, other_reveal = _vote(alice, prover=prover, epoch=b"attacker-epoch")

    result = tally(
        [sybil, other_epoch],
        [sybil_reveal, other_reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=roster,
        provers=provers,
    )

    assert result.total_valid == 0
    reasons = sorted(reason for _, reason in result.rejected)
    assert reasons == ["epoch/subject mismatch", "ineligible voter"]


# ---------------------------------------------------------------------------
# pvote-1 (r1): strict-mode counterparts of the C2 roster/nullifier regressions
# ---------------------------------------------------------------------------


def _strict_box(*keys: Ed25519PrivateKey) -> PrivateBallotBox:
    prover = _AssuringOpeningProver()
    return PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset(_pub(k) for k in keys),
        provers={prover.scheme_id: prover},
        strict_v2=True,
    )


@pytest.mark.parametrize("path", ["tally", "box"])
def test_strict_duplicate_voter_counts_once(path: str) -> None:
    alice = Ed25519PrivateKey.generate()
    prover = _AssuringOpeningProver()
    first, first_reveal = _vote(alice, prover=prover, nonce=b"a" * 32)
    second, second_reveal = _vote(
        alice, prover=prover, choice=BallotChoice.NAY, nonce=b"b" * 32
    )

    if path == "tally":
        result = tally(
            [first, second],
            [first_reveal, second_reveal],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({_pub(alice)}),
            provers={prover.scheme_id: prover},
            strict_v2=True,
        )
        assert result.total_valid == 1
        assert [reason for _, reason in result.rejected] == ["duplicate voter"]
        return

    box = _strict_box(alice)
    box.submit_commit(first)
    with pytest.raises(DoubleVoteError, match="duplicate voter"):
        box.submit_commit(second)
    box.close_commit_phase()
    box.submit_reveal(first_reveal)
    assert box.tally(require_all_revealed=True).total_valid == 1


def _copied_digest_ballots(prover):
    alice = Ed25519PrivateKey.generate()
    mallory = Ed25519PrivateKey.generate()
    alice_commit, alice_reveal = _vote(alice, prover=prover)
    copied = replace(
        alice_commit,
        voter=_pub(mallory),
        nullifier=compute_nullifier(voter_pub=_pub(mallory), epoch=EPOCH, subject=SUBJECT),
    )
    return alice, mallory, alice_commit, alice_reveal, _resign(mallory, copied)


@pytest.mark.parametrize("path", ["tally", "box"])
def test_strict_copied_digest_cannot_reserve_legitimate_ballot(path: str) -> None:
    prover = _AssuringOpeningProver()
    alice, mallory, alice_commit, alice_reveal, copied = _copied_digest_ballots(prover)

    if path == "tally":
        result = tally(
            [copied, alice_commit],
            [alice_reveal],
            epoch=EPOCH,
            subject=SUBJECT,
            eligible_voters=frozenset({_pub(alice), _pub(mallory)}),
            provers={prover.scheme_id: prover},
            strict_v2=True,
        )
    else:
        box = _strict_box(alice, mallory)
        # The copied digest does not open under mallory's key, so the assuring
        # verifier refuses it at admission and it cannot reserve anything.
        with pytest.raises(InvalidCommitError, match="invalid validity proof"):
            box.submit_commit(copied)
        box.submit_commit(alice_commit)
        box.close_commit_phase()
        box.submit_reveal(alice_reveal)
        result = box.tally(require_all_revealed=True)

    assert result.total_valid == 1
    assert result.totals[BallotChoice.YEA] == 1
    if path == "tally":
        assert [reason for _, reason in result.rejected] == ["invalid validity proof"]


def test_strict_concurrent_same_voter_submissions_store_only_one_ballot() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = _AssuringOpeningProver()
    first, _ = _vote(alice, prover=prover, nonce=b"a" * 32)
    second, _ = _vote(alice, prover=prover, choice=BallotChoice.NAY, nonce=b"b" * 32)
    box = _strict_box(alice)
    barrier = threading.Barrier(2)

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
    assert sum(type(outcome) is DoubleVoteError for outcome in outcomes) == 1
    box.close_commit_phase()
    result = box.tally()
    assert [reason for _, reason in result.rejected] == ["missing reveal"]


# ---------------------------------------------------------------------------
# pvote-2: a non-assuring (hash) verifier never counts without an explicit opt-in
# ---------------------------------------------------------------------------


def test_nonstrict_tally_rejects_hash_prover_without_opt_in() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = HashCommitmentProver()
    commit, reveal = _vote(alice, prover=prover)

    result = tally(
        [commit],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=False,
    )

    assert result.total_valid == 0
    assert any("validity assurance" in reason for _, reason in result.rejected)


def test_nonstrict_ballot_box_rejects_hash_prover_without_opt_in() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = HashCommitmentProver()
    commit, _ = _vote(alice, prover=prover)
    box = PrivateBallotBox(
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=False,
    )

    with pytest.raises(InvalidCommitError, match="validity assurance"):
        box.submit_commit(commit)


def test_hash_prover_counts_only_with_explicit_insecure_opt_in() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = HashCommitmentProver()
    commit, reveal = _vote(alice, prover=prover)

    result = tally(
        [commit],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        strict_v2=False,
        allow_insecure_hash_prover=True,
    )

    assert result.totals[BallotChoice.YEA] == 1


def test_insecure_opt_in_never_overrides_strict_mode() -> None:
    alice = Ed25519PrivateKey.generate()
    prover = HashCommitmentProver()
    commit, reveal = _vote(alice, prover=prover)

    result = tally(
        [commit],
        [reveal],
        epoch=EPOCH,
        subject=SUBJECT,
        eligible_voters=frozenset({_pub(alice)}),
        provers={prover.scheme_id: prover},
        allow_insecure_hash_prover=True,
    )

    assert result.total_valid == 0
    assert any("validity assurance" in reason for _, reason in result.rejected)


# ---------------------------------------------------------------------------
# privacy-1: non-finite RDP fails closed; spend+assert is one critical section
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [math.nan, math.inf])
def test_nonfinite_rdp_value_converts_to_infinite_epsilon(bad: float) -> None:
    epsilon, _ = _rdp_to_epsilon_balle2020([bad, bad], [2.0, 4.0], 1e-5)

    assert epsilon == math.inf


def test_nan_rdp_on_one_order_does_not_win_the_minimum() -> None:
    finite_eps, _ = _rdp_to_epsilon_balle2020([0.5], [4.0], 1e-5)
    epsilon, alpha = _rdp_to_epsilon_balle2020([math.nan, 0.5], [2.0, 4.0], 1e-5)

    assert alpha == 4.0
    assert epsilon == pytest.approx(finite_eps)


def test_assert_budget_fails_closed_when_epsilon_is_mutated_to_nan() -> None:
    accountant = PrivacyAccountant(epsilon=1.0, delta=1e-5)
    accountant.spend(sensitivity=1.0, sigma=1.0)
    accountant.epsilon = math.nan

    with pytest.raises(PrivacyBudgetExhausted):
        accountant.assert_budget()


def test_spend_and_assert_raises_when_step_exceeds_budget() -> None:
    accountant = PrivacyAccountant(epsilon=1.0, delta=1e-5)

    with pytest.raises(PrivacyBudgetExhausted):
        accountant.spend_and_assert(sensitivity=1.0, sigma=0.1)

    # The mechanism ran, so its cost stays recorded and the gate stays shut.
    assert accountant.summary()["num_mechanism_invocations"] == 1
    with pytest.raises(PrivacyBudgetExhausted):
        accountant.assert_budget()


@pytest.mark.parametrize(
    ("sensitivity", "sigma", "sample_rate"),
    [(math.nan, 1.0, 1.0), (1.0, math.nan, 1.0), (1.0, 1.0, math.nan), (1.0, math.inf, 1.0)],
)
def test_spend_and_assert_rejects_nonfinite_inputs(
    sensitivity: float, sigma: float, sample_rate: float
) -> None:
    accountant = PrivacyAccountant(epsilon=1.0, delta=1e-5)

    with pytest.raises(ValueError):
        accountant.spend_and_assert(sensitivity=sensitivity, sigma=sigma, sample_rate=sample_rate)
    assert accountant.summary()["num_mechanism_invocations"] == 0


def test_spend_and_assert_is_atomic_across_threads() -> None:
    """Concurrent callers may not all pass the gate on a stale view of the budget."""
    accountant = PrivacyAccountant(epsilon=1.0, delta=1e-5)
    sigma = accountant.required_sigma(sensitivity=1.0)
    workers = 8
    barrier = threading.Barrier(workers)
    passed: list[int] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        try:
            accountant.spend_and_assert(sensitivity=1.0, sigma=sigma)
        except PrivacyBudgetExhausted:
            return
        with lock:
            passed.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # sigma certifies exactly one step within the budget.
    assert len(passed) == 1


# ---------------------------------------------------------------------------
# swarm_ode (torch-only): drand binding, ODE BODES flag, vectorised sampling
# ---------------------------------------------------------------------------


def _drand_response(payload: dict[str, object]):
    return io.BytesIO(json.dumps(payload).encode())


def _valid_beacon(round_number: int) -> dict[str, object]:
    signature = bytes(range(48)) + round_number.to_bytes(48, "big")
    return {
        "round": round_number,
        "randomness": hashlib.sha256(signature).hexdigest(),
        "signature": signature.hex(),
        "previous_signature": "",
    }


@requires_torch
def test_drand_rejects_randomness_not_bound_to_signature() -> None:
    from constitutional_swarm.swarm_ode import DrandClient

    beacon = _valid_beacon(1000)
    beacon["randomness"] = "00" * 32
    with patch("urllib.request.urlopen", return_value=_drand_response(beacon)):
        with pytest.raises(RuntimeError, match="randomness"):
            DrandClient().at_round(1000)


@requires_torch
def test_drand_rejects_missing_signature() -> None:
    from constitutional_swarm.swarm_ode import DrandClient

    beacon = _valid_beacon(1000)
    del beacon["signature"]
    with patch("urllib.request.urlopen", return_value=_drand_response(beacon)):
        with pytest.raises(RuntimeError, match="signature"):
            DrandClient().at_round(1000)


@requires_torch
def test_drand_rejects_round_other_than_requested() -> None:
    from constitutional_swarm.swarm_ode import DrandClient

    with patch("urllib.request.urlopen", return_value=_drand_response(_valid_beacon(999))):
        with pytest.raises(RuntimeError, match="round"):
            DrandClient().at_round(1000)


@requires_torch
def test_drand_accepts_bound_entry_and_documents_unauthenticated() -> None:
    from constitutional_swarm.swarm_ode import DrandClient

    beacon = _valid_beacon(1000)
    with patch("urllib.request.urlopen", return_value=_drand_response(beacon)):
        entry = DrandClient().at_round(1000)

    assert entry.round_number == 1000
    assert entry.randomness_hex == beacon["randomness"]
    doc = DrandClient.__doc__ or ""
    assert "unauthenticated" in doc.lower()
    assert "publicly verifiable" not in doc.lower()


@requires_torch
def test_ode_snapshots_do_not_claim_bodes_passage() -> None:
    import torch

    from constitutional_swarm.merkle_crdt import MerkleCRDT
    from constitutional_swarm.swarm_ode import StationaryField, integrate

    crdt = MerkleCRDT(agent_id="ode-c31")
    integrate(
        StationaryField(torch.zeros(3, 3)),
        torch.eye(3) * 0.5,
        n_steps=4,
        record_every=2,
        crdt=crdt,
    )

    nodes = crdt.topological_order()
    assert nodes
    assert not any(node.bodes_passed for node in nodes)


@requires_torch
def test_sample_tensor_does_not_fall_back_to_per_element_scan() -> None:
    from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

    sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=6, seed=3)
    with patch.object(
        DiscreteGaussianSampler, "sample", side_effect=AssertionError("per-element scan")
    ):
        values = sampler.sample_tensor((64,))

    assert values.shape == (64,)
    assert all(float(v).is_integer() and -6 <= v <= 6 for v in values.tolist())


@requires_torch
def test_vectorised_sampler_matches_pmf_and_replays() -> None:
    from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

    a = DiscreteGaussianSampler(sigma=2.0, tail_bound=12, seed=11)
    b = DiscreteGaussianSampler(sigma=2.0, tail_bound=12, seed=11)
    draws = a.sample_vector(20_000)

    assert draws == b.sample_vector(20_000)
    assert all(isinstance(x, int) and -12 <= x <= 12 for x in draws)
    mean = sum(draws) / len(draws)
    var = sum(x * x for x in draws) / len(draws) - mean * mean
    assert abs(mean) < 0.1
    assert var == pytest.approx(4.0, rel=0.1)
    assert isinstance(a.sample(), int)


# ---------------------------------------------------------------------------
# L3 (r1): seed material keeps full entropy through child derivation
# ---------------------------------------------------------------------------


@requires_torch
@pytest.mark.parametrize("high_bit", [32, 40, 63, 100])
def test_child_noise_differs_for_seeds_differing_only_above_bit_32(high_bit: int) -> None:
    from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

    base = 0x1234_5678
    a = DiscreteGaussianSampler(sigma=1.0, seed=base)
    b = DiscreteGaussianSampler(sigma=1.0, seed=base | (1 << high_bit))

    noise_a = a.sensitivity_clipped_noise((256,), sensitivity=2.0)
    noise_b = b.sensitivity_clipped_noise((256,), sensitivity=2.0)

    assert not bool((noise_a == noise_b).all())


@requires_torch
def test_child_noise_replays_for_the_same_seed() -> None:
    from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

    seed = (1 << 127) | 0xDEAD_BEEF
    a = DiscreteGaussianSampler(sigma=1.5, seed=seed)
    b = DiscreteGaussianSampler(sigma=1.5, seed=seed)
    first = [a.sensitivity_clipped_noise((64,), sensitivity=3.0) for _ in range(3)]
    second = [b.sensitivity_clipped_noise((64,), sensitivity=3.0) for _ in range(3)]

    assert all(bool((x == y).all()) for x, y in zip(first, second, strict=True))
    assert not bool((first[0] == first[1]).all())


@requires_torch
def test_drand_private_seed_entropy_above_bit_32_and_64_is_not_discarded() -> None:
    from constitutional_swarm.swarm_ode import DrandBeaconEntry, DrandClient

    entry = DrandBeaconEntry(
        round_number=7, randomness_hex="ab" * 32, signature_hex="", previous_sig_hex=""
    )
    client = DrandClient()
    private = (1 << 120) | 0xFEED
    with patch.object(DrandClient, "at_round", return_value=entry):
        s1, _ = client.seeded_sampler(sigma=1.0, round_number=7, private_seed=private)
        s2, _ = client.seeded_sampler(
            sigma=1.0, round_number=7, private_seed=private ^ (1 << 40)
        )
        s3, _ = client.seeded_sampler(sigma=1.0, round_number=7, private_seed=private)

    v1 = s1.sensitivity_clipped_noise((128,), sensitivity=2.0)
    v2 = s2.sensitivity_clipped_noise((128,), sensitivity=2.0)
    v3 = s3.sensitivity_clipped_noise((128,), sensitivity=2.0)
    assert not bool((v1 == v2).all())
    assert bool((v1 == v3).all())


@requires_torch
@pytest.mark.parametrize("bad_seed", [-1, True, 1.5])
def test_sampler_rejects_ambiguous_seed_material(bad_seed: object) -> None:
    from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

    with pytest.raises(ValueError, match="seed"):
        DiscreteGaussianSampler(sigma=1.0, seed=bad_seed)  # type: ignore[arg-type]
