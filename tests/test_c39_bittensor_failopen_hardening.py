"""C39 regression tests: bittensor fail-open defaults and scoring.

Each test feeds an invalid or adversarial input that the pre-C39 code accepted.
"""

from __future__ import annotations

import inspect
import math
from dataclasses import replace

import pytest

from constitutional_swarm.bittensor import emission_calculator, tier_manager
from constitutional_swarm.bittensor.compliance_certificate import (
    AuditPeriod,
    CertificateIssuer,
    ComplianceCertificate,
    ComplianceSnapshot,
    HashCommitmentProver,
    HMACProver,
    ProofType,
    ZKPStubProver,
)
from constitutional_swarm.bittensor.emission_calculator import (
    EmissionCalculator,
    EmissionCycle,
    EmissionWeights,
    MinerEmission,
    MinerEmissionInput,
)
from constitutional_swarm.bittensor.island_evolution import (
    EmissionEvolver,
    EmissionGenome,
    MinerQualityObservation,
    _spearman_rho,
)
from constitutional_swarm.bittensor.map_elites import (
    CellCoordinate,
    DeliberationStrategy,
    GovernanceDomain,
    MinerApproach,
    MinerQualityGrid,
)
from constitutional_swarm.bittensor.protocol import MinerTier
from constitutional_swarm.bittensor.tier_manager import TaskComplexity, TierManager

CONST_HASH = "608508a9bd224290"


def _snapshot() -> ComplianceSnapshot:
    return ComplianceSnapshot(
        total_decisions=100,
        passed_decisions=99,
        escalated_decisions=1,
        auto_resolved_decisions=0,
        constitutional_hash=CONST_HASH,
    )


class LegacyOnlyProver:
    """Implements only the snapshot-scoped legacy pair (pre-C39 Protocol)."""

    proof_type = ProofType.HMAC_SHA256

    def __init__(self) -> None:
        self._inner = HMACProver("secret")

    def prove(self, snapshot: ComplianceSnapshot, threshold: float, ch: str) -> str:
        return self._inner.prove(snapshot, threshold, ch)

    def verify(self, proof: str, snapshot: ComplianceSnapshot, threshold: float, ch: str) -> bool:
        return self._inner.verify(proof, snapshot, threshold, ch)


# ---------------------------------------------------------------------------
# bittensor-cert-1
# ---------------------------------------------------------------------------


def test_cert1_issuer_rejects_prover_without_certificate_scoped_methods() -> None:
    with pytest.raises(TypeError, match="prove_certificate"):
        CertificateIssuer("issuer", prover=LegacyOnlyProver())  # type: ignore[arg-type]


def test_cert1_issue_and_verify_have_no_legacy_snapshot_fallback() -> None:
    source = inspect.getsource(CertificateIssuer)
    assert "self._prover.prove(" not in source
    assert "self._prover.verify(" not in source


# ---------------------------------------------------------------------------
# bittensor-cert-2
# ---------------------------------------------------------------------------


def test_cert2_stub_prover_requires_explicit_insecure_opt_in() -> None:
    with pytest.raises(ValueError, match="allow_insecure_stub"):
        CertificateIssuer("issuer", prover=ZKPStubProver())


def test_cert2_stub_certificates_are_labelled_as_stub_not_hmac() -> None:
    issuer = CertificateIssuer("issuer", prover=ZKPStubProver(), allow_insecure_stub=True)
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    assert cert.proof_type is ProofType.ZKP_STUB
    assert issuer.summary()["proof_type"] == ProofType.ZKP_STUB.value


def test_cert2_constructor_proof_type_cannot_mislabel_the_prover() -> None:
    with pytest.raises(ValueError, match="proof_type"):
        CertificateIssuer(
            "issuer",
            prover=ZKPStubProver(),
            proof_type=ProofType.ZKP_NOIR,
            allow_insecure_stub=True,
        )
    with pytest.raises(ValueError, match="proof_type"):
        CertificateIssuer("issuer", secret_key="secret", proof_type=ProofType.ZKP_CIRCOM)


def test_cert2_custom_prover_without_declared_proof_type_is_refused() -> None:
    class Undeclared:
        def prove(self, *_: object) -> str:
            return "p"

        def verify(self, *_: object) -> bool:
            return True

        def prove_certificate(self, _cert: ComplianceCertificate) -> str:
            return "p"

        def verify_certificate(self, _cert: ComplianceCertificate) -> bool:
            return True

    with pytest.raises(TypeError, match="proof_type"):
        CertificateIssuer("issuer", prover=Undeclared())  # type: ignore[arg-type]


def test_cert2_verify_rejects_certificate_with_foreign_proof_type() -> None:
    """A cert carrying a different proof_type than the pinned prover is refused,
    even when the proof itself recomputes (the prover binds what it is handed)."""

    class LabelBlindProver(HMACProver):
        """Validates only the HMAC over whatever cert it is given."""

    issuer = CertificateIssuer("issuer", prover=LabelBlindProver("secret"))
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    relabelled = replace(cert, proof_type=ProofType.ZKP_NOIR, proof="")
    relabelled = replace(relabelled, proof=LabelBlindProver("secret").prove_certificate(relabelled))
    assert LabelBlindProver("secret").verify_certificate(relabelled) is True

    assert issuer.verify(relabelled) is False


@pytest.mark.parametrize(
    ("prover", "expected"),
    [
        (HMACProver("s"), "hmac_sha256"),
        (HashCommitmentProver("s"), "hmac_sha256"),
        (ZKPStubProver(), "zkp_stub"),
    ],
)
def test_cert2_builtin_provers_declare_their_proof_type(
    prover: object, expected: str
) -> None:
    assert getattr(prover, "proof_type", None) is ProofType(expected)


# ---------------------------------------------------------------------------
# bittensor-rest-12
# ---------------------------------------------------------------------------


def test_rest12_compute_without_allowlist_fails_closed() -> None:
    calc = EmissionCalculator()
    with pytest.raises(ValueError, match="registered_miners"):
        calc.compute([MinerEmissionInput("sybil-1"), MinerEmissionInput("sybil-2")])


def test_rest12_explicit_opt_in_allows_unregistered() -> None:
    cycle = EmissionCalculator(allow_unregistered=True).compute(
        [MinerEmissionInput("a"), MinerEmissionInput("b")]
    )
    assert cycle.active_miners == 2


def test_rest12_allowlist_and_opt_in_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="allow_unregistered"):
        EmissionCalculator(registered_miners={"a"}, allow_unregistered=True)


def test_rest12_allow_unregistered_must_be_bool() -> None:
    with pytest.raises(TypeError, match="allow_unregistered"):
        EmissionCalculator(allow_unregistered=1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# bittensor-rest-11
# ---------------------------------------------------------------------------


def test_rest11_unqualified_initial_tier_is_refused_by_default() -> None:
    mgr = TierManager()
    with pytest.raises(ValueError, match="admin_override"):
        mgr.register_miner("new", initial_tier=MinerTier.ELDER)
    assert mgr.get_performance("new") is None
    result = mgr.route_task("t", TaskComplexity.CONSTITUTIONAL)
    assert result.selected_miner is None


def test_rest11_admin_override_is_explicit_and_audited() -> None:
    mgr = TierManager()
    perf = mgr.register_miner("admin", initial_tier=MinerTier.ELDER, admin_override=True)
    assert perf.current_tier is MinerTier.ELDER
    log = mgr.promotion_log
    assert len(log) == 1
    assert log[0].to_tier is MinerTier.ELDER
    assert "admin_override" in log[0].reason


def test_rest11_record_precedent_requires_an_id() -> None:
    mgr = TierManager()
    mgr.register_miner("m")
    with pytest.raises(TypeError):
        mgr.record_precedent("m")  # type: ignore[call-arg]
    for bad in ("", "   ", 7, None):
        with pytest.raises((TypeError, ValueError)):
            mgr.record_precedent("m", bad)  # type: ignore[arg-type]


def test_rest11_record_precedent_deduplicates_per_precedent_id() -> None:
    mgr = TierManager()
    mgr.register_miner("m")
    mgr.record_precedent("m", "prec-1")
    mgr.record_precedent("m", "prec-1")
    mgr.record_precedent("m", " prec-1 ")
    perf = mgr.get_performance("m")
    assert perf is not None
    assert perf.precedents_contributed == 1


def test_rest11_precedent_cannot_be_credited_to_two_miners() -> None:
    mgr = TierManager()
    mgr.register_miner("a")
    mgr.register_miner("b")
    mgr.record_precedent("a", "prec-1")
    with pytest.raises(ValueError, match="already credited"):
        mgr.record_precedent("b", "prec-1")


def test_rest11_record_precedent_does_not_auto_register_unknown_miners() -> None:
    mgr = TierManager()
    with pytest.raises(ValueError, match="not registered"):
        mgr.record_precedent("ghost", "prec-1")
    assert mgr.get_performance("ghost") is None


# ---------------------------------------------------------------------------
# bittensor-rest-14
# ---------------------------------------------------------------------------


def test_rest14_constant_predictor_has_zero_rank_correlation() -> None:
    assert _spearman_rho([0.0, 0.0, 0.0], [1.0, 2.0, 3.0]) == 0.0
    assert _spearman_rho([0.0, 0.0, 0.0], [3.0, 2.0, 1.0]) == 0.0


def test_rest14_ties_use_average_ranks() -> None:
    # x ranks: [1.5, 1.5, 3, 4]; y ranks: [1, 2, 3, 4] -> Pearson of ranks
    rho = _spearman_rho([1.0, 1.0, 2.0, 3.0], [1.0, 2.0, 3.0, 4.0])
    assert rho == pytest.approx(0.9486832980505138)


def _obs(uid: str, quality: float, reputation: float) -> MinerQualityObservation:
    return MinerQualityObservation(
        uid,
        consensus_quality=quality,
        acceptance_rate=quality,
        reputation=reputation,
        tier=MinerTier.APPRENTICE,
        precedent_contributions=0,
        manifold_trust=0.0,
    )


def test_rest14_two_observations_are_insufficient() -> None:
    evolver = EmissionEvolver(seed=1)
    genome = EmissionGenome("g", 1.0, 0.0, 0.0, 0.0, 0)
    obs = [_obs("a", 0.9, 2.0), _obs("b", 0.1, 1.0)]
    assert evolver.evaluate_genome(genome, obs) == 0.0
    with pytest.raises(ValueError, match="observations"):
        evolver.evolve_all(obs)


def test_rest14_global_best_is_rescored_on_new_observations() -> None:
    evolver = EmissionEvolver(seed=3, population_per_island=4)
    evolver.initialize_islands()
    aligned = [_obs("a", 0.9, 2.0), _obs("b", 0.5, 1.0), _obs("c", 0.1, 0.5)]
    evolver.evolve_all(aligned)
    best = evolver.active_genome
    assert best is not None
    inverted = [_obs("a", 0.1, 2.0), _obs("b", 0.5, 1.0), _obs("c", 0.9, 0.5)]
    evolver.evolve_all(inverted)
    current = evolver.active_genome
    assert current is not None
    assert evolver.summary()["global_best_fitness"] == pytest.approx(
        round(evolver.evaluate_genome(current, inverted), 4)
    )


# ---------------------------------------------------------------------------
# opt-1 / opt-2 / opt-3 / fsum
# ---------------------------------------------------------------------------


def test_opt1_tier_order_is_single_sourced() -> None:
    assert emission_calculator._TIER_ORDER is tier_manager._TIER_ORDER


def test_opt2_map_elites_history_removed_and_island_marked_experimental() -> None:
    assert not hasattr(MinerQualityGrid(), "_history")
    from constitutional_swarm.bittensor import island_evolution

    assert "EXPERIMENTAL" in (island_evolution.__doc__ or "")


def _approach(fitness_seed: float, uid: str = "m") -> MinerApproach:
    return MinerApproach(
        miner_uid=uid,
        domain=GovernanceDomain.SAFETY,
        strategy=DeliberationStrategy.HYBRID,
        fitness=0.0,
        acceptance_rate=fitness_seed,
        reasoning_quality=fitness_seed,
        speed_ms=100.0,
        sample_count=10,
    )


def test_opt3_challenge_log_is_bounded() -> None:
    grid = MinerQualityGrid(ceiling_window=3)
    for _ in range(50):
        grid.challenge(_approach(0.5))
    assert grid.summary()["total_challenges"] == 50
    coord = CellCoordinate(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
    assert grid.ceiling_for_cell(coord) is True
    assert grid.ceiling_detected() is True
    assert len(grid._challenge_log) <= 3  # type: ignore[attr-defined]


def test_fsum_cycle_weight_sum_is_exact() -> None:
    w = 0.1
    emissions = [MinerEmission(f"m{i}", w, w, 1.0, False, False) for i in range(10)]
    cycle = EmissionCycle(emissions, 10, 10, EmissionWeights())
    assert cycle.weight_sum == 1.0


def test_fsum_island_normalisation_sums_exactly_to_one() -> None:
    evolver = EmissionEvolver(seed=1)
    evolver._global_best = EmissionGenome("g", 0.1, 0.0, 0.0, 0.0, 0)
    obs = [_obs(f"m{i}", 0.5, 1.0) for i in range(10)]
    weights = evolver.compute_emission_weights(obs)
    assert math.fsum(weights.values()) == 1.0
    assert all(w == 0.1 for w in weights.values())
