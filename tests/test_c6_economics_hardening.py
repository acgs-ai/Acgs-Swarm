"""Regression coverage for C6 economics boundaries and authoritative scoring."""

from __future__ import annotations

import inspect
import math
import threading
from typing import Any

import pytest
from acgs_lite import Constitution

import constitutional_swarm.bittensor.emission_calculator as c6_emission_module
import constitutional_swarm.bittensor.map_elites as c6_map_module
import constitutional_swarm.bittensor.threshold_updater as c6_threshold_module
import constitutional_swarm.bittensor.tier_manager as c6_tier_module
import constitutional_swarm.bittensor.validator as c6_validator_module
from constitutional_swarm.bittensor.emission_calculator import (
    EmissionCalculator,
    EmissionWeights,
    MinerEmissionInput,
    _safe_normalize,
)
from constitutional_swarm.bittensor.map_elites import (
    DeliberationStrategy,
    FitnessWeights,
    GovernanceDomain,
    MinerApproach,
    MinerQualityGrid,
)
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord
from constitutional_swarm.bittensor.protocol import EscalationType, MinerTier, ValidatorConfig
from constitutional_swarm.bittensor.threshold_updater import (
    DEFAULT_WEIGHTS,
    BayesianThresholdUpdater,
    DimensionEvidence,
)
from constitutional_swarm.bittensor.tier_manager import (
    MinerPerformance,
    TaskComplexity,
    TierManager,
)
from constitutional_swarm.bittensor.validator import ConstitutionalValidator


def test_c6_tier_all_public_performance_records_are_detached_snapshots() -> None:
    manager = TierManager()

    registered = manager.register_miner("snapshot-miner", domains={"finance"})
    registered.judgments_validated = 999
    registered.domains.add("escaped-register")

    repeated = manager.register_miner("snapshot-miner")
    repeated.reputation = 2.0
    repeated.domains.add("escaped-repeat")

    fetched = manager.get_performance("snapshot-miner")
    assert fetched is not None
    fetched.current_tier = MinerTier.ELDER
    fetched.domains.add("escaped-get")

    listed = manager.all_miners[0]
    listed.judgments_rejected = 999
    listed.domains.add("escaped-all")

    manager.record_judgment(
        "snapshot-miner",
        accepted=True,
        domain="finance",
        reputation=1.3,
    )
    for _ in range(9):
        manager.record_judgment("snapshot-miner", accepted=True, domain="finance")

    eligible = manager.eligible_miners(TaskComplexity.MEDIUM)
    assert len(eligible) == 1
    eligible[0].domains.add("escaped-eligible")
    eligible[0].current_tier = MinerTier.ELDER

    actual = manager.get_performance("snapshot-miner")
    assert actual is not None
    assert actual.judgments_validated == 10
    assert actual.judgments_rejected == 0
    assert actual.reputation == pytest.approx(1.3)
    assert actual.current_tier == MinerTier.JOURNEYMAN
    assert actual.domains == {"finance"}


def test_c6_tier_snapshot_mutation_isolated_during_concurrent_updates() -> None:
    manager = TierManager()
    manager.register_miner("concurrent", domains={"finance"})
    manager.record_judgment(
        "concurrent",
        accepted=True,
        domain="finance",
        reputation=1.3,
    )
    errors: list[BaseException] = []

    def mutate_snapshots() -> None:
        try:
            for _ in range(100):
                snapshot = manager.get_performance("concurrent")
                assert snapshot is not None
                snapshot.judgments_validated = -10_000
                snapshot.domains.clear()
                for item in manager.all_miners:
                    item.reputation = 0.0
        except BaseException as exc:  # test thread must report assertion failures
            errors.append(exc)

    def record_updates() -> None:
        try:
            for _ in range(25):
                manager.record_judgment("concurrent", accepted=True, domain="finance")
        except BaseException as exc:  # test thread must report assertion failures
            errors.append(exc)

    threads = [threading.Thread(target=mutate_snapshots), threading.Thread(target=record_updates)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    actual = manager.get_performance("concurrent")
    assert actual is not None
    assert actual.judgments_validated == 26
    assert actual.reputation == pytest.approx(1.3)
    assert actual.domains == {"finance"}


def test_c6_tier_acceptance_gate_blocks_promotion_but_never_demotes() -> None:
    manager = TierManager(min_acceptance_rate=0.8)
    manager.register_miner("acceptance")

    for _ in range(3):
        manager.record_judgment("acceptance", accepted=False, reputation=1.3)
    for _ in range(11):
        manager.record_judgment("acceptance", accepted=True, reputation=1.3)

    below = manager.get_performance("acceptance")
    assert below is not None
    assert below.acceptance_rate < 0.8
    assert below.current_tier == MinerTier.APPRENTICE

    manager.record_judgment("acceptance", accepted=True, reputation=1.3)
    exact = manager.get_performance("acceptance")
    assert exact is not None
    assert exact.acceptance_rate == pytest.approx(0.8)
    assert exact.current_tier == MinerTier.JOURNEYMAN

    manager.record_judgment("acceptance", accepted=False, reputation=1.3)
    retained = manager.get_performance("acceptance")
    assert retained is not None
    assert retained.acceptance_rate < 0.8
    assert retained.current_tier == MinerTier.JOURNEYMAN


def test_c6_tier_existing_journeyman_with_ten_accepts_and_three_rejects_is_retained() -> None:
    manager = TierManager()
    manager.register_miner("journeyman")

    for _ in range(10):
        manager.record_judgment("journeyman", accepted=True, reputation=1.3)
    for _ in range(3):
        manager.record_judgment("journeyman", accepted=False, reputation=1.3)

    performance = manager.get_performance("journeyman")
    assert performance is not None
    assert performance.acceptance_rate == pytest.approx(10 / 13)
    assert performance.current_tier is MinerTier.JOURNEYMAN


def test_c6_tier_acceptance_policy_is_explicit_for_every_tier() -> None:
    from constitutional_swarm.bittensor.tier_manager import (
        TIER_PROMOTION_MIN_ACCEPTANCE_RATE,
    )

    assert set(TIER_PROMOTION_MIN_ACCEPTANCE_RATE) == set(MinerTier)
    assert TIER_PROMOTION_MIN_ACCEPTANCE_RATE == {
        MinerTier.APPRENTICE: 0.0,
        MinerTier.JOURNEYMAN: 0.8,
        MinerTier.MASTER: 0.8,
        MinerTier.ELDER: 0.8,
    }


def test_c6_tier_structural_reputation_failure_still_demotes() -> None:
    manager = TierManager()
    manager.register_miner("demote")
    for _ in range(10):
        manager.record_judgment("demote", accepted=True, reputation=1.3)

    event = manager.record_judgment("demote", accepted=True, reputation=0.9)

    assert event is not None
    assert event.to_tier is MinerTier.APPRENTICE


def test_c6_tier_rejected_judgment_does_not_establish_specialization() -> None:
    manager = TierManager()
    manager.register_miner("rejected-specialist")
    for _ in range(50):
        manager.record_judgment("rejected-specialist", accepted=True, reputation=1.6)

    manager.record_judgment(
        "rejected-specialist",
        accepted=False,
        domain="finance",
        reputation=1.6,
    )
    performance = manager.get_performance("rejected-specialist")
    assert performance is not None
    assert performance.domains == set()
    assert performance.current_tier == MinerTier.JOURNEYMAN


def test_c6_tier_elder_requires_specialist_and_precedent() -> None:
    manager = TierManager()
    manager.register_miner("elder-candidate", domains={"finance"})
    for _ in range(200):
        manager.record_judgment("elder-candidate", accepted=True, reputation=1.9)

    before_precedent = manager.get_performance("elder-candidate")
    assert before_precedent is not None
    assert before_precedent.current_tier == MinerTier.MASTER

    promotion = manager.record_precedent("elder-candidate")
    assert promotion is not None
    assert promotion.to_tier == MinerTier.ELDER

    manager.register_miner("non-specialist")
    for _ in range(200):
        manager.record_judgment("non-specialist", accepted=True, reputation=1.9)
    manager.record_precedent("non-specialist")
    non_specialist = manager.get_performance("non-specialist")
    assert non_specialist is not None
    assert non_specialist.current_tier == MinerTier.JOURNEYMAN


@pytest.mark.parametrize(
    "min_acceptance_rate",
    [-0.01, 0.0, 1.01, float("nan"), float("inf")],
)
def test_c6_tier_rejects_invalid_acceptance_policy(min_acceptance_rate: float) -> None:
    with pytest.raises((TypeError, ValueError)):
        TierManager(min_acceptance_rate=min_acceptance_rate)


def test_c6_tier_preserves_explicit_admin_initial_tier_override() -> None:
    manager = TierManager()

    registered = manager.register_miner("trusted-admin", initial_tier=MinerTier.ELDER)

    assert registered.current_tier is MinerTier.ELDER
    persisted = manager.get_performance("trusted-admin")
    assert persisted is not None
    assert persisted.current_tier is MinerTier.ELDER


@pytest.mark.parametrize(
    "kwargs",
    [
        {"judgments_validated": -1},
        {"judgments_rejected": -1},
        {"precedents_contributed": -1},
        {"reputation": -0.01},
        {"reputation": 2.01},
        {"reputation": float("nan")},
        {"avg_authenticity": -0.01},
        {"avg_authenticity": 1.01},
        {"avg_authenticity": float("inf")},
        {"first_seen_at": -1.0},
        {"last_active_at": float("nan")},
    ],
)
def test_c6_tier_performance_constructor_rejects_invalid_numeric_state(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        MinerPerformance("invalid", **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"accepted": 1},
        {"accepted": "yes"},
        {"accepted": True, "authenticity": -0.01},
        {"accepted": True, "authenticity": 1.01},
        {"accepted": True, "authenticity": float("nan")},
        {"accepted": True, "reputation": -0.01},
        {"accepted": True, "reputation": 2.01},
        {"accepted": True, "reputation": float("inf")},
    ],
)
def test_c6_tier_invalid_judgment_is_atomic(kwargs: dict[str, object]) -> None:
    manager = TierManager()
    manager.register_miner("atomic", domains={"finance"})
    before = manager.get_performance("atomic")

    with pytest.raises((TypeError, ValueError)):
        manager.record_judgment("atomic", **kwargs)

    assert manager.get_performance("atomic") == before


def test_c6_tier_invalid_judgment_does_not_auto_register() -> None:
    manager = TierManager()
    with pytest.raises((TypeError, ValueError)):
        manager.record_judgment("invalid-new", accepted=True, authenticity=float("nan"))
    assert manager.get_performance("invalid-new") is None


def test_c6_tier_zero_authenticity_participates_in_ema() -> None:
    manager = TierManager()
    manager.record_judgment("authenticity", accepted=True, authenticity=0.8)
    manager.record_judgment("authenticity", accepted=True, authenticity=0.0)

    performance = manager.get_performance("authenticity")
    assert performance is not None
    assert performance.avg_authenticity == pytest.approx(0.128)


def test_c6_tier_omitted_authenticity_does_not_change_ema() -> None:
    manager = TierManager()
    manager.record_judgment("authenticity", accepted=True, authenticity=0.8)
    measured = manager.get_performance("authenticity")
    assert measured is not None

    manager.record_judgment("authenticity", accepted=True)
    omitted = manager.get_performance("authenticity")
    assert omitted is not None
    assert omitted.avg_authenticity == pytest.approx(measured.avg_authenticity)

    manager.record_judgment("authenticity", accepted=True, authenticity=0.0)
    explicit_zero = manager.get_performance("authenticity")
    assert explicit_zero is not None
    assert explicit_zero.avg_authenticity < omitted.avg_authenticity

def _c6_write_constitution(tmp_path: Any, name: str = "c6-emissions") -> Any:
    path = tmp_path / f"{name}.yaml"
    path.write_text(
        """
name: c6-emissions
rules:
  - id: safety-01
    text: Do not cause physical harm
    severity: critical
    hardcoded: true
    keywords: [harm]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def _c6_make_validator(
    tmp_path: Any,
    *,
    use_manifold: bool = True,
) -> ConstitutionalValidator:
    return ConstitutionalValidator(
        ValidatorConfig(
            constitution_path=str(_c6_write_constitution(tmp_path)),
            peers_per_validation=3,
            quorum=2,
            use_manifold=use_manifold,
            complete_evidence=False,
            single_operator_dev=True,
        )
    )


class _C6StaticTrustManifold:
    def __init__(
        self,
        raw_trust: tuple[tuple[float, ...], ...] | None,
        *,
        projected: tuple[tuple[float, ...], ...] | None = None,
    ) -> None:
        if raw_trust is not None:
            self._raw_trust = raw_trust
        self.trust_matrix = projected if projected is not None else raw_trust


class TestC6EmissionInputValidation:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("manifold_trust", float("nan")),
            ("manifold_trust", float("inf")),
            ("manifold_trust", -0.01),
            ("reputation", float("nan")),
            ("reputation", float("inf")),
            ("reputation", -0.01),
            ("reputation", 2.01),
            ("avg_authenticity", float("nan")),
            ("avg_authenticity", float("inf")),
            ("avg_authenticity", -0.01),
            ("avg_authenticity", 1.01),
            ("precedent_contributions", -1),
            ("precedent_contributions", 1.5),
            ("precedent_contributions", True),
        ],
    )
    def test_c6_miner_input_rejects_invalid_numeric_values(
        self, field: str, value: float | bool
    ) -> None:
        with pytest.raises((TypeError, ValueError), match=field):
            MinerEmissionInput("miner", **{field: value})

    @pytest.mark.parametrize("value", [True, False, "1", object(), 10**1000])
    def test_c6_finite_validator_rejects_non_numeric_bool_and_float_overflow(
        self, value: object
    ) -> None:
        from constitutional_swarm.bittensor._validation import _validate_finite

        with pytest.raises(ValueError, match="signal"):
            _validate_finite("signal", value)  # type: ignore[arg-type]

    def test_c6_shared_numeric_validators_support_signed_and_bounded_values(self) -> None:
        from constitutional_swarm.bittensor._validation import (
            _validate_count,
            _validate_finite,
        )

        assert _validate_finite("signed", -2.5, minimum=None) == -2.5
        with pytest.raises(ValueError, match="default"):
            _validate_finite("default", -0.01)
        assert _validate_count("bounded", 3, maximum=3) == 3
        with pytest.raises(ValueError, match="at most 3"):
            _validate_count("bounded", 4, maximum=3)

    def test_c6_owned_modules_share_one_numeric_validation_implementation(self) -> None:
        from constitutional_swarm.bittensor import _validation

        for module in (
            c6_emission_module,
            c6_map_module,
            c6_threshold_module,
            c6_tier_module,
            c6_validator_module,
        ):
            assert module._validate_finite is _validation._validate_finite
        for module in (
            c6_emission_module,
            c6_map_module,
            c6_threshold_module,
            c6_tier_module,
        ):
            assert module._validate_count is _validation._validate_count

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"min_weight_fraction": float("nan")},
            {"min_weight_fraction": -0.01},
            {"min_weight_fraction": 1.01},
            {"max_weight_fraction": float("inf")},
            {"max_weight_fraction": 0.0},
            {"max_weight_fraction": 1.01},
        ],
    )
    def test_c6_calculator_rejects_invalid_configuration(self, kwargs: dict[str, float]) -> None:
        with pytest.raises(ValueError):
            EmissionCalculator(**kwargs)

    def test_c6_weight_components_reject_nan_before_sum_check(self) -> None:
        with pytest.raises(ValueError, match="manifold_trust"):
            EmissionWeights(
                manifold_trust=float("nan"),
                reputation=0.25,
                tier=0.20,
                precedent=0.15,
                authenticity=0.10,
            )

    def test_c6_compute_revalidates_mutable_inputs(self) -> None:
        miner = MinerEmissionInput("miner", reputation=1.0)
        miner.reputation = float("nan")

        with pytest.raises(ValueError, match="reputation"):
            EmissionCalculator().compute([miner])

    def test_c6_compute_rejects_duplicate_uids_before_dict_projection(self) -> None:
        with pytest.raises(ValueError, match="duplicate.*miner-1"):
            EmissionCalculator().compute(
                [MinerEmissionInput("miner-1"), MinerEmissionInput("miner-1", is_active=False)]
            )

    def test_c6_registered_set_is_copied_at_constructor_boundary(self) -> None:
        registered = {"registered"}
        calculator = EmissionCalculator(registered_miners=registered)
        registered.add("late-alias")

        weights = calculator.compute(
            [MinerEmissionInput("registered"), MinerEmissionInput("late-alias")]
        ).as_weight_dict()

        assert weights == {"registered": pytest.approx(1.0), "late-alias": 0.0}

    def test_c6_safe_normalize_avoids_overflow_for_large_finite_values(self) -> None:
        assert _safe_normalize([1e308, 1e308]) == [pytest.approx(0.5), pytest.approx(0.5)]


class TestC6EmissionBoundedSimplex:
    def test_c6_infeasible_configured_cap_is_relaxed_and_reported_for_two_miners(self) -> None:
        cycle = EmissionCalculator(max_weight_fraction=0.40).compute(
            [MinerEmissionInput("strong", reputation=2.0), MinerEmissionInput("weak", reputation=0.0)]
        )

        assert cycle.as_weight_dict() == {
            "strong": pytest.approx(0.5),
            "weak": pytest.approx(0.5),
        }
        assert cycle.configured_cap == pytest.approx(0.40)
        assert cycle.effective_cap == pytest.approx(0.50)
        assert cycle.cap_relaxed is True

    def test_c6_feasible_cap_and_floor_hold_without_post_normalization_violation(self) -> None:
        cycle = EmissionCalculator(
            min_weight_fraction=0.20, max_weight_fraction=0.40
        ).compute(
            [
                MinerEmissionInput(
                    "dominant",
                    tier=MinerTier.ELDER,
                    manifold_trust=10.0,
                    reputation=2.0,
                    precedent_contributions=100,
                    avg_authenticity=1.0,
                ),
                *[MinerEmissionInput(f"weak-{idx}", reputation=0.0) for idx in range(3)],
            ]
        )
        values = list(cycle.as_weight_dict().values())

        assert sum(values) == pytest.approx(1.0)
        assert min(values) >= 0.20 / 4 - 1e-9
        assert max(values) <= 0.40 + 1e-9
        assert cycle.configured_cap == pytest.approx(0.40)
        assert cycle.effective_cap == pytest.approx(0.40)
        assert cycle.cap_relaxed is False

    def test_c6_full_reserve_and_exact_feasible_cap_produce_uniform_simplex(self) -> None:
        cycle = EmissionCalculator(
            min_weight_fraction=1.0, max_weight_fraction=0.25
        ).compute(
            [
                MinerEmissionInput("dominant", reputation=2.0),
                MinerEmissionInput("zero-a", reputation=0.0),
                MinerEmissionInput("zero-b", reputation=0.0),
                MinerEmissionInput("zero-c", reputation=0.0),
            ]
        )
        assert list(cycle.as_weight_dict().values()) == [pytest.approx(0.25)] * 4


class TestC6ValidatorEmissionDelegation:
    def test_c6_validator_compute_method_does_not_read_mesh_private_state_directly(
        self,
    ) -> None:
        source = inspect.getsource(ConstitutionalValidator.compute_emission_weights)
        assert "mesh._" not in source

    def test_c6_validator_delegates_to_emission_calculator_with_real_mesh_snapshot(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha", tier=MinerTier.APPRENTICE)
        validator.register_miner("beta", tier=MinerTier.MASTER)
        validator.register_miner("gamma", tier=MinerTier.JOURNEYMAN)
        captured: dict[str, Any] = {}
        real_calculator = EmissionCalculator

        class C6SpyEmissionCalculator(real_calculator):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                captured["registered_miners"] = set(kwargs.get("registered_miners", set()))
                super().__init__(*args, **kwargs)

            def compute(self, inputs: list[MinerEmissionInput]):  # type: ignore[no-untyped-def]
                captured["inputs"] = list(inputs)
                return super().compute(inputs)

        monkeypatch.setattr(c6_validator_module, "EmissionCalculator", C6SpyEmissionCalculator)

        weights = validator.compute_emission_weights(["alpha", "beta", "gamma"])

        assert set(weights) == {"alpha", "beta", "gamma"}
        assert captured["registered_miners"] == {"alpha", "beta", "gamma"}
        inputs = {item.miner_uid: item for item in captured["inputs"]}
        assert set(inputs) == {"alpha", "beta", "gamma"}
        assert inputs["beta"].tier is MinerTier.MASTER
        assert all(item.precedent_contributions == 0 for item in inputs.values())
        assert all(item.avg_authenticity == 0.0 for item in inputs.values())

    def test_c6_unknown_explicit_uids_receive_zero_and_empty_request_stays_empty(
        self, tmp_path: Any
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("known")

        assert validator.compute_emission_weights([]) == {}
        assert validator.compute_emission_weights(["unknown"]) == {"unknown": 0.0}
        assert validator.compute_emission_weights(["known", "unknown"]) == {
            "known": pytest.approx(1.0),
            "unknown": 0.0,
        }

    def test_c6_validator_deduplicates_requested_uids_preserving_first_seen_order(
        self, tmp_path: Any
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("known")

        weights = validator.compute_emission_weights(
            ["known", "known", "unknown", "known", "unknown"]
        )

        assert list(weights) == ["known", "unknown"]
        assert weights == {"known": pytest.approx(1.0), "unknown": 0.0}

    def test_c6_real_birkhoff_raw_trust_changes_emission_weights(self, tmp_path: Any) -> None:
        with_manifold = _c6_make_validator(tmp_path, use_manifold=True)
        without_manifold = _c6_make_validator(tmp_path, use_manifold=False)
        for validator in (with_manifold, without_manifold):
            for uid in ("alpha", "beta", "gamma"):
                validator.register_miner(uid)

        mesh = with_manifold.mesh
        with mesh._lock:
            indices = dict(mesh._agent_indices)
            assert mesh._manifold is not None
            mesh._manifold.update_trust(indices["alpha"], indices["beta"], 5.0)
            mesh._manifold.update_trust(indices["gamma"], indices["beta"], 3.0)
            mesh._manifold.update_trust(indices["alpha"], indices["gamma"], -4.0)

        manifold_weights = with_manifold.compute_emission_weights()
        baseline_weights = without_manifold.compute_emission_weights()

        assert manifold_weights != baseline_weights
        assert manifold_weights["beta"] > manifold_weights["gamma"]
        assert list(baseline_weights.values()) == [pytest.approx(1 / 3)] * 3

    @pytest.mark.parametrize("raw_trust", [None, ((0.0, 0.0), (0.0, 0.0))])
    def test_c6_missing_or_constant_raw_trust_drops_manifold_coefficient(
        self,
        tmp_path: Any,
        monkeypatch: pytest.MonkeyPatch,
        raw_trust: tuple[tuple[float, ...], ...] | None,
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")
        mesh = validator.mesh
        with mesh._lock:
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                raw_trust,
                projected=((0.5, 0.5), (0.5, 0.5)),
            )
        captured: dict[str, EmissionWeights] = {}
        real_calculator = EmissionCalculator

        class C6WeightSpy(real_calculator):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                captured["weights"] = self._weights

        monkeypatch.setattr(c6_validator_module, "EmissionCalculator", C6WeightSpy)

        weights = validator.compute_emission_weights()

        assert captured["weights"].manifold_trust == 0.0
        effective = captured["weights"]
        assert (
            effective.manifold_trust
            + effective.reputation
            + effective.tier
            + effective.precedent
            + effective.authenticity
        ) == pytest.approx(1.0)
        assert list(weights.values()) == [pytest.approx(0.5)] * 2

    def test_c6_raw_trust_normalization_uses_full_mesh_before_requested_subset(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")
        validator.mesh.register_local_signer("mesh-only")
        mesh = validator.mesh
        with mesh._lock:
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                ((-3.0, 0.0, 3.0), (-3.0, 0.0, 3.0), (0.0, 0.0, 0.0)),
                projected=((1 / 3, 1 / 3, 1 / 3),) * 3,
            )
        captured: dict[str, Any] = {}
        real_calculator = EmissionCalculator

        class C6InputSpy(real_calculator):
            def compute(self, inputs: list[MinerEmissionInput]):  # type: ignore[no-untyped-def]
                captured["inputs"] = list(inputs)
                return super().compute(inputs)

        monkeypatch.setattr(c6_validator_module, "EmissionCalculator", C6InputSpy)

        validator.compute_emission_weights(["alpha", "beta"])

        inputs = {item.miner_uid: item for item in captured["inputs"]}
        assert inputs["alpha"].manifold_trust == pytest.approx(0.0)
        assert inputs["beta"].manifold_trust == pytest.approx(2 / 3)

    def test_c6_trust_uses_mesh_identity_map_after_churn_and_external_registration(
        self, tmp_path: Any
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        for uid in ("alpha", "beta", "gamma", "delta"):
            validator.register_miner(uid)
        validator.mesh.register_local_signer("mesh-only")
        validator.unregister_miner("alpha")
        validator.register_miner("alpha")

        mesh = validator.mesh
        with mesh._lock:
            indices = dict(mesh._agent_indices)
            size = len(indices)
            received = {uid: 0.1 for uid in indices}
            received["beta"] = 5.0
            matrix = [[0.0] * size for _ in range(size)]
            for uid, index in indices.items():
                matrix[0][index] = received[uid]
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                tuple(tuple(row) for row in matrix),
                projected=tuple(tuple(1.0 / size for _ in range(size)) for _ in range(size)),
            )

        weights = validator.compute_emission_weights()

        assert set(weights) == {"alpha", "beta", "gamma", "delta"}
        assert "mesh-only" not in weights
        assert all(weights["beta"] > weights[uid] for uid in ("alpha", "gamma", "delta"))

    def test_c6_constitution_rotation_rebuilds_registry_snapshot_without_guessing_order(
        self, tmp_path: Any
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        for uid in ("alpha", "beta", "gamma"):
            validator.register_miner(uid)

        validator.rotate_constitution(
            Constitution.from_yaml(_c6_write_constitution(tmp_path, "c6-emissions-rotated"))
        )
        validator.mesh.register_local_signer("mesh-only-after-rotation")

        weights = validator.compute_emission_weights()
        assert set(weights) == {"alpha", "beta", "gamma"}
        assert sum(weights.values()) == pytest.approx(1.0)
        assert "mesh-only-after-rotation" not in weights

    @pytest.mark.parametrize(
        "matrix",
        [
            ((0.5, 0.5), (1.0,)),
            ((float("nan"), 0.5), (1.0, 0.5)),
            ((float("inf"), 0.5), (1.0, 0.5)),
        ],
    )
    def test_c6_validator_rejects_corrupt_manifold_matrix_snapshot(
        self,
        tmp_path: Any,
        matrix: tuple[tuple[float, ...], ...],
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")

        mesh = validator.mesh
        with mesh._lock:
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                matrix,
                projected=((0.5, 0.5), (0.5, 0.5)),
            )

        with pytest.raises(ValueError, match="trust|manifold"):
            validator.compute_emission_weights()

    def test_c6_validator_rejects_corruption_outside_requested_subset(
        self,
        tmp_path: Any,
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")

        mesh = validator.mesh
        with mesh._lock:
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                ((0.5, float("nan")), (0.5, -0.25)),
                projected=((0.5, 0.5), (0.5, 0.5)),
            )

        with pytest.raises(ValueError, match="trust|manifold"):
            validator.compute_emission_weights(["alpha"])

    @pytest.mark.parametrize(
        "indices",
        [
            {"alpha": 0, "beta": 0},
            {"alpha": 0, "beta": 2},
            {"alpha": True, "beta": 1},
        ],
    )
    def test_c6_validator_rejects_corrupt_manifold_index_snapshot(
        self,
        tmp_path: Any,
        indices: dict[str, int],
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")

        mesh = validator.mesh
        with mesh._lock:
            mesh._agent_indices = indices
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                ((0.5, 0.5), (0.5, 0.5)),
                projected=((0.5, 0.5), (0.5, 0.5)),
            )

        with pytest.raises(ValueError, match="index|indices|manifold"):
            validator.compute_emission_weights()

    def test_c6_validator_rejects_mesh_agent_index_key_mismatch(
        self,
        tmp_path: Any,
    ) -> None:
        validator = _c6_make_validator(tmp_path)
        validator.register_miner("alpha")
        validator.register_miner("beta")

        mesh = validator.mesh
        with mesh._lock:
            mesh._agent_indices = {"alpha": 0}
            mesh._manifold = _C6StaticTrustManifold(  # type: ignore[assignment]
                ((1.0,),),
                projected=((1.0,),),
            )

        with pytest.raises(ValueError, match="cover.*mesh agent"):
            validator.compute_emission_weights(["alpha"])


def test_c6_validator_stats_are_detached_and_summary_reads_internal_snapshot(
    tmp_path: Any,
) -> None:
    validator = _c6_make_validator(tmp_path)

    escaped = validator.stats
    escaped.validations_performed = 999
    escaped.judgments_accepted = 999

    assert validator.stats.validations_performed == 0
    assert validator.stats.judgments_accepted == 0
    assert validator.summary()["validator_stats"] == {
        "validations": 0,
        "accepted": 0,
        "rejected": 0,
        "acceptance_rate": 0.0,
        "avg_validation_ms": 0.0,
    }


_C6_HASH = "608508a9bd224290"
_C6_DIMS = tuple(DEFAULT_WEIGHTS)


def _c6_precedent(
    case_id: str,
    *,
    dimension: str = "security",
    score: float = 0.8,
) -> PrecedentRecord:
    impact = {name: 0.1 for name in _C6_DIMS}
    impact[dimension] = score
    return PrecedentRecord.create(
        case_id=case_id,
        task_id=f"task-{case_id}",
        miner_uid="miner-c6",
        judgment="Domain-neutral judgment text",
        reasoning="C6 regression evidence",
        votes_for=3,
        votes_against=0,
        proof_root_hash=f"proof-{case_id}",
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        impact_vector=impact,
        constitutional_hash=_C6_HASH,
        ambiguous_dimensions=(dimension,),
    )


def _c6_evidence(
    positive: str,
    negative: str,
    *,
    domain: str = "",
    cases: int = 10,
) -> list[DimensionEvidence]:
    evidence = []
    for dimension in _C6_DIMS:
        if dimension == positive:
            evidence.append(DimensionEvidence(dimension, domain, cases, float(cases), 0.0))
        elif dimension == negative:
            evidence.append(DimensionEvidence(dimension, domain, cases, 0.0, float(cases)))
        else:
            evidence.append(DimensionEvidence(dimension, domain, 0, 0.0, 0.0))
    return evidence


@pytest.mark.parametrize(
    "base_weights",
    [
        {"safety": float("nan")},
        {"safety": float("inf")},
        {"safety": -0.01},
        {"safety": 0.41},
        {"unknown": 0.1},
    ],
)
def test_c6_threshold_rejects_invalid_base_weights(base_weights: dict[str, float]) -> None:
    with pytest.raises((TypeError, ValueError)):
        BayesianThresholdUpdater(base_weights=base_weights)


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"max_shift_per_cycle": float("nan")}, ValueError),
        ({"max_shift_per_cycle": -0.01}, ValueError),
        ({"min_evidence_count": 0}, ValueError),
        ({"min_evidence_count": 1.5}, (TypeError, ValueError)),
        ({"confirmation_threshold": float("inf")}, ValueError),
        ({"confirmation_threshold": 1.01}, ValueError),
    ],
)
def test_c6_threshold_rejects_invalid_configuration(
    kwargs: dict[str, object], error: type[Exception] | tuple[type[Exception], ...]
) -> None:
    with pytest.raises(error):
        BayesianThresholdUpdater(**kwargs)


@pytest.mark.parametrize(
    "values",
    [
        ("security", "", 1, float("nan"), 0.0),
        ("security", "", 1, 0.0, float("inf")),
        ("security", "", 1, -1.0, 2.0),
        ("security", "", -1, 0.0, 0.0),
        ("not-a-dimension", "", 1, 1.0, 0.0),
    ],
)
def test_c6_threshold_rejects_invalid_evidence(values: tuple) -> None:
    with pytest.raises((TypeError, ValueError)):
        DimensionEvidence(*values)


def test_c6_threshold_domain_filter_requires_authoritative_metadata() -> None:
    updater = BayesianThresholdUpdater()
    records = [_c6_precedent("case-a"), _c6_precedent("case-b")]

    with pytest.raises(ValueError, match="case_domains"):
        updater.collect_evidence(records, domain="healthcare")


def test_c6_threshold_domain_filter_uses_case_metadata_only() -> None:
    updater = BayesianThresholdUpdater()
    healthcare = _c6_precedent("opaque-a", score=0.9)
    finance = _c6_precedent("opaque-b", score=0.1)
    metadata = {"opaque-a": "healthcare", "opaque-b": "finance"}

    hc = updater.collect_evidence(
        [healthcare, finance], domain="healthcare", case_domains=metadata
    )
    fi = updater.collect_evidence([healthcare, finance], domain="finance", case_domains=metadata)
    global_evidence = updater.collect_evidence([healthcare, finance])

    hc_security = next(item for item in hc if item.dimension == "security")
    fi_security = next(item for item in fi if item.dimension == "security")
    global_security = next(item for item in global_evidence if item.dimension == "security")
    assert (hc_security.total_cases, hc_security.confirmed_count, hc_security.overblown_count) == (
        1,
        1.0,
        0.0,
    )
    assert (fi_security.total_cases, fi_security.confirmed_count, fi_security.overblown_count) == (
        1,
        0.0,
        1.0,
    )
    assert global_security.total_cases == 2


def test_c6_threshold_full_scale_shifts_survive_projection_and_match_audit() -> None:
    updater = BayesianThresholdUpdater(max_shift_per_cycle=0.08, min_evidence_count=1)
    cycle = updater.update(_c6_evidence("safety", "security"))

    assert cycle.posterior_weights["safety"] == pytest.approx(0.28)
    assert cycle.posterior_weights["security"] == pytest.approx(0.12)
    assert sum(cycle.posterior_weights.values()) == pytest.approx(1.0)
    by_dimension = {item.dimension: item for item in cycle.updates}
    for dimension in _C6_DIMS:
        audit = by_dimension[dimension]
        assert audit.posterior == pytest.approx(cycle.posterior_weights[dimension])
        assert audit.shift == pytest.approx(audit.posterior - audit.prior)


def test_c6_threshold_audit_distinguishes_clamping_from_simplex_balancing() -> None:
    updater = BayesianThresholdUpdater(max_shift_per_cycle=0.08, min_evidence_count=1)
    cycle = updater.update([DimensionEvidence("safety", "", 10, 10.0, 0.0)])
    by_dimension = {item.dimension: item for item in cycle.updates}

    assert by_dimension["safety"].shift == pytest.approx(0.08)
    assert by_dimension["safety"].was_capped is False
    for dimension in set(_C6_DIMS) - {"safety"}:
        assert by_dimension[dimension].shift < 0.0
        assert by_dimension[dimension].was_capped is False
        assert "balanced" in by_dimension[dimension].explanation

    boundary_weights = dict.fromkeys(_C6_DIMS, 0.10)
    boundary_weights["safety"] = 0.40
    bounded = BayesianThresholdUpdater(
        base_weights=boundary_weights,
        max_shift_per_cycle=0.08,
        min_evidence_count=1,
    ).update([DimensionEvidence("safety", "", 10, 10.0, 0.0)])
    bounded_safety = next(item for item in bounded.updates if item.dimension == "safety")
    assert bounded_safety.shift == pytest.approx(0.0)
    assert bounded_safety.was_capped is True
    assert "bounded" in bounded_safety.explanation


def test_c6_threshold_repeated_updates_preserve_all_invariants() -> None:
    updater = BayesianThresholdUpdater(max_shift_per_cycle=0.08, min_evidence_count=1)
    for index in range(30):
        positive = _C6_DIMS[index % len(_C6_DIMS)]
        negative = _C6_DIMS[(index + 1) % len(_C6_DIMS)]
        before = updater.weights()
        cycle = updater.update(_c6_evidence(positive, negative))
        after = cycle.posterior_weights
        assert sum(after.values()) == pytest.approx(1.0)
        assert all(0.02 <= value <= 0.40 for value in after.values())
        assert all(abs(after[name] - before[name]) <= 0.08 + 1e-12 for name in _C6_DIMS)


def test_c6_threshold_rejects_duplicate_or_cross_domain_evidence_atomically() -> None:
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    original = updater.weights("finance")
    duplicate = [
        DimensionEvidence("security", "finance", 2, 2.0, 0.0),
        DimensionEvidence("security", "finance", 2, 0.0, 2.0),
    ]
    with pytest.raises(ValueError):
        updater.update(duplicate, domain="finance")
    with pytest.raises(ValueError):
        updater.update(
            [DimensionEvidence("security", "healthcare", 2, 2.0, 0.0)],
            domain="finance",
        )
    assert updater.weights("finance") == original
    assert updater.all_cycles() == []


def test_c6_threshold_update_trusts_frozen_evidence_constructor_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    evidence = _c6_evidence("safety", "security")

    def fail_duplicate_validation(*args: object, **kwargs: object) -> None:
        raise AssertionError("update() duplicated DimensionEvidence numeric validation")

    monkeypatch.setattr(c6_threshold_module, "_validate_count", fail_duplicate_validation)
    monkeypatch.setattr(c6_threshold_module, "_validate_finite", fail_duplicate_validation)

    cycle = updater.update(evidence)
    assert cycle.posterior_weights["safety"] > cycle.prior_weights["safety"]


def test_c6_threshold_cycles_are_deeply_detached() -> None:
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    returned = updater.update(_c6_evidence("safety", "security"))
    expected = dict(returned.posterior_weights)
    returned.posterior_weights["safety"] = 999.0
    returned.evidence_summary.clear()

    first_snapshot = updater.all_cycles()
    assert first_snapshot[0].posterior_weights == expected
    assert first_snapshot[0].evidence_summary
    first_snapshot[0].prior_weights.clear()
    assert updater.all_cycles()[0].prior_weights


def _c6_approach(
    uid: str,
    *,
    fitness: float,
    acceptance: float,
    reasoning: float,
    speed_ms: float,
    samples: int = 10,
) -> MinerApproach:
    return MinerApproach(
        miner_uid=uid,
        domain=GovernanceDomain.SAFETY,
        strategy=DeliberationStrategy.HYBRID,
        fitness=fitness,
        acceptance_rate=acceptance,
        reasoning_quality=reasoning,
        speed_ms=speed_ms,
        sample_count=samples,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"fitness": float("nan")},
        {"fitness": float("inf")},
        {"fitness": 1.01},
        {"acceptance_rate": -0.01},
        {"acceptance_rate": float("nan")},
        {"reasoning_quality": 1.01},
        {"speed_ms": -1.0},
        {"speed_ms": float("inf")},
        {"sample_count": -1},
        {"sample_count": 1.5},
        {"timestamp": float("nan")},
    ],
)
def test_c6_map_rejects_invalid_approach_at_construction(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "miner_uid": "miner",
        "domain": GovernanceDomain.SAFETY,
        "strategy": DeliberationStrategy.HYBRID,
        "fitness": 0.5,
        "acceptance_rate": 0.5,
        "reasoning_quality": 0.5,
        "speed_ms": 100.0,
        "sample_count": 10,
    }
    values.update(overrides)
    with pytest.raises((TypeError, ValueError)):
        MinerApproach(**values)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"acceptance_weight": -0.1, "reasoning_weight": 0.5, "speed_weight": 0.6},
        {"acceptance_weight": float("nan")},
        {"acceptance_weight": 0.6, "reasoning_weight": 0.3, "speed_weight": 0.2},
        {"speed_baseline_ms": 0.0},
        {"min_samples": 0},
        {"min_samples": 1.5},
        {"min_samples": 2**31},
    ],
)
def test_c6_map_rejects_invalid_fitness_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        FitnessWeights(**kwargs)


def test_c6_map_near_unit_coefficients_stay_bounded_and_challenge_successfully() -> None:
    weights = FitnessWeights(
        acceptance_weight=0.5,
        reasoning_weight=0.3,
        speed_weight=0.2000000005,
    )
    grid = MinerQualityGrid(fitness_weights=weights)

    computed = grid.compute_fitness(1.0, 1.0, 0.0)
    assert math.isfinite(computed)
    assert 0.0 <= computed <= 1.0

    challenger = _c6_approach(
        "maximal",
        fitness=0.0,
        acceptance=1.0,
        reasoning=1.0,
        speed_ms=0.0,
    )
    assert grid.challenge(challenger) is True
    incumbent = grid.best_for(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
    assert incumbent is not None
    assert incumbent.fitness == pytest.approx(1.0)


@pytest.mark.parametrize("ceiling_window", [0, -1, 1.5])
def test_c6_map_rejects_invalid_ceiling_window(ceiling_window: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        MinerQualityGrid(ceiling_window=ceiling_window)


def test_c6_map_recomputes_fitness_and_ignores_forged_scores() -> None:
    grid = MinerQualityGrid()
    weak_forged_high = _c6_approach(
        "weak", fitness=1.0, acceptance=0.1, reasoning=0.1, speed_ms=900.0
    )
    same_metrics_forged_low = _c6_approach(
        "same", fitness=0.0, acceptance=0.1, reasoning=0.1, speed_ms=900.0
    )
    truly_better_forged_low = _c6_approach(
        "better", fitness=0.0, acceptance=0.9, reasoning=0.9, speed_ms=100.0
    )

    assert grid.challenge(weak_forged_high) is True
    incumbent = grid.best_for(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
    assert incumbent is not None
    assert incumbent.fitness == pytest.approx(grid.compute_fitness(0.1, 0.1, 900.0))
    assert grid.challenge(same_metrics_forged_low) is False
    assert grid.challenge(truly_better_forged_low) is True
    incumbent = grid.best_for(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
    assert incumbent is not None
    assert incumbent.miner_uid == "better"
    assert incumbent.fitness == pytest.approx(grid.compute_fitness(0.9, 0.9, 100.0))


def test_c6_map_challenge_clamps_observed_speed_and_sample_count_before_storage() -> None:
    from constitutional_swarm.bittensor.map_elites import MAX_SAMPLE_COUNT

    grid = MinerQualityGrid()
    approach = _c6_approach(
        "bounded",
        fitness=0.0,
        acceptance=0.9,
        reasoning=0.8,
        speed_ms=1e30,
        samples=MAX_SAMPLE_COUNT + 10_000,
    )

    assert grid.challenge(approach) is True
    stored = grid.best_for(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
    assert stored is not None
    assert stored.speed_ms == pytest.approx(1000.0)
    assert stored.sample_count == MAX_SAMPLE_COUNT


def test_c6_map_challenge_revalidates_original_fitness_at_ingress() -> None:
    grid = MinerQualityGrid()
    approach = _c6_approach(
        "mutated",
        fitness=0.5,
        acceptance=0.9,
        reasoning=0.8,
        speed_ms=100.0,
    )
    object.__setattr__(approach, "fitness", float("nan"))

    with pytest.raises(ValueError, match="fitness"):
        grid.challenge(approach)


def test_c6_map_challenge_documents_validator_observed_measurement_boundary() -> None:
    doc = inspect.getdoc(MinerQualityGrid.challenge)
    assert doc is not None
    assert "validator-observed" in doc


@pytest.mark.parametrize(
    "values",
    [
        (float("nan"), 0.5, 100.0),
        (0.5, float("inf"), 100.0),
        (0.5, 0.5, -1.0),
    ],
)
def test_c6_map_compute_fitness_validates_ingress(values: tuple[float, float, float]) -> None:
    with pytest.raises(ValueError):
        MinerQualityGrid().compute_fitness(*values)


def test_c6_map_query_and_bonus_inputs_are_validated() -> None:
    grid = MinerQualityGrid()
    with pytest.raises((TypeError, ValueError)):
        grid.top_miners(n=-1)
    with pytest.raises((TypeError, ValueError)):
        grid.top_miners(n=1.5)
    with pytest.raises(ValueError):
        grid.exploration_bonus("miner", multiplier=float("nan"))
    with pytest.raises(ValueError):
        grid.exploration_bonus("miner", multiplier=0.99)


def test_c6_map_canonical_fitness_is_always_finite_and_bounded() -> None:
    grid = MinerQualityGrid()
    cases = ((0.0, 0.0, 0.0), (1.0, 1.0, 0.0), (1.0, 1.0, 1e30))
    for acceptance, reasoning, speed in cases:
        fitness = grid.compute_fitness(acceptance, reasoning, speed)
        assert math.isfinite(fitness)
        assert 0.0 <= fitness <= 1.0


def test_c6_emission_simultaneous_cap_and_floor_pressure_conserves_mass() -> None:
    cycle = EmissionCalculator(
        weights=EmissionWeights(1.0, 0.0, 0.0, 0.0, 0.0),
        min_weight_fraction=0.96,
        max_weight_fraction=0.30,
    ).compute([
        MinerEmissionInput(str(i), manifold_trust=trust)
        for i, trust in enumerate((0.5, 0.49, 0.005, 0.005))
    ])
    assert cycle.weight_sum == pytest.approx(1.0, abs=1e-12)
    assert all(0.24 <= row.emission_weight <= 0.30 for row in cycle.emissions)


def test_c6_emission_summary_reports_cap_relaxation() -> None:
    cycle = EmissionCalculator().compute([MinerEmissionInput("only")])
    summary = cycle.summary()
    assert summary["configured_cap"] == 0.40
    assert summary["effective_cap"] == 1.0
    assert summary["cap_relaxed"] is True
