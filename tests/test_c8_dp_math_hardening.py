"""Regression tests for C8 differential-privacy math hardening."""

from __future__ import annotations

import inspect
import math
import re
import sys
from importlib.util import find_spec
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import constitutional_swarm.privacy_accountant as privacy_accountant
from constitutional_swarm.privacy_accountant import (
    PrivacyAccountant,
    PrivacyBudgetExhausted,
)

_TORCH_AVAILABLE = find_spec("torch") is not None
if _TORCH_AVAILABLE:
    import torch

    import constitutional_swarm.swarm_ode as swarm_ode
    from constitutional_swarm.swarm_ode import (
        DiscreteGaussianSampler,
        add_dp_noise,
        calibrate_sigma,
        exact_spectral_project_torch,
        projected_rk4_step,
        spectral_project_torch,
    )
else:
    torch = None  # type: ignore[assignment]
    swarm_ode = None
    DiscreteGaussianSampler = Any  # type: ignore[misc,assignment]
    add_dp_noise = None
    calibrate_sigma = None
    exact_spectral_project_torch = None
    projected_rk4_step = None
    spectral_project_torch = None


def _analytic_gaussian_delta(epsilon: float, sensitivity: float, sigma: float) -> float:
    """Return the exact Gaussian-mechanism delta using only ``math.erfc``."""
    mu = sensitivity / sigma

    def normal_cdf(value: float) -> float:
        return 0.5 * math.erfc(-value / math.sqrt(2.0))

    return normal_cdf(mu / 2.0 - epsilon / mu) - math.exp(epsilon) * normal_cdf(
        -mu / 2.0 - epsilon / mu
    )


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_exact_spectral_projection_certifies_seeded_property_grid() -> None:
    generator = torch.Generator().manual_seed(20261008)

    for index in range(200):
        dimension = 1 + index % 8
        dtype = torch.float32 if index % 2 else torch.float64
        radius = (0.125, 0.5, 1.0, 3.0)[index % 4]
        scale = (0.0, 0.1, 1.0, 10.0, 1_000.0)[index % 5]
        matrix = torch.randn(
            (dimension, dimension),
            dtype=dtype,
            generator=generator,
        ) * scale

        projected = exact_spectral_project_torch(matrix, r=radius)
        certified_norm = torch.linalg.svdvals(projected).amax().item()

        assert projected.shape == matrix.shape
        assert projected.dtype == matrix.dtype
        assert projected.device == matrix.device
        assert torch.isfinite(projected).all()
        assert certified_norm <= radius


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_exact_spectral_projection_handles_adversarial_zero_and_passthrough() -> None:
    adversarial = torch.diag(
        torch.tensor([1.0 + 2**-20, 1.0, 1.0 - 2**-20], dtype=torch.float64)
    )
    projected = exact_spectral_project_torch(adversarial, r=1.0)
    assert torch.linalg.svdvals(projected).amax().item() <= 1.0

    for matrix in (
        torch.zeros((3, 3), dtype=torch.float64),
        0.5 * torch.eye(3, dtype=torch.float64),
    ):
        passthrough = exact_spectral_project_torch(matrix, r=1.0)
        assert passthrough is matrix


@pytest.mark.parametrize(
    "matrix",
    [
        None,
        torch.ones(3) if _TORCH_AVAILABLE else None,
        torch.ones((2, 3)) if _TORCH_AVAILABLE else None,
        torch.empty((0, 0)) if _TORCH_AVAILABLE else None,
        torch.ones((2, 2), dtype=torch.int64) if _TORCH_AVAILABLE else None,
        torch.tensor([[math.nan]]) if _TORCH_AVAILABLE else None,
        torch.tensor([[math.inf]]) if _TORCH_AVAILABLE else None,
    ],
)
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_exact_spectral_projection_rejects_invalid_matrix(matrix: object) -> None:
    with pytest.raises((TypeError, ValueError), match="H|matrix|square|floating|finite|non-empty"):
        exact_spectral_project_torch(matrix)  # type: ignore[arg-type]


@pytest.mark.parametrize("radius", [0.0, -1.0, math.nan, math.inf, -math.inf, True, "1"])
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_exact_spectral_projection_rejects_invalid_radius(radius: object) -> None:
    with pytest.raises((TypeError, ValueError), match="r|radius"):
        exact_spectral_project_torch(torch.eye(2), r=radius)  # type: ignore[arg-type]


@pytest.mark.parametrize("alpha", [1.005, 1.01])
def test_custom_renyi_orders_above_one_calibrate_and_spend(alpha: float) -> None:
    accountant = PrivacyAccountant(epsilon=5_000.0, delta=1e-5, alphas=(alpha,))

    sigma = accountant.required_sigma(sensitivity=1.0)
    accountant.spend(sensitivity=1.0, sigma=sigma)
    accountant.assert_budget()

    converted, selected = privacy_accountant._rdp_to_epsilon_balle2020(
        [privacy_accountant._rdp_gaussian(alpha, sigma)],
        [alpha],
        1e-5,
    )
    assert math.isfinite(converted)
    assert selected == alpha
    assert accountant.summary()["epsilon_spent"] <= accountant.epsilon


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_maci_protocol_reference_implementation_executes_with_certified_projection() -> None:
    protocol = Path("docs/maci_dp_protocol.md").read_text(encoding="utf-8")
    implementation_section = protocol.split("## 7. Implementation Sketch", maxsplit=1)[1]
    match = re.search(r"```python\n(?P<code>.*?)\n```", implementation_section, re.DOTALL)
    assert match is not None

    namespace: dict[str, object] = {}
    exec(compile(match.group("code"), "docs/maci_dp_protocol.md", "exec"), namespace)
    broadcast = namespace["dp_broadcast_matrix"]
    with patch("numpy.random.normal", return_value=torch.zeros((2, 2)).numpy()):
        noisy, sigma = broadcast(  # type: ignore[operator]
            [[4.0, 3.0], [2.0, -5.0]],
            epsilon=8.0,
        )

    assert len(noisy) == 2
    assert all(len(row) == 2 for row in noisy)
    assert math.isfinite(sigma) and sigma > 0


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_default_sampler_uses_fresh_os_entropy_and_explicit_seed_replays() -> None:
    """Unseeded instances must not inherit torch.Generator's fixed default state."""
    with patch("secrets.randbits", side_effect=[0x1234, 0x5678]) as randbits:
        first = DiscreteGaussianSampler(sigma=1.0)
        second = DiscreteGaussianSampler(sigma=1.0)

    assert randbits.call_args_list == [((64,),), ((64,),)]
    assert first.sample_vector(32) != second.sample_vector(32)

    replay_a = DiscreteGaussianSampler(sigma=1.0, seed=8675309)
    replay_b = DiscreteGaussianSampler(sigma=1.0, seed=8675309)
    assert replay_a.sample_vector(64) == replay_b.sample_vector(64)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_unseeded_scaled_calls_each_receive_fresh_os_entropy() -> None:
    """Scaled child samplers must not fall back to torch's fixed default seed."""
    with patch("secrets.randbits", side_effect=[0x1111, 0x2222, 0x3333]) as randbits:
        sampler = DiscreteGaussianSampler(sigma=1.0)
        first = sampler.sensitivity_clipped_noise((32,), sensitivity=2.0)
        second = sampler.sensitivity_clipped_noise((32,), sensitivity=2.0)

    assert randbits.call_args_list == [((64,),), ((64,),), ((64,),)]
    assert not torch.equal(first, second)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_sampler_does_not_mutate_global_torch_rng_state() -> None:
    torch.manual_seed(8128)
    state_before = torch.random.get_rng_state().clone()

    sampler = DiscreteGaussianSampler(sigma=1.5, seed=99)
    sampler.sample_vector(16)
    sampler.sensitivity_clipped_noise((16,), sensitivity=2.0)

    assert torch.equal(torch.random.get_rng_state(), state_before)


@pytest.mark.parametrize("sigma,sensitivity", [(0.5, 0.25), (1.0, 2.0), (2.0, 5.0)])
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_scaled_sampler_recomputes_six_sigma_tail(sigma: float, sensitivity: float) -> None:
    """Sensitivity scaling must scale support along with the standard deviation."""
    parent = DiscreteGaussianSampler(sigma=sigma, tail_bound=6, seed=7)
    captured: list[DiscreteGaussianSampler] = []

    def capture(child: DiscreteGaussianSampler, shape: tuple[int, ...]) -> torch.Tensor:
        captured.append(child)
        return torch.zeros(shape)

    with patch.object(DiscreteGaussianSampler, "sample_tensor", autospec=True, side_effect=capture):
        parent.sensitivity_clipped_noise((2,), sensitivity=sensitivity)

    assert len(captured) == 1
    scaled = captured[0]
    assert scaled.sigma == pytest.approx(sigma * sensitivity)
    assert scaled.tail_bound >= math.ceil(6 * scaled.sigma)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_scaled_sampler_empirical_std_tracks_scaled_sigma() -> None:
    """The scaled distribution must not collapse against an inherited narrow support."""
    sampler = DiscreteGaussianSampler(sigma=2.0, tail_bound=6, seed=12345)
    samples = sampler.sensitivity_clipped_noise((4_000,), sensitivity=5.0)

    assert samples.std(unbiased=False).item() == pytest.approx(10.0, rel=0.25)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_smallest_positive_sigma_builds_a_valid_point_mass() -> None:
    sampler = DiscreteGaussianSampler(sigma=math.nextafter(0.0, 1.0), seed=1)

    assert sampler.pmf(0) == pytest.approx(1.0)
    assert sampler.sample_vector(8) == [0] * 8


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_unrepresentable_derived_support_fails_before_allocation() -> None:
    with pytest.raises(ValueError, match="support|tail"):
        DiscreteGaussianSampler(sigma=sys.float_info.max, seed=1)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_oversized_support_is_rejected_before_range_or_tensor_allocation() -> None:
    def allocation_reached(*args: object, **kwargs: object) -> None:
        raise AssertionError("support allocation was reached")

    with (
        patch.object(swarm_ode, "range", side_effect=allocation_reached, create=True),
        patch.object(swarm_ode.torch, "tensor", side_effect=allocation_reached),
    ):
        for arguments in (
            {"sigma": 1e8, "seed": 1},
            {"sigma": 1.0, "tail_bound": 500_001, "seed": 1},
        ):
            with pytest.raises(ValueError, match="support|table|resource"):
                DiscreteGaussianSampler(**arguments)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_huge_sigma_with_small_explicit_tail_remains_constructible() -> None:
    sampler = DiscreteGaussianSampler(sigma=sys.float_info.max, tail_bound=2, seed=1)

    assert sampler.tail_bound == 2
    assert sum(sampler.pmf(k) for k in range(-2, 3)) == pytest.approx(1.0)


@pytest.mark.parametrize("sensitivity", [0.1, 0.3, 1.0, 3.0])
def test_high_epsilon_calibration_fits_the_accountants_own_rdp_budget(
    sensitivity: float,
) -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)

    sigma = accountant.required_sigma(sensitivity=sensitivity)
    accountant.spend(sensitivity=sensitivity, sigma=sigma)
    accountant.assert_budget()

    assert math.isfinite(sigma) and sigma > 0.0
    assert accountant.summary()["epsilon_spent"] <= accountant.epsilon + 1e-10


@pytest.mark.parametrize("epsilon", [0.05, 0.1])
@pytest.mark.parametrize("delta", [1e-9, 1e-5])
def test_default_alpha_grid_certifies_common_small_budgets(
    epsilon: float,
    delta: float,
) -> None:
    accountant = PrivacyAccountant(epsilon=epsilon, delta=delta)

    sigma = accountant.required_sigma(sensitivity=1.0)
    accountant.spend(sensitivity=1.0, sigma=sigma)
    accountant.assert_budget()

    assert math.isfinite(sigma) and sigma > 0.0
    assert accountant.summary()["epsilon_spent"] <= epsilon + 1e-12
    assert max(accountant.alphas) >= 4096
    assert _analytic_gaussian_delta(epsilon, 1.0, sigma) <= delta * (1.0 + 1e-10)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_matrix_l2_sensitivity_matches_extremal_spectral_ball_matrices() -> None:
    matrix_l2_sensitivity = getattr(privacy_accountant, "matrix_l2_sensitivity")

    for certified_bound in (0.25, 1.0, 3.5):
        for matrix_dimension in (1, 2, 50):
            positive_extreme = certified_bound * torch.eye(
                matrix_dimension,
                dtype=torch.float64,
            )
            negative_extreme = -positive_extreme
            sensitivity = matrix_l2_sensitivity(
                certified_spectral_bound=certified_bound,
                matrix_dimension=matrix_dimension,
            )

            assert torch.linalg.matrix_norm(positive_extreme, ord=2).item() == pytest.approx(
                certified_bound
            )
            assert torch.linalg.matrix_norm(negative_extreme, ord=2).item() == pytest.approx(
                certified_bound
            )
            assert torch.linalg.vector_norm(positive_extreme - negative_extreme).item() == (
                pytest.approx(sensitivity)
            )
            assert sensitivity > 2.0 * (1.0 - 0.1) * certified_bound


@pytest.mark.parametrize(
    "certified_bound",
    [0.0, -1.0, math.nan, math.inf, -math.inf],
)
def test_matrix_l2_sensitivity_rejects_invalid_certified_bound(
    certified_bound: float,
) -> None:
    matrix_l2_sensitivity = getattr(privacy_accountant, "matrix_l2_sensitivity")

    with pytest.raises(ValueError, match="certified_spectral_bound"):
        matrix_l2_sensitivity(
            certified_spectral_bound=certified_bound,
            matrix_dimension=2,
        )


@pytest.mark.parametrize("matrix_dimension", [0, -1, True, 1.5])
def test_matrix_l2_sensitivity_rejects_invalid_matrix_dimension(
    matrix_dimension: object,
) -> None:
    matrix_l2_sensitivity = getattr(privacy_accountant, "matrix_l2_sensitivity")

    with pytest.raises(ValueError, match="matrix_dimension"):
        matrix_l2_sensitivity(
            certified_spectral_bound=1.0,
            matrix_dimension=matrix_dimension,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "certified_bound,matrix_dimension",
    [(sys.float_info.max, 2), (1.0, 10**1000)],
)
def test_matrix_l2_sensitivity_rejects_unrepresentable_result(
    certified_bound: float,
    matrix_dimension: int,
) -> None:
    matrix_l2_sensitivity = getattr(privacy_accountant, "matrix_l2_sensitivity")

    with pytest.raises(ValueError, match="finite|represent"):
        matrix_l2_sensitivity(
            certified_spectral_bound=certified_bound,
            matrix_dimension=matrix_dimension,
        )


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_calibrate_sigma_uses_explicit_matrix_l2_contract_and_accountant() -> None:
    certified_bound = 1.8
    matrix_dimension = 50
    epsilon = 1.0
    delta = 1e-5
    sensitivity = 2.0 * certified_bound * math.sqrt(matrix_dimension)
    expected = PrivacyAccountant(epsilon=epsilon, delta=delta).required_sigma(
        sensitivity=sensitivity
    )

    sigma = calibrate_sigma(
        certified_spectral_bound=certified_bound,
        matrix_dimension=matrix_dimension,
        epsilon=epsilon,
        delta=delta,
    )

    assert sigma == expected
    assert sensitivity > 2.0 * certified_bound


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_calibrate_sigma_contract_is_keyword_only_and_has_no_residual_discount() -> None:
    signature = inspect.signature(calibrate_sigma)

    assert list(signature.parameters) == [
        "certified_spectral_bound",
        "matrix_dimension",
        "epsilon",
        "delta",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    with pytest.raises(TypeError):
        calibrate_sigma(1.0, 2, 1.0, 1e-5)  # type: ignore[misc]


@pytest.mark.parametrize(
    "field,value",
    [
        ("certified_spectral_bound", math.nan),
        ("certified_spectral_bound", math.inf),
        ("certified_spectral_bound", -1.0),
        ("matrix_dimension", 0),
        ("matrix_dimension", True),
        ("epsilon", math.nan),
        ("epsilon", math.inf),
        ("epsilon", -1.0),
        ("delta", math.nan),
        ("delta", math.inf),
        ("delta", -1.0),
    ],
)
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_calibrate_sigma_rejects_invalid_contract_inputs(field: str, value: object) -> None:
    arguments: dict[str, object] = {
        "certified_spectral_bound": 1.0,
        "matrix_dimension": 2,
        "epsilon": 1.0,
        "delta": 1e-5,
    }
    arguments[field] = value

    with pytest.raises(ValueError, match=field):
        calibrate_sigma(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize("epsilon", [0.5, 1.0, 8.0, 100.0])
@pytest.mark.parametrize("delta", [1e-12, 1e-5, 0.1])
@pytest.mark.parametrize("sensitivity", [0.1, 1.0, 10.0])
@pytest.mark.parametrize("with_history", [False, True])
def test_calibration_grid_is_safe_or_fails_closed(
    epsilon: float,
    delta: float,
    sensitivity: float,
    with_history: bool,
) -> None:
    accountant = PrivacyAccountant(epsilon=epsilon, delta=delta)
    if with_history:
        accountant.spend(sensitivity=sensitivity, sigma=sensitivity * 1e6)

    sigma = accountant.required_sigma(sensitivity=sensitivity)
    assert math.isfinite(sigma) and sigma > 0.0
    accountant.spend(sensitivity=sensitivity, sigma=sigma)
    accountant.assert_budget()
    assert accountant.summary()["epsilon_spent"] <= epsilon + 1e-10

    if not with_history:
        assert _analytic_gaussian_delta(epsilon, sensitivity, sigma) <= delta * (1.0 + 1e-10)


@pytest.mark.parametrize("sensitivity", [math.nextafter(0.0, 1.0), sys.float_info.max])
def test_extreme_sensitivity_calibration_is_safe_or_fails_closed(sensitivity: float) -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)

    try:
        sigma = accountant.required_sigma(sensitivity=sensitivity)
    except PrivacyBudgetExhausted:
        return

    assert math.isfinite(sigma) and sigma > 0.0
    accountant.spend(sensitivity=sensitivity, sigma=sigma)
    accountant.assert_budget()


@pytest.mark.parametrize(
    "sensitivity,sigma",
    [(1e308, 5e-324), (5e-324, 1e308)],
)
def test_spend_rejects_unrepresentable_noise_multiplier(
    sensitivity: float,
    sigma: float,
) -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)

    with pytest.raises(ValueError, match="noise multiplier"):
        accountant.spend(sensitivity=sensitivity, sigma=sigma)


def test_next_step_calibration_composes_with_recorded_history() -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)
    fresh_sigma = accountant.required_sigma(sensitivity=1.0)
    accountant.spend(sensitivity=1.0, sigma=8.0)

    next_sigma = accountant.required_sigma(sensitivity=1.0)
    accountant.spend(sensitivity=1.0, sigma=next_sigma)
    accountant.assert_budget()

    assert next_sigma > fresh_sigma
    assert accountant.summary()["epsilon_spent"] <= accountant.epsilon + 1e-10


def test_calibration_fails_when_alpha_grid_cannot_certify_budget() -> None:
    accountant = PrivacyAccountant(epsilon=1.0, delta=1e-5, alphas=(2.0,))

    with pytest.raises(PrivacyBudgetExhausted, match="alpha|order|certif"):
        accountant.required_sigma(sensitivity=1.0)


@pytest.mark.parametrize("epsilon", [math.nan, math.inf, -math.inf])
def test_accountant_rejects_non_finite_epsilon(epsilon: float) -> None:
    with pytest.raises(ValueError, match="epsilon"):
        PrivacyAccountant(epsilon=epsilon, delta=1e-5)


@pytest.mark.parametrize("delta", [math.nan, math.inf, -math.inf])
def test_accountant_rejects_non_finite_delta(delta: float) -> None:
    with pytest.raises(ValueError, match="delta"):
        PrivacyAccountant(epsilon=1.0, delta=delta)


@pytest.mark.parametrize("alphas", [(math.nan,), (math.inf,), (1.0,), ()])
def test_accountant_rejects_invalid_alpha_grid(alphas: tuple[float, ...]) -> None:
    with pytest.raises(ValueError, match="alpha"):
        PrivacyAccountant(epsilon=1.0, delta=1e-5, alphas=alphas)


@pytest.mark.parametrize("sensitivity", [0.0, -1.0, math.nan, math.inf, -math.inf])
def test_required_sigma_rejects_invalid_sensitivity(sensitivity: float) -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)

    with pytest.raises(ValueError, match="sensitivity"):
        accountant.required_sigma(sensitivity=sensitivity)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sensitivity", math.nan),
        ("sensitivity", math.inf),
        ("sigma", math.nan),
        ("sigma", math.inf),
        ("sample_rate", math.nan),
    ],
)
def test_spend_rejects_non_finite_inputs(field: str, value: float) -> None:
    accountant = PrivacyAccountant(epsilon=8.0, delta=1e-5)
    arguments = {"sensitivity": 1.0, "sigma": 1.0, "sample_rate": 1.0}
    arguments[field] = value

    with pytest.raises(ValueError, match=field):
        accountant.spend(**arguments)


@pytest.mark.parametrize("sigma", [math.nan, math.inf, -math.inf])
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_sampler_rejects_non_finite_sigma(sigma: float) -> None:
    with pytest.raises(ValueError, match="sigma"):
        DiscreteGaussianSampler(sigma=sigma)


@pytest.mark.parametrize("tail_bound", [0, -1, 1.5, math.inf])
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_sampler_rejects_invalid_tail_bound(tail_bound: float) -> None:
    with pytest.raises(ValueError, match="tail_bound"):
        DiscreteGaussianSampler(sigma=1.0, tail_bound=tail_bound)  # type: ignore[arg-type]


@pytest.mark.parametrize("sigma", [math.nan, math.inf, -math.inf])
@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_add_dp_noise_rejects_non_finite_sigma(sigma: float) -> None:
    with pytest.raises(ValueError, match="sigma"):
        add_dp_noise(torch.zeros((2, 2)), sigma)


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_projected_rk4_docs_describe_residual_before_final_projection() -> None:
    module_doc = swarm_ode.__doc__ or ""
    function_doc = inspect.getdoc(projected_rk4_step) or ""

    assert "residual" in module_doc.lower()
    assert "final projection" in module_doc.lower()
    assert "residual" in function_doc.lower()
    assert "final projection" in function_doc.lower()


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_spectral_projection_docs_do_not_claim_power_iteration_certifies_dp_bound() -> None:
    doc = inspect.getdoc(spectral_project_torch) or ""

    assert "estimate" in doc.lower()
    assert "not" in doc.lower()
    assert "certif" in doc.lower()


@pytest.mark.skipif(not _TORCH_AVAILABLE, reason="torch not installed")
def test_sampler_docs_describe_float64_inverse_cdf_scan() -> None:
    doc = inspect.getdoc(DiscreteGaussianSampler) or ""

    assert "float64" in doc
    assert "inverse" in doc.lower()
    assert "cdf" in doc.lower()
    assert "searchsorted" in doc.lower()
    assert "alias method" not in doc.lower()
    assert "no floating-point" not in doc.lower()
    assert "distribution standard deviation" in doc.lower()
