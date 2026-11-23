"""Certified conservative spectral-sphere bound & independent NumPy SVD oracle tests."""

from __future__ import annotations

import math
import random
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from constitutional_swarm.spectral_sphere import (
    SpectralSphereManifold,
    spectral_norm_power_iter,
    spectral_sphere_project,
)


def _exact_svd_norm(matrix: tuple[tuple[float, ...], ...] | list[list[float]]) -> float:
    arr = np.asarray(matrix, dtype=np.float64)
    if arr.size == 0:
        return 0.0
    return float(np.linalg.svd(arr, compute_uv=False)[0])


def test_core_module_imports_zero_numpy_in_clean_subprocess() -> None:
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    code = (
        "import sys; "
        "import constitutional_swarm.spectral_sphere as ss; "
        "assert 'numpy' not in sys.modules, f'unexpected numpy import: {sys.modules.get(\"numpy\")}'; "
        "res = ss.spectral_sphere_project([[0.0, -2.0], [2.0, 0.0]], r=1.0); "
        "assert res.spectral_norm_upper_bound <= 1.0; "
        "assert 'numpy' not in sys.modules"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env={"PYTHONPATH": src_dir},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


@pytest.mark.parametrize(
    ("name", "matrix", "r", "max_iter"),
    [
        ("default_seed_orthogonal", [[0.0, 2.0], [-2.0, 0.0]], 1.0, 30),
        ("zero_iteration_now_rejected", None, None, None),
        ("small_radius", [[1e-8, 0.0], [0.0, 1e-8]], 1e-9, 30),
    ],
)
def test_appendix_a_counterexamples_are_eliminated(
    name: str,
    matrix: list[list[float]] | None,
    r: float | None,
    max_iter: int | None,
) -> None:
    if name == "zero_iteration_now_rejected":
        with pytest.raises(ValueError, match="positive integer"):
            spectral_sphere_project([[0.0, 2.0], [0.0, 0.0]], r=1.0, max_power_iter=0)
        return

    assert matrix is not None and r is not None and max_iter is not None
    result = spectral_sphere_project(matrix, r=r, max_power_iter=max_iter)
    exact = _exact_svd_norm(result.matrix)
    assert result.clipped is True
    assert result.spectral_norm_upper_bound <= r
    assert result.spectral_norm <= r
    assert result.spectral_norm_estimate <= result.spectral_norm_upper_bound
    assert exact <= r


def test_analytical_diagonal_and_rank_one_bounds_match_exact() -> None:
    diag = [[3.5, 0.0, 0.0], [0.0, -1.25, 0.0], [0.0, 0.0, 0.5]]
    res = spectral_sphere_project(diag, r=1.0)
    assert res.clipped is True
    assert res.spectral_norm_upper_bound == pytest.approx(1.0, rel=1e-12, abs=1e-12)
    assert _exact_svd_norm(res.matrix) == pytest.approx(1.0, rel=1e-12, abs=1e-12)
    assert res.matrix[0][0] == pytest.approx(1.0, rel=1e-12)

    u = [3.0, -4.0, 0.0]
    v = [1.0, 2.0, -2.0]  # ||u||_2 = 5, ||v||_2 = 3 => exact sigma_max = 15
    rank1 = [[ui * vj for vj in v] for ui in u]
    res1 = spectral_sphere_project(rank1, r=1.0)
    assert res1.clipped is True
    assert res1.spectral_norm_upper_bound <= 1.0
    assert _exact_svd_norm(res1.matrix) <= 1.0


def test_scale_extremes_subnormals_overflow_and_mixed_scales() -> None:
    # Subnormals & tiny radius
    sub = [[1e-320, 0.0], [0.0, 1e-320]]
    sub_res = spectral_sphere_project(sub, r=1e-321)
    assert sub_res.clipped is True
    assert sub_res.spectral_norm_upper_bound <= 1e-321
    assert math.isfinite(sub_res.matrix[0][0])

    # Tiny positive eigenvalue scale invariant power iter (< 1e-14 previously returned 0.0!)
    assert spectral_norm_power_iter([[1e-10, 0.0], [0.0, 1e-10]]) == pytest.approx(
        1e-10, rel=1e-6
    )

    # Large finite scaled cleanly
    huge_diag = [[1e308, 0.0], [0.0, 1e308]]
    huge_res = spectral_sphere_project(huge_diag, r=1.0)
    assert huge_res.clipped is True
    assert huge_res.spectral_norm_upper_bound <= 1.0
    assert _exact_svd_norm(huge_res.matrix) == pytest.approx(1.0, rel=1e-12)

    # Extreme overflow where Frobenius/Holder/CW all overflow float64 -> fail closed
    with pytest.raises(ValueError, match="finite"):
        spectral_sphere_project([[1e308, 1e308], [1e308, 1e308]], r=1.0)

    # Mixed scales spanning 200+ orders of magnitude
    mixed = [[1e200, 1e-100], [1e-100, 1e200]]
    mixed_res = spectral_sphere_project(mixed, r=2.0)
    assert mixed_res.clipped is True
    assert mixed_res.spectral_norm_upper_bound <= 2.0
    assert mixed_res.matrix[0][0] == pytest.approx(2.0, rel=1e-6)


def test_boundary_degenerate_and_idempotency() -> None:
    # Near boundary
    near = [[1.0 + 1e-12, 0.0], [0.0, 1.0]]
    res = spectral_sphere_project(near, r=1.0)
    assert res.clipped is True
    assert res.spectral_norm_upper_bound <= 1.0
    assert _exact_svd_norm(res.matrix) <= 1.0

    # Near-degenerate singular values
    degen = [[1.0, 0.0], [0.0, 1.0 - 1e-12]]
    res_d = spectral_sphere_project(degen, r=1.0)
    assert res_d.clipped is False
    assert res_d.spectral_norm_upper_bound <= 1.0

    # Idempotency on random matrix
    rng = random.Random(2026)
    mat = [[rng.gauss(0.0, 3.0) for _ in range(6)] for _ in range(6)]
    first = spectral_sphere_project(mat, r=0.75)
    assert first.spectral_norm_upper_bound <= 0.75
    second = spectral_sphere_project([list(row) for row in first.matrix], r=0.75)
    assert second.clipped is False
    assert second.spectral_norm_upper_bound <= 0.75


@pytest.mark.parametrize(
    "bad_iter",
    [0, -1, -5, True, False, 1.5],  # type: ignore[list-item]
)
def test_rejects_invalid_max_iterations_and_power_iter(bad_iter: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        spectral_sphere_project([[1.0]], r=1.0, max_power_iter=bad_iter)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        spectral_norm_power_iter([[1.0]], max_iterations=bad_iter)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        SpectralSphereManifold(2, max_power_iter=bad_iter)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_r", [0.0, -1.0, float("nan"), float("inf"), True])
def test_rejects_invalid_radius_everywhere(bad_r: object) -> None:
    with pytest.raises(ValueError, match="r must be"):
        spectral_sphere_project([[1.0]], r=bad_r)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="r must be"):
        SpectralSphereManifold(2, r=bad_r)  # type: ignore[arg-type]


def test_random_matrix_families_against_numpy_svd_oracle() -> None:
    rng = random.Random(314159)
    np_rng = np.random.default_rng(314159)
    radii = (0.05, 0.5, 1.0, 2.5, 1e-6)

    for trial in range(250):
        n = (2, 3, 4, 6, 8, 10)[trial % 6]
        r = radii[trial % len(radii)]
        kind = trial % 5
        if kind == 0:
            mat = [[rng.gauss(0.0, 2.0) for _ in range(n)] for _ in range(n)]
        elif kind == 1:
            mat = [[rng.uniform(0.0, 1.0) for _ in range(n)] for _ in range(n)]
        elif kind == 2:
            # Skew-symmetric (orthogonal-like eigenvalues in +/- i*lambda pairs)
            mat = [[0.0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i + 1, n):
                    val = rng.gauss(0.0, 2.0)
                    mat[i][j] = val
                    mat[j][i] = -val
        elif kind == 3:
            q, _ = np.linalg.qr(np_rng.normal(size=(n, n)))
            mat = (2.0 * r * q).tolist()
        else:
            mat = [
                [rng.uniform(-3.0, 3.0) if rng.random() < 0.25 else 0.0 for _ in range(n)]
                for _ in range(n)
            ]

        res = spectral_sphere_project(mat, r=r, max_power_iter=30)
        exact = _exact_svd_norm(res.matrix)
        assert res.spectral_norm_upper_bound == res.spectral_norm
        assert res.spectral_norm_upper_bound <= r
        assert exact <= r
        assert res.spectral_norm_estimate <= res.spectral_norm_upper_bound + 1e-12
        assert exact <= res.spectral_norm_upper_bound + 1e-12


def test_manifold_ema_blend_is_recertified_and_summary_complete() -> None:
    m = SpectralSphereManifold(4, r=1.0, smoothing=0.9)
    m.update_trust_batch([(0, 1, 5.0), (1, 0, -5.0), (2, 3, 2.0)])
    m.update_trust_batch([(0, 2, 4.0), (3, 1, -4.0)])
    assert m.is_stable is True
    assert m.spectral_norm <= 1.0
    assert _exact_svd_norm(m.trust_matrix) <= 1.0
    summary = m.summary()
    assert summary["spectral_norm_upper_bound"] == summary["spectral_norm"]
    assert summary["spectral_norm_upper_bound"] <= 1.0
    assert summary["spectral_norm_estimate"] <= summary["spectral_norm_upper_bound"]
    assert summary["bound_method"] == "min(frobenius,sqrt(norm1*norm_inf),collatz_wielandt)"


def test_residual_compose_zero_counterexample_documented() -> None:
    """Confirm signed counterexample A=I, B=-(alpha/(1-alpha))*I collapses to zero."""
    alpha = 0.1
    scale = -alpha / (1.0 - alpha)
    a = SpectralSphereManifold(2, r=1.0, smoothing=0.0)
    b = SpectralSphereManifold(2, r=1.0, smoothing=0.0)
    a.replace_raw_trust([[1.0, 0.0], [0.0, 1.0]])
    b.replace_raw_trust([[scale, 0.0], [0.0, scale]])
    c = a.compose(b, residual_alpha=alpha)
    assert c.spectral_norm == pytest.approx(0.0, abs=1e-14)
    assert _exact_svd_norm(c.trust_matrix) == pytest.approx(0.0, abs=1e-14)
