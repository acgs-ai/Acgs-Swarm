"""
Spectral-Sphere Manifold — Path C replacement for the Birkhoff constraint.

The Birkhoff uniformity-collapse experiment iterates re-projected products of the form
`B[k + 1] = Sinkhorn(B[k] @ B[0])` via row/column normalization (`exp`-clamping), which
drives strictly positive doubly stochastic iterates toward the uniform matrix
`J = (1/N)·11ᵀ` (Perron–Frobenius eigenvector) in O(10) cycles. See
`test_manifold_degeneration.py` for the empirical baseline control.

This module replaces Sinkhorn projection with a **Spectral-Sphere projection** enforced
against a certified pure-Python conservative global upper bound:

    H_proj = H * min(1, r / sigma_bound(H))

where `sigma_max(H) <= sigma_bound(H)` is guaranteed mathematically in IEEE-754 arithmetic
without runtime external dependencies (no NumPy required). Because
`sigma_max(H_proj) <= sigma_bound(H_proj) <= r` holds globally, arbitrary sign patterns
(including explicit distrust via negative entries) and small radii remain bounded without
relying on uncertified power-iteration lower bounds or additive radius slack.

Theoretical grounding:
  - sHC paper (arXiv:2603.20896): spectral norm sphere as manifold constraint
  - mHC paper (arXiv:2512.24880): manifold constraints prevent signal explosion
  - MCFS Phase 2: non-Euclidean swarm topology for trust preservation

API mirrors GovernanceManifold so callers can swap in SpectralSphereManifold
while distinguishing:
  - ``spectral_norm_upper_bound`` (and legacy alias ``spectral_norm``): certified global
    conservative upper bound (`>= sigma_max(H)` and `<= r` after projection)
  - ``spectral_norm_estimate``: lower-bound power-iteration estimate (`<= sigma_max(H)`)
"""

from __future__ import annotations

import math
import random
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


_DEFAULT_BOUND_METHOD = "min(frobenius,sqrt(norm1*norm_inf),collatz_wielandt)"


@dataclass(frozen=True)
class SpectralProjectionResult:
    """Result of a spectral-sphere projection step.

    ``spectral_norm`` is the certified conservative global upper bound on ``sigma_max(matrix)``
    (aliased by ``spectral_norm_upper_bound``); it is NOT an exact singular value nor an
    optimistic power-iteration lower bound. ``spectral_norm_estimate`` records the scale-invariant
    power-iteration lower-bound estimate for diagnostics.
    """

    matrix: tuple[tuple[float, ...], ...]
    spectral_norm: float  # Certified conservative upper bound on sigma_max(matrix), <= r
    clipped: bool  # True if projection rescaled the matrix
    power_iterations: int
    spectral_norm_upper_bound: float = 0.0
    spectral_norm_estimate: float = 0.0
    bound_method: str = _DEFAULT_BOUND_METHOD

    def __post_init__(self) -> None:
        if self.spectral_norm_upper_bound == 0.0 and self.spectral_norm != 0.0:
            object.__setattr__(self, "spectral_norm_upper_bound", self.spectral_norm)


def _require_positive_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer (>= 1), got {value!r}")
    return value


def _require_non_negative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer (>= 0), got {value!r}")
    return value


def _require_positive_finite(value: float, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not (math.isfinite(value) and value > 0.0)
    ):
        raise ValueError(f"{name} must be a finite positive number, got {value!r}")
    return float(value)


def _mat_mul(a: list[list[float]], b: list[list[float]], n: int) -> list[list[float]]:
    """O(n³) matrix multiply — pure Python, no numpy required."""
    return [[math.fsum(a[i][k] * b[k][j] for k in range(n)) for j in range(n)] for i in range(n)]


def _mat_vec(m: Sequence[Sequence[float]], v: list[float], n: int) -> list[float]:
    """Matrix-vector product using full-precision fsum accumulation."""
    return [math.fsum(m[i][j] * v[j] for j in range(n)) for i in range(n)]


def _mat_T_vec(m: Sequence[Sequence[float]], v: list[float], n: int) -> list[float]:
    """Transpose-vector product (for power iteration on M^T * M)."""
    return [math.fsum(m[j][i] * v[j] for j in range(n)) for i in range(n)]


def _l2_norm_scaled(v: list[float]) -> float:
    """Overflow/underflow-safe Euclidean norm of a vector."""
    max_abs = 0.0
    for x in v:
        ax = abs(x)
        if ax > max_abs:
            max_abs = ax
    if max_abs == 0.0:
        return 0.0
    _, exp = math.frexp(max_abs)
    if exp == 0:
        sq_sum = math.fsum(x * x for x in v)
        return math.sqrt(sq_sum)
    scaled = [math.ldexp(x, -exp) for x in v]
    sq_sum = math.fsum(x * x for x in scaled)
    try:
        return math.ldexp(math.sqrt(sq_sum), exp)
    except OverflowError:
        return math.inf


def _validated_square_matrix(
    matrix: Sequence[Sequence[float]], n: int | None = None
) -> int:
    """Reject non-square, boolean, or non-finite matrices; return the dimension.

    Shared by the projection (verifier) and ``replace_raw_trust`` (builder) so a
    NaN/inf entry can never reach a projected result that claims a bound.
    """
    size = len(matrix) if n is None else n
    if len(matrix) != size or any(len(row) != size for row in matrix):
        raise ValueError(f"trust matrix must be square {size}x{size}")
    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(
                    f"trust matrix entries must be finite, got {value!r} at [{i}][{j}]"
                )
    return size


def _sum_up(vals: list[float]) -> float:
    """Exact-if-singleton, otherwise strictly upward-rounded sum of non-negative values."""
    nz = [v for v in vals if v != 0.0]
    if not nz:
        return 0.0
    if len(nz) == 1:
        return nz[0]
    s = math.fsum(nz)
    return math.nextafter(s, math.inf) if math.isfinite(s) else math.inf


def _mul_up(a: float, b: float) -> float:
    if a == 0.0 or b == 0.0:
        return 0.0
    prod = a * b
    return math.nextafter(prod, math.inf) if math.isfinite(prod) else math.inf


def _div_up(a: float, b: float) -> float:
    if a == 0.0:
        return 0.0
    quot = a / b
    return math.nextafter(quot, math.inf) if math.isfinite(quot) else math.inf


def _sqrt_up(a: float) -> float:
    if a == 0.0:
        return 0.0
    if not math.isfinite(a):
        return math.inf
    return math.nextafter(math.sqrt(a), math.inf)


def _collatz_wielandt_ub_scaled(abs_rows: list[list[float]], n: int) -> float:
    """Certified Collatz–Wielandt / Schur upper bound on ``sigma_max(M_s)``.

    Proof:
        Since ``M_s^T M_s`` is real symmetric PSD, ``sigma_max(M_s)^2 = rho(M_s^T M_s)``.
        For any strictly positive vector ``v > 0`` (``D = diag(v)``), similarity invariance
        and triangle inequality ``|(M_s^T M_s)_{ij}| <= (|M_s|^T |M_s|)_{ij}`` yield:

            sigma_max(M_s)^2 = rho(D^{-1} M_s^T M_s D)
                             <= ||D^{-1} |M_s|^T |M_s| D||_inf
                             = max_i ((|M_s|^T (|M_s| v))_i / v_i).

        This inequality holds for *every* positive ``v > 0``, independent of convergence.
        Power iterations only align ``v`` near the Perron vector to tighten the bound on
        non-negative matrices; the final upward-rounded evaluation guarantees soundness.
    """
    v = [1.0] * n
    for _ in range(10):
        mv = [math.fsum(abs_rows[i][j] * v[j] for j in range(n)) for i in range(n)]
        mtmv = [math.fsum(abs_rows[j][i] * mv[j] for j in range(n)) for i in range(n)]
        m = max(mtmv)
        if m == 0.0:
            return 0.0
        inv = 1.0 / m
        v_next = [max(x * inv, 1e-12) for x in mtmv]
        if max(abs(v_next[i] - v[i]) for i in range(n)) <= 1e-6:
            v = v_next
            break
        v = v_next

    mv_up = [_sum_up([_mul_up(abs_rows[i][j], v[j]) for j in range(n)]) for i in range(n)]
    ratios: list[float] = []
    for i in range(n):
        num = _sum_up([_mul_up(abs_rows[j][i], mv_up[j]) for j in range(n)])
        if num > 0.0:
            ratios.append(_div_up(num, v[i]))
    if not ratios:
        return 0.0
    max_r = max(ratios)
    return _sqrt_up(max_r)


def _conservative_spectral_upper_bound(matrix: Sequence[Sequence[float]]) -> float:
    """Pure-Python certified global upper bound on ``sigma_max(matrix)``.

    Combines Frobenius, Holder (``sqrt(||M||_1 * ||M||_inf)``), and Schur / Collatz–Wielandt
    (``min(F, H, CW)``) using exact ``math.frexp``/``math.ldexp`` power-of-2 exponent scaling
    and IEEE-754 upward rounding (`math.nextafter(..., math.inf)`). Raises ``ValueError``
    if the resulting certified upper bound overflows finite IEEE-754 ``float64``.
    """
    n = len(matrix)
    if n == 0:
        return 0.0

    max_abs = 0.0
    for row in matrix:
        for val in row:
            av = abs(float(val))
            if av > max_abs:
                max_abs = av
    if max_abs == 0.0:
        return 0.0

    _, exp = math.frexp(max_abs)
    abs_rows: list[list[float]] = []
    row_sums: list[float] = []
    col_buckets: list[list[float]] = [[] for _ in range(n)]
    sq_terms: list[float] = []
    max_row_nnz = 0
    max_col_nnz = [0] * n

    for i in range(n):
        arow: list[float] = []
        row_nz: list[float] = []
        for j in range(n):
            x = abs(float(matrix[i][j]))
            if x == 0.0:
                s = 0.0
            else:
                s = math.ldexp(x, -exp)
                if math.ldexp(s, exp) < x:
                    s = math.nextafter(s, math.inf)
                row_nz.append(s)
                col_buckets[j].append(s)
                max_col_nnz[j] += 1
                sq_terms.append(_mul_up(s, s))
            arow.append(s)
        if len(row_nz) > max_row_nnz:
            max_row_nnz = len(row_nz)
        abs_rows.append(arow)
        row_sums.append(_sum_up(row_nz))

    norm_inf_s = max(row_sums)
    norm_1_s = max(_sum_up(col) for col in col_buckets)

    if norm_1_s == norm_inf_s:
        holder_s = norm_1_s
    else:
        holder_s = _sqrt_up(_mul_up(norm_1_s, norm_inf_s))

    # Fast exact path for diagonal / monomial matrices where each row & column has <= 1 nonzero:
    # holder_s equals max_abs / 2**exp = exact sigma_max(M_s), so no tighter bound exists.
    if max_row_nnz <= 1 and max(max_col_nnz) <= 1:
        ub_s = holder_s
    else:
        frob_s = _sqrt_up(_sum_up(sq_terms))
        cw_s = _collatz_wielandt_ub_scaled(abs_rows, n)
        ub_s = min(frob_s, holder_s, cw_s)

    if not math.isfinite(ub_s):
        raise ValueError(
            "spectral norm upper bound is not finite; trust matrix entries are too large to project"
        )
    try:
        ub = math.ldexp(ub_s, exp)
    except OverflowError as exc:
        raise ValueError(
            "spectral norm upper bound is not finite; trust matrix entries are too large to project"
        ) from exc
    if not math.isfinite(ub):
        raise ValueError(
            "spectral norm upper bound is not finite; trust matrix entries are too large to project"
        )
    if ub < sys.float_info.min and ub_s > 0.0 and math.ldexp(ub, -exp) < ub_s:
        ub = math.nextafter(ub, math.inf)
    return ub


def spectral_norm_power_iter(
    matrix: list[list[float]],
    *,
    max_iterations: int = 30,
    seed: int = 0,
    tol: float = 1e-8,
) -> float:
    """Estimate a lower bound on ``sigma_max(matrix)`` via power iteration on ``M^T * M``.

    Note:
        Randomized power iteration is a **lower-bound estimate** (it can underestimate
        ``sigma_max`` if the starting vector is near-orthogonal to the leading right
        singular vector or if ``max_iterations`` is small). Use
        :func:`spectral_sphere_project` or ``spectral_norm_upper_bound`` for certified
        global containment.

    Scale-invariant via exact ``math.frexp``/``math.ldexp`` exponent normalization so
    entries spanning from subnormals (`1e-320`) to large finite values (`1e308`) avoid
    spurious underflow or intermediate overflow.
    """
    _require_positive_int(max_iterations, "max_iterations")
    _require_positive_finite(tol, "tol")
    n = _validated_square_matrix(matrix)
    if n == 0:
        return 0.0

    max_abs = max(abs(float(matrix[i][j])) for i in range(n) for j in range(n))
    if max_abs == 0.0:
        return 0.0

    _, exp = math.frexp(max_abs)
    # Keep matrix bit-identical when already well-scaled (exp == 0) so existing
    # canonical test vectors retain deterministic IEEE-754 parity.
    work_matrix: list[list[float]]
    if exp == 0:
        work_matrix = [[float(v) for v in row] for row in matrix]
    else:
        work_matrix = [[math.ldexp(float(v), -exp) for v in row] for row in matrix]

    rng = random.Random(seed)
    v = [rng.gauss(0, 1) for _ in range(n)]
    norm_v = _l2_norm_scaled(v)
    if norm_v == 0.0:
        return 0.0
    v = [x / norm_v for x in v]

    sigma_s = 0.0
    for _ in range(max_iterations):
        mv = _mat_vec(work_matrix, v, n)
        mtmv = _mat_T_vec(work_matrix, mv, n)
        new_norm = _l2_norm_scaled(mtmv)
        if new_norm == 0.0:
            sigma_s = 0.0
            break
        # Rayliegh/power ratio on normalized v_k has unit ||v_k||_2 = 1.
        new_sigma = math.sqrt(new_norm)
        if not math.isfinite(new_sigma):
            return math.inf
        v = [x / new_norm for x in mtmv]
        if abs(new_sigma - sigma_s) / (sigma_s + 1e-12) < tol:
            sigma_s = new_sigma
            break
        sigma_s = new_sigma

    if exp == 0:
        return sigma_s
    try:
        return math.ldexp(sigma_s, exp)
    except OverflowError:
        return math.inf


def _finite_sigma(matrix: list[list[float]], max_power_iter: int) -> float:
    """Power-iteration sigma estimate that refuses overflowed (non-finite) results."""
    sigma = spectral_norm_power_iter(matrix, max_iterations=max_power_iter)
    if not math.isfinite(sigma):
        raise ValueError(
            "spectral norm estimate is not finite; trust matrix entries are too large to project"
        )
    return sigma


def _scale_matrix_exponent_safe(
    matrix: Sequence[Sequence[float]],
    r: float,
    denom: float,
    *,
    shrink_ulps: int = 0,
) -> list[list[float]]:
    """Compute ``matrix * (r / denom)`` safely without intermediate overflow or underflow."""
    r_m, r_e = math.frexp(r)
    d_m, d_e = math.frexp(denom)
    ratio = r_m / d_m
    for _ in range(shrink_ulps):
        ratio = math.nextafter(ratio, 0.0)
    exp_shift = r_e - d_e

    scaled: list[list[float]] = []
    for row in matrix:
        out_row: list[float] = []
        for raw_val in row:
            val = float(raw_val)
            if val == 0.0:
                out_row.append(0.0)
                continue
            v_m, v_e = math.frexp(val)
            prod_m = v_m * ratio
            try:
                res = math.ldexp(prod_m, v_e + exp_shift)
            except OverflowError as exc:
                raise ValueError(
                    "scaled trust matrix overflowed finite float64 bounds"
                ) from exc
            if not math.isfinite(res):
                raise ValueError("scaled trust matrix produced non-finite value")
            out_row.append(res)
        scaled.append(out_row)
    return scaled


def spectral_sphere_project(
    matrix: list[list[float]],
    *,
    r: float = 1.0,
    max_power_iter: int = 30,
) -> SpectralProjectionResult:
    """Project matrix onto the spectral-norm sphere of radius ``r``.

    Computes ``H_proj = H * min(1, r / max(upper_bound(H), sigma_est(H)))`` using a
    pure-Python certified conservative global upper bound so ``sigma_max(H_proj) <= r``
    holds strictly (no additive radius slack).

    Args:
        matrix: nxn trust matrix.
        r: Positive finite spectral-sphere radius (default 1.0).
        max_power_iter: Positive integer power iterations for lower-bound diagnostic
            ``spectral_norm_estimate``.

    Returns:
        SpectralProjectionResult with projected matrix, certified ``spectral_norm``
        (``spectral_norm_upper_bound``), diagnostic ``spectral_norm_estimate``, and
        ``bound_method``.
    """
    r_val = _require_positive_finite(r, "r")
    _require_positive_int(max_power_iter, "max_power_iter")
    _validated_square_matrix(matrix)

    ub = _conservative_spectral_upper_bound(matrix)
    sigma_est = _finite_sigma(matrix, max_power_iter)
    effective_bound = max(ub, sigma_est)

    if effective_bound <= r_val:
        projected: list[list[float]] = [[float(v) for v in row] for row in matrix]
        clipped = False
    else:
        clipped = True
        projected = _scale_matrix_exponent_safe(matrix, r_val, effective_bound, shrink_ulps=0)

        for retry in range(3):
            ub = _conservative_spectral_upper_bound(projected)
            sigma_est = _finite_sigma(projected, max_power_iter)
            effective_bound = max(ub, sigma_est)
            if effective_bound <= r_val:
                break
            projected = _scale_matrix_exponent_safe(
                projected, r_val, effective_bound, shrink_ulps=4 * (retry + 1)
            )
        else:
            ub = _conservative_spectral_upper_bound(projected)
            sigma_est = _finite_sigma(projected, max_power_iter)
            effective_bound = max(ub, sigma_est)
            if effective_bound > r_val:
                raise ArithmeticError(
                    "spectral projection did not converge: "
                    f"measured bound {effective_bound!r} > r={r_val!r}"
                )

    return SpectralProjectionResult(
        matrix=tuple(tuple(row) for row in projected),
        spectral_norm=ub,
        clipped=clipped,
        power_iterations=max_power_iter,
        spectral_norm_upper_bound=ub,
        spectral_norm_estimate=sigma_est,
        bound_method=_DEFAULT_BOUND_METHOD,
    )


class SpectralSphereManifold:
    """Governance manifold constrained to a spectral-norm sphere.

    Drop-in replacement for GovernanceManifold. The key behavioral difference:

        GovernanceManifold.compose() → repeated Sinkhorn-Knopp re-projection
                                      → Perron-Frobenius uniformity collapse in O(10) cycles

        SpectralSphereManifold.compose() → spectral_sphere_project (certified global UB)
                                         → preserves non-uniform/negative entries and
                                           stabilizes variance under empirical random-init
                                           workloads with residual_alpha=0.1

    The manifold relaxes the doubly-stochastic constraint entirely, keeping only
    ``sigma_max(H) <= spectral_norm_upper_bound <= r``. Negative entries (explicit distrust
    or adversarial flags) are preserved across projections.
    """

    def __init__(
        self,
        num_agents: int,
        *,
        r: float = 1.0,
        max_power_iter: int = 30,
        smoothing: float = 0.9,
    ) -> None:
        self._n = _require_non_negative_int(num_agents, "num_agents")
        self._r = _require_positive_finite(r, "r")
        self._max_power_iter = _require_positive_int(max_power_iter, "max_power_iter")
        if (
            isinstance(smoothing, bool)
            or not isinstance(smoothing, (int, float))
            or not math.isfinite(smoothing)
            or not 0.0 <= smoothing < 1.0
        ):
            raise ValueError(f"smoothing must be finite in [0, 1), got {smoothing!r}")
        self._smoothing = float(smoothing)
        self._raw_trust: list[list[float]] = [[0.0] * self._n for _ in range(self._n)]
        self._projected: SpectralProjectionResult | None = None
        self._smoothed: SpectralProjectionResult | None = None
        self._commit_generation = 0

    @property
    def num_agents(self) -> int:
        return self._n

    @property
    def radius(self) -> float:
        """Spectral-sphere radius constraint."""
        return self._r

    def update_trust(self, from_agent: int, to_agent: int, delta: float) -> None:
        """Apply one trust update and commit one projected EMA generation."""
        self.update_trust_batch([(from_agent, to_agent, delta)])

    @property
    def commit_generation(self) -> int:
        """Number of committed update batches; observation never changes it."""
        return self._commit_generation

    def update_trust_batch(self, updates: list[tuple[int, int, float]]) -> None:
        """Apply a settlement-sized update batch and advance EMA exactly once."""
        for from_agent, to_agent, delta in updates:
            if (
                isinstance(delta, bool)
                or not isinstance(delta, (int, float))
                or not math.isfinite(delta)
            ):
                raise ValueError(f"delta must be a finite number, got {delta!r}")
            if isinstance(from_agent, bool) or isinstance(to_agent, bool):
                raise TypeError("agent indices must be integers, not bool")
            if not (0 <= from_agent < self._n and 0 <= to_agent < self._n):
                raise IndexError(
                    f"agent index out of range [0, {self._n}): "
                    f"from_agent={from_agent}, to_agent={to_agent}"
                )
        if not updates:
            return
        for from_agent, to_agent, delta in updates:
            self._raw_trust[from_agent][to_agent] += float(delta)
        self._commit_projection()

    def replace_raw_trust(self, matrix: list[list[float]], *, commit: bool = True) -> None:
        """Replace raw state during an ID-stable rebuild."""
        if len(matrix) != self._n or any(len(row) != self._n for row in matrix):
            raise ValueError("replacement trust matrix dimensions do not match manifold")
        _validated_square_matrix(matrix, self._n)
        self._raw_trust = [[float(v) for v in row] for row in matrix]
        self._projected = None
        self._smoothed = None
        if commit:
            self._commit_projection()

    def _commit_projection(self) -> SpectralProjectionResult:
        """Commit one projection/EMA step after mutation, certifying the blended matrix."""
        new_proj = spectral_sphere_project(
            self._raw_trust,
            r=self._r,
            max_power_iter=self._max_power_iter,
        )
        if self._smoothing > 0.0 and self._smoothed is not None:
            alpha = self._smoothing
            beta = 1.0 - alpha
            previous = self._smoothed
            blended_list = [
                [
                    alpha * previous.matrix[i][j] + beta * new_proj.matrix[i][j]
                    for j in range(self._n)
                ]
                for i in range(self._n)
            ]
            # Re-certify the blended matrix on the sphere so IEEE-754 rounding never pushes
            # the stored smoothed state outside r or misreports its bound.
            blended_proj = spectral_sphere_project(
                blended_list,
                r=self._r,
                max_power_iter=self._max_power_iter,
            )
            new_proj = SpectralProjectionResult(
                matrix=blended_proj.matrix,
                spectral_norm=blended_proj.spectral_norm,
                clipped=new_proj.clipped or blended_proj.clipped,
                power_iterations=0,
                spectral_norm_upper_bound=blended_proj.spectral_norm_upper_bound,
                spectral_norm_estimate=blended_proj.spectral_norm_estimate,
                bound_method=blended_proj.bound_method,
            )
        self._smoothed = new_proj
        self._projected = new_proj
        self._commit_generation += 1
        return new_proj

    def project(self) -> SpectralProjectionResult:
        """Project current raw trust matrix onto the spectral sphere.

        This is an observation-only API. Projection and EMA state are committed
        by update methods so repeated reads cannot advance trust dynamics.
        """
        if self._projected is not None:
            return self._projected
        return spectral_sphere_project(
            self._raw_trust,
            r=self._r,
            max_power_iter=self._max_power_iter,
        )

    @property
    def trust_matrix(self) -> tuple[tuple[float, ...], ...]:
        """The spectral-sphere-projected trust matrix."""
        return self.project().matrix

    @property
    def spectral_norm(self) -> float:
        """Certified conservative upper bound on sigma_max of the projected matrix (<= r)."""
        return self.project().spectral_norm

    @property
    def is_stable(self) -> bool:
        """True iff the certified spectral norm upper bound satisfies bound <= r."""
        return self.spectral_norm <= self._r

    def compose(
        self,
        other: SpectralSphereManifold,
        *,
        residual_alpha: float = 0.1,
    ) -> SpectralSphereManifold:
        """Compose two spectral-sphere manifolds.

        Computes ``spectral_sphere_project(alpha * I + (1 - alpha) * (A @ B))``.

        Important qualification on rank preservation:
            Empirically, values in ``[0.05, 0.20]`` (default ``0.1``) prevent rank-1
            power-iteration collapse on tested random non-negative trust workloads
            (see ``tests/test_spectral_sphere_retention.py`` and
            ``tests/test_spectral_sphere_vs_birkhoff.py``). However, residual identity
            injection does *not* universally guarantee full rank for arbitrary signed inputs
            ``(A, B)`` — for example, ``A = I`` and ``B = -(alpha / (1 - alpha)) * I``
            yields the zero matrix identically.
        """
        if self._n != other._n:
            raise ValueError("Cannot compose manifolds of different sizes")
        if abs(self._r - other._r) > 1e-10:
            raise ValueError(f"Spectral sphere radii must match: {self._r} != {other._r}")
        if (
            isinstance(residual_alpha, bool)
            or not isinstance(residual_alpha, (int, float))
            or not math.isfinite(residual_alpha)
            or not 0.0 <= residual_alpha < 1.0
        ):
            raise ValueError(f"residual_alpha must be in [0, 1), got {residual_alpha!r}")

        a = [list(row) for row in self.trust_matrix]
        b = [list(row) for row in other.trust_matrix]
        n = self._n

        product = _mat_mul(a, b, n)

        if residual_alpha > 0.0:
            beta = 1.0 - float(residual_alpha)
            alpha_f = float(residual_alpha)
            product = [
                [beta * product[i][j] + (alpha_f if i == j else 0.0) for j in range(n)]
                for i in range(n)
            ]

        result = SpectralSphereManifold(
            n,
            r=self._r,
            max_power_iter=self._max_power_iter,
            smoothing=self._smoothing,
        )
        result.replace_raw_trust(product)
        return result

    def influence_vector(self, agent_idx: int) -> tuple[float, ...]:
        """Trust row for agent_idx (may contain negative entries — explicit distrust)."""
        return self.trust_matrix[agent_idx]

    def summary(self) -> dict[str, Any]:
        proj = self.project()
        return {
            "num_agents": self._n,
            "radius": self._r,
            "spectral_norm": proj.spectral_norm,
            "spectral_norm_upper_bound": proj.spectral_norm_upper_bound,
            "spectral_norm_estimate": proj.spectral_norm_estimate,
            "bound_method": proj.bound_method,
            "clipped": proj.clipped,
            "is_stable": self.is_stable,
        }
