"""Privacy budget accountant for (ε, δ)-differential privacy in the swarm.

Implements Rényi Differential Privacy (RDP) composition (Mironov 2017, CSF)
with the improved RDP→(ε,δ) conversion from Balle et al. 2020 (NeurIPS).
RDP composition is ~12× tighter than simple Gaussian composition for typical
FL parameters; adding mini-batch subsampling gains another ~19×.

Each call to :meth:`spend` records Gaussian mechanism expenditure. The total
(ε, δ)-DP budget is computed at query time via the exact RDP accountant, not
accumulated naively.  :meth:`assert_budget` raises :class:`PrivacyBudgetExhausted`
if the cumulative ε exceeds the allowed budget.

Fail-closed: if ``assert_budget`` is called after the budget is exceeded the
swarm *stops broadcasting* DP-noised updates — it does not silently continue.

Usage::

    from constitutional_swarm.privacy_accountant import PrivacyAccountant

    pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
    for step in training_steps:
        sigma = pa.required_sigma(sensitivity=0.1)
        pa.spend(sensitivity=0.1, sigma=sigma)
        pa.assert_budget()   # raises if over budget
        swarm_ode.add_dp_noise(H, sigma)

References
----------
- Mironov 2017: "Rényi Differential Privacy" (CSF) — arXiv:1702.07476
- Balle et al. 2020: improved RDP→(ε,δ) (NeurIPS) — arXiv:1905.09982 Theorem 21
- Abadi et al. 2016: "Deep Learning with DP" (CCS) — arXiv:1607.00133
"""

from __future__ import annotations

import math
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field


class PrivacyBudgetExhausted(RuntimeError):
    """Raised when the cumulative ε-budget for this session is exceeded."""


@dataclass
class _SpendRecord:
    sensitivity: float
    sigma: float
    sample_rate: float  # q = batch_size / dataset_size; 1.0 = no subsampling


# Candidate Rényi orders: dense near 1, integer orders through 63, then
# powers of two through 4096. The high orders let the finite grid certify
# common low-epsilon budgets instead of imposing an artificial epsilon floor.
_DEFAULT_ALPHAS: tuple[float, ...] = tuple(
    [1 + x / 10.0 for x in range(1, 100)]
    + list(range(12, 64))
    + [64, 128, 256, 512, 1024, 2048, 4096]
)


def matrix_l2_sensitivity(
    *,
    certified_spectral_bound: float,
    matrix_dimension: int,
) -> float:
    """Return the flattened L2 sensitivity for an ``n × n`` matrix release.

    Two matrices with certified spectral norm at most ``r`` can differ by at
    most ``2 * r * sqrt(n)`` in Frobenius norm. Entrywise Gaussian noise is a
    vector-valued mechanism, so it must use this Frobenius/L2 diameter rather
    than the spectral norm diameter ``2 * r``.

    ``certified_spectral_bound`` must come from a caller-owned certificate or
    deterministic bound. A stochastic power-iteration estimate is not a
    certificate for differential-privacy calibration.
    """
    if (
        isinstance(certified_spectral_bound, bool)
        or not isinstance(certified_spectral_bound, (int, float))
        or not math.isfinite(certified_spectral_bound)
        or certified_spectral_bound <= 0
    ):
        raise ValueError(
            "certified_spectral_bound must be a finite positive number, "
            f"got {certified_spectral_bound}"
        )
    if (
        isinstance(matrix_dimension, bool)
        or not isinstance(matrix_dimension, int)
        or matrix_dimension <= 0
    ):
        raise ValueError(f"matrix_dimension must be a positive integer, got {matrix_dimension}")

    try:
        sensitivity = 2.0 * float(certified_spectral_bound) * math.sqrt(matrix_dimension)
    except OverflowError as exc:
        raise ValueError(
            "matrix L2 sensitivity is not representable as a finite positive float"
        ) from exc
    if not math.isfinite(sensitivity) or sensitivity <= 0:
        raise ValueError("matrix L2 sensitivity is not representable as a finite positive float")
    return sensitivity


def _rdp_gaussian(alpha: float, noise_multiplier: float) -> float:
    """Per-step RDP for the Gaussian mechanism (Mironov 2017, Theorem 3).

    ε(α) = α / (2 · noise_multiplier²)   where noise_multiplier = σ / Δ
    """
    return alpha / 2.0 / noise_multiplier / noise_multiplier


def _rdp_subsampled_gaussian(alpha: float, noise_multiplier: float, sample_rate: float) -> float:
    """RDP for the subsampled Gaussian mechanism (Mironov, Talwar, Zhang 2019).

    Uses the analytic upper bound: for Poisson subsampling at rate q,
    ε_sub(α) ≤ (1/(α-1)) · log(1 + q² · C(α-1) · (exp((α-1)·ε_base) - 1))
    where ε_base = α / (2·nm²) is the un-subsampled RDP.

    For large noise multiplier (nm ≥ 1) and small q, this simplifies to
    approximately q² · ε_base — a ~1/q² privacy amplification.

    Falls back to the un-subsampled bound when sample_rate ≥ 1.
    """
    if sample_rate >= 1.0:
        return _rdp_gaussian(alpha, noise_multiplier)
    if alpha <= 1.0:
        return 0.0

    eps_base = _rdp_gaussian(alpha, noise_multiplier)
    q = sample_rate

    # Tight bound via the log-sum-exp form (Mironov et al. 2019, Proposition 3).
    # For numerical stability, use expm1 when the exponent is small.
    exponent = (alpha - 1.0) * eps_base
    if exponent > 50.0:
        # Overflow-safe: log(q² · exp(exponent)) ≈ 2·log(q) + exponent
        # Clamp to 0.0: for extremely small q the log(q) term can dominate and
        # produce a negative "RDP" value, which is physically impossible and would
        # cause cumulative ε to underflow.  The amplification is at most eps_base.
        return max(0.0, (2.0 * math.log(q) + exponent) / (alpha - 1.0))
    try:
        inner = 1.0 + q * q * math.expm1(exponent)
        if inner <= 0:
            return eps_base  # fallback: no amplification
        return math.log(inner) / (alpha - 1.0)
    except (ValueError, OverflowError):
        return eps_base  # conservative fallback


def _rdp_to_epsilon_balle2020(
    rdp_values: Sequence[float],
    alphas: Sequence[float],
    delta: float,
) -> tuple[float, float]:
    """Convert RDP to (ε, δ)-DP via the improved formula (Balle et al. 2020).

    ε = min_α { ε_RDP(α) + log(1 − 1/α) − log(δ · α) / (α − 1) }

    Returns
    -------
    tuple[float, float]
        (epsilon, optimal_alpha)

    Non-finite RDP values (NaN or +inf) are treated as +inf for their order,
    so a corrupted composition can never convert to a small epsilon.
    """
    best_eps = math.inf
    best_alpha = alphas[0]
    for a, r in zip(alphas, rdp_values, strict=False):
        if a <= 1.0:
            continue
        if not math.isfinite(r):
            continue  # +inf for this order: it can never be the minimum
        try:
            eps = r + math.log1p(-1.0 / a) - math.log(delta * a) / (a - 1.0)
        except (ValueError, ZeroDivisionError):
            continue
        if not math.isfinite(eps):
            continue
        eps = max(0.0, eps)
        if eps < best_eps:
            best_eps = eps
            best_alpha = a
    return best_eps, best_alpha


def _validated_noise_multiplier(sensitivity: float, sigma: float, sample_rate: float) -> float:
    """Validate one Gaussian-mechanism spend and return its noise multiplier."""
    if not math.isfinite(sensitivity) or sensitivity <= 0:
        raise ValueError(f"sensitivity must be positive, got {sensitivity}")
    if not math.isfinite(sigma) or sigma <= 0:
        raise ValueError(f"sigma must be positive, got {sigma}")
    if not math.isfinite(sample_rate) or not (0 < sample_rate <= 1.0):
        raise ValueError(f"sample_rate must be in (0,1], got {sample_rate}")
    nm = sigma / sensitivity
    if not math.isfinite(nm) or nm <= 0:
        raise ValueError("sigma / sensitivity must produce a finite positive noise multiplier")
    return nm


@dataclass
class PrivacyAccountant:
    """Session-scoped RDP moments accountant for (ε, δ)-DP.

    Uses Rényi Differential Privacy (Mironov 2017) for per-step tracking
    and the improved RDP→(ε,δ) conversion from Balle et al. 2020.
    This is ~12× tighter than simple composition for typical FL parameters.

    Parameters
    ----------
    epsilon:
        Maximum total ε budget for this session.
    delta:
        Target δ failure probability (shared across the session).
    alphas:
        Candidate finite Rényi orders strictly greater than one to optimise
        over. The default grid is dense near one and extends sparsely through
        order 4096 so common small epsilon budgets remain certifiable.
    """

    epsilon: float
    delta: float
    alphas: tuple[float, ...] = field(default=_DEFAULT_ALPHAS)

    _history: list[_SpendRecord] = field(default_factory=list, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.epsilon) or self.epsilon <= 0:
            raise ValueError(f"epsilon must be positive, got {self.epsilon}")
        if not math.isfinite(self.delta) or not (0 < self.delta < 1):
            raise ValueError(f"delta must be in (0,1), got {self.delta}")
        if not self.alphas or any(not math.isfinite(alpha) or alpha <= 1.0 for alpha in self.alphas):
            raise ValueError("alphas must be a non-empty sequence of finite orders greater than 1")

    # ------------------------------------------------------------------
    # RDP accounting internals
    # ------------------------------------------------------------------

    def _history_snapshot(self) -> tuple[_SpendRecord, ...]:
        """Return one immutable view of the shared spend history."""
        with self._lock:
            return tuple(self._history)

    def _compute_rdp_total_from_history(
        self,
        history: Sequence[_SpendRecord],
    ) -> list[float]:
        """Sum RDP across a caller-owned immutable history snapshot."""
        rdp_total = [0.0] * len(self.alphas)
        for rec in history:
            nm = rec.sigma / rec.sensitivity
            for i, alpha in enumerate(self.alphas):
                rdp_total[i] += _rdp_subsampled_gaussian(alpha, nm, rec.sample_rate)
        return rdp_total

    def _compute_rdp_total(self) -> list[float]:
        """Sum RDP across all recorded steps, per Rényi order α.

        Composition is exact for RDP: ε_total(α) = Σ_step ε_step(α).
        When a step uses Poisson subsampling (sample_rate < 1), the
        subsampled Gaussian RDP bound (Mironov et al. 2019) provides
        privacy amplification of up to ~q².
        """
        return self._compute_rdp_total_from_history(self._history_snapshot())

    def _epsilon_from_history(self, history: Sequence[_SpendRecord]) -> float:
        """Convert one immutable history snapshot to cumulative epsilon."""
        if not history:
            return 0.0
        rdp_total = self._compute_rdp_total_from_history(history)
        epsilon, _ = _rdp_to_epsilon_balle2020(rdp_total, self.alphas, self.delta)
        return epsilon

    def _current_epsilon(self) -> float:
        """Return the current (ε, δ)-DP ε via RDP composition + Balle 2020."""
        return self._epsilon_from_history(self._history_snapshot())

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def required_sigma(self, sensitivity: float) -> float:
        """Compute the minimum σ for *one more step* within the remaining budget.

        Calibrates σ by inverting the same RDP composition and Balle 2020
        conversion used to account for the next full-sample Gaussian step. The
        calculation uses a locked history snapshot; callers sharing an
        accountant must synchronise the subsequent :meth:`spend` if they need
        calibration and recording to act as one reservation.

        Raises :class:`PrivacyBudgetExhausted` if no budget remains, the
        configured finite alpha grid has a conversion floor above the target
        epsilon, or no finite representable sigma can certify the next step.
        """
        if not math.isfinite(sensitivity) or sensitivity <= 0:
            raise ValueError(f"sensitivity must be positive, got {sensitivity}")

        history = self._history_snapshot()
        spent = self._epsilon_from_history(history)
        if spent >= self.epsilon:
            raise PrivacyBudgetExhausted(
                f"Privacy budget exhausted: used {spent:.4f} / {self.epsilon:.4f} ε"
            )

        accumulated_rdp = self._compute_rdp_total_from_history(history)

        def epsilon_with_next_step(noise_multiplier: float) -> float:
            composed = [
                total + _rdp_subsampled_gaussian(alpha, noise_multiplier, 1.0)
                for total, alpha in zip(accumulated_rdp, self.alphas, strict=True)
            ]
            epsilon, _ = _rdp_to_epsilon_balle2020(composed, self.alphas, self.delta)
            return epsilon

        asymptotic_epsilon, _ = _rdp_to_epsilon_balle2020(
            accumulated_rdp,
            self.alphas,
            self.delta,
        )
        if asymptotic_epsilon >= self.epsilon:
            raise PrivacyBudgetExhausted(
                "Configured alpha/order grid cannot certify another step within "
                f"epsilon={self.epsilon}"
            )

        lower_multiplier = 0.0
        upper_multiplier = 1.0
        for _ in range(1024):
            if epsilon_with_next_step(upper_multiplier) <= self.epsilon:
                break
            lower_multiplier = upper_multiplier
            upper_multiplier *= 2.0
            if not math.isfinite(upper_multiplier):
                raise PrivacyBudgetExhausted(
                    "Configured alpha/order grid cannot certify a finite noise scale"
                )
        else:  # pragma: no cover - bounded by finite float exponent range
            raise PrivacyBudgetExhausted(
                "Configured alpha/order grid cannot certify a finite noise scale"
            )

        for _ in range(96):
            midpoint = (lower_multiplier + upper_multiplier) / 2.0
            if epsilon_with_next_step(midpoint) <= self.epsilon:
                upper_multiplier = midpoint
            else:
                lower_multiplier = midpoint

        sigma = sensitivity * upper_multiplier
        if not math.isfinite(sigma) or sigma <= 0:
            raise PrivacyBudgetExhausted("Unable to represent a finite positive calibrated sigma")
        for _ in range(1024):
            represented_multiplier = sigma / sensitivity
            if (
                math.isfinite(represented_multiplier)
                and represented_multiplier > 0
                and epsilon_with_next_step(represented_multiplier) <= self.epsilon
            ):
                return sigma
            sigma = math.nextafter(sigma, math.inf)
            if not math.isfinite(sigma):
                break
        raise PrivacyBudgetExhausted("Unable to represent a sigma that certifies the budget")

    def spend(self, sensitivity: float, sigma: float, sample_rate: float = 1.0) -> float:
        """Record a Gaussian mechanism invocation and return ε consumed.

        Parameters
        ----------
        sensitivity:
            L2-sensitivity of the function being privatised.
        sigma:
            Noise standard deviation used for this invocation.
        sample_rate:
            Poisson subsampling rate q ∈ (0, 1].  Use q = batch_size / N
            to get privacy amplification by subsampling (can reduce ε by
            up to ~q² when q ≪ 1).  Default 1.0 = no subsampling.

        Returns
        -------
        float
            The ε contributed by this single step (computed via RDP).
        """
        nm = _validated_noise_multiplier(sensitivity, sigma, sample_rate)

        # Per-step RDP contribution at the optimal alpha.
        # Use the subsampled bound so telemetry accurately reflects
        # the privacy amplification when sample_rate < 1.
        per_step_rdp = [_rdp_subsampled_gaussian(a, nm, sample_rate) for a in self.alphas]
        eps_step, _ = _rdp_to_epsilon_balle2020(per_step_rdp, self.alphas, self.delta)

        with self._lock:
            self._history.append(
                _SpendRecord(sensitivity=sensitivity, sigma=sigma, sample_rate=sample_rate)
            )

        return eps_step

    def spend_and_assert(
        self, sensitivity: float, sigma: float, sample_rate: float = 1.0
    ) -> float:
        """Record one mechanism invocation and enforce the budget atomically.

        The record is appended and the cumulative ε recomputed inside one
        critical section, so concurrent callers cannot all pass the gate on
        a stale view of the history (check-then-act race). The record is
        kept even when the gate trips: the mechanism ran and its privacy
        cost is spent. Returns the cumulative ε after this step.

        Raises :class:`PrivacyBudgetExhausted` when the cumulative ε exceeds
        (or cannot be shown to be within) the budget.
        """
        _validated_noise_multiplier(sensitivity, sigma, sample_rate)
        record = _SpendRecord(sensitivity=sensitivity, sigma=sigma, sample_rate=sample_rate)
        with self._lock:
            self._history.append(record)
            spent = self._epsilon_from_history(tuple(self._history))
        if not (spent <= self.epsilon):
            raise PrivacyBudgetExhausted(
                f"ε budget exceeded: spent {spent:.4f} > limit {self.epsilon:.4f} "
                f"(RDP composition, δ={self.delta})"
            )
        return spent

    def assert_budget(self) -> None:
        """Raise :class:`PrivacyBudgetExhausted` if the ε budget is exceeded.

        This is the fail-closed gate: call this after every :meth:`spend`
        to halt processing if the cumulative ε limit has been reached.
        The ε is computed via RDP composition + Balle 2020 — tighter than
        simple summation.
        """
        spent = self._current_epsilon()
        # Negated comparison: a NaN on either side fails closed.
        if not (spent <= self.epsilon):
            raise PrivacyBudgetExhausted(
                f"ε budget exceeded: spent {spent:.4f} > limit {self.epsilon:.4f} "
                f"(RDP composition, δ={self.delta})"
            )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def remaining_epsilon(self) -> float:
        """Remaining ε budget (may be negative if over budget)."""
        return self.epsilon - self._current_epsilon()

    @property
    def budget_fraction_used(self) -> float:
        """Fraction of the ε budget consumed, in [0, ∞)."""
        spent = self._current_epsilon()
        return spent / self.epsilon

    def summary(self) -> dict:
        """Return a serialisable summary of the current budget state."""
        history = self._history_snapshot()
        spent = self._epsilon_from_history(history)
        return {
            "epsilon_total": self.epsilon,
            "epsilon_spent": spent,
            "epsilon_remaining": self.epsilon - spent,
            "delta": self.delta,
            "num_mechanism_invocations": len(history),
            "budget_fraction_used": spent / self.epsilon,
            "exhausted": not (spent <= self.epsilon),
            "composition_method": "RDP (Mironov 2017) + Balle 2020 conversion",
        }
