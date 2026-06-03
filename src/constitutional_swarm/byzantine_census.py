"""Statistical tampered-fraction census for Byzantine quorum accounting.

The mesh's Byzantine fault tolerance assumes fewer than ``1/3`` of validators are
compromised (``f < n/3``). The abliteration admission gates
(:mod:`constitutional_swarm.node_admission`) can *screen* an individual candidate,
but on their own they do not tell you whether the **swarm-wide** tampered fraction
actually satisfies that bound. This module closes that gap: given the screening
results over a *sample* of nodes, it estimates the population tampered fraction with
a confidence interval and renders a Byzantine-safety verdict against the threshold.

This is a measurement primitive — pure NumPy (plus the stdlib ``math`` for the
normal quantile and binomial tails), deterministic, CI-safe, no torch / live model.
It does not modify any model or committee; it turns a stream of per-node
:class:`~constitutional_swarm.node_admission.AdmissionDecision` verdicts into a
swarm-level health signal.

**Honest scope (read before relying on a "safe" verdict).** This bounds only the
*detectable* tampered fraction over the *screened* nodes. It assumes (a) the screen
itself is sound — you have genuine weight/activation access to each sampled node —
and (b) the sample is representative of the population. It does **not** catch a node
that hides its tampering from the screen (adversarial self-report) or tampering the
detector cannot see. So ``verdict == "safe"`` is a *necessary, not sufficient*
condition for the true Byzantine assumption: it says "the screenable population's
tampered fraction is below the threshold at this confidence." Closing the adversarial
self-report gap needs verifiable model-integrity evidence (remote attestation), which
lives outside this pure-NumPy core. See ``docs/internal/abliteration_threat_model.md``.

Crucially, a :class:`~constitutional_swarm.node_admission.RefusalDistributionReport`
verdict (``fragile``) is a *trust signal, not a tamper verdict* — a fragile node is
honest, only abliteration-vulnerable — so :func:`census_from_decisions` refuses to
count it. Only :class:`~constitutional_swarm.eval.monotonic_mas.abliteration_detector.
AbliterationReport` verdicts (``abliterated``) feed the census.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from .eval.monotonic_mas.abliteration_detector import AbliterationReport
from .node_admission import AdmissionDecision

__all__ = [
    "TamperCensus",
    "census_from_decisions",
    "estimate_tampered_fraction",
]

_METHODS = ("wilson", "clopper-pearson")
# Byzantine fault-tolerance bound: quorum is safe only while f < n/3.
_BYZANTINE_THRESHOLD = 1.0 / 3.0


@dataclass(frozen=True)
class TamperCensus:
    """Swarm-level tampered-fraction estimate with a Byzantine-safety verdict.

    ``p_hat`` is the point estimate ``n_tampered / n_screened``; ``ci_low`` /
    ``ci_high`` bound it at ``confidence`` (two-sided). ``verdict`` compares the
    interval to ``threshold`` (default ``1/3``):

    - ``"safe"`` — the whole interval is below the threshold: the screened tampered
      fraction is confidently under the Byzantine bound.
    - ``"violated"`` — the whole interval is at/above the threshold: the bound is
      confidently exceeded.
    - ``"inconclusive"`` — the interval straddles the threshold: screen more nodes.

    Remember the honest-scope caveat in the module docstring: this concerns the
    *detectable* fraction over *screened* nodes only.
    """

    n_screened: int
    n_tampered: int
    p_hat: float
    ci_low: float
    ci_high: float
    confidence: float
    threshold: float
    method: str
    verdict: str

    @property
    def safe(self) -> bool:
        """True iff the verdict is ``"safe"`` (interval below the threshold)."""
        return self.verdict == "safe"


def _norm_ppf(p: float) -> float:
    """Inverse standard-normal CDF (Acklam's rational approximation, err < 1.2e-9)."""
    a = (
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    )
    b = (
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    )
    c = (
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    )
    d = (
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    )
    plow = 0.02425
    phigh = 1.0 - plow
    if p < plow:
        q = math.sqrt(-2.0 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0
        )
    if p > phigh:
        q = math.sqrt(-2.0 * math.log(1.0 - p))
        return -(
            ((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]
        ) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    q = p - 0.5
    r = q * q
    return (
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
        * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    )


def _binom_cdf(n: int, x: int, p: float) -> float:
    """``P(X <= x)`` for ``X ~ Binomial(n, p)``, summed in log-space."""
    if x < 0:
        return 0.0
    if x >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    log_p = math.log(p)
    log_q = math.log1p(-p)
    lg_n1 = math.lgamma(n + 1)
    total = 0.0
    for k in range(x + 1):
        log_pmf = (
            lg_n1
            - math.lgamma(k + 1)
            - math.lgamma(n - k + 1)
            + k * log_p
            + (n - k) * log_q
        )
        total += math.exp(log_pmf)
    return min(total, 1.0)


def _bisect(lower_branch: bool, n: int, x: int, alpha: float) -> float:
    """Bisect for one Clopper-Pearson bound.

    ``lower_branch`` finds ``p`` with ``P(X >= x | p) = alpha`` (upper tail,
    increasing in ``p``); otherwise finds ``p`` with ``P(X <= x | p) = alpha``
    (lower tail, decreasing in ``p``).
    """
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = 0.5 * (lo + hi)
        if lower_branch:
            # P(X >= x) = 1 - P(X <= x-1); increasing in p.
            value = (1.0 - _binom_cdf(n, x - 1, mid)) - alpha
            if value < 0.0:
                lo = mid
            else:
                hi = mid
        else:
            # P(X <= x); decreasing in p.
            value = _binom_cdf(n, x, mid) - alpha
            if value > 0.0:
                lo = mid
            else:
                hi = mid
    return 0.5 * (lo + hi)


def _wilson_interval(n: int, x: int, confidence: float) -> tuple[float, float]:
    z = _norm_ppf(0.5 * (1.0 + confidence))
    p_hat = x / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    half = (z / denom) * math.sqrt(p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n))
    return max(0.0, center - half), min(1.0, center + half)


def _clopper_pearson_interval(n: int, x: int, confidence: float) -> tuple[float, float]:
    alpha = 1.0 - confidence
    lo = 0.0 if x == 0 else _bisect(True, n, x, alpha / 2.0)
    hi = 1.0 if x == n else _bisect(False, n, x, alpha / 2.0)
    return lo, hi


def estimate_tampered_fraction(
    n_screened: int,
    n_tampered: int,
    *,
    confidence: float = 0.95,
    threshold: float = _BYZANTINE_THRESHOLD,
    method: str = "wilson",
) -> TamperCensus:
    """Estimate the tampered fraction from a screened sample, with a CI and verdict.

    Treats screening as ``n_screened`` Bernoulli trials with ``n_tampered``
    successes (tampered nodes) and forms a two-sided ``confidence`` interval for the
    population tampered fraction, then compares it to ``threshold`` (default ``1/3``,
    the Byzantine bound) to produce a ``"safe"`` / ``"violated"`` / ``"inconclusive"``
    verdict.

    Parameters
    ----------
    n_screened, n_tampered:
        Sample size and number flagged tampered (``0 <= n_tampered <= n_screened``,
        ``n_screened >= 1``).
    confidence:
        Two-sided confidence level in ``(0, 1)`` (default ``0.95``).
    threshold:
        Byzantine fraction bound in ``(0, 1)`` (default ``1/3``).
    method:
        ``"wilson"`` (default; closed-form score interval, robust for small ``n`` and
        extreme ``p``) or ``"clopper-pearson"`` (exact, conservative — wider).

    Returns
    -------
    TamperCensus

    Raises
    ------
    ValueError
        On an empty sample, ``n_tampered`` out of range, or a parameter outside its
        domain.
    """
    if n_screened < 1:
        msg = "n_screened must be >= 1 (no nodes screened)"
        raise ValueError(msg)
    if not 0 <= n_tampered <= n_screened:
        msg = f"n_tampered must be in [0, {n_screened}], got {n_tampered}"
        raise ValueError(msg)
    if not 0.0 < confidence < 1.0:
        msg = "confidence must be in (0, 1)"
        raise ValueError(msg)
    if not 0.0 < threshold < 1.0:
        msg = "threshold must be in (0, 1)"
        raise ValueError(msg)
    if method not in _METHODS:
        msg = f"method must be one of {_METHODS}, got {method!r}"
        raise ValueError(msg)

    if method == "wilson":
        ci_low, ci_high = _wilson_interval(n_screened, n_tampered, confidence)
    else:
        ci_low, ci_high = _clopper_pearson_interval(n_screened, n_tampered, confidence)

    if ci_high < threshold:
        verdict = "safe"
    elif ci_low >= threshold:
        verdict = "violated"
    else:
        verdict = "inconclusive"

    return TamperCensus(
        n_screened=n_screened,
        n_tampered=n_tampered,
        p_hat=n_tampered / n_screened,
        ci_low=ci_low,
        ci_high=ci_high,
        confidence=confidence,
        threshold=threshold,
        method=method,
        verdict=verdict,
    )


def census_from_decisions(
    decisions: Iterable[AdmissionDecision[AbliterationReport]],
    *,
    confidence: float = 0.95,
    threshold: float = _BYZANTINE_THRESHOLD,
    method: str = "wilson",
) -> TamperCensus:
    """Build a :class:`TamperCensus` from abliteration admission decisions.

    Pools the per-agent reports across ``decisions``, **deduplicating by agent id**
    (last verdict wins, so a node re-screened across rounds counts once), counts how
    many are ``abliterated``, and forwards to :func:`estimate_tampered_fraction`.

    Only :class:`~constitutional_swarm.eval.monotonic_mas.abliteration_detector.
    AbliterationReport` verdicts are tamper verdicts. A
    :class:`~constitutional_swarm.node_admission.RefusalDistributionReport`
    (``fragile``) is a *trust signal, not a tamper verdict* — passing a distribution
    gate's decision here raises ``ValueError`` rather than silently conflating
    fragility with tampering.

    Raises
    ------
    ValueError
        If a report is not an :class:`AbliterationReport`, or if no agents were
        screened (propagated from :func:`estimate_tampered_fraction`).
    """
    tampered_by_agent: dict[str, bool] = {}
    for decision in decisions:
        for agent_id, report in decision.reports.items():
            if not isinstance(report, AbliterationReport):
                msg = (
                    "census_from_decisions only counts AbliterationReport (tamper) "
                    "verdicts; a RefusalDistributionReport 'fragile' flag is a trust "
                    "signal, not a tamper verdict, and must not be pooled into the "
                    "Byzantine census"
                )
                raise ValueError(msg)
            tampered_by_agent[agent_id] = report.abliterated

    n_screened = len(tampered_by_agent)
    if n_screened == 0:
        msg = "no agents screened across the provided decisions"
        raise ValueError(msg)
    n_tampered = sum(tampered_by_agent.values())
    return estimate_tampered_fraction(
        n_screened,
        n_tampered,
        confidence=confidence,
        threshold=threshold,
        method=method,
    )
