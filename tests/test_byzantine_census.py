"""Tests for the Byzantine tampered-fraction census.

Deterministic, pure-Python/NumPy: no torch, no live model, no scipy. We check the
interval math (Wilson + Clopper-Pearson via self-implemented normal quantile and
binomial tails), the three-way Byzantine verdict, and the honest guard that refuses
to count a refusal-distribution *trust* signal as a *tamper* verdict.
"""

from __future__ import annotations

import pytest

from constitutional_swarm.byzantine_census import (
    TamperCensus,
    census_from_decisions,
    estimate_tampered_fraction,
)
from constitutional_swarm.byzantine_census import _norm_ppf  # noqa: PLC2701 (internal math under test)
from constitutional_swarm.eval.monotonic_mas.abliteration_detector import (
    AbliterationReport,
)
from constitutional_swarm.node_admission import (
    AdmissionDecision,
    RefusalDistributionReport,
)


# --- normal quantile -------------------------------------------------------


def test_norm_ppf_known_values() -> None:
    assert _norm_ppf(0.5) == pytest.approx(0.0, abs=1e-9)
    assert _norm_ppf(0.975) == pytest.approx(1.959963985, abs=1e-6)
    assert _norm_ppf(0.95) == pytest.approx(1.644853627, abs=1e-6)
    # symmetry
    assert _norm_ppf(0.1) == pytest.approx(-_norm_ppf(0.9), abs=1e-6)


# --- point estimate + interval shape ---------------------------------------


def test_wilson_brackets_point_estimate() -> None:
    c = estimate_tampered_fraction(100, 10, confidence=0.95, method="wilson")
    assert c.p_hat == pytest.approx(0.10)
    assert c.ci_low < c.p_hat < c.ci_high
    assert c.ci_low == pytest.approx(0.0552, abs=5e-3)
    assert c.ci_high == pytest.approx(0.1744, abs=5e-3)
    assert c.method == "wilson"


def test_clopper_pearson_is_more_conservative_than_wilson() -> None:
    w = estimate_tampered_fraction(100, 10, confidence=0.95, method="wilson")
    cp = estimate_tampered_fraction(100, 10, confidence=0.95, method="clopper-pearson")
    # Exact interval is wider (lower low, higher high) than the score interval.
    assert cp.ci_low <= w.ci_low
    assert cp.ci_high >= w.ci_high
    assert cp.ci_low == pytest.approx(0.0490, abs=5e-3)
    assert cp.ci_high == pytest.approx(0.1762, abs=5e-3)


def test_higher_confidence_widens_interval() -> None:
    lo = estimate_tampered_fraction(100, 10, confidence=0.90)
    hi = estimate_tampered_fraction(100, 10, confidence=0.99)
    assert (hi.ci_high - hi.ci_low) > (lo.ci_high - lo.ci_low)


# --- verdicts --------------------------------------------------------------


def test_verdict_safe_when_interval_below_threshold() -> None:
    c = estimate_tampered_fraction(100, 5)  # p_hat 0.05, well under 1/3
    assert c.ci_high < c.threshold
    assert c.verdict == "safe"
    assert c.safe is True


def test_verdict_violated_when_interval_above_threshold() -> None:
    c = estimate_tampered_fraction(100, 50)  # p_hat 0.5, ci_low ~0.40 >= 1/3
    assert c.ci_low >= c.threshold
    assert c.verdict == "violated"
    assert c.safe is False


def test_verdict_inconclusive_when_interval_straddles_threshold() -> None:
    c = estimate_tampered_fraction(10, 3)  # wide CI brackets 1/3
    assert c.ci_low < c.threshold <= c.ci_high
    assert c.verdict == "inconclusive"


def test_threshold_is_tunable() -> None:
    # 20/100 = 0.20: safe under the 1/3 Byzantine bound, but violated under a
    # stricter 0.1 policy threshold.
    assert estimate_tampered_fraction(100, 20, threshold=1 / 3).verdict == "safe"
    assert estimate_tampered_fraction(100, 20, threshold=0.1).verdict == "violated"


# --- boundary counts -------------------------------------------------------


def test_zero_tampered_is_safe() -> None:
    for method in ("wilson", "clopper-pearson"):
        c = estimate_tampered_fraction(50, 0, method=method)
        assert c.p_hat == 0.0
        assert c.ci_low == pytest.approx(0.0, abs=1e-9)
        assert c.verdict == "safe"


def test_all_tampered_is_violated() -> None:
    for method in ("wilson", "clopper-pearson"):
        c = estimate_tampered_fraction(50, 50, method=method)
        assert c.p_hat == 1.0
        assert c.ci_high == pytest.approx(1.0, abs=1e-9)
        assert c.verdict == "violated"


def test_estimate_is_monotonic_in_tampered_count() -> None:
    prev_low = -1.0
    prev_phat = -1.0
    for x in range(0, 101, 10):
        c = estimate_tampered_fraction(100, x)
        assert c.p_hat >= prev_phat
        assert c.ci_low >= prev_low - 1e-12  # non-decreasing lower bound
        prev_phat, prev_low = c.p_hat, c.ci_low


def test_determinism() -> None:
    a = estimate_tampered_fraction(123, 17, confidence=0.95, method="clopper-pearson")
    b = estimate_tampered_fraction(123, 17, confidence=0.95, method="clopper-pearson")
    assert a == b


# --- validation ------------------------------------------------------------


def test_validation_errors() -> None:
    with pytest.raises(ValueError, match="n_screened must be"):
        estimate_tampered_fraction(0, 0)
    with pytest.raises(ValueError, match="n_tampered must be"):
        estimate_tampered_fraction(10, 11)
    with pytest.raises(ValueError, match="n_tampered must be"):
        estimate_tampered_fraction(10, -1)
    with pytest.raises(ValueError, match="confidence must be"):
        estimate_tampered_fraction(10, 1, confidence=1.0)
    with pytest.raises(ValueError, match="threshold must be"):
        estimate_tampered_fraction(10, 1, threshold=0.0)
    with pytest.raises(ValueError, match="method must be one of"):
        estimate_tampered_fraction(10, 1, method="bogus")


# --- census_from_decisions -------------------------------------------------


def _decision(verdicts: dict[str, bool]) -> AdmissionDecision[AbliterationReport]:
    reports = {
        aid: AbliterationReport(
            abliterated=tampered, mode="weight", score=1.0 if tampered else 0.0
        )
        for aid, tampered in verdicts.items()
    }
    admitted = tuple(sorted(a for a, t in verdicts.items() if not t))
    rejected = tuple(sorted(a for a, t in verdicts.items() if t))
    return AdmissionDecision(admitted=admitted, rejected=rejected, reports=reports)


def test_census_from_decisions_counts_abliterated() -> None:
    decision = _decision({f"n{i}": (i < 4) for i in range(40)})  # 4/40 tampered
    c = census_from_decisions([decision])
    assert c.n_screened == 40
    assert c.n_tampered == 4
    assert c.p_hat == pytest.approx(0.1)


def test_census_from_decisions_dedups_by_agent_last_wins() -> None:
    d1 = _decision({"a": False, "b": True})
    d2 = _decision({"b": False, "c": True})  # "b" re-screened, now clean
    c = census_from_decisions([d1, d2])
    assert c.n_screened == 3  # a, b, c — not 4
    assert c.n_tampered == 1  # only c; b's last verdict is clean


def test_census_rejects_refusal_distribution_reports() -> None:
    # A 'fragile' flag is a trust signal, not a tamper verdict — pooling it into the
    # Byzantine census would conflate fragility with tampering.
    bad = AdmissionDecision(
        admitted=("x",),
        rejected=(),
        reports={
            "x": RefusalDistributionReport(
                fragile=False, score=1.0, min_distribution=0.5
            )
        },
    )
    with pytest.raises(ValueError, match="trust signal"):
        census_from_decisions([bad])


def test_census_empty_raises() -> None:
    with pytest.raises(ValueError, match="no agents screened"):
        census_from_decisions([])


def test_census_forwards_method_and_threshold() -> None:
    decision = _decision({f"n{i}": (i < 20) for i in range(100)})  # 20/100
    safe = census_from_decisions([decision], threshold=1 / 3)
    strict = census_from_decisions([decision], threshold=0.1, method="clopper-pearson")
    assert safe.verdict == "safe"
    assert strict.verdict == "violated"
    assert strict.method == "clopper-pearson"
