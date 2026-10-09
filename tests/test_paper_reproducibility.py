"""Executable checks for paper claims not covered by module-level tests."""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("torch")

from scripts.reproduce_paper_claims import (
    DP_MATRIX_DIMENSION,
    ICLR_UNMAPPED_IDS,
    NDSS_UNMAPPED_IDS,
    collect_evidence,
    summary,
)
from constitutional_swarm.privacy_accountant import PrivacyAccountant, matrix_l2_sensitivity


DELTA = 1e-5
RADIUS = 1.0
ROOT = Path(__file__).resolve().parents[1]


def _read(rel_path: str) -> str:
    return (ROOT / rel_path).read_text(encoding="utf-8")


def _gaussian_sigma(*, epsilon: float, matrix_dimension: int = DP_MATRIX_DIMENSION) -> float:
    """Production matrix-Gaussian calibration for a certified spectral bound."""
    sensitivity = matrix_l2_sensitivity(
        certified_spectral_bound=RADIUS,
        matrix_dimension=matrix_dimension,
    )
    return PrivacyAccountant(epsilon=epsilon, delta=DELTA).required_sigma(
        sensitivity=sensitivity
    )


def test_ndss_09_historical_composition_is_not_the_live_certificate() -> None:
    """NDSS-09: preserve paper parity while the protocol uses the accountant."""
    per_round_epsilon = 0.25
    per_round_delta = 1e-6
    k_rounds = 16

    epsilon_total = per_round_epsilon * math.sqrt(2.0 * k_rounds * math.log(1.0 / per_round_delta))
    delta_total = k_rounds * per_round_delta

    assert epsilon_total == pytest.approx(5.256521769756932)
    assert delta_total == pytest.approx(1.6e-5)
    paper_text = _read("papers/ndss2027/sections/protocol.tex")
    protocol_text = _read("docs/maci_dp_protocol.md")

    assert "standard composition is approximately" in paper_text
    assert "Use one session-scoped `PrivacyAccountant`" in protocol_text
    assert "call `spend`" in protocol_text
    assert "`assert_budget`" in protocol_text


def test_iclr_15_corrected_calibration_uses_matrix_l2_sensitivity() -> None:
    """ICLR-15 errata: matrix dimension is part of the sensitivity contract."""
    sensitivity = matrix_l2_sensitivity(
        certified_spectral_bound=RADIUS,
        matrix_dimension=DP_MATRIX_DIMENSION,
    )

    assert sensitivity == pytest.approx(2.0 * RADIUS * math.sqrt(DP_MATRIX_DIMENSION))
    assert _gaussian_sigma(epsilon=1.0) == pytest.approx(57.2103885, rel=1e-8)


def test_ndss_18_corrected_calibration_has_no_residual_discount() -> None:
    """NDSS-18 errata: alpha is absent without a certified Frobenius clip."""
    evidence = {item.claim_id: item for item in collect_evidence()}["NDSS-18"]

    assert _gaussian_sigma(epsilon=2.0) == pytest.approx(30.3930097, rel=1e-8)
    assert evidence.measurements["published_epsilon2_baseline_sigma"] == 4.84
    assert evidence.measurements["published_epsilon2_residual_sigma"] == 4.36
    assert evidence.measurements["legacy_harness_constants_unverified"] == [1.92, 1.73]


def test_iclr_15_paper_dp_noise_table_matches_errata_proposal() -> None:
    """ICLR-15: immutable old values and corrected proposal stay paired."""
    old_rows = (
        "1.0 & 9.69 & 8.72 ($-10\\%$) & 7.75 ($-20\\%$) & 4.84 ($-50\\%$)",
        "2.0 & 4.84 & 4.36 ($-10\\%$) & 3.88 ($-20\\%$) & 2.42 ($-50\\%$)",
        "4.0 & 2.42 & 2.18 ($-10\\%$) & 1.94 ($-20\\%$) & 1.21 ($-50\\%$)",
        "8.0 & 1.21 & 1.09 ($-10\\%$) & 0.97 ($-20\\%$) & 0.61 ($-50\\%$)",
    )
    expected = {
        1.0: 57.21038854,
        2.0: 30.3930097,
        4.0: 16.37049377,
        8.0: 9.01801824,
    }
    paper_text = _read("papers/iclr2027/sections/experiments.tex")
    errata_text = _read("papers/DP_SENSITIVITY_ERRATA.md")

    for old_row in old_rows:
        assert old_row in paper_text
        assert old_row in errata_text
    assert "residual-discount columns" in errata_text
    for epsilon, corrected_sigma in expected.items():
        calibrated = _gaussian_sigma(epsilon=epsilon)

        assert calibrated == pytest.approx(corrected_sigma, rel=1e-8)
        assert f"{corrected_sigma:.8f}" in errata_text


def test_ndss_17_paper_dp_accuracy_table_matches_errata_proposal() -> None:
    """NDSS-17: historical table values map to corrected proposed values."""
    old_rows = (
        "1.0 & 8.721 & formula check & exact & Yes",
        "2.0 & 4.360 & formula check & exact & Yes",
        "4.0 & 2.180 & formula check & exact & Yes",
        "8.0 & 1.090 & formula check & exact & Yes",
    )
    expected_theory = {
        1.0: 57.21038854,
        2.0: 30.3930097,
        4.0: 16.37049377,
        8.0: 9.01801824,
    }
    paper_text = _read("papers/ndss2027/sections/evaluation.tex")
    errata_text = _read("papers/DP_SENSITIVITY_ERRATA.md")

    for old_row in old_rows:
        assert old_row in paper_text
        assert old_row in errata_text
    assert "no empirical samples" in errata_text
    for epsilon, corrected_sigma in expected_theory.items():
        calibrated = _gaussian_sigma(epsilon=epsilon)

        assert calibrated == pytest.approx(corrected_sigma, rel=1e-8)
        assert f"{corrected_sigma:.8f}" in errata_text


def test_ndss_18_paper_absolute_sigma_values_match_errata_proposal() -> None:
    """NDSS-18: old comparison is retained only as an errata target."""
    corrected = _gaussian_sigma(epsilon=2.0)
    paper_text = _read("papers/ndss2027/sections/evaluation.tex")
    errata_text = _read("papers/DP_SENSITIVITY_ERRATA.md")

    assert corrected == pytest.approx(30.3930097, rel=1e-8)
    assert "baseline\n$\\sigma = 4.84$" in paper_text
    assert "residual-injection\n$\\sigma = 4.36$" in paper_text
    assert "No residual-based reduction is certified" in errata_text


def test_ndss_10_matrix_noise_bound_uses_conservative_spectral_scale() -> None:
    """NDSS-10: matrix Gaussian noise uses the 2*sqrt(n) spectral-norm scale."""
    n_agents = 50
    sigma = RADIUS / (2.0 * math.sqrt(n_agents))
    evidence = {item.claim_id: item for item in collect_evidence()}["NDSS-10"]

    assert 2.0 * sigma * math.sqrt(n_agents) == pytest.approx(RADIUS)
    assert evidence.measurements["leading_spectral_scale"] == "2*sigma*sqrt(n)"
    assert evidence.measurements["heuristic_threshold"] == "sigma <= r/(2*sqrt(n))"
    assert evidence.measurements["heuristic_only"] is True
    assert evidence.measurements["privacy_or_tail_certificate"] is False
    assert "$\\sigma \\leq r/(2\\sqrt{n})$" in _read("papers/ndss2027/sections/protocol.tex")


def test_iclr_local_benchmark_claims_are_script_backed() -> None:
    """ICLR unsupported exact capacity claims must not appear as results."""
    files = [
        "papers/iclr2027/sections/abstract.tex",
        "papers/iclr2027/sections/introduction.tex",
        "papers/iclr2027/sections/experiments.tex",
        "papers/iclr2027/sections/conclusion.tex",
        "papers/iclr2027/figures/variance_comparison.tex",
    ]
    combined = "\n".join(_read(path) for path in files)

    for unsupported in ("2{,}656", "2656", "287\\%", "38\\%", "71\\%"):
        assert unsupported not in combined
    assert "topological-capacity benchmark is pending" not in combined
    assert "30-seed benchmark is pending" not in combined
    assert "Ablation benchmarks for radius and residual sensitivity are pending" not in combined
    assert "scripts/reproduce\\_paper\\_claims.py" in combined
    assert "projected-RK4 stability reproduced by harness" in combined


def test_ndss_external_benchmarks_are_not_reported_as_completed_results() -> None:
    """NDSS external SWE-bench numbers remain explicitly outside reported claims."""
    evaluation = _read("papers/ndss2027/sections/evaluation.tex")
    conclusion = _read("papers/ndss2027/sections/conclusion.tex")

    for unsupported in (
        "3.2 \\pm 0.4",
        "8.7 \\pm 1.2",
        "1{,}000",
        "15$--$30\\%",
        "$>100\\%$",
        "$1.2 \\pm 0.1$",
        "$0.025\\%$",
        "1018 tests",
    ):
        assert unsupported not in evaluation + conclusion
    assert "official\\_swe\\_bench\\_claimed=false" in evaluation
    assert "Official SWE-bench results are not claimed" in evaluation
    assert "Latency microbenchmarks\nare reproducible through the script" in evaluation
    assert (
        "Phase 2 regression tests cover CID\nintegrity, EEC convergence, and DP calibration"
        in conclusion
    )
    assert "scripts/reproduce\\_paper\\_claims.py" in conclusion


def test_claim_map_has_no_unmapped_or_xfail_rows() -> None:
    """Every listed paper claim has a passing artifact or explicit external non-claim."""
    claim_map = _read("docs/internal/claims_map.md")

    assert "| Total | 44 | 44 | 0 |" in claim_map
    assert "| unmapped |" not in claim_map
    assert "| mapped-xfail |" not in claim_map
    assert "Reproducibility Gaps" not in claim_map


def test_remaining_claim_registry_covers_all_previous_unmapped_claims() -> None:
    evidence = collect_evidence()
    claim_ids = {item.claim_id for item in evidence}

    assert claim_ids == ICLR_UNMAPPED_IDS | NDSS_UNMAPPED_IDS


def test_remaining_claim_reproducers_all_pass() -> None:
    evidence = collect_evidence()
    report = summary(evidence)

    assert report["total"] == 24
    assert report["failed"] == 0
    assert report["failed_claim_ids"] == []
    assert "ICLR-03" in report["withdrawn_claim_ids"]
    assert "ICLR-14" in report["withdrawn_claim_ids"]
    assert set(report["errata_proposed_ids"]) == {"ICLR-15", "NDSS-17", "NDSS-18"}
    scored = [
        item
        for item in evidence
        if item.status in {"measured", "formula"}
        and item.measurements.get("errata_proposed") is not True
    ]
    assert scored
    assert all(item.passed for item in scored)
    assert all(item.status != "withdrawn" or not item.passed for item in evidence)
    errata = [item for item in evidence if item.measurements.get("errata_proposed") is True]
    assert all(not item.passed for item in errata)
    assert all(item.status == "formula" for item in errata)
    assert all(item.measurements["corrected_calibration_verified"] for item in errata)
    assert all("2656" not in json.dumps(item.measurements) or item.status == "withdrawn" for item in evidence)


def test_remaining_claims_carry_external_source_provenance() -> None:
    evidence = collect_evidence()

    assert all(item.external_source_present for item in evidence)
    assert all(item.source for item in evidence)


def test_swebench_claims_are_measured_synthetic_non_official() -> None:
    evidence = {item.claim_id: item for item in collect_evidence()}

    assert "PROVISIONAL" not in evidence["NDSS-20"].note
    assert "PROVISIONAL" not in evidence["NDSS-21"].note
    assert evidence["NDSS-20"].passed
    assert evidence["NDSS-21"].passed
    assert evidence["NDSS-20"].measurements["official_swebench_claimed"] is False
    assert evidence["NDSS-20"].measurements["official_swe_bench_claimed"] is False
    assert evidence["NDSS-21"].measurements["synthetic_only"] is True
    assert evidence["NDSS-20"].measurements["fedsink_lift_over_sinkhorn_crdt"] >= 0.15


def test_reproduce_paper_claims_cli_json() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/reproduce_paper_claims.py",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["failed"] == 0
    assert payload["summary"]["failed_claim_ids"] == []
    assert payload["summary"]["total"] == 24
    assert "ICLR-03" in payload["summary"]["withdrawn_claim_ids"]
    assert set(payload["summary"]["errata_proposed_ids"]) == {
        "ICLR-15",
        "NDSS-17",
        "NDSS-18",
    }


def test_claim_map_reproducer_row_matches_live_registry() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/reproduce_paper_claims.py",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    claim_map = _read("docs/internal/claims_map.md")

    assert result.returncode == 0
    assert payload["summary"]["failed"] == 0
    assert "withdrawn_claim_ids" in payload["summary"]
    assert "withdrawn 2656%" in claim_map
