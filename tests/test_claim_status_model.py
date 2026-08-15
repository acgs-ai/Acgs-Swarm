"""Claim registry status model: withdrawn/non-claim are not scored passes."""

from __future__ import annotations

from scripts.reproduce_paper_claims import collect_evidence, summary


def test_measured_and_formula_claims_use_live_producers() -> None:
    evidence = {item.claim_id: item for item in collect_evidence()}
    assert evidence["ICLR-15"].status == "formula"
    assert evidence["ICLR-15"].measurements["producer"] == "_dp_sigma"
    assert evidence["NDSS-20"].status == "measured"
    assert evidence["NDSS-20"].measurements["synthetic_only"] is True
    assert evidence["NDSS-20"].measurements["official_swebench_claimed"] is False


def test_withdrawn_and_non_claim_are_not_passes() -> None:
    report = summary(collect_evidence())
    assert report["failed"] == 0
    assert "ICLR-03" in report["withdrawn_claim_ids"]
    assert "NDSS-13" in report["non_claim_ids"]
    assert "ICLR-03" not in report["failed_claim_ids"]
    by_id = {item.claim_id: item for item in collect_evidence()}
    assert by_id["ICLR-03"].passed is False
    assert by_id["NDSS-24"].status == "non_claim"
    assert by_id["NDSS-24"].passed is False


def test_no_self_comparison_pass_for_withdrawn_capacity() -> None:
    for item in collect_evidence():
        if item.status in {"measured", "formula"} and item.passed:
            blob = str(item.measurements)
            assert "2656" not in blob
            assert "1000 > 0" not in blob
