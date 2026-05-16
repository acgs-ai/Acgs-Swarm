from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_v0_1_scope_doc_locks_verifier_first_boundary() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_verifier_first_scope.md").read_text()
    normalized = text.lower()

    assert "evidence verifier" in normalized
    assert "portable governance receipts" in normalized
    assert "collusion, slow-burn harm, and provenance forgery" in normalized
    expected_metrics = (
        "reconstructability, containment delta, k-of-n compromise, and overhead curve"
    )
    assert expected_metrics in normalized
    assert "AgentSpec-style runtime monitoring and logging" in text
    assert "Claims of production-grade governance" in text
    assert "Lead v0.1 with governed software and DevOps agents" in text
    assert "local in-toto/DSSE-shaped profile" in text
    assert "SCITT" in text
    assert "Sigstore/Rekor" in text
    assert "case-based governance memory" in text
    assert "SWE-bench, TheAgentCompany, or AgentDojo" in text


def test_governance_benchmark_plan_is_devops_first_and_budgeted() -> None:
    text = (REPO_ROOT / "docs/internal/governance_benchmark_plan.md").read_text()

    assert "Lead vertical: governed software and DevOps agents" in text
    assert "Collusion" in text
    assert "Slow-burn harm" in text
    assert "Provenance forgery" in text
    assert "AgentSpec-style trigger, predicate, and enforcement checks" in text
    assert "SCITT-compatible profile" in text
    assert "Sigstore/Rekor-compatible bundle" in text
    assert "adaptive adversary with knowledge of the governance protocol" in text
    assert "USD 500 to USD 1000" in text


def test_receipt_profile_adr_preserves_local_non_claim_boundary() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_receipt_profile_adr.md").read_text()

    assert "local in-toto/DSSE-shaped governance receipt profile" in text
    assert "not an\nimplementation of in-toto, DSSE, SCITT" in text
    assert "Signatures prove only that a verifier-trusted declared key signed" in text
    assert "Default verification fails closed" in text


def test_gap_register_tracks_v0_1_open_implementation_gaps() -> None:
    text = (REPO_ROOT / "docs/internal/gap_register.md").read_text()

    assert "GAP-V01-VERIFIER-FIRST-SCOPE" in text
    assert "GAP-V01-PORTABLE-RECEIPTS" in text
    assert "GAP-V01-EVIDENCE-VERIFIER" in text
    assert "GAP-V01-ADVERSARIAL-BENCHMARK" in text
    assert "GAP-V01-STRONG-BASELINE" in text
    assert "GAP-V01-REPRODUCTION-BUDGET" in text
    assert "closed local evidence" in text
    assert "production-grade governance are\n  not claimed" in text


def test_completion_audit_keeps_external_study_blockers_explicit() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_completion_audit.md").read_text()

    assert "Do not mark the active goal complete from local evidence alone" in text
    assert "No reviewer cohort data is present in the repo" in text
    assert "no completed external replication bundle exists" in text
    assert "reviewer_answer_template.csv" in text
