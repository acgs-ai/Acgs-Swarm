from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_v0_1_scope_doc_locks_verifier_first_boundary() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_verifier_first_scope.md").read_text()
    normalized = text.lower()

    for expected in (
        "evidence verifier",
        "portable governance receipts",
        "collusion, slow-burn harm, and provenance forgery",
        "reconstructability, containment delta, k-of-n compromise, and overhead curve",
    ):
        assert expected in normalized

    for expected in (
        "AgentSpec-style runtime monitoring and logging",
        "Claims of production-grade governance",
        "Lead v0.1 with governed software and DevOps agents",
        "local in-toto/DSSE-shaped profile",
        "SCITT",
        "Sigstore/Rekor",
        "case-based governance memory",
        "SWE-bench, TheAgentCompany, or AgentDojo",
    ):
        assert expected in text


def test_governance_benchmark_plan_is_devops_first_and_budgeted() -> None:
    text = (REPO_ROOT / "docs/internal/governance_benchmark_plan.md").read_text()

    for expected in (
        "Lead vertical: governed software and DevOps agents",
        "Collusion",
        "Slow-burn harm",
        "Provenance forgery",
        "AgentSpec-style trigger, predicate, and enforcement checks",
        "SCITT-compatible profile",
        "Sigstore/Rekor-compatible bundle",
        "adaptive adversary with knowledge of the governance protocol",
        "USD 500 to USD 1000",
    ):
        assert expected in text


def test_receipt_profile_adr_preserves_local_non_claim_boundary() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_receipt_profile_adr.md").read_text()

    for expected in (
        "local in-toto/DSSE-shaped governance receipt profile",
        "not an\nimplementation of in-toto, DSSE, SCITT",
        "Signatures prove only that a verifier-trusted declared key signed",
        "Default verification fails closed",
    ):
        assert expected in text


def test_gap_register_tracks_v0_1_open_implementation_gaps() -> None:
    text = (REPO_ROOT / "docs/internal/gap_register.md").read_text()

    for expected in (
        "GAP-V01-VERIFIER-FIRST-SCOPE",
        "GAP-V01-PORTABLE-RECEIPTS",
        "GAP-V01-EVIDENCE-VERIFIER",
        "GAP-V01-ADVERSARIAL-BENCHMARK",
        "GAP-V01-STRONG-BASELINE",
        "GAP-V01-REPRODUCTION-BUDGET",
        "closed local evidence",
        "production-grade governance are\n  not claimed",
    ):
        assert expected in text


def test_completion_audit_keeps_external_study_blockers_explicit() -> None:
    text = (REPO_ROOT / "docs/internal/acgs_v0_1_completion_audit.md").read_text()

    for expected in (
        "Do not mark the active goal complete from local evidence alone",
        "owner-published blind-review data and scorecard",
        "public-study tier is verified",
        "independent non-ACGS replication requirement",
        "issue `#48` currently has 7 comments",
        "discussion `#49` currently has 3 comments",
        "forks_count=0",
        "network_count=0",
        "fresh web search this turn",
        "no completed external replication bundle exists",
        "reviewer_answer_template.csv",
    ):
        assert expected in text
