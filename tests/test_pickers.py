"""Unit tests for SWE-bench best-of-K pickers.

Each picker takes list[SWEPatch] and returns (winner_index, reason). Tests
cover: empty input, all-empty candidates, longest tie-breaking, file-set
voting, governed-score selection, and the structural-validity priority
that empty-file-set patches must lose to bucketed-file patches.
"""

from __future__ import annotations

import pytest
from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.eval.monotonic_mas.detectors.mcfs_constitution import (
    MCFS_ROLE_CONSTITUTION,
)
from constitutional_swarm.swe_bench.agent import SWEPatch
from constitutional_swarm.swe_bench.pickers import (
    PICKERS,
    pick_first_valid,
    pick_governed_score,
    pick_longest,
    pick_vote,
)


def _patch(text: str) -> SWEPatch:
    return SWEPatch(
        task_id="x",
        patch=text,
        success=bool(text.strip()),
        governed=False,
        intervention_rate=0.0,
        duration_s=0.0,
        metadata={},
    )


_DIFF_A = "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"
_DIFF_B = "--- a/bar.py\n+++ b/bar.py\n@@ -1 +1 @@\n-x\n+y\n"
_DIFF_A_LONGER = (
    "--- a/foo.py\n+++ b/foo.py\n@@ -1,3 +1,3 @@\n-a\n-b\n-c\n+a2\n+b2\n+c2\n"
)


# ── pick_longest ────────────────────────────────────────────────────────────


def test_longest_picks_max_chars() -> None:
    cands = [_patch(_DIFF_A), _patch(_DIFF_A_LONGER), _patch(_DIFF_B)]
    idx, reason = pick_longest(cands)
    assert idx == 1
    assert "longest" in reason


def test_longest_ignores_empty() -> None:
    cands = [_patch(""), _patch(_DIFF_A), _patch("")]
    idx, _ = pick_longest(cands)
    assert idx == 1


def test_longest_returns_neg1_when_all_empty() -> None:
    cands = [_patch(""), _patch(""), _patch("")]
    idx, reason = pick_longest(cands)
    assert idx == -1
    assert "no_valid" in reason


def test_longest_breaks_ties_by_lower_index() -> None:
    same_len = _DIFF_A
    cands = [_patch(same_len), _patch(same_len)]
    idx, _ = pick_longest(cands)
    assert idx == 0


# ── pick_first_valid ────────────────────────────────────────────────────────


def test_first_valid_picks_first_non_empty() -> None:
    cands = [_patch(""), _patch(_DIFF_A), _patch(_DIFF_B)]
    idx, reason = pick_first_valid(cands)
    assert idx == 1
    assert "first-valid" in reason


def test_first_valid_returns_neg1_when_all_empty() -> None:
    cands = [_patch(""), _patch("")]
    idx, _ = pick_first_valid(cands)
    assert idx == -1


# ── pick_governed_score ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def dna() -> AgentDNA:
    return AgentDNA(
        constitution=MCFS_ROLE_CONSTITUTION,
        agent_id="test-judge",
        strict=False,
        risk_scoring=True,
    )


def test_governed_score_picks_clean_over_dirty(dna: AgentDNA) -> None:
    """A patch containing constitutional violations must lose to a clean one."""
    clean = _DIFF_A
    # Inject text that triggers MCFS-ROLE-001 (disable safety) — the constitutional
    # rules are designed to fire on this phrase, so this candidate should be
    # ranked worst even though it's longer.
    dirty = (
        "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n"
        "-old\n+# disable safety checks for performance\n"
    )
    cands = [_patch(clean), _patch(dirty)]
    idx, reason = pick_governed_score(cands, dna)
    assert idx == 0
    assert "governed-score" in reason


def test_governed_score_breaks_ties_by_length(dna: AgentDNA) -> None:
    """When two candidates have equal risk (e.g. both clean), longer wins."""
    cands = [_patch(_DIFF_A), _patch(_DIFF_A_LONGER)]
    idx, _ = pick_governed_score(cands, dna)
    assert idx == 1


def test_governed_score_returns_neg1_when_all_empty(dna: AgentDNA) -> None:
    cands = [_patch(""), _patch("")]
    idx, _ = pick_governed_score(cands, dna)
    assert idx == -1


# ── pick_vote ───────────────────────────────────────────────────────────────


def test_vote_picks_majority_file_set() -> None:
    """Two agents agreeing on file-set should beat one outlier."""
    same_files = "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-x\n+y\n"
    same_files_v2 = "--- a/foo.py\n+++ b/foo.py\n@@ -2 +2 @@\n-aa\n+bb\n"
    different = "--- a/bar.py\n+++ b/bar.py\n@@ -1 +1 @@\n-z\n+w\n"
    cands = [_patch(same_files), _patch(same_files_v2), _patch(different)]
    idx, reason = pick_vote(cands)
    assert idx in (0, 1)  # one from the {foo.py} bucket
    assert "vote" in reason


def test_vote_deprioritizes_empty_file_set() -> None:
    """Patches with no file header must lose to any patch that has files,
    even if the empty-file-set bucket is larger.

    Regression test for the structural-validity bug observed in run
    bok-verified-2026-05-09: 2 hunk-only patches were grouped into the
    empty-file-set bucket and won by majority over a single applyable
    patch with proper headers. The fix prioritizes has-files buckets
    regardless of size.
    """
    # NOTE: post-fix _extract_diff would reject these at extraction, but the
    # picker must also handle the case defensively (e.g. patches reconstructed
    # from external sources).
    hunk_only_a = "@@ -1 +1 @@\n-old\n+new\n"
    hunk_only_b = "@@ -2 +2 @@\n-foo\n+bar\n"
    has_file = "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"
    cands = [_patch(hunk_only_a), _patch(hunk_only_b), _patch(has_file)]
    idx, reason = pick_vote(cands)
    assert idx == 2, (
        f"vote must pick the has-files candidate even when outnumbered, got {idx}"
    )
    assert "vote" in reason


def test_vote_returns_neg1_when_all_empty() -> None:
    cands = [_patch(""), _patch("")]
    idx, _ = pick_vote(cands)
    assert idx == -1


# ── PICKERS registry sanity ─────────────────────────────────────────────────


def test_pickers_registry_complete() -> None:
    assert set(PICKERS.keys()) == {
        "longest", "first-valid", "governed-score", "vote",
    }
