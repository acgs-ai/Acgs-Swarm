"""Pickers for best-of-K SWE-bench swarm aggregation.

Each picker takes a list of :class:`SWEPatch` candidates (one per agent on
the same task) and returns ``(winner_index, reason)`` where ``winner_index``
is the position in the candidate list of the chosen winner, or ``-1`` if
no candidate is selectable. ``reason`` is a short human-readable string
that explains the choice; recorded in the per-instance JSONL for audit.

Implemented pickers
-------------------
- ``longest``: pick the candidate with the longest patch (more characters
  = more substantive). Ties broken by lower agent index.
- ``first-valid``: pick the first candidate with a non-empty patch (round-
  robin agent-0 favored). Useful as a baseline for "no picker logic at all".
- ``governed-score``: score each non-empty candidate through
  ``AgentDNA.validate()`` against ``MCFS_ROLE_CONSTITUTION``; pick the
  candidate with the lowest risk_score (i.e. safest). Ties broken by
  longest, then lower index. This is the H1-relevant picker — it answers
  "does constitutional governance, used as a selector, beat naive picks?"
- ``vote``: file-set majority. Extract ``--- a/<path>`` and ``+++ b/<path>``
  paths from each candidate; bucket by frozen set; pick a candidate from
  the largest bucket. Ties broken by longest patch in the bucket.

All pickers must be deterministic given the same input order.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from constitutional_swarm.dna import AgentDNA
    from constitutional_swarm.swe_bench.agent import SWEPatch


_FILE_RE = re.compile(r"^[-+]{3} [ab]/(\S+)", re.MULTILINE)


def _files_in_patch(patch: str) -> frozenset[str]:
    """Return the set of files modified by *patch* (a/b prefix stripped)."""
    return frozenset(_FILE_RE.findall(patch))


def _valid_indices(candidates: list[SWEPatch]) -> list[int]:
    return [i for i, c in enumerate(candidates) if c.patch.strip()]


def pick_longest(candidates: list[SWEPatch]) -> tuple[int, str]:
    valid = _valid_indices(candidates)
    if not valid:
        return -1, "no_valid_candidate"
    winner = max(valid, key=lambda i: (len(candidates[i].patch), -i))
    return winner, f"longest: {len(candidates[winner].patch)} chars"


def pick_first_valid(candidates: list[SWEPatch]) -> tuple[int, str]:
    for i, c in enumerate(candidates):
        if c.patch.strip():
            return i, f"first-valid: agent#{i}"
    return -1, "no_valid_candidate"


def pick_governed_score(
    candidates: list[SWEPatch],
    dna: AgentDNA,
) -> tuple[int, str]:
    """Pick the candidate with the lowest constitutional risk_score.

    Empty/errored candidates are excluded. Ties on risk_score are broken
    by longer patch, then lower agent index.
    """
    valid = _valid_indices(candidates)
    if not valid:
        return -1, "no_valid_candidate"

    scored: list[tuple[int, float, int]] = []
    for i in valid:
        v = dna.validate(candidates[i].patch)
        risk = float(getattr(v, "risk_score", 0.0) or 0.0)
        viol_count = len(getattr(v, "violations", ()) or ())
        # Treat any violation as max risk so it loses to clean candidates.
        if viol_count > 0:
            risk = max(risk, 1.0)
        scored.append((i, risk, len(candidates[i].patch)))

    # Sort by (risk asc, -length, index asc).
    scored.sort(key=lambda t: (t[1], -t[2], t[0]))
    winner = scored[0]
    return winner[0], (
        f"governed-score: risk={winner[1]:.3f} "
        f"len={winner[2]} agent#{winner[0]}"
    )


def pick_vote(candidates: list[SWEPatch]) -> tuple[int, str]:
    """Pick from the most-popular file-set bucket; ties → longest in bucket.

    All-empty input → -1. All-distinct file-sets degenerates to longest.
    """
    valid = _valid_indices(candidates)
    if not valid:
        return -1, "no_valid_candidate"

    buckets: dict[frozenset[str], list[int]] = {}
    for i in valid:
        files = _files_in_patch(candidates[i].patch)
        buckets.setdefault(files, []).append(i)

    # Order buckets by (has-files first, count desc, max-length desc).
    # Empty file-set patches are structurally invalid (git apply needs file
    # headers), so deprioritize them regardless of bucket size — better to
    # pick a smaller "real" bucket than a malformed-but-popular one.
    ranked = sorted(
        buckets.items(),
        key=lambda kv: (
            0 if kv[0] else 1,  # has-files first (0 < 1)
            -len(kv[1]),
            -max(len(candidates[i].patch) for i in kv[1]),
        ),
    )
    bucket_files, bucket = ranked[0]
    # Pick longest within the winning bucket (tie -> lower index).
    winner = max(bucket, key=lambda i: (len(candidates[i].patch), -i))
    file_count = len(bucket_files)
    bucket_size = len(bucket)
    return winner, (
        f"vote: {bucket_size}/{len(valid)} agreed on "
        f"{file_count}-file set; longest in bucket"
    )


# Registry for CLI dispatch. Picker callables can take an extra `dna` kwarg;
# the runner provides it only to pickers that declare it.
PICKERS = {
    "longest": pick_longest,
    "first-valid": pick_first_valid,
    "governed-score": pick_governed_score,
    "vote": pick_vote,
}


def needs_dna(picker_name: str) -> bool:
    return picker_name == "governed-score"


__all__ = [
    "PICKERS",
    "needs_dna",
    "pick_first_valid",
    "pick_governed_score",
    "pick_longest",
    "pick_vote",
]
