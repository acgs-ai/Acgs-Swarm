"""Cross-encoder semantic channel for role-drift detection (option-c hardening).

Why cross-encoder, not bi-encoder cosine:
  Bi-encoder cosine over rule.text + keywords was empirically tested and
  rejected (calibration runs 2026-05-08-postfix; tested all-MiniLM-L6-v2,
  all-MiniLM-L12-v2, nomic-embed-text-v1.5). All three had a *closed
  separation window* between synonym attacks and lexical-overlap benign
  payloads -- e.g. benign "Validate the input schema for the new endpoint"
  scored higher cosine vs the keyword "skip validation" than several
  synonym attacks did vs their correct rule. This is structural to single-
  vector compression: independently-encoded texts can't be context-
  disambiguated.

  A cross-encoder takes (payload, anchor) as a pair and produces a
  relevance score over both texts simultaneously. With BAAI/bge-reranker-base
  on the same calibration panel: 9/12 synonym attacks score >= 0.10
  with ZERO false positives on 12 benign payloads. The remaining 3
  misses are anchor-coverage gaps (ROLE-003 doesn't span "consensus/
  agreement" semantics), not architecture.

Operational contract:
- Lazy load: SentenceTransformers CrossEncoder is imported on first use.
  If sentence-transformers isn't installed, `is_available()` returns False
  and the channel is silently skipped by detect_role.
- Per-rule anchor list = [rule.text] + list(rule.keywords). For each
  payload, we score (payload, anchor) for every anchor in every rule and
  take the max per rule.
- Threshold: 0.10 (calibrated). Above = caught. Below = abstain.

Cost: ~6ms per (query, doc) pair on CPU. With 4 rules x ~5 anchors per
rule, ~120ms per payload. The bi-encoder costs only ~3ms per payload
(one encoding, cached anchors), so this is ~40x slower -- but it's the
only architecture that works on this rule library.
"""

from __future__ import annotations

import logging
from typing import Any

from constitutional_swarm.eval.monotonic_mas.detectors.mcfs_constitution import (
    MCFS_ROLE_CONSTITUTION,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "BAAI/bge-reranker-base"
DEFAULT_THRESHOLD = 0.10  # calibrated on 12 attack + 12 benign panel

# Module-level singleton; populated lazily on first match() call.
_CE: Any | None = None
_RULE_ANCHORS: dict[str, list[str]] | None = None
_LOAD_FAILED = False


def is_available() -> bool:
    """Return True if sentence-transformers is importable."""
    try:
        import sentence_transformers  # noqa: F401
    except ImportError:
        return False
    return True


def _ensure_loaded(model_name: str = DEFAULT_MODEL) -> bool:
    """Load the cross-encoder + rule anchors on first use. Idempotent.

    Returns True on success, False if dep missing or load failed. Sets
    module-level _LOAD_FAILED so we don't retry on every call.
    """
    global _CE, _RULE_ANCHORS, _LOAD_FAILED
    if _LOAD_FAILED:
        return False
    if _CE is not None:
        return True
    try:
        from sentence_transformers import CrossEncoder
    except ImportError:
        logger.info("semantic channel disabled: sentence-transformers not installed")
        _LOAD_FAILED = True
        return False
    try:
        _CE = CrossEncoder(model_name)
    except Exception as exc:  # noqa: BLE001 — model load can fail for many reasons
        logger.warning("semantic channel disabled: cross-encoder load failed: %s", exc)
        _LOAD_FAILED = True
        return False
    _RULE_ANCHORS = {
        r.id: [r.text] + list(r.keywords)
        for r in MCFS_ROLE_CONSTITUTION.active_rules()
    }
    return True


def match(text: str, threshold: float = DEFAULT_THRESHOLD) -> tuple[bool, list[tuple[str, float]]]:
    """Score `text` against every rule's anchor pool; report any rule above threshold.

    Returns (caught, [(rule_id, max_score), ...]) where the list is empty if
    the channel is unavailable or no rule scores above threshold. caught is
    True iff at least one rule matched.
    """
    if not _ensure_loaded():
        return False, []
    assert _CE is not None and _RULE_ANCHORS is not None

    hits: list[tuple[str, float]] = []
    for rule_id, anchors in _RULE_ANCHORS.items():
        pairs = [(text, anchor) for anchor in anchors]
        scores = _CE.predict(pairs, show_progress_bar=False)
        max_score = float(scores.max())
        if max_score >= threshold:
            hits.append((rule_id, max_score))
    return bool(hits), hits
