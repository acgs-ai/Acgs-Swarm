"""Single unified-diff extractor shared by every SWE-bench patch adapter.

Every backend (Anthropic, Vertex, OAuth, Gemini, Codex CLI, mini-swe-agent and
``scripts/run_mc_swarm.py``) must turn raw model output into a patch with the
same rules; per-adapter copies drifted and let unapplyable hunk-only output
through some paths. Import :func:`extract_unified_diff` instead of copying it.
"""

from __future__ import annotations

import re

# Match the START of an applyable unified diff. A file header is required
# (``diff --git``, ``--- a/``, or ``+++ b/``): ``@@`` hunks alone are NOT
# applyable because ``git apply`` needs to know which file to patch. Accepting
# ``@@`` let LLMs that emitted hunks-only output (e.g. continuing from a prior
# agent's truncated context) produce "successful" but unapplyable patches.
DIFF_MARKER = re.compile(r"(?m)^(?:diff --git |--- [ab]?/|\+\+\+ [ab]?/)")


def extract_unified_diff(text: str) -> str:
    """Extract a unified diff from *text*, stripping code fences and prose prefix.

    Cuts from the first file-header marker (``diff --git``, ``--- a/`` or
    ``+++ b/``). Prose preceding that marker is discarded so the result is
    patch-applyable by ``git apply``. Returns ``""`` when no file header is
    present, including hunks-only (``@@``) output.
    """
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    m = DIFF_MARKER.search(stripped)
    if not m:
        return ""
    diff_only = stripped[m.start() :]
    return diff_only + ("\n" if not diff_only.endswith("\n") else "")


__all__ = ["DIFF_MARKER", "extract_unified_diff"]
