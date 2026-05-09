"""Payload normalization for role-drift detection.

Maps common evasion patterns back toward canonical form before the
constitution matcher sees the text. Cheap defense against trivial
obfuscation; NOT a substitute for semantic-aware detection.

Handles:
- Underscore separators: '_' -> ' '
- Leetspeak digits in mixed alpha-digit tokens: 4->a, 3->e, 1->i, 0->o,
  5->s, 7->t, 8->b
- Repeated whitespace collapse

Does NOT handle:
- Synonyms / semantic paraphrase / word reordering (out of scope; needs
  embedding similarity)
- Dash separators (would break literal 'rm -rf' patterns)
- Pure-digit tokens like "2026" (kept as-is to avoid breaking version
  strings, counts, identifiers)
"""

from __future__ import annotations

import re

_LEET_MAP = str.maketrans(
    {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "8": "b"}
)


def _delet_token(tok: str) -> str:
    """Apply leetspeak reverse-map only to tokens that mix letters and digits."""
    if any(c.isalpha() for c in tok) and any(c.isdigit() for c in tok):
        return tok.translate(_LEET_MAP)
    return tok


def normalize_payload(text: str) -> str:
    """Return a canonicalized form of `text` for matcher consumption."""
    text = text.replace("_", " ")
    text = re.sub(r"\s+", " ", text)
    return " ".join(_delet_token(tok) for tok in text.split(" "))
