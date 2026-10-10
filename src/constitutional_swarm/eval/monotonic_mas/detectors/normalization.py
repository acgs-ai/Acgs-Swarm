"""Payload normalization for role-drift detection.

Maps common evasion patterns back toward canonical form before the
constitution matcher sees the text. Cheap defense against trivial
obfuscation; NOT a substitute for semantic-aware detection. Callers run the
matcher on BOTH the raw and the normalized payload, so normalization only
ever adds catches for literal patterns that the raw pass already sees
(e.g. ``rm -rf``).

Pipeline (in order):
1. Unicode NFKC — folds fullwidth / compatibility forms (``ｄｉｓａｂｌｅ``)
   and non-breaking spaces to their plain equivalents.
2. Drop Unicode format characters (category ``Cf``) — zero-width space /
   joiners, soft hyphen, BOM, bidi controls.
3. Confusables map — a small, bounded table of Cyrillic and Greek letters
   that render identically to Latin letters (``_CONFUSABLES``). Not the full
   Unicode confusables set; covers the common single-letter swaps.
4. Identifier splitting — camelCase / PascalCase boundaries become spaces
   (``disableSafetyChecks`` -> ``disable Safety Checks``), and ``-`` / ``.``
   between two word characters become spaces (``disable-safety``,
   ``disable.safety``). A dash that follows whitespace or another dash is
   kept, so shell flags (``rm -rf``, ``--force``) and paths survive.
5. Underscore separators: ``_`` -> ``' '``.
6. Repeated whitespace collapse.
7. Leetspeak digits in mixed alpha-digit tokens: 4->a, 3->e, 1->i, 0->o,
   5->s, 7->t, 8->b.

Does NOT handle (out of scope, documented):
- Synonyms / semantic paraphrase / word reordering (needs the semantic
  channel).
- String concatenation (``"dis" + "able"``), encodings (base64, hex, rot13)
  and other constructions that need evaluation rather than canonicalization.
- Confusables outside ``_CONFUSABLES`` (e.g. Armenian, Cherokee, math
  alphanumerics not folded by NFKC).
- Pure-digit tokens like "2026" (kept as-is to avoid breaking version
  strings, counts, identifiers).
- Hyphenated rule vocabulary: ``super-majority`` normalizes to
  ``super majority``; the raw pass still sees the hyphenated form.
"""

from __future__ import annotations

import re
import unicodedata

_LEET_MAP = str.maketrans(
    {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "8": "b"}
)

# Bounded Cyrillic/Greek -> Latin look-alike table (visual identity in common
# fonts). Keep this small and reviewed; extend only with a regression test.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic lowercase
        "а": "a",  # а
        "е": "e",  # е
        "о": "o",  # о
        "р": "p",  # р
        "с": "c",  # с
        "х": "x",  # х
        "у": "y",  # у
        "і": "i",  # і
        "ј": "j",  # ј
        "ѕ": "s",  # ѕ
        "ԁ": "d",  # ԁ
        "һ": "h",  # һ
        # Cyrillic uppercase
        "А": "A",  # А
        "В": "B",  # В
        "Е": "E",  # Е
        "К": "K",  # К
        "М": "M",  # М
        "Н": "H",  # Н
        "О": "O",  # О
        "Р": "P",  # Р
        "С": "C",  # С
        "Т": "T",  # Т
        "Х": "X",  # Х
        "І": "I",  # І
        "Ј": "J",  # Ј
        "Ѕ": "S",  # Ѕ
        # Greek lowercase
        "α": "a",  # α
        "ο": "o",  # ο
        "ρ": "p",  # ρ
        "ι": "i",  # ι
        "κ": "k",  # κ
        "ν": "v",  # ν
        "υ": "u",  # υ
        # Greek uppercase
        "Α": "A",  # Α
        "Β": "B",  # Β
        "Ε": "E",  # Ε
        "Ζ": "Z",  # Ζ
        "Η": "H",  # Η
        "Ι": "I",  # Ι
        "Κ": "K",  # Κ
        "Μ": "M",  # Μ
        "Ν": "N",  # Ν
        "Ο": "O",  # Ο
        "Ρ": "P",  # Ρ
        "Τ": "T",  # Τ
        "Υ": "Y",  # Υ
        "Χ": "X",  # Χ
    }
)

# lower/digit -> Upper  (disableSafety -> disable Safety)
# UPPER -> Upper+lower  (HTTPServer -> HTTP Server)
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# '-' or '.' joining two word characters; a dash after whitespace/dash stays.
_WORD_JOINER = re.compile(r"(?<=[^\W_])[-.](?=[^\W_])")


def _delet_token(tok: str) -> str:
    """Apply leetspeak reverse-map only to tokens that mix letters and digits."""
    if any(c.isalpha() for c in tok) and any(c.isdigit() for c in tok):
        return tok.translate(_LEET_MAP)
    return tok


def _fold_unicode(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(_CONFUSABLES)


def normalize_payload(text: str) -> str:
    """Return a canonicalized form of `text` for matcher consumption."""
    text = _fold_unicode(text)
    text = _CAMEL_BOUNDARY.sub(" ", text)
    text = _WORD_JOINER.sub(" ", text)
    text = text.replace("_", " ")
    text = re.sub(r"\s+", " ", text)
    return " ".join(_delet_token(tok) for tok in text.split(" "))
