"""Versioned typed framing for new digests and ASCII plain identifiers.

The frozen transcript is ``PREFIX || frame(domain) || frame(tag || payload)``
for each part, where ``frame(x)`` is an unsigned eight-byte big-endian length
followed by ``x``.  Tags are ``b``, ``s``, and ``i`` for bytes, UTF-8 strings,
and minimal decimal ASCII integers respectively.  Existing digest encodings
must not be migrated to this new format implicitly.

Wrong argument types raise ``TypeError``. Invalid domains, unencodable parts,
oversized frames, and identifiers outside the documented grammar raise
``ValueError``.
"""

from __future__ import annotations

import hashlib
import re
from typing import cast

__all__ = ["framed_digest", "require_plain_id"]

_DIGEST_PREFIX = b"constitutional-swarm.framed-digest.v1\x00"
_PLAIN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)


def _frame(payload: bytes) -> bytes:
    try:
        length = len(payload).to_bytes(8, "big")
    except OverflowError as exc:
        raise ValueError("framed payload is too large") from exc
    return length + payload


def framed_digest(domain: bytes, *parts: bytes | str | int) -> bytes:
    """Return a SHA-256 digest over a versioned, typed transcript."""
    if type(domain) is not bytes:
        raise TypeError("domain must be exact bytes")
    if not domain:
        raise ValueError("domain must not be empty")

    digest = hashlib.sha256()
    digest.update(_DIGEST_PREFIX)
    digest.update(_frame(domain))
    for part in parts:
        part_type = type(part)
        if part_type is bytes:
            payload = b"b" + cast(bytes, part)
        elif part_type is str:
            try:
                payload = b"s" + cast(str, part).encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ValueError("string part is not valid UTF-8") from exc
        elif part_type is int:
            try:
                payload = b"i" + str(cast(int, part)).encode("ascii")
            except (UnicodeEncodeError, ValueError) as exc:
                raise ValueError("integer part cannot be encoded") from exc
        else:
            raise TypeError("parts must be exact bytes, str, or int values")
        digest.update(_frame(payload))
    return digest.digest()


def require_plain_id(s: str) -> str:
    """Require an ASCII identifier of at most 128 characters.

    The first character is alphanumeric; remaining characters are ASCII
    alphanumerics or ``.``, ``_``, ``:``, and ``-``. Path separators,
    whitespace, non-ASCII text, and the substring ``..`` are rejected.
    """
    if type(s) is not str:
        raise TypeError("identifier must be an exact string")
    if _PLAIN_ID_PATTERN.fullmatch(s) is None or ".." in s:
        raise ValueError("identifier must match the ASCII plain-ID grammar")
    return s
