"""Bounded strict JSON parsing and deterministic project JSON encoding.

``canonical_dumps`` is intended only for new project digests.  It is not an
RFC 8785 implementation and must not replace an existing byte-stable encoder.

Data, syntax, encoding, resource-policy, and canonicalization failures raise
``StrictJSONError``. Wrong argument or value types raise ``TypeError``.
"""

from __future__ import annotations

import json
import math
from typing import Any, cast

__all__ = ["StrictJSONError", "canonical_dumps", "loads", "reject_duplicate_keys"]


class StrictJSONError(ValueError):
    """Raised when JSON data violates this module's strict policy."""


def _require_utf8(value: str, *, context: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise StrictJSONError(f"{context} is not valid UTF-8") from exc


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while rejecting every duplicate member name."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str:
            raise TypeError("JSON object keys must be exact strings")
        _require_utf8(key, context="JSON object key")
        if key in result:
            raise StrictJSONError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _scan_depth(text: str, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise StrictJSONError("JSON nesting depth exceeds max_depth")
        elif char in "]}" and depth:
            depth -= 1


def _reject_constant(token: str) -> Any:
    raise StrictJSONError(f"JSON number must be finite: {token}")


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise StrictJSONError(f"JSON number must be finite: {token}")
    return value


def _reject_float(token: str) -> Any:
    raise StrictJSONError(f"JSON float is not allowed: {token}")


def _validate_decoded_strings(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        current_type = type(current)
        if current_type is str:
            _require_utf8(cast(str, current), context="decoded JSON string")
        elif current_type is list:
            stack.extend(cast("list[Any]", current))
        elif current_type is dict:
            mapping = cast("dict[str, Any]", current)
            for key, item in mapping.items():
                _require_utf8(key, context="decoded JSON object key")
                stack.append(item)


def loads(
    raw: str | bytes | bytearray,
    *,
    max_bytes: int,
    max_depth: int = 64,
    allow_float: bool = True,
) -> Any:
    """Decode bounded JSON while rejecting ambiguous or non-finite input."""
    if type(max_bytes) is not int:
        raise TypeError("max_bytes must be an integer")
    if max_bytes <= 0:
        raise StrictJSONError("max_bytes must be positive")
    if type(max_depth) is not int:
        raise TypeError("max_depth must be an integer")
    if max_depth < 0:
        raise StrictJSONError("max_depth must be non-negative")
    if type(allow_float) is not bool:
        raise TypeError("allow_float must be a boolean")

    raw_type = type(raw)
    if raw_type not in (str, bytes, bytearray):
        raise TypeError("raw must be an exact str, bytes, or bytearray")
    if len(raw) > max_bytes:
        raise StrictJSONError("JSON input exceeds max_bytes byte limit")

    if raw_type is str:
        string_raw = cast(str, raw)
        try:
            encoded = string_raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise StrictJSONError("JSON text is not valid UTF-8") from exc
    elif raw_type is bytes:
        encoded = cast(bytes, raw)
    elif raw_type is bytearray:
        encoded = bytes(cast(bytearray, raw))

    if len(encoded) > max_bytes:
        raise StrictJSONError("JSON input exceeds max_bytes byte limit")
    if raw_type is str:
        text = cast(str, raw)
    else:
        try:
            text = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("JSON bytes are not valid UTF-8") from exc
    _scan_depth(text, max_depth)
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float if allow_float else _reject_float,
        )
        _validate_decoded_strings(decoded)
        return decoded
    except StrictJSONError:
        raise
    except RecursionError as exc:
        raise StrictJSONError("JSON decoder recursion limit exceeded") from exc
    except ValueError as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc


def _detached_json_tree(value: object) -> Any:
    """Validate and copy per-container snapshots without invoking callbacks."""
    holder: list[Any] = [None]
    active: set[int] = set()
    stack: list[tuple[bool, object, Any, int | str]] = [(False, value, holder, 0)]

    while stack:
        exiting, current, parent, slot = stack.pop()
        current_type = type(current)
        if exiting:
            active.remove(id(current))
            continue
        if current is None or current_type in (bool, int, str):
            if current_type is str:
                _require_utf8(cast(str, current), context="canonical JSON string")
            parent[slot] = current
            continue
        if current_type is float:
            if not math.isfinite(cast(float, current)):
                raise StrictJSONError("canonical JSON numbers must be finite")
            parent[slot] = current
            continue
        if current_type not in (list, dict):
            raise TypeError(f"unsupported canonical JSON type: {current_type.__name__}")

        identity = id(current)
        if identity in active:
            raise StrictJSONError("circular reference in canonical JSON value")
        active.add(identity)
        stack.append((True, current, parent, slot))

        if current_type is list:
            snapshot = cast("list[Any]", current).copy()
            detached_list: list[Any] = [None] * len(snapshot)
            parent[slot] = detached_list
            for index in range(len(snapshot) - 1, -1, -1):
                stack.append((False, snapshot[index], detached_list, index))
            continue

        detached_dict: dict[str, Any] = {}
        parent[slot] = detached_dict
        items = list(cast("dict[object, Any]", current).items())
        for key, item in reversed(items):
            if type(key) is not str:
                raise TypeError("canonical JSON object keys must be exact strings")
            _require_utf8(key, context="canonical JSON object key")
            stack.append((False, item, detached_dict, key))

    return holder[0]


def canonical_dumps(obj: object) -> str:
    """Encode detached per-container snapshots with stable project settings.

    The copy prevents mutation between validation and encoding.  It is not a
    globally atomic snapshot if another thread mutates different containers
    while the tree is being copied.

    Keys sort by Unicode code-point order. ``-0.0`` and ``0.0`` remain distinct,
    as do ``1.0`` and ``1``; callers hashing numeric data must normalize it.
    """
    detached = _detached_json_tree(obj)
    try:
        return json.dumps(
            detached,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except RecursionError as exc:
        raise StrictJSONError("canonical JSON recursion limit exceeded") from exc
    except ValueError as exc:
        raise StrictJSONError(f"canonical JSON encoding failed: {exc}") from exc
