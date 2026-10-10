"""Shared numeric validation for Bittensor economics boundaries."""

from __future__ import annotations

import math
from numbers import Real


def _validate_finite(
    name: str,
    value: object,
    minimum: float | None = 0.0,
    maximum: float | None = None,
) -> float:
    """Return a finite float within the requested inclusive range."""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a finite number")
    try:
        converted = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be finite")
    if minimum is not None and converted < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and converted > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return converted


def _validate_count(
    name: str,
    value: object,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    """Return an integer count within the requested inclusive range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be representable as a finite number") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be representable as a finite number")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return value
