"""The regex depth scanner must accept and reject exactly what the loop did.

``strict_json._scan_depth`` runs on every authority IPC frame and every W2
ledger row.  It replaced a character-by-character loop; the loop is kept here
as the reference so the two can be compared on the same inputs.
"""

from __future__ import annotations

import json
import random
import time

import pytest

from constitutional_swarm.strict_json import StrictJSONError, _scan_depth, loads


def _reference_scan_depth(text: str, max_depth: int) -> None:
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


def _outcome(scan: object, text: str, max_depth: int) -> str:
    try:
        scan(text, max_depth)  # type: ignore[operator]
    except StrictJSONError as error:
        return str(error)
    return "accepted"


_ALPHABET = (
    '"',
    "\\",
    "[",
    "]",
    "{",
    "}",
    "a",
    ",",
    ":",
    "\n",
    " ",
    "é",
    "\\\\",
    '\\"',
    "\\u005b",
    "1",
)
_DEPTHS = (0, 1, 2, 3, 5, 64)


def test_random_token_soup_matches_reference() -> None:
    rng = random.Random(20261123)
    for _ in range(40_000):
        text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 40)))
        depth = rng.choice(_DEPTHS)
        assert _outcome(_scan_depth, text, depth) == _outcome(_reference_scan_depth, text, depth), (
            text,
            depth,
        )


def _random_json(rng: random.Random, depth: int) -> object:
    if depth == 0 or rng.random() < 0.2:
        return rng.choice(['x\\"[{', 1, None, "]}", "\\"])
    if rng.random() < 0.5:
        return [_random_json(rng, depth - 1) for _ in range(rng.randint(0, 3))]
    return {
        rng.choice(['k"[', "a", "{"]) + str(index): _random_json(rng, depth - 1)
        for index in range(rng.randint(0, 3))
    }


def test_valid_and_truncated_json_matches_reference() -> None:
    rng = random.Random(1123)
    for _ in range(4_000):
        text = json.dumps(_random_json(rng, rng.randint(0, 9)), ensure_ascii=rng.random() < 0.5)
        if rng.random() < 0.3:
            text = text[: rng.randint(0, len(text))]
        for depth in (0, 2, 4, 6, 8, 64):
            assert _outcome(_scan_depth, text, depth) == _outcome(
                _reference_scan_depth, text, depth
            ), (text, depth)


@pytest.mark.parametrize(
    "text",
    (
        '"' + "a" * 400_000,
        '"' + "\\" * 400_001,
        '"' * 400_000,
        '"\\' * 200_000,
        "[]" * 200_000,
        '{"a":' * 60 + '"' + "a" * 400_000,
    ),
    ids=("unterminated", "backslashes", "quotes", "quote-backslash", "pairs", "nested"),
)
def test_adversarial_input_is_scanned_in_linear_time(text: str) -> None:
    expected = _outcome(_reference_scan_depth, text, 64)
    started = time.perf_counter()
    assert _outcome(_scan_depth, text, 64) == expected
    # Linear scanning takes a few milliseconds here; backtracking would not finish.
    assert time.perf_counter() - started < 5.0


def test_loads_still_enforces_depth_and_ignores_brackets_in_strings() -> None:
    assert loads('{"t":"[[[[ \\" ]]]] {{{{"}', max_bytes=64, max_depth=1) == {
        "t": '[[[[ " ]]]] {{{{'
    }
    with pytest.raises(StrictJSONError, match="nesting depth"):
        loads("[[[]]]", max_bytes=16, max_depth=2)
    assert loads("[[[]]]", max_bytes=16, max_depth=3) == [[[]]]
    with pytest.raises(StrictJSONError, match="invalid JSON"):
        loads('"[[[[[[[[', max_bytes=16, max_depth=1)
