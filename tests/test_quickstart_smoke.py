"""Offline smoke test: execute the Python blocks of docs/quickstart.md and README.md verbatim."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = ROOT / "docs" / "quickstart.md"
README = ROOT / "README.md"


def _quickstart_source(doc: Path, *, index: int = 0, expected_blocks: int | None = None) -> str:
    blocks = re.findall(r"```python\n(.*?)```", doc.read_text(encoding="utf-8"), flags=re.DOTALL)
    if expected_blocks is not None:
        assert len(blocks) == expected_blocks, (
            f"{doc.name} must contain {expected_blocks} python block(s)"
        )
    else:
        assert len(blocks) > index, f"{doc.name} missing python block at index {index}"
    return blocks[index]


def test_quickstart_runs_offline_and_settles(capsys: pytest.CaptureFixture[str]) -> None:
    source = _quickstart_source(QUICKSTART, index=0, expected_blocks=1)
    namespace: dict[str, object] = {"__name__": "quickstart"}
    exec(compile(source, str(QUICKSTART), "exec"), namespace)  # noqa: S102

    result = cast(Any, namespace["result"])
    assert (result.accepted, result.quorum_met, result.settled) == (True, True, True)

    printed = capsys.readouterr().out.strip()
    expected = ast.literal_eval(printed)
    assert expected == {"accepted": True, "quorum_met": True, "settled": True}


def test_readme_quickstart_runs_offline_and_settles(capsys: pytest.CaptureFixture[str]) -> None:
    source = _quickstart_source(README, index=0, expected_blocks=1)
    namespace: dict[str, object] = {"__name__": "readme_quickstart"}
    exec(compile(source, str(README), "exec"), namespace)  # noqa: S102

    result = cast(Any, namespace["result"])
    assert (result.accepted, result.quorum_met, result.settled) == (True, True, True)

    printed = capsys.readouterr().out.strip()
    assert printed == "True True True"
