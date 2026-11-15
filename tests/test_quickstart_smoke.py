"""Offline smoke test: execute the Python block of docs/quickstart.md verbatim."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, cast

import pytest

QUICKSTART = Path(__file__).resolve().parents[1] / "docs" / "quickstart.md"


def _quickstart_source() -> str:
    blocks = re.findall(r"```python\n(.*?)```", QUICKSTART.read_text(), flags=re.DOTALL)
    assert len(blocks) == 1, "docs/quickstart.md must contain exactly one python block"
    return blocks[0]


def test_quickstart_runs_offline_and_settles(capsys: pytest.CaptureFixture[str]) -> None:
    source = _quickstart_source()
    namespace: dict[str, object] = {"__name__": "quickstart"}
    exec(compile(source, str(QUICKSTART), "exec"), namespace)  # noqa: S102

    result = cast(Any, namespace["result"])
    assert (result.accepted, result.quorum_met, result.settled) == (True, True, True)

    printed = capsys.readouterr().out.strip()
    expected = ast.literal_eval(printed)
    assert expected == {"accepted": True, "quorum_met": True, "settled": True}
