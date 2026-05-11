"""Smoke test for examples/langgraph_swarm_demo.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_demo_runs_to_completion():
    repo_root = Path(__file__).resolve().parent.parent
    demo = repo_root / "examples" / "langgraph_swarm_demo.py"
    assert demo.is_file(), f"demo not found at {demo}"

    proc = subprocess.run(
        [sys.executable, str(demo)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(repo_root),
        check=False,
    )

    assert proc.returncode == 0, (
        f"demo exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    out = proc.stdout
    for key in (
        "total=",
        "resolved=",
        "resolve_rate=",
        "crdt_size=",
        "governed_count=",
        "mean_intervention=",
    ):
        assert key in out, f"missing {key!r} in demo output:\n{out}"
