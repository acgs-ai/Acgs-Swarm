"""Core import-isolation regression tests.

The top-level ``constitutional_swarm`` package must import cleanly *and cheaply*
without any optional extra installed. In particular it must not eagerly import
the optional ``bittensor`` subpackage — doing so previously added ~458ms to
every ``import constitutional_swarm`` (RUNTIME_OPTIMIZATION_REPORT.md bottleneck
B1) and violated the "keep the core import-free of optional extras" rule.

These assertions run in a *fresh* interpreter via subprocess because, inside the
pytest process, ``constitutional_swarm.bittensor`` is almost certainly already
imported by other tests or collection — an in-process ``sys.modules`` check
would be false-green. The subprocess gives a hermetic interpreter.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run_isolated(snippet: str) -> subprocess.CompletedProcess[str]:
    """Run ``snippet`` in a fresh interpreter; return the completed process."""
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(snippet)],
        capture_output=True,
        text=True,
    )


def test_core_import_does_not_load_bittensor() -> None:
    """`import constitutional_swarm` must not pull in the bittensor subpackage."""
    result = _run_isolated(
        """
        import sys

        import constitutional_swarm  # noqa: F401

        leaked = sorted(
            name
            for name in sys.modules
            if name == "constitutional_swarm.bittensor"
            or name.startswith("constitutional_swarm.bittensor.")
        )
        if leaked:
            raise AssertionError(
                "core import eagerly loaded bittensor submodules: " + ", ".join(leaked)
            )
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "core import isolation failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout


def test_mac_acgs_loop_import_does_not_load_bittensor() -> None:
    """Importing the mac_acgs_loop module alone must also stay bittensor-free.

    The eager import lived in ``mac_acgs_loop``; guard the module directly so a
    regression is attributed precisely even if some other module later changes.
    """
    result = _run_isolated(
        """
        import sys

        import constitutional_swarm.mac_acgs_loop  # noqa: F401

        leaked = sorted(
            name
            for name in sys.modules
            if name == "constitutional_swarm.bittensor"
            or name.startswith("constitutional_swarm.bittensor.")
        )
        if leaked:
            raise AssertionError(
                "mac_acgs_loop import eagerly loaded bittensor submodules: "
                + ", ".join(leaked)
            )
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "mac_acgs_loop import isolation failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout
