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


_FORBIDDEN_DEFAULT_MODULES = (
    "bittensor",
    "torch",
    "langgraph",
    "braintrust",
    "constitutional_swarm.bittensor",
    "constitutional_swarm.mac_acgs_loop",
    "constitutional_swarm.merkle_crdt",
    "constitutional_swarm.violation_subspace",
    "constitutional_swarm.private_vote",
    "constitutional_swarm.bench",
    "constitutional_swarm.forensic_benchmark",
    "constitutional_swarm.langgraph_runtime",
    "constitutional_swarm.swe_bench",
    "constitutional_swarm.latent_dna",
    "constitutional_swarm.swarm_ode",
    "constitutional_swarm.manifold",
    "numpy",
)


def test_core_import_does_not_load_sidecar_or_research_modules() -> None:
    """Default import must stay off the sidecar / research / eval graph."""
    forbidden = ", ".join(repr(name) for name in _FORBIDDEN_DEFAULT_MODULES)
    result = _run_isolated(
        f"""
        import sys
        import threading

        before_threads = {{t.ident for t in threading.enumerate()}}
        import constitutional_swarm  # noqa: F401
        after_threads = {{t.ident for t in threading.enumerate()}}

        leaked = []
        for name in ({forbidden},):
            if name in sys.modules:
                leaked.append(name)
        extra_modules = [
            name for name in sys.modules
            if name == "constitutional_swarm.bittensor"
            or name.startswith("constitutional_swarm.bittensor.")
            or name == "constitutional_swarm.swe_bench"
            or name.startswith("constitutional_swarm.swe_bench.")
        ]
        leaked.extend(sorted(set(extra_modules) - set(leaked)))
        if leaked:
            raise AssertionError(
                "core import eagerly loaded sidecar/research modules: "
                + ", ".join(leaked)
            )
        new_threads = after_threads - before_threads
        if new_threads:
            raise AssertionError(f"core import started threads: {{new_threads}}")
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "core sidecar isolation failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout


def test_stable_facade_names_import() -> None:
    result = _run_isolated(
        """
        from constitutional_swarm import (
            AgentDNA,
            ConstitutionalMesh,
            DAGCompiler,
            GovernanceReceipt,
            JSONLSettlementStore,
            PROFILE_VERSION,
            SwarmExecutor,
            TaskDAG,
            verify_bundle,
        )
        assert AgentDNA.__name__ == "AgentDNA"
        assert ConstitutionalMesh.__name__ == "ConstitutionalMesh"
        assert PROFILE_VERSION.startswith("acgs.local.intoto-dsse-shaped")
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "stable facade import failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout


def test_legacy_lazy_names_still_import_when_present() -> None:
    result = _run_isolated(
        """
        from constitutional_swarm import EvolutionLog, MerkleCRDT, MacAcgsLoop
        assert EvolutionLog.__name__ == "EvolutionLog"
        assert MerkleCRDT.__name__ == "MerkleCRDT"
        assert MacAcgsLoop.__name__ == "MacAcgsLoop"
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "legacy lazy import failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "OK" in result.stdout


def test_optional_extra_missing_error_is_actionable() -> None:
    """Missing optional deps get an extra hint; unrelated ImportErrors stay raw."""
    result = _run_isolated(
        """
        from constitutional_swarm import _annotate_optional_import_error

        hinted = _annotate_optional_import_error(
            "constitutional_swarm.latent_dna",
            ImportError("No module named 'torch'", name="torch"),
        )
        text = str(hinted)
        assert "research" in text, text
        assert "constitutional-swarm[research]" in text, text

        internal = ImportError("cannot import name 'Boom' from 'constitutional_swarm.dna'")
        same = _annotate_optional_import_error("constitutional_swarm.latent_dna", internal)
        assert same is internal
        print("OK")
        """
    )
    assert result.returncode == 0, (
        "optional extra error test failed.\n"
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
