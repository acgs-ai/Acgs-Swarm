"""Packaging isolation checks for the published wheel."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = ROOT / "scripts" / "verify_isolated_wheel.py"
_SPEC = importlib.util.spec_from_file_location("verify_isolated_wheel", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_wheel = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_wheel)


def test_script_exports_cover_the_isolation_contract() -> None:
    assert "numpy" in _wheel.FORBIDDEN_MODULES
    assert "braintrust" in _wheel.FORBIDDEN_MODULES
    assert "constitutional_swarm.swe_bench" in _wheel.FORBIDDEN_MODULES
    assert "AgentDNA" in _wheel.FACADE_SYMBOLS
    assert "PROFILE_VERSION" in _wheel.FACADE_SYMBOLS
    assert _SCRIPT.is_file()


def test_metadata_helper_rejects_core_numpy() -> None:
    try:
        _wheel.assert_core_requires(["acgs-lite>=2.8.1", "numpy>=1.24"])
    except SystemExit as exc:
        assert "numpy leaked" in str(exc)
    else:
        raise AssertionError("core numpy must fail closed")


def test_metadata_helper_accepts_extra_only_numpy() -> None:
    _wheel.assert_core_requires(
        [
            "acgs-lite>=2.8.1",
            "cryptography>=44.0.2",
            'numpy>=1.24; extra == "research"',
            'braintrust==0.31.0; extra == "braintrust"',
        ]
    )
