"""Tests for the optional-extra typecheck-coverage guardrail (U2).

The guardrail asserts every declared optional extra is classified as either
``checked`` (and installed by a blocking typecheck CI job) or ``excepted`` (with a
reason), so a new extra-gated module cannot silently escape the type-check surface.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

from scripts.check_typecheck_coverage import (
    blocking_typecheck_extras,
    evaluate,
    main,
)

ROOT = Path(__file__).resolve().parent.parent


def _pyproject(optional_deps: dict, coverage: dict | None) -> dict:
    data: dict = {"project": {"optional-dependencies": optional_deps}}
    if coverage is not None:
        data["tool"] = {"constitutional_swarm": {"typecheck_coverage": coverage}}
    return data


def _job(runs: list[str], *, continue_on_error: bool = False) -> dict:
    job: dict = {"steps": [{"run": r} for r in runs]}
    if continue_on_error:
        job["continue-on-error"] = True
    return job


def _ci(jobs: dict) -> dict:
    return {"jobs": jobs}


def test_passes_when_all_classified_and_checked_covered() -> None:
    pp = _pyproject(
        {"dev": ["mypy"], "transport": ["websockets"]},
        {"checked": ["transport"], "excepted": {"dev": "tooling only"}},
    )
    ci = _ci({"typecheck-transport": _job(['pip install -e ".[dev,transport]"', "mypy"])})
    assert evaluate(pp, ci) == []


def test_fails_when_checked_extra_uncovered() -> None:
    pp = _pyproject(
        {"transport": ["websockets"]},
        {"checked": ["transport"], "excepted": {}},
    )
    # Only the no-extras typecheck job exists; transport is never installed.
    ci = _ci({"typecheck": _job(['pip install -e ".[dev]"', "mypy"])})
    failures = evaluate(pp, ci)
    assert any("transport" in f and "checked" in f for f in failures), failures


def test_fails_when_extra_unclassified() -> None:
    pp = _pyproject(
        {"transport": ["websockets"], "newextra": ["something"]},
        {"checked": ["transport"], "excepted": {}},
    )
    ci = _ci({"typecheck-transport": _job(['pip install -e ".[dev,transport]"', "mypy"])})
    failures = evaluate(pp, ci)
    assert any("newextra" in f and "unclassified" in f for f in failures), failures


def test_excepted_with_reason_passes_without_reason_fails() -> None:
    ci = _ci({"typecheck": _job(['pip install -e ".[dev]"', "mypy"])})
    with_reason = _pyproject(
        {"research": ["torch"]},
        {"checked": [], "excepted": {"research": "heavy/crash-prone"}},
    )
    assert evaluate(with_reason, ci) == []

    empty_reason = _pyproject(
        {"research": ["torch"]},
        {"checked": [], "excepted": {"research": "   "}},
    )
    failures = evaluate(empty_reason, ci)
    assert any("research" in f and "reason" in f for f in failures), failures


def test_missing_manifest_table_reports_clearly() -> None:
    pp = _pyproject({"transport": ["websockets"]}, None)
    ci = _ci({"typecheck": _job(['pip install -e ".[dev]"', "mypy"])})
    failures = evaluate(pp, ci)
    assert failures
    assert any("typecheck_coverage" in f for f in failures), failures
    # A missing table is one clear error, not one-per-extra noise.
    assert len(failures) == 1, failures


def test_blocking_typecheck_extras_parsing() -> None:
    ci = _ci(
        {
            "typecheck": _job(['pip install -e ".[dev]"', "mypy"]),
            "typecheck-transport": _job(['pip install -e ".[dev,transport]"', "mypy"]),
            # Has transport but runs no mypy -> not a typecheck job.
            "test": _job(['pip install -e ".[${{ matrix.extras }},transport]"', "pytest -q"]),
            # A typecheck job with a shell-var extra: the literal `dev` is picked
            # up but the `$EXTRA` token must be dropped, not counted as covered.
            "typecheck-dyn": _job(['pip install -e ".[dev,$EXTRA]"', "mypy"]),
            # Runs mypy but is non-blocking -> does not satisfy coverage.
            "research-typecheck": _job(
                ['pip install -e ".[dev,research]"', "mypy"], continue_on_error=True
            ),
        }
    )
    extras = blocking_typecheck_extras(ci)
    assert extras == {"dev", "transport"}, extras
    # No interpolation / shell-var token may leak in.
    assert not any("matrix" in e or "{" in e or "$" in e for e in extras), extras


def test_real_repo_pyproject_and_ci_pass() -> None:
    pp = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    failures = evaluate(pp, ci)
    assert failures == [], failures


def test_main_exits_zero_on_real_repo() -> None:
    assert main([]) == 0
