#!/usr/bin/env python3
"""Guardrail: every optional extra must be in the typecheck surface or excepted.

The mypy gate only "sees" the real types of a dependency that ships ``py.typed``;
a type error in an extra-gated module is invisible until that extra is installed
in the typecheck environment. This check asserts that every declared optional
extra in ``[project.optional-dependencies]`` is classified in the
``[tool.constitutional_swarm.typecheck_coverage]`` manifest as either:

- ``checked`` — type-bearing; it MUST be installed by a *blocking* typecheck CI
  job (a job and ``mypy`` step whose ``continue-on-error`` is absent or false); or
- ``excepted`` — not type-checked by the gate; it MUST carry a non-empty reason.

So a newly added extra-gated module cannot silently escape the type surface.

Runs fully offline and needs only ``pyyaml`` + ``tomllib`` (stdlib, 3.11+). Run
via ``make typecheck-coverage`` or directly::

    uv run --no-sync python scripts/check_typecheck_coverage.py

Exit code is 0 only when every declared extra is correctly classified and every
``checked`` extra is covered by a blocking typecheck job.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

# Matches the extras inside a `pip install -e ".[dev,transport]"` step.
_EXTRAS_RE = re.compile(r"\.\[([^\]]+)\]")
# A typecheck job is one whose step invokes mypy as a bare command.
_MYPY_RE = re.compile(r"\bmypy\b")


def _continue_on_error_is_blocking(config: dict[str, Any]) -> bool:
    """Return True only when continue-on-error is absent or literal False."""

    return "continue-on-error" not in config or config["continue-on-error"] is False


def blocking_typecheck_extras(ci: dict[str, Any]) -> set[str]:
    """Return the union of extras installed by every *blocking* typecheck job.

    A job qualifies when (a) job-level ``continue-on-error`` is absent or
    literal ``False`` and (b) at least one step's ``run`` invokes ``mypy`` with
    step-level ``continue-on-error`` absent or literal ``False``. Dynamic
    expressions and other non-boolean values are treated as non-blocking because
    they can allow failure without failing the workflow.
    Extras are extracted from that same job's ``pip install -e ".[...]"`` step;
    interpolation tokens like ``${{ matrix.extras }}`` are ignored so the
    ``test`` job's templated install can never leak in.
    """

    extras: set[str] = set()
    for job in (ci.get("jobs") or {}).values():
        if not isinstance(job, dict) or not _continue_on_error_is_blocking(job):
            continue
        steps = [step for step in (job.get("steps") or []) if isinstance(step, dict)]
        runs = [step.get("run", "") for step in steps]
        has_blocking_mypy = any(
            _MYPY_RE.search(step.get("run", ""))
            and _continue_on_error_is_blocking(step)
            for step in steps
        )
        if not has_blocking_mypy:
            continue
        for run in runs:
            for match in _EXTRAS_RE.finditer(run):
                for token in match.group(1).split(","):
                    token = token.strip()
                    # Reject any interpolation/shell token (`${{ matrix.extras }}`,
                    # `$VAR`, `{...}`) — real extra names are [a-z0-9._-] only.
                    if token and "$" not in token and "{" not in token:
                        extras.add(token)
    return extras


def evaluate(pyproject: dict[str, Any], ci: dict[str, Any]) -> list[str]:
    """Return a list of failure messages; an empty list means the gate passes."""

    declared = set((pyproject.get("project") or {}).get("optional-dependencies") or {})
    coverage = (
        ((pyproject.get("tool") or {}).get("constitutional_swarm") or {}).get(
            "typecheck_coverage"
        )
        or {}
    )

    if not coverage:
        return [
            "missing or empty [tool.constitutional_swarm.typecheck_coverage] table "
            "in pyproject.toml — classify every optional extra as 'checked' or 'excepted'"
        ]

    checked = set(coverage.get("checked") or [])
    excepted: dict[str, Any] = dict(coverage.get("excepted") or {})
    classified = checked | set(excepted)
    covered = blocking_typecheck_extras(ci)

    failures: list[str] = []

    for extra in sorted(declared - classified):
        failures.append(
            f"extra '{extra}' is unclassified — add it to "
            "[tool.constitutional_swarm.typecheck_coverage] as 'checked' or 'excepted'"
        )

    for extra in sorted(checked):
        if extra not in covered:
            failures.append(
                f"extra '{extra}' is classified 'checked' but no blocking typecheck "
                "CI job installs it (expected it in a `mypy` job's pip install)"
            )

    for extra in sorted(excepted):
        reason = excepted.get(extra)
        if not (isinstance(reason, str) and reason.strip()):
            failures.append(
                f"extra '{extra}' is 'excepted' but carries no reason — add one"
            )

    return failures


def main(argv: list[str] | None = None) -> int:
    """Load the repo's pyproject + CI workflow, evaluate, and print the verdict."""

    # argv is accepted for symmetry with other script entry points; the check
    # always runs against the repo's own pyproject.toml and ci.yml.
    _ = argv
    print("=== typecheck-coverage: every optional extra is checked or excepted ===\n")

    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    ci = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))

    failures = evaluate(pyproject, ci)
    if not failures:
        print("  [PASS] every declared optional extra is classified and covered")
        print("\ntypecheck-coverage: ALL CHECKS PASSED")
        return 0

    for failure in failures:
        print(f"  [FAIL] {failure}")
    print("\ntypecheck-coverage: FAILURES DETECTED (see [FAIL] lines above)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
