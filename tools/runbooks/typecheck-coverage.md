# Runbook: typecheck-coverage

Asserts the mypy type gate cannot be silently bypassed by an optional extra. The
gate only "sees" the real types of a dependency that ships `py.typed`, so a type
error in an extra-gated module is invisible until that extra is installed in the
typecheck environment. Runs offline; needs only `pyyaml` + `tomllib` (stdlib 3.11+).

## Command
```bash
make typecheck-coverage    # uv run --no-sync python scripts/check_typecheck_coverage.py
```

## What it validates
Every extra in `pyproject.toml [project.optional-dependencies]` must be classified
in `[tool.constitutional_swarm.typecheck_coverage]` as one of:

- **`checked`** — type-bearing (ships `py.typed`, used in type positions). MUST be
  installed by a *blocking* typecheck CI job (a job whose step runs `mypy` and is
  not `continue-on-error`). The parser reads which extras each such job installs
  from its `pip install -e ".[...]"` step in `.github/workflows/ci.yml`.
- **`excepted`** — not type-checked by the gate. MUST carry a non-empty reason
  (stub-less, heavy/crash-prone, or a tracked deferral).

## Output
A `PASS`/`FAIL` verdict. Non-zero exit when an extra is unclassified, a `checked`
extra is not installed by any blocking typecheck job, or an `excepted` extra has no
reason.

## Fixing failures
- **Unclassified extra** — you added an extra to `[project.optional-dependencies]`.
  Classify it: `checked` if it ships `py.typed` and is used in type positions (and
  add it to a typecheck job's install), otherwise `excepted` with a reason.
- **`checked` but uncovered** — add the extra to a blocking typecheck job's
  `pip install` line in `ci.yml`, or reclassify it `excepted`.
- **`excepted` without a reason** — add a one-line reason.

The check is idempotent. See `DECISIONS.md` for the canonical typecheck-surface
decision and `BLOCKERS.md` B3 for the type-gate history.
