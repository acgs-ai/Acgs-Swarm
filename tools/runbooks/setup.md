# Runbook: setup

Bring a fresh checkout to a runnable state.

## Command
```bash
make setup            # uv sync --no-sources --extra dev --extra transport
```

## Why `--no-sources`
`pyproject.toml` pins `acgs-lite = { workspace = true }` for in-monorepo
development. A standalone clone has no uv workspace, so a plain `uv sync`
fails to resolve `acgs-lite`. `make setup` passes `--no-sources` so uv
resolves `acgs-lite>=2.8.1` from PyPI instead. See BLOCKERS.md (B1).

## Prerequisites
- `uv` on PATH — https://docs.astral.sh/uv/getting-started/installation/
- Network access to PyPI

## Verify
```bash
make smoke            # import + CLI sanity, no credentials needed
```

## Common failures
| Symptom | Cause | Fix |
|---|---|---|
| `'uv' not found` | uv not installed | install uv, re-run |
| `references a workspace ... not a workspace member` | ran bare `uv sync` | use `make setup` (adds `--no-sources`) |
| `ModuleNotFoundError: acgs_lite` | sync skipped/failed | re-run `make setup`, check network |
