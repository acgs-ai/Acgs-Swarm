# Runbook: test

## Command
```bash
make test             # default suite: excludes slow/benchmark/e2e/research/bittensor
make test-all         # adds research-marked tests
```

Equivalent raw invocation:
```bash
uv run --no-sync pytest tests/ --import-mode=importlib \
  -m "not slow and not benchmark and not e2e and not research and not bittensor" -q
```

## Notes
- Tests run fully offline; CI injects dummy `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.
- Repo root must be on the pytest path so a few tests can `import scripts.*`.
  This is configured in `pyproject.toml` (`pythonpath = ["src", "."]`).
- Markers are defined in `pyproject.toml [tool.pytest.ini_options].markers`.

## Subsets
```bash
uv run --no-sync pytest tests/test_governed_handoff.py -q     # one file
uv run --no-sync pytest tests/ -m security -q                  # security regressions
```

## Common failures
| Symptom | Cause | Fix |
|---|---|---|
| `No module named 'scripts'` at collection | repo root not on path | ensure `pythonpath` includes `.` (already set) |
| `No module named 'websockets'` | transport extra missing | `make setup` (installs transport) |
