# Contributing to Acgs-Swarm

Thanks for helping improve `constitutional-swarm`.

## Before you start
1. Read [`README.md`](README.md) for project positioning and maturity tiers.
2. Read [`docs/community.md`](docs/community.md) for contributor pathways.
3. Check open issues and discussions before starting major work.

## Local setup
```bash
# from repository root
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Optional extras:
```bash
pip install -e ".[transport]"
pip install -e ".[research]"
pip install -e ".[bittensor]"
pip install -e ".[langgraph]"
```

## Development workflow
1. Create a branch from `main`.
2. Make focused changes.
3. Run verification commands (below).
4. Update docs when behavior/API/expected workflow changes.
5. Open a PR with a clear scope and test evidence.

## Verification commands
```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest tests/ --import-mode=importlib -q
python -m pytest -m "not slow and not e2e and not research" tests/ --import-mode=importlib -q
python -m build
```

## Documentation expectations
- Keep stable runtime docs separate from research/experimental docs.
- Avoid unverified claims about performance, security, benchmarks, or compliance.
- If a claim cannot be traced to source/tests/scripts, mark it as intended direction or remove it.
- Link related docs instead of duplicating deep technical internals.

## PR expectations
- Explain why the change is needed.
- List what changed.
- Include tests/checks run.
- Call out any limitations or follow-up work.

## Reporting security issues
Do **not** open public issues for unpatched vulnerabilities.
Follow [`SECURITY.md`](SECURITY.md) for private reporting.

## Community norms
By participating, you agree to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
