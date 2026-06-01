# constitutional-swarm — agent-operable entrypoints
#
# Every supported workflow has a one-command target here. Agents (and humans)
# should never need to inspect source to learn how to run the project.
#
# Runner: this repo is uv-managed (see uv.lock). All targets shell out through
# `uv run` against a project virtualenv. The system interpreter is python3;
# there is no bare `python`, `pip`, `ruff`, or `pytest` on PATH — use these
# targets (or `uv run <tool>`), not global tools.
#
# Standalone vs monorepo: pyproject pins `acgs-lite = { workspace = true }`
# for in-monorepo development. A standalone checkout has no workspace, so
# `make setup` passes `--no-sources` to resolve acgs-lite from PyPI instead.
# See BLOCKERS.md (B1).

UV ?= uv
# Extras installed by `make setup`. Override: `make setup EXTRAS="dev transport research"`
EXTRAS ?= dev transport
SYNC_FLAGS ?= --no-sources $(addprefix --extra ,$(EXTRAS))
# Test selection: skip slow/network/research/bittensor by default (matches CI).
TEST_MARKERS ?= not slow and not benchmark and not e2e and not research and not bittensor
PYTEST = $(UV) run --no-sync pytest tests/ --import-mode=importlib

.DEFAULT_GOAL := help
.PHONY: help setup dev test test-all lint format typecheck smoke verify agent-check clean

help: ## Show this help
	@echo "constitutional-swarm — make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install the package + dev extras (one-time onboarding)
	@command -v $(UV) >/dev/null 2>&1 || { \
	  echo "ERROR: 'uv' not found. Install it: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
	$(UV) sync $(SYNC_FLAGS)
	@echo "OK: environment ready. Next: 'make smoke' then 'make test'."

dev: setup smoke ## Prepare a development environment and confirm it imports

test: ## Run the default test suite (skips slow/network/research/bittensor)
	$(PYTEST) -m "$(TEST_MARKERS)" -q

test-all: ## Run the full test suite including research markers
	$(PYTEST) -m "not slow and not benchmark and not e2e" -q

lint: ## Lint the package with ruff (CI gate)
	$(UV) run --no-sync ruff check src/constitutional_swarm/

format: ## Auto-format with ruff
	$(UV) run --no-sync ruff format src/ scripts/

typecheck: ## Static checks. No mypy/pyright is configured (see BLOCKERS.md B3); ruff lint is the available static gate.
	@echo "No dedicated type checker is configured; running ruff lint as the static-analysis gate."
	$(UV) run --no-sync ruff check src/constitutional_swarm/

smoke: ## Fast import + CLI sanity check (no network, no API keys)
	$(UV) run --no-sync python -c "import constitutional_swarm; print('import constitutional_swarm OK')"
	$(UV) run --no-sync acgs-swarm --help >/dev/null && echo "acgs-swarm CLI OK"
	$(UV) run --no-sync acgs-verify-receipts --help >/dev/null && echo "acgs-verify-receipts CLI OK"

agent-check: ## Validate agent/tool registries + doc completeness (no install required)
	$(UV) run --no-sync python scripts/agent_check.py

verify: lint agent-check smoke test ## Full local gate: lint -> registry/doc check -> smoke -> tests
	@echo "OK: verify passed."

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .benchmarks dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
