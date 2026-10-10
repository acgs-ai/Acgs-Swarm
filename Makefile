# constitutional-swarm — agent-operable entrypoints
#
# Every supported workflow has a one-command target here. Agents (and humans)
# should never need to inspect source to learn how to run the project.
#
# Runner: this repo is uv-managed (see uv.lock). Gates execute tools from the
# project virtualenv explicitly, after proving that environment matches the
# lock. The system interpreter is python3; use these targets, not global tools.
#
# Standalone vs monorepo: pyproject pins `acgs-lite = { workspace = true }`
# for in-monorepo development. A standalone checkout has no workspace, so
# `make setup` passes `--no-sources` to resolve acgs-lite from PyPI instead.
# See BLOCKERS.md (B1).

UV ?= uv
# Extras installed by `make setup`. Override: `make setup EXTRAS="dev transport research"`
EXTRAS_ORIGIN := $(origin EXTRAS)
EXTRAS ?= dev transport
NORMALIZED_EXTRAS := $(sort $(EXTRAS))
SYNC_FLAGS ?= --no-sources
SYNC_ARGS = $(SYNC_FLAGS) $(addprefix --extra ,$(NORMALIZED_EXTRAS))
# Test selection: skip slow/network/research/bittensor by default (matches CI).
TEST_MARKERS ?= not slow and not benchmark and not e2e and not research and not bittensor
# Live PostgreSQL contracts run in CI job test-postgres (requires APCC_POSTGRES_DSN
# + [postgres]). Default verify must not import psycopg via that frozen suite.
TEST_IGNORE ?= --ignore=tests/test_apcc_postgres.py
VENV_PYTHON = .venv/bin/python
VENV_PYTEST = .venv/bin/pytest
VENV_RUFF = .venv/bin/ruff
VENV_MYPY = .venv/bin/mypy
VENV_SWARM = .venv/bin/acgs-swarm
VENV_VERIFY_RECEIPTS = .venv/bin/acgs-verify-receipts
VENV_SELF_EVOLVE = .venv/bin/acgs-agent-self-evolve
PYTEST = $(VENV_PYTHON) -m pytest tests/ --import-mode=importlib $(TEST_IGNORE)
TLA2TOOLS_JAR ?=
TLC_TIMEOUT ?= 180
TLC_LOG ?= tlc-gcb-witness.log

.DEFAULT_GOAL := help
.PHONY: help setup check-env dev test test-all lint format typecheck typecheck-coverage smoke verify verify-wheel agent-check agent-self-evolve tla-gcb-coverage clean

help: ## Show this help
	@echo "constitutional-swarm — make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install the package + dev extras (one-time onboarding)
	@command -v $(UV) >/dev/null 2>&1 || { \
	  echo "ERROR: 'uv' not found. Install it: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
	UV_PROJECT_ENVIRONMENT="$(CURDIR)/.venv" $(UV) sync --locked $(SYNC_ARGS)
	@printf '%s\n' "$(NORMALIZED_EXTRAS)" > .venv/.make-extras
	@echo "OK: environment ready. Next: 'make smoke' then 'make test'."

check-env: ## Fail unless the project venv exists and exactly matches uv.lock
	@set -eu; \
	fail() { echo "ERROR: project environment is missing or stale; run make setup"; exit 1; }; \
	[ -x "$(VENV_PYTHON)" ] || fail; \
	"$(VENV_PYTHON)" -I -c 'import os, sys; raise SystemExit(0 if os.path.realpath(sys.prefix) == os.path.realpath(".venv") else 1)' || fail; \
	venv="$$($(VENV_PYTHON) -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' .venv)" || fail; \
	venv_bin="$$venv/bin"; \
	for tool in $(VENV_PYTEST) $(VENV_RUFF) $(VENV_MYPY) $(VENV_SWARM) $(VENV_VERIFY_RECEIPTS) $(VENV_SELF_EVOLVE); do \
	  [ -x "$$tool" ] || fail; \
	  resolved="$$($(VENV_PYTHON) -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$$tool")" || fail; \
	  case "$$resolved" in "$$venv_bin"/*) ;; *) fail ;; esac; \
	done; \
	[ -r .venv/.make-extras ] || fail; \
	saved_extras="$$(cat .venv/.make-extras)" || fail; \
	[ -n "$$saved_extras" ] || fail; \
	if [ "$(EXTRAS_ORIGIN)" != "undefined" ] && [ "$(NORMALIZED_EXTRAS)" != "$$saved_extras" ]; then \
	  echo "ERROR: EXTRAS mismatch: requested '$(NORMALIZED_EXTRAS)', installed '$$saved_extras'."; \
	  echo "Run make setup EXTRAS=\"$(NORMALIZED_EXTRAS)\"."; \
	  exit 1; \
	fi; \
	command -v $(UV) >/dev/null 2>&1 || fail; \
	set --; for extra in $$saved_extras; do set -- "$$@" --extra "$$extra"; done; \
	uv_output="$$(UV_PROJECT_ENVIRONMENT="$(CURDIR)/.venv" $(UV) sync --check --locked $(SYNC_FLAGS) "$$@" 2>&1)" || { \
	  printf '%s\n' "$$uv_output" >&2; fail; \
	}

dev: setup smoke ## Prepare a development environment and confirm it imports

test: check-env ## Run the default test suite (skips slow/network/research/bittensor)
	$(PYTEST) -m "$(TEST_MARKERS)" -q

test-all: check-env ## Run the full test suite including research markers
	$(PYTEST) -m "not slow and not benchmark and not e2e" -q

lint: check-env ## Lint the package with ruff (CI gate)
	$(VENV_RUFF) check src/constitutional_swarm/

format: check-env ## Auto-format with ruff
	$(VENV_RUFF) format src/ scripts/

typecheck: check-env ## Static type-check with mypy (config + adoption baseline in pyproject.toml [tool.mypy]).
	$(VENV_PYTHON) -m mypy

smoke: check-env ## Fast import + CLI sanity check (no network, no API keys)
	$(VENV_PYTHON) -c "import constitutional_swarm; print('import constitutional_swarm OK')"
	$(VENV_SWARM) --help >/dev/null && echo "acgs-swarm CLI OK"
	$(VENV_VERIFY_RECEIPTS) --help >/dev/null && echo "acgs-verify-receipts CLI OK"
	$(VENV_SELF_EVOLVE) --help >/dev/null && echo "acgs-agent-self-evolve CLI OK"

agent-check: check-env ## Validate agent/tool registries + doc completeness
	$(VENV_PYTHON) scripts/agent_check.py

typecheck-coverage: check-env ## Assert every optional extra is type-checked or excepted
	$(VENV_PYTHON) scripts/check_typecheck_coverage.py

agent-self-evolve: check-env ## Build offline self-evolution harnesses for every repo agent
	$(VENV_PYTHON) -c 'from constitutional_swarm.agent_self_evolve import main; raise SystemExit(main())' --json --write-report .omx/state/agent-self-evolve-report.json --fail-under 1.0

tla-gcb-coverage: check-env ## Prove the exact GCB non-vacuity witness with pinned TLC v1.7.4
	@test -n "$(TLA2TOOLS_JAR)" || { echo "ERROR: set TLA2TOOLS_JAR to the pinned TLC v1.7.4 jar"; exit 2; }
	$(VENV_PYTHON) scripts/run_tlc_expected_witness.py \
		--tlc-jar "$(TLA2TOOLS_JAR)" --timeout "$(TLC_TIMEOUT)" --log "$(TLC_LOG)"

verify: lint typecheck agent-check typecheck-coverage smoke test ## Full local gate: lint -> typecheck -> registry/doc + coverage check -> smoke -> tests
	@echo "OK: verify passed."

verify-wheel: check-env ## Build the wheel and install it into a blank venv (not the project .venv)
	$(VENV_PYTHON) scripts/verify_isolated_wheel.py

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .benchmarks dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
