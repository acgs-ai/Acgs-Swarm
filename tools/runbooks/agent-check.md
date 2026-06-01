# Runbook: agent-check

The self-validation gate that proves a fresh agent can understand and operate
the repo. Runs offline; requires only `pyyaml` + `jsonschema` (both in the dev venv).

## Command
```bash
make agent-check       # uv run python scripts/agent_check.py
```

## What it validates
1. **Tool registry** — `tools/registry.yaml` parses and conforms to
   `tools/schemas/registry.schema.json`.
2. **Agent registry** — every `agents/*.agent.yaml` conforms to
   `agents/schemas/agent.schema.json`.
3. **Cross-references** — each agent's `required_tools` exists in the tool registry.
4. **Runbook links** — any `runbook:` path referenced by a tool exists on disk.
5. **Doc completeness** — every required root doc exists and is non-empty
   (README, ARCHITECTURE, PROJECT_MAP, TOOLS, TASKS, DECISIONS, AGENTS,
   CONTRIBUTING, BLOCKERS).

## Output
A per-check `PASS`/`FAIL` list and a final summary. Non-zero exit on any failure.

## Fixing failures
The failing check names the offending file and the schema path or missing
artifact. Fix that file and re-run — the check is idempotent.
