# Tool registry

The single source of truth for every command an agent may execute.

| File | Purpose |
|---|---|
| [`registry.yaml`](registry.yaml) | Catalogue of tools: command, env, inputs, outputs, failure modes, retry, validation, owner module. |
| [`schemas/registry.schema.json`](schemas/registry.schema.json) | JSON Schema the registry is validated against. |
| [`runbooks/`](runbooks/) | Step-by-step guides for the non-trivial tools. |

Validate with `make agent-check`. The human-readable index is
[`../TOOLS.md`](../TOOLS.md).

## Adding a tool

1. Add an entry to `registry.yaml` (all required fields — see the schema).
2. If non-trivial, add a runbook under `runbooks/` and link it via `runbook:`.
3. Run `make agent-check` to validate.

No supported command should live only in an undocumented script.
