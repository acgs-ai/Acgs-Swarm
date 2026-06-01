# Runbook: governed-handoff (`acgs-swarm`)

Run a task through constitutional handoff gates and produce a verifiable
evidence bundle. This is the closest thing to "running the product."

## Subcommands
```bash
uv run --no-sync acgs-swarm run    --task <task.md>        # execute through gates
uv run --no-sync acgs-swarm verify --bundle <bundle.json>  # check an evidence bundle
uv run --no-sync acgs-swarm pack   --task <audit-jsonl-id> # rebuild a bundle from the audit log
```

## Example
A ready-made task lives under `examples/governed-handoff/`:
```bash
uv run --no-sync acgs-swarm run --task examples/governed-handoff/task.md
```
The example ships its own `.acgs/constitution.yaml` and `.acgs/swarm.yaml`.

## Credentials
- `run` needs `ANTHROPIC_API_KEY` only when the task invokes a live LLM agent.
- `verify` and `pack` are read-only and need no credentials.

## Outputs
- `run`: an evidence bundle JSON + audit-log append.
- `verify`: a pass/fail verdict (non-zero exit on rejection).
- `pack`: a rebuilt bundle from a prior audit task id.

## Safety
`verify`/`pack` are idempotent. `run` appends to the audit log — re-running
re-executes the task. Vote signatures are mandatory on mesh submission.
