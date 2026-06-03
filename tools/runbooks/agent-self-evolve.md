# Runbook: agent-self-evolve

Builds an offline, deterministic self-evolution harness for every repo agent:

- operational role manifests: `agents/*.agent.yaml`
- persona templates: `agents/templates/**/*.md` with agent frontmatter

The harness does **not** call live LLMs or external agent CLIs. It emits per-agent
mutation scope, guardrails, probes, static pass rates, and suggested fixes.

## Run

```bash
make agent-self-evolve
```

Direct script usage:

```bash
python3 scripts/agent_self_evolve.py --json --write-report .omx/state/agent-self-evolve-report.json --fail-under 1.0
python3 scripts/agent_self_evolve.py --no-templates --fail-under 1.0
```

## Output

Default Make target writes:

```text
.omx/state/agent-self-evolve-report.json
```

Key fields:

- `summary.agents` — total agents discovered
- `summary.agents_without_harness` — must be `0`
- `summary.probe_pass_rate` — static probe pass rate
- `agents.<name>.harness` — mutation scope, guardrails, and probes for that agent
- `agents.<name>.suggestions` — deterministic fixes for failed static probes

## Failure modes

- A role manifest references an unknown tool.
- A persona template has invalid or incomplete frontmatter.
- A mutation removes safety, validation, artifacts, or stable identity metadata.

Fix the reported agent file and rerun the command. The command is idempotent.
