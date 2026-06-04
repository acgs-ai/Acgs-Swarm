# Agent registry

Machine-readable manifests defining the agent roles that operate this repo.
One file per role: `<role>.agent.yaml`, validated against
[`schemas/agent.schema.json`](schemas/agent.schema.json) by `make agent-check`.

## Roles

| Role | Purpose |
|---|---|
| [`researcher`](researcher.agent.yaml) | Reproduce/extend empirical claims; keep citations valid. |
| [`coder`](coder.agent.yaml) | Implement features/fixes while preserving governance invariants. |
| [`reviewer`](reviewer.agent.yaml) | Review diffs for correctness, invariants, security, conventions. |
| [`qa`](qa.agent.yaml) | Validate end-to-end behavior, CLIs, security/eval harnesses. |
| [`docs`](docs.agent.yaml) | Keep docs + registries self-describing and accurate. |
| [`release`](release.agent.yaml) | Run the acceptance gate, build, changelog, tag. |

## Manifest contract

Each manifest declares: `name`, `purpose`, `scope` (allowed/forbidden),
`required_tools` (must exist in [`../tools/registry.yaml`](../tools/registry.yaml)),
`io_contract`, `safety`, `execution`, `validation`, and `artifacts`.

## Execution lifecycle

Every agent task follows:

```text
discover → register/select role → plan → execute → validate → produce artifact → log result
```

A completed task should report: execution log, changed-files summary, tests
run, validation result, unresolved blockers ([../BLOCKERS.md](../BLOCKERS.md)),
and the next recommended action.

## Self-evolution harness

Run the offline harness generator before mutating agent contracts or templates:

```bash
make agent-self-evolve
# or run the harness module directly:
uv run --no-sync python -m constitutional_swarm.agent_self_evolve --json --fail-under 1.0
```

The report is written to `.omx/state/agent-self-evolve-report.json` and includes
one harness per discovered operational manifest and persona template: mutation
scope, guardrails, static probes, pass rates, and deterministic suggestions. The
command is offline; it does not call live LLMs or external agent runtimes.
