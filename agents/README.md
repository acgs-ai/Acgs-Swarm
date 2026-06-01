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
