# Reproduction note: offline agent-self-evolve static-probe harness

Status: reproduction note (internal). Scope: static / offline probe coverage only.
Observed: 2026-06-03.

This note records a faithful, observed reproduction of the offline
agent-self-evolve harness. It documents only numbers that were reproduced
locally on the date above. It does not advance any paper empirical claim.

## 1. What the harness measures

The harness builds an **offline, deterministic static probe plan** for every
agent in the repo. The agent population is two cohorts:

- **6 operational role manifests** — `agents/*.agent.yaml`
- **184 persona templates** — Markdown personas with agent frontmatter under
  `agents/templates/**/*.md`

Total discovered: **190 agents**.

It does **not** call live LLMs, an agent runtime, or any external agent CLI.
Each agent receives **4 static probes** (`command: offline-static`). Pass/fail is
decided purely by static contract coverage — schema / YAML frontmatter
parseability, persona-body substance, declared scope, and stable machine
identity (filename stem) — **not** by live agent behavior. For the persona
cohort the four probe ids observed are `frontmatter-contract`, `prompt-body`,
`stable-identity`, and `frontmatter-parseability`; the operational cohort is
probed against its own manifest contract. The harness emits, per agent, the
mutation scope, guardrails, probe list, static pass rate, and deterministic
suggested fixes for any failed probe.

Because every probe is static and offline, the run is idempotent and
reproducible without network, model, or runtime dependencies.

## 2. Reproduction commands

Run from the repo root (`/home/martin/Acgs-Swarm`). All three invocations below
were executed and observed for this note:

```bash
# Primary: module entry point
uv run --no-sync python -m constitutional_swarm.agent_self_evolve --json --fail-under 1.0

# Equivalent: Make target
make agent-self-evolve

# Equivalent: compatibility wrapper script
uv run --no-sync python scripts/agent_self_evolve.py --json --fail-under 1.0
```

All three produced the same summary metrics and exited `0`.

Caveat — the bare `acgs-agent-self-evolve` console script is **not** presented as
runnable today: it only exists after `make setup` / `uv sync` installs the
package's entry point into the venv, so prefer the module / wrapper / Make forms
above for a clean checkout.

## 3. Results

Observed `summary` block (identical across all three entry points), 2026-06-03:

| Metric                    | Observed value |
|---------------------------|----------------|
| `agents`                  | 190            |
| `operational_agents`      | 6              |
| `template_agents`         | 184            |
| `agents_without_harness`  | 0              |
| `probes_total`            | 760            |
| `probes_passed`           | 760            |
| `probe_pass_rate`         | 1.0            |
| process exit code         | 0              |

`probes_total` = 190 agents x 4 static probes = 760, consistent with the
per-agent probe plan. This matches the pinned expectation exactly.

## 4. Interpretation

A `probe_pass_rate` of `1.0` (0 failing static probes, `agents_without_harness`
= 0) means **full coverage of the static contract**: every operational manifest
and persona template parses, carries the required frontmatter / schema fields,
has a substantial body, declares a scope, and exposes a stable machine id.

Scope and limits — read carefully:

- This is a **static / offline probe-coverage** result. It says nothing about
  live agent behavior, model output quality, or task success.
- It is **not** a demonstration of live "self-evolution." The harness only
  *plans* mutation scope, guardrails, and probes; it does not mutate agents or
  run them.
- It is **not** a paper empirical claim and must not be cited as one. It is an
  internal reproducibility checkpoint for the harness's static contract.

In short: the contract surface is fully covered and the harness is wired and
idempotent — nothing more is claimed.

## 5. Cross-links

- Runbook (by reference, not edited): `tools/runbooks/agent-self-evolve.md`
- Claims map (by reference, not edited): `docs/internal/claims_map.md`
