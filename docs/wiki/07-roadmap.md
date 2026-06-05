# 07 · Roadmap — direction, state, blockers, next tasks

[← 06 Runtime Flows](06-runtime-flows.md) · Next: [08 Handoff →](08-handoff.md)

This consolidates the strategic direction ([`docs/roadmap.md`](../roadmap.md)),
the working next-actions ([`TASKS.md`](../../TASKS.md)), and open blockers
([`BLOCKERS.md`](../../BLOCKERS.md)) into one maintainer view. When they disagree,
those three files win — update them and this page together.

## Direction by tier

### Stable core — *harden, don't expand*
- Improve onboarding docs/examples for governed execution and mesh settlement.
- Maintain API stability for `AgentDNA`, `ConstitutionalMesh`, `SwarmExecutor`,
  `TaskDAG`.
- Expand regression coverage around **signed-vote settlement and replay/recovery**
  (the highest-value test surface).

### Advanced runtime — *integration quality*
- Operator/deployment guidance for remote vote transport (`[transport]`).
- Stronger examples for receipt verification + settlement evidence workflows.
- Integration quality for LangGraph and Bittensor optional modules.

### Research / experimental — *iterate freely (within invariants)*
- Iterate on `latent_dna`, `swarm_ode`, `merkle_crdt`.
- Keep `manifold.py` as the baseline control while evaluating the spectral-sphere
  direction.
- Improve reproducibility assets for benchmark/eval scripts and paper claims.

### Documentation
- Keep beginner docs separate from deep research drafts.
- Keep **evidence-linked claims only** (tests/scripts/source-backed).
- Expand FAQ/troubleshooting from real contributor questions.

### Explicitly out of scope (do not imply)
Compliance certification · regulator approval · universal production readiness
across research modules.

## Current state snapshot (as of this wiki)

- **Onboarding blockers (B1–B7): all resolved or mitigated.** The mypy gate (B3)
  and standalone-vs-submodule framing (B6) are closed. Check live state with
  `make agent-check` + `make verify`.
- **Typecheck gate is environment-consistent:** two blocking mypy jobs (no-extras
  + `transport`); `make typecheck-coverage` fails CI if a new optional extra
  escapes the type surface. `langgraph` is *excepted* with a known live error
  (`swarm_topology.py:126`) pending a code fix + crash-free mypy band.
- **Governed-handoff kernel hardened** (DECISIONS.md 2026-06-03): signed evidence
  bundles, default-DENY tool gate, fail-closed version pin. The "unforgeable"
  framing is now true *when a trust anchor is supplied*.
- **Recent merges:** safe `compose()` default + retention docs (#80), typecheck
  env-consistency (#78), agent-self-evolve packaged module (#77/#75), DSSE/in-toto
  projector (#55), abliteration detector (#56).

## Recommended next tasks for an incoming agent

From [`TASKS.md`](../../TASKS.md), in priority order:

1. **Resolve any open blockers** — re-check [`BLOCKERS.md`](../../BLOCKERS.md);
   all onboarding blockers are currently closed/mitigated.
2. **Add DSSE receipts to the tool registry** — `governance_receipts_dsse.py`
   (merged #55) is not yet in `tools/registry.yaml`; add an entry + runbook.
3. **Backfill registry coverage** — audit `scripts/`; ensure every operator-facing
   script has a `tools/registry.yaml` entry (no tool should live only in an
   undocumented script).
4. **Expand settlement/replay regression tests** — the stable-core priority above.

### Known follow-ups worth picking up (from code/docs)
- **`mac_acgs_loop.py` import leak** — move the unconditional
  `bittensor.came_coordinator` import inside its constructing method to keep the
  core import light (~458ms saved). See
  [`src/constitutional_swarm/AGENTS.md`](../../src/constitutional_swarm/AGENTS.md)
  MANUAL + `docs/RUNTIME_OPTIMIZATION_REPORT.md` B1.
- **`langgraph_runtime/swarm_topology.py:126`** — fix the live type error so
  `langgraph` can graduate from `excepted` to `checked` in the typecheck gate.
- **Spectral-sphere `compose()` rank-1 collapse** — characterized in PR #80;
  collapse is an operator-choice property, not OT-specific. Further work tracked
  in `docs/solutions/`.

## How to pick up work

```bash
make setup          # one-time
make agent-check    # confirm the repo is self-consistent
make verify         # full local gate before changing anything
```

Then read [`AGENTS.md`](../../AGENTS.md), pick a role from
[`agents/`](../../agents/), and record any blocker you hit in
[`BLOCKERS.md`](../../BLOCKERS.md). Longer-horizon planning artifacts live in
[`docs/plans/`](../plans/).

Continue to [08 Handoff →](08-handoff.md).
