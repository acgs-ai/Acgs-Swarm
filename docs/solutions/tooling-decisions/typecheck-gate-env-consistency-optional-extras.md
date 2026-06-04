---
title: Keep the mypy type gate environment-consistent across optional extras
date: 2026-06-04
category: tooling-decisions
module: constitutional_swarm type-check gate (mypy + CI)
problem_type: tooling_decision
component: tooling
severity: medium
applies_when:
  - "Adding or changing an optional extra in [project.optional-dependencies]"
  - "A module is gated behind an optional dependency (try/except import, TYPE_CHECKING guard)"
  - "mypy passes in CI but fails locally (or the inverse) on the same commit"
  - "Claiming the type gate is clean without saying which dependency surface it ran against"
tags:
  - mypy
  - typecheck
  - ci
  - optional-dependencies
  - py-typed
  - type-gate
  - environment-consistency
related_components:
  - development_workflow
  - testing_framework
---

# Keep the mypy type gate environment-consistent across optional extras

## Context

The `make verify` type gate runs `mypy` over `src/constitutional_swarm`. For a
long time mypy ran in exactly one CI job that installed `.[dev]` only, while every
*other* CI job (and the local `make typecheck` default, `EXTRAS="dev transport"`)
installed the `transport` extra. The consequence: a type error that only manifests
once an optional dependency's **real** types resolve was invisible to the gate
until that extra was installed — so it never blocked a PR.

This is not hypothetical. `gossip_protocol.py` typed a `connection_closed_error`
fallback as `type[RuntimeError]` while the `else` branch assigned
`websockets.exceptions.ConnectionClosed`. With `transport` installed, mypy resolves
the real `ConnectionClosed` type and flags the mismatch; without it, `websockets`
is `Any` (via `ignore_missing_imports`) and the error vanishes. A developer running
`make verify` locally would catch it; CI would not. The gate's verdict — and its
"108 files clean" claim — was silently relative to which extras happened to be
installed.

## Guidance

**The decisive fact: only a dependency that ships `py.typed` changes what mypy
sees.** Installing a stub-less extra (mypy treats it as `Any` either way) adds zero
type coverage; installing a `py.typed` extra makes mypy resolve real types and can
surface real errors. Audit `py.typed` status first — it drives every other
decision.

1. **Run mypy against the dependency surface you actually ship and test, not a
   subset.** If an extra ships `py.typed` and its symbols are used in type
   positions, the gate must run with it installed or the error class is unreachable.
   Keep a no-extras job too (it is the published-library distribution contract —
   the package must type-check with zero optional deps), and add a sibling job per
   type-bearing extra. Two cheap mypy jobs (no-extras + the type-bearing extra) beat
   one: a strict superset, no reliance on a "dominance" argument.

2. **Do not let heavy/stub-less extras into the fast gate.** `torch`/`transformers`
   are multi-GB and crash mypy; they ship `py.typed` but the cost dwarfs the value.
   Classify them `excepted` and, if ever gated, `follow_imports = "skip"` on
   `torch.*` so mypy never recurses into them.

3. **Guard the classification so a new extra cannot silently escape.** Maintain a
   manifest classifying *every* declared extra as `checked` (installed by a blocking
   mypy job) or `excepted` (with a reason), and a CI check that fails when an extra
   is unclassified or a `checked` extra drops out of the typecheck job. Adding an
   extra then *forces* a type-coverage decision.

4. **Fix surfaced errors with the env-invariant pattern, not a wider annotation
   that hides them.** Annotate against the real optional type under
   `if TYPE_CHECKING:` and gate the runtime import — so the reference is checked
   even with no extra installed (mypy's documented conditional-import pattern).

5. **Mind `warn_unused_ignores` under optional deps.** `# type: ignore`s on optional
   imports are needed in some extra configurations and unused in others, so the flag
   flip-flops by environment — keep it OFF, or adopt the
   `# type: ignore[code,unused-ignore]` idiom before re-enabling. Likewise, a dep
   that is installed-but-unstubbed (here, `acgs-lite`) is pinned to `Any` via a
   `follow_imports = "skip"` override so its verdict does not depend on which build
   is installed.

## Why This Matters

A type gate whose verdict depends on the install surface produces two failure
modes: **green-locally-red-in-CI** (or the inverse) on the same commit, which
erodes trust in the gate; and a **silently growing blind spot** — every new
`py.typed` extra-gated module adds code the gate never checks, while the project
still believes "the whole package is clean." `langgraph`/`langchain` were exactly
this: they ship `py.typed` and already carry a live variance error
(`langgraph_runtime/swarm_topology.py:126`) plus a mypy-1.11 crash, invisible only
because they are uninstalled everywhere. Making the surface explicit (a classified,
CI-enforced manifest) converts that invisible debt into a tracked, named decision.

## When to Apply

- When adding or modifying an entry in `[project.optional-dependencies]`.
- When a new module imports an optional dependency (decide: is it type-bearing?).
- When mypy disagrees between local and CI on the same commit.
- Before asserting "the type gate is clean" — state the dependency surface it ran
  against, because "clean" is meaningless without it.

## Examples

**CI — before (one env-relative gate):**

```yaml
typecheck:
  steps:
    - run: pip install -e ".[dev]"      # transport NOT installed
    - run: mypy                          # never sees real websockets types
```

**CI — after (two surfaces, both blocking):**

```yaml
typecheck:                               # no-extras: distribution contract
  steps:
    - run: pip install -e ".[dev]"
    - run: mypy
typecheck-transport:                     # type-bearing surface
  steps:
    - run: pip install -e ".[dev,transport]"
    - run: mypy
```

**The guardrail manifest** (`pyproject.toml`) — every extra is classified:

```toml
[tool.constitutional_swarm.typecheck_coverage]
checked = ["transport"]                  # installed by a blocking mypy job

[tool.constitutional_swarm.typecheck_coverage.excepted]
research = "torch/transformers are heavy and crash mypy; follow_imports=skip if gated"
langgraph = "type-bearing but has a known live error (swarm_topology.py:126); deferred"
bittensor = "ships no py.typed; installing adds no coverage"
# ... every remaining extra, each with a reason
```

`scripts/check_typecheck_coverage.py` (wired into `make verify` + the `agent-check`
CI job) reconciles this manifest against the extras the **blocking mypy jobs**
install (parsed from `ci.yml`, scoped to jobs whose step runs `mypy` and that are
not `continue-on-error`), and exits non-zero on an unclassified extra, a `checked`
extra no job installs, or an `excepted` extra with no reason. A new extra fails the
gate until it is classified.

**Env-invariant fix** for a runtime-divergent optional type (the
`gossip_protocol.py` class of error): annotate the fallback broadly
(`connection_closed_error: type[BaseException] = RuntimeError`) or, to keep the
precise type checked even without the extra, lift the real-type reference into an
`if TYPE_CHECKING:` block.

## Related

- `BLOCKERS.md` B3 — the mypy adoption history and the `acgs-lite`
  `follow_imports = "skip"` drift-robustness decision.
- `DECISIONS.md` — "Typecheck gate environment consistency" (2026-06-03 log entry).
- `tools/runbooks/typecheck-coverage.md` — the guardrail runbook.
- `docs/plans/2026-06-03-003-fix-typecheck-env-consistency-plan.md` — the full plan
  and the empirically-verified reasoning (KTD1 dominance, the langgraph live error).
- PR [#78](https://github.com/dislovelhl/Acgs-Swarm/pull/78).
