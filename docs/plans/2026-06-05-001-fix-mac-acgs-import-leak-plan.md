---
title: "fix: Stop mac_acgs_loop from eager-importing the bittensor subpackage"
status: active
date: 2026-06-05
type: fix
depth: lightweight
---

# fix: Stop mac_acgs_loop from eager-importing the bittensor subpackage

## Summary

`import constitutional_swarm` currently pulls in the entire optional
`bittensor` subpackage (~458 ms, measured) because `mac_acgs_loop.py` imports
`constitutional_swarm.bittensor.came_coordinator` at module scope. This
violates the repo's standing rule that the core package must import without any
optional extra installed. Make the bittensor symbols load lazily — only when a
MAC-ACGS object is actually constructed — so the core import stays light, then
lock the boundary with a regression test.

The naive "move the import into the method" fix (as sketched in
`src/constitutional_swarm/AGENTS.md`) is **necessary but not sufficient**: one
of the three uses is a dataclass `default_factory=CAMECoordinatorConfig` that is
evaluated at module-load time, not call time. The plan handles that case
explicitly.

---

## Problem frame

- **Where:** `src/constitutional_swarm/mac_acgs_loop.py`, module-level import at
  lines 43–47.
- **Why it matters:** `bittensor` is an optional extra (`pip install
  ".[bittensor]"`). The core must remain importable and fast without it. The
  eager import is bottleneck **B1** in `docs/RUNTIME_OPTIMIZATION_REPORT.md` and
  a documented known-issue in `src/constitutional_swarm/AGENTS.md`.
- **Constraint:** behavior must not change. `MacAcgsLoop`, `MacAcgsConfig`, and
  `MacAcgsCycleResult` must keep their current public contract and construction
  semantics. `mac_acgs_loop` legitimately *needs* bittensor at runtime — the
  goal is to defer the import to first use, not to remove the dependency.

### The three runtime touch points (why a single method-move is incomplete)

The module references three bittensor symbols. `from __future__ import
annotations` is already active (line 36), so all *annotations* are lazy strings
and only need a `TYPE_CHECKING` import. The remaining **runtime** evaluations
are what force the eager import:

| Line | Use | Kind | Handling |
|---|---|---|---|
| 164 | `came_config: CAMECoordinatorConfig = field(default_factory=CAMECoordinatorConfig)` | Module-load-time value (the factory callable must resolve when the dataclass is defined) | Replace the factory with a module-level helper that imports lazily and returns `CAMECoordinatorConfig()` |
| 255 | `self._came = came or CAMECoordinator(config=...)` inside `MacAcgsLoop.__init__` | Call-time construction | Function-local import in `__init__` |
| 314 | `came_result = CAMECycleResult(...)` (fail-closed branch of the cycle method) | Call-time construction | Function-local import in that method |
| 164/188/251 | annotations only | Lazy string (future-annotations) | `TYPE_CHECKING` import block |

---

## Requirements

- **R1** — After the change, `import constitutional_swarm` must not import
  `constitutional_swarm.bittensor` (nor the third-party `bittensor` SDK) when
  the bittensor extra is not in use.
- **R2** — `MacAcgsConfig()`, `MacAcgsLoop(...)`, and a full cycle run must
  behave exactly as before (same defaults, same CAMECoordinator construction,
  same fail-closed `CAMECycleResult`).
- **R3** — A regression test must fail if the eager import is ever reintroduced.
- **R4** — `make verify` (lint, mypy no-extras + transport, agent-check,
  smoke, tests) stays green.

---

## Key technical decisions

- **KTD-1 — Lazy `default_factory` via a module-level helper, not a `lambda`.**
  Define a small named function (e.g. `_default_came_config`) that does the
  function-local import and returns `CAMECoordinatorConfig()`. A named helper is
  clearer than a `lambda`, is mypy-friendly, and keeps the dataclass field
  declaration readable. This defers the import from *module load* to *first
  `MacAcgsConfig()` instantiation*, which is an intentional use of the MAC-ACGS
  feature and therefore an acceptable place to pay the bittensor import cost.

- **KTD-2 — `TYPE_CHECKING` block for annotations.** Add
  `if TYPE_CHECKING: from constitutional_swarm.bittensor.came_coordinator import
  (CAMECoordinator, CAMECoordinatorConfig, CAMECycleResult)`. Because
  `from __future__ import annotations` is active, the annotations on lines 164,
  188, and 251 resolve as strings and need no runtime import. Keep all three
  names imported here so mypy and IDEs still resolve them.

- **KTD-3 — Function-local imports at the two construction sites.** Import
  `CAMECoordinator` inside `__init__` (line ~255) and `CAMECycleResult` inside
  the cycle method's fail-closed branch (line ~314). Keep imports as narrow as
  possible (only the symbol used at that site).

- **KTD-4 — Subprocess-based import-isolation test.** Assert the boundary in a
  *fresh interpreter*, because within the pytest process `bittensor` is almost
  certainly already imported by other tests/collection, which would make an
  in-process `sys.modules` assertion flaky/false-green. Run
  `python -c "import constitutional_swarm, sys; assert not any(m == 'constitutional_swarm.bittensor' or m.startswith('constitutional_swarm.bittensor.') for m in sys.modules)"`
  via `subprocess` using `sys.executable`. This mirrors the clean-interpreter
  intent of the existing `sys.modules` manipulation in
  `tests/test_langgraph_guards.py` but is hermetic.

---

## Implementation units

### U1. Make the bittensor import lazy in `mac_acgs_loop.py`

- **Goal:** Remove the module-level `from
  constitutional_swarm.bittensor.came_coordinator import (...)` while preserving
  identical behavior. Satisfies R1, R2.
- **Dependencies:** none.
- **Files:**
  - `src/constitutional_swarm/mac_acgs_loop.py` (modify)
- **Approach:**
  1. Delete the eager import block (lines 43–47).
  2. Add `TYPE_CHECKING` to the `typing` import and a `TYPE_CHECKING:` block
     importing `CAMECoordinator`, `CAMECoordinatorConfig`, `CAMECycleResult`
     (KTD-2).
  3. Add a module-level `_default_came_config()` helper that imports
     `CAMECoordinatorConfig` locally and returns an instance; change the
     `MacAcgsConfig.came_config` field to
     `field(default_factory=_default_came_config)` and make its annotation a
     string-forward-ref form consistent with the file (KTD-1).
  4. Add a function-local `import` of `CAMECoordinator` in `MacAcgsLoop.__init__`
     before the `came or CAMECoordinator(...)` line (KTD-3).
  5. Add a function-local `import` of `CAMECycleResult` in the fail-closed branch
     of the cycle method before constructing it (KTD-3).
- **Patterns to follow:** the existing `from __future__ import annotations`
  (already present); narrow function-local imports as used elsewhere in the
  codebase for optional extras.
- **Test scenarios:**
  - `MacAcgsConfig()` returns a config whose `came_config` is a
    `CAMECoordinatorConfig` instance with unchanged default values (R2).
  - Constructing `MacAcgsLoop()` with no `came=` builds a default
    `CAMECoordinator`; passing an explicit `came=` object uses it verbatim (R2).
  - A cycle run that triggers the hash-mismatch fail-closed branch still
    produces the aborted `CAMECycleResult(log_id="aborted:hash_mismatch", ...)`
    (R2). Covered by existing `tests/test_breakthrough_modules.py`; extend only
    if a gap surfaces.
  - `mypy` (no-extras surface) resolves all three annotations with no new
    errors (R4).
- **Verification:** existing MAC-ACGS tests in
  `tests/test_breakthrough_modules.py` pass unchanged; `make smoke` and
  `make typecheck` stay green.

### U2. Add an import-isolation regression test

- **Goal:** Fail the build if the eager bittensor import is reintroduced.
  Satisfies R3.
- **Dependencies:** U1.
- **Files:**
  - `tests/test_core_import_isolation.py` (create)
- **Approach:** A subprocess test (KTD-4) that runs a fresh interpreter,
  imports only `constitutional_swarm`, and asserts no
  `constitutional_swarm.bittensor*` module is present in `sys.modules`. Use
  `sys.executable` and `subprocess.run(..., check=True)`; assert exit code 0 and
  surface the child's stderr on failure. Keep it dependency-free so it runs in
  the default (no-extras) suite.
- **Test scenarios:**
  - Happy path: fresh `import constitutional_swarm` leaves no
    `constitutional_swarm.bittensor` entry in `sys.modules` → test passes (R1).
  - Guard: if a future edit re-adds the eager import, the subprocess assertion
    fails with a clear message naming the leaked module → test fails (R3).
  - Robustness: the test does not require the `bittensor` extra to be installed
    and skips nothing in the default suite.
- **Test expectation:** this unit *is* the test; its own verification is that it
  passes after U1 and fails when U1 is reverted.
- **Verification:** `pytest tests/test_core_import_isolation.py` passes; reverting
  U1 locally makes it fail (spot-check, not committed).

---

## Scope boundaries

**In scope:** the single eager import in `mac_acgs_loop.py` and a regression
test that guards the core→bittensor import boundary.

### Deferred to follow-up work

- A broader sweep for *other* eager optional-extra imports across the core
  (none currently documented beyond B1, but a general "no optional extra at
  core import time" test could enumerate `transport`, `research`, `langgraph`
  too). Out of scope here — this plan fixes the one documented leak.
- Updating `src/constitutional_swarm/AGENTS.md` MANUAL section and
  `docs/RUNTIME_OPTIMIZATION_REPORT.md` B1 to mark the issue resolved is a
  docs-follow-up; fold into the same PR if cheap, but not required for the fix.

---

## Verification (whole change)

- `make verify` is green (lint → typecheck no-extras + transport → agent-check →
  typecheck-coverage → smoke → test).
- New `tests/test_core_import_isolation.py` passes; existing
  `tests/test_breakthrough_modules.py` MAC-ACGS coverage passes unchanged.
- Manual spot-check (optional): time `python -c "import constitutional_swarm"`
  before/after to confirm the ~458 ms bittensor cost is gone from the cold core
  import.
