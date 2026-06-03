---
date: 2026-06-03
topic: extended-refusal-finetuning
focus: Training-time defense-in-depth against abliteration (feasibility)
mode: repo-grounded
status: proposed
origin: docs/internal/abliteration_threat_model.md (Follow-ups → Open, item #2)
---

# feat: extended-refusal fine-tuning — feasibility & scope

## Summary

This is a **feasibility assessment**, not an implementation plan. It scopes the
second open follow-up in the abliteration threat model — *defense-in-depth at
training time* via **extended-refusal fine-tuning** (arXiv:2505.19056) — and
recommends how (and whether) `constitutional_swarm` should host it.

The headline recommendation: **do not absorb a training pipeline into the
package core.** Ship a thin, optional, `[research]`-gated *reference recipe* +
an evaluation harness that reuses the existing pure-NumPy detector, and keep the
actual fine-tuning (model weights, GPU, dataset) outside the CI-tested surface.
The package's value proposition is *externalized enforcement*; weight-hardening a
model is a complementary but categorically different artifact and must not dilute
that identity or the CI-safe guarantee.

---

## Problem Frame

### The threat-model gap this addresses

Abliteration removes refusal by orthogonalizing write matrices against a *single*
refusal direction `r̂`. **Extended-refusal fine-tuning** (arXiv:2505.19056)
distributes the refusal behavior across *many* dimensions, so no single-direction
edit can remove it (>90% residual refusal reported). It is a *training-time*
defense for **trusted nodes** — it hardens the model itself, complementing the
already-shipped *externalized* defenses (detector, admission gates, hardened
steering) that assume nothing about a node's internal alignment.

### Why this is categorically different from everything shipped so far

| Property | Shipped abliteration work | Extended-refusal fine-tuning |
|---|---|---|
| Compute | pure NumPy, no model | GPU, full fine-tuning run |
| CI | runs in CI (no torch/model) | cannot run in CI |
| Artifact | code + a node-trust signal | **modified model weights** |
| Determinism | deterministic, unit-testable | stochastic training outcome |
| Identity fit | "externalized enforcement" ✅ | "harden the model" — adjacent |

Everything the package ships about abliteration today is deliberately
**model-free and CI-safe** (`abliteration_detector.py`: "no torch/live model
needed"). A fine-tuning loop breaks all four rows. That is the core tension this
document exists to resolve.

---

## Key Questions (must be answered before any implementation plan)

1. **Identity.** Is producing hardened *model weights* in-scope for a governance
   library whose thesis is that governance lives *outside* the model? Or is the
   right artifact a **recipe + eval** that others run, with the package only
   *measuring* the result (which it can already do, CI-safe)?
2. **Dependency surface.** Fine-tuning needs `torch` + `transformers` + a PEFT/
   full-FT stack + a refusal dataset. The `[research]` extra has torch/transformers
   but no trainer. Adding `trl`/`peft` widens the install and the maintenance/
   security surface. Is that acceptable for a feature no CI job can exercise?
3. **Verifiability.** The package's whole posture is "fail-closed, verifiable."
   A training outcome is not deterministically verifiable. The *only* CI-safe,
   deterministic part is **measuring residual refusal after the fact** — which the
   existing detector + `ViolationSubspace.refusal_alignment` already do. Is a
   measurement-only contribution sufficient to "close" the follow-up?
4. **Dataset/licensing.** Extended-refusal FT needs a refusal/harmful-prompt
   corpus. Sourcing, licensing, and shipping (or not shipping) that data is a
   non-trivial governance question for this repo specifically.

---

## Options

### Option A — Reference recipe + eval harness (recommended)

Ship, under the `[research]` extra and clearly marked "reference, not a
CI-tested package feature":

- `docs/recipes/extended_refusal_finetuning.md` — a runnable recipe (model,
  dataset shape, multi-direction refusal objective per arXiv:2505.19056, hparams,
  expected residual-refusal target).
- A **pure-NumPy evaluation** entry point that reuses
  `abliteration_detector.refusal_direction` + `ViolationSubspace.refusal_alignment`
  + latent-separation to score *how distributed* a model's refusal is — the
  "did the hardening work?" check. This part **is** CI-safe (operates on supplied
  activations/weights fixtures, no training).
- Optionally a `scripts/` driver that *calls into* a user's torch+trl environment
  but is excluded from the test matrix (like the SWE-bench live-eval scripts).

*Why recommended:* keeps the package's CI-safe, externalized-enforcement identity
intact; still closes the gap in a verifiable way (the package can *measure*
distributed refusal); puts the GPU/dataset/weights burden where it belongs (the
operator of a trusted node), not in the library.

### Option B — Full in-package fine-tuning module

A `latent_dna`-adjacent module that owns the training loop (torch + trl/peft).

*Why not (default):* breaks CI-safety, widens the dependency/security surface for
an untestable feature, ships non-deterministic behavior, and asserts a "we harden
models" identity the package has deliberately avoided. Only revisit if a concrete
downstream consumer commits to maintaining it behind the `[research]` extra.

### Option C — Document-only

Record the defense in the threat model (already done) and the paper; ship no code.

*Why not:* leaves the "did it work?" measurement on the table, which the package
is uniquely positioned to provide CI-safe.

---

## Recommendation

**Option A.** Treat extended-refusal fine-tuning as an *operator recipe* the
package documents and *evaluates*, not a feature it *implements*. Concretely, the
next implementation plan (if greenlit) would be scoped to:

1. A CI-safe `refusal_distribution_score` (NumPy) on top of the existing detector,
   answering "is this model's refusal single-direction (abliteration-fragile) or
   distributed (hardened)?" — the verifiable deliverable.
2. A `[research]`-gated, test-matrix-excluded recipe + driver for the actual FT.
3. Threat-model + paper wording that frames it as defense-in-depth for trusted
   nodes, explicitly *outside* the externalized-enforcement core.

## Scope Boundaries (non-goals)

- No training loop, dataset, or model weights in the CI-tested package core.
- No new always-on dependencies; anything heavy stays under `[research]` and out
  of the test matrix.
- No claim that the package "hardens models" — it documents a recipe and
  *measures* the outcome.

## Sources

- arXiv:2505.19056 (extended-refusal defense + latent-separation signal)
- arXiv:2406.11717 (Arditi — refusal direction), arXiv:2602.02132 (multi-directional refusal)
- `docs/internal/abliteration_threat_model.md` (Follow-ups → Open #2)
- `src/constitutional_swarm/eval/monotonic_mas/abliteration_detector.py` (CI-safe detector core)
- `src/constitutional_swarm/violation_subspace.py` (`refusal_alignment`, the measurement primitive)
