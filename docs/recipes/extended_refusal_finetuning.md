# Recipe: extended-refusal fine-tuning (abliteration-resistant refusal)

> **Reference recipe — not a CI-tested package feature.** This document describes
> an operator workflow that runs *outside* `constitutional_swarm`'s tested core. The
> library ships the CI-safe **measurement** (`refusal_distribution_score`) that tells
> you whether the hardening worked; it does **not** train, hold a dataset, or ship
> model weights. Producing hardened weights is the trusted-node operator's
> responsibility. See `docs/internal/abliteration_threat_model.md` and the
> feasibility study `docs/plans/2026-06-03-001-feat-extended-refusal-finetuning-feasibility.md`.

## What this defends against

*Abliteration* (Arditi et al., arXiv:2406.11717; automated by Heretic) removes a
model's safety refusal by orthogonalizing the residual-stream **write** matrices
against a *single* refusal direction `r̂`:

```
W' = (I − r̂ r̂ᵀ) W      ⇒      r̂ᵀ W' = 0
```

Because the refusal lives on one direction, one edit removes it. **Extended-refusal
fine-tuning** (arXiv:2505.19056, *"An Embarrassingly Simple Defense Against LLM
Abliteration Attacks"*) trains the model so refusal is mediated by **many**
directions. No single-direction edit can then remove it — the paper reports >90%
residual refusal after abliteration of an extended-refusal model.

This is a **training-time** defense for **trusted nodes** you operate. It complements
— it does not replace — the externalized defenses the swarm already ships (output
validation, peer quorum, the abliteration detector + admission gates, hardened
steering), which assume nothing about a node's internal alignment.

## Prerequisites

```bash
pip install 'constitutional-swarm[research,finetune]'
```

- `research` provides `torch` + `transformers`.
- `finetune` provides the trainer stack (`trl`, `peft`).
- A GPU sufficient for fine-tuning your target model.
- A refusal corpus (see **Dataset shape** — you supply the data; this repo ships none).

## Dataset shape

You provide the corpus; this recipe documents only its **shape**, not the data
(sourcing and licensing a harmful-prompt corpus is your governance decision). Two
splits, each a list of `{prompt, response}` records:

| Split | Prompt | Target response |
|-------|--------|-----------------|
| **Refusal** | harmful / policy-violating requests | a refusal (the behavior to distribute) |
| **Retain**  | benign requests | normal helpful completions (preserves capability) |

Mix benign "retain" examples in at roughly 1:1–2:1 (retain:refusal) so the model
keeps general capability while the refusal behavior is reinforced across dimensions.

## Objective

Extended-refusal fine-tuning is ordinary supervised fine-tuning (SFT / LoRA) on the
refusal split, with two design choices that distribute the refusal representation:

1. **Train across layers, not a probe head.** Full-model or multi-layer LoRA (not a
   single late-layer adapter) so the refusal signal is written by many residual-stream
   matrices, not one.
2. **Vary the refusal surface.** Diverse refusal phrasings and harmful-prompt
   categories so no single contrastive direction dominates the learned representation.

Reference hyperparameters (starting point — tune for your model):

| Knob | Reference value |
|------|-----------------|
| Method | LoRA (r=16–32) over all attention + MLP projections, or full FT if affordable |
| LR | 1e-5 (full FT) / 1e-4 (LoRA) |
| Epochs | 2–3 |
| Batch | as large as the GPU allows; grad-accum to ≥16 effective |
| Retain ratio | 1:1 to 2:1 (retain:refusal) |

## Running it

A thin reference driver is provided (excluded from the test matrix — it imports
`torch`/`trl` and is never collected by CI):

```bash
python scripts/finetune_extended_refusal.py --help
```

It wires the model, the two splits, and the trainer, then runs the verification step
below on the resulting model.

## Verification — did the hardening work?

This is the part the library does, CI-safe. Extract refusal directions at **several**
layers / token positions / prompt subsets, then score how distributed they are:

```python
import numpy as np
from constitutional_swarm.eval.monotonic_mas.abliteration_detector import (
    refusal_direction,
    refusal_distribution_score,
)

# Collect last-token residual activations for harmful vs harmless prompts at a
# spread of layers (you produce these from your model — torch side, not shown).
# harmful_by_layer[i], harmless_by_layer[i]: (n, d_model) arrays at layer i.
directions = np.vstack([
    refusal_direction(harmful_by_layer[i], harmless_by_layer[i])
    for i in probe_layers
])

score = refusal_distribution_score(directions)
print(f"refusal distribution score: {score:.3f}")
```

- **Base / single-direction model** → score near **0** (every layer recovers the same
  `r̂`): abliteration-fragile.
- **Extended-refusal-hardened model** → score toward **1** (layers recover distinct
  directions): a single-direction edit leaves most refusal intact.

To weight directions by the refusal-writing capacity that *survives* a partial edit,
pass the residual-stream write matrices:

```python
score = refusal_distribution_score(directions, write_matrices=write_matrices)
```

A successful hardening run should move the score from ≈0 (pre-FT) to a high value
(post-FT), and the model should retain >90% of its refusals after a Heretic/abliteration
pass against any single extracted direction. Pair this with the abliteration detector
(`detect_from_weights` / `detect_from_activations`) for the full before/after picture.

## Scope notes

- This recipe and `scripts/finetune_extended_refusal.py` carry **no CI coverage** by
  design — only `refusal_distribution_score` (the measurement) is gated by CI.
- The library makes **no claim to harden models**; it documents this recipe and
  *measures* the outcome.

## Sources

- arXiv:2505.19056 — extended-refusal defense + latent-separation signal
- arXiv:2406.11717 — Arditi et al., refusal direction
- arXiv:2602.02132 — multi-directional refusal
- `docs/internal/abliteration_threat_model.md` — the threat this closes (Follow-ups → #2)
