# Threat model: abliterated agents in a constitutional swarm

**Status:** active · **Date:** 2026-06-01 · **Scope:** MCFS governance vs. model tampering

## Threat

*Abliteration* removes a language model's safety-refusal mechanism without
retraining, by orthogonalizing the residual-stream **write** matrices against the
"refusal direction" `r̂`. For every write matrix `W` (attention out-projection
`W_O`, MLP down-projection `W_out`):

```
W' = (I − r̂ r̂ᵀ) W      ⇒      r̂ᵀ W' = 0
```

`r̂` is extracted by difference-of-means of last-token residual activations on
harmful vs. harmless prompts (Arditi et al., arXiv:2406.11717). `Heretic`
(github.com/p-e-w/heretic) automates parameter selection via Optuna, co-minimizing
refusals and KL-divergence from the original model.

**Adversary in our setting:** a swarm node running an abliterated model. It no
longer self-refuses, so it may emit constitutional violations the model would
previously have declined.

## What is robust (and why)

`constitutional_swarm` **externalizes enforcement**, so most defenses do not
depend on the model's internal alignment and survive abliteration:

| Defense | Layer | Abliteration-robust? |
|---|---|---|
| `AgentDNA.validate` (rule engine + risk scorer + Z3) | output-external | ✅ catches the violation in the emitted text |
| Mesh peer quorum (`mesh/core.py`) | output-external | ✅ honest peers reject; Byzantine-tolerant to <1/3 |
| Role-drift detectors incl. cross-encoder (`eval/.../semantic.py`) | output-external | ✅ semantic channel resists synonym evasion |
| Gossip / settlement / constitutional-hash guard | protocol-level | ✅ structural invariants |

**Headline claim (paper-relevant):** *constitutional governance is abliteration-robust
by externalization* — removing a model's internal refusal does not remove the
swarm's ability to catch what that model produces, because enforcement lives in
output validation + peer quorum, not in the model's weights.

## Where it bites

1. **Activation-space steering degrades silently.** `latent_dna` (BODES) and
   `violation_subspace` steer `h ← h − γ (h·v_viol) v_viol` in the *same* residual
   space abliteration attacks. The steering literature (arXiv:2603.24543, R²≥0.85
   for >3B models) indicates `v_viol` is largely *aligned* with `r̂`. On an
   abliterated model the steering vector still enters the residual stream, but the
   abliterated write matrices cannot reinforce it downstream — efficacy drops with
   no error raised. Output validation backstops correctness, but the steering layer
   quietly stops contributing. **Mitigated** by `ViolationSubspace.orthogonalize_against`
   (see *Hardened steering* under Follow-ups → Shipped): steering in directions ⟂ `r̂`
   is not what abliteration zeros, so it keeps contributing.
2. **No tamper detection.** The swarm catches *violations* but could not detect a
   *tampered model*. Byzantine tolerance assumes <1/3 abliterated peers with no way
   to count them.

## Mitigation shipped

`eval/monotonic_mas/abliteration_detector.py` — a node-trust signal using two
published, pure-numpy detection methods (CI-safe; no torch/live model needed for
the detector logic or its tests):

- **Weight null-space signature** (mechanistically exact): refusal energy
  `‖r̂ᵀ W‖ / ‖W‖_F` collapses toward 0 when abliterated. `detect_from_weights`
  flags via reference-ratio (handles *partial* abliteration) or absolute floor.
- **Latent-separation collapse** (arXiv:2505.19056): harmful/benign final-hidden-state
  distance drops 28–38% post-abliteration. `detect_from_activations` flags a low
  ratio vs. a trusted reference.

`refusal_direction` (Arditi extraction) and `apply_abliteration` (models the edit)
are included so the signal is verifiable end-to-end and so callers can build
reference/adversarial fixtures.

## Follow-ups

### Shipped

- ✅ **Detector integrated into quorum node-admission.**
  `node_admission.AbliterationAdmissionGate` screens candidate validators' write
  matrices and feeds the rejected ids into `CommitteeSelector.select(exclude=...)`,
  so an abliterated node cannot be sampled into a committee. Defaults to the `min`
  aggregation preset (flag if *any* write matrix collapses), which closes the
  minority-subset evasion the `median` default missed (dogfood finding F1). The
  gate also returns per-agent `AbliterationReport`s for the down-weight-instead-of-
  exclude alternative. Screening still requires runtime weights → `research` extra
  + a model. (PR #61.)
- ✅ **Configurable detector aggregation.** `detect_from_weights` gained an
  `aggregate` parameter (`"median"` | `"mean"` | `"min"` | `"quantile"`) so callers
  can trade reference-noise robustness for minority-subset sensitivity. (PR #60.)
- ✅ **Activation-path admission.** `node_admission.ActivationAdmissionGate` screens
  nodes that expose final-hidden-state activations but not write matrices, via
  `detect_from_activations` (harmful/benign separation-collapse vs. a trusted
  `reference_separation`). Same `screen()` / `select_admissible()` surface as the
  weight gate, so either modality feeds the same `CommitteeSelector.select(exclude=...)`
  path. Candidates are passed as `ActivationProbe(harmful, harmless)`.
- ✅ **Hardened steering.** `ViolationSubspace.orthogonalize_against(r̂)` projects the
  refusal direction out of the governance steering subspace, so the steering edit in
  the original residual space is orthogonal to `r̂` and survives abliteration
  (arXiv:2603.24543). It handles both the plain (RepE/mean-diff) and LEACE regimes —
  the edit maps through `dewhitener` in LEACE mode, so the deflation is computed in
  `r̃ = dewhitener @ r̂` space — and multi-directional refusal sets (arXiv:2602.02132).
  `ViolationSubspace.refusal_alignment(r̂)` quantifies the exposure (fraction of `r̂`
  captured by the subspace, ∈ `[0, 1]`) and verifies the fix drives it to ≈ 0. A basis
  lying entirely within the refusal span raises (it must be refit, not hardened). This
  closes the silent-degradation gap in *"Where it bites" #1*; `r̂` comes from
  `abliteration_detector.refusal_direction`. Pure-NumPy, CI-safe.

### Open

- ⬜ **Defense-in-depth at training time** (for trusted nodes): extended-refusal
  fine-tuning distributes refusal across dimensions and resists single-direction
  abliteration (arXiv:2505.19056, >90% residual refusal). Requires a real model +
  fine-tuning loop (torch, not CI-safe), so it sits outside the pure-NumPy detector/
  steering core — scoped separately. See
  `docs/plans/` (extended-refusal fine-tuning feasibility) before implementing.

## Sources

Arditi et al. 2406.11717 · Heretic (p-e-w) · arXiv:2505.19056 (extended-refusal
defense + latent-separation signal) · arXiv:2603.24543 (steering/refusal alignment)
· arXiv:2602.02132 (multi-directional refusal) · FailSpy/abliterator · Labonne
(HF blog).
