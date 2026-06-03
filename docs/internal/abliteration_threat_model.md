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

- ✅ **Training-time defense-in-depth (Option A: recipe + CI-safe measurement).**
  Extended-refusal fine-tuning distributes refusal across many dimensions so no
  single-direction abliteration can remove it (arXiv:2505.19056, >90% residual
  refusal). Shipped *as Option A* (per the feasibility study): the library does **not**
  absorb a training pipeline. It ships (a) `abliteration_detector.refusal_distribution_score`
  — a pure-NumPy, CI-safe measurement of how distributed a model's refusal is
  (`~0` = single-direction/abliteration-fragile, `~1` = distributed/hardened), the
  verifiable "did the hardening work?" check; (b) a `[research,finetune]`-gated, test-
  matrix-excluded reference recipe (`docs/recipes/extended_refusal_finetuning.md`) +
  driver (`scripts/finetune_extended_refusal.py`) for the actual fine-tuning.
  **Scope (honest):** the library *measures* the outcome; **producing hardened model
  weights remains the trusted-node operator's action**, deliberately outside the
  externalized-enforcement, CI-safe core. (Plan:
  `docs/plans/2026-06-03-002-feat-extended-refusal-finetuning-plan.md`; feasibility:
  `docs/plans/2026-06-03-001-feat-extended-refusal-finetuning-feasibility.md`.)
- ✅ **Refusal-distribution admission gate.** `node_admission.RefusalDistributionGate`
  screens candidate validators on the *distribution* axis: it flags a node whose
  refusal is mediated by a single direction (`refusal_distribution_score` below a
  configurable `min_distribution`) so a trusted committee can prefer extended-refusal-
  hardened nodes. Same `screen()` / `select_admissible()` surface as the abliteration
  gates, feeding the same `CommitteeSelector.select(exclude=...)` path. The flag is a
  **trust signal, not a tamper verdict** — its report uses the honest field name
  `fragile` (the node is honest, just one orthogonalization from losing refusal), so a
  caller may down-weight rather than exclude. Candidates are passed as
  `RefusalDirectionProbe(directions, write_matrices=None)`; the optional write matrices
  weight each direction by its *surviving* refusal-writing energy. Screening needs
  runtime directions/weights → `research` extra + a model; the score itself is pure-NumPy.
- ✅ **Tamper-fraction census for Byzantine accounting** (addresses *Where it bites #2*).
  `byzantine_census.estimate_tampered_fraction(n_screened, n_tampered, ...)` turns a
  screened sample into a point estimate plus a two-sided confidence interval for the
  swarm-wide tampered fraction (Wilson score or exact Clopper-Pearson, both pure-NumPy
  /stdlib — no scipy), and renders a verdict against the `1/3` Byzantine bound:
  `"safe"` (CI below threshold), `"violated"` (CI above), or `"inconclusive"` (CI
  straddles → screen more). `census_from_decisions(...)` pools
  `AbliterationAdmissionGate` / `ActivationAdmissionGate` decisions (dedup by agent),
  and **refuses** to count a `RefusalDistributionReport` `fragile` flag — that is a
  trust signal, not a tamper verdict. **Scope (honest):** this bounds only the
  *detectable* tampered fraction over *screened* nodes and assumes the screen is sound
  and the sample representative, so `"safe"` is *necessary but not sufficient* for the
  true assumption. It does not catch a node that hides tampering from the screen
  (adversarial self-report).

### Open

- ⬜ **Adversarial self-report / unscreened tampering.** The census above bounds the
  *detectable* fraction; a node that hides tampering from the screen is not counted.
  Closing this needs verifiable model-integrity evidence — **remote attestation** (TEE
  quote / signed weight digest + a verifier feeding the same census) — whose trust root
  is hardware/external and therefore sits outside the pure-NumPy, externalized-enforcement
  core (analogous to the extended-refusal training pipeline staying out of CI). Scoped as
  an attestation-integration follow-up, not an incremental measurement primitive.

## Sources

Arditi et al. 2406.11717 · Heretic (p-e-w) · arXiv:2505.19056 (extended-refusal
defense + latent-separation signal) · arXiv:2603.24543 (steering/refusal alignment)
· arXiv:2602.02132 (multi-directional refusal) · FailSpy/abliterator · Labonne
(HF blog).
