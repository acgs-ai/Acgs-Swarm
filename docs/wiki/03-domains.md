# 03 · Domains — the conceptual vocabulary

[← 02 Getting Started](02-getting-started.md) · Next: [04 Directory Map →](04-directory-map.md)

This page explains the *domains of meaning* the code operates in, so the module
reference (page 5) reads as elaboration rather than introduction. Short
definitions live in [`docs/concepts.md`](../concepts.md); deep dives in
[`docs/security-model.md`](../security-model.md) and the package paper. The
[glossary](09-glossary.md) is the quick lookup.

---

## Domain 1 — Constitutional governance (Pattern A)

A **constitution** (from `acgs-lite`) is a set of principles/rules over domains,
with a stable identity hash (`608508a9bd224290`). **Governed execution** means
policy checks run *in the runtime path*, not only in post-hoc audit.

- **Agent DNA** (`dna.py`): each agent embeds an `AgentDNA` co-processor.
  `validate(text)` returns a `DNAValidationResult` (valid + violations + risk).
  It is fast by design (~443ns/check) so it can sit on the hot path. `check_maci`
  and `govern` extend it; `constitutional_dna` is a decorator that wraps any
  callable. A disabled DNA raises `DNADisabledError` rather than silently passing.
- **Why local enforcement:** a central gate is a single point of failure and a
  bottleneck; embedding the check makes every agent independently accountable.

## Domain 2 — Orchestrator-free execution (Pattern B)

Work is a **DAG of tasks**, not an imperative script driven by a coordinator.

- **Compile:** `DAGCompiler.compile(GoalSpec)` (or `compile_from_yaml`) turns a
  structured goal into a `TaskDAG` of `TaskNode`s with dependency edges.
- **Execute:** `SwarmExecutor` lets capable agents *claim* ready nodes, do the
  work, and *submit* results; the DAG tracks readiness (`ready_nodes`,
  `mark_ready`, `complete_node`) until `is_complete`.
- **Stigmergy:** agents coordinate indirectly through a shared `ArtifactStore`
  (`artifact.py`) — content-addressed `Artifact`s published and discovered by
  task/domain/agent, like ants leaving pheromone trails. No agent commands
  another; the artifact medium *is* the coordination.
- **Capability routing:** `CapabilityRegistry` (`capability.py`) gives O(1)
  lookup of which agent can handle a domain (`find_best`).

## Domain 3 — Peer validation & settlement (Pattern C)

Outputs are accepted only after **assigned peers vote**, and decisions become
**durable, replayable evidence**.

- **The mesh:** `ConstitutionalMesh` (`mesh/core.py`) assigns peers
  (`request_validation` → `PeerAssignment`), collects **mandatory Ed25519-signed
  votes** (`register_local_signer`/`register_remote_agent` → `sign_vote` →
  `submit_vote`), and settles when quorum is met (`get_result` → `MeshResult`
  with a `MeshProof`). Unsigned or mis-signed votes raise
  `InvalidVoteSignatureError`. A settled assignment is frozen
  (`AssignmentSettledError`); durable replays are blocked
  (`RecoveredAssignmentError`).
- **Settlement stores** (`settlement_store.py`): `JSONLSettlementStore` and
  `SQLiteSettlementStore` persist `SettlementRecord`s append-only, with a
  pending/clear two-phase pattern so a crash mid-settle is recoverable.
- **Governance receipts** (`governance_receipts.py`): a **verifier-first**
  profile. Receipts are canonicalized (`canonical_json_bytes`), hash-linked, and
  independently verifiable (`verify_bundle`) — the verifier needs no trust in the
  producer. `acgs-verify-receipts` is the CLI; `governance_receipts_dsse.py`
  projects receipts onto DSSE / in-toto envelopes for supply-chain tooling.
- **Quorum certificates** (`quorum_certificate.py`): `QuorumCertificate` bundles
  signed votes meeting a weight threshold, with **accountable safety** — two
  conflicting certificates for the same `(assignment, epoch)` produce slashable
  `ConflictEvidence`.
- **Validator sets** (`validator_set.py`): Sybil-resilient membership with
  fault-domain weight caps and VRF-style deterministic committee selection
  (`CommitteeSelector.select`).

<a id="trust-dynamics"></a>
## Domain 4 — Trust dynamics / the governance manifold (Pattern D)

Trust between agents is a matrix that evolves over time. Left unconstrained it
can blow up (one agent dominates) or collapse (everyone identical). The fix:
**project each update into a bounded manifold.**

- **`spectral_sphere.py` (production direction):** constrains the trust matrix to
  a **spectral-norm sphere** (‖H‖₂ ≤ r) via power iteration. This bounds
  influence while preserving heterogeneity — `compose()` stays well-conditioned.
- **`manifold.py` (baseline control — DO NOT FIX):** the Birkhoff/Sinkhorn
  projection onto the doubly-stochastic polytope. It suffers **uniformity
  collapse** (the trust matrix tends to uniform), which is *the empirical proof*
  motivating the spectral-sphere replacement. The 2 xfail tests are this collapse;
  they are kept deliberately. See
  [the spectral-sphere learning](../solutions/) and `DECISIONS.md`.
- **`swarm_ode.py` (research):** treats trust as a continuous-time ODE
  (`dH/dt = f_θ(H,t)`), integrated with **Projected RK4** that re-projects onto
  the spectral sphere each step; includes DP-noise calibration for gossip.

> **Landmine:** any change that "improves" `manifold.py`'s collapse must instead
> go through `spectral_sphere.py`. The collapse is the result, not the bug.

## Domain 5 — Evolution metrics & reconfiguration

- **`evolution_log.py`:** an append-only, SQLite-backed log of governance metrics
  that **enforces strict monotonicity + non-negative acceleration at write
  time**. A non-increasing value raises `NonIncreasingValueError`; a decelerating
  delta raises `DecelerationBlockedError`; updates/deletes raise
  `MutationBlockedError`. It also detects regressions/decelerations/gaps for a
  dashboard. This is how the swarm proves it is *accelerating its own
  improvement*, not drifting.
- **`epoch_reconfig.py`:** versioned constitutional amendment under **joint
  consensus** — a `TransitionCertificate` must be ratified by *both* the old and
  new validator sets, the proposal epoch must match, and the amendment diff must
  fit a declared `DriftBudget` (else `DriftBudgetExceeded`).
- **`debate_resolver.py`:** a CourtGuard-style structured adversarial debate
  (Proposer → Challenger → Defense → Verdict) with a Merkle-rooted transcript,
  for MACI-aware governance.

## Domain 6 — Node admission & Byzantine safety

- **Abliteration** is the attack of surgically removing a model's refusal
  direction (making it comply with anything). `node_admission.py` screens
  candidate validators *before* they join a quorum, using detectors in
  `eval/monotonic_mas/abliteration_detector.py` (refusal-direction energy,
  harmful/benign activation separation, refusal *distribution*). See
  [`docs/internal/abliteration_threat_model.md`](../internal/abliteration_threat_model.md).
- **`byzantine_census.py`:** estimates the tampered fraction of the swarm from a
  screened sample (with a confidence interval) and returns a Byzantine-safety
  verdict.

## Domain 7 — Privacy & federation (research)

- **`privacy_accountant.py`:** session-scoped RDP moments accountant for
  (ε,δ)-differential privacy; raises `PrivacyBudgetExhausted` when the cumulative
  ε-budget is spent.
- **`private_vote.py`:** commit-reveal private voting with **nullifiers** to
  prevent double-voting (`DoubleVoteError`), optional validity proofs (hash
  commitment now, ZK-SNARK marker for later), and a deterministic `tally`.
- **`federated_bridge.py`:** cross-organizational FCHP layer — verifiable
  `AgentCredential`s gate access across org boundaries with an audit log.
- Protocol-level detail: [`docs/maci_dp_protocol.md`](../maci_dp_protocol.md).

## Domain 8 — Latent-space steering (research)

- **`latent_dna.py`:** wraps a HuggingFace model with **BODES** steering — a
  forward hook nudges the residual stream away from a learned violation direction
  during `generate_governed(...)`, giving constitutional control *inside* the
  model rather than around it.
- **`violation_subspace.py`:** fits the rank-`k` "violation subspace" (contrastive
  SVD or **LEACE** oblique whitening) that the steering projects against;
  `adversarial_score` measures residual violation mass after steering.

## Domain 9 — Bittensor governance subnet (advanced/research)

`bittensor/` is a full incentive-aligned governance subnet (gated behind
`[bittensor]`). The loop: the **SN Owner** (`subnet_owner.py`) escalates hard
cases; **miners** (`miner.py`) deliberate; **validators** (`validator.py`) grade
with cryptographic proof; **emissions** (`emission_calculator.py`,
`island_evolution.py`) reward quality; validated judgments become **precedent**
(`precedent_store.py`), get **codified into rules** (`rule_codifier.py`), and feed
a **MAP-Elites** quality grid (`map_elites.py`, `came_coordinator.py`). Audit
trails anchor to **Arweave** (`arweave_audit_log.py`) and chain
(`chain_anchor.py`). Anti-collusion via commit-reveal **NMC** (`nmc_protocol.py`).
See [`bittensor/AGENTS.md`](../../src/constitutional_swarm/bittensor/AGENTS.md).

## Domain 10 — Evaluation & SWE-bench (research)

- **`swe_bench/`:** a scaffold to run agents (Claude/Codex/Gemini/Vertex/mini)
  against SWE-bench Lite, optionally as a **swarm** coordinated through a
  MerkleCRDT, with best-of-K pickers, a Docker-less local harness, and a recovery
  plane. See [`swe_bench/AGENTS.md`](../../src/constitutional_swarm/swe_bench/AGENTS.md).
- **`eval/monotonic_mas/`:** role-drift / handoff / dedupe detectors and an
  autoresearch evaluator (mission H1) measuring whether governance catches
  coordination failures.
- **`forensic_benchmark.py`:** a reproducible blind-review benchmark protocol
  (incident generation, reviewer scoring, paired sign-test) for the v0.1
  public-study claim.

Continue to [04 Directory Map →](04-directory-map.md).
