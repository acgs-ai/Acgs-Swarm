# 05 · Module reference — code logic, module by module

[← 04 Directory Map](04-directory-map.md) · Next: [06 Runtime Flows →](06-runtime-flows.md)

The per-module map of *what the code does and how*. Organized by maturity tier
(see [01-overview](01-overview.md#maturity-tiers-what-to-trust)). For each module:
**purpose**, **key public surface** (classes/functions exported via
`__init__.py` where applicable), **logic notes**, and **⚠ invariants/gotchas**.

> Source of truth for the public surface is `__init__.py`'s `__all__`. If you add
> a public symbol, add it there (alphabetized) — `make agent-check` enforces it.

---

# Stable core

### `dna.py` — Agent DNA (Pattern A)
- **Purpose:** embedded constitutional co-processor; the local enforcement hot path.
- **Surface:** `AgentDNA` (`.from_rules`, `.from_yaml`, `.default`, `.validate`,
  `.check_maci`, `.govern`, `.disable`/`.enable`, `.hash`, `.stats`),
  `DNAValidationResult`, `constitutional_dna` (decorator), `DNADisabledError`.
- **Logic:** `validate(text)` runs the constitution's rule matchers and returns
  valid + violations + risk; built to sit inline on the local hot path.
  `constitutional_dna` wraps any callable to validate its output.
- **⚠** A disabled DNA **raises** `DNADisabledError` on `validate()` — it never
  silently passes. Greek-symbol-heavy sibling `latent_dna.py` is *not* this.

### `compiler.py` — DAG compiler (Pattern B)
- **Purpose:** turn a structured goal into an executable DAG.
- **Surface:** `DAGCompiler` (`.compile`, `.compile_from_yaml`), `GoalSpec`,
  `GoalStep` (a `Mapping` for backward-compatible dict access).
- **Logic:** a `GoalSpec` of `GoalStep`s → `TaskDAG` with dependency edges
  inferred from step references.

### `swarm.py` — stigmergic execution (Pattern B)
- **Purpose:** orchestrator-free DAG execution.
- **Surface:** `TaskDAG` (`.add_node`, `.ready_nodes`, `.mark_ready`,
  `.claim_node`, `.complete_node`, `.is_complete`, `.progress`, `.to_contracts`),
  `TaskNode`, `SwarmExecutor` (`.load_dag`, `.available_tasks`, `.claim`,
  `.submit`, `.is_complete`, `.progress`, `.dag`).
- **Logic:** agents pull `available_tasks`, `claim` a node, do work, `submit`;
  the DAG advances readiness until complete. No central driver.

### `execution.py` — shared execution model
- **Purpose:** lifecycle states + work receipts shared across swarm internals.
- **Surface:** `WorkReceipt` (`.claim`, `.complete`, `.fail`, `.is_expired`,
  `.is_claimable`, `.execution_status`), `ExecutionStatus`, `ContractStatus`,
  `contract_status_from_execution`.
- **Logic:** canonical `ExecutionStatus` is mapped to the public `ContractStatus`
  so receipt APIs stay backward-compatible. `contract.py` is a thin compat layer.

### `artifact.py` — artifact store (Pattern B)
- **Purpose:** the stigmergic coordination medium.
- **Surface:** `Artifact` (immutable, `.content_hash`), `ArtifactStore`
  (`.publish`, `.publish_deferred`, `.get_by_task`/`_domain`/`_agent`, `.watch`,
  `.verify_integrity`, `.summary`).
- **Logic:** content-addressed artifacts indexed by task/domain/agent; `watch`
  registers callbacks dispatched on publish. In-memory.

### `capability.py` — capability routing
- **Purpose:** O(1) "who can do this domain" lookup.
- **Surface:** `Capability` (`.matches`), `CapabilityRegistry` (`.register`,
  `.find_by_domain`, `.find_best`, `.summary`).

### `mesh/` — Constitutional Mesh (Pattern C)
- **Purpose:** Byzantine-tolerant peer validation with cryptographic proof.
- **Surface (`mesh/core.py`):** `ConstitutionalMesh` —
  `register_local_signer` / `register_remote_agent` / `sign_vote`,
  `request_validation` (→ `PeerAssignment`), `submit_vote`, `get_result`
  (→ `MeshResult` + `MeshProof`), `halt`/`resume`/`is_halted`,
  `rotate_constitution`, `get_reputation`, `_select_peers` (trust-weighted
  sampling + one exploration slot).
- **Supporting types:** `mesh/voting.py` (`ValidationVote.vote_hash`,
  `RemoteVoteRequest`), `mesh/peers.py` (`PeerAssignment`), `mesh/settlement.py`
  (`MeshProof.verify`, `MeshResult`, `ReconciliationReport`), `mesh/exceptions.py`.
- **Logic:** a producer requests validation; the mesh assigns peers; each peer
  signs and submits a vote; on quorum the result is settled, frozen, and (if a
  store is attached) persisted, with a `MeshProof` for later verification.
- **⚠** Signed votes are **mandatory** — missing/bad signature →
  `InvalidVoteSignatureError`. Settled = frozen (`AssignmentSettledError`);
  durable replay blocked (`RecoveredAssignmentError`); halted mesh blocks all ops
  (`MeshHaltedError`); persistence failure after freeze → `SettlementPersistenceError`.

### `settlement_store.py` — durable settlement
- **Purpose:** persist settled results as replayable evidence.
- **Surface:** `SettlementStore` (Protocol), `JSONLSettlementStore`,
  `SQLiteSettlementStore` — `.append`, `.load_all`, `.mark_pending`,
  `.clear_pending`, `.load_pending`, `.pending_count`, `.describe`;
  `SettlementRecord`, `DuplicateSettlementError`.
- **⚠** Append-only; duplicate key → `DuplicateSettlementError`. The
  pending/clear pair is the crash-safe two-phase write — mark pending before the
  freeze, clear only after durable success.

### `governance_receipts.py` (+ `_cli.py`, `_dsse.py`) — verifier-first receipts
- **Purpose:** canonicalized, independently verifiable governance evidence.
- **Surface:** Pydantic models `GovernanceReceipt`, `GovernanceReceiptBundle`,
  `ReceiptPayload`, `RoleIdentity`, `ValidatorVote`, `SignatureRecord`,
  `VerificationVerdict`; functions `canonical_json_bytes`, `payload_digest`,
  `build_receipt`, `verify_bundle`, `bundle_from/to_json`, `reconstructability_score`.
  CLI: `governance_receipts_cli.main` → `acgs-verify-receipts`.
  DSSE: `governance_receipts_dsse.py` — `to_in_toto_statement`,
  `to_dsse_envelope`/`verify_dsse_envelope`, `DsseSigner`, `pae`.
- **Logic:** receipts hash-link a payload + detached signatures; `verify_bundle`
  re-derives digests and checks signatures with **no trust in the producer**
  (verifier-first profile, ADR `acgs_v0_1_verifier_first_scope.md`).

### `quorum_certificate.py` — accountable-safety quorum
- **Surface:** `QuorumCertificate` (`.to_dict`/`.from_dict`, `.qc_id`),
  `SignedVote` (`.message`, `.verify`), `ConflictEvidence` (`.is_slashable`),
  `build_vote_message`, `build_certificate`, `verify_certificate`, `detect_conflict`.
- **Logic:** a QC bundles Ed25519 votes ≥ weight threshold. Two QCs for the same
  `(assignment, epoch)` with different artifact hashes → slashable conflict.

### `validator_set.py` — Sybil-resilient committees
- **Surface:** `ValidatorSet` (`.add`/`.remove`, `.effective_total_weight`,
  `.domain_weights`, `.snapshot`), `ValidatorIdentity` (`.effective_weight`),
  `FaultDomainPolicy`, `CommitteeSelector` (`.select`, `.select_until_independent`),
  `CommitteeSelection` (`.has_quorum`), `SybilBoundViolation`.
- **Logic:** VRF-style deterministic sampling with a per-fault-domain weight cap;
  exceeding the cap raises `SybilBoundViolation`.

### `governed_handoff.py` — `acgs-swarm` CLI
- **Purpose:** governed coding-agent task handoff producing an **unforgeable
  evidence bundle**.
- **Surface:** CLI `acgs-swarm {run|verify|pack}` (`main`, `build_parser`);
  `PolicyEngine.decide` (`PolicyDecision`), adapters (`MockAdapter`,
  `LocalShellAdapter`, `ExternalAgentAdapter`, `ExecutorAdapter` Protocol),
  `build_bundle`, `verify_bundle`, `BundleSigner`, `AuditLogger`, `TaskSpec`,
  `RunResult`, `Action`.
- **Logic (hardened — see `DECISIONS.md` 2026-06-03):**
  - `build_bundle(signer=, constitutional_version=)` Ed25519-signs a
    domain-separated attestation (`BUNDLE_SIG_DOMAIN`) binding chain_hash +
    constitution_hash + version pin + final_state + task identity.
  - `verify_bundle(..., trusted_public_keys=...)` **requires** a valid signature
    for `ok` when a trust anchor is supplied; trust derives only from
    out-of-band keys, never the bundle-embedded key.
  - The `tool_call` gate is **default-DENY allowlist**
    (`DEFAULT_COMMAND_ALLOWLIST = python, python3, pytest`); the constitution may
    extend but never weaken it.
  - `_intake` **fails closed** if the constitution declares a
    `constitutional_version`/`hash` ≠ the pinned `608508a9bd224290`.
- **⚠** Backward compatible: with no signer/anchor, `verify_bundle` still returns
  `ok` on chain-consistency and runs are honestly reported `signed: false`.

### `protocol.py` — canonical protocol encoders
- **Purpose:** the canonical-byte boundary for a future Rust core.
- **Surface:** `canonical_json_bytes`, `protocol_sha256_hex`,
  `canonical_content_hash` (+ `legacy_*` compat fixtures), `encode_vote_payload_v1`,
  `encode_remote_vote_request_*_v1`, `encode_mesh_proof_v1`,
  `encode_settlement_record_v1`, `encode_spectral_sphere_snapshot_v1`.
- **⚠** `legacy_*` functions reproduce the *current* Python wire format and must
  stay byte-stable; the `*_v1` encoders are the versioned Rust-core target.
  ADR: `docs/internal/rust_core_protocol_adr.md`.

### `constants.py` / `contract.py`
- Shared constants (incl. the constitutional hash) / backward-compatible contract
  API layered on `execution.py`.

---

# Advanced runtime

### `remote_vote_transport/` — remote vote RPC (`[transport]`)
- **Surface:** `RemoteVoteClient.request_vote`, `RemoteVoteServer`
  (`.start`/`.stop`/`.actual_port`), `LocalRemotePeer.handle_vote_request`,
  `RemoteVoteResponse`, encode/decode helpers.
- **Logic:** one-shot request-response over WebSocket; a public-key-only peer
  validates and signs the request. Replay protection via nonce window
  (`RemoteVoteReplayError`).

### `gossip_protocol.py` — gossip transport (`[transport]`)
- **Surface:** `SwarmNode` (CRDT replica + transport; `.gossip_round`,
  `.run_gossip_loop`), `GossipServer`, `GossipClient`, `GossipPeerRegistry`,
  `encode_batch`/`decode_batch`, `spin_up_swarm`, `simulate_ws_gossip_convergence`.
- **Logic:** nodes exchange `DAGNode` batches over WebSocket and set-union merge
  them into a local `MerkleCRDT`, converging without a coordinator.

### `evolution_log.py` — invariant-enforced metrics
- **Surface:** `EvolutionLog` (`.open`/`.close`, `.record`, `.detect_regression`,
  `.detect_deceleration`, `.detect_gaps`, `.dashboard`, `.admit`,
  `.valid_trajectory`); error hierarchy `EvolutionViolationError` →
  `NonIncreasingValueError`, `DecelerationBlockedError`, `MissingPriorEpochError`,
  `DuplicateRecordError`, `MutationBlockedError`.
- **Logic:** append-only SQLite; **every write checks strict monotonicity +
  non-negative acceleration**. Detectors surface regressions/decelerations/gaps.
- **⚠** Never silently drop a record — raise the matching error. No UPDATE/DELETE.

### `spectral_sphere.py` — bounded trust dynamics (production)
- **Surface:** `SpectralSphereManifold` (`.update_trust`, `.project`,
  `.spectral_norm`, `.is_stable`, `.compose`, `.influence_vector`, `.summary`),
  `spectral_sphere_project`, `spectral_norm_power_iter`, `SpectralProjectionResult`.
- **Logic:** projects the trust matrix onto the spectral-norm sphere ‖H‖₂ ≤ r via
  power iteration; bounds influence while preserving heterogeneity. Smoothing
  default is `0.9` (was `0.999` — see TASKS.md / PR #57).
- **⚠** `compose()` at `residual_alpha=0` can still rank-1 collapse — that's an
  operator-choice property, not OT-specific (see the spectral-sphere learning /
  PR #80). This is the **production** replacement for `manifold.py`.

### `epoch_reconfig.py` — versioned reconfiguration
- **Surface:** `ConstitutionVersion` (`.digest`), `AmendmentProposal` (`.drift`),
  `DriftBudget`, `TransitionCertificate`, `compute_version_digest`,
  `evaluate_drift`, `verify_transition`; errors `InvalidTransitionError`,
  `EpochMismatchError`, `JointQuorumNotMetError`, `DriftBudgetExceeded`.
- **Logic:** an amendment must pass **joint consensus** (old AND new validator
  sets ratify), match the expected epoch, and fit the declared drift budget.
- **Formal model:** `specs/constitution_reconfig.tla`.

### `debate_resolver.py` — adversarial debate
- **Surface:** `DebateResolver` (`.propose`, `.challenge`, `.defend`, `.resolve`,
  `.summary`), `DebateRecord` (`.compute_merkle_root`), `FinalVerdict`
  (`.is_approved`), `VerdictOutcome`.
- **Logic:** CourtGuard pattern — Proposer/Challenger/Defense produce a
  Merkle-rooted transcript resolved to a verdict.

### `node_admission.py` — abliteration-aware admission
- **Surface:** `AbliterationAdmissionGate`, `ActivationAdmissionGate`,
  `RefusalDistributionGate` (each `.evaluate`/`.screen`/`.select_admissible`),
  `AdmissionDecision` (`.rejected_set`), `ActivationProbe`, `RefusalDirectionProbe`.
- **Logic:** screens candidate validators for abliteration *before* quorum
  admission using weight-energy, activation-separation, and refusal-distribution
  probes (detectors in `eval/monotonic_mas/abliteration_detector.py`).

### `byzantine_census.py` — tampered-fraction census
- **Surface:** `TamperCensus` (`.safe`), `estimate_tampered_fraction`,
  `census_from_decisions`.
- **Logic:** statistical estimate (with CI) of the swarm's tampered fraction +
  Byzantine-safety verdict, built from admission decisions.

### `langgraph_runtime/` — LangGraph adapter (`[langgraph]`)
- **Surface:** `build_swarm_graph` (`runtime.py`); nodes `validate_node`,
  `generate_node`, `append_crdt_node`, `evolve_trust_node`, `settle_node`;
  guards `constitutional_hash_guard`, `fail_closed_guard`, `quorum_guard`;
  `SwarmGraphState` (TypedDict); `EvolutionLogObserver`/`observe_stream`;
  `build_handoff_swarm` (`swarm_topology.py`, `[langgraph-swarm]`);
  `LangGraphSWEBenchAgent`.
- **Logic:** maps the governed flow onto a LangGraph `StateGraph` —
  validate→generate→append-CRDT→evolve-trust→settle, with conditional-edge guards
  that **fail closed** on hash mismatch (`ConstitutionalHashError`) and gate
  quorum (3-of-5). Side-car observer mirrors stream events into `EvolutionLog`.
- **⚠** Known live type error `swarm_topology.py:126` — excepted in the mypy gate
  (DECISIONS.md typecheck entry).
- Adapter guide: [`docs/langgraph_runtime.md`](../langgraph_runtime.md).

### `bittensor/` — governance subnet (`[bittensor]`)
The largest subpackage; a full incentive subnet. By role:

| Concern | Modules |
|---|---|
| Runtimes | `subnet_owner.py`, `miner.py`, `validator.py`, `axon_server.py`, `dendrite_client.py` |
| Coordination | `governance_coordinator.py`, `came_coordinator.py`, `nmc_protocol.py` (anti-collusion commit-reveal) |
| Quality / evolution | `map_elites.py`, `island_evolution.py`, `emission_calculator.py`, `threshold_updater.py`, `tier_manager.py`, `authenticity_detector.py` |
| Precedent / rules | `precedent_store.py`, `rule_codifier.py`, `cascade.py` |
| Audit / anchoring | `arweave_audit_log.py`, `chain_anchor.py`, `compliance_certificate.py`, `constitution_sync.py` |
| Protocol / wire | `protocol.py`, `synapses.py`, `synapse_adapter.py` |

- **⚠** `arweave_audit_log.py` uses a **two-phase commit**: cache Phase 1 in
  `_retry_state`, clear only on Phase 2 success (crash-safe). `TierManager` and
  `PrecedentStore` are thread-safe via `threading.Lock`. Precedent quorum is
  **3/5** (`min_total_validators=5, min_votes_for_precedent=3`).
  Guide: [`bittensor/AGENTS.md`](../../src/constitutional_swarm/bittensor/AGENTS.md).

---

# Research / experimental

### `latent_dna.py` — BODES residual steering (`[research]`)
- **Surface:** `LatentDNAWrapper` (`.enable`/`.disable`, `.generate_governed`,
  `.extract_violation_vector`, `.intervention_stats`).
- **Logic:** registers a forward hook (`_BODESHook` / rank-k `_BODESSubspaceHook`)
  that steers the residual stream away from a violation direction during
  generation.
- **⚠** Carries ~53 pre-existing RUF002/RUF003 ruff errors (Greek characters).
  **Do not mass-rewrite** — suppress targeted rules if lint-clean is required.

### `violation_subspace.py` — LEACE steering subspace
- **Surface:** `ViolationSubspace` (`.projector`, `.project_component`, `.steer`,
  `.refusal_alignment`, `.is_leace`), `RiskAdaptiveSteering`, `fit_subspace`,
  `fit_leace`, `adversarial_score`; errors `InsufficientSamplesError`,
  `DimensionMismatchError`.

### `swarm_ode.py` — continuous-time trust
- **Surface:** `integrate`, `projected_rk4_step`, `spectral_project_torch`,
  `TrustDecayField`/`StationaryField` (vector fields), `DiscreteGaussianSampler`,
  `DrandClient` (beacon), `calibrate_sigma`/`add_dp_noise`.
- **Logic:** integrates `dH/dt = f_θ(H,t)` with Projected RK4 re-projecting onto
  the spectral sphere each step; DP-noise calibrated per NDSS Lemma 4.3 / Eq. 3.

### `merkle_crdt.py` — content-addressed DAG
- **Surface:** `MerkleCRDT` (`.append`, `.merge`/`.merge_nodes`, `.heads`,
  `.topological_order`, `.verify_integrity`), `DAGNode` (`.verify_cid`),
  `compute_cid`, `simulate_gossip_convergence`.
- **Logic:** SHA-256 CID content addressing; set-union merge makes replicas
  converge. Pairs with `gossip_protocol.py`.

### `manifold.py` — Birkhoff baseline (**FROZEN CONTROL — DO NOT FIX**)
- **Surface:** `GovernanceManifold` (`.update_trust`, `.project`, `.compose`,
  `.spectral_bound`, `.is_stable`), `ManifoldProjectionResult`, `sinkhorn_knopp`.
- **⚠** Its **uniformity collapse is the kept empirical proof** motivating
  `spectral_sphere.py`. The 2 xfail tests are this collapse. Any "fix" goes
  through `spectral_sphere.py`. (DECISIONS.md, AGENTS.md, CLAUDE.md all repeat this.)

### `privacy_accountant.py` — (ε,δ)-DP accounting
- **Surface:** `PrivacyAccountant` (`.required_sigma`, `.spend`, `.assert_budget`,
  `.remaining_epsilon`, `.summary`), `PrivacyBudgetExhausted`.

### `private_vote.py` — commit-reveal private voting
- **Surface:** `PrivateBallotBox` (`.submit_commit`, `.close_commit_phase`,
  `.submit_reveal`, `.tally`), `build_commit`/`build_reveal`/`tally`,
  `compute_nullifier`, `CommitRecord`/`RevealRecord`/`PrivateTally`,
  `BallotChoice`, validity provers (`HashCommitmentProver`, `ZKSnarkProver`
  marker); errors `DoubleVoteError`, `InvalidCommitError`, `InvalidRevealError`,
  `MissingRevealError`.
- **Logic:** commit phase hides votes; reveal phase validates against commits;
  **nullifiers** block double-voting per epoch; tally is deterministic.

### `federated_bridge.py` — cross-org credential gate
- **Surface:** `FederatedConstitutionBridge` (`.register_credential`, `.gate`,
  `.audit_log`, `.summary`), `AgentCredential` (`.fingerprint`, `.is_expired`,
  `.authorised_for`), `FederationDecision`, `CredentialStatus`.

### `mac_acgs_loop.py` — auto-constitution pipeline
- **Surface:** `MacAcgsLoop` (`.run_cycle`, `.add_external_challenger`,
  `.audit_log`, `.constitution_updates`, `.coverage_history`, `.summary`),
  `MacAcgsConfig`, `MacAcgsCycleResult`, `PipelineEvent`/`PipelineEventType`.
- **⚠** Known **import-boundary leak**: line ~43 imports
  `bittensor.came_coordinator` unconditionally (~458ms on every package import).
  Fix is to move it inside the constructing method (see
  `src/constitutional_swarm/AGENTS.md` MANUAL section + RUNTIME_OPTIMIZATION_REPORT B1).

### `forensic_benchmark.py` — blind-review benchmark protocol
- **Surface:** Pydantic models (`ForensicBenchmarkProtocol`, `BenchmarkScorecard`,
  `IncidentSpec`, `BenchmarkArtifactPack`, `BenchmarkResultBundle`, …) +
  `validate_protocol`, `score_reviewer_answers`, `paired_sign_test_p_value`,
  `build_result_bundle`, `generate_incident_specs`, `generate_artifact_pack`.
- **Logic:** the reproducible v0.1 public-study contract — generate adversarial
  incidents with hidden ground truth, collect blind-reviewer answers, score by
  matched condition, gate the success claim with a paired sign test.

### `bench.py` — overhead benchmark
- `SwarmBenchmark` (`.run`, `.scaling_report`), `BenchmarkResult` — measures
  governance overhead at scale.

### `agent_self_evolve.py` — offline self-evolution harnesses
- **Surface:** `discover_agents`, `evaluate_agent`, `build_report`,
  `reference_patterns`, `AgentRecord`, `main` (→ `acgs-agent-self-evolve`).
- **Logic:** builds a deterministic self-evolution harness for every repo agent
  and scores it against source-backed reference patterns. Module promoted from a
  script in PR #77; design learning in
  `docs/solutions/design-patterns/agent-probe-harness-design.md`.

### `eval/monotonic_mas/` — coordination-failure detectors
- **Surface:** `detectors/role.py` (`detect_role` wraps `AgentDNA.validate`),
  `detectors/handoff.py`, `detectors/dedupe.py`, `detectors/semantic.py`
  (cross-encoder, `[semantic]`), `abliteration_detector.py` (`detect_from_weights`,
  `detect_from_activations`, `refusal_direction`, …), `adversarial_robustness.py`
  (perturbation probes), `evaluator.py`/`replay.py` (autoresearch mission H1).

### `swe_bench/` — SWE-bench scaffold
- **Surface:** `SWEBenchAgent.solve` (base) with backends `ClaudeSWEBenchAgent`,
  `ClaudeOAuthSWEBenchAgent`, `CodexSWEBenchAgent`, `GeminiSWEBenchAgent`,
  `VertexClaudeSWEBenchAgent`, `MiniSWEBenchAgent`, `GovernedAgent` (post-hoc
  constitutional wrapper); `SWEBenchHarness`/`LocalSWEBenchHarness` (Docker-less);
  `SwarmCoordinator` (`run_in_memory`/`run_gossip`, MerkleCRDT-coordinated);
  `pickers.py` (best-of-K: `pick_governed_score`, `pick_vote`, …);
  `SWERecoveryController` (recovery plane); `run_one_by_one.py` runner.
- Guide + backend/recovery notes:
  [`swe_bench/AGENTS.md`](../../src/constitutional_swarm/swe_bench/AGENTS.md),
  `docs/internal/swebench_swarm_backend_and_recovery.md`.

---

<a id="scripts"></a>
## `scripts/` (operator & eval CLIs)

Each operator-facing script should have a `tools/registry.yaml` entry (enforced
philosophy; see `TOOLS.md`). Highlights:

| Script | Purpose |
|---|---|
| `agent_check.py` | The agent-operability gate (`make agent-check`). |
| `agent_self_evolve.py` | Backward-compat wrapper for the packaged self-evolve harness. |
| `reproduce_paper_claims.py` | Emit JSON metrics reproducing empirical claims. |
| `run_governance_benchmark.py` | Governance benchmark (offline-deterministic default). |
| `run_swe_bench_lite.py`, `run_swe_bench_swarm_lite.py`, `run_official_swarm_swebench.py`, `run_mc_swarm.py` | SWE-bench runners (need API keys / cost tokens). |
| `eval_trust_convergence.py`, `eval_swe_bench_synthetic.py`, `benchmark_coverage.py` | Eval/measurement scripts. |
| `verify_citations.py`, `verify_governance_receipts.py` | Citation + receipt verification. |
| `generate_security_report.py` | Build `security-audit-report.md` from security tests. |
| `generate_rust_protocol_fixtures.py` | Emit canonical fixtures for the Rust core. |
| `check_typecheck_coverage.py` | Assert every optional extra is type-checked or excepted. |
| `testnet_deploy.py` | Bittensor testnet deploy (`register`/`miner`/`validator`). |
| `finetune_extended_refusal.py`, `convert_swarm_output_to_swebench_predictions.py` | Recipe/finetuning + format conversion. |

Continue to [06 Runtime Flows →](06-runtime-flows.md).
