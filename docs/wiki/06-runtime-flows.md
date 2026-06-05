# 06 · Runtime flows — how a governed task actually moves

[← 05 Module Reference](05-module-reference.md) · Next: [07 Roadmap →](07-roadmap.md)

Page 5 describes modules in isolation; this page traces the **end-to-end code
logic** — the sequences that connect them. Each flow names the concrete
functions so you can follow it in the source.

## The canonical pipeline (one view)

```text
Agent call / input
  → AgentDNA.validate(...)              local constitutional enforcement (in the agent path)
  → DAGCompiler.compile + SwarmExecutor orchestrator-free DAG execution
  → ConstitutionalMesh                  peer validation with mandatory signed votes
  → SettlementStore                     durable finalization evidence (JSONL / SQLite)
  → governance_receipts.build/verify    canonicalized, replayable audit trail
  → spectral_sphere / swarm_ode         bounded trust dynamics feed back into peer selection
```

---

## Flow 1 — Local enforcement (the hot path)

The cheapest, most-run path. Every agent action passes through DNA before its
output is trusted.

1. Build a DNA: `AgentDNA.default(agent_id=...)` or `.from_yaml(constitution)`.
2. `result = agent.validate(text)` → `DNAValidationResult(valid, violations, risk)`.
   Runs the constitution's matchers in ~443ns.
3. Caller branches on `result.valid`; `constitutional_dna` can wrap a callable to
   do this automatically. A disabled DNA raises `DNADisabledError`.

**Where it's reused:** `eval/monotonic_mas/detectors/role.py:detect_role`,
`langgraph_runtime/nodes.py:validate_node`, `swe_bench/governed_agent.py`.

---

## Flow 2 — Compile & execute a goal (orchestrator-free)

1. **Compile:** `DAGCompiler().compile(GoalSpec(...))` → `TaskDAG` of `TaskNode`s
   with dependency edges (`compile_from_yaml` for YAML goals).
2. **Load:** `SwarmExecutor().load_dag(dag)`.
3. **Loop (per agent, no coordinator):**
   - `tasks = executor.available_tasks()` (only dependency-ready nodes)
   - `executor.claim(task_id, agent_id)` → a `WorkReceipt`
   - agent does the work, optionally publishing an `Artifact` to the
     `ArtifactStore` (stigmergic signal others can `watch`/`get_by_domain`)
   - `executor.submit(task_id, result)` → DAG marks complete, unlocks dependents
4. Repeat until `executor.is_complete()`; `progress()` reports completion.

**Capability routing:** `CapabilityRegistry.find_best(domain)` picks which agent
claims a node.

---

## Flow 3 — Peer-validated settlement (the governance core)

This is the flow the quickstart in `README.md` demonstrates.

1. **Register signers** (signatures are mandatory):
   `mesh.register_local_signer(agent_id, domain=...)` for each peer (or
   `register_remote_agent(public_key)` for a key-only remote peer).
2. **Request validation:**
   `assignment = mesh.request_validation(producer_id, output, artifact_id)`
   → `PeerAssignment` listing the selected peers. Peer selection is
   **trust-weighted** (`_select_peers`: weighted sampling + one exploration slot),
   so Flow 6's trust matrix steers who validates.
3. **Each peer signs and votes:**
   ```python
   sig = mesh.sign_vote(assignment.assignment_id, voter_id, approved=True, reason=...)
   mesh.submit_vote(assignment.assignment_id, voter_id, approved=True, reason=..., signature=sig)
   ```
   A missing/wrong signature raises `InvalidVoteSignatureError`.
4. **Settle on quorum:** once enough votes arrive,
   `result = mesh.get_result(assignment.assignment_id)` →
   `MeshResult(accepted, quorum_met, settled)` carrying a `MeshProof`
   (`proof.verify()` re-checks it).
5. **Freeze + persist:** a settled assignment is frozen
   (further votes → `AssignmentSettledError`). If a `SettlementStore` is attached,
   the result is appended; a failure after freeze raises
   `SettlementPersistenceError`.

**Crash safety:** the store's two-phase write — `mark_pending` before the freeze,
`clear_pending` only after a durable append. On restart, `load_pending` +
`ReconciliationReport` reconcile in-flight settlements; a durable replay attempt
raises `RecoveredAssignmentError`.

---

## Flow 4 — Remote / gossip validation (`[transport]`)

**Remote one-shot vote:** `RemoteVoteClient.request_vote(...)` →
`RemoteVoteServer` → `LocalRemotePeer.handle_vote_request` validates and signs →
`RemoteVoteResponse`. Nonce reuse inside the replay window raises
`RemoteVoteReplayError`.

**Gossip convergence:** each `SwarmNode` holds a local `MerkleCRDT`;
`gossip_round()` exchanges `DAGNode` batches with sampled peers
(`GossipClient.send_batch` → `GossipServer`), set-union merging into the CRDT.
Replicas converge to the same head set without a coordinator
(`simulate_ws_gossip_convergence`).

---

## Flow 5 — Generate a verifiable governance receipt

1. Build a `ReceiptPayload` (roles, evidence hashes, validator votes).
2. `receipt = build_receipt(payload, ...)` — computes the canonical digest
   (`payload_canonical_bytes` → `payload_digest`) and attaches detached
   `SignatureRecord`s.
3. Bundle receipts → `GovernanceReceiptBundle`; serialize with `bundle_to_json`.
4. **Independent verification:** `verify_bundle(bundle)` re-derives every digest
   and checks signatures with **no trust in the producer** → `VerificationVerdict`.
   CLI: `acgs-verify-receipts bundle.json`.
5. **Supply-chain projection (optional):** `to_dsse_envelope(receipt, DsseSigner)`
   / `to_in_toto_statement(...)` for DSSE / in-toto consumers;
   `verify_dsse_envelope` checks them.

---

## Flow 6 — Trust dynamics feeding back into selection

1. After settlement, reputations update; the trust matrix `H` evolves.
2. **Bounded projection (production):** `SpectralSphereManifold.update_trust(...)`
   →`project()` keeps `‖H‖₂ ≤ r` (power iteration). `is_stable()` /
   `spectral_norm()` report health.
3. **Continuous-time (research):** `swarm_ode.integrate(...)` advances `H` with
   `projected_rk4_step` (re-projecting each step); `add_dp_noise` for DP gossip.
4. The updated trust weights flow back into `mesh._select_peers` (Flow 3 step 2),
   closing the loop — better-trusted peers are sampled more, with one exploration
   slot for discovery.

> **Baseline control:** `manifold.py` runs the same projection with
> Birkhoff/Sinkhorn and **collapses to uniformity** — the kept empirical proof,
> not a path to use in production. (See [03-domains §trust](03-domains.md#trust-dynamics).)

---

## Flow 7 — Governed coding-agent handoff (`acgs-swarm` CLI)

The productized, hardened flow (`governed_handoff.py`).

1. `acgs-swarm run` → `_intake` loads the task + constitution and **fails closed**
   if a declared constitution version/hash ≠ pinned `608508a9bd224290`.
2. An adapter (`MockAdapter` / `ExternalAgentAdapter` for Codex/Claude) proposes
   `Action`s.
3. `PolicyEngine.decide(action)` → `PolicyDecision`. The `tool_call` gate is
   **default-DENY** against `DEFAULT_COMMAND_ALLOWLIST = (python, python3, pytest)`;
   the constitution may extend, never weaken it.
4. Approved actions execute; each step is hash-linked into an audit chain
   (`AuditLogger`, `replay_hashes`).
5. `build_bundle(signer=BundleSigner, constitutional_version=...)` Ed25519-signs a
   domain-separated attestation (`BUNDLE_SIG_DOMAIN`) binding chain_hash +
   constitution_hash + version pin + final_state + task identity.
6. `acgs-swarm verify --trusted-key KEYID=HEX` →
   `verify_bundle(..., trusted_public_keys=...)` **requires** a valid signature for
   `ok`; trust derives only from the out-of-band key, never the embedded one.
   With no anchor, it still returns `ok` on chain-consistency and reports
   `signed: false` honestly.

---

## Flow 8 — Constitutional amendment (joint consensus)

1. Propose: `AmendmentProposal(prior, proposed, to_epoch)`; `drift = .drift` is the
   symmetric-difference rule count (`evaluate_drift`).
2. Gate drift: must fit the declared `DriftBudget` else `DriftBudgetExceeded`.
3. Ratify under **joint consensus**: a `TransitionCertificate` needs *both* the
   old and new validator sets to ratify; `verify_transition(...)` enforces epoch
   match (`EpochMismatchError`) and joint quorum (`JointQuorumNotMetError`).
4. On success, the new `ConstitutionVersion` (`.digest`) becomes active; the
   bittensor layer distributes it via `constitution_sync.py`.
- **Formal model:** `specs/constitution_reconfig.tla` (checked by `tla-check` CI).

---

## Flow 9 — Node admission before quorum (anti-abliteration)

1. Collect probes per candidate validator (`ActivationProbe` /
   `RefusalDirectionProbe`, or write matrices).
2. A gate screens them: `AbliterationAdmissionGate.select_admissible(...)` /
   `ActivationAdmissionGate` / `RefusalDistributionGate` →
   `AdmissionDecision` (`.rejected_set`).
3. Detection math lives in `eval/monotonic_mas/abliteration_detector.py`
   (`refusal_direction`, `weight_refusal_energy`, `latent_separation`,
   `refusal_distribution_score`).
4. `byzantine_census.census_from_decisions(...)` aggregates the decisions into a
   swarm-level tampered-fraction estimate + Byzantine-safety verdict.

Continue to [07 Roadmap →](07-roadmap.md).
