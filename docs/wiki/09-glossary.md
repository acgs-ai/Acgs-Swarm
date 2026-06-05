# 09 · Glossary — terms & acronyms

[← 08 Handoff](08-handoff.md) · [Wiki home](README.md)

Quick lookup for the vocabulary used across the codebase. Conceptual depth is in
[03-domains](03-domains.md); short definitions in [`docs/concepts.md`](../concepts.md).

| Term | Meaning |
|---|---|
| **ACGS** | Autonomous Constitutional Governance System — the parent program; `acgs-lite` is its single-action governance base that this package extends to societies of agents. |
| **Agent DNA** | The embedded constitutional co-processor (`AgentDNA`) carried by each agent; validates actions locally (~443ns/check). Pattern A. |
| **Abliteration** | Attack that surgically removes a model's refusal direction so it complies with anything. Screened by `node_admission.py`. |
| **BODES** | The residual-stream steering technique in `latent_dna.py` — a forward hook nudges generation away from a learned violation direction. |
| **Birkhoff polytope** | The set of doubly-stochastic matrices. `manifold.py`'s Sinkhorn-Knopp projection targets it; its uniformity collapse is the kept research control. |
| **CID** | Content IDentifier — a SHA-256 hash addressing an immutable node/artifact (`merkle_crdt.py`, `artifact.py`). |
| **Constitution** | The principles/rules (from `acgs-lite`) governing agent behavior; canonical identity hash `608508a9bd224290`. |
| **Constitutional Mesh** | Byzantine-tolerant peer-validation layer with mandatory signed votes (`ConstitutionalMesh`). Pattern C. |
| **CRDT** | Conflict-free Replicated Data Type — `MerkleCRDT` uses set-union merge so gossiping replicas converge. |
| **DAG** | Directed Acyclic Graph of tasks (`TaskDAG`); the unit of orchestrator-free execution. Pattern B. |
| **DNA validation** | The `AgentDNA.validate(text)` check → `DNAValidationResult(valid, violations, risk)`. |
| **DP / (ε,δ)-DP** | Differential Privacy; budget tracked by `privacy_accountant.py`, noise calibrated in `swarm_ode.py`. |
| **DSSE / in-toto** | Supply-chain attestation envelope/statement formats; receipts project onto them via `governance_receipts_dsse.py`. |
| **Drift budget** | Per-amendment cap on how much a constitution may change (`epoch_reconfig.py`); exceeding it → `DriftBudgetExceeded`. |
| **Ed25519** | The signature scheme used for votes, receipts, and evidence bundles. |
| **EvolutionLog** | Append-only SQLite metrics log enforcing strict monotonicity + non-negative acceleration at write time. |
| **FCHP** | Federated Constitution Handshake Protocol — the cross-org credential layer (`federated_bridge.py`). |
| **Governed execution** | Execution where policy checks run in the runtime path, not just post-hoc audit. |
| **Governance receipt** | Canonicalized, hash-linked, independently verifiable record of a governance decision (`governance_receipts.py`). |
| **Joint consensus** | A constitutional amendment must be ratified by *both* the old and new validator sets (`TransitionCertificate`). |
| **LEACE** | Least-squares Concept Erasure — the oblique-whitening method for fitting the violation subspace (`violation_subspace.py`). |
| **MACI** | Minimal Anti-Collusion Infrastructure — informs the private-vote / debate design. Protocol draft: `docs/maci_dp_protocol.md`. |
| **MAP-Elites** | Quality-diversity optimizer used for miner quality (`bittensor/map_elites.py`) and coverage-aware governance (`came_coordinator.py`). |
| **MCFS** | Manifold-Constrained Federated Swarm — the research stack (latent DNA, swarm ODE, Merkle-CRDT, privacy/federation, bittensor, eval). |
| **MeshProof** | Cryptographic proof object attached to a settled `MeshResult`; `verify()` re-checks it. |
| **Nullifier** | A privacy-preserving double-vote tag in `private_vote.py`; a repeat in an epoch → `DoubleVoteError`. |
| **NMC** | The anti-collusion multi-miner commit-reveal deliberation protocol (`bittensor/nmc_protocol.py`). |
| **Precedent** | A validated miner judgment recorded as constitutional case law (`bittensor/precedent_store.py`), retrievable by 7-vector similarity. |
| **Projected RK4** | Runge-Kutta-4 integration that re-projects onto the spectral sphere each step (`swarm_ode.py`). |
| **Quorum certificate** | A bundle of signed votes meeting a weight threshold; conflicting QCs → slashable `ConflictEvidence`. |
| **Settlement** | Durable persistence of a finalized decision (`SettlementStore`) for replay/recovery. |
| **Sinkhorn-Knopp** | Iterative algorithm projecting a non-negative matrix onto the Birkhoff polytope (`manifold.py`). |
| **Spectral sphere** | The production trust-dynamics constraint: `‖H‖₂ ≤ r` via power iteration (`spectral_sphere.py`). Pattern D. |
| **Stigmergy** | Indirect coordination through a shared medium (the `ArtifactStore`) rather than direct commands. Pattern B. |
| **Sybil resistance** | Fault-domain weight caps + VRF committee selection so one entity can't dominate a quorum (`validator_set.py`). |
| **SWE-bench** | The software-engineering benchmark the `swe_bench/` scaffold targets. |
| **TAO** | The Bittensor network token; emissions reward miner quality (`emission_calculator.py`). |
| **TLA+** | The formal spec language; `specs/` models mesh safety and reconfiguration, checked in CI. |
| **Trust matrix (H)** | The agent-to-agent trust state evolved by the manifold/ODE modules and fed back into peer selection. |
| **Verifier-first** | Receipt design where the verifier needs no trust in the producer; everything re-derives from canonical bytes. |
| **Violation subspace** | The rank-`k` direction(s) representing constitutional violations that steering projects against (`violation_subspace.py`). |

[← Back to wiki home](README.md)
