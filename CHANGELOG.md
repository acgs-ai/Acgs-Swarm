# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

Security-fix campaign (batches C1–C48, C25b, C35b, C42b, C51a, C51b). Verifiers now take
their trust anchors (keys, roots, rosters, thresholds) from their own
configuration rather than from the object they verify, and insecure modes need
an explicit opt-in. Many changes are breaking: read **Migration** first.
Rationale for each batch is in `DECISIONS.md`. These notes cover the campaign
only. They do not cover the APCC-1 / GCB feature work that also landed after
1.1.0.

> **Breaking, data: APCC SQLite and PostgreSQL authority stores written before
> C32 may not reopen.** C32 changed how non-decision audit and event ids are
> encoded (stage, candidate, `EVIDENCE_ASSEMBLED`/`COMMIT_PENDING`, revoke,
> replace, outbox, outbox-delivered, missing, recovery-missing) to a framed,
> length-prefixed digest. The PostgreSQL store imports the same id function and
> semantic validator from the SQLite store. C32 did **not** bump the authority
> schema version, which both backends still write as `3`. A v3 store containing
> such rows written by pre-C32 code fails to open with a generic error, not
> with the explicit "schema version is incompatible" error:
> - SQLite: `ValueError: APCC SQLite store semantic validation failed`
> - PostgreSQL: `ValueError: APCC authority store semantic validation failed`
>
> There is no in-place migration. Rebuild affected stores, or wait for the deferred schema
> v4 bump, which needs the PostgreSQL 17 GCB catalog fingerprint
> (`_POSTGRES_GCB_CATALOG_FINGERPRINT`) regenerated in the same change. Until
> v4 lands, do not run mixed-version writers against one store.

### Security
- **Consensus and certificates.** `quorum_certificate`, `epoch_reconfig` and
  `bittensor/constitution_sync` verify against verifier-owned policy and
  registry-pinned keys. Certificates can no longer choose their own threshold,
  drift budget or registry. QC vote signatures bind `voter_id`, so one key can
  no longer vouch for every ID that shares it. `ValidatorSet` refuses silent
  re-keying, and node admission is fail-closed for validators that were not
  admitted.
- **Mesh and vote evidence.** Vote envelopes sign the assigned electorate and,
  from protocol v3, the digest of a signed assignment issued by a trusted
  assigner. Consumers require every assigned vote and recompute the outcome.
  Assigner, voter, producer and settlement-signer roles must be distinct. Trust
  objects are rebuilt from raw bytes, and registry subclasses are rejected.
  Malformed or legacy persisted settlements are quarantined rather than
  trusted. The signed-envelope cache holds only assigned voters on open
  assignments.
- **Assignment authority (C48).** Settlement recovery,
  `ConstitutionalValidator` and `PrecedentCascade` (when it holds a mesh)
  verify assignments only against `ConstitutionalMesh.assigner_trust_root`
  plus the pinned assigner id and key, never against the live
  `vote_registry`. `assigner_trust_root` now holds only the pinned assigner
  grant rather than a snapshot of the live registry. A mesh built by
  `rotate_constitution` therefore cannot inherit a late-registered assigner,
  and `receipt_trust_registry()` exports only the pinned assigner as its
  assigner grant (validator and settlement-key grants are still exported).
- **Remote-vote replay window (C29, C48).** In both the mesh core and
  `LocalRemotePeer`, a nonce is checked and recorded only after the request
  signature verifies, expires at `max(now, timestamp) + W`, and is swept from
  the whole cache. Eviction uses `expires_at < now`, so a replay at exactly
  `timestamp + W` is still rejected and a badly signed request cannot probe
  the cache.
- **Transport.** Gossip and remote voting require TLS off loopback, never send
  the shared token in plaintext, compare tokens in constant time, and bound
  anti-entropy. `RemoteVoteClient` rejects TLS contexts without
  `CERT_REQUIRED` and `check_hostname`.
- **Governed handoff.** The `tool_call` gate is a closed, code-owned
  `SAFE_COMMANDS` table. Signing keys come from a private key file and are
  never inherited by child processes, and the supervisor is made non-dumpable
  on every launch, with a read-back check. Evidence files are created
  exclusively, and handoff v2 bundles need an external trust anchor. The
  external agent command is resolved on the fixed PATH (C51a), and system
  directories come before `/usr/local/bin`.
- **Governance receipts and settlement.** Contradictory tallies, duplicate
  identities, role downgrades and unsigned report-mode results fail closed.
  DSSE accepts only the in-toto payload type and canonical base64. Fixture or
  publicly derivable keys are labelled `development`, never `proof_grade`.
  Settlement file locking fails closed.
- **Governance gates.** `govern` enforces its result. Federated credentials
  must be signed by issuer keys pinned at bridge construction. Debate roles
  come from a pinned registry. The MAC-ACGS loop cannot approve its own rules.
  The constitution-transition and evolution-log write paths cannot be bypassed.
- **Bittensor.**
  - Miner responses are authenticated and bound to all 11 request fields
    (response protocol v2), and the axon runs bittensor's own `default_verify`.
  - Precedent admission requires at least 3 approvals out of at least 5 votes,
    plus a strict majority.
  - NMC commitments are bound to `(session_id, case_id, miner_uid)`.
  - Rule codification separates proposer and governor duties.
  - Emissions, tiers, certificates and audit batches fail closed.
  - Audit logs and chain anchors use a count-committed RFC 6962-style Merkle
    tree with caller-pinned roots.
- **APCC.**
  - Observations are verified against the caller's own request.
  - The strict JSON parser is used throughout, and GCB numeric fields are
    compared by canonical bytes.
  - Stores refuse version-mismatched stages and foreign-workflow certificate
    revocations, and enforce a plain-ID grammar on request ids.
  - B4/B5 empirical adapters pin their trust roots, and the B5 journal MAC
    uses a dedicated secret.
  - The authority supervisor pins observer-launch expectations, and the
    privileged child sends only stable error codes.
- **Privacy and DP.**
  - Private ballots are voter-bound, need an enrolled key, and default to
    strict proof checking.
  - DP sensitivity is corrected to `2·r·√n` with RDP-inverted sigma.
  - Unseeded noise uses fresh entropy, and sampler child seeds use a
    full-width KDF.
  - NaN RDP no longer clamps to zero.
- **Evaluation and SWE-bench.**
  - The local harness applies the official `test_patch` and needs JUnit
    evidence.
  - Subprocesses get a minimal environment and are killed as a process group.
  - Governance and evaluation share one detector entry point. Its
    normalization covers NFKC, confusables, camelCase and leetspeak, and
    (C51b) accent folding and blank-filler characters.
  - (C51b) Instance ids are allowlisted before they reach paths or harness
    argv.
  - (C51a) LangGraph streaming appends only the exact patch that the
    validator checked and the settle node accepted.
  - A hunk-only diff is not accepted as a patch.
  - Forensic benchmark packs are committed before collection.
  - Benchmark CLIs parse JSON strictly, and TLC runners execute a hashed
    private copy of the jar.
- **Shared helpers.** New `strict_json`, `framing` (`framed_digest`,
  `require_plain_id`) and `secure_files` (`private_file`) modules give one
  policy for parsing, framed digests and private-file reads.

### Changed
Signatures, defaults and wire formats. Entries marked **Breaking** need caller
or data changes.

- **Mesh.**
  - **Breaking:** vote evidence and remote requests are protocol v3 and bind a
    signed assignment v1 from a trusted assigner. v1, v2, unsigned and
    aggregate live evidence is rejected.
  - **Breaking:** `sign_vote_envelope` requires the assigned roster and quorum.
    Externally supplied registries need `assigner_id` and
    `assigner_private_key`.
  - `sign_vote` / `sign_vote_envelope` raise `AssignmentSettledError`,
    `RecoveredAssignmentError` or `UnauthorizedVoterError`.
  - **Breaking:** `MeshProof.verify()` returns `False` for v1 proofs unless
    called with `allow_legacy_v1=True`.
  - `ConstitutionalMesh(complete_evidence=...)` is deprecated and does nothing.
  - New `ConstitutionalMesh.assigner_trust_root` (only the pinned assigner
    grant), `assigner_key_id`, `quarantined_settlements`, and `summary()`
    quarantine fields. Construction logs and skips bad stored settlements
    instead of raising.
  - **Breaking:** mesh key coercion (`register_remote_agent(vote_public_key=...)`,
    `register_local_signer(vote_private_key=...)` and the constructor key
    arguments) delegates to `vote_envelope.public_key_from` /
    `private_key_from`. Hex must be exact lowercase with no whitespace or
    newline (`ValueError`). `str` subclasses are rejected for private keys,
    and `bytearray` raises `TypeError`.
  - `submit_vote_envelope` runs the admission checks (halted, settled,
    recovered, stale constitution, assigned, registered) before signature
    verification, so an invalid envelope for a settled or halted assignment
    raises the admission error instead of `ValueError`. Each submitted
    envelope is verified once.
  - `verify_remote_vote_request(nonce_cache=...)` stores expiry times
    (`max(now, timestamp) + W`) as cache values instead of receipt times.
  - `PeerAssignment` gains a derived `signed_assignment_digest` field. It is
    not an `__init__` argument and is excluded from equality and repr.
  - Performance: the pending-assignment count is an O(1) counter, and the
    stale-assignment scan runs only after `rotate_constitution` or an observed
    hash mismatch. Reconcile reads the durable store once per pass, and
    settlement writes look up one record by id instead of rebuilding the
    receipt index.
  - `verify_assignment_vote_envelopes` accepts `assigner_trust_root`,
    `expected_assigner_id` and `expected_assigner_key_id`.
  - `vote_envelope` exports `public_key_from`, `private_key_from` and
    `content_hash`.
  - **Breaking:** `LocalRemotePeer` rejects non-canonical key hex and request
    subclasses, and takes `clock=`.
- **QC votes.**
  - **Breaking:** QC votes must sign
    `build_vote_message_v2(assignment_id, artifact_hash, epoch, voter_id)`, and
    `SignedVote.message()` returns v2. v1 votes are accepted only with
    `CertificateVerificationPolicy(allow_legacy_v1=True)`.
  - **Breaking:** partial-committee selections differ from earlier releases;
    full-set committees are unchanged.
  - **Breaking:** `ValidatorSet.add(v, *, replace=False, rekey=False)` raises
    on an existing ID.
  - `build_vote_message_v2`, `CertificateVerificationPolicy` and
    `TransitionVerificationPolicy` are now importable from
    `constitutional_swarm` through the lazy namespace. They are not part of
    the frozen `__all__` façade.
- **Transitions and sync.**
  - **Breaking:** transition certificates use the
    `constitutional-transition-v3` subject, and existing certificates need
    re-ratification. `CertificateVerificationPolicy` and
    `TransitionVerificationPolicy` own the thresholds.
  - **Breaking:** `ConstitutionDistributor` requires an Ed25519 signing key, and
    `allow_unsigned` is removed. The sync wire is v2, and v1 needs
    `allow_legacy_v1=True`.
  - **Breaking:** `verify_task_hash` takes only the full 64-hex digest.
- **Governance gates.**
  - **Breaking:** `govern(fn=None, *, action_type=None, block_on_violation=True,
    block_on_warnings=False)` raises `ConstitutionalViolationError` on an
    invalid result or a verified Z3 counterexample. `constitutional_dna` takes
    the same keywords. WARN matches are logged and counted in
    `stats["warnings"]`.
  - **Breaking:** a DNA with a `maci_role` needs `action_type`.
  - **Breaking:** `FederatedConstitutionBridge(issuer_keys=...)` is needed to
    register credentials. `AgentCredential.expires_at` is required and
    `issuer_signature` must verify. `gate()` and `revoke()` require `org_id`,
    and empty `domains` deny (use `ALL_DOMAINS`).
  - **Breaking:** `DebateResolver(participants=...)` is required for any
    challenge to count.
  - **Breaking:** `MacAcgsConfig.auto_challenge` and `auto_defend` default to
    `False`.
  - Debate seals are v2.
- **Governed handoff.**
  - **Breaking:** only `true` (no arguments) and `echo` (plain words) can run.
    `command_allowlist` selects from `SAFE_COMMANDS` and can no longer add
    commands:
    - a list, tuple or set narrows the table (unknown names are ignored, and
      an empty one enables nothing);
    - a non-sequence value, such as a string, enables nothing;
    - an absent or null value enables the whole table.
  - **Breaking:** `tool_call` executables must be bare names.
  - **Breaking (C51a):** `ExternalAgentAdapter` resolves its command's
    `argv[0]` on `FIXED_SUBPROCESS_PATH` or requires an absolute path. These
    raise `RuntimeError` before any child starts:
    - a relative command (`./agent`);
    - an empty or whitespace-only command, which used to run the task file
      itself;
    - an unparseable command;
    - a command that does not resolve.
  - `FIXED_SUBPROCESS_PATH` is now `/usr/bin:/bin:/usr/local/bin`, so
    `/usr/local/bin` can no longer shadow system tools.
  - **Breaking:** a repeated task id or `pack` over an existing bundle raises
    `FileExistsError`.
  - `ACGS_SIGNING_KEY_FILE` is preferred and `ACGS_SIGNING_KEY` is deprecated.
  - Removed `DENIED_INTERPRETER_COMMANDS`; added `SAFE_COMMANDS` and
    `SafeCommandSpec`.
- **Receipts and settlement.**
  - **Breaking:** receipt decisions must match their tallies.
  - **Breaking:** settlement signers cannot also be voters, the assigner or
    the producer.
  - New `verify_bundle(..., require_proof_grade=...)` and
    `acgs-verify-receipts --require-proof-grade`.
  - `verify_dsse_envelope` returns structured `invalid` instead of raising.
  - **Breaking (platform):** without `fcntl` or `msvcrt`, settlement stores
    raise `SettlementLockUnavailableError`.
  - New `exclusive_file_lock` and `lookup_settlement`.
- **Bittensor.**
  - **Breaking:** `MinerAxonServer` needs `response_signing_key=` (or the
    dev-only `allow_unsigned_responses=True`) and must be attached with
    `server.attach_to(axon)`.
  - `constitutional_swarm.bittensor` now exports `authenticate_response`,
    `verify_axon_response_signature` and `request_binding_digest`.
  - **Breaking:** the testnet `miner` needs `--trusted-validators`, and the
    testnet validator needs `--authority-keys` (an owner-only file) and
    public-only `--authorized-voters`.
  - **Breaking:** `AnchorRecord.verify_membership(proof, *, expected_root)`
    requires a caller-pinned root. `AuditBatch.verify_entry()` requires
    `expected_root` and `expected_batch_id`, and `verify_merkle_path()`
    requires `leaf_count` and `leaf_index`.
  - **Breaking:** `AuditLogEntry.from_dict` and `AuditBatch.from_dict` reject
    unknown and missing keys.
  - **Breaking:** audit leaves and Merkle roots are v2, and pre-C35 roots do not
    verify.
  - **Breaking:** `compute_commitment_hash(..., *, session_id, case_id,
    miner_uid)`, and NMC sessions need a non-empty `required_miners`.
  - **Breaking:** `RuleCodifier(governors=..., proposer_id=...)`, and
    approve/activate/reject/revoke take `governor=`.
  - **Breaking:** `BayesianThresholdUpdater(precedent_store=...)`.
  - **Breaking:** `finalize_case` votes must cover the recorded selection
    exactly, and `register_validator` rejects duplicates.
  - **Breaking:** `CertificateIssuer` needs a cert-scoped prover;
    `ZKPStubProver` needs `allow_insecure_stub=True`.
  - **Breaking:** `EmissionCalculator.compute` needs `registered_miners` or
    `allow_unregistered=True`.
  - **Breaking:** `TierManager.register_miner(initial_tier=...)` above
    APPRENTICE needs `admin_override=True`, and `record_precedent(miner_uid,
    precedent_id)`.
  - **Breaking:** removed inert fields; passing any of them raises
    `TypeError`:
    - `ValidatorConfig.authenticity_detection`
    - `ValidatorConfig.reputation_decay_rate`
    - `SubnetMetrics.avg_judgment_time_seconds`
    - `SubnetMetrics.active_validators`
    - `SubnetMetrics.manifold_spectral_bound`
    - `ValidationSynapse.authenticity_score`
  - **Breaking:** removed `ConstitutionalMiner.record_acceptance` and
    `record_rejection`.
- **Private voting and DP.**
  - **Breaking:** `tally()` and `PrivateBallotBox` need `eligible_voters` and
    default to `strict_v2=True`. The hash-scaffold prover needs
    `allow_insecure_hash_prover=True`.
  - **Breaking:** `compute_nullifier(*, voter_pub, epoch, subject)`.
  - **Breaking:** commit, nullifier and signature wire formats are v2.
  - **Breaking:** `swarm_ode.calibrate_sigma(*, certified_spectral_bound,
    matrix_dimension, epsilon, delta)`, and returned sigmas change.
  - **Breaking:** `DiscreteGaussianSampler` streams differ from earlier
    releases.
  - **Breaking:** `swarm_ode.integrate(crdt=...)` records
    `bodes_passed=False`.
- **Gossip.**
  - **Breaking:** `GossipServer`, `GossipClient` and `SwarmNode` take
    `transport_security` (`"auto"` by default). Under `auto` a non-loopback
    host needs TLS material, and the client must ACK.
- **APCC.**
  - **Breaking:** `verify_authority_observation` and
    `AuthorityObservationVerificationStream.consume` require keyword-only
    `expected_request`, and `VerifiedAuthorityObservation` gains
    `request_digest`.
  - **Breaking:** removed the `apcc.codec` observation delegates; import them
    from `apcc.observation`.
  - B5 `ADAPTER_VERSION` is `gcb1-subprocess-v2`, and old B5 state must be
    recreated.
  - **Breaking:** the authority child requires distinct role keys and an
    explicit policy version, and `KeySourceRef(kind=...)` accepts only `"file"`
    or `"consumed"`.
  - `TrustedGovernanceBootstrap` raises `authority_anchor_mismatch` for seals
    that do not match its config, and `governed_commit.sign_control_command`
    is removed.
  - See the store note at the top of this section.
- **Evaluation.**
  - **Breaking:** monotonic-MAS `EVALUATION_VERSION` is 4; start new run ids.
  - **Breaking:** `AbliterationAdmissionGate(reference={})` raises.
  - **Breaking:** `EvolutionLog.admit()` is read-only.
  - **Breaking:** forensic packs are `acgs-forensic-pack-v5` and must be
    regenerated. `IncidentSpec` and `generate_incident_specs` are removed; use
    `generate_artifact_pack()`.
  - `spectral_sphere_project` and `replace_raw_trust` raise on non-finite or
    unbounded input.
  - `LatentDNAWrapper.enable()` checks the declared hidden width.
  - (C51b) The normalized matching pass decomposes (NFKD), drops combining
    marks and format characters, then recomposes (NFC), so accented keywords
    such as `dísáble` are caught. Visibly blank fillers (U+115F, U+1160,
    U+3164, U+FFA0, U+2800) become spaces, and zero-width characters are
    still deleted.
  - (C51b) ROLE-004 matches `rm` recursive and force flags in any order
    (`-fr`, `-Rf`, `-r -f`, long options) using bounded patterns only.
    `farm -fr` is a known benign catch.
  - (C51b) The MCFS rule-set hash changes from `4b9636ce4710779f` to
    `ebcb7caa26e6abfb`. The project constitutional hash `608508a9bd224290` is
    unchanged.
- **SWE-bench.**
  - **Breaking (C51b):** instance ids must match
    `[A-Za-z0-9][A-Za-z0-9._-]*`, checked in `run_one_by_one` and in the
    official runner's `load_instance_ids` before an id reaches a path or the
    harness argv. Path components reject a leading `-`.
  - **Breaking:** local evaluation needs the official `test_patch` and JUnit
    evidence.
  - Generation summaries report `patch_generated` and `patch_rate`;
    `resolved` and `resolve_rate` remain as deprecated aliases.
  - `GovernedAgent(semantic=False)` adds normalized-pass metadata.
  - CRDT `bodes_passed` is true only for accepted patches.
  - `run_one`, `run_swarm_batch` and `run_best_of_k_batch` take `run_root=`.
    Without it, library calls use a private temp root.
  - `scripts/run_mc_swarm.py` labels results `pass@k`.
  - (C51b) `scripts/run_mc_swarm.py` changes:
    - it uses the shared `build_swe_bench_prompt`, so the MC prompt now
      includes hints and headers;
    - it reports evaluated and unevaluated candidate counts;
    - it adds patch and apply `@k` metric labels (existing keys are unchanged);
    - it requires `--agents >= 1`.
- **LangGraph.**
  - **Breaking:** graph builders need a pinned `dna.hash`.
  - **Breaking:** custom graphs must emit clean validation evidence and
    `governance_status="accepted"` from the settle node.
  - Error labels are a closed set (`governance_rejected`, `governance_halted`,
    `governance_incomplete`, `invalid_patch`).
  - (C51a) `stream_to_crdt` appends at most once, after the stream ends. It
    appends only if the final patch equals both the patch the validate node
    checked and the patch the settle node read when it accepted.
  - (C51a) Each update is bound to the input state its task read, so a
    same-step sibling cannot attach evidence or acceptance to another patch.
  - (C51a) Nothing is appended in these cases:
    - the caller breaks early, calls `aclose()`, or an exception occurs
      mid-stream;
    - a cached or replayed updates chunk arrives;
    - a task starts without a result event.
  - (C51a) Non-dict (pydantic or dataclass) state is supported.
- **Core.**
  - `CapabilityRegistry` is thread-safe, and `find_best(domain=...)` returns
    `None` when nothing in the domain matches.
  - `discover_agents` raises on duplicate names.
- **Build.**
  - Make gates fail closed unless the locked venv is exact (run `make setup`).
  - Ruff is pinned to 0.15.12.
  - Publishing grants OIDC only to the publish job.

### Fixed
- The APCC store no longer bricks itself on a fresh-attempt `stage_result`
  whose expected version differs from the node version. It now raises
  `STAGED_RESULT_CONFLICT` and writes nothing.
- Governed commit: a denied control command no longer commits partial writes,
  and `REVOKE_ROOT` no longer commits outside the transaction.
- `load_pending` no longer races `clear_pending`. Settlement lookups no longer
  leak connections or rescan the whole store.
- `sign_vote_envelope` no longer raises `KeyError` when a cache purge races it.
- Emission caps conserve mass, NaN and bool inputs are rejected, and tier
  snapshots are detached.
- `PrivateBallotBox(provers=None)` no longer fails on `dict(None)`.
- Duplicate implementations were folded into one shared copy each: diff
  extraction, Messages-API agents, `workflow_bindings`, Merkle code,
  admission gates, and strict-JSON hooks.
- `tests/test_c15_forensic_commitment_hardening.py` no longer pins a foreign
  worktree path.

### Migration
- **APCC stores:** see the note at the top of this section.
- **Regenerate** stored or signed artifacts in any of the formats that changed
  above:
  - private-vote commits and reveals;
  - handoff v1 bundles;
  - governance-receipt fixtures;
  - debate seals;
  - v1/v2 mesh vote evidence and missing-assignment evidence;
  - transition v2 certificates;
  - forensic packs (v5);
  - monotonic-MAS runs (v4);
  - audit-log batches (leaf and Merkle v2);
  - B5 state.
- **Coordinate wire rollouts** for:
  - mesh protocol v3;
  - QC vote message v2;
  - constitution-sync v2;
  - bittensor response protocol v2;
  - gossip anti-entropy and TLS.
- **Provision trust anchors:**
  - assigner and request-signing keys (`--authority-keys`);
  - public voter grants;
  - trusted validator hotkeys;
  - federated issuer keys;
  - debate participants;
  - rule-codifier governors;
  - an `ACGS_SIGNING_KEY_FILE`.
- **Explicit opt-ins** keep the old permissive behaviour. Use them only for
  development:
  - `allow_legacy_v1`;
  - `strict_v2=False` and `allow_insecure_hash_prover`;
  - `allow_unsigned_responses`;
  - `allow_insecure_stub`;
  - `allow_unregistered`;
  - `admin_override`;
  - `block_on_violation=False`;
  - `single_operator_dev`.

## [1.1.0] - 2026-08-16

Import-star and optional-dependency break relative to 1.0.0. See
`docs/API_COMPATIBILITY.md` and `MIGRATION.md`. This metadata cut does
not publish to PyPI; `publish.yml` runs only after a GitHub Release.

### Fixed
- Declare `jsonschema` and `pyyaml` on the `[dev]` extra so
  `make agent-check` / CI agent-operability can import
  `scripts/agent_check.py` after `numpy`/`braintrust` left the default
  extra graph.
- Concurrent `full_validation` thread-safety test retries
  `MeshSnapshotStaleError`. Reputation settlement is supposed to
  invalidate in-flight routing snapshots; zero stale errors is not
  part of the contract.

### Changed
- Default `import constitutional_swarm` now eager-loads only the governance
  runtime surface (AgentDNA, DAG/executor, ConstitutionalMesh, settlement
  stores, v0.1 receipts). Research, Bittensor, LangGraph, eval, and benchmark
  symbols remain available via lazy `__getattr__` or explicit submodule
  imports. `from constitutional_swarm import *` is now the stable façade
  only — an intentional import-star compatibility break. `MeshSnapshotStaleError`
  is part of that façade. See `docs/API_COMPATIBILITY.md`.
- Mesh settlement receipts now bind `action` / `decision` / policy and content
  hashes to the committed settlement, persist pending votes for crash recovery,
  and treat a receipt as completed evidence only when a settlement points at
  its payload digest.
- `braintrust` is an optional extra (`[braintrust]`), not a core dependency.
- `numpy` is no longer a core runtime dependency; it ships with `[dev]` and
  `[research]`.
- Paper-claim registry statuses are now `measured` / `formula` / `non_claim` /
  `withdrawn`. Withdrawn 2656% and hardcoded latency pins no longer count as
  reproduction passes.

### Added
- Isolated-wheel packaging gate: `scripts/verify_isolated_wheel.py` /
  `make verify-wheel` installs the built wheel into a blank venv.
- `acgs-verify-receipts --settlement-store --assignment-id` starts
  verification from a committed settlement pointer.
- SQLite settlements persist a nullable `receipt_digest` pointer with
  idempotent migration of older databases.
- Agent self-evolution harness: `constitutional_swarm.agent_self_evolve` / `acgs-agent-self-evolve` discovers every operational agent manifest and vendored persona template, emits offline per-agent mutation scopes/guardrails/probes/suggestions, and is wired through `make agent-self-evolve`, `tools/registry.yaml`, a script wrapper, and a runbook.
- Byzantine tamper-fraction census: `byzantine_census.estimate_tampered_fraction`
  turns a screened sample (`n_screened`, `n_tampered`) into a point estimate plus a
  two-sided confidence interval (Wilson score or exact Clopper-Pearson — pure
  NumPy/stdlib, no scipy) and a verdict against the `1/3` Byzantine bound
  (`"safe"` / `"violated"` / `"inconclusive"`). `census_from_decisions` pools
  abliteration admission decisions (dedup by agent) and refuses to count a
  `RefusalDistributionReport` `fragile` flag (a trust signal, not a tamper verdict).
  Bounds the *detectable* tampered fraction over *screened* nodes — `"safe"` is
  necessary, not sufficient; closing the adversarial-self-report gap needs remote
  attestation (out of the pure-NumPy core). Addresses the Byzantine-accounting gap in
  `docs/internal/abliteration_threat_model.md`.
- Refusal-distribution node admission: `node_admission.RefusalDistributionGate`
  screens candidate validators on the *distribution* axis — flagging a node whose
  refusal is single-direction (`refusal_distribution_score` below a configurable
  `min_distribution`) so a trusted committee can prefer extended-refusal-hardened
  nodes. Same `screen()` / `select_admissible()` surface as the abliteration gates,
  feeding the same `CommitteeSelector.select(exclude=...)` path. Candidates are passed
  as `RefusalDirectionProbe(directions, write_matrices=None)`. The flag is a trust
  signal, not a tamper verdict — its report uses the field name `fragile`, so callers
  may down-weight rather than exclude. (`AdmissionDecision` is now generic over its
  report type.) Closes the activation-/weight-path admission follow-up in
  `docs/internal/abliteration_threat_model.md`.
- Extended-refusal fine-tuning defense-in-depth (Option A — recipe + CI-safe
  measurement). `abliteration_detector.refusal_distribution_score(directions, *,
  write_matrices=None)` measures how *distributed* a model's refusal representation is
  (`~0` = single-direction/abliteration-fragile, `~1` = spread across many directions/
  extended-refusal hardened, arXiv:2505.19056) via the normalized participation ratio of
  a set of extracted refusal directions, optionally weighted by surviving refusal-writing
  energy across write matrices. Pure-NumPy, deterministic, no torch. Ships with an
  operator recipe (`docs/recipes/extended_refusal_finetuning.md`) and a
  `[research,finetune]`-gated, test-matrix-excluded reference driver
  (`scripts/finetune_extended_refusal.py`) for the actual fine-tuning, plus an opt-in
  `finetune` extra (`trl`, `peft`). The library *measures* the outcome; producing
  hardened weights remains a trusted-node operator action. Closes the last open
  follow-up (#2, *shipped-with-scope*) in `docs/internal/abliteration_threat_model.md`.
- Abliteration-hardened steering: `violation_subspace.ViolationSubspace` gained
  `orthogonalize_against(r_hat)` and `refusal_alignment(r_hat)`. The former projects
  the refusal direction `r̂` out of the governance steering subspace so the steering
  edit in the original residual space is orthogonal to `r̂` and survives abliteration
  (which only zeros write matrices along `r̂`); it handles the plain (RepE/mean-diff)
  and LEACE regimes (deflation computed in `r̃ = dewhitener @ r̂` space for LEACE) and
  multi-directional refusal sets. The latter reports the fraction of `r̂` captured by
  the subspace (∈ `[0, 1]`) to quantify exposure and verify the fix. A subspace lying
  entirely within the refusal span raises (must be refit, not hardened). Pure-NumPy,
  CI-safe; closes the "harden steering" follow-up in
  `docs/internal/abliteration_threat_model.md`.
- Static type-checking with mypy (closes BLOCKERS.md B3): `[tool.mypy]` config in
  `pyproject.toml` (`ignore_missing_imports`, with an adoption baseline that
  allow-lists modules carrying pre-existing type errors so the rest of the package
  — including new code — is checked and protected from regressions). `make
  typecheck` now runs `mypy` (was a ruff stand-in) and is part of `make verify`; a
  `typecheck` CI job gates PRs. `mypy>=1.11` added to the `dev` extra.
- Abliteration-aware quorum admission: `node_admission.AbliterationAdmissionGate`
  screens candidate validators' residual-stream write matrices with the
  abliteration detector and feeds the rejected agent ids into
  `CommitteeSelector.select(exclude=...)`, so an abliterated model cannot be
  sampled into a committee. Defaults to the `min` aggregation preset (flags if any
  single write matrix collapses), closing the minority-subset evasion the `median`
  default misses. `screen()` returns per-agent `AbliterationReport`s for the
  down-weight-instead-of-exclude alternative; `select_admissible()` is a one-call
  screen-then-select wrapper supporting the fault-domain-independent path.
  Exported as `AbliterationAdmissionGate` / `AdmissionDecision`.
- Activation-path admission: `node_admission.ActivationAdmissionGate` screens nodes
  that expose final-hidden-state activations but not write matrices, via
  `detect_from_activations` (harmful/benign separation-collapse vs. a trusted
  reference). Candidates are passed as `ActivationProbe(harmful, harmless)`; the
  `screen()` / `select_admissible()` surface matches the weight gate, so either
  modality feeds the same `CommitteeSelector.select(exclude=...)` path. Exported as
  `ActivationAdmissionGate` / `ActivationProbe`.
- `detect_from_weights` gained a configurable `aggregate` parameter
  (`"median"` default | `"mean"` | `"min"` | `"quantile"` with a `quantile` knob)
  so callers can trade robustness for minority-subset sensitivity.
- Agent-operability layer: a `Makefile` with one-command targets (`setup`, `dev`,
  `test`, `lint`, `typecheck`, `smoke`, `verify`, `agent-check`); a tool registry
  (`tools/registry.yaml` + JSON schema + runbooks) and agent registry
  (`agents/*.agent.yaml` + schema) for `researcher`/`coder`/`reviewer`/`qa`/`docs`/`release`;
  a `scripts/agent_check.py` self-validation gate wired into a new
  `agent-check` CI workflow; root entry-point docs (`ARCHITECTURE`, `PROJECT_MAP`,
  `TOOLS`, `TASKS`, `DECISIONS`, `BLOCKERS`); and `.env.example`.
- Standalone setup path documented (`uv sync --no-sources`) so a non-monorepo
  checkout resolves `acgs-lite` from PyPI.

### Fixed
- Type-checking: graduated the stable-core modules to a clean mypy pass and
  removed their `[[tool.mypy.overrides]]` allow-list entry, so they are now
  enforced. Fixes are annotation-only / behavior-preserving: `compiler` (cast the
  post-init-normalized `GoalSpec.steps`; `GoalSpec.steps` widened to a covariant
  `Sequence`), `dna` (`_stats_lock` declared as an `init=False` field), `mesh.core`
  (typed optional `RemoteVoteClient` import; cast the spectral shadow manifold),
  `governance_receipts` (`Final` literal constants), `governed_handoff`
  (narrowing + a renamed local), `private_vote` (corrected `# type: ignore` code),
  `protocol` (guard `asdict` against dataclass *types*), `remote_vote_transport`
  (`inspect.isawaitable` narrowing).
- Type-checking: graduated the remaining optional-dependency-gated subpackages
  (`bittensor`, `langgraph_runtime`, `swe_bench`, `latent_dna`,
  `eval.monotonic_mas.evaluator`) and **removed the adoption allow-list entirely**
  — the whole package is now enforced. The acgs-lite `valid-type` /
  `object-not-callable` noise (no `py.typed`) is handled package-wide by a single
  `follow_imports = "skip"` override on `acgs_lite.*`, which also makes the gate
  robust to acgs-lite version drift between the local workspace build and CI's
  PyPI wheel. Remaining fixes were annotation-only / behavior-preserving:
  `_HFModelLike` protocol gained `eval`/`__call__`; import-or-stub fallbacks in
  `langgraph_runtime` annotated to match their real signatures; a `partial`
  replaced a loop-capture lambda; `SwarmGraphState` casts on read-only `Mapping`
  reads; `_summarize_rows` widened to a covariant `Sequence`; a corrected
  `timings: list[tuple[int, str, float]]` annotation; `PICKERS` typed as
  `dict[str, Callable[..., tuple[int, str]]]`; walrus narrowing for optional
  duration lists. 108 source files check clean with no heavy extras installed
  (closes the BLOCKERS.md B3 follow-up).
- `SpectralSphereManifold` default `smoothing` lowered from `0.999` to `0.9`. The
  over-damped default retained 99.9% of stale state per projection, so the
  production trust manifold (built with defaults in `mesh/core.py`, consumed by
  `_select_peers`) accumulated trust at ~0.1% per cycle and stayed near zero
  within the O(10)-cycle window it exists to win against Birkhoff uniformity
  collapse. Restores responsiveness while keeping noise-damping hysteresis.
- `private_vote.tally(..., require_all_revealed=True)` now gates on reveal
  *validity*, not mere presence. A present-but-invalid reveal (correct commit
  digest, wrong nonce) previously bypassed the gate and the ballot was silently
  dropped instead of raising `MissingRevealError`.
- pytest `pythonpath` now includes the repo root so tests importing `scripts.*`
  collect when run from the project root; interpreter-agnostic assertion in the
  official SWE-bench command test (`sys.executable` may be `python3`).
- Docs: `CLAUDE.md` and `AGENTS.md` no longer describe this checkout
  unconditionally as a "git submodule" (closes BLOCKERS.md B6). The standalone
  repository (its own remote) is now the documented default git workflow, and the
  submodule `git add`/`git commit`-from-`packages/constitutional_swarm/` rules are
  scoped to the ACGS-monorepo checkout only.

### Migration
- See `MIGRATION.md` (v1.1.0 section) and `docs/API_COMPATIBILITY.md` for
  the import-star / extras break.

## [1.0.0] - 2026-04-23

### Added
- Signed envelope for remote votes: nonce + timestamp + Ed25519 signature; replay window enforced server-side (task sec-wss-envelope)
- Startup settlement reconciliation: `ConstitutionalMesh.reconcile_pending_settlements()` returns a `ReconciliationReport`; optional `auto_reconcile` kwarg on mesh construction (task sec-startup-reconcile)
- `RemoteVoteReplayError`, `RecoveredAssignmentError` exceptions exposed via top-level import
- `SettlementRecord.schema_version` (default 1) and `is_recovered` flag persisted in JSONL + SQLite stores (idempotent ALTER on load) (tasks sec-schema-version-prep, sec-settle-replay)
- `GoalStep` dataclass with Mapping compatibility; unknown keys preserved in `GoalStep.extra` (task refactor-goalspec)
- Shadow spectral invariant test (`tests/test_shadow_spectral_invariant.py`, N=100 zero-divergence) (task cov-e2e-remote)

### Changed
- Remote vote transport: tri-state `transport_security: Literal["plaintext", "tls", "auto"]`; `auto` resolves to `tls` unless host is loopback; passing both `ssl_context` and `transport_security` raises `ValueError` (task sec-wss-envelope)
- Envelope requirement: remote vote requests missing nonce/timestamp are rejected; no legacy compat path
- Public API narrowed: top-level `__all__` now = `["AgentDNA", "ConstitutionalMesh", "GovernanceManifold", "SwarmExecutor", "TaskDAG"]`. Advanced names remain importable from submodules (e.g. `from constitutional_swarm.remote_vote_transport import RemoteVoteClient`) (task api-narrow-final)
- `mesh.py` split into `mesh/` package: `core`, `voting`, `settlement`, `peers`, `exceptions` (backward-compat facade in `__init__.py`) (task refactor-mesh-split)
- `remote_vote_transport.py` split into `remote_vote_transport/` package: `protocol`, `transport`, `peer` (backward-compat facade) (task refactor-transport-split)

### Removed
- Legacy envelope compat path for unsigned remote vote requests

### Migration
- See `MIGRATION.md` for the 0.3 -> 1.0 upgrade guide (transport_security, schema_version, register_agent)


## [0.3.0] - 2026-04-23

### Breaking Changes

`register_agent()` has been **removed** (not just deprecated). Calling it now raises
`AttributeError`. See [MIGRATION.md](MIGRATION.md) for the upgrade guide.

**Before (0.2.x):**
```python
# public-key-only peer
mesh.register_agent("agent-1", vote_public_key=pub_key)
```

**After (0.3.0):**
```python
# public-key-only peer (signing happens outside this process)
mesh.register_remote_agent("agent-1", vote_public_key=pub_key)

# local signer (this process holds and uses the private key)
mesh.register_local_signer("agent-1", vote_private_key=priv_key)
```

### Added
- Added `MIGRATION.md` with a mapping table and before/after examples for the
  `register_agent()` → `register_local_signer()` / `register_remote_agent()` migration.
- Added two new `collect_remote_votes()` tests: missing-route `KeyError` and
  wrong-`assignment_id` response handling.

### Changed
- `register_agent()` now raises `AttributeError` (removed; was `DeprecationWarning` in 0.2.x).
- `collect_remote_votes()` KeyError message now names the missing peer ID and
  shows the expected `peer_routes` key syntax.
- `HarnessResult.resolved` and `LocalSWEBenchHarness.evaluate()` docstrings now
  document the `evaluation_mode="local_dockerless"` distinction so downstream
  consumers can distinguish local results from official SWE-bench leaderboard scores.

## [0.2.0] - 2026-04-16

### Added
- Added `EvolutionLog`, a SQLite-backed append-only governance metric log whose SQLite triggers reject regressions, gaps, and deceleration at write time for capability-curve entries.
- Added remote vote transport primitives so public-key-only peers can validate and sign mesh votes outside the producer process.
- Added remote vote transport tests and evolution log tests, bringing the package test inventory from 38 to 40 files.
- Added self-contained paper build assets so the ICLR 2027 and NDSS 2027 manuscripts compile directly from the repo.

### Changed
- Mesh peers now register explicitly with `register_local_signer(...)` and `register_remote_agent(...)`, and the public docs and examples now match that split.
- Remote vote verification now requires detached signatures, and malformed remote vote responses fail closed instead of coercing types.
- Deterministic DAG node IDs now use explicit collision detection during compiler and DAG node creation.
- The constitutional mesh settlement path now rejects duplicate JSONL settlement appends and avoids persisting raw content in settled records.
- Package guidance, README examples, and paper text now document the new governance and transport behavior.

### Fixed
- Fixed the paper sources so both submissions build cleanly with local vendored template assets and warning-free LaTeX logs.
- Removed tracked Python bytecode caches from the repository and ignored local Codex/OMX session artifacts and generated paper PDFs.

### Removed
- Removed the obsolete `HANDOFF_FORGECODE.md` handoff document.

### Breaking Changes

`register_agent()` has been split into two explicit methods. Code using the old API will receive a `DeprecationWarning` and will break in v0.3.0.

**Before (0.1.x):**
```python
mesh.register_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)
```

**After (0.2.x):**
```python
# For peers whose keys live outside this process:
mesh.register_remote_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)

# For peers whose private key lives in this process:
mesh.register_local_signer(
    agent_id="agent-1",
    domain="safety",
    vote_private_key=my_priv_key,
)
```
