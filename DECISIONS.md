# Decisions

Index of architecture & product decisions. Detailed ADRs live in
[`docs/internal/`](docs/internal/); the invariants they encode are summarized in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Standing invariants (do not change without an ADR)

| Decision | Value / rule | Rationale |
|---|---|---|
| Constitutional hash | `608508a9bd224290` | Stable identity of the canonical constitution. |
| Precedent quorum | 3/5 super-majority over at least five distinct, authorized `VoteEnvelope` signers (`min_total_validators=5, min_votes_for_precedent=3`) | Counts and roots are derived consistency data; only verified voter evidence can create precedent. |
| Signed votes mandatory | Versioned, canonical Ed25519 `VoteEnvelope` evidence is carried unchanged from voter to every consumer | No unauthenticated trust updates or aggregate-only proof. |
| Signer authority is external | Voter keys use `VoteSignerRegistry`; receipt keys use structured `SignerTrustGrant` roles | Evidence cannot authorize its own signer or self-declare a privileged role. |
| `manifold.py` is frozen | Birkhoff/Sinkhorn baseline is **not** fixed | Its uniformity collapse is the kept empirical control; `spectral_sphere.py` is the production direction. |
| `EvolutionLog` write rules | Strict monotonicity + acceleration enforced at write time | Append-only, SQLite-backed governance metrics. |
| Two-phase audit commit | Cache Phase 1 in `_retry_state`, clear only on Phase 2 success | Crash-safe Arweave audit logging. |

## Architecture Decision Records (`docs/internal/`)

| ADR / note | Topic |
|---|---|
| [`acgs_v0_1_receipt_profile_adr.md`](docs/internal/acgs_v0_1_receipt_profile_adr.md) | Governance receipt profile. |
| [`acgs_v0_1_verifier_first_scope.md`](docs/internal/acgs_v0_1_verifier_first_scope.md) | Verifier-first scope for v0.1. |
| [`rust_core_protocol_adr.md`](docs/internal/rust_core_protocol_adr.md) | Rust core protocol direction. |
| [`abliteration_threat_model.md`](docs/internal/abliteration_threat_model.md) | Abliteration threat model + defense mapping. |
| [`governance_benchmark_plan.md`](docs/internal/governance_benchmark_plan.md) | Governance benchmark methodology. |
| [`swebench_swarm_backend_and_recovery.md`](docs/internal/swebench_swarm_backend_and_recovery.md) | SWE-bench swarm backend + recovery. |
| [`acgs_v0_1_standards_research.md`](docs/internal/acgs_v0_1_standards_research.md), [`claims_map.md`](docs/internal/claims_map.md), [`gap_register.md`](docs/internal/gap_register.md) | Standards research, claims mapping, gap register. |

(See [`docs/internal/`](docs/internal/) for the full set, including audits and checklists.)

## Tooling decisions (this workspace)

| Decision | Choice | Rationale |
|---|---|---|
| Dependency/runner | `uv` + `uv.lock` | Reproducible installs; the system interpreter is `python3` with no global pip/ruff/pytest. |
| Standalone setup | `uv sync --no-sources` (in `make setup`) | `pyproject` pins `acgs-lite = { workspace = true }` for monorepo dev; a standalone clone resolves it from PyPI instead. See [BLOCKERS.md](BLOCKERS.md) B1. |
| Pytest path | `pythonpath = ["src", "."]` | A few tests `import scripts.*`; repo root must be importable when running from root. |
| Static analysis | mypy (whole package, no allow-list) + ruff | `make typecheck` runs mypy across two CI surfaces (no-extras + `transport`); `make typecheck-coverage` guards extra-gating. See [BLOCKERS.md](BLOCKERS.md) B3 and the 2026-06-03 typecheck env-consistency log entry below. |
| Single source of truth for commands | `tools/registry.yaml` | Validated by `make agent-check`; `TOOLS.md` is the human view. |

## Decisions log

### 2026-10-09 — Canonical vote evidence and role-scoped trust

Aggregate vote counts and root hashes do not prove which validators voted, what
they signed, or whether they were authorized. The former mesh and remote-vote
signature inputs also joined free-text fields with colons, so different field
partitions could produce the same pre-image. The protocol now treats one
versioned `VoteEnvelope` as the indivisible unit of vote evidence.

- **Canonical envelope:** `mesh/vote_envelope.py` defines protocol version 1,
  domain-separated sorted-key JSON encoding, strict codecs, Ed25519 signing and
  verification, and a deterministic envelope root. Each envelope binds voter
  and key identity, task, assignment, producer, artifact, content hash,
  constitutional hash, decision, reason, nonce, and issue time. Request
  signatures use a separate versioned canonical domain.
- **External authorization:** `VoteSignerRegistry` binds a canonical voter ID to
  one Ed25519 key fingerprint and explicit roles. IDs are NFKC-normalized,
  Unicode format characters are removed, then values are trimmed and
  case-folded. Vote key IDs and compared public-key fingerprints are lowercase
  hexadecimal. Canonical identity collisions and cross-identity key reuse fail.
  `ConstitutionalMesh(vote_registry=...)` accepts the out-of-band registry;
  `mesh.vote_registry` exposes it read-only. `VoteSignerRegistry.trust_grants`
  exports only identities already authorized for the requested role and assigns
  exactly that role, so exporting validator grants cannot promote voter-only
  identities. `mesh.receipt_trust_registry()` combines those exact-role voter
  grants with the mesh's separately authorized settlement receipt signer.
- **End-to-end evidence:** mesh results, remote responses, Bittensor validation
  synapses, precedent records, settlement schema v2 records, and governance
  receipts preserve the original envelope list. Every state-changing consumer
  re-verifies signer authority, signatures, subject bindings, distinct voters,
  and derived counts. A supplied root or tally never authenticates a result.
- **Collection and decision are separate:** precedent-producing
  `ValidatorConfig` defaults to five peers, quorum three, and
  `complete_evidence=True`. The validator collects all five distinct envelopes
  while retaining the 3-of-5 decision rule; early-settling mesh operation must
  be selected explicitly and cannot create precedent from incomplete evidence.
- **Unique mesh outcome:** the constructor requires configured quorum to be a
  strict majority of configured `peers_per_validation`. Settlement and
  pending-record recovery then require an approving or denying strict majority
  of the actual assigned peer set, including any peers added by risk expansion.
  A tie or a schema v1/otherwise unauthenticated stored result is quarantined
  instead of becoming active state.
- **Assignment-bound selection and receipts:** the mesh validates the final
  peer selection before recording an assignment: it must contain exactly the
  risk-expanded number requested, use canonical distinct identities, exclude
  the producer, and contain only available candidates. Proof-grade governance
  receipts sign the canonical `assigned_peers` roster, require every verified
  envelope voter to be a member, and derive the strict-majority denominator
  from that roster. `assigned_peer_count` remains a compatibility projection
  and must equal the signed roster length; it is never trusted as the quorum
  source.
- **Explicit compatibility versions:** current detached vote payloads use
  domain-separated canonical protocol v2 and current remote request signatures
  use domain-separated canonical protocol v1. The historical colon-joined
  encodings are available only through explicit detached-vote v1 and
  remote-request v0 selection. Remote wire decode accepts only the exact
  protocol-v1 request schema. `MeshProof` defaults to v2;
  schema-v2 settlement recovery requires an explicitly serialized v2 proof, so
  a missing proof version or a v1 proof cannot authenticate current settlement
  evidence.
- **Role-scoped receipts:** the v0.1 governance-receipt wrapper remains stable,
  but proof-grade settlement receipts require schema v2 envelope evidence.
  `trusted_signers` values are structured `SignerTrustGrant` records containing
  `identity_id`, `public_key_hex`, and one or more of `validator`,
  `coordinator`, or `settlement`. The verifier derives the required outer role
  from the evidence shape; signed metadata cannot lower it. Flat trust maps,
  unsigned or aggregate-only vote history, missing roles, and unauthorized
  signer keys fail closed.
- **Proof-grade deterministic fixtures:** `governance_fixtures.py` now derives
  reproducible Ed25519 voter and coordinator keys from fixed seeds, includes the
  original signed envelopes in every valid benchmark receipt, and returns
  explicit identity/key/role grants from `fixture_trusted_signers()`. Fixture
  content hashes cover canonical JSON containing the action and evidence-hash
  map. An escalation that has no signable approve/deny outcome is represented
  as a fail-closed denial while its escalation rationale remains in the signed
  vote evidence. This changes deterministic payload digests but preserves the
  benchmark narratives and verifier path.
- **Trusted precedent source for codification:** `RuleCodifier` no longer
  creates a registry-less fallback store. Non-empty clustering, proposal,
  approval, and activation require an injected `PrecedentStore`; supplied
  records must be exact canonical records already admitted by that store.
  Empty read-only clustering/proposal calls may still return an empty list
  without a store. `PrecedentBackedCodifier` follows the same rule: an empty
  observed stream is readable, while observation or populated codification
  requires the explicitly supplied trusted store.
- **Explicit validator provisioning:** `ConstitutionalValidator` accepts a
  caller-supplied `VoteSignerRegistry`, and `register_miner(...,
  vote_private_key=...)` registers the exact local Ed25519 signer material and
  preserves it across constitution rotation. The testnet validator command
  requires `--authorized-voters FILE`; that JSON file must contain at least
  `peers_per_validation + 1` distinct normalized identities (six with the
  default five-peer configuration) with distinct 32-byte private keys encoded
  as 64 lowercase hexadecimal characters. The extra identity is required
  because the judgment producer is excluded from its own assignment. The
  validator and `SubnetOwner` share the resulting registry. Invalid or missing
  grants fail before the Bittensor SDK, wallet, or subtensor is accessed, and
  metagraph hotkeys are never implicitly authorized.
- **Authenticated miner responses:** `GovernanceDeliberation` carries
  `response_protocol_version`, `response_signer_hotkey`, and
  `response_signature`. The response body signature binds the original request
  hash and requester hotkey, the selected axon identity, and the complete
  judgment body. The testnet validator verifies both the Bittensor SDK axon
  routing signature and this request-bound body signature before conversion,
  validation, or precedent admission; unsigned or mismatched responses fail
  closed.
- **Frozen historical vectors:** `scripts/generate_rust_protocol_fixtures.py`
  explicitly selects detached vote v1, remote request v0, and `MeshProof` v1,
  then serializes only each version's frozen historical fields. The checked-in
  Rust fixture corpus remains byte-identical; secure current defaults do not
  silently redefine those compatibility vectors.

Rejected alternatives were delimiter escaping at individual call sites,
trust-on-first-use for keys carried beside an envelope, quorum five, and trusting
an outer receipt signature over supplied aggregates. These approaches either
leave multiple encoders, let evidence self-authorize, change 3-of-5 into
unanimity, or preserve the original provenance gap.

Migration is explicit: provision voter and receipt trust registries out of band,
emit protocol-v1 envelopes, and write new mesh settlements as schema v2. There
is no implicit unsigned or aggregate admission fallback. Historical schema v1
settlements and v0.1 aggregate receipts may still be parsed as records, but they
are not proof-grade evidence. Fixture consumers must accept structured grants
instead of flat key maps, and any code that submits precedents for codification
must share the same explicitly provisioned admission store. Historical Rust
vectors stay on their frozen explicit versions; new protocol evidence uses the
current secure defaults instead of modifying the checked-in compatibility
corpus. Testnet operators must provide an `authorized_voters` JSON document to
the validator command; existing deployments that relied on metagraph discovery
as voter authorization now fail closed until at least
`peers_per_validation + 1` independent local signing authorities are
provisioned (six with the default five-peer configuration).

### 2026-10-09 — Forensic benchmark commitment and reviewer isolation

- A forensic result is locally valid only when public generator code regenerates
  the answer key, condition key, templates, manifests, and every manifested
  reviewer artifact from the committed `pack_nonce`, with byte equality for
  those result-evidence files. Unblinded `artifacts/**` sources are outside that
  result-evidence manifest; `--verify-replication-kit` and reviewer-packet
  generation from `--coordinator-pack` regenerate and byte-compare the complete
  coordinator pack, including those sources.
- The generator emits a precollection commitment over canonical sorted-key JSON
  containing the exact answer-key hash, condition-key hash, nonce hash,
  generator version, and reviewer-manifest hash. The answer seal binds the
  digest. Validation requires the expected digest through a separate argument;
  no file in the mutable bundle can supply its own trust anchor.
- Reviewer assignment uses the fixed balanced cohort `reviewer-1` through
  `reviewer-6`. Each reviewer receives each underlying
  incident under exactly one condition. Reviewer-specific, condition-specific
  HMAC-SHA256 incident pseudonyms and pseudonym-only packet ordering prevent the
  tested public-order and twin-packet joins, and matrix validation rejects rows
  outside the assignment. This control does not prevent reviewers from sharing
  packets across cohorts or inferring a condition from its semantic content.
- Significance uses the incident as the unit: condition accuracy is aggregated
  across assigned reviewers and questions, then an exact one-sided sign test is
  applied to incident-stratified, between-reviewer ACGS-versus-baseline
  contrasts with ties removed.
- Command lines, attestor names, and unsigned provenance are diagnostic
  metadata. Until an authenticated provenance channel exists,
  `authenticated_provenance`, `external_success`, `independence_verified`, and
  `success_evidence` remain false. Exact or greater-than-95-percent reviewer
  answer agreement is also diagnostic; it is not proof of copying or
  independence.
- Coordinator manifests do not publish plain hashes of unblinded source
  artifacts. The kit verifier and coordinator-pack packet generator instead
  check source-artifact integrity by regenerating the complete canonical pack
  from the retained nonce and comparing paths and bytes. The
  `coordinator_pack/reviewer_manifest.json` and root `kit_manifest.json` remain
  coordinator-only until unblinding; each distributed reviewer packet carries
  only its isolated filtered manifest.
- Standalone reviewer packets are derived from a retained coordinator pack or a
  nonce file. Inline nonce input is compatibility-only and produces an exposure
  warning; omitting every nonce source is an error.
- Result evidence uses a strict logical-name allowlist. Required evidence and an
  optional scorecard are accepted; caller-defined evidence manifests cannot
  authenticate their own members.
- Residual trust lies in the out-of-band commitment channel and study operations.
  Value signatures can differ by condition. Reviewer packet sharing or collusion,
  coordinator disclosure of the nonce or hidden keys, and authenticated reviewer
  identity remain outside local validation.

### 2026-08-15 — Public façade and receipt identity

- `__all__` is the stable eager façade. Star-import no longer dumps research
  symbols. Legacy names stay lazy. Documented in `docs/API_COMPATIBILITY.md`.
  Shipped as 1.1.0. Publishing GitHub/PyPI artifacts is a separate
  human-gated step.
- `receipt_digest` is the v0.1 payload digest (canonical statement identity),
  not the signed-envelope hash. Mesh receipts use key id `settlement-receipt`.

### 2026-06-03 — Typecheck gate environment consistency

The mypy gate ran only in a dev-only CI job, so type errors that surface only when
an optional `py.typed` extra is installed (e.g. `websockets`/`transport`) never
blocked a PR — a structural blind spot proven by `gossip_protocol.py`. Decisions:

- **Two blocking typecheck CI jobs**, not one: keep the no-extras job (the published
  library's distribution contract) and add `typecheck-transport` (`.[dev,transport]`,
  matching the local `make typecheck` default `EXTRAS="dev transport"`). A single
  replace was the lighter alternative; two jobs guarantee a superset without leaning
  on the dominance argument.
- **Heavy `research` (torch/transformers) stays out of the gate** — heavy and crashes
  mypy; `follow_imports = "skip"` if ever gated.
- **`warn_unused_ignores` stays OFF** — env-divergent ignores would flip-flop;
  re-enabling cleanly needs the `# type: ignore[code,unused-ignore]` idiom — deferred.
- **Regression guardrail**: `make typecheck-coverage` (`scripts/check_typecheck_coverage.py`)
  asserts every optional extra is `checked` (installed by a blocking mypy job) or
  `excepted` (with a reason) in `[tool.constitutional_swarm.typecheck_coverage]`, so a
  new extra-gated module cannot silently reopen the blind spot. `langgraph` is excepted
  with a known live error (`swarm_topology.py:126`) pending a code fix + mypy-band pin.

Plan: `docs/plans/2026-06-03-003-fix-typecheck-env-consistency-plan.md`.

### 2026-06-03 — Governed-handoff kernel hardening (make the security claims true)

A real-world validation pass found `governed_handoff.py`'s evidence bundle did not
deliver the forgery-resistance its framing implies, and the deterministic gate was
default-ALLOW. Hardened the kernel (executor side unchanged) so the repo's own
security claims hold:

| Change | Before | After |
|---|---|---|
| Evidence bundle integrity | `verify_bundle` only re-checked chain self-consistency → a coherent chain fabricated from scratch verified green (verifier == forger) | `build_bundle` optionally Ed25519-signs a domain-separated attestation pre-image (`BUNDLE_SIG_DOMAIN`, binds chain_hash + constitution_hash + version pin + final_state + task identity). `verify_bundle(..., trusted_public_keys=...)` REQUIRES a valid signature for `ok` when a trust anchor is supplied. Trust derives only from out-of-band keys, never the bundle-embedded key. |
| `tool_call` gate | default-ALLOW (denylist only) → `curl http://x/` ran | code-owned default-DENY allowlist `DEFAULT_COMMAND_ALLOWLIST = (true, echo)`; a constitution may EXTEND it but never weaken the default. Interpreter/test-runner/shell commands (`python*`, `pypy*`, `pytest`, `bash`, `env`, `uv`, `node`, …) are in `DENIED_INTERPRETER_COMMANDS` and are denied UNCONDITIONALLY — an allowlist cannot re-enable them, since `python -c <code>` / a `pytest` conftest / `bash -c` would bypass every other gate. `ACGS_TEST` therefore runs only pre-vetted non-interpreter commands; running the real test suite is a supervisor responsibility outside the governed directive stream. |
| Constitution version pin | `608508a9bd224290` computed + emitted but never compared | `_intake` fails closed if the constitution **declares** a `constitutional_version` / `constitutional_hash` that ≠ the pinned constant (enforce-if-declared; silent when undeclared, preserving existing configs) |

**New public surface:** `BundleSigner`, `verify_bundle(trusted_public_keys=...)`,
`build_bundle(constitutional_version=, signer=)`, env `ACGS_SIGNING_KEY` /
`ACGS_SIGNING_KEY_ID`, CLI `acgs-swarm verify --trusted-key KEYID=HEX`. Backward
compatible: with no signer/anchor, `verify_bundle(path)` still returns `ok` on
chain-consistency and runs stay unsigned (honestly reported as `signed: false`).
**Superseded 2026-10-08 (C3 attestation fix):** unanchored or unsigned bundles now
return `ok: false`; every summary field (`tests_run`, `policy_decisions`,
`file_changes`, `tool_events`, `role_assignments`) is bound into the v2 signed
pre-image and re-derived from replayed events.
The constitutional hash constant itself is **unchanged** — this only adds
enforcement that references it. Signing uses the core `cryptography` dep (no new
optional extra). Deferred: REVIEW-halts-loop and full executor loop-ification
(belong with the agent-loop work, not this correctness fix).

**Why:** the productized signed-evidence-bundle space is commoditized (Microsoft
AGT, nono, Pipelock, Fuzentry), so the durable, identity-aligned move is making
the deterministic kernel actually forgery-resistant as research.


### 2026-10-09 — C14 final review: signed electorate and separate voter custody

This decision supersedes the C14 v1 envelope and shared testnet trust provisions
above. Authentic signatures alone do not prevent an aggregator omitting dissent
or an operator signing for every identity. Current vote envelopes therefore bind
the canonical sorted assigned roster hash, assigned count, quorum, and evidence
mode in protocol v2. Admission verifies the complete roster, recomputes every
tally, and enforces both the signed quorum and a strict majority of all assigned
voters. Precedents additionally require at least five distinct authorized voters
and at least three approvals. Historical v1 and aggregate evidence fails closed.

Owner authority is a frozen public-key snapshot provisioned outside the validator.
Mutating or re-keying the validator registry cannot change owner authority. Default
validator provisioning accepts remote voters' public keys and collects their
signatures remotely. Local multi-identity signing requires explicit development
mode; its signed evidence is labelled non-independent and default precedent
admission rejects it. A mode label is not proof of independent custody; the
external trust registry and custody policy remain deployment responsibilities.

Receipts bind the exact envelope electorate and quorum, require complete votes,
and enforce a quorum floor of three. The outer role is settlement whenever the
receipt carries vote envelopes or an assignment ID, regardless of removable
evidence hash entries. The CLI supports verifier-selected expected signer roles.
The mesh receipt trust getter is a pure public-data export, never an independent
verifier trust anchor. Cascade consensus must authenticate v2 evidence and
recompute outcomes, rather than trust a structural proof or supplied counts.

Rejected alternatives: unsigned roster metadata preserves omission attacks;
sharing or copying a mutable registry exposes the admission trust root to
re-keying; marking local votes independent without changing key custody merely
renames the original defect. Legacy fixture encoders may remain explicit, but
live request and signature verification cannot select legacy encodings.

V2 settlement never freezes a partial electorate. The historical
`complete_evidence=False` parameter remains accepted for call compatibility but
no longer permits early settlement. Persistent mesh configurations require
quorum at least three at construction, so the mesh cannot declare an outcome
persistable when the receipt layer would reject its quorum.
