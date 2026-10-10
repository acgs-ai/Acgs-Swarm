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

- **Historical C14 v1 envelope (superseded):** `mesh/vote_envelope.py` defined
  protocol version 1,
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

This historical migration required provisioning voter and receipt trust
registries out of band, emitting the then-current protocol-v1 envelopes, and
writing new mesh settlements as schema v2. The later C14 final-review decision
below supersedes live envelope emission with protocol v2. There
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
  `success_evidence` remain false. The original exact or greater-than-95-percent
  reviewer-agreement heuristic was diagnostic only; the C16 decision below
  supersedes it with a calibrated shared-wrong-answer diagnostic.
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
| `tool_call` gate | default-ALLOW (denylist only) → `curl http://x/` ran | default-DENY against a closed, code-owned safe-command table `SAFE_COMMANDS` (current form, C25b): `true` (no arguments) and `echo` (plain-word arguments, no flags or path separators, ≤64 arguments of ≤256 characters). Every entry carries its own argument policy (`SafeCommandSpec`). `command_allowlist` may only SELECT from the table. A list, tuple or set narrows it: unknown names are ignored, and an empty one enables nothing. A non-sequence value (for example a string) enables nothing. An absent or null value enables the whole table. Configuration can never add an executable, flag, or argument shape, so interpreters, shells, launchers and test runners cannot be enabled. `ACGS_TEST` therefore runs only these commands; running the real test suite is a supervisor responsibility outside the governed directive stream. |
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
**Superseded 2026-10-10 (C25, C25b):** the original `tool_call` row let a
constitution EXTEND `DEFAULT_COMMAND_ALLOWLIST` and relied on a
`DENIED_INTERPRETER_COMMANDS` denylist plus an argv-wide name scan. That design
was open-world: any unlisted launcher (`split --filter`, `capsh`, `prlimit`,
`setpriv`, `bwrap`) or `--opt=value` form re-opened code execution. The denylist
was deleted and replaced by the closed `SAFE_COMMANDS` table above; adding a
command now requires a code change with a reviewed argument policy. Signing
material moved to `ACGS_SIGNING_KEY_FILE` (an owner-only, single-link regular
file read through `secure_files.private_file`); `ACGS_SIGNING_KEY` is deprecated
and every `ACGS_SIGNING_*` variable is withheld from child processes. Every
governed child launch makes the supervisor non-dumpable on Linux (signed or
unsigned) and reads `PR_GET_DUMPABLE` back, failing closed if it is not 0.
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

This entry records the C14 transition to roster-bound envelope v2. The C16
completion decision below supersedes its live envelope and remote-request
versions and moves electorate authority out of voter-signed evidence. The outer
`MeshProof` and settlement schema remain independently versioned at v2.

### 2026-10-09 — C16 follow-up: closed benchmark and handoff detection gaps

Reviewer packet integrity is now an exact inventory contract: every regular file
under a distributed packet must have one canonical relative POSIX path in its
manifest, with `reviewer_manifest.json` as the sole manifest-external file.
Unlisted, renamed, traversal-aliased, and symlinked packet members fail closed;
the verifier rejects a symlink in any path component before reading a leaf.

Reviewer-copying diagnostics no longer treat high overall agreement as evidence.
They test identical shared wrong answers using a hypergeometric upper tail
conditional on both reviewers' observed error counts, then apply a Bonferroni
correction across every comparable pair in that answer matrix. All-correct and
low-noise honest reviewers are therefore not flagged solely for agreement.
This remains a diagnostic under independence and exchangeability assumptions;
common difficult questions, an incorrect ground-truth key, few observed errors,
or deliberate removal of shared errors can reduce calibration or power.

Governed handoff treats `.env.*`, nested `**/.env`, and nested `**/.env.*`
paths as code-owned protected paths after normalization and case folding.

Receipt verification now requires independent vote evidence by default.
`verify_bundle(..., require_independent_votes=True)` labels successful output
`evidence_policy="proof_grade"`; callers must explicitly opt into development
evidence, and the CLI exposes that exception as `--allow-dev-evidence` with
`evidence_policy="development"` in its output. The exception is rejected for
settlement-store verification, where proof-grade evidence remains mandatory.

`VoteSignerRegistry.frozen_copy()` now returns a separate
`FrozenVoteSignerRegistry` whose key maps are `MappingProxyType` values and
whose grants are tuples. The snapshot exposes lookup/export operations but no
mutation methods, so a caller cannot re-enable mutation by changing a flag.
The former registry-constructor `frozen=` switch is removed; provision a mutable
registry, then call `.frozen_copy()` when establishing a trust root.

Cascade admission now enforces an electorate at least as large as
`min_consensus_miners` and a quorum at least both a strict majority and the
configured `consensus_threshold` floor. `run_full_cascade_remote(...)` provides
the working independent-voter path through remote signed-envelope collection;
the accepted result is reverified before it can produce a delta. The configured
floor is checked directly as `quorum / electorate_size` against
`consensus_threshold`.

Independent mesh recovery now quarantines historical development-mode records.
Recovering them requires a mesh explicitly configured with
`evidence_mode="single_operator_dev"`; the mode remains labelled development
evidence and does not establish independent custody or an authenticated
electorate.

The authenticated-assigner design proposed by C16 N1 is **not delivered** in
this change. Protocol v2 still binds a voter-carried assigned roster, so the
electorate remains self-attested. A complete fix requires coordinated changes to
the remote vote wire protocol, remote signer path, and cross-language fixtures,
which were outside this worktree's owned files. No signed-assignment fixture,
testnet, deployment, receipt, cascade, or recovery migration is claimed.

**Supersession:** the statement above records the original C16 ownership
boundary. The completion decision below delivers that coordinated migration and
is authoritative for current proof-grade behavior.

### 2026-10-09 — C16 completion: authenticated assignment authority

Voters no longer define who may vote. Before releasing vote requests, the mesh
creates an immutable signed-assignment v1 object. Its domain-separated,
sorted-key canonical JSON binds the task, assignment, assigner and key,
producer, artifact and content hash, constitutional hash, sorted normalized
peer roster, strict-majority quorum, selection seed, and issue time. An Ed25519
key carrying the explicit `assigner` role signs this object. Vote-envelope v3
binds the digest of the complete signed assignment, including its signature, so
an envelope cannot be moved to a different assignment or paired with a forged
roster.

Proof-grade consumers authenticate the assignment before the votes. Precedent
admission, validator finalization, subnet-owner admission, cascade validation,
governance receipt construction and verification, and settlement recovery all
derive the expected peers and quorum from that authenticated object, then
verify complete, distinct vote-envelope v3 evidence. Missing assignments,
untrusted or unauthorized assigners, subject-binding mismatches, assignment
digest mismatches, and legacy envelope versions fail closed. Development mode
may relax the independent-custody requirement only; it cannot waive assignment
authority.

Assignment trust is an immutable public-key value. A mesh using its internally
owned registry creates a dedicated local assigner key and freezes its trust
snapshot. A mesh using an externally supplied registry requires an explicitly
provisioned assigner identity, private key, and matching `assigner` grant before
the snapshot is established. The normalized assigner identity is reserved from
voter registration, remote-agent registration, and voter unregistration, so
those lifecycle operations cannot overwrite or remove assignment authority.
Public trust export remains bootstrap data rather than verifier authority.
Recovery therefore requires the original assigner and voter public trust roots;
persisted evidence cannot authorize keys carried inside itself.

Remote vote request v3 carries the signed assignment and signs the exact request
schema. A remote peer independently verifies both its request-signer allowlist
and an immutable assigner registry, then checks the assignment bindings, exact
roster and quorum, and its own membership before signing a vote. Request-signing
authority, assignment authority, and voter authority are separate roles even if
an operator deliberately provisions the same key material for more than one.

Testnet validator startup now requires `--authority-keys` in addition to
`--authorized-voters`. The authority-key file supplies `assigner_id`,
`assigner_private_key_hex`, and `request_signing_private_key_hex`; each remote
peer must receive the matching assigner public grant and request-signer public
key through an independent provisioning channel. Fixtures, precedents,
synapses, and receipts carry the signed assignment. Historical records without
one remain readable only as unverified history and cannot be upgraded by
inventing assignment authority.

The checked-in Rust compatibility fixture bytes remain unchanged. Their
explicit historical detached-vote v1, remote-request v0, and `MeshProof` v1
encoders are retained, while the separate v-next helper emits signed-assignment
v1 and remote-request v3 examples. Current outer `MeshProof` and settlement
objects remain v2; these versions describe different protocol layers.

Rejected alternatives were deriving the expected roster from the submitted
envelopes, trusting an unsigned outer roster, or treating the request signer as
the assigner. Each makes the electorate self-attested or collapses independent
authority boundaries. The assignment signature proves which authorized key
selected the electorate; it does not prove unbiased selection or independent
host custody. The recorded selection seed supports the built-in selection path,
but a custom selection policy is not necessarily replayable from that seed.
Trust registration, key custody, and production provisioning remain deployment
responsibilities and are not established by local tests.

### 2026-10-09 — C16 rework: exclusive assigner custody

This entry supersedes the C16-completion statement that assignment and voter
authority may deliberately reuse an identity or key. An assigner is now
cryptographically disjoint from the electorate: `assigner` and
`voter`/`validator` roles are mutually exclusive both per normalized identity
and per Ed25519 public key. Mutable registration and replacement, immutable
snapshot construction, and governance-receipt grant loading all reject a
dual-role identity or key. Assignment validation also rejects an assigner in
the assigned roster and rejects an assigner key equal to any voter key. These
checks apply even to hand-built registry state, so bypassing a convenience
registration helper cannot make a self-assigned coalition proof-grade.

Settlement recovery is pinned to the recovering mesh's configured assigner,
not merely any key carrying an `assigner` grant in its frozen registry. The
persisted signed assignment must name that exact normalized assigner identity
and its exact public-key fingerprint before its signature or votes can activate
state. A broader registry therefore cannot redirect recovery to another trusted
assigner.

This entry also completes the earlier reviewer-packet inventory statement.
Manifested regular files and only the directories required by their canonical
paths are allowed. Unlisted directories and filesystem entries that are neither
regular files nor directories, including FIFOs, sockets, and devices, fail
closed with `unlisted_packet_entry`; the existing symlink-specific rejection is
retained.

C17 Phase B consolidates candidate trust-root validation for mutable register
and replace operations without changing validation order, lock scope, errors,
or mutations. All proof-grade consumers continue through the shared signed-
assignment verifier. Settlement recovery intentionally checks its pinned
authority root before checking assignment-bound votes against the current voter
registry; the checks protect distinct trust roots.

### 2026-10-09 — C17 Phase A: close remaining trust and secret-file edges

Signed-assignment verification now separates the assigner from the producer as
well as from the electorate. Equal normalized identities fail closed, and a
role-independent registry lookup rejects a producer identity whose registered
Ed25519 key equals the authorized assigner key. An unknown producer key remains
valid because the assignment schema does not require producer registration.
Custom structural registry views must implement `public_key_for_identity`.
Remote peers require the exact `FrozenVoteSignerRegistry`, and frozen grant
roles require the exact built-in `frozenset`, so subclasses cannot override
authorization operations at those two trust boundaries.

Governed handoff extends its normalized, case-insensitive code-owned path set to
`.envrc~`, `.envrc.*`, and their nested variants. Testnet validator startup now
opens the private authority-key document without following a symlink in the
final path component and accepts only a regular file with no group or other
permission bits. The public
`--authorized-voters` file remains public-only provisioning data and keeps its
existing policy.

These checks change only fail-closed admission and startup behavior. The
signed-assignment schema, canonical bytes, digest, signatures, and frozen Rust
compatibility fixtures are unchanged.

Rework 1 closes nested trust-object gaps as well. Registry validation requires
the exact internal grant type and exact built-in `str` values for identities and
every role. Trust-root ingestion serializes caller-supplied Ed25519 public-key
objects to raw bytes and reconstructs concrete keys with
`Ed25519PublicKey.from_public_bytes`; caller-defined verification or comparison
methods are never retained. Remote request-signer allowlists use the same
reconstruction boundary and store canonical lowercase raw-key hex strings.

The authority-key loader also requires the opened descriptor's `st_uid` to
equal `os.geteuid()`. `O_NOFOLLOW` protects only the final path component; it
does not establish a recursive no-symlink policy for parent components, so
operators must control every parent directory in the authority-file path.

### 2026-10-10 — Systemic sweep C18–C51: trust anchors come from the verifier

One rule runs through every batch: a verifier takes its trust anchors (keys,
roots, rosters, thresholds, expected request) from its own configuration, never
from the object it is judging, and an insecure mode needs an explicit, greppable
opt-in. Per-batch decisions follow. Batch labels (C18, C48, …) match the
`fix/C<N>-…` branch names in the integration merge commits, for example
`git log --merges --grep 'fix/C48'`. C14, C16 and C17 have their own entries
above.

- **Shared helpers (C18).** `strict_json` (duplicate keys, NaN, lone surrogates,
  depth and size limits), `framing.framed_digest` / `require_plain_id` (typed,
  length-framed digests; a finite ASCII identifier grammar) and
  `secure_files.private_file` (descriptor-based owner, mode and link checks)
  are stdlib-only. New digests use `canonical_dumps`; the byte-stable encoders
  already in use (codec, protocol v1, governance receipts, contract) are not
  merged into it, because their digests are persisted or signed.
- **Transitions and sync (C19).** Thresholds, drift budget and trust root come
  from verifier-owned policy; a certificate must agree with them. Transition
  votes sign `constitutional-transition-v3`, sync messages are wire v2 and must
  be signed by a trusted issuer, and replay state is per issuer. A governed
  certificate waives neither issuer authentication nor replay checks.
- **QC votes (C20).** `SignedVote` signatures bind `voter_id` through
  `build_vote_message_v2` (`acgs-swarm/qc-vote/v2`). Only the verifier's
  `CertificateVerificationPolicy(allow_legacy_v1=True)` can accept v1; a
  per-vote version field was rejected because the verified object would pick
  its own weaker format. Fault-domain caps keep cap-vs-raw semantics with an
  opt-in `enforce_domain_share`; water-filling was rejected because it changes
  every quorum decision.
- **Admission and R4 audit (C21).** Gates snapshot trusted inputs at
  construction, weight candidates must present exactly the reference matrix
  names, and a gate whose precondition cannot be checked fails rather than
  reporting "skipped". The R4 audit runs the generator in a `python -I -S`
  child; it is not a sandbox.
- **Authority plane (C22, C23).** Observer launch is pinned to
  `ObserverLaunchExpectationsV1` built from supervisor-held state, never read
  back from the attestation. All authority-plane JSON uses the shared strict
  parser. The privileged child sends only stable codes from
  `_PROTOCOL_ERROR_CODES` over IPC, requires pairwise-distinct role keys, and
  takes the policy version explicitly. Collapsing all denials to one code was
  rejected because callers depend on reasons such as `untrusted_policy_binding`.
- **Governed commit (C24).** Seal anchors are pinned to the bootstrap config
  (`authority_anchor_mismatch` otherwise) and `_transaction` is the single
  commit owner. Recorded limit: the agent signature in
  `GovernedReceiptPayload.canonical_bytes` covers only the APCC
  producer-statement projection. Policy context (`policy_version`,
  `policy_digest`, epochs, `authority_root`, `workflow_generation`,
  `state_version`, `profile`, `intent`, `verifier_policy_id`) is bound by the
  policy-signed `AuthoritativeVerdict`, not by the agent. Changing that would
  bump the APCC producer-statement protocol. It is left to a deferred design
  decision on request authority.
- **Governed handoff (C25, C25b, C51a).** Signer material and executable
  authorization share one subprocess boundary. See the 2026-06-03 entry's
  2026-10-10 supersession note for the closed `SAFE_COMMANDS` table. The
  operator-configured `ExternalAgentAdapter` command is not routed through
  `SAFE_COMMANDS`, because it must launch real agent CLIs. It is resolved on
  `FIXED_SUBPROCESS_PATH` (`/usr/bin:/bin:/usr/local/bin`, with system
  directories first) or must be absolute. A relative, blank, unparseable or
  unresolvable command fails before spawn.
- **Receipts and settlement (C26, C27).** Settlement signers must be distinct
  from voters, the assigner and the producer, checked at the grant and again at
  verification. Evidence verified against a root containing a `fixture-`
  identity or a publicly derivable key is labelled `development`, never
  `proof_grade`. Settlement persistence uses one OS lock helper
  (`exclusive_file_lock`, `flock`); running without a lock raises
  `SettlementLockUnavailableError` rather than warning.
- **Mesh core and vote envelopes (C28, C29, C48).** Persisted-settlement loading
  has one quarantine boundary: an unparsable, hash-inconsistent or
  evidence-failing record is logged with its cause and never becomes
  authoritative, and construction never aborts on stored history. Assignment
  authority is a caller-pinned trust root: `verify_assignment_vote_envelopes`
  takes `assigner_trust_root`, `expected_assigner_id` and
  `expected_assigner_key_id`. `ConstitutionalMesh.vote_registry` deliberately
  stays the live, mutable voter registry (C28), and `assigner_trust_root` is a
  separate frozen registry holding only the pinned assigner grant (assigner id
  and key). It is deliberately not a snapshot of the live registry, so a mesh
  built by `rotate_constitution` cannot inherit a late-registered assigner and
  `receipt_trust_registry()` exports only the pinned assigner as its assigner
  grant. C48 kept that split by design
  and declined to make `vote_registry` return `frozen_copy()`, because
  `ConstitutionalValidator.rotate_constitution` passes the live registry into a
  new mesh that mutates it. Instead every in-repo verifier path (mesh recovery,
  `ConstitutionalValidator`, `PrecedentCascade` when it holds a mesh) pins
  `assigner_trust_root` plus the pinned assigner id and key. A third-party
  verifier that reads `vote_registry` without passing `assigner_trust_root`
  still trusts live assigner grants. Remote-vote nonces (mesh core and
  `LocalRemotePeer`) are checked and recorded only after the signature
  verifies, expire at `max(now, timestamp) + W`, and are evicted only when
  `expires_at < now`, so a replay at exactly `timestamp + W` is still rejected.
- **Gossip (C30).** Gossip reuses the remote-vote TLS policy: plaintext is the
  default only on loopback, and the shared token is refused on any plaintext
  non-loopback link. There is no override for a TLS-terminating proxy.
- **Private voting and DP (C31).** Private voting is fail-closed by default:
  `strict_v2=True`, and the hash-scaffold prover counts only with
  `allow_insecure_hash_prover=True` in non-strict mode. `DrandClient` stays
  unauthenticated (no BLS dependency) and says so; ODE snapshots never claim
  BODES passage.
- **APCC stores (C32).** Non-decision audit ids use
  `framed_digest(b"apcc.audit-id.v2", ...)`; the decision family (`commit`,
  `DENIED`, `CONFLICTED`, `conflict`) keeps the v1 NUL-join because
  `observation.py` recomputes it independently. Migration is fail-closed
  (rewriting would re-hash the trust-log chain). The PostgreSQL store imports
  the same id function and semantic validator, so both backends are affected.
  The schema v4 bump is deferred because it needs the PG17 GCB catalog
  fingerprint regenerated. Until then, pre-C32 SQLite and PostgreSQL stores
  fail to reopen with a generic error ("APCC SQLite store semantic validation
  failed" or "APCC authority store semantic validation failed"). The store runs
  the same per-row validator when writing as when reopening, so it cannot seal
  a state it would reject.
- **APCC observation and empirical (C33, C34).** The request an observation
  answers comes from the caller (`expected_request`) and is compared before any
  cryptographic work; the verified result records `request_digest`. B4 pins its
  proof trust root at adapter construction; B5's journal MAC comes from a
  dedicated supervisor-only secret via HKDF, and B5 bumped `ADAPTER_VERSION` to
  `gcb1-subprocess-v2` with no migration.
- **Audit log and anchors (C35, C35b).** One count-committed RFC 6962-style
  Merkle tree serves audit batches and chain anchors. Verifier trust facts come
  from the caller (`expected_root`, `expected_batch_id`); there is no unpinned
  fallback. Decoders accept exactly the key set `to_dict()` emits, because
  silent defaults changed the hashed leaf content.
- **Bittensor (C36–C39).** Response authentication is one library function
  (`synapse_adapter.authenticate_response`) that both the client and the
  testnet script call; scripts may add allow-lists but never re-implement
  verification. A miner axon attaches only through `attach_to`. NMC commitments
  bind `(session_id, case_id, miner_uid)` with a v2 framed digest and rosters
  are mandatory. Rule codification separates duties (pinned governor roster,
  proposer excluded, pinned constitution hash). Precedent metadata shape is a
  `PrecedentRecord` constructor invariant; cryptographic `task_id` binding is a
  follow-up. Economics and attestation need explicit opt-ins:
  `allow_insecure_stub`, `allow_unregistered`, `admin_override`.
- **SWE-bench (C40, C41).** Governance and evaluation share one detector entry
  point (`evaluate_payload`), so the enforced robustness floor is the one that
  is measured. The CRDT `bodes_passed` flag carries the governance verdict.
  Library code never derives a write location from the cwd. Patch adapters
  share one diff extractor and one Messages-API base; oracle-selected
  best-of-k results are labelled pass@k. C51b allowlists instance ids
  (`[A-Za-z0-9][A-Za-z0-9._-]*`) before they reach paths or harness argv. It
  extends normalization with accent folding (NFKD, drop marks, NFC) and maps
  blank fillers to spaces, while zero-width characters are still deleted.
  ROLE-004 matches `rm` recursive and force flags in any order using bounded
  patterns only, so matching stays linear. That changed the MCFS rule-set hash
  (`4b9636ce4710779f` → `ebcb7caa26e6abfb`), which nothing pins; the project
  constitutional hash is unchanged.
- **LangGraph runtime (C42, C42b, C51a).** The actual DNA hash is pinned and
  rechecked; acceptance is a terminal verdict owned by the settle node, and
  streaming trusts only that node's own update. Error labels are a closed set.
  `stream_to_crdt` appends at most once, after the stream ends, and only when
  the final patch equals the patch the validator checked and the settle node
  read. Each update is bound to the input state its task read, and an
  unobserved write (a replayed chunk, a task without a result event, or early
  close) appends nothing. This is an in-process evidence protocol, not
  cryptographic attestation.
- **Core governance gates (C43).** `govern` raises by default on an invalid
  result or a verified Z3 counterexample; WARN-tier matches are logged and
  counted, not raised, because blocking them would override the constitution
  author's intent. Credentials verify against issuer keys pinned at bridge
  construction, debate roles come from a registry pinned on the resolver, and
  the MAC-ACGS loop approves only through a registered external challenger.
- **Numerics (C44).** Spectral-sphere projection is a verifier: non-finite input,
  an overflowed estimate or an unverified bound raises rather than reporting
  `r`, because `trust_matrix` readers do not consult `is_stable`.
- **Core misc and tooling (C45, C47).** Duplicate agent names are rejected at
  discovery (report schema unchanged); ArtifactStore visibility guards run
  outside the non-reentrant store lock. Benchmark CLI verifiers parse
  security-relevant JSON with the shared strict loader, and packet JSON that
  only a lenient parser accepts is reported as `ambiguous_packet_json`. TLC
  runners hash and run a private copy of the jar.
