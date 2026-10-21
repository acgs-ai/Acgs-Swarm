# APCC-1 task tracker

## Resume audit — 2026-10-16

The checklist below predates substantial implementation and is not a reliable
inventory of missing code. Specification, SQLite/PostgreSQL, Go verifier, formal
models, and partial empirical artifacts exist. Existing checkboxes are retained
until their complete acceptance criteria have fresh supporting evidence.

This source archive was compared against the historical local worktree at
`f6f4f7162f6ee657fc241cd5dc89445f9b18fad9`: all 965 tracked paths exist; only
the pre-existing Braintrust version change in `pyproject.toml` differs. Local
Git history was restored without replacing working files, on
`apcc-1-resume-20261016`. No remote verification or publication is implied.

Fresh baseline: `make verify` passed with 2956 passed, 57 skipped, and 95
deselected after restricting group/other write permission on the experiment
matrix directory and its matrix/schema inputs. All 32 APCC TLC configurations
were accepted by the pinned runner (4 normal successes and 28 expected named
witness/ablation violations). These checks do not complete the frozen empirical
campaign, historical-baseline tests, or independent acceptance reviews.

The Go module now includes an independent, test-only JCS reference and an
APCC-CJ1 subset comparison. All 26 RFC 8785 Appendix B rows, module race tests,
vet, formatting, a short fuzz campaign, and all 126 Python/Go vectors passed
independent local review. Production CJ1 parsing is unchanged.

Two design constraints were addressed during this audit:

- The scheduler now resolves exact persisted APCC observation targets through
  the authority. All 21 new integration and negative-path tests passed, with
  independent review. This also repaired the spawned observer's status-store
  wiring. Full B6 experiment execution remains unqualified; invalid governed
  receipts must not be mislabeled as durable APCC denials.
- The frozen 30-second performance cells require at least 10,000 completed
  operations even at 10 operations/second. That target permits about 300
  operations. The user authorized retaining 10,000 completed operations and
  extending low-rate runs to 1,000/100/30 seconds at 10/100/500 operations/s.
  Additive matrix v2 implements this rule; the original frozen matrix remains
  unchanged. Full campaign measurements and acceptance reviews remain open.

Current evidence and open gates: [resume record](../docs/internal/APCC-1-Resume-2026-10-16.md).
The [novelty verdict](../docs/internal/APCC-1-Novelty-Verdict.md) is
**INSUFFICIENT EVIDENCE**.

## Baseline and planning

- [x] Resolve the exact GCB-1 worktree, branch, commit, merge-base, and origin.
- [x] Read root and directory-local source/test/security/docs/spec/script rules.
- [x] Run fresh unmodified `make verify` and `make test-all` baselines.
- [x] Run the pre-existing Mesh, constitution-reconfiguration, GCB safety, and
  GCB non-vacuity TLC gates.
- [x] Check hosted branch/check/workflow evidence for the exact baseline SHA.
- [x] Record `BASELINE_REMOTE_EVIDENCE_INCOMPLETE`.
- [x] Complete a read-only extraction and implementation planning lane.
- [x] Complete current official-source research for PostgreSQL, Psycopg, JCS,
  Go JSON, Ed25519, and the independent-verifier boundary.
- [ ] Complete and approve the architecture lane's protocol/state/store matrix.

## Specification freeze

- [ ] Write `APCC-1-Protocol-Spec.md`.
- [ ] Write `APCC-1-Threat-Model.md`.
- [ ] Write `APCC-1-Security-Properties.md`.
- [ ] Freeze canonical schema, limits, domain separation, and failure codes.
- [ ] Freeze canonical outer envelope and exact byte-level signature preimages.
- [ ] Freeze roles, state machine, operations, and atomic linearization point.
- [ ] Freeze nonce-bound online current-status semantics; defer snapshots.
- [ ] Embed exact reconstructible producer/policy/authority signed bodies.
- [ ] Freeze store-global `commit_id` and cross-workflow conflict handling.
- [ ] Freeze the fair experiment/benchmark plan before final measurements.
- [ ] Run independent protocol-minimality pre-implementation review.

## Core and SQLite realization

- [ ] Capture RED protocol model and import-boundary tests.
- [ ] Implement storage-independent model, interfaces, errors, and operations.
- [ ] Capture RED strict-codec/canonicalization tests and negative vectors.
- [ ] Implement canonical codec and deterministic vector generator.
- [ ] Capture RED signature, binding, tamper, replay, and equivocation tests.
- [ ] Implement producer verification and commit-certificate verification.
- [ ] Implement protocol service and state transitions.
- [ ] Extract the SQLite authority-store adapter.
- [ ] Route GCB and SwarmExecutor through the single APCC commit path.
- [ ] Run SQLite conformance, contention, crash, recovery, revocation, visibility,
  predecessor, response-loss, and outbox tests.

## PostgreSQL and independent verifier

- [ ] Implement PostgreSQL schema and adapter without weakening APCC semantics.
- [ ] Run the shared conformance suite against a real PostgreSQL 17+ service.
- [ ] Add PostgreSQL CI service/gate configuration.
- [ ] Generate positive and negative cross-language conformance vectors.
- [ ] Implement the standalone Go verifier without Python reuse.
- [ ] Run Go unit, RFC vector, APCC vector, formatting, vet, and static checks.
- [ ] Prove Python/Go agreement on every valid and invalid vector.

## Formal, adversarial, and empirical evidence

- [ ] Implement APCC TLA+ safety model and normal configuration.
- [ ] Implement explicit conditional-liveness assumptions/configuration.
- [ ] Implement five exact non-vacuity witnesses and fail-closed runner.
- [ ] Map every formal invariant/action to implementation tests/anchors.
- [ ] Implement fair B0–B6 baselines.
- [ ] Implement the required attack and recovery matrix.
- [ ] Implement the required ablations.
- [ ] Implement and smoke-test the frozen benchmark harness.
- [ ] Run final attacks, recovery scenarios, ablations, and benchmarks.
- [ ] Validate raw result schemas, counts, seeds, environment, and hashes.

## Research, artifacts, reviews, and handoff

- [ ] Write `APCC-1-Prior-Art.md` from current primary sources.
- [ ] Write `APCC-1-Experiment-Plan.md`.
- [ ] Write `APCC-1-Results.md`.
- [ ] Write `APCC-1-Novelty-Verdict.md`.
- [ ] Add one-command reproduction tooling and artifact manifest.
- [ ] Reviewer A: protocol minimality.
- [ ] Reviewer B: formal correctness and non-vacuity.
- [ ] Reviewer C: cryptographic/canonical/cross-language conformance.
- [ ] Reviewer D: novelty and experimental validity.
- [ ] Remediate and re-review every P0/P1 finding.
- [ ] Run the complete repository/APCC verification matrix.
- [ ] Inspect explicit status, diff stat, diff check, and generated/sealed files.
- [ ] Create scoped local commits; confirm no push, PR, release, or deployment.
- [ ] Issue exactly one evidence-bounded novelty classification and final handoff.

## Durable runtime cost checkpoint — 2026-10-17

Scoped SQLite connection reuse is retained after independent lifecycle review,
four balanced comparisons against the exact original source, 1,000 additional
growing-store operations, independent signed-proof replay, and a fresh full
local gate (3,203 passed, 57 skipped, 95 deselected). The paired mean reduction
was 7.82%, from pooled 120.46 to 111.02 ms. Ordinary native connection lifetimes
remain unchanged; all durable transactions and live proof checks remain.

The [sealed runtime evidence](../experiments/apcc-1/b6-runtime-reuse-20261017/README.md)
retains failed wiring and intermediate controls, including the corrected original
source provenance. All 1,400 final-candidate comparison/growth operations still
exceeded 100 ms. These are diagnostics, not qualification successes. The
earlier qualification attempt recorded 4,972/10,000 and was incomplete. A further pure
certificate-parsing hypothesis was tested separately in four balanced triples
and rejected: effects were mixed and the candidate was slower overall. No
production codec change was retained. The campaign and acceptance checkboxes
above remain open. The owner selected preservation of v3 and continued source
optimization. Private preparation batching, terminal outbox finalization/audit
fusion and private fresh authority commit/claim batching are retained after
independent review and balanced comparisons. The optional new-store GCB admission
index retains strict validation and legacy no-migration behavior; its short-run
comparison was mixed, while the growing-history lookup benefit reproduced.
The final local gate passed with 3,304 tests, 57 skipped and 95 deselected;
all 308 source/test/support pins stayed unchanged. Independent replay passed
7,758 complete diagnostic proofs across separate comparison, wiring, growth,
failed-prefix and instrumented-profile series. The 26 partial rows in the failed
series are unsealed and contribute zero accepted successes. No diagnostic count
is pooled into qualification. Codec changes were restored, and the output-reference
index was deferred for unproven net benefit. Final-source growth averaged
81.6176 ms with 17/1,000 operations at least 100 ms. A fresh unchanged v3 run sealed 9,220/10,000 on-time verified successes,
780 overloads and zero late completions. Original-verifier shard replay passed,
but the gate remains incomplete; operation mean 85.0455 ms, p95 102.5686 ms. All 308
pins stayed unchanged. The separate checkpoint investigation independently
replayed 1,010 trace proofs and 1,636 comparison proofs; these contribute zero
qualification successes. Fixed 128-page checkpoints were slower in all four
blocks; 256 pages had mixed effects and a slightly slower overall mean. Both
were rejected without production changes. All 308 prior gate pins still match.
No checkpoint-causation claim or new qualification attempt follows. Further
source optimization and the fixed v3 gate remain open; every workload, durability,
sink and live proof check remains. See the
[source-optimization evidence](../experiments/apcc-1/b6-source-optimization-20261017/README.md)
and [checkpoint diagnostics](../experiments/apcc-1/b6-checkpoint-diagnostics-20261017/README.md).

## Access-path and W2 continuation — 2026-10-17

Three isolated access-path candidates were measured and rejected: explicit outbox
index hints, checked native lease dispatch, and direct stat. None improved every
balanced block; the dispatch result was effectively neutral. Independent replay
passed 1,636 comparison/wiring proofs and 120 separate profile proofs. These are
diagnostics, never pooled into qualification. At the
[access-path seal](../experiments/apcc-1/b6-access-path-20261017/README.md), production
and all 308 prior gate pins remained unchanged. V3 remains 9,220/10,000.

The next software prerequisite is the explicit authenticated
[W2 causal profile](../docs/internal/APCC-1-W2-Causal-Profile.md): depth 99 for the
100-node chain, default depth 64 unchanged, fixed certificate/byte ceilings,
persisted signed configuration binding, observer launch agreement, and explicit
PostgreSQL exclusion pending parity. A spawned regression exercises 100 distinct
agents, 100 commits, and 100 signed consumable observations. Its proofs do not
qualify concurrency 16, pacing, cache lifecycle, or the operation floor. The
dedicated W2 diagnostic driver now passes 30 tests, including two complete
chains, actual 16-worker admission, overlap, rotation, and strict independent
replay. A separate uninstrumented CLI run and fresh replay passed 100 operations.
The full local gate passed **3,357 tests, 57 skipped, 95 deselected**; all 767
recorded inputs stayed unchanged. Evidence is retained in the
[W2 bundle](../experiments/apcc-1/w2-causal-profile-20261017/README.md).

- [x] Implement and authenticate the explicit SQLite W2 depth profile.
- [x] Complete one-/two-chain W2 diagnostics and relative-path CLI execution.
- [x] Verify independent proof replay, failure cleanup, and the full local gate.
- [ ] Qualify W2 fixed-window pacing, cold/warm lifecycle, and operation floor.
- [ ] Reach the unchanged v3 10,000/10,000 success gate.
- [ ] Prototype and measure the reviewed
  [fresh-provisioning source candidate](../docs/internal/APCC-1-Fresh-Provisioning-Candidate.md).

The broader workload, PostgreSQL, campaign, ablation, and final-review gates stay
open. Diagnostic successes do not advance qualification counts.

## W2 fixed-window functional implementation — 2026-10-17

- [x] Add versioned private scheduler routing for16 genuine workflow projections
  on the existing authenticated execution handle/channel.
- [x] Implement explicit fixed-window node slots, causal admission, real permit
  deadlines, overload/late accounting, and complete-only lane rotation.
- [x] Implement bounded same-handle cold/warm continuation with isolated ledgers,
  fresh clock epochs, continuous observation replay and separate repetition stores.
- [x] Extend independent CLI accounting/proof replay, campaign mutation tests and
  real16-permit cancellation/observer-crash cleanup checks.
- [x] Audit all8 valid ledgers and6 repetition manifests in fresh CLI processes
  using external SHA256 pins; reject all4 failed prefixes.
- [x] Pass the full local gate:3,444 passed,57 skipped,95 deselected;777 final
  input pins unchanged. Preserve all12 prior bundles/589 sealed entries;766 of
  prior767 inputs unchanged, with only private scheduler routing versioned.
- [x] Prepare and independently review the separate
  [observer-renewal protocol draft](../docs/internal/APCC-1-W2-Observer-Renewal-Protocol-Draft.md).
- [x] Implement and verify an approved renewal protocol before long warm cells;
  the existing1,200-second launch cap remains enforced.
- [x] Approve and freeze explicit campaign parameters (2026-10-18).
- [ ] Execute/audit/seal complete frozen qualification cells. The first numeric
  attempt is fatal; see the dated renewal continuation below.

[Current functional evidence](../experiments/apcc-1/w2-campaign-20261017/README.md)
records100 cold/100 warm CLI commits, a200-commit two-chain window and natural
16-permit overload stress. These separate denominators produce zero campaign
qualification successes. W1 v3, PostgreSQL W2 rejection, the public B6 adapter,
W6 composition and the design-only fresh-provisioning candidate remain unchanged.

## W2 observer renewal and first numeric attempt — 2026-10-18

- [x] Implement scoped epoch keys, durable signed renewal journal, authority
  admission fencing, predecessor continuity and complete-proof permit retention.
- [x] Complete eight failure cases and 16 fresh CLI checks; preserve rejected
  earlier source variants and exact owned-resource cleanup evidence.
- [x] Execute cold conditioning plus four real 1,000-second warm windows:
  1,700 verified operations, four renewals, zero overload/late under functional
  5-second SLA and 10-second handover limits. Audit all five windows and the
  repetition in fresh processes; seal the [Phase 1 capsule](../experiments/apcc-1/w2-renewal-20261018/README.md).
- [x] Pass numeric generation `make verify`: 3,771 passed, 57 skipped,
  103 deselected; all 979 gate inputs unchanged.
- [x] Execute the first frozen cold 10/s cell and stop on its first admission
  rejection: 66 on-time commits, one overload, zero late completions,
  9,933 unexecuted slots; no qualified cell.
- [x] Preserve the original numeric verifier initialization failure; add a
  separately pinned read-only auditor that verifies the fatal prefix and rejects
  a success request. All 12 focused checks and independent review pass.
- [x] Finish the additive auditor full gate: 3,774 passed, 66 skipped,
  103 deselected; all 981 gate inputs / 805 primary inputs unchanged. Seal and
  checksum-verify the [numeric failure capsule](../experiments/apcc-1/w2-numeric-cold-20261018/README.md).
- [ ] Qualify the numeric campaign. The remaining 344 windows are unexecuted,
  and numeric warm execution is not implemented in this first-cell slice.

The [implementation record](../docs/internal/APCC-1-W2-Renewal-Implementation-2026-10-18.md)
distinguishes functional timing, numeric timing, controller accounting and
authority proofs. No cross-window pooling or threshold relaxation is applied.
