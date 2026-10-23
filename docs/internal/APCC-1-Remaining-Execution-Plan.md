# APCC-1 remaining execution plan

## Status and boundary

This plan covers the remaining software and campaign work after the reviewed
matrix-v2 duration and trusted-observation changes. Ordinary local implementation
has no external-authority blocker. On 2026-10-16 the owner authorized preparation
of a reviewed 10,000-node W6 protocol revision. Its additive runtime profile is
implemented and locally qualified after security fixes, independent review,
and a successful final repository gate; see the
[W6 protocol checkpoint](APCC-1-W6-Protocol-Revision.md#qualification-checkpoint--2026-10-16).
The default 1,000-node profile remains unchanged. This authorization does not
change a frozen v1/v2 artifact or close the empirical campaign.

Complete-only workflow rotation and the bounded SQLite/W1 B6 supervisor are
now implemented in the additive qualification-v3 path. Steps 1–4 below describe
the implemented software contract. Their measured software-qualification gate
still requires a separately replayed shard with at least 10,000 on-time
verified successes; implementation and smoke tests do not satisfy it. See the
[B6 supervisor checkpoint](APCC-1-B6-Supervisor-Checkpoint-2026-10-16.md) for
current review, validation, and measurement status.
The first measured attempt failed before the fixed window completed and is
retained separately. After reviewed transport/replay fixes and a passing final
local gate, the second attempt ran through the fixed window and sealed 4,972
on-time verified successes from 10,000 scheduled arrivals. Independent shard
replay passed, but the strict 10,000-success floor remains unmet.

The 2026-10-17 cost investigation retained bounded connection reuse only inside
isolated SQLite authority/observer children, preserving ordinary native
connection lifetimes. Four balanced pairs against the exact original source
improved mean operation time from 120.46 to 111.02 ms (7.82% mean paired
reduction). A separate 1,000-operation growing-store run and independent replay
passed. The fresh full local gate passed with 3,203 tests, 57 skipped and 95
deselected. See the [sealed runtime checkpoint](../../experiments/apcc-1/b6-runtime-reuse-20261017/README.md).

A further exact-byte certificate-decoding cache was tested in four balanced
triples, with an unwrapped control and a cache-disabled wrapper. Its effects
were mixed and it was slower overall; it was rejected without production codec
changes. See the [decoder diagnostic](../../experiments/apcc-1/b6-codec-profile-20261017/README.md).
All measured candidate operations in both investigations still exceeded 100 ms.
No new qualification run was attempted and diagnostic successes are not pooled
with the historical shard. The fixed 1,000-second, 10-arrivals/second gate has
exactly 10,000 arrivals, leaving no allowance for drops or late completions.
The owner subsequently selected **preserve v3 and continue source optimization**.
No changed criterion, resource substitution or longer observer lifetime is
approved by that choice. Four balanced source comparisons retained private GCB
preparation batching: 400 operations per arm averaged 114.6281 ms before and
95.7991 ms after, with all four pairs improving 14.22–20.47%. Independent replay
passed all 1,600 measured and 12 wiring proofs. The codec duplicate-walk candidate
was rejected for mixed effects and its source restored. Batch-only still had
84/400 operations at or above 100 ms; these diagnostics do not qualify v3.
Terminal outbox finalization/audit fusion and private fresh authority commit/claim
batching were subsequently retained after independent review, fault/replay tests,
four balanced comparisons each and growing-store checks. A precisely validated
optional GCB admission index is provisioned for new stores; legacy stores open
without migration. Its short-run comparison was mixed (three improvements, one
regression); its growing-history query access path reproduced independently.
The final full local gate passed with 3,304 tests, 57 skipped and 95 deselected,
with all 308 source/test/support pins unchanged. The final separate 1,000-operation
growing-store diagnostic averaged 81.6176 ms, p95 95.2719 ms, with 17 operations
at least 100 ms. All 7,758 complete diagnostic proofs replayed independently,
including an explicitly separate aborted-series prefix and instrumented profile;
none count toward qualification. The APCC output-reference index was deferred
because its net whole-operation benefit is unproven. A fresh unchanged v3
qualification sealed 9,220 on-time verified successes from 10,000 scheduled
arrivals, with 780 overloads and no late completions. Separate original-verifier
shard replay passed, but the 10,000-success gate remains unmet. Its measured
operation mean was 85.0455 ms, p95 102.5686 ms. All source/support pins stayed
unchanged. A separate checkpoint investigation replayed 1,010 traced proofs and
1,636 policy-comparison proofs. Fixed 128-page checkpoints were slower in every
block; 256-page results were mixed and slightly slower overall. Both were
rejected without production changes. All 308 prior gate pins matched at that seal. The
trace cannot attribute long synchronization calls to checkpoints. Outbox query
hints and path-wrapper changes lack a demonstrated net whole-operation gain.
No further qualification attempt was made. The original campaign retains its
1,000-page setting; further source optimization and the fixed v3 gate remain open.
See the [source-optimization evidence](../../experiments/apcc-1/b6-source-optimization-20261017/README.md)
and [rejected checkpoint diagnostics](../../experiments/apcc-1/b6-checkpoint-diagnostics-20261017/README.md).

A further balanced comparison rejected all three access-path candidates:
explicit outbox index hints, checked native lease dispatch, and direct `os.stat`.
Each arm measured 400 operations; mean operation times were 83.0961 ms for the
control, 87.2138 ms for index hints, 83.0918 ms for dispatch, and 86.7506 ms for
direct stat. None improved all four blocks. Independent original-verifier replay
passed 1,636 comparison/wiring proofs and 120 separate profile proofs, including
ten retained proofs from an unsuccessful instrumentation capture. These add zero
qualification successes. The [sealed access-path evidence](../../experiments/apcc-1/b6-access-path-20261017/README.md)
contains the rejected variants and exact source provenance. Production and all
308 prior gate pins were unchanged when that evidence was sealed.

The current software slice adds an explicit, authenticated SQLite
[W2 causal profile](APCC-1-W2-Causal-Profile.md). Default depth remains 64; W2
selects depth 99 for its 100-node chain while retaining certificate and byte
ceilings. This changes the current source identity after the optimization seal.
It does not change v3, activate the public B6 adapter, or qualify the W2 workload.
The separate [W2 diagnostic driver](APCC-1-W2-Diagnostic-Driver.md) implements
real bounded 16-worker admission, ordered coherent observation, exact payloads,
two-chain rotation, and controller-sealed independent proof replay. Its final
relative-path suite passed 30 tests, including 200 genuine operations and
semantic tampering. A separate uninstrumented CLI run and fresh process replay
passed 100 operations. Both report actual occupancy 3/16 and remain noncampaign.
The fixed v3 gate and W2 workload qualification remain open. The
[fresh-provisioning candidate](APCC-1-Fresh-Provisioning-Candidate.md) is the next
bounded v3 source hypothesis; its inferred transaction saving is unmeasured and
has not been implemented or adopted.

The W2-inclusive full local gate passed **3,357 tests, 57 skipped, 95 deselected**;
all 767 selected source/test/support pins stayed unchanged. The
[W2 evidence bundle](../../experiments/apcc-1/w2-causal-profile-20261017/README.md)
preserves the relative-path startup failure, repaired contract test, accepted
proof ledgers, distinct historical source capsule, and final validation. These
local results do not replace the measured qualification gates.

The retained measurement contract requires at least 10,000 completed operations,
uses `max(30, ceil(10000 / target_rate_per_second))`, and keeps underfilled runs as
incomplete evidence rather than extending or relabelling them
([measurement revision](APCC-1-Measurement-Revision-v2.md#decision-and-scope)).
The unchanged workload matrix also fixes topology, concurrency, seeds, cache
state, mutation schedules, and store coverage
([experiment plan](APCC-1-Experiment-Plan.md#frozen-workload-matrix)).

## Current evidence and gaps

- **Trusted observation exists for committed operations.** The execution handle
  exposes an exact-request `observation_target` RPC in
  [`authority_service.py`](../../src/constitutional_swarm/authority_service.py).
  The spawned-path
  test verifies a signed observation, current consumability, authority proof, and
  output digest in
  [`test_apcc_observation_target.py`](../../tests/test_apcc_observation_target.py).
  The same test
  proves denied and uncommitted requests have no observation target
  after denial. A legacy `DENIED` decision therefore must not be reported as an
  observed `APCC_DENIED` outcome.
- **The B6 supervisor is implemented for SQLite/W1/cold.**
  [`qualification_v3.py`](../../src/constitutional_swarm/apcc_empirical/qualification_v3.py)
  composes the exact spawned execution handle with signed, sequential observer
  verification and exact request/output binding. Public B6 remains inert in
  [`adapters.py`](../../src/constitutional_swarm/apcc_empirical/adapters.py).
  The [v3 protocol](APCC-1-Qualification-Live-Protocol-v3.md) keeps unsupported
  cells rejected and smoke output outside matrix evidence. The full-window
  second attempt produced 4,972 on-time verified successes, leaving the
  10,000-operation measured gate unmet.
- **Complete-only repeated workflows are implemented.** `SwarmExecutor.load_dag`
  in [`swarm.py`](../../src/constitutional_swarm/swarm.py) requires authoritative
  completion of the old workflow and fully validates the replacement before
  swapping local state. The spawned dispatcher rejects stale workflow
  operations while retaining exact historical observation targets. Tests in
  [`test_apcc_workflow_rotation.py`](../../tests/test_apcc_workflow_rotation.py)
  cover atomic rejection and signed observations from successive one-node
  workflows; inflating a single DAG is not used as a W1 substitute.
- **The W6 node-profile path is locally qualified; the workload is pending.** The additive
  `w6-independent-10000-v1` profile supports admission of up to 10,000 independent
  nodes, while the default profile retains its 1,000-node limit. Persisted
  admission-profile authentication and tamper rejection are covered by the
  reviewed implementation and targeted tests. The final local gate passed
  with 3,031 tests; see the
  [qualification evidence and limits](APCC-1-W6-Protocol-Revision.md#qualification-checkpoint--2026-10-16).
  Admission and representative commits do not qualify the frozen workload's
  1,000 logical agents, concurrency 100, or exactly 10,000 commits. Segmentation
  remains an invalid substitute for its single DAG.
- **The trusted PostgreSQL writer path is missing.** `AuthorityChildConfig`
  carries a filesystem `database_path` and the child provisions or opens that
  path through `TrustedGovernanceBootstrap` in
  [`authority_child.py`](../../src/constitutional_swarm/authority_child.py). The
  observer in
  [`authority_service.py`](../../src/constitutional_swarm/authority_service.py)
  can read either SQLite or PostgreSQL, but this
  does not provide a spawned PostgreSQL authority writer/executor. Green
  PostgreSQL store tests do not close that integration gap.
- **Higher workload concurrency is not yet demonstrated.** Scheduler RPCs
  serialize on one execution-handle lock in `authority_service.py`, and executor
  operations use one `SwarmExecutor` lock. W1's concurrency-one vertical does
  not qualify higher-concurrency workloads. Dedicated reviewed
  drivers are still required for concurrency 16/100, W5 simultaneous contention,
  and W7-W9 update, revocation, and replay schedules.
- **A campaign must be restartable in bounded units.** `RawArtifactWriter`
  in [`artifacts.py`](../../src/constitutional_swarm/apcc_empirical/artifacts.py)
  accepts a frozen-order planner subsequence, validates and fsyncs every appended
  row, and refuses to finalize a declared unit missing required rows. The v3
  supervisor uses one exact repetition per shard and independently replays its
  ledger through `verify_shard`. An underfilled duration can have a complete,
  valid artifact containing `incomplete_run: true`; valid packaging does not
  mean the operation floor passed. This does not justify one months-long run.
- **The resource floor is material.** Ordinary and ablation duration cells alone
  schedule 11,513,600 seconds, approximately 133.259 sequential days; ideal W6
  time adds about 11.926 days before setup, storage, security, parser, and formal
  work ([measurement revision](APCC-1-Measurement-Revision-v2.md)). Parallel
  allocation must be isolated and recorded before data collection.

## Staged implementation and remaining work

Steps 1–4 are implemented for the bounded v3 selection. Their measured
acceptance gate remains distinct from code completion; see the checkpoint.
Steps 5–8 remain open.

1. **Complete-only workflow rotation — implemented.** Allow the trusted executor to attach
   a different, already provisioned workflow only after authoritative state says
   the current DAG is complete. Validate the replacement before swapping local
   projections. Reject incomplete rotation, missing workflows, topology changes,
   and old-workflow requests. Prove through the spawned dispatcher that commits
   from both workflows retain independently signed, consumable observations.
2. **SQLite/W1 qualification-v3 vertical — implemented.** Keep the public B6
   adapter inert. A supervisor owns authority/admin, observer/controller, and
   producer keys; starts the observer before the scheduler; provisions a fresh
   one-node workflow per proposal; and records commit and observation timings
   separately. Smoke output is explicitly non-evidence.
3. **Authoritative completion semantics — implemented.** Count a completed B6 operation
   only when the real commit is `COMMITTED`, the exact observation target resolves,
   the signed observation verifies in sequence, current status is consumable,
   authority proof is present, and observed output bytes match the committed
   digest. Record attempts separately. Require at least 10,000 such verified
   successes for a complete duration cell; otherwise retain `incomplete_run: true`.
4. **V3 evidence shards — implemented.** Select exact frozen planner subsequences and
   finalize one bounded artifact shard per cell/repetition. Each shard pins the
   matrix/schema, environment, Git SHA, tools, and trial order. Aggregate only
   independently validated shards; never pool different matrix hashes.
5. **Implement workload-specific drivers.** W2 now has an explicit authenticated
   SQLite depth profile and a functional one-/two-chain diagnostic driver; its
   fixed-window pacing, cold/warm lifecycle and operation-floor qualification
   remain open. Add W2-W5 and W7-W10 only after each
   driver demonstrates its frozen topology, agent count, concurrency, pacing,
   cache state, and mutation/retry schedule. Unsupported cells stay explicitly
   blocked or not run; they do not receive synthetic raw rows.
6. **Add the spawned PostgreSQL authority backend.** Introduce an explicit child
   backend configuration and least-privilege credential transfer for the writer,
   then run the same supervisor, observation, negative-path, and semantic-parity
   checks as SQLite. PostgreSQL observer support alone is insufficient.
7. **Implement and qualify the W6 workload driver.** The additive
   [node-profile revision](APCC-1-W6-Protocol-Revision.md) is implemented and
   locally verified, including authenticated persisted-profile binding, tamper
   rejection, default-profile compatibility, bounded transport, coherent status
   reads, spawned integration, and independent review. Implement and qualify the
   driver against the unchanged W6 topology, logical-agent assignment,
   concurrency, and operation count. Do not substitute admission tests or
   representative commits for a full W6 run.
8. **Launch the campaign only after software qualification.** Freeze environment
   identities, host/resource allocation, shard schedule, baseline/store ordering,
   and failure-retention rules. Run the planned campaign and ablations, then
   perform analysis and independent reviews. Software readiness is not campaign
   completion.

## Acceptance and stop rules

The software phase is ready for campaign execution only when the SQLite/W1 v3
vertical produces a schema-valid shard with at least 10,000 independently
verified successful operations, workflow rotation and denial boundaries pass
spawned integration tests, frozen artifacts are unchanged, and every unsupported
store/workload is explicitly blocked. Stop rather than publish a completion claim
for any invalid authoritative commit, missing observer proof, Python/Go mismatch,
store semantic divergence, topology/concurrency substitution, incomplete shard,
or unrecorded resource allocation.

The full APCC-1 empirical milestone remains partial until the PostgreSQL trusted
path, W6 workload qualification, all workload drivers, the complete campaign,
ablations, and independent reviews are finished.
