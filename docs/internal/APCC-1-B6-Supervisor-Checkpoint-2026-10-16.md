# APCC-1 B6 supervisor checkpoint — 2026-10-16

## Status and boundary

Complete-only workflow rotation and the additive qualification-v3 SQLite/W1
supervisor implement steps 1–4 of the
[remaining execution plan](APCC-1-Remaining-Execution-Plan.md). The public B6
adapter remains inert. This checkpoint records implementation and local
validation separately from the required 10,000-operation measured qualification.
The first measured attempt **failed** before its fixed window completed. The
second attempt ran through its fixed 1,000-second window and sealed a ledger
with **4,972 on-time verified successes**. It is **incomplete** against the
strict 10,000-operation floor; independent shard replay passed. The software
is implemented and reviewed, but neither measured qualification nor the APCC-1
campaign is complete.

The [v3 protocol](APCC-1-Qualification-Live-Protocol-v3.md) and
[declarative record](../../experiments/apcc-1/qualification-live.v3.json) were
prepared before measurement and are now preserved unchanged. Historical v1/v2
artifacts and the [W6 qualification report](APCC-1-W6-Protocol-Revision.md)
remain separate evidence. The bundle for this checkpoint is
[`experiments/apcc-1/b6-supervisor-20261016/`](../../experiments/apcc-1/b6-supervisor-20261016/README.md);
its [`qualification.json`](../../experiments/apcc-1/b6-supervisor-20261016/qualification.json)
is the evidence index. It retains both measured attempts, public proof ledgers/shards,
rehearsals, diagnostics, and the corresponding source archives.

## Implemented behavior

- `SwarmExecutor.load_dag` in
  [`swarm.py`](../../src/constitutional_swarm/swarm.py) allows trusted rotation
  only after authoritative completion of the current workflow. It validates the
  entire replacement before swapping state. Failed attachment leaves the prior
  workflow usable; stale workflow operations are rejected through the spawned
  dispatcher in
  [`authority_service.py`](../../src/constitutional_swarm/authority_service.py).
  Exact historical observation targets remain independently verifiable.
- [`qualification_v3.py`](../../src/constitutional_swarm/apcc_empirical/qualification_v3.py)
  provisions a unique one-node workflow per W1 proposal, starts the observer
  before the scheduler, and counts only on-time commits with exact signed
  observation, authority certificate/status/output proof, and verified canonical
  payloads. Missed arrival slots are dropped rather than caught up or used to
  extend the fixed deadline.
- [`run_apcc_qualification_v3.py`](../../scripts/run_apcc_qualification_v3.py)
  exposes `smoke`, `run`, and `verify`. It records actual source/environment
  provenance, refuses existing output paths, and accepts only the bounded
  SQLite/W1/cold planner selection for qualification. Smoke remains non-evidence.
- A signed operation ledger and schema-validated single-repetition raw shard
  support replay and restart into new output paths. Underfilled runs retain
  `incomplete_run: true`; packaging validity does not imply the operation floor
  passed.

Independent review identified three issues addressed before measurement:
bounded observer launch lifetime sufficient for the fixed window, exact receipt
binding in proof replay, and binding raw-row validation to the same bytes read
for reconstruction. Final independent source review found all three issues
resolved, with 19 additional regression cases. The lifetime default remains 300,000 ms, bounded
strict-integer overrides stop at 1,200,000 ms, and live verification retains the
real clock and 5,000-ms status freshness.

Subsequent investigation independently reproduced observer and scheduler exit
after three seconds of idle time. The transport fix waits for socket readiness
before receiving a new frame; the existing two-second timeout remains fatal
for a stalled partial frame. Two regression tests and independent review cover
that distinction. This reproduced defect is not proof of the first measured
attempt's exact failure cause.

Ledger replay also validates the legacy GCB verdict's scoped policy signature,
ALLOW decision, identity, digests, store binding, generation, and recorded-time
validity. This establishes a valid bound verdict in the sealed ledger. It does
not prove byte identity with the historical verdict used at commit time through
the persisted APCC proof.

## Validation checkpoint

Targeted results and repository-gate history:

- 93 B6 supervisor tests passed after the subsequent fixes in
  [`test_apcc_qualification_v3.py`](../../tests/test_apcc_qualification_v3.py).
- 31 workflow-rotation tests in
  [`test_apcc_workflow_rotation.py`](../../tests/test_apcc_workflow_rotation.py).
- Final `make verify`: **3,155 passed, 57 skipped, 95 deselected in 222.64
  seconds**, exit 0. This includes the subsequent transport and verdict-replay
  fixes and supersedes the earlier 3,141-test gate.

Final independent review reran all **124 targeted tests in 32.21 seconds**, with
passing style checks and isolated-wheel checks on Python 3.13 and 3.11. It
accepted the verdict's 12 negative cases and the two transport regressions,
and reported zero source/lock drift. Three fresh repaired-build smoke rehearsals
and their replays passed before the second attempt. Independent measured-shard
replay passed. All 151 archived source files and all 141 runtime source files
matched their pins, including the restored baseline lockfile. Exact command logs
and source/evidence hashes are retained in the checkpoint bundle.

## Measurement checkpoint

The first planned attempt selects
`aOm0qaWqGRH-Iw_bEjgs2C_sRyfmnj71qG2He0omIzs`: B6/SQLite/W1/cold, seed 104729,
repetition 0, 10/s, fixed 1,000 seconds, and at least 10,000 on-time verified
successes. Three separate fresh-database smoke rehearsals and any pilot remain
diagnostics. None contributes operations to this measured repetition.

The first attempt aborted after approximately **39.47 seconds**, with **169
admitted and committed operations, 168 verified**, and `authority_unavailable`
while observing the next committed operation. Its exact cause remains unproven.
This is failed execution, not a completed underfilled duration shard. Original
pins, ledger, database, and diagnostics are retained; it does not qualify.

A subsequent source-unchanged diagnostic verified **500 operations in 67.72
seconds**. That smoke result cannot replace the failed measurement or count
toward its operation floor.

The second attempt sealed the following terminal counts for the same selected
cell in a new run with its own source and environment pins:

| Measurement | Result |
| --- | ---: |
| Scheduled arrivals | 10,000 |
| Admitted operations | 4,973 |
| Committed operations | 4,973 |
| On-time verified successes | 4,972 |
| Dropped arrivals / overload | 5,027 |
| Post-deadline completion excluded | 1 |
| Actual elapsed time | 1,000.034219945 seconds |
| `incomplete_run` | `true` |

No operation was admitted after the 1,000-second deadline. The last admitted
operation finished late and was excluded from the success count; actual
elapsed time records that completion rather than claiming the measurement
window was extended. Raw-shard finalization and the runner's replay completed:
CLI exit **2**, status `incomplete`, and `shard_verified: true`. The sealed ledger
SHA-256 is
`71848c347edd9dda76872cc08cb2cda31c45ad4fc0de9c3e66cd823415e88aad`.
Independent replay also passed with exit **2**, `shard_verified: true`, and
4,972 verified successes. A direct audit confirmed 4,973 distinct workflow IDs,
commit IDs, nonces, and arrival slots; 4,972 on-time completions; one excluded
late completion; 5,027 overloaded arrivals; and zero post-deadline admissions.
The strict 10,000-success floor is not met despite valid packaging and replay.
Counts from the failed attempt or smoke runs are not combined with this
measurement.

Median operation duration was **132.761 ms**, with **155.636 ms p95**. Median
components were 42.034 ms before commit, 72.969 ms committing, 10.068 ms observing,
and 6.225 ms verifying proof. These component medians are descriptive and need
not sum to the median total. At a 100-ms arrival interval, these observed costs
explain the material throughput gap under this recorded host and storage
configuration; they do not isolate a unique optimization or establish results
on another environment.

Testing unexpectedly regenerated `uv.lock`. The regenerated copy and forensic
evidence were preserved, then the exact baseline lockfile was restored. The
failed attempt retains its actual regenerated-lock pin; its source identity is
not rewritten to the restored baseline. The frozen v3 protocol and declarative
record remain unchanged. The second attempt has separate complete source and
environment pins, with the restored baseline lockfile. Its source archive
contains 151 files (899,181 bytes).

The environment must identify the actual host/source and durable file-backed
SQLite WAL/FULL storage. Local host differences or concurrent user workloads
must be disclosed; no exclusive-host or frozen-campaign-baseline claim follows
from this software qualification.

## Remaining acceptance and campaign work

The reviewed implementation and final local tests passed. The measured software
acceptance gate remains **unmet** because the second attempt produced 4,972
on-time verified operations against the strict 10,000 floor. A valid replayed
incomplete artifact preserves the result; it does not satisfy that gate or
authorize a campaign-completion claim.

The next concrete implementation work is performance profiling of durable
commit and provisioning costs to reach the unchanged 10,000-success floor within
the fixed window. Preserve durability and proof checks while investigating the
throughput gap.

Trusted PostgreSQL authority writing, W2–W10 workload-specific execution
(including W6's full topology/concurrency), warm cells, ablations, all remaining
matrix repetitions, comparative analysis, and final empirical review remain
outside this bounded implementation. The full APCC-1 milestone remains partial.

## Continuation — 2026-10-17

The later unchanged-v3 attempt in the
[source-optimization evidence](../../experiments/apcc-1/b6-source-optimization-20261017/README.md)
sealed **9,220/10,000** on-time verified successes, 780 overloads, and no late
completions. Original-verifier replay passed; the qualification gate remains
unmet. Subsequent checkpoint and access-path comparisons produced no retained
optimization and no newer qualification attempt. The
[access-path evidence](../../experiments/apcc-1/b6-access-path-20261017/README.md)
separately replays 1,636 comparison/wiring proofs and 120 profile proofs; none
count toward v3. All three access-path candidates were rejected.

The next implementation slice enables the frozen W2 chain's causal depth through
an explicit authenticated [SQLite profile](APCC-1-W2-Causal-Profile.md), preserving
the default depth and every v3 criterion. The spawned 100-agent chain regression
verifies all 100 signed observations. The separate
[W2 diagnostic driver](APCC-1-W2-Diagnostic-Driver.md) now passes functional
capacity, exact-payload, two-chain rotation, and ledger replay checks: 30 tests,
200 genuine operations, and a separate uninstrumented 100-operation CLI run with
fresh process replay. Both recorded occupancy 3/16. Fixed-window pacing, warm
lifecycle, and workload qualification remain open. No current diagnostic
activates the public B6 adapter or closes the wider campaign.
