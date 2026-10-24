# APCC-1 qualification-live protocol v3

Protocol ID: `apcc-1.qualification-live.v3`. Prepared on 2026-10-16 before
the v3 measured run. This document and the accompanying
[declarative protocol record](../../experiments/apcc-1/qualification-live.v3.json)
specify the SQLite/W1 supervisor qualification. Retain their SHA-256 hashes in
the execution evidence before measurement; independent review and measured
results belong in a separate checkpoint. This document asserts no successful
measurement or campaign completion.

## Scope and implementation

The implementation is
[`qualification_v3.py`](../../src/constitutional_swarm/apcc_empirical/qualification_v3.py),
with CLI
[`run_apcc_qualification_v3.py`](../../scripts/run_apcc_qualification_v3.py).
It adds the bounded vertical in steps 1–4 of the
[remaining execution plan](APCC-1-Remaining-Execution-Plan.md).
The existing v1/v2 qualification protocols, runners, configurations, matrices,
schemas, and evidence remain historical artifacts. V3 neither repairs their
rows retrospectively nor closes either frozen campaign.

`select_run` accepts an exact planner identity from `matrix.v2.json` only when
it denotes B6, SQLite, W1, cold cache, measured phase, a 1,024/4,096-byte payload
pair, and no ablation. It retains the selected seed, repetition, trial index,
sub-seed, rate, and duration. The planner supplies rates 10, 100, and 500/s,
five seeds, and ten measured repetitions; support for selection does not imply
that any of these cells has been completed. PostgreSQL, warm cache, W2–W10,
other baselines, ablations, and unknown trial identities fail before child
launch. There is no qualification operation-count or duration override.

The first qualification attempt is the 10/s, seed 104729, repetition 0 cell:
`aOm0qaWqGRH-Iw_bEjgs2C_sRyfmnj71qG2He0omIzs`.
Its fixed duration is 1,000 seconds and its completion floor is 10,000 verified
operations. A single repetition cannot establish the complete ten-repetition
cell or any comparison against B5.

The protocol JSON is a declarative premeasurement record, not executable CLI
configuration. The runner obtains executable selection and validation rules
from the pinned matrix/schema and its source; archive all of these identities
together.

## Runtime and workflow rotation

Each run creates a fresh SQLite database, private execution directory, and
fresh per-role signing keys. The supervisor starts the authority and observer
before starting the scheduler, pins the observer launch to its controller and
scoped public trust, and removes private key source files before scheduler
launch. Retained evidence contains public verification material, not private
keys. Record the storage filesystem, hardware/resource allocation, concurrent
load, operating system, and durability settings in the supplied environment.
The CLI adds actual Git HEAD, dirty-state indication, source-file hash manifest,
platform, and tool versions; a dirty checkout's Git SHA alone is insufficient
source provenance.

Observer launch lifetime is bounded explicitly by
`AuthorityObserverLaunchConfig.launch_lifetime_ms`: the default is 300,000 ms,
and only strict integers from 1 through 1,200,000 ms are accepted. The supervisor
selects `max(300000, duration_seconds * 1000 + 100000)`, yielding 1,100,000 ms
for the first 1,000-second run. Before starting the measurement clock, it checks
that the signed launch has enough remaining coverage for the entire window.
Ledger replay checks that its signed interval matches the selected lifetime.
This changes neither the default
launch lifetime nor the 5,000-ms status freshness requirement. Live proof
verification continues to use the real clock; it does not backdate observations
to keep an expired launch valid.

Measurement uses a durable file-backed SQLite database with WAL journaling and
FULL synchronization. A tmpfs database is not a substitute. The qualification
host may differ from the frozen campaign baseline: record the actual kernel,
source, filesystem, and load without claiming a dedicated or exclusive host.
This is local software qualification under its recorded environment; it does
not transfer results to a different campaign baseline.

W1 uses one producer identity, concurrency one, and a new independently
provisioned one-node workflow for every admitted proposal. Signed admin
provisioning and registration precede scheduler attachment. The existing
trusted execution handle is used through B6 `execute_trusted`; public B6
`execute` remains inert. An arbitrary caller-supplied handle is not sufficient.

Complete-only rotation is implemented by `SwarmExecutor.load_dag` in
[`swarm.py`](../../src/constitutional_swarm/swarm.py) and dispatched through
[`authority_service.py`](../../src/constitutional_swarm/authority_service.py).
It reads the whole current workflow's authoritative state, requires every
node to be governed-committed, and validates the already provisioned replacement
before atomically replacing local projections. Failed rotation preserves the
old executor state. Stale claim, produce, request-build, and commit operations
are rejected after rotation. Exact persisted observation targets remain
available for historical commits; their consumability still depends on current
authority status. Rotation does not promise immunity to later revocation.

The input size is the complete canonical node-input object, including node
metadata. The output size is the complete canonical `Artifact` object. Padding
only a text field to these sizes would violate the workload. `build_payloads`
constructs exactly 1,024 canonical input bytes and 4,096 canonical output bytes.

## Cold cache and rehearsals

The original experiment prose specifies three warmups globally. The executable
matrix contract schedules three warmups only for warm cells and rejects
pre-run queries or warmup counts for cold cells. V3 follows that executable cold
contract: each measured run has a new database and process set,
`pre_run_queries: 0`, and `warmup_runs_completed: 0`. Required schema creation
and secure authority/observer bootstrap reads are disclosed separately; this
is not a claim to flush operating-system or hardware caches.

Before the first measured attempt, retain three separate fresh-database smoke
rehearsals. They are diagnostics, produce no matrix raw rows, and do not become
warmup evidence for the measured database. A larger smoke pilot may assess
growing-store cost, also without contributing measured operations. Smoke accepts
1–1,000 operations and is always explicitly non-evidence.

## Pacing, timing, and completion

The matrix-v2 duration is `max(30, ceil(10000 / target_rate_per_second))`:
1,000, 100, and 30 seconds for 10, 100, and 500/s respectively. The measurement
clock starts after process bootstrap and before the operation loop. Each slot
has a scheduled arrival derived from its index and rate. The single executor
sleeps until the next admitted slot; arrivals missed while it is busy are
dropped and counted as overload. It does not catch up with a burst or extend
the window to achieve the completion floor.

Per-operation elapsed timing includes provisioning, rotation, claim,
production/staging, commit, observation-target resolution, signed observation,
and proof verification. Commit and observation timestamps are retained
separately. Startup is outside this operation window; retained environment and
bootstrap disclosures identify that boundary. A final operation may finish
after the deadline, but cannot count toward the floor. The supervisor admits
no new operation at or after the deadline and preserves the actual elapsed
time, including any late completion.

A counted operation requires all of the following:

- The real trusted commit outcome is `COMMITTED`.
- The exact request resolves to its workflow, node, attempt, and commit
  observation target with a fresh nonce.
- The signed observer launch and response verify against pinned controller,
  run identity, launch expectations, scoped trust, and monotonically ordered
  observation stream.
- The snapshot is committed, currently consumable at observation time, and
  supplies `AUTHORITY_CERTIFICATE_STATUS_OUTPUT` proof.
- All observed output bytes match the expected canonical payload and committed
  digest, and the receipt binds the expected canonical input digest.
- Proof verification finishes strictly before the fixed deadline.

Scheduled, admitted, committed, verified, and overloaded counts are retained
separately. Underfilled fixed-window runs retain `incomplete_run: true` and
`INCOMPLETE_RUN`; they are not retried inside the same window. A denial, missing
target, or failed proof stops qualification and retains diagnostics. A legacy
`DENIED` outcome is never relabelled as an observed `APCC_DENIED`. Interrupted or
failed execution cannot produce a successful finalized shard.

## Replay and bounded evidence

Each output path must be new. A qualification run produces one planner
repetition under `shard/` using `RawArtifactWriter`, plus its execution ledger
under `execution/ledger.jsonl`. A smoke ledger is directly under its output
directory. The canonical JSONL ledger records the signed launch, public trust,
environment and source provenance, unique workflow/commit identities, request
hashes, nonces, signed observations, operation clocks, and counts. A signed
terminal seal binds the entire preceding ledger. Missing, truncated, reordered,
duplicated, or modified entries must fail replay.

`verify_shard` reads the schema-validated raw artifact, binds the raw row's
`artifact_sha256` to the ledger, verifies every signed proof, and reconstructs
the exact raw row from the replayed counts and planner identity. It checks
matrix/schema and environment/source provenance against the shard manifest.
Verification uses each recorded observation verification time, bounded against
the recorded run clock, so later replay does not expire a valid historical
measurement. Historical replay establishes consumability at the recorded time,
not present-day consumability after possible revocation.

The ledger's public keys and seal alone do not independently attest to the
operator or host: preserve an external evidence manifest with the ledger/shard,
source, and protocol hashes. An unanchored smoke-ledger replay is a consistency
check and never qualification evidence. Retain failed/interrupted ledgers and
`failure.json` diagnostics where produced, without inventing missing raw rows.
Resume by selecting a new exact planner repetition/output path; do not append
operations to a sealed or failed run, overwrite evidence, pool different matrix
hashes, or merge smoke counts into measurements.

## Commands and qualification gate

From the repository root, with an existing environment JSON containing a
nonempty string-to-string map of the recorded environment facts:

```bash
uv run --no-sync python scripts/run_apcc_qualification_v3.py --help
uv run --no-sync python scripts/run_apcc_qualification_v3.py smoke --output /absolute/new-smoke-path --operations 3
uv run --no-sync python scripts/run_apcc_qualification_v3.py verify --output /absolute/new-smoke-path --smoke
uv run --no-sync python scripts/run_apcc_qualification_v3.py run --output /absolute/new-qualification-path --trial-id aOm0qaWqGRH-Iw_bEjgs2C_sRyfmnj71qG2He0omIzs --environment-json /absolute/environment.json --environment-id recorded-host-allocation-id
uv run --no-sync python scripts/run_apcc_qualification_v3.py verify --output /absolute/new-qualification-path
```

Exit 0 means a verified complete qualification or successful explicitly labelled
smoke diagnostic; inspect `qualification_evidence`. Exit 2 retains a verified
but incomplete qualification. Exit 1 indicates an error and exit 130 an
interruption. CLI output is JSON progress followed by a result/error.

The software acceptance gate requires independent source/security review,
spawned rotation and denial-boundary tests, local repository gates, unchanged
frozen artifacts, and a separately replayed schema-valid shard with at least
10,000 on-time verified successes. Until that evidence exists, the measured
qualification remains pending or incomplete. PostgreSQL writer integration,
other workload drivers, full matrix repetitions, ablations, comparative
statistics, and the wider APCC-1 campaign remain separate work.
