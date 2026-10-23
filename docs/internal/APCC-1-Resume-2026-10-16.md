# APCC-1 resume record — 2026-10-16

```text
APCC-1 QUALIFICATION PARTIAL
BASELINE_REMOTE_EVIDENCE_INCOMPLETE
NOVELTY: INSUFFICIENT EVIDENCE
PRODUCTION READINESS NOT CLAIMED
```

This record separates resumed local work from the
[historical results](APCC-1-Results.md), [frozen plan](APCC-1-Experiment-Plan.md),
and qualification-live [v1](APCC-1-Qualification-Live-Protocol.md) /
[v2](APCC-1-Qualification-Live-Protocol-v2.md). Those records retain their
identities and outcomes. The [novelty verdict](APCC-1-Novelty-Verdict.md) retains
the prior-art research cut-off of 2026-08-28.

## Checkout and evidence identity

- Scope: `/home/martin/Downloads/Acgs-Swarm-main`, a standalone local repository.
- Restored local base: `f6f4f7162f6ee657fc241cd5dc89445f9b18fad9`.
- Branch: `apcc-1-resume-20261016`; no remote configured.
- The archive comparison checked 965 formerly tracked files, found none
  missing and one differing file: the pre-existing `pyproject.toml` Braintrust
  requirement change from 0.31 to 0.35. That change was preserved.
- Fresh evidence concerns a **working tree**, not a clean immutable HEAD.
  Restored local history does not authenticate an upstream baseline.

Logs, failed runs, query profiles and independent review reports are preserved
under [experiments/apcc-1/resume-20261016/](../../experiments/apcc-1/resume-20261016/).
`SHA256SUMS` binds the preserved evidence; `source-snapshot.json` records the
working-tree file hashes and base identity. Temporary originals remain under
`/tmp/apcc-resume-20261016/`. The task-owned PostgreSQL container was stopped
after verification; its data was retained.

## Local checks and limits

| Check | Observed result | Preserved evidence filename | Claim boundary |
| --- | --- | --- | --- |
| Baseline `make verify` | `2956 passed, 57 skipped, 95 deselected in 166.01s (0:02:46)`; `OK: verify passed.` | `verify-permissions-fixed.log` | Baseline before later source changes; excludes live PostgreSQL. |
| Final `make verify` | `3001 passed, 57 skipped, 95 deselected in 181.92s`; `OK: verify passed.`; exit 0. | `final-verify.log` | Includes observation-target and duration-revision changes; excludes live PostgreSQL. |
| Final `make test-all` | `3023 passed, 57 skipped, 71 deselected, 2 xfailed in 184.47s`; exit 0. | `final-test-all.log` | Repository-defined expanded marker selection; skipped extras remain unverified. |
| APCC TLC | 32 accepted configurations: 4 exit 0 and 28 expected exit 12; harness exit 0. | `tlc.log`, `validation-commands.txt`, `validation-inputs-sha256.json` | Witness/ablation violations establish intended modeled conditions, not ordinary safety success or empirical ablations. |
| Independent Go JCS reference | Standard-library reference and 26 official RFC 8785 Appendix B cases passed; race suite passed; vet and format outputs empty. | `go-race.log`, `go-vet.log`, `go-gofmt.log` | Canonicalization assurance; CJ1 continues rejecting numeric values. |
| Go fuzz run | 15-second requested budget; `22461` executions; `PASS`. | `go-fuzz.log` | Bounded fuzz evidence, not exhaustive equivalence. |
| Python/Go differential | `APCC differential PASS (126 vectors)` | `go-differential.log` | Agreement on the executed corpus. |
| Isolated wheel gate | `isolated wheel gate OK`; checks passed on Python 3.13.13 and 3.11.15. | `verify-wheel.log` | Packaging and import/CLI isolation, not deployment. |
| Full PostgreSQL suite | `3 failed, 363 passed in 4384.03s (1:13:04)`; exit 1. | `postgres.log`, `postgres.xml`, `postgres-environment.log` | Fresh PostgreSQL 17 on Podman loopback port 55436; not a passing suite. |
| PostgreSQL isolated rerun | `3 failed, 1 passed, 362 deselected in 149.87s`; exit 1. | `postgres-rerun.log` | Reproduces all three failures; the zero-sibling positive control passes. |
| PostgreSQL full rerun after environment correction | `366 passed in 496.01s`; exit 0, no skips. | `postgres-direct-full.log`, `postgres-direct-full.xml`, `postgres-direct-result.json` | Direct loopback within the task container network namespace, session `jit=off`; same frozen source/tests and unchanged durability settings. |
| Observation-target regression suite | `21 passed in 10.40s`; exit 0; independent review found no remaining actionable findings. | `observer-target-final.log` | Real spawned authority/scheduler/observer, exact replay, semantic verification, corrupt and substituted bindings, and read-only resolution. Full B6 remains unqualified. |
| Duration revision and legacy compatibility | 142 tests passed; independent review found no actionable findings; generated hashes reproduced. | `duration-revision-tests.log`, `duration-revision-generation.log` | Versioned plan/schema/artifact support, not campaign execution. |
| Rebuilt isolated wheel | `isolated wheel gate OK`; exit 0. | `final-verify-wheel.log` | Final source packaged and checked in isolated environments. |
| Independent reviews | Go, observation-target and duration-revision reviews found no remaining actionable findings in their bounded slices. | `review-go.txt`, `review-observer.txt`, `review-duration.txt` | Slice reviews, not four-lane APCC acceptance. |

The first baseline attempt had 15 permission-related failures. Removing
group/other write permission from the experiment matrix directory and schema
inputs let existing strict-input checks run. Failed output remains in
`baseline-verify.log` and `first-failure.log`. This repaired local permissions;
the input checks were not relaxed.

The PostgreSQL failures were
`test_postgres_skip_locked_outbox_has_one_persisted_event_identity` and
`test_postgres_attestation_latency_reports_linear_sibling_catalog_cost[1]`
and `[5]`. Query profiling identified JIT compilation overhead and substantial
client-side delay through the rootless container's published port. Direct
container loopback with per-session `jit=off` passed all 366 tests. The exact
TCP delay mechanism was not packet-traced. The
`postgres-performance-diagnosis.md` evidence record preserves the comparisons,
settings and limits. No source or threshold was relaxed. This local environment
result does not close the P2 limitations in the
[B2 close record](APCC-1-B2-Postgres-Close.md) or prove remote CI.

## User-authorized measurement revision

The user authorized retaining **10,000 completed operations** and extending
low-rate runs. Planned duration: `max(30, ceil(10000 / target_rate))` seconds.

| Target proposals/s | Planned measured duration |
| ---: | ---: |
| 10 | 1,000 seconds |
| 100 | 100 seconds |
| 500 | 30 seconds |

Status: **IMPLEMENTED / INDEPENDENTLY REVIEWED** in the additive
[measurement revision](APCC-1-Measurement-Revision-v2.md). This requires reruns
of every affected B0–B6 cell. The original plan and qualification v1/v2
outcomes stay unchanged. An attempted rate and longer duration do not guarantee
10,000 completions; overloaded runs must still be retained and flagged.

## Remaining closure work

| Item | Status | Required evidence |
| --- | --- | --- |
| B6 `observation_target` handling | **LOCAL SLICE VERIFIED** | Applied source, 21 positive/negative tests, independent review and passing repository gate. |
| Full B6 trusted execution and PostgreSQL performance | **UNCLOSED** | Trusted supervision and live authority-store measurements with planned controls; catalog expectations cannot replace observed outcomes. |
| Frozen 102,416-cell campaign | **PENDING_MEASUREMENT** | Versioned complete campaign, raw cell identities and revised-duration measurements kept separate from v1. |
| Empirical ablations | **UNCLOSED** | One-at-a-time implementation removals, failed invariants and matched performance cells. |
| Full PostgreSQL local test gate | **PASSED IN RECORDED ENVIRONMENT** | 366 tests passed after transport/JIT correction. Performance campaign and remote CI remain separate. |
| Prior-art archives and claim charts | **UNCLOSED** | Hashed sources and pinned comparisons, without relabeling old research as refreshed. |
| Four independent acceptance reviews | **UNCLOSED** | Protocol minimality, formal correctness, cryptographic/canonical conformance, and novelty/experimental-validity reviews of the final attributable candidate and campaign. |
| Evidence preservation and final local gates | **COMPLETE** | Stable logs and hash manifests; repository, expanded tests, isolated wheel and live PostgreSQL gates passed. |

Authoritative local entrypoints are the [Makefile](../../Makefile)
(`make verify`, `make agent-check`, `make verify-wheel`) and the separate
PostgreSQL job in [CI](../../.github/workflows/ci.yml). These local results do
not assert remote CI, publication or deployment. The
[remaining execution plan](APCC-1-Remaining-Execution-Plan.md) identifies the
trusted PostgreSQL execution, repeated-workflow, W6 capacity and workload-driver
gaps. W6's frozen 10,000-node DAG exceeds the runtime's 1,000-node limit; the
owner's protocol-revision decision is pending. No frozen topology or safety
limit has been changed to conceal that conflict.
