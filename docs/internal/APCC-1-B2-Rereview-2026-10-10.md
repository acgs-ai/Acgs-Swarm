# APCC-1 B2 frozen-pair re-review (2026-10-10)

Status:

```text
APCC-1 QUALIFICATION PARTIAL
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```

This record re-closes the B2 frozen pair after the C1–C51 security campaign
(#166). It does not replace the earlier records: `APCC-1-B2-Postgres-Close.md`,
`APCC-1-Phase0-Reconcile.md` and `APCC-1-Results.md` §16–17 still describe the
pair as it was when they were written. It is not an APCC-1 acceptance,
novelty, or production-readiness verdict.

## Why a re-review

The original static close approved pair content `576c0449` / `dff15b7f`
(`APPROVE-WITH-P2`; P0=0; P1=0). Since then:

1. C32 (`4ea47b1`) changed `sqlite_store.py`, whose `_AuthorityStoreCore`,
   `_audit_id` and semantic validator `postgres_store.py` inherits. The approval
   no longer covered the code PostgreSQL actually runs.
2. `4f3460f` changed one line in `tests/test_apcc_postgres.py`: the stage in
   `test_postgres_full_catalog_and_fk_checks_run_once_per_authority_transaction`
   now passes `expected_node_version="1"`, because C32 refuses a fresh stage at
   a stale node version before any write. Without it, CI `test-postgres` failed
   with `STAGED_RESULT_CONFLICT`.

## Pair under review (main `29f8c05`)

```text
576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a  src/constitutional_swarm/apcc/postgres_store.py   (unchanged)
177d313792c51cc5c999ebe7f9d9463ddce43bd6721240f2516b29413c34a358  tests/test_apcc_postgres.py                        (was dff15b7f…)
```

## Method

Independent static review in a separate agent invocation from the one that made
the change (opus security reviewer, read-only worktree at `29f8c05`). Scope: the
pair, and `git diff f40af8d..29f8c05 -- src/constitutional_swarm/apcc/`
(commits `4ea47b1`, `4311af3`, `4f3460f`). No live PostgreSQL run in the review
itself. Live evidence comes from elsewhere: CI `test-postgres` passed the full
file (366 tests) at `4f3460f` and at `29f8c05`. The `29f8c05` pass came on a
rerun, after one segfault inside `psycopg_binary` 3.3.6 during a threaded
contention test.

## Verdict

```text
APPROVE-WITH-P2   P0=0   P1=0   P2=7 (5 carried from Results §17, 2 new)
```

The shared-core changes stay correct and fail closed under PostgreSQL.

- **Audit ids:** `postgres_store.py:50` imports `_audit_id` from the SQLite
  core. The PostgreSQL-local id sites (`recovery-missing`, `revoke`,
  `outbox-delivered`) use the same kinds and parts as the core, so what
  PostgreSQL writes matches what the shared validator accepts on reopen. The
  legacy decision family still matches `observation.py`.
- **Pre-write refusals:** the stage version check and
  `_validate_written_candidate` run inside the PostgreSQL `_transaction`,
  before `_seal_mutation_checkpoint`. They raise a plain `ValueError` with no
  `sqlstate`, so `_retry_known_abort` re-raises on the first attempt and the
  transaction rolls back. There is no retry loop and no seal.
- **Revocation binding and `require_plain_id`:** these hold for PostgreSQL.
  Revocation runs under the certificate and workflow locks. `require_plain_id`
  is enforced in the request dataclasses before any SQL runs.

### New P2s

| id | finding | effect |
| --- | --- | --- |
| N1 | Audit ids moved to the v2 framed digest, but the schema version stays `3` (PostgreSQL CHECK and catalog fingerprint unchanged). | A pre-campaign PostgreSQL store passes the schema gate and then fails semantic validation on reopen. It fails closed, so this is an availability issue, not a security one. It is documented in CHANGELOG under Breaking and in DECISIONS (C32). The deferred schema v4 bump resolves it. |
| N2 | `postgres_store.py:3279-3291` keeps its own runtime-signer check instead of `ports.validate_runtime_signers`. | If the key provider throws, the raw exception propagates instead of `ValueError("APCC runtime signer is unavailable")`. Both paths refuse to open. This is the copy flagged as follow-up at `tests/test_c32_apcc_stores_hardening.py:293`. |

### Carried P2s (Results §17)

All five are still present. `postgres_store.py` is byte-identical, so P2s 2–5
are unchanged by construction.

1. GCB fingerprint is not threaded through reader and observation paths.
2. No native PostgreSQL `commit_output_refs` pin.
3. SQLSTATE 23505 mismatch is handled outside the retry loop
   (`postgres_store.py:4241`, `:4268`).
4. Outbox delivery is at-least-once.
5. `hashtextextended` advisory-lock collisions are theoretically possible.

## Does the test change weaken the test?

No.

- The new call still goes through `store.stage_result`, which opens one
  PostgreSQL transaction.
- `_validate_written_candidate` is pure and calls none of the six counted
  catalog functions, so the "5× `_catalog_fingerprint`, 1× each other"
  assertion measures the same thing.
- Before the change, this stage call took the path that wrote a store-bricking
  row: the inserted version came from the node, but the audit id was built
  from the stale version. The old test was therefore counting queries on an
  invalid state.
- A wrong version now raises, so the test cannot pass vacuously.

## Not verified

- A live reopen of a store written before the campaign (N1 is inferred from
  the encoding change plus the unchanged schema version).
- Importing `postgres_store` in the review venv (`psycopg` absent there); the
  import binding was confirmed by reading the source.
- A dependency audit.
