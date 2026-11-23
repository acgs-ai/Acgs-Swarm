# ADR-0001: APCC Authority Store Offline v3-to-v4 Migration Protocol

- **Status:** Accepted
- **Date:** 2026-11-22
- **Scope:** `constitutional_swarm.apcc` SQLite authority stores (v3 -> v4) and PostgreSQL 17 operational cutover procedure

## 1. Context & Root Cause

C32 incremented `_AUTHORITY_SCHEMA_VERSION` from `"3"` to `"4"` in `src/constitutional_swarm/apcc/sqlite_store.py`. Both SQLite schema v3 and schema v4 enforce fail-closed verification on `open()`:

- `SQLiteAuthorityStore.open()` and `SQLiteAuthorityReader.open()` verify `PRAGMA user_version == 4`, `metadata.schema_version == "4"`, `metadata.schema_fingerprint == _SCHEMA_FINGERPRINT`, full DDL object parity, full semantic integrity (`_validate_semantic_integrity`), and the Ed25519-sealed `semantic_checkpoint` signature.
- Every APCC v3 database—whether pre-C32 or post-C32—is rejected fail-closed with `ValueError("APCC authority schema version is incompatible")` and zero byte/sidecar mutation.

Empirical comparison of authentic v3 artifacts against schema v4 shows two distinct v3 populations:

1. **Authentic pre-C32 v3 stores** (exemplified by `tests/fixtures/apcc/apcc_pre_c32_v3.sqlite`):
   - SQLite DDL matches v4 (`0` DDL diffs across tables, indexes, and triggers).
   - `metadata.schema_fingerprint` matches the canonical v3 fingerprint (`1qM32kCg6RpbrXemVDsaSsUCbgR9glpRKfDQJMym02Y`) and the v3 `semantic_checkpoint` Ed25519 signature verifies.
   - However, C32 candidate rows fail `_validate_candidate_row` because pre-C32 candidate `audit_event_id` values were derived under the pre-C32 format rather than the C32 `_audit_id(state.value, proposal.commit_id, _proposal_identity(proposal))` / `_audit_id("stage", ...)` derivation.
2. **Authentic post-C32 v3 stores:**
   - Identical DDL to v4 (`0` DDL diffs), valid v3 `metadata` + signed v3 `semantic_checkpoint`, and 100% compliant with C32 `_validate_semantic_integrity`.

## 2. Forbidden Approaches

1. **No auto-migration in `open()`:** Opening an authority store must remain strictly fail-closed on incompatible schema versions so a downgrade/version mismatch cannot silently mutate historical evidence or mask corruption.
2. **No in-place metadata or `PRAGMA user_version` rewriting:** Rewriting `PRAGMA user_version=4` and `metadata.schema_version='4'` in place violates evidence immutability because:
   - `semantic_checkpoint` signs `schema_fingerprint` (which binds the schema version).
   - Re-sealing a pre-C32 database as v4 would either immediately fail v4 open (`APCC SQLite store semantic validation failed`) or, worse, encourage mutating signed/hashed historical rows.
3. **No silent re-signing of pre-C32 candidate rows:** Recomputing `candidates.audit_event_id` on pre-C32 databases destroys forensic correspondence with pre-C32 audit evidence and is forbidden.

## 3. Decision: Offline Read-Only-Source -> Fresh-v4-Target Migration + Continuity Receipt

All SQLite `v3 -> v4` migration runs exclusively **offline** via `constitutional_swarm.apcc.migration_v3_to_v4` (`python -m constitutional_swarm.apcc.migration_v3_to_v4`):

1. **Zero-mutation inspection (`inspect_sqlite_store`):**
   - Refuses stores with non-empty uncheckpointed `-wal` sidecars rather than modifying or checkpointing source files.
   - Copies the source file into a temporary directory before running SQLite inspection so zero bytes, `-wal`, or `-shm` files are ever created or altered alongside the source database.
   - Classifies the source store into one of:
     - `v4_current`
     - `v3_post_c32_migratable`
     - `v3_pre_c32_incompatible`
     - `v3_gcb_unsupported` (GCB-attached SQLite tables present; requires typed governance bootstrap migration, not flat APCC table copy)
     - `v3_tampered_or_corrupt`
     - `unsupported_schema`
2. **Fresh-target migration (`migrate_sqlite_v3_to_v4`):**
   - Proceeds **only** for `v3_post_c32_migratable`. Refuses existing `target_path` or `receipt_path`.
   - Verifies that the supplied `AuthorityRuntime` holds the exact `COMMIT` and `STATUS` signing keys configured in `metadata.config` via `validate_runtime_signers`.
   - Stages a new temporary v4 SQLite DB (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`), installs v4 tables/indexes/triggers, and copies all 19 APCC data tables verbatim in topological foreign-key order.
   - Writes v4 `metadata` (`schema_version='4'`, v4 `_SCHEMA_FINGERPRINT`, exact original `config`).
   - Chains the new v4 `semantic_checkpoint` row from the verified v3 checkpoint:
     - `change_sequence = source.change_sequence + 1`
     - `prior_digest = source.checkpoint_digest`
   - Installs `_SEMANTIC_CHECKPOINT_TRIGGERS`, runs full v4 `_validate_schema_manifest` + `_validate_semantic_integrity`, seals the checkpoint with `AuthoritySigningRole.COMMIT`, validates `_validate_schema`, runs `PRAGMA wal_checkpoint(TRUNCATE)` (`(0, 0, 0)`), `os.fsync`, and atomically links into `target_path`.
   - Verifies a staging copy of the exact published target bytes via both `SQLiteAuthorityReader.open()` and `SQLiteAuthorityStore.open()`, and asserts `source_path` SHA-256 is bit-for-bit unchanged.
   - Emits an Ed25519-signed `MigrationContinuityReceipt` (`APCC-MIGRATION-CONTINUITY-V1`) binding `source_sha256`, `source_schema_fingerprint`, `source_checkpoint_digest`, `source_change_sequence`, `target_sha256`, `target_schema_fingerprint`, `target_checkpoint_digest`, `target_change_sequence`, `migrated_certificate_digests_sha256`, `migrated_counts`, and `migrated_at_ms`.
   - Offline verification (`verify-receipt`) requires an externally pinned `--commit-public-key` trust root (never self-trusting the unverified target database's `metadata.config`) and re-verifies the Ed25519 signature, full target schema/semantic integrity, table counts, certificate digest set, and uncheckpointed WAL absence.

## 4. Operational Triage for Pre-C32 v3 Stores

When `inspect` classifies a store as `v3_pre_c32_incompatible`:
- Keep the v3 database archived read-only alongside its SHA-256 digest and inspection report (`v3_pre_c32_incompatible`).
- Provision a fresh schema v4 authority store (`SQLiteAuthorityStore.provision`) for new commits rather than mutating or re-signing pre-C32 candidate rows.
- Verify any historical pre-C32 commit certificates offline using `verify_historical` / `verify_causal_closure` on extracted detached envelopes.

## 5. PostgreSQL 17 Operational Cutover Procedure

1. Freeze writers against the schema v3 PostgreSQL schema and verify current `semantic_checkpoint` and trust-log head.
2. Confirm schema v4 catalog fingerprints (`_POSTGRES_CATALOG_FINGERPRINT = "s-gycb2MocWE-vCFg3fyKw9tSRPK0ayWSKxg9dMfU9w"` for base and `_POSTGRES_GCB_CATALOG_FINGERPRINT = "boKYmnLfKZ0KaZ81HwsAJ6e8hURsyEkqGaIpg9E2lPc"` for GCB).
3. Provision a fresh schema v4 target schema (`postgres_store.provision`) with the same `APCCAuthorityConfig`.
4. Copy verified post-C32 rows into the fresh schema, update v4 `metadata` (and `gcb_store_meta.schema_version='4'` when GCB-attached), chain and seal `semantic_checkpoint` (`change_sequence + 1`, `prior_digest = source_checkpoint_digest`), and verify via both `postgres_store` writer `open()` and reader `open()` in a non-mutating check.
5. Cut over application DSNs/schemas to the verified v4 schema and retain the v3 schema read-only as forensic archive.
