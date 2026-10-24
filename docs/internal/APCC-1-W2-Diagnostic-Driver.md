# APCC-1 W2 diagnostic driver

[`w2_driver.py`](../../src/constitutional_swarm/apcc_empirical/w2_driver.py) adds
one- or two-chain diagnostics using the authenticated
[W2 causal profile](APCC-1-W2-Causal-Profile.md). It does not emit campaign rows or
change the W1 v3 qualification driver, frozen matrix, or public B6 capabilities.

Each workflow contains exactly 100 nodes in one linear chain. One hundred
distinct scoped producer keys map agents `agent-000` through `agent-099` to the
corresponding nodes. The same logical identities are registered in each fresh
workflow. Canonical node input is exactly 1,024 bytes and the canonical artifact
dictionary is exactly 4,096 bytes, including each successor's dependency.

The supervisor starts the isolated observer before the genuine spawned executor.
A pool starts sixteen live worker threads and admits at most sixteen operations;
a permit covers the complete operation through proof verification. Successor
admission follows the predecessor's successful commit acknowledgement. An ordered
gate serializes observation and verification-stream consumption. A shared lock
excludes mutations while taking the observer's attested snapshot; expensive
independent proof verification occurs outside that lock and may overlap the next
node's commit. No snapshot-consistency check is removed or retried into success.

The chain has one ready node at a time. Configured capacity, actual worker
identities, and observed occupancy are recorded separately; sixteen simultaneous
commits are not claimed. Each complete chain drains all verified operations and
passes authoritative completion before rotating on the same authority/executor
handles. Failed operations wake ordered waiters and retain an unsealed diagnostic
prefix while shutting down owned workers and children.

## Running and replaying

From the checkout, use a new output path:

```bash
uv run --no-sync python scripts/run_apcc_w2_diagnostic.py smoke --output .context/w2-smoke --chains 2
uv run --no-sync python scripts/run_apcc_w2_diagnostic.py verify --ledger .context/w2-smoke/ledger.jsonl --expected-sha256 <recorded-ledger-sha256>
```

The CLI reports `campaign_eligible: false` even when every diagnostic proof
verifies. It never overwrites an existing output directory. A successful smoke
records a result file next to its ledger. Interrupted or failed runs retain their
actual prefix and do not acquire a success seal.

The separate `w2-driver-v1` controller seal binds the ledger prefix. Independent
replay checks the exact governed request, producer and policy signatures,
observation target, signed ordered observation, authority certificate/status/output
proof, exact payloads, and full digest-pinned causal closure for every row. It
checks the immediately preceding node's six-field reference, identity uniqueness,
complete-chain rotation, admission/commit/verification timing, per-worker
nonoverlap, and occupancy bounded by sixteen. Missing nodes and unsigned tails
are invalid. Recorded source/protocol/matrix/schema and runtime provenance must
remain stable across execution; an external ledger digest can pin replay input.

The expected public authority configuration is a controller-sealed expectation.
The offline ledger does not claim an authority-signed configuration checkpoint.
The observer PID is bound by its signed launch attestation; the other process and
thread identities are supervisor measurements.

## Acceptance boundary

Tests and retained evidence are linked from the
[W2 evidence bundle](../../experiments/apcc-1/w2-causal-profile-20261017/README.md).
Tests exercise actual 16-worker admission, successor execution during predecessor
verification, two complete chains, independently replayed proofs, controller-resealed
semantic tampering, and failure cleanup. A diagnostic has no target arrival rate,
fixed measurement window, warm-run lifecycle, or 10,000-operation acceptance
claim. Those remain prerequisite work for W2 campaign qualification. V3 remains
separate and continues to reject W2.
