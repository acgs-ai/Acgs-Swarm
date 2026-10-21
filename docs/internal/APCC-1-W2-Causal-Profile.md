# APCC-1 W2 authority causal profile

The frozen W2 workload requires a 100-node linear DAG. Its last node has causal
depth 99, while the authority previously always used the default depth 64.
The existing [protocol](APCC-1-Protocol-Spec.md#bounded-causal-closure-verification)
already permits configured closure limits. The additive SQLite profile below
implements that configuration without changing certificates, the default
deployment, or the frozen v3 qualification.

## Configuration and authenticated persistence

`AuthorityCausalProfile` and `APCCAuthorityConfig.causal_profile` in
[`ports.py`](../../src/constitutional_swarm/apcc/ports.py) select a fixed profile:

| Profile | Maximum depth | Distinct certificates | Resolved envelope bytes |
| --- | ---: | ---: | ---: |
| `DEFAULT` (`default`) | 64 | 4,096 | 67,108,864 |
| `W2_LINEAR_100` (`w2-linear-100`) | 99 | 4,096 | 67,108,864 |

The root counts as depth zero. Configuration requires the enum itself; arbitrary
numeric budgets and strings are rejected. The generic verifier's existing
`CausalClosureLimits` API remains unchanged.

[`sqlite_store.py`](../../src/constitutional_swarm/apcc/sqlite_store.py) preserves
the default canonical configuration's three fields and default signed-checkpoint
body bytes. W2 adds the canonical `causal_profile` field and includes a digest of
the complete canonical public configuration in its signed semantic checkpoint.
An explicitly serialized default, unknown profile, or extra field is invalid.
Changing, inserting, or removing the profile without a matching authority
signature fails checkpoint verification. Reopening with a different expected
configuration fails. Existing read and mutation transaction attestation continues
to pin the entire configuration; no mismatch is automatically resealed.

Admission, individual and batched status, logical-node status, persisted closure
verification, and observation consistency use the selected bounds. Existing
signature, exact predecessor identity, revocation, certificate-count, byte-budget,
and disposition checks remain in force.

The spawned observer in
[`authority_service.py`](../../src/constitutional_swarm/authority_service.py)
receives the expected public configuration digest privately from the selected
authority configuration. It compares the reader configuration inside an attested
launch read transaction before publishing observer readiness. Public launch and
status schemas are unchanged. The checkpoint authenticates configuration and
state; it does not add an external monotonic anchor against restoration of an
entire previously signed database snapshot.

[`postgres_store.py`](../../src/constitutional_swarm/apcc/postgres_store.py)
explicitly rejects W2 in provisioning, opening, direct construction, and persisted
configuration decoding. PostgreSQL profile parity and its trusted spawned writer
remain separate work.

## Verification and remaining workload work

The new regression suites are
[`test_apcc_causal_profile.py`](../../tests/test_apcc_causal_profile.py) and
[`test_apcc_causal_profile_observer.py`](../../tests/test_apcc_causal_profile_observer.py).
They cover profile compatibility and tampering, real signed chain boundaries,
reopen and status paths, PostgreSQL rejection, observer mismatch, and a genuine
spawned 100-agent chain with 100 signed consumable observations and independent
closure replay. Validation results and source pins are recorded in the
[profile evidence](../../experiments/apcc-1/w2-causal-profile-20261017/README.md).

This profile enables the causal depth needed by W2. The separate
[diagnostic driver](APCC-1-W2-Diagnostic-Driver.md) now exercises one or two complete
chains, 100 scoped producer identities, exact decoded payload sizes, real bounded
16-worker capacity, complete-only rotation, and one ordered observation verifier.
These are functional checks. They do not qualify target arrival rates,
cold/warm lifecycle, repetitions, or the 10,000-operation floor.
The chain has one ready node at a time; actual work occupancy must be recorded
separately from configured capacity. Concurrent calls behind an RPC lock alone
do not demonstrate that capacity.

The additive driver needs its own ledger and exact 100-node/99-edge replay
validator. V3's W1 validator requires a unique one-node workflow per operation;
it continues to reject W2. No profile test or diagnostic proof is a v3 success,
W2 campaign row, or authorization to activate the public B6 adapter.
