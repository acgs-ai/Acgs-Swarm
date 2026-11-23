# API stability in 1.2.x

This page says which parts of `constitutional_swarm` you can build on, and which
can change under you. It applies to the 1.2.x release line.
`tests/test_api_stability_surface.py` checks every table below against the
package, so a module cannot ship without a tier and a public name cannot change
silently.

For how the façade is imported and why legacy names are lazy, see
[`API_COMPATIBILITY.md`](API_COMPATIBILITY.md).

## What each tier promises

| Tier | Promise within 1.2.x | How to import |
|---|---|---|
| Stable core | Names, signatures, and behaviour do not change incompatibly. A breaking change needs a major version. | `from constitutional_swarm import Name` |
| Advanced runtime | Same promise for the documented classes, but the module may need an optional extra. | By module path, e.g. `constitutional_swarm.evolution_log` |
| Provisional | Stored and signed formats are stable. Python names can change in a minor release, with a changelog entry. | By module path, e.g. `constitutional_swarm.apcc.execution_gateway` |
| Research and experimental | None. Anything can change or disappear in any release. | By module path |
| Internal support | None. Importable only because Python has no private modules. | Do not import |

Three rules hold everywhere:

- A name that starts with an underscore is private, whatever module it is in.
- The lazy top-level names (`from constitutional_swarm import EvolutionLog` and
  the like) exist for old callers and carry no promise. Import from the module.
- Security fixes can change behaviour in any tier. They are listed under
  **Migration** in `CHANGELOG.md`.

## Stable core

The stable API is exactly `constitutional_swarm.__all__`: 73 names, frozen in
the test. These modules define them, and the two console scripts live here too.

| Module | What it holds |
|---|---|
| `artifact` | `Artifact`, `ArtifactStore` |
| `capability` | `Capability`, `CapabilityRegistry` |
| `compiler` | `DAGCompiler`, `GoalSpec`, `GoalStep` |
| `contract` | `TaskContract`, `ContractStatus` (compatibility layer over `execution`) |
| `dna` | `AgentDNA`, `constitutional_dna`, `DNADisabledError` |
| `execution` | `SwarmExecutor`, `ExecutionStatus`, `WorkReceipt` |
| `governance_errors` | `GovernanceBypassDenied` |
| `governance_receipts` | Receipt types, `build_receipt`, `verify_bundle`, bundle encoding |
| `governance_receipts_cli` | The `acgs-verify-receipts` command |
| `governed_commit` | `GovernedCommitBoundary`, `CommitRequest`, `sign_governed_receipt` |
| `governed_handoff` | The `acgs-swarm` governed-handoff command |
| `mesh` | `ConstitutionalMesh`, votes, proofs, and the mesh exceptions |
| `settlement_evidence` | Settlement-to-receipt binding, `verify_committed_settlement_receipt` |
| `settlement_store` | `SettlementStore` and its JSONL and SQLite implementations |
| `swarm` | `TaskDAG`, `TaskNode` |

For the two commands, the promise covers their documented options and exit
codes, not the Python functions behind them.

## Advanced runtime

| Module | Extra | Notes |
|---|---|---|
| `bittensor` | `[bittensor]` | Subnet integration. Bounded to bittensor below 11. |
| `evolution_log` | none | `EvolutionLog` and its monotonicity errors. |
| `langgraph_runtime` | `[langgraph]` | LangGraph adapter. |
| `remote_vote_transport` | `[transport]` | WebSocket vote transport. |
| `spectral_sphere` | none | `SpectralSphereManifold`. |

## Provisional: APCC authority runtime

> **Proposed tier.** Nothing before this page said which tier APCC is in. The
> placement below is a proposal for the maintainers to confirm before 1.2.0 is
> published. The rest of this page restates tiers that `ARCHITECTURE.md`,
> `README.md`, and `API_COMPATIBILITY.md` already describe.

APCC is new in 1.2. What it writes to disk and what it signs are already
stable, because stores and receipts outlive a release:

- authority schema version 4, for both SQLite and PostgreSQL 17 stores;
- the APCC-1 certificate, status, and observation encodings;
- the v3-to-v4 migration continuity receipt;
- the execution gateway's wire contract with a target: the `Idempotency-Key`,
  `X-Fencing-Token`, `X-APCC-Event-Id`, and `X-APCC-Certificate-Digest`
  headers and the receipt body.

The Python API is provisional. It is one release old and has had no outside
users yet, so names and signatures can still change in a minor release.

| Module | Public surface |
|---|---|
| `apcc` | The package. It re-exports nothing; import its modules. |
| `apcc.execution_gateway` | The 13 names in its `__all__`, frozen in the test. |
| `apcc.migration_v3_to_v4` | The `python -m constitutional_swarm.apcc.migration_v3_to_v4` command and receipt verification. |
| `apcc.model` | Immutable APCC v1 protocol records. |
| `apcc.observation` | Signed authority observations and their verification. |
| `apcc.ports` | The runtime, clock, key-provider, and outbox-sink protocols. |
| `apcc.postgres_store` | `PostgresAuthorityStore`, `PostgresAuthorityReader`, `PostgresRetryPolicy`. Needs `[postgres]`. |
| `apcc.service` | `APCCCommitService`, the typed entry point for authority operations. |
| `apcc.sqlite_store` | `SQLiteAuthorityStore`, `SQLiteAuthorityReader`. |
| `apcc.verifier` | `verify_historical`, `verify_causal_closure`, `verify_current`. |
| `authority_child` | Authority child process entry point. |
| `authority_ipc` | Authenticated IPC between the authority processes. |
| `authority_isolation` | Linux controlled-boot checks for the privileged processes. |
| `authority_observer` | Launch configuration for the isolated observer. |
| `authority_service` | IPC boundary and clients for the privileged authority process. |

The execution gateway has limits you should know before relying on it. Unless
noted, each is pinned by a test in
`tests/test_apcc_execution_gateway_fault_e2e.py`, which runs the gateway
against a real HTTPS target process through a fault-injecting proxy:

- **It does not retry.** There is no backoff and no `Retry-After` handling. A
  failed delivery is tried again only when the authority store redelivers the
  outbox event, and each delivery sends exactly one request.
- **After a lost response it cannot tell whether the target applied the
  effect.** The ledger row stays `IN_FLIGHT`. Exactly-once then depends on the
  target: it must deduplicate by idempotency key and reject a fencing token
  older than one it has seen. A target that does neither can apply an effect
  twice.
- **Only 200 and 201 count as success.** Any other status, including 202, 429,
  and 5xx, raises an error and leaves the row `IN_FLIGHT`.
- **Each attempt spends a fencing token before it connects**, so a refused
  connection or a TLS failure still advances the token.
- **It has no TLS options of its own.** HTTPS uses the interpreter's default
  trust store. To trust a private CA, pass an `opener` built with your own
  `ssl.SSLContext`. An expired certificate, an untrusted issuer, and a
  hostname mismatch all fail before any request is sent.
- **Target responses are treated as untrusted.** A target can echo the bearer
  token, so an HTTP error is reported by status code alone: the target's body,
  headers, and reason phrase are kept out of the message and out of the
  exception chain. In a receipt, `target_reference` and `applied_digest` must
  be at most 512 printable ASCII characters with no spaces and must not contain
  the bearer token, and a receipt over 64 KiB is rejected. Local socket and TLS
  errors keep their own text. (Pinned in
  `tests/test_apcc_execution_gateway_untrusted_response.py`.)
- **Key rotation is not supported.** A store refuses to reopen with different
  commit or status keys, and a verifier holds one key per role and scope. A
  certificate signed under other keys is rejected, and the gateway raises
  rather than marking the effect blocked, so later events wait behind it.

## Research and experimental

| Module | Notes |
|---|---|
| `agent_self_evolve` | The `acgs-agent-self-evolve` command (self-evolution harness for repo agents). |
| `apcc_empirical` | APCC qualification and W2 measurement harnesses. |
| `bench` | Benchmark helpers. |
| `byzantine_census` | Tampered-fraction census for quorum accounting. |
| `debate_resolver` | Adversarial debate resolver. |
| `epoch_reconfig` | Versioned constitutional reconfiguration. |
| `eval` | Evaluation scaffolding. |
| `federated_bridge` | Cross-constitution federation. |
| `forensic_benchmark` | Protocol checks and scoring for the forensic benchmark. |
| `gossip_protocol` | Gossip transport for `merkle_crdt`. Needs `[transport]`. |
| `latent_dna` | Residual steering. Needs `[research]`. |
| `mac_acgs_loop` | MAC-ACGS auto-constitution pipeline. |
| `manifold` | Birkhoff baseline, kept as an empirical control. Do not fix its collapse. |
| `merkle_crdt` | Content-addressed artifact DAG. |
| `node_admission` | Abliteration-aware node admission. Needs `[research]`. |
| `privacy_accountant` | Differential-privacy accounting. |
| `private_vote` | Commit-reveal voting with nullifiers. |
| `quorum_certificate` | Quorum certificates with slashable conflicting votes. |
| `swarm_ode` | Continuous-time trust dynamics. Needs `[research]`. |
| `swe_bench` | SWE-bench evaluation scaffold. |
| `validator_set` | Validator set with VRF committee selection. |
| `violation_subspace` | LEACE-style violation subspace. Needs `[research]`. |

## Internal support

| Module | Notes |
|---|---|
| `apcc.codec` | APCC-CJ1 canonical encoding. |
| `apcc.crypto` | Signature primitives. |
| `apcc.gcb_projection` | Data-only contract for the governed-commit projection. |
| `constants` | Shared constants. |
| `framing` | Typed framing for digests and plain identifiers. |
| `governance_fixtures` | Offline fixtures for the receipt-verifier benchmark. |
| `governance_receipts_dsse` | DSSE envelope helpers behind the receipt API. |
| `protocol` | Canonical protocol encoders. |
| `secure_files` | Fail-closed checks on private files. |
| `strict_json` | Bounded strict JSON parsing and canonical encoding. |

## Changing this page

Moving a module between tiers, or adding or removing a stable name, is an API
decision. Change the table here and the matching entry in
`tests/test_api_stability_surface.py` in the same commit, and add a changelog
entry.
