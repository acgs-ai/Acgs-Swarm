# APCC-1 W2 observer renewal implementation — 2026-10-18

Phase 1 implementation and local functional acceptance are complete. The first numeric cold attempt is a preserved fatal outcome, so numeric qualification remains incomplete and the other 344 planned windows are unexecuted. This is local evidence; no hosted CI or release claim is made.

## Implemented boundary

SQLite `W2_LINEAR_100` retains 100 nodes, depth 99, immediate-predecessor edges, distinct scoped producers, and canonical 1,024-byte inputs / 4,096-byte outputs. APCC authority codecs, default depth 64, signed checkpoint representations, durability paths and profile-substitution rejection remain intact. PostgreSQL rejects this profile. W1, its fresh-provisioning design, public B6 and W6 composition are unchanged.

The opt-in renewal protocol fences admission, drains full-proof work, verifies the predecessor seal and signed transition journal, and binds the successor observer to the existing authority session and exact profile. Every observer launch remains subject to the 1,200-second cap and the finite repetition budget. Stale epochs, unapproved rollover and competing preparation fail closed. A real 16-worker pool retains permits through proof verification. Release, completion publication and admission accounting share the state lock, closing the saturation interval race without weakening proofs.

## Completed functional evidence

The immutable final-source execution completed a 100-second cold conditioning window with 100 operations, followed by four 1,000-second warm windows with 400 operations each. All **1,700 operations committed**, with **zero overloads and zero late completions** under the functional parameters. Four observer renewals occurred across the five windows. These are separate functional denominators; they are not pooled into a numeric qualification result. Every ledger and repetition remains `campaign_eligible:false`, and accounting qualification remains false.

| Parameter | Completed functional run | Approved numeric policy |
| --- | --- | --- |
| Admission grace | 25 ms | 25 ms |
| Operation SLA | 5,000 ms | 200 ms |
| Absolute slot ceiling | Not the numeric qualification gate | 225 ms |
| Window drain | 1,000 ms | 1,000 ms |
| Renewal handover | 10,000 ms | One combined 2,000 ms bound |
| Observer launch cap | 1,200,000 ms | 1,200,000 ms |

The functional results do **not** establish the tighter numeric SLA or handover bound.

Final-source `make verify` exited successfully: **3,721 passed, 57 skipped, 103 deselected**, in 1,285.92 seconds. Before/after maps contained identical 799 input pins. Independent source/security review closed the identified expiry, admission, journal-binding, lifecycle, cleanup and saturation-accounting findings.

The failure suite completed eight cases: six real runtime fault injections and two public-artifact mutations. Six runtime cases cover cancellation after drain, observer crash during handover, stale epoch use, expiry before handover, competing prepare and unapproved rollover. The two artifact cases cover a truncated signed journal and an unsealed predecessor. Sixteen separate, uninstrumented `-I -S` CLI checks produced eight valid-prefix successes and eight expected repetition rejections. Runtime fault injection remains explicitly instrumented; only the replay subprocesses are uninstrumented. These are failure-contract checks, not numeric performance results.

## Provenance, cleanup and retained rejected evidence

The final 799-input source manifest is `f8e4b3eb21c2553df0fe39f3b3d383c45e815897648426da40ce7da70e2653db`. Against the 778-entry baseline, 775 entries are unchanged. The three explicit existing-file opt-in changes are `apcc_empirical/w2_campaign.py`, `authority_child.py`, and `authority_service.py`; additive renewal modules/tests account for the remaining final inputs. All **13 prior bundles / 648 sealed entries** remain unchanged. The earlier 11-bundle / 542-entry milestone is retained within that preserved history.

An earlier long attempt is retained as rejected evidence: its warm-window header/footer source hashes disagreed after a peer temporarily edited and restored an evidence helper. That attempt was cancelled; restoring the file did not rehabilitate its provenance. The final long run and full gate used the immutable final snapshot. Earlier smoke and source variants remain labeled separately. In particular, the two artifact-mutation cases use genuine earlier smoke input replayed by the final-source CLI; they are not relabeled final-source generation.

Final long-run cleanup proves absence of all eight owned child PIDs and absence of controller descriptors for the run. Failure-suite cleanup likewise records owned-process scope. Shared-host process permissions prevent proving global descriptor absence, so `clean:false` / `fd_absence_proven:false` remain intact alongside `owned_cleanup_proven:true`. Public evidence is restricted to allowlisted signed observations, plans, journals, manifests, logs and cleanup reports. Raw SQLite stores and private keys are not exported.

The [sealed Phase 1 capsule](../../experiments/apcc-1/w2-renewal-20261018/README.md) contains 247 public entries, all five successful individual-window CLI audits and the successful whole-repetition audit. Its external `SHA256SUMS` digest is `6570e801a85f7893fde2a19b82778f51249a2e1dd834ca1afc20ca796057c76b`. All member checksums pass. Final code lives in `src/constitutional_swarm/apcc_empirical/w2_renewal_runtime.py`, `w2_renewal_journal.py`, `w2_renewal_codec.py`, `w2_renewal_campaign.py`, and `w2_renewal_replay.py`; the CLI is `scripts/run_apcc_w2_renewal.py`. The capsule preserves exact source archives for replay rather than relying on later live source.

## Numeric candidate and remaining gates

The approved numeric policy schedules 10,000 operations within each single window: 1,000 / 100 / 20 seconds at 10 / 100 / 500 operations per second. The frozen current plan requires 10,000 on-time commits and zero late completions per window. Multiple chains may count within that window; windows or repetitions may not pool denominators. The approved 25 / 200 / 225 / 1,000 / 2,000 ms bounds remain fixed.

An isolated, reviewed candidate implements **only the first cold 10/s row**, seed 104729, repetition 0. It uses one initial observer epoch and performs no renewals. Its 198,000 ms setup cutoff is checked against a conservative pre-authority monotonic origin and signed launch validity, reserving 1,000,000 ms for the window, 1,000 ms for drain and 1,000 ms margin within the original lifetime. Setup infeasibility is a preserved failed attempt, not grounds to extend the cap or relax timing.

Seeded payloads retain fixed byte sizes. The first overload or late operation stops new admission while admitted proofs drain. A controller-signed witness binds the actual post-fsync ledger completion to the fixed window drain deadline; it remains accounting metadata, never an authority fact. Failure artifacts preserve primary/cleanup errors, measured progress and actual prefix hashes without inventing overloads or claiming unaudited proofs passed.

The 803-input numeric generation passed independent code review and full `make verify`: **3,771 passed, 57 skipped, 103 deselected**. All 979 gate inputs were unchanged. An externally pinned acceptance receipt binds the completed Phase 1 capsule and actual source-delta gate before execution.

The real first cold attempt provisioned 100 workflows and 10,000 scoped producer registrations. Setup, including bootstrap, checkpoint and launch, took **104,810.047485 ms**, within the 198,000 ms cutoff. The operation window stopped after **66 on-time commits and one admission rejection**, with **zero late completions and 9,933 slots unexecuted**. Its scheduled denominator remains 10,000; neither the prefix nor other windows supply missing commits. This is a fatal result, not a completed qualifying window. The other **344 windows remain unexecuted**, including 100/s, 500/s and numeric warm execution.

The recorded rejection is slot 66 (chain 2, node 4), with its 6,625 ms deadline and 6,636.093585 ms decision. The controller labels it `permit_exhausted`; maximum observed occupancy was 2/16, so this evidence does not establish saturation of all 16 permits. Median admission-through-release latency for the 66 completed operations was **94.773472 ms**, maximum **146.694142 ms**. Median commit acknowledgement was **50.349383 ms**, including authority validation, IPC and durable persistence. These stages do not isolate fsync, and the shallow failed prefix cannot establish latency for complete depth-99 chains. No durability or proof path was changed for these measurements.

All four exact owned child PIDs are absent and controller descriptors are clear. Global shared-host FD absence remains unproven. The process exited normally after preserving the fatal result; exit 0 is not qualification.

The original fresh numeric CLI exposed an initialization defect: replay writes diagnostic `Context.progress`, which execution initializes but the original replay constructor does not. Its rejected audit and stack trace remain evidence. The separately versioned `scripts/run_apcc_w2_numeric_audit.py` initializes only that diagnostic map in a subclass, then invokes the unchanged original constructor and full `audit_result` validation. It never starts execution, changes a signed clock, patches a proof check, or rewrites the 803 generation inputs or ledgers. Its own SHA256 and the original generation-manifest SHA256 are mandatory external arguments; it enforces fresh `-I -S` isolation and hashes generation source before and after replay.

The repaired fresh auditor verifies the fatal prefix and rejects a success request. All 12 focused auditor checks pass, including wrong pins, truncation and profile downgrade. Independent review finds no unresolved source issue. The additive auditor full `make verify` passed: **3,774 passed, 66 skipped, 103 deselected**. All **981 gate inputs** and **805 live primary inputs** match their frozen hashes. Nine external-evidence auditor tests are skipped in the default gate and passed separately as part of the 12-case run. Campaign and cell qualification remain false.

The numeric outcome capsule is assembled separately from the immutable Phase 1 capsule. It preserves the original 803-input generation, the two additive auditor files, all rejected audits, final review/gate evidence, stage timings and the admission-rejection analysis. The latter identifies shared execution-handle RPC contention as a source-backed inference; it does not prove the precise lock-wait cause or authorize changing epoch fencing.

## Published numeric outcome

The [sealed numeric failure capsule](../../experiments/apcc-1/w2-numeric-cold-20261018/README.md) contains **324 public entries**. Its external `SHA256SUMS` digest is `885ee57c8fa2a944d772788d771dcf1127018d40aeedcfd16d9ebd5451c555e0`; every member checksum passes. Its coverage record retains the first outcome as fatal and all other 344 windows as unexecuted. Numeric qualification remains incomplete.
