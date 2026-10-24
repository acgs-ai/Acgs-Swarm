# W2 fixed-window campaign protocol (controller revision v1)

This additive controller uses `apcc_empirical/w2_campaign.py` and
`apcc_empirical/w2_pacing.py`. Authority certificates, signed checkpoints, causal
profile encoding, default depth64, and the public B6 adapter remain unchanged.
The existing signed W2 observer experiment identity is retained; the distinct
`APCC-1.w2-campaign-v1.ledger` controller seal binds campaign accounting and cannot
grant authority. Every admitted operation uses the unchanged W2 proof checker,
including fresh full causal closure traversal, scoped identities, fixed payloads,
exact-field APCC codecs, signed launch and ordered signed observation stream.

## Pacing

`bounded-round-robin-16-v1` schedules node proposals, not chain initiation rates.
For each batch of at most16 chains it schedules every root, every node1, and so
on through node99, then advances to the next batch. Slot i starts at
`floor(i * duration_ns / scheduled_operations)`. Admission ends exclusively at
`min(slot_start + admission_grace_ns, duration_ns)`. A rejected slot is never
caught up. Descendants of rejected predecessors remain rejected. An incomplete
chain cannot be rotated out to repair the denominator.

Admission grace, operation SLA, drain and floor are mandatory explicit parameters.
The user explicitly selected mandatory parameters and deferred qualification;
neither a window nor a repetition verifier can emit campaign eligibility here.
SLA starts at admission; a completion is late if its verification ends after that
SLA or after `duration_ns + drain_ns`. All controller timings are monotonic epoch
offsets; wall-clock observation checks remain separate. Overloads contain no
authority mutation or manufactured authority denial. Reasons describe controller
observations, never authority facts. Sixteen real workers hold their permits
through full verification. No artificial overlap barriers are installed.
An admission deadline rejection remains generic when a previously admitted
predecessor's acknowledgement races the final poll; it cannot claim that the
authority had not committed. A missing predecessor slot can be classified
separately without contradicting a later signed observation.
Admission is timestamped after reserving a real permit and before publishing the
work item. A reservation at or beyond its exclusive deadline releases the permit
without queueing work or assigning an ordered observation ticket.

Workflow provisioning occurs before the window clock. Provisioning is not counted
as workload throughput or hidden inside operation latency. The scheduler has at
most16 independent projections, each using the same existing authenticated
execution channel. Per-thread lane routing preserves the genuine B6 handle.
Mutation and snapshot exclusion remains global; independent proof verification
can overlap the next committed node or another chain's execution.

## Lifecycle and evidence boundary

Each invocation creates an exclusive evidence directory, fresh authority database,
keys, run identity and monotonic epoch. Separate repetitions cannot share files.
The signed observer launch is bound to the exact W2 configuration. Reusing a lane
requires all100 previous proofs to finish and the mutation/snapshot lock to clear.
Failed or cancelled runs retain an unsealed prefix and do not qualify.
Cancellation is checked inside mutation exclusion before starting new writes.
Failure wakes admission and ordered-observation waiters; cleanup attempts every
owned worker, observer and authority child even if an earlier close raises.

`run_repetition` supports one to four explicit window plans. Window000 is cold;
subsequent windows are warm continuation on the same populated store and the
same handles. Every previous scheduled chain must complete full verification
before transition, and the mutation/snapshot lock must be clear. This does not
exercise reopen and makes no reopened-store claim. Each window has a fresh
monotonic epoch, separate ledger and disjoint workflow identities; each new
repetition uses a fresh store. Warm ledgers bind the previous ledger's SHA256 and
fixed sibling filename. Independent warm replay recursively consumes every prior
signed observation from the original launch. Missing ledgers, sequence resets,
profile substitution and truncated repetition manifests reject.

The existing observer lifetime cap is1,200 seconds. Full10/s warm qualification
(three1,000-second warmups plus measurement) cannot fit that cap. Renewal/reopen
requires a separately reviewed key-preserving lifecycle design. Generating fresh
keys to reopen an old signed store, shortening warmups or increasing the cap is
forbidden. No warm reopen agreement is claimed by a cold-only ledger.

The CLI currently produces functional windows with qualification disabled.
Campaign qualification also requires approved numeric timing parameters, complete
cold/warm repetition coverage and an externally sealed provenance capsule. A
synthetic accounting pass or a local functional run creates zero qualification
successes. W1 v3 remains9,220/10,000,780 overloads,0 late completions. PostgreSQL
W2, W1 provisioning changes, W6 and the public adapter are outside this revision.

Audit each ledger in a fresh uninstrumented process using
`scripts/run_apcc_w2_campaign.py verify --ledger PATH --expected-sha256 SHA`.
The external SHA256SUMS pin is mandatory. The verifier derives counts from every
slot, binds admitted timings to signed proof rows, traverses every committed
prefix without a verification-result cache, checks worker occupancy and complete
lane rotation, and rejects truncated or substituted accounting.

Preserve all12 prior bundles and589 sealed entries, including the W2 diagnostic
bundle added after the earlier11-bundle/542-entry boundary. New evidence lives in
separate directories; historical manifests and frozen matrices are not rewritten.

## Functional execution example

These explicitly chosen local functional parameters are not approved campaign
thresholds. The70-second/100-operation window deliberately provides headroom;
it is not one of the frozen10/100/500 proposals-per-second cells.

```sh
uv run --no-sync python scripts/run_apcc_w2_campaign.py run \
  --output .context/w2-functional-new --windows 2 \
  --duration-ns 70000000000 --scheduled-operations 100 \
  --admission-grace-ns 690000000 --operation-sla-ns 5000000000 \
  --drain-ns 10000000000 --operation-floor 100
```

Record external hashes of `window-000.jsonl`, `window-001.jsonl` and
`repetition.json`. Audit each ledger with `verify` and audit the manifest with
`verify-repetition --manifest PATH --expected-sha256 SHA` in fresh processes.
Supply the preceding ledgers when auditing a warm window. These commands verify
functional evidence and always report `campaign_eligible: false`.

The separately reviewed [long warm-cell lifecycle boundary](APCC-1-W2-Warm-Lifecycle-Boundary.md)
records the remaining protocol work without implementing observer renewal.
