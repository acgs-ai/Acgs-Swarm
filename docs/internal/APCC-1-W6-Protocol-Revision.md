# APCC-1 W6 protocol revision

## Decision and evidence status

On 2026-10-16 the owner authorized preparation of a reviewed protocol revision
supporting one 10,000-node workflow. This document defines the additive
`w6-independent-10000-v1` profile. Authorization to prepare the revision is
accepted. The local node-profile implementation is qualified by the checks in
the checkpoint below, including independent review and the final repository
gate. Empirical W6 execution remains open. This document does not record a
completed campaign or a new freeze of the measurement artifacts.

The [frozen experiment plan](APCC-1-Experiment-Plan.md#frozen-workload-matrix)
requires W6 to execute one DAG of 10,000 independent nodes, using 1,000 logical
agents round-robin, executor concurrency 100, 1 KiB inputs, 4 KiB outputs, and
exactly 10,000 commits. Splitting this DAG into smaller workflows changes that
experiment. The runtime's default 1,000-node admission bound cannot admit the
required DAG. This revision supplies an explicit, bounded admission profile;
it does not change those workload dimensions.

The original protocol, experiment plan, matrix v1/v2, schemas, qualification
protocols, and historical results remain unchanged. The
[measurement revision v2](APCC-1-Measurement-Revision-v2.md) continues to apply;
W6 retains its fixed-operation rule rather than a duration threshold.

## Normative profile contract

The following requirements are normative for this revision. A profile is an
immutable choice made by trusted configuration/bootstrap, not a field accepted
from an untrusted scheduler, producer, commit request, or ordinary RPC caller.

| Property | `WorkflowProfile.DEFAULT` | `WorkflowProfile.W6_INDEPENDENT_10000` |
| --- | --- | --- |
| Wire/configuration profile name | Existing default profile | `w6-independent-10000-v1` |
| Maximum workflow nodes | 1,000 | 10,000 |
| Permitted topology | Existing default rules | Independent nodes only; no predecessor edges |
| Default control-frame bytes | 1 MiB | 16 MiB |
| Trusted control-frame override | Existing positive explicit override behavior retained | Positive value no greater than 16 MiB |
| RPC timeout | Existing 2 seconds | Finite 30 seconds |

MiB means 1,048,576 bytes. The frame bound covers the complete encoded control
frame, including its envelope, rather than only the nested workflow payload.
The W6 profile must reject a frame larger than its configured bound before
decoding its payload. A valid node count alone does not authorize a frame that
exceeds that byte bound. The default profile's 1 MiB value is a default, not a
new restriction on its existing trusted explicit-override API.

Selecting W6 does not mean every admitted workflow has 10,000 nodes. Existing
minimum-size and field-validity rules still apply, with 10,000 as the maximum
and independence required for every node. Only a run with the exact frozen W6
shape can qualify as W6 evidence.

The trusted authority, scheduler, executor, and their control channels must
agree on the selected profile. Unknown profile values and profile mismatches
must fail closed. An untrusted request must not upgrade a default authority or
choose a larger frame budget or timeout. Omitting the trusted profile selection
retains the default behavior. No implicit inference from node count is allowed.

## Admission and reopening

Workflow admission must validate the entire candidate before any workflow,
node, or APCC registration write. The existing node identifiers, node
definitions, edge validity,
duplicates, per-node fields, and resource limits must pass, together with the
selected profile's count and topology checks. A W6 candidate with one
predecessor edge, an invalid late node, or 10,001 nodes must leave no partially
registered workflow, node, or APCC state. Existing signed `DENIED` control-audit
records remain permitted and required by their existing audit semantics; a
rejection must not suppress that evidence. Existing transactions remain the
atomic registration boundary after successful admission.

The scheduler's local DAG admission and the authority's persisted-workflow
admission must both enforce the profile. A scheduler-side check cannot replace
authority validation. A matching profile must also be enforced when an executor
attaches an already provisioned workflow, including reload/restart paths.

The admitted profile must be durably bound to each workflow through the existing
signed `CREATE_WORKFLOW` control event, in
`command_material.parameters.admission_profile`. Trusted administration inserts
the selected profile; the ordinary RPC request schema must not accept that
field from callers. This binding uses the existing control-event format and
requires no database schema migration. Legacy records without an admission
profile mean `DEFAULT`; they do not inherit the profile of whichever process
opens the store later.

The persisted admission profile and the configured profile must match on reopen
or attachment regardless of node count. A W6 workflow containing 1,000 or fewer
nodes is still W6 and must not be silently reopened as `DEFAULT`; the converse
mismatch also fails closed. A default-profile instance must additionally reject
an oversized persisted workflow. Explicit W6 configuration remains necessary
after restart; neither a small nor a large node count grants profile authority.
Failure leaves the stored workflow intact.

## Whole-workflow status semantics

The authority may read status for up to 10,000 admitted nodes by internally
partitioning queries into chunks of at most 1,000 identities. All chunks must
run inside one read transaction and produce one semantic attestation for the
whole request. The implementation must not compose independently timed or
independently signed chunk attestations into a claimed coherent snapshot.

Chunking is an internal query strategy. It does not raise the public APCC store
batch limit, change identity matching, or make partial status success valid.
A missing, inconsistent, invalid, or unavailable chunk fails the whole status
operation under the existing fail-closed semantics. Every requested node must
be accounted for before a whole-workflow result is returned. The transaction's
existing store isolation guarantees remain the consistency model.

## Unchanged security and resource boundaries

This revision does not change per-node cryptographic verification, signature
requirements, certificate/proposal binding, nonce ownership, policy or registry
checks, replay behavior, predecessor limits, ancestry/depth limits, causal
closure rules, or public APCC store batch limits. W6 independence removes edges
from this workload; it does not relax validation of edges in other profiles.
Per-node commit authorization and signed-observer verification remain required.
The 30-second transport timeout does not extend observer freshness windows or
signature lifetimes.

The enlarged limits apply only to the selected W6 workflow/control path.
Payload, certificate, observer, and public batch limits do not inherit a
10-fold increase. Internal status chunks remain bounded at 1,000 entries even
when their enclosing workflow contains 10,000 nodes. The default profile
remains available without opting into these larger allocations.

The node, frame, and timeout bounds limit admitted work; they are not a measured
peak-memory guarantee or a throughput promise. Encoding/decoding can retain
multiple copies, and a whole-workflow status result can hold 10,000 entries.
Qualification must record resource observations and timing failures. An
operation that cannot complete within its bound fails rather than extending
the bound automatically. This revision does not authorize unbounded queues,
dynamic timeout growth, partial workflow admission, or a larger public batch.

## Failure and unknown outcomes

Admission rejection must be distinguishable from a commit whose response was
lost. A timeout, child exit, transport failure, or lost response after dispatch
does not prove that a commit was denied or absent. The caller must retain an
unknown outcome until the existing exact-request replay/authoritative
observation path resolves it. Retrying must preserve the original commit
identity and canonical request; it must not mint a replacement identity to
conceal an uncertain outcome.

No unavailable observation may be relabelled `APCC_DENIED`. A legacy denial
before APCC recording remains distinct from an observed APCC denial. Resource
failures and incomplete evidence are retained under the measurement contract;
they cannot be converted into successful operations by changing topology,
concurrency, identities, or operation counts.

## Implementation locations and acceptance checks

The workflow admission and execution path is implemented in
`src/constitutional_swarm/governed_commit.py` and
`src/constitutional_swarm/swarm.py`. Trusted child configuration/bootstrap is in
`src/constitutional_swarm/authority_child.py`; framed control transport,
dispatch, and execution proxies are in
`src/constitutional_swarm/authority_service.py`. Review must follow the actual
spawned call path through these modules, not only direct method tests.

Qualification requires separate implementation, independent review, and
verification evidence for all of the following:

1. Default admission still rejects 1,001 nodes and accepts valid workflows
   within its existing bounds. Existing default frame override behavior and the
   2-second timeout remain compatible.
2. Trusted W6 selection admits a single valid 10,000-node independent workflow
   and rejects 10,001 nodes, any dependency edge, unknown profiles, and profile
   mismatches. Invalid late nodes cause no workflow, node, or APCC registration
   writes; signed denial auditing remains intact.
3. Reopening/attachment rejects persisted/configured profile mismatches even
   below 1,001 nodes, treats legacy unmarked workflows as `DEFAULT`, and rejects
   oversized workflows under `DEFAULT`. Explicitly configured W6 instances
   validate and attach compatible, durably W6-bound workflows.
4. Full control frames at and beyond the configured boundary are handled
   correctly, including envelopes; the W6 bound cannot exceed 16 MiB and its
   timeout remains finite at 30 seconds.
5. Whole-workflow status covers all 10,000 nodes, uses chunks no larger than
   1,000 within one read transaction, and returns one coherent semantic
   attestation. Public batch limits and negative-path behavior remain intact.
6. Spawned integration demonstrates admission, representative real commits,
   exact-request observation targets, verified signed observations, output
   binding, and denial cases under the selected profile. Direct unit tests
   alone are insufficient to establish dispatcher wiring.
7. Existing default-path tests, relevant lint/type checks, and independent
   security review pass without modifying frozen artifacts or weakening
   cryptographic, durability, or evidence thresholds.

Evidence is intended for `experiments/apcc-1/w6-revision-20261016/`, with command
outputs, exit statuses, source identity, environment details, and a hash
manifest. During preparation, logs reside under
`/home/martin/.cache/w6-1016/evidence`. The presence of this document or that
directory alone is not proof that any acceptance check passed. The checkpoint
below records the local qualification result and its evidence limits.

## Exclusions and remaining campaign work

Admission plus representative commits qualifies only the tested protocol path.
It does not establish 1,000 logical agent identities, round-robin assignment,
100-way executor concurrency, 10,000 successful observed commits, all three
target rates, cache/store coverage, repetitions, or measured performance. Those
remain workload-driver and campaign obligations under the frozen matrix.

This revision does not implement workflow rotation, the remaining B6 workload
drivers, the spawned PostgreSQL authority writer, PostgreSQL integration
qualification, the full campaign, ablations, or final APCC-1 acceptance reviews.
An untested store/backend remains unqualified even if the shared profile
configuration exists. Local qualification of this protocol revision removes the
specific node-limit blocker for the tested path; it does not
close APCC-1 or turn earlier incomplete measurements into complete results.

## Qualification checkpoint — 2026-10-16

**Status: local node-profile qualification passed; W6 campaign pending.** The
targeted profile suite and final repository gate pass after the review findings
and integration failures were addressed. Independent code, protocol, and
artifact-cleanup reviews reported no remaining actionable findings. The evidence
directory named above retains both failures and later results. The prior
`resume-20261016` evidence bundle remains unchanged.

| Check | Observed result | Scope and limit |
| --- | --- | --- |
| `python -m pytest tests/test_apcc_w6_profile.py --import-mode=importlib -q` | `27 passed in 21.07s`; exit 0 | Admission, profile, transport, status, and representative spawned-path coverage; not a W6 campaign run |
| Timed targeted-suite invocation | Wall time 21.50 seconds; reported maximum RSS 114,516 KiB | GNU `time` observation for this invocation; not a bound on combined service memory or per-operation performance |
| Facade, admission-fixture, and observation checks | `25 passed in 18.01s`; exit 0 | Compatibility and observer regression checks |
| Disk-backed artifact-cleanup checks | `45 passed in 5.37s`; exit 0 | Btrfs coverage, including the stale-directory-descriptor cleanup regression |
| Tmpfs artifact-cleanup checks | `3 passed in 0.87s`; exit 0 | Additional cleanup regression check in the final gate's filesystem environment |
| Independent code and protocol review | No actionable findings reported after the profile-binding corrections | Review supplements rather than replaces repository verification |
| Initial `make verify` | `7 failed, 3016 passed, 57 skipped, 95 deselected, 1 error in 494.03s`; make exit 2 | Failed Btrfs-backed run retained; not discarded or relabelled |
| Final `make verify` | `3031 passed, 57 skipped, 95 deselected in 190.31s`; make exit 0 | Lint, mypy, agent-check, typecheck coverage, smoke, and default test gate passed; skipped/deselected coverage is not claimed |
| `make verify-wheel` | `isolated wheel gate OK`; exit 0 | Isolated installed-wheel import, facade, CLI, lazy compatibility, and missing-extra checks passed |

The targeted result and resource report are retained in
`w6-profile-final-27.log`; the initial full-gate failure is retained in
`make-verify.log`; the successful final gate is in `make-verify-final.log` under
the preparation evidence directory. Integration repairs covered default-path
harness compatibility, stable-facade expectations, an incomplete admission
fixture, and artifact cleanup with a stale directory file descriptor on Btrfs.
The initial controller-startup timeout is retained with the failed run; the
final gate passed. Timing thresholds and security checks were not weakened.
The isolated wheel result is retained in `verify-wheel-final.log`.

The final gate used the private executable tmpfs directory
`TMPDIR=/run/user/1000/w.kL3` because `/tmp` was exhausted. The first full run used
Btrfs-backed temporary storage; the cleanup regression was separately tested on
Btrfs after its repair. Both environments and their results are retained. The
190.31-second and 494.03-second runs are not a controlled performance comparison
and must not be presented as a speedup. Tmpfs integration success does not
establish disk durability, PostgreSQL qualification, or campaign performance.

The spawned W6 integration checks use a 10,000-node workflow and three
representative observed commits. They configure 1,000 verification keys; this
does not demonstrate registration or operation of 1,000 logical agents. Three
observed commits do not establish exactly 10,000 completed commits, round-robin
assignment, concurrency 100, target-rate execution, or the frozen campaign's
repetitions and store/cache coverage. Those empirical requirements remain open
despite the successful local software gate.
