# APCC-1 next source candidate: fresh W1 provisioning

Status: design only, eligible for a bounded prototype after the current source
baseline is frozen. No implementation, transaction saving, or speedup is claimed.
The frozen v3 window, success floor, storage profile, and live proof checks remain
unchanged.

Current W1 provisioning creates a workflow and registers its producer through
two separately acknowledged admin operations. A new private composite request
could place the two existing signed control commands inside one existing GCB
transaction. Keep the public operations unchanged and retain both distinct
signed `CREATE_WORKFLOW` and `REGISTER_AGENT` payloads, audit events, signature
checks, and control-version increments (`V` to `V+1` to `V+2`). A new combined
`ControlAction` is unsuitable: workflow attachment authenticates the create event,
and stale-authority checks inspect registration events.

The candidate would add a private boundary method in
[`governed_commit.py`](../../src/constitutional_swarm/governed_commit.py), a
private trusted-admin builder and exact-field admin dispatch in
[`authority_service.py`](../../src/constitutional_swarm/authority_service.py),
and replace only the adjacent fresh-W1 provisioning calls in
[`qualification_v3.py`](../../src/constitutional_swarm/apcc_empirical/qualification_v3.py).
Signed response publication must follow the single successful durable commit.
Provisioning stays inside operation timing, before scheduler attachment.

Inside the unchanged `BEGIN IMMEDIATE` transaction, require exactly the ordered
pair, one absent workflow, default profiles, one independent node, generation one,
one initial trusted producer, matching store/workflow/admin identities, unused
distinct command IDs, and contiguous expected versions. Revalidate each command
against the authoritative seal; a version observed while constructing signatures
does not replace this check. Reuse existing validation, action, audit, and CAS
logic rather than invoking two independently committing public methods.

A savepoint must cover both actions, success audit events, and version updates.
On any expected second-action failure, roll back that savepoint before recording
denial/security events at the original version. Persistence or checkpoint failure
rolls back the outer transaction and produces no success acknowledgement. A lost
response after commit leaves both transitions durable; it does not authorize
retrying or resuming a partially provisioned public workflow.

Do not combine scheduler attachment, claim, sink delivery, outbox recovery, or
revocation with this operation. Preserve both public acknowledgement boundaries,
WAL/FULL, schema, connection lease checks, and existing checkpoint attestation.
The expected successful W1 write-boundary reduction is seven to six, plus one
admin round trip; creation/registration affect legacy GCB tables, so a saved
checkpoint signature is not assumed.

Acceptance requires state/signature/audit/version parity, successful attachment
and original-verifier replay, atomic rollback after every action/CAS/audit fault,
stale versions and signature/identity/order/replay rejection, and rejection on
execution/status channels. Commit/checkpoint failure and response loss need
explicit tests. Instrument the actual transaction count, then freeze and compare
isolated source capsules in balanced whole-operation runs. Retain the candidate
only if net improvement is repeatable; do not adopt the architectural estimate as
performance evidence.
