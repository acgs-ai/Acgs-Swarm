# W2 long warm-cell lifecycle boundary

Status: design only. No authority renewal, retained secret source, checkpoint
change, launch-lifetime increase or transaction change is implemented here.

The frozen10/s window lasts1,000 seconds. Three warmup windows and one measured
window require at least4,000 seconds, excluding provisioning and proof drain.
The current observer launch cap is1,200 seconds; closing its observer revokes
the authority lifecycle. Authority private keys are consumed by isolated child
startup and are unavailable to the campaign controller. A new configuration
cannot reopen the existing signed store because its trust keys differ.

Bounded warm continuation can reuse the original authority, scheduler and observer
when the sum of all explicit windows, drains and launch margin fits the existing
cap. It requires complete verification of every previous chain, clear mutation
and snapshot exclusion, unchanged exact profile/configuration and a continuous
signed observation stream. Each ledger has a new monotonic clock epoch and an
externally pinned chain of predecessor ledgers; replay starts at the original
signed launch and consumes every preceding observation. No replay counter is
invented or reset.

A future long-cell protocol needs independent review before implementation:

1. A trusted supervisor requests renewal only after full worker drain and a
   coherent attested snapshot. The authority session, exact configuration digest,
   SQLite file identity and semantic checkpoint must agree with the original
   launch and every previous renewal. The existing launch does not contain the
   configuration/checkpoint digest: verify the exact authority-signed W2 semantic
   checkpoint separately and bind its configuration digest in the renewal proof.
   A controller header cannot substitute for that authority proof.
2. Preserve the existing controller-signed observer launch domain and signer.
   An authority-owned key source separately signs an exact-field, domain-separated
   continuity statement without returning authority secret material to the
   controller. A dedicated scoped renewal signer role must be specified and
   reviewed; an authority key cannot be repurposed as the controller signer.
   The statement binds the prior launch digest, final observation sequence/digest,
   successor launch digest, exact signed checkpoint digest and unchanged authority
   configuration digest.
3. Each individual launch retains its existing lifetime cap. The campaign plan
   declares a finite maximum number of renewals and total elapsed lifetime;
   open-ended renewal is invalid.
4. Renewal cannot revive a revoked/failed authority session. In-flight work,
   incomplete chains, profile downgrade, stale checkpoint, mismatched file or
   sequence rollback fail closed before any successor admission. A durable,
   monotonically increasing renewal index and unique idempotency key must bind
   exactly one predecessor/successor relation. Specify an explicit state-machine
   branch for drained, successor-prepared, predecessor-retired and successor-active
   states, including crash recovery. It must never activate two observer/status
   channels or reinterpret the existing revoking observer-close transition.
5. Fresh-process replay validates the entire signed launch/renewal/observation
   chain, plus controller timing records and external capsule hashes. Controller
   assertions alone cannot attest key custody, profile agreement or reopen.

The reviewed transcript design must specify protocol/domain/version, experiment,
run/store/repetition identities, prior and successor launch digests/session IDs,
final prior observation sequence/digest, authoritative trust sequence/head, signed
semantic checkpoint digest, exact configuration digest, monotonic renewal index,
external plan digest, cumulative renewal/lifetime bounds and unique nonce. Verify
exact fields and reject every fork or second successor of the same predecessor.

Required negatives include unapproved renewal, missing predecessor launch,
replayed renewal, altered profile or checkpoint, overlapping observer lifetimes
without a bound handover, partial verification drain, observer crash and
cancellation during handover. Existing default launch bytes and public adapter
behavior must remain unchanged. Until this protocol is approved and implemented,
the4,000-second warm cell remains explicitly unsupported.
