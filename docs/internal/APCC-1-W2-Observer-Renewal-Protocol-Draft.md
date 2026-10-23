# W2 observer renewal protocol draft v1

Status: reviewable proposal only. No renewal endpoint, signer delegation, database
schema, bootstrap path or lifecycle transition described here is implemented.
Existing launches retain their1,200,000ms maximum lifetime and ordinary observer
closure still revokes the session. Campaign qualification remains deferred.

This selects **observer renewal within one continuing authority process**, avoiding
authority-key export or full-stack reopen. A failed authority requires a new
repetition; renewal cannot recover or revive it. A future implementation starts a
new campaign with renewal enabled at its cold bootstrap. It cannot retrofit a
historical sealed repetition or modify its signed checkpoint/configuration.

## Encoding and trust roots

All bodies below use the existing APCC-CJ1 canonical object encoding, UTF-8,
duplicate/unknown-field rejection and no trailing bytes. These are separate
protocol objects, not additional fields accepted by any APCC certificate,
checkpoint, observation or launch codec. Every field listed is mandatory.
Counters/times are canonical nonnegative decimal strings (no sign or leading
zeroes except`0`), bounded by the existing safe-integer maximum2^53−1. Every
protocol digest field uses the existing canonical unpadded base64url encoding of
exactly32 SHA256 bytes, without a prefix. External SHA256SUMS remains lowercase
64-character hexadecimal; decode its hash bytes and compare those same bytes
when binding an externally pinned plan to its protocol digest. These textual
encodings are not interchangeable without that explicit conversion.
New renewal/delegation nonces decode to exactly16 bytes; existing launch nonces
remain32 bytes under their unchanged codec. Public keys/signatures decode to
32/64 bytes. Identity strings follow the existing authority identity validation.
Null and floats are invalid.

Every signature object has exactly`body`, `key_id`, `signature`; the signature
preimage is its specified domain, a NUL separator, then canonical body bytes.
The algorithm is fixed Ed25519; no algorithm-negotiation field is accepted.
The complete signed object digest identifies a transcript record. A successor
launch retains the **existing controller signer, domain and exact launch codec**.

The proposed authority-owned renewal key is generated inside the authority child
at cold bootstrap and never exported. A separate delegation is signed by the
existing store-scoped COMMIT key under
`APCC-W2-OBSERVER-RENEWAL-DELEGATION-V1`. This is an explicitly proposed new
privileged signing purpose requiring implementation review; a commit signature
does not implicitly authorize it in the current runtime. The delegation body has
exactly:

| Field | Meaning |
|---|---|
|`protocol`|Literal`APCC-W2-OBSERVER-RENEWAL-DELEGATION-V1`|
|`authority_store_id`, `authority_session_id`, `repetition_id`|Original cold identities|
|`renewal_key_id`, `renewal_public_key`|Dedicated public renewal identity|
|`role`|Literal`observer-renewal-v1`|
|`initial_launch_digest`, `plan_digest`|Original controller launch and externally approved plan|
|`config_digest`, `checkpoint_digest`|Exact configuration and existing authority-signed semantic checkpoint|
|`not_before_ms`, `not_after_ms`|Finite delegation validity inside the plan lifetime|
|`nonce`|Unique delegation nonce|

Verify the delegation with the original exact COMMIT trust binding, independently
verify the existing signed semantic checkpoint and its W2 configuration digest,
and match the original signed launch. A controller header is not an authoritative
configuration proof. The delegated key cannot sign APCC commits/statuses, admit
nodes or broaden its store/session/repetition/plan scope.
Its public key must differ from the controller, every observer and every APCC
role binding. Each signature object's exact key ID must match its pinned signer
binding or delegation; matching only the public key is insufficient.

## Approved plan

The external plan artifact binds the exact W2 profile, cold/warm window plans and
repetition count, controller/authority trust roots, renewal public key/key ID, and explicit
`maximum_renewals`, `maximum_total_lifetime_ms`, `handover_timeout_ms` and
`maximum_single_launch_ms`. No operational defaults are supplied. The last value
cannot exceed1,200,000ms. Total validity runs from the original launch's not-before
time; renewal never restarts it. All declared windows, drains and handover budgets
must fit this bound before cold admission. The externally approved SHA256 is the
plan root; a controller cannot replace it while resealing diagnostic metadata.

The plan references the renewal public key/key ID, not a delegation digest.
Compute the plan digest first, then sign its binding delegation. The final
evidence capsule pins both digests. This avoids a circular plan/delegation hash.
At activation require original-not-before <= issued/activation time <= the
minimum of delegation-not-after and original-not-before plus the total-lifetime
bound. Each successor interval is positive, inside those bounds and no longer
than the explicit single-launch bound. Activation must precede the prior launch's
expiry. There is no expiry-gap recovery or renewal of an expired session.
The authority also enforces its monotonic elapsed budget from cold bootstrap;
the continuity statement's cumulative elapsed value must not decrease or exceed
the total-lifetime bound. Wall-clock rollback cannot restart or extend that
budget. These remain process-clock attestations under the existing trusted-host
clock assumption; the protocol claims no independent hardware time proof.

## Continuity statement

The authority-owned renewal key signs under
`APCC-W2-OBSERVER-RENEWAL-CONTINUITY-V1`. Its exact body fields are:

| Field | Meaning |
|---|---|
|`protocol`|Literal`APCC-W2-OBSERVER-RENEWAL-CONTINUITY-V1`|
|`experiment_id`, `run_id`, `authority_store_id`, `authority_session_id`, `repetition_id`|Unchanged scope|
|`delegation_digest`, `plan_digest`|Pinned authorization roots|
|`renewal_index`|Prior durable index plus one; initial index is zero|
|`prior_launch_digest`, `successor_launch_digest`|Exactly one predecessor/successor|
|`prior_observer_session_id`, `successor_observer_session_id`|Session handover binding|
|`prior_final_observation_sequence`, `prior_final_observation_digest`|Final signed prior observation|
|`trust_change_sequence`, `trust_log_head`|Exact authority trust position at drain|
|`config_digest`, `checkpoint_digest`|Unchanged exact W2 configuration and current signed checkpoint|
|`issued_at_ms`, `successor_not_after_ms`|Finite time bounds inside delegation and plan|
|`cumulative_elapsed_ms`|Authority monotonic elapsed time since the original cold bootstrap|
|`nonce`|Unique handover/idempotency identity|

The successor launch is prepared and controller-signed before this statement, but
cannot activate a status/observation channel until continuity is durably accepted.
Exactly one statement digest may succeed for a `(repetition_id, renewal_index)`
and one successor for each prior launch. An identical retry returns the original
record; a changed nonce/body or second successor rejects. It cannot mint a new
launch on every retry or consume a second renewal index.

## Proposed durable handover state machine

1. **ACTIVE:** only the current observer has a usable status/read channel.
   Requesting renewal first stops new controller admissions and drains every real
   worker permit through full verification. Incomplete chains reject handover.
2. **DRAINED:** establish a durable authority-owned admission/mutation fence;
   reject scheduler and admin workload mutations through activation. Controller
   stopping/locking alone cannot enforce this fence. Under that exclusion, the
   authority independently checks workflow completion, exact checkpoint/config
   and trust head. Full proof-verification drain remains a separate controller
   measurement, not a fact attested by the authority.
   The prior observer signs its final coherent observation. Persist the unique
   handover reservation and next index before preparing the successor.
3. **PREPARED:** bootstrap a hardened successor process with a disabled, read-only
   channel. Verify PID launch proof, exact store/profile/checkpoint and the
   controller-signed launch; then commit the continuity statement durably before
   returning its signature. Preparation
   neither retires the old observer nor admits workload.
4. **RETIRED:** atomically revoke the prior channel capability in authority-owned
   durable state and bind its terminal observation. Only this explicit, validated
   handover branch permits planned retirement without the ordinary observer-close
   revocation. An unexpected prior crash before retirement fails the repetition.
5. **ACTIVE successor:** after durable retirement and continuity validation,
   persist activation before enabling its single channel or resuming admissions. The old
   observer is joined and cannot issue new usable observations. An unplanned
   authority failure or successor failure fails closed.

Crash/retry rules: before a durable reservation, cancellation fails this handover
without creating a successor. After reservation, cancellation or prepared-child
loss fails the repetition; it cannot resume the prior session with a different
successor or reuse the index. Identical retries with the same live bound successor
may continue the recorded state transition. If retirement committed,
the old channel stays permanently disabled. A retry may activate only the already
bound live successor; otherwise the repetition fails. An authority process restart
always fails this renewal-only repetition. No recovery branch exports keys,
reopens a store with fresh keys, reinstates a retired observer or substitutes a
new successor after retirement. Every timeout cancels admission and cleans up
owned prepared children. Durable state transitions must use the existing
durability/proof discipline; no transaction adoption is authorized by this draft.

## Independent acceptance requirements

Replay starts at the original signed launch and authoritative checkpoint, verifies
the scoped delegation, externally approved plan, each continuity signature and
single-successor relation, then consumes all observations in order. Across a
handover, the signed terminal/start continuity anchors establish the next stream;
the successor's initial trust sequence/head must equal the drained continuity
position. Its observer session/key/launch nonce are fresh, and its unchanged
observation stream starts at local sequence1. Reject every prior-session
observation after the recorded terminal sequence even if its launch has not yet
expired. The controller cannot supply an arbitrary initial sequence. Every ordinary APCC
proof and full W2 causal closure still verifies through its unchanged codec.

Tests must cover fork/replay/nonce/index conflicts, signer-role substitution,
checkpoint/profile downgrade, stale trust head, missing final observation,
preparation/retirement/activation crash points, unexpected prior death, poisoned
successor launch, lifetime/count exhaustion, admission during drain, incomplete
chain rotation, cancellation and orphan/descriptor cleanup. A fresh process must
verify every cold/warm ledger and the whole externally sealed capsule. No
qualification claim follows from this draft or a synthetic continuity transcript.
