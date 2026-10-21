# APCC-1 novelty verdict

Recorded: **2026-10-16**. Classification: **INSUFFICIENT EVIDENCE**.

`BASELINE_REMOTE_EVIDENCE_INCOMPLETE` remains applicable. APCC-1 qualification
is partial; production readiness is not claimed. This document supplies the
missing verdict artifact without closing the frozen experiment plan.

## Evidence boundary

The research basis is the repository's [prior-art ledger](APCC-1-Prior-Art.md),
whose research cut-off and retrieval date are **2026-08-28**. This document
does not refresh those sources or upgrade their evidence grades. Missing
archives, hashes and exact claim locations remain gaps. The ledger's
systems-abstraction ceiling is a possible ceiling for further evaluation,
not an awarded classification.

The [historical results](APCC-1-Results.md) retain their measurement SHAs and
dates. Fresh local checks belong to the separate
[resume record](APCC-1-Resume-2026-10-16.md). Neither record establishes absence
of the APCC conjunction from prior art.

## Implementation, assurance and campaign

The conjunction in the [protocol specification](APCC-1-Protocol-Spec.md)
combines reconstructible role-bound statements and signatures; exact workflow,
version and attempt bindings; predecessor causality; fresh current authority
status; and one authority transaction persisting the certificate, logical
pointer, replay identity, decision and outbox intent.

| Evidence category | Supported interpretation | Remaining limit |
| --- | --- | --- |
| Existing implementation | Python store/service/verifier implementations and a separate Go verifier exist. | Existence and integration do not establish a new mechanism. |
| Implementation assurance | Local tests, independent canonicalization checks and bounded formal models support the properties they exercise. | They do not establish the full threat model, production readiness or novelty. The fresh PostgreSQL test gate passes in the specifically recorded environment; full empirical qualification remains open. |
| Frozen campaign | The original plan and qualification protocols define distinct experiments. | The 102,416-cell campaign, complete B6 execution and empirical ablations remain unclosed. Qualification subsets cannot replace the frozen matrix. |
| Prior-art comparison | The ledger identifies substantial component and combination overlap. | Hashed source archives, complete claim charts and the required independent acceptance reviews remain missing. |

## Strongest counterargument

**The exact APCC interface may be a predictable composition of established
systems mechanisms.** The ledger's adverse case combines CCF/IA-CCF receipts
and governed state, Corda's signed causal transactions and commit authority,
or Fabric's endorsed ordered commit, with current-status checks and a
transactional outbox. TCT supplies another proof-carrying transaction
comparison. Authenticated Workflows, Proof of Execution and CommitGuard are
close agent-domain comparisons in that ledger, with their 2026 preprint dates
and evidence grades requiring qualification.

These are summaries of the existing ledger, not newly verified findings.
Its adverse-combination matrix leaves the exact APCC wire/store contract as
a comparison question. A portable certificate and one API around that
contract do not themselves demonstrate an unexpected technical effect.
Conversely, this incomplete record does not establish that one qualifying
source fully subsumes the entire conjunction.

## Requirements for reconsideration

1. Preserve immutable, hashed primary sources and complete element-by-element
   claim charts for the closest ledger entries, retaining dates, grades,
   trust assumptions and exact page/section locations.
2. Complete required B0–B6 measurements and empirical ablations under an
   explicitly versioned protocol, with raw outcomes, positive controls,
   environment identity and content hashes. Preserve failed runs.
3. Resolve implementation and measurement blockers and obtain the four
   independent acceptance reviews required by the
   [experiment plan](APCC-1-Experiment-Plan.md#artifacts-and-stopping-rules).
4. Evaluate whether the exact conjunction produces a documented technical
   effect that the strongest adverse compositions do not already predict.

The user's authorized low-rate duration revision changes future measurement
methodology. It does not repair historical incomplete runs or change this
classification. A green local validation gate cannot close these research
requirements by itself.
