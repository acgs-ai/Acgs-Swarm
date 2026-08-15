# Public API compatibility

Status: accepted for the product-convergence runtime.

## Decision

`constitutional_swarm` publishes a **stable eager façade** and an **unstable
legacy compatibility namespace**.

1. `constitutional_swarm.__all__` is the stable façade. It is what
   `from constitutional_swarm import *` returns.
2. Default `import constitutional_swarm` eager-loads only that façade:
   AgentDNA, DAG/executor, ConstitutionalMesh, settlement stores, and the
   v0.1 receipt types/helpers.
3. Legacy research, eval, Bittensor, LangGraph, and benchmark names remain
   importable as `from constitutional_swarm import LegacyName`. Those names
   resolve through lazy `__getattr__` and are **not** a stability promise.
4. Direct submodule imports (`import constitutional_swarm.swe_bench`) stay
   valid and remain the preferred way to reach research/eval code.

This is an intentional compatibility break for star-import callers that
previously received the research-heavy surface. Direct legacy imports are
not restored as eager default imports, because that would pull optional
dependencies (`numpy`, `torch`, `bittensor`, LangGraph, SWE-bench) into
every install.

The next published version after this branch should be **1.1.0** (minor
bump for an observable import-star change). This checkout does not
publish a release.

## Receipt identity (v0.1)

`SettlementRecord.receipt_digest` is the receipt **payload digest**
(canonical statement identity). It is not the signed-envelope
`receipt_hash`. The canonical settlement digest excludes `receipt_digest`
so the pointer cannot appear in its own pre-image.

A receipt file is completed evidence only when a committed settlement
points at that payload digest. Mesh receipts are signed with the
dedicated `settlement-receipt` key id. Request/vote signatures use a
different key and a different pre-image.

## Non-goals

- Do not reintroduce eager optional dependencies to preserve import-star.
- Do not add a fourth evidence format.
- Do not depend on `gove_zone`.
