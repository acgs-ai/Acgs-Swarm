# Core concepts

This page defines the project vocabulary used across docs and APIs.

## Governed execution
Execution where policy checks happen in the runtime path, not only in post-hoc auditing.

In `constitutional-swarm`, this is centered on `AgentDNA.validate(...)` and mesh vote pathways.

## Local constitutional enforcement
Each agent can carry embedded policy checks (`AgentDNA`) so safe/unsafe decisions are made locally before outputs are accepted.

## Orchestrator-free execution
Tasks can be represented as DAGs (`TaskDAG`) and claimed/executed by capable agents (`SwarmExecutor`) without a central orchestration service.

## Peer validation
Produced outputs are evaluated by assigned peers in `ConstitutionalMesh`.
Votes are signed and quorum determines acceptance/rejection.

## Durable settlement
Final validation outcomes can be persisted (`JSONLSettlementStore`, `SQLiteSettlementStore`) for replay and recovery.

## Replayable receipts
Governance receipts are canonicalized, hash-linked, and verifiable via `governance_receipts` and CLI tooling (`acgs-verify-receipts`).

## Bounded trust dynamics
Trust updates can be projected into bounded spaces via:
- `spectral_sphere.py` (current runtime direction)
- `manifold.py` (Birkhoff/Sinkhorn baseline control)

## Stable vs advanced vs research
- Stable: core runtime APIs that most users should start with.
- Advanced: optional but practical runtime modules.
- Research: experimental modules intended for evaluation and iteration.

See [`README.md`](../README.md) maturity tiers and [`docs/roadmap.md`](roadmap.md).
