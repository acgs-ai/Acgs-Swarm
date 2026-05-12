<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# docs

## Purpose
Long-form design and protocol documentation for constitutional-swarm. User-facing README lives at the repo root; this directory holds deeper protocol drafts and internal architecture notes.

## Key Files
| File | Description |
|------|-------------|
| `maci_dp_protocol.md` | MCFS privacy and MACI (Minimum Anti-Collusion Infrastructure) differential-privacy protocol draft — the privacy story for `private_vote.py`, `privacy_accountant.py`, and federated voting |
| `internal/swebench_swarm_backend_and_recovery.md` | SWE-Bench swarm backend and recovery-plane operator note for `mini_swe_agent.py`, `recovery_orchestrator.py`, and the runner scripts |
| `internal/mini_swe_agent_external_baseline.md` | External baseline/control decision record for optional mini-swe-agent integration |

## For AI Agents

### Working In This Directory
- Treat these as living design docs — update alongside the implementing code.
- Protocol docs should reference the exact Python module implementing them (e.g., `src/constitutional_swarm/private_vote.py`).
- Do not commit generated artifacts (PDFs, rendered HTML) here; keep Markdown-only.

## Dependencies

### Internal
- Cross-referenced by `README.md` (repo root) and by paper drafts under `paper/` and `papers/`.

<!-- MANUAL: -->
