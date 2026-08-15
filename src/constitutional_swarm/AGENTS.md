<!-- Parent: ../AGENTS.md -->

# constitutional_swarm

## Purpose
Top-level Python package implementing the four breakthrough patterns described in the package paper: (A) embedded Agent DNA constitutional validation, (B) stigmergic DAG-compiled swarm execution, (C) Byzantine-tolerant Constitutional Mesh with peer validation, and (D) manifold-constrained trust propagation (Sinkhorn/Birkhoff baseline and the production-direction Spectral Sphere replacement). Also hosts MCFS research modules — latent DNA residual steering, continuous-time swarm ODE, Merkle-CRDT artifact store, violation subspace / LEACE steering, federated/private voting, epoch reconfiguration, and evaluation scaffolds.

Full module inventory: see `README.md` at the repo root.

## Agent-Critical Files
| File | Why agents must know about it |
|------|-------------------------------|
| `manifold.py` | **Research control — do not "fix" its collapse.** Birkhoff/Sinkhorn baseline; uniformity collapse is retained as empirical proof. `spectral_sphere.py` is the production replacement. |
| `mesh/` | `ConstitutionalMesh` package. Requires Ed25519 vote signatures (`register_local_signer`, `register_remote_agent`, `sign_vote`); raise `InvalidVoteSignatureError` on mismatch. |
| `evolution_log.py` | Writes must remain strictly monotonic with non-negative acceleration; raise `NonIncreasingValueError` / `DecelerationBlockedError`, never silently drop records. |
| `latent_dna.py` | 53 pre-existing RUF002/RUF003 ruff errors (Greek characters). Do not mass-rewrite — suppress targeted rules if lint-clean is required. |
| `mac_acgs_loop.py` | Import boundary is lazy (bittensor loaded only at construction). Guarded by `tests/test_core_import_isolation.py` — keep it that way. See MANUAL section. |
| `__init__.py` | Eager product surface only. Legacy/research names go through `__getattr__` (`_LAZY_ATTRS` / `_LAZY_MODULES`), not top-level imports. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `bittensor/` | Bittensor subnet integration — validator, miner, CAME coordinator, precedent store, tier manager, Arweave audit log (see `bittensor/AGENTS.md`) |
| `swe_bench/` | SWE-Bench evaluation scaffold — `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator` (see `swe_bench/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- New *stable product* symbols go in `__init__.py` eager imports and `__all__`. Research/sidecar names go in `_LAZY_ATTRS` or `_LAZY_MODULES` so they stay off the default import graph.
- Vote submission paths require signatures: when modifying `mesh/`, preserve the `register_local_signer` / `register_remote_agent` / `sign_vote` contract and raise `InvalidVoteSignatureError` on mismatch.
- `EvolutionLog` writes must remain strictly monotonic with non-negative acceleration; new write paths should raise `NonIncreasingValueError` / `DecelerationBlockedError` rather than silently dropping records.
- `manifold.py` is the **research control**, not a bug. Changes that "fix" its collapse must be sent through `spectral_sphere.py` instead.
- `latent_dna.py` carries 53 pre-existing ruff errors (Greek characters trigger RUF002/RUF003); do not mass-rewrite them — suppress targeted rules if lint-clean is required.
- Keep imports of `bittensor`, heavy ML libs, and network stacks gated behind their optional extras; the top-level package must remain importable without them.

### Testing Requirements
- Each module has a matching `tests/test_<module>.py`. Keep parity when adding new modules.
- Research extras: `pip install -e ".[research]"` before running latent DNA, swarm ODE, or spectral sphere tests that need torch.
- Transport tests: `pip install -e ".[transport]"` for `test_gossip_protocol.py` / `test_remote_vote_transport.py`.
- Bittensor tests skip cleanly if the extra is absent.

### Common Patterns
- Errors are domain-specific exception classes (see `__init__.py`'s `__all__`). Prefer raising one of these over `ValueError`.
- `@dataclass(frozen=True)` for records crossing module boundaries (`SettlementRecord`, `MeshProof`, `TransitionCertificate`, etc.).
- SQLite-backed stores (`EvolutionLog`, `SQLiteSettlementStore`) use WAL-safe append-only writes.
- CRDT and Merkle modules use SHA-256 CIDs for content addressing.

<!-- MANUAL: -->

### Resolved: mac_acgs_loop.py bittensor import leak

**Status: fixed (2026-06-05).** `mac_acgs_loop.py` no longer imports
`bittensor.came_coordinator` at module scope. The bittensor symbols load lazily
— only when a MAC-ACGS object is actually constructed — so
`import constitutional_swarm` stays light (cold import ~267ms, down from ~458ms
of bittensor cost) and no longer pulls in the bittensor subpackage.

The naive "move the import into one method" sketch was insufficient: the module
had **three** runtime touch points, including a dataclass
`field(default_factory=CAMECoordinatorConfig)` that is evaluated at *module load*
time. The implemented fix:

- A `TYPE_CHECKING` block imports the three symbols for annotations (the module
  already uses `from __future__ import annotations`, so annotations are lazy
  strings).
- A module-level `_default_came_config()` helper does a function-local import and
  is used as the field's `default_factory` (defers the import to first
  `MacAcgsConfig()` instantiation).
- Function-local imports at the two construction sites (`MacAcgsLoop.__init__`
  and the cycle method's fail-closed `CAMECycleResult` branch).

**Do not reintroduce a module-level bittensor import here.**
`tests/test_core_import_isolation.py` is a subprocess regression guard that fails
if any `constitutional_swarm.bittensor*` module is loaded by the core import.
Historical context: `docs/RUNTIME_OPTIMIZATION_REPORT.md` (bottleneck B1).
