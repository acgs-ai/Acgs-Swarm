"""MAC-ACGS autonomous research loop — runnable end-to-end example.

Demonstrates the full auto-constitution pipeline with real components only:

    miner observations -> CAME evolution (MAP-Elites grid, ceiling detection)
    -> precedent clustering (RuleCodifier) -> rule proposal
    -> adversarial debate (DebateResolver) -> constitutional update
    -> hash verification (fail-closed) -> audit log

Why the adapter below exists: ``CAMECoordinator``'s default wiring hands the
codifier live grid approaches, but ``RuleCodifier.find_clusters()`` clusters
``PrecedentRecord`` objects (and ``MinerQualityGrid`` exposes no approach
iterator), so the default composition can never propose a rule. Feeding the
codifier from an explicit precedent stream — escalated, validator-approved
cases — closes the loop. Run:

    python examples/mac_acgs_autonomous_research.py
"""

from __future__ import annotations

import itertools
import json
import random

from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
from constitutional_swarm.bittensor.map_elites import (
    DeliberationStrategy,
    GovernanceDomain,
    MinerApproach,
)
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord
from constitutional_swarm.bittensor.protocol import EscalationType
from constitutional_swarm.bittensor.rule_codifier import RuleCodifier
from constitutional_swarm.mac_acgs_loop import MacAcgsLoop

CONSTITUTIONAL_HASH = "608508a9bd224290"


class PrecedentBackedCodifier:
    """Real RuleCodifier fed by an accumulated precedent stream."""

    def __init__(self) -> None:
        self.inner = RuleCodifier(
            constitutional_hash=CONSTITUTIONAL_HASH,
            min_cluster_size=5,
            min_validator_agreement=0.85,
        )
        self.precedents: list[PrecedentRecord] = []

    def observe(self, precedent: PrecedentRecord) -> None:
        self.precedents.append(precedent)

    def find_clusters(self, _live_approaches: list) -> list:
        return self.inner.find_clusters(self.precedents)

    def propose_rules(self, clusters: list) -> list[str]:
        return [c.rule_text for c in self.inner.propose_rules(clusters)]


def synth_approaches(rng: random.Random, cycle: int, n: int = 24) -> list[MinerApproach]:
    """Quality improves for 3 cycles, then stagnates -> ceiling -> codification."""
    cells = itertools.cycle(itertools.product(GovernanceDomain, DeliberationStrategy))
    base = 0.4 + 0.15 * cycle if cycle <= 3 else 0.05
    return [
        MinerApproach(
            miner_uid=f"miner-{i % 12}",
            domain=domain,
            strategy=strategy,
            fitness=min(1.0, base + rng.uniform(0, 0.1)),
            acceptance_rate=min(1.0, base + rng.uniform(0, 0.1)),
            reasoning_quality=min(1.0, base + rng.uniform(0, 0.1)),
            speed_ms=rng.uniform(200, 900),
            sample_count=6,
        )
        for i, (domain, strategy) in zip(range(n), cells, strict=False)
    ]


def synth_precedent(rng: random.Random, idx: int) -> PrecedentRecord:
    """An escalated safety/security case with high validator consensus."""
    return PrecedentRecord.create(
        case_id=f"case-{idx}",
        task_id=f"task-{idx}",
        miner_uid=f"miner-{idx % 12}",
        judgment="deny: irreversible side effect without receipt",
        reasoning="Side-effectful action lacked a valid decision receipt.",
        votes_for=9,
        votes_against=1,
        proof_root_hash=f"{idx:064x}",
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        impact_vector={
            "safety": 0.9 + rng.uniform(-0.05, 0.05),
            "security": 0.8 + rng.uniform(-0.05, 0.05),
            "privacy": 0.1,
            "fairness": 0.1,
            "reliability": 0.2,
            "transparency": 0.1,
            "efficiency": 0.1,
        },
        constitutional_hash=CONSTITUTIONAL_HASH,
        ambiguous_dimensions=("safety", "security"),
    )


def main() -> int:
    rng = random.Random(42)
    codifier = PrecedentBackedCodifier()
    loop = MacAcgsLoop(came=CAMECoordinator(codifier=codifier))
    loop.add_external_challenger("human-reviewer-1")

    for cycle in range(1, 9):
        codifier.observe(synth_precedent(rng, 2 * cycle))
        codifier.observe(synth_precedent(rng, 2 * cycle + 1))
        result = loop.run_cycle(synth_approaches(rng, cycle))
        print(
            json.dumps(
                {
                    "cycle": result.cycle_number,
                    "coverage": round(result.came_result.grid_coverage, 3),
                    "ceiling": result.came_result.ceiling_detected,
                    "proposed": len(result.came_result.rules_proposed),
                    "approved": result.proposals_approved,
                    "hash_verified": result.hash_verified,
                }
            )
        )

    updates = loop.constitution_updates()
    print(f"constitutional updates committed: {len(updates)}")
    for upd in updates:
        print(json.dumps(upd if isinstance(upd, dict) else upd.__dict__, default=str))
    return 0 if updates else 1


if __name__ == "__main__":
    raise SystemExit(main())
