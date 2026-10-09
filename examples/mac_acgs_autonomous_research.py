"""MAC-ACGS autonomous research loop with externally supplied evidence.

Demonstrates the full auto-constitution pipeline with real components only:

    miner observations -> CAME evolution (MAP-Elites grid, ceiling detection)
    -> precedent clustering (RuleCodifier) -> rule proposal
    -> adversarial debate (DebateResolver) -> constitutional update
    -> hash verification (fail-closed) -> audit log

Why the precedent-backed codifier exists: post-#118 ``CAMECoordinator`` is
deliberately precedent-agnostic — at ceiling it passes the codifier an empty
``live_approaches`` list (feeding raw grid approaches into rule proposal would
bypass precedent admission), so a plain ``RuleCodifier`` receives nothing and
can never propose a rule. ``PrecedentBackedCodifier`` closes the loop by
observing an explicit store-backed stream of escalated cases. Precedents and
their public-key-only trust registry must be supplied by an external voter
collection path. Embed this module and call ``run_with_precedents``. Direct
execution fails closed because it has no authenticated external evidence input.
"""

from __future__ import annotations

import itertools
import json
import random
import sys
from collections.abc import Sequence

from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
from constitutional_swarm.bittensor.map_elites import (
    DeliberationStrategy,
    GovernanceDomain,
    MinerApproach,
)
from constitutional_swarm.bittensor.precedent_backed_codifier import PrecedentBackedCodifier
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore
from constitutional_swarm.mac_acgs_loop import MacAcgsLoop
from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

CONSTITUTIONAL_HASH = "608508a9bd224290"


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


def run_with_precedents(
    precedents: Sequence[PrecedentRecord],
    vote_registry: VoteSignerRegistry,
) -> tuple[MacAcgsLoop, PrecedentStore, PrecedentBackedCodifier]:
    """Run using evidence collected and signed by external voters."""
    if len(precedents) < 16:
        raise ValueError("at least 16 externally signed precedents are required")
    rng = random.Random(42)
    store = PrecedentStore(
        CONSTITUTIONAL_HASH,
        vote_registry=vote_registry.frozen_copy(),
    )
    codifier = PrecedentBackedCodifier(precedent_store=store)
    loop = MacAcgsLoop(came=CAMECoordinator(codifier=codifier))
    loop.add_external_challenger("human-reviewer-1")

    for cycle in range(1, 9):
        codifier.observe(store.admit(precedents[2 * cycle - 2]))
        codifier.observe(store.admit(precedents[2 * cycle - 1]))
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
    return loop, store, codifier


def main() -> int:
    """Fail closed until the embedding application supplies external evidence."""
    print(
        "external signed precedents and a public-key trust registry are required; "
        "call run_with_precedents()",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
