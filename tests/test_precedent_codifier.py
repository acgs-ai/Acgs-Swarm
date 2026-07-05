"""Unit tests for the packaged :class:`PrecedentBackedCodifier`.

Focused on the adapter class directly. The full example loop (precedent ->
rules -> debate -> committed constitutional update) is already guarded by
``tests/test_mac_acgs_autonomous_example.py``; here we pin the class contract:

* it ignores the live-grid argument and clusters its own precedent stream
  (the whole point of PR #118 — the coordinator stays precedent-agnostic),
* observe()/observe_many()/seed accumulate that stream,
* an empty stream proposes nothing (regression pin for #118 semantics),
* one coordinator-level positive check that a real ceiling yields rule strings.
"""

from __future__ import annotations

from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
from constitutional_swarm.bittensor.map_elites import (
    DeliberationStrategy,
    GovernanceDomain,
    MinerApproach,
)
from constitutional_swarm.bittensor.precedent_backed_codifier import PrecedentBackedCodifier
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord
from constitutional_swarm.bittensor.protocol import EscalationType
from constitutional_swarm.constants import CONSTITUTIONAL_HASH


def _precedent(idx: int) -> PrecedentRecord:
    """A high-consensus escalated case concentrated in privacy + security.

    Identical impact vectors so the records agglomerate into a single cluster;
    votes_for=9 / votes_against=1 gives validator_grade == 0.9.
    """
    return PrecedentRecord.create(
        case_id=f"case-{idx}",
        task_id=f"task-{idx}",
        miner_uid=f"miner-{idx}",
        judgment="deny: personal data access without consent verification",
        reasoning="Access to PII lacked explicit consent verification.",
        votes_for=9,
        votes_against=1,
        proof_root_hash=f"{idx:064x}",
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        impact_vector={
            "safety": 0.1,
            "security": 0.85,
            "privacy": 0.9,
            "fairness": 0.1,
            "reliability": 0.1,
            "transparency": 0.1,
            "efficiency": 0.1,
        },
        constitutional_hash=CONSTITUTIONAL_HASH,
        ambiguous_dimensions=("privacy", "security"),
    )


def _grid_batch(fitness: float) -> list[MinerApproach]:
    """Six distinct grid cells at a uniform fitness (sample_count clears min_samples).

    Filling the cells at high fitness and resubmitting at lower fitness yields
    only non-replacements, which saturates the grid's global ceiling window (5).
    """
    cells = [
        (GovernanceDomain.PRIVACY, DeliberationStrategy.PRECEDENT_BASED),
        (GovernanceDomain.SECURITY, DeliberationStrategy.HYBRID),
        (GovernanceDomain.SAFETY, DeliberationStrategy.CONSTITUTIONAL_REASONING),
        (GovernanceDomain.FAIRNESS, DeliberationStrategy.STAKEHOLDER_ANALYSIS),
        (GovernanceDomain.RELIABILITY, DeliberationStrategy.HYBRID),
        (GovernanceDomain.TRANSPARENCY, DeliberationStrategy.PRECEDENT_BASED),
    ]
    return [
        MinerApproach(
            miner_uid=f"miner-{i}",
            domain=domain,
            strategy=strategy,
            fitness=fitness,
            acceptance_rate=fitness,
            reasoning_quality=fitness,
            speed_ms=300.0,
            sample_count=6,
        )
        for i, (domain, strategy) in enumerate(cells)
    ]


class TestPrecedentBackedCodifier:
    """Contract for the CAME loop-closing adapter."""

    def test_ignores_live_approaches_arg(self) -> None:
        """find_clusters discards its argument and clusters the observed stream (PR #118)."""
        codifier = PrecedentBackedCodifier()
        codifier.observe_many(_precedent(i) for i in range(6))

        clusters = codifier.find_clusters(["garbage", "more garbage"])
        assert clusters, "the observed precedents must be clustered regardless of the arg"
        assert sum(len(c.precedent_ids) for c in clusters) == 6

    def test_observe_and_observe_many_accumulate(self) -> None:
        """observe(), observe_many(), and the seed param all grow the stream."""
        codifier = PrecedentBackedCodifier()
        codifier.observe(_precedent(0))
        assert len(codifier.precedents) == 1

        codifier.observe_many(_precedent(i) for i in range(1, 5))
        assert len(codifier.precedents) == 5
        assert sum(len(c.precedent_ids) for c in codifier.find_clusters([])) == 5

        seeded = PrecedentBackedCodifier(precedents=[_precedent(i) for i in range(3)])
        assert len(seeded.precedents) == 3

    def test_empty_stream_proposes_nothing(self) -> None:
        """No precedents => no clusters => propose_rules yields [] (regression pin for #118)."""
        codifier = PrecedentBackedCodifier(min_cluster_size=5, min_validator_agreement=0.70)
        clusters = codifier.find_clusters([])
        assert clusters == []
        assert codifier.propose_rules(clusters) == []

    def test_end_to_end_non_empty_rules_via_coordinator(self) -> None:
        """A real ceiling + a validated precedent stream yields non-empty rule strings.

        Asserts positively on rules_proposed content — never "no exception
        raised" — because CAMECoordinator swallows codification failures, so a
        no-exception assertion would hide a dead loop. (The downstream committed
        constitutional update is guarded separately in the example test; this is
        the direct CAMECycleResult.rules_proposed companion.)
        """
        codifier = PrecedentBackedCodifier(min_cluster_size=5, min_validator_agreement=0.70)
        codifier.observe_many(_precedent(i) for i in range(15))

        coord = CAMECoordinator(codifier=codifier)
        try:
            first = coord.evolve_cycle(_grid_batch(0.9))
            assert first.ceiling_detected is False
            assert first.rules_proposed == []

            ceiling_cycle = coord.evolve_cycle(_grid_batch(0.5))
            assert ceiling_cycle.ceiling_detected is True
            assert len(ceiling_cycle.rules_proposed) >= 1
            assert all(isinstance(rule, str) and rule for rule in ceiling_cycle.rules_proposed)
        finally:
            coord.close()
