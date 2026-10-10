"""MAP-Elites Miner Quality Optimization.

Maintains a quality-diversity grid over (governance_domain x deliberation_strategy).
Each cell tracks the best-performing miner approach for that combination.
Forces exploration of the full behavioral space — prevents convergence to a
single "good enough" strategy.

7 domains x 4 strategies = 28 cells.

Evolutionary pattern: MAP-Elites (Mouret & Clune, 2015).
Ceiling detection per cell and globally.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from constitutional_swarm.bittensor._validation import _validate_count, _validate_finite


MAX_SAMPLE_COUNT = 2**31 - 1


class GovernanceDomain(Enum):
    """The 7 constitutional governance dimensions."""

    SAFETY = "safety"
    SECURITY = "security"
    PRIVACY = "privacy"
    FAIRNESS = "fairness"
    RELIABILITY = "reliability"
    TRANSPARENCY = "transparency"
    EFFICIENCY = "efficiency"


class DeliberationStrategy(Enum):
    """Deliberation approach families."""

    PRECEDENT_BASED = "precedent_based"
    STAKEHOLDER_ANALYSIS = "stakeholder_analysis"
    CONSTITUTIONAL_REASONING = "constitutional_reasoning"
    HYBRID = "hybrid"


@dataclass(frozen=True, slots=True)
class CellCoordinate:
    """Position in the MAP-Elites grid."""

    domain: GovernanceDomain
    strategy: DeliberationStrategy


@dataclass(frozen=True, slots=True)
class MinerApproach:
    """A snapshot of a miner's behavioral phenotype at evaluation time."""

    miner_uid: str
    domain: GovernanceDomain
    strategy: DeliberationStrategy
    fitness: float
    acceptance_rate: float
    reasoning_quality: float
    speed_ms: float
    sample_count: int
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not isinstance(self.miner_uid, str) or not self.miner_uid:
            raise ValueError("miner_uid must be a nonempty string")
        if not isinstance(self.domain, GovernanceDomain):
            raise TypeError("domain must be a GovernanceDomain")
        if not isinstance(self.strategy, DeliberationStrategy):
            raise TypeError("strategy must be a DeliberationStrategy")
        _validate_finite("fitness", self.fitness, maximum=1.0)
        _validate_finite("acceptance_rate", self.acceptance_rate, maximum=1.0)
        _validate_finite("reasoning_quality", self.reasoning_quality, maximum=1.0)
        _validate_finite("speed_ms", self.speed_ms)
        _validate_count("sample_count", self.sample_count)
        _validate_finite("timestamp", self.timestamp)


@dataclass(frozen=True, slots=True)
class FitnessWeights:
    """Tunable weights for the composite fitness function."""

    acceptance_weight: float = 0.5
    reasoning_weight: float = 0.3
    speed_weight: float = 0.2
    speed_baseline_ms: float = 1000.0
    min_samples: int = 5

    def __post_init__(self) -> None:
        coefficients = (
            _validate_finite("acceptance_weight", self.acceptance_weight, maximum=1.0),
            _validate_finite("reasoning_weight", self.reasoning_weight, maximum=1.0),
            _validate_finite("speed_weight", self.speed_weight, maximum=1.0),
        )
        if abs(math.fsum(coefficients) - 1.0) > 1e-9:
            raise ValueError("fitness coefficients must sum to 1.0")
        baseline = _validate_finite("speed_baseline_ms", self.speed_baseline_ms)
        if baseline <= 0.0:
            raise ValueError("speed_baseline_ms must be greater than zero")
        _validate_count(
            "min_samples",
            self.min_samples,
            minimum=1,
            maximum=MAX_SAMPLE_COUNT,
        )


class MinerQualityGrid:
    """MAP-Elites grid: best miner approach per (domain, strategy) cell.

    Properties:
    - Forces diversity: one miner can't dominate all cells
    - Identifies unexplored regions for targeted incentives
    - Ceiling detection signals convergence
    """

    TOTAL_CELLS = len(GovernanceDomain) * len(DeliberationStrategy)  # 28

    def __init__(
        self,
        *,
        fitness_weights: FitnessWeights | None = None,
        ceiling_window: int = 5,
    ) -> None:
        self._weights = fitness_weights or FitnessWeights()
        self._grid: dict[CellCoordinate, MinerApproach] = {}
        self._ceiling_window = _validate_count(
            "ceiling_window", ceiling_window, minimum=1
        )
        # Ceiling detection only ever reads the last ``ceiling_window`` outcomes,
        # so keep bounded windows (global and per cell) plus a running total.
        self._challenge_log: deque[bool] = deque(maxlen=self._ceiling_window)
        self._cell_challenges: dict[CellCoordinate, deque[bool]] = {}
        self._total_challenges = 0

    def compute_fitness(
        self,
        acceptance_rate: float,
        reasoning_quality: float,
        speed_ms: float,
    ) -> float:
        """Weighted composite fitness in [0, 1].

        Speed is inverted and normalized against baseline.
        """
        acceptance_rate = _validate_finite(
            "acceptance_rate", acceptance_rate, maximum=1.0
        )
        reasoning_quality = _validate_finite(
            "reasoning_quality", reasoning_quality, maximum=1.0
        )
        speed_ms = _validate_finite("speed_ms", speed_ms)
        w = self._weights
        speed_score = max(0.0, 1.0 - speed_ms / w.speed_baseline_ms)
        coefficient_total = math.fsum(
            (w.acceptance_weight, w.reasoning_weight, w.speed_weight)
        )
        fitness = (
            w.acceptance_weight * acceptance_rate
            + w.reasoning_weight * reasoning_quality
            + w.speed_weight * speed_score
        ) / coefficient_total
        return min(1.0, max(0.0, fitness))

    def challenge(self, approach: MinerApproach) -> bool:
        """Try to place an approach in its grid cell.

        ``approach`` must contain validator-observed measurements. Callers are
        responsible for deriving acceptance, reasoning, latency, and sample
        count from trusted validator state rather than miner claims.

        Returns True if it replaces the incumbent or fills an empty cell.
        Requires min_samples to be met.
        """
        if not isinstance(approach, MinerApproach):
            raise TypeError("approach must be a MinerApproach")
        _validate_finite("fitness", approach.fitness, maximum=1.0)
        _validate_finite("acceptance_rate", approach.acceptance_rate, maximum=1.0)
        _validate_finite("reasoning_quality", approach.reasoning_quality, maximum=1.0)
        speed_ms = _validate_finite("speed_ms", approach.speed_ms)
        sample_count = _validate_count("sample_count", approach.sample_count)
        _validate_finite("timestamp", approach.timestamp)

        bounded_speed_ms = min(speed_ms, self._weights.speed_baseline_ms)
        bounded_sample_count = min(sample_count, MAX_SAMPLE_COUNT)
        canonical_fitness = self.compute_fitness(
            approach.acceptance_rate,
            approach.reasoning_quality,
            bounded_speed_ms,
        )
        canonical = replace(
            approach,
            fitness=canonical_fitness,
            speed_ms=bounded_speed_ms,
            sample_count=bounded_sample_count,
        )
        if canonical.sample_count < self._weights.min_samples:
            return False

        coord = CellCoordinate(domain=canonical.domain, strategy=canonical.strategy)

        incumbent = self._grid.get(coord)
        replaced = False

        if incumbent is None or canonical.fitness > incumbent.fitness:
            self._grid[coord] = canonical
            replaced = True

        self._challenge_log.append(replaced)
        self._cell_challenges.setdefault(
            coord, deque(maxlen=self._ceiling_window)
        ).append(replaced)
        self._total_challenges += 1
        return replaced

    @property
    def coverage(self) -> float:
        """Fraction of 28 cells occupied."""
        return len(self._grid) / self.TOTAL_CELLS

    @property
    def occupied_count(self) -> int:
        return len(self._grid)

    def best_for(
        self,
        domain: GovernanceDomain,
        strategy: DeliberationStrategy,
    ) -> MinerApproach | None:
        """Return the incumbent for a cell, or None if empty."""
        return self._grid.get(CellCoordinate(domain=domain, strategy=strategy))

    def diversity_score(self) -> float:
        """Unique miner_uids across occupied cells / total occupied.

        Low diversity = one miner dominating many cells.
        """
        if not self._grid:
            return 0.0
        uids = {a.miner_uid for a in self._grid.values()}
        return len(uids) / len(self._grid)

    def empty_cells(self) -> list[CellCoordinate]:
        """Cells with no incumbent — targets for exploration incentives."""
        result = []
        for domain in GovernanceDomain:
            for strategy in DeliberationStrategy:
                coord = CellCoordinate(domain=domain, strategy=strategy)
                if coord not in self._grid:
                    result.append(coord)
        return result

    def domain_coverage(self, domain: GovernanceDomain) -> int:
        """How many strategy cells are filled for a domain (0-4)."""
        return sum(
            1
            for strategy in DeliberationStrategy
            if CellCoordinate(domain=domain, strategy=strategy) in self._grid
        )

    def ceiling_detected(self) -> bool:
        """True when last N challenges produced no improvements globally."""
        if len(self._challenge_log) < self._ceiling_window:
            return False
        return not any(self._challenge_log)

    def ceiling_for_cell(self, coord: CellCoordinate) -> bool:
        """True when last N challenges to this specific cell had no improvement."""
        cell_challenges = self._cell_challenges.get(coord)
        if cell_challenges is None or len(cell_challenges) < self._ceiling_window:
            return False
        return not any(cell_challenges)

    def top_miners(self, n: int = 5) -> list[MinerApproach]:
        """Top N miners by fitness across all cells."""
        _validate_count("n", n)
        return sorted(self._grid.values(), key=lambda a: a.fitness, reverse=True)[:n]

    def summary(self) -> dict[str, Any]:
        """Grid statistics for monitoring."""
        return {
            "coverage": round(self.coverage, 3),
            "occupied_cells": self.occupied_count,
            "total_cells": self.TOTAL_CELLS,
            "diversity_score": round(self.diversity_score(), 3),
            "ceiling_detected": self.ceiling_detected(),
            "total_challenges": self._total_challenges,
            "unique_miners": len({a.miner_uid for a in self._grid.values()}),
            "domain_coverage": {d.value: self.domain_coverage(d) for d in GovernanceDomain},
        }

    def exploration_bonus(self, miner_uid: str, multiplier: float = 1.1) -> float:
        """Compute exploration bonus for a miner.

        Miners that occupy cells with low challenge counts or that
        have contributed to empty-cell-adjacent domains get a bonus.
        """
        if not isinstance(miner_uid, str) or not miner_uid:
            raise ValueError("miner_uid must be a nonempty string")
        multiplier = _validate_finite("multiplier", multiplier, minimum=1.0)
        cells_held = sum(1 for a in self._grid.values() if a.miner_uid == miner_uid)
        if cells_held == 0:
            return multiplier  # New miner — maximum exploration incentive
        # Bonus decreases as miner occupies more cells (diminishing returns)
        return 1.0 + (multiplier - 1.0) / cells_held
