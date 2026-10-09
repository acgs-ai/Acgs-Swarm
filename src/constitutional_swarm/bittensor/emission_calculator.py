"""Emission Calculator — TAO emission weight formula.

Implements the full emission formula from the roadmap economic model,
combining all five signal sources into a single normalized weight per miner:

  emission_weight(miner_i) = f(
      manifold_trust[i],          Validated nonnegative trust signal
      reputation[i],              ConstitutionalMesh reputation score
      tier_multiplier[i],         MinerTier TAO bonus (1.0x - 4.0x)
      precedent_contribution[i],  PrecedentStore contribution count
      authenticity_score[i],      Average AuthenticityDetector score
  )

Formula (configurable weights, defaults sum to 1.0):
  raw_score = (
      w_trust         x normalize(manifold_trust)
    + w_reputation    x normalize(reputation)
    + w_tier          x normalize(tier_multiplier)
    + w_precedent     x normalize(precedent_contributions)
    + w_authenticity  x authenticity_score
  )
  emission_weight = normalize(raw_score) over all miners

Safeguards:
  • Bounded influence: no miner exceeds the feasible effective cap
  • Conservation: weights sum to exactly 1.0
  • Minimum floor: every eligible miner gets min_weight_fraction / eligible count
  • Tier hard gate: miners below minimum_tier get zero weight

Roadmap: 08-subnet-implementation-roadmap.md § Economic Model Integration
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from constitutional_swarm.bittensor._validation import _validate_count, _validate_finite
from constitutional_swarm.bittensor.protocol import TIER_TAO_MULTIPLIER, MinerTier

# ---------------------------------------------------------------------------
# Formula weights (configurable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EmissionWeights:
    """Relative importance of each signal in the emission formula."""

    manifold_trust: float = 0.30
    reputation: float = 0.25
    tier: float = 0.20
    precedent: float = 0.15
    authenticity: float = 0.10

    def __post_init__(self) -> None:
        for name in ("manifold_trust", "reputation", "tier", "precedent", "authenticity"):
            _validate_finite(name, getattr(self, name), minimum=0.0, maximum=1.0)
        total = (
            self.manifold_trust + self.reputation + self.tier + self.precedent + self.authenticity
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"EmissionWeights must sum to 1.0, got {total:.6f}")


DEFAULT_EMISSION_WEIGHTS = EmissionWeights()


# ---------------------------------------------------------------------------
# Per-miner input snapshot
# ---------------------------------------------------------------------------


@dataclass
class MinerEmissionInput:
    """All signal inputs for one miner in one emission cycle."""

    miner_uid: str
    tier: MinerTier = MinerTier.APPRENTICE
    manifold_trust: float = 0.0  # validated nonnegative trust signal
    reputation: float = 1.0  # from ConstitutionalMesh
    precedent_contributions: int = 0  # from PrecedentStore
    avg_authenticity: float = 0.0  # from AuthenticityDetector rolling avg
    is_active: bool = True  # inactive miners get zero weight

    def __post_init__(self) -> None:
        _validate_miner_input(self)


# ---------------------------------------------------------------------------
# Emission result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MinerEmission:
    """Computed emission for one miner."""

    miner_uid: str
    raw_score: float  # before normalization + clamping
    emission_weight: float  # final normalized weight (0.0 - 1.0)
    tier_multiplier: float
    was_floor_applied: bool
    was_cap_applied: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "miner_uid": self.miner_uid,
            "raw_score": round(self.raw_score, 6),
            "emission_weight": round(self.emission_weight, 6),
            "tier_multiplier": self.tier_multiplier,
            "was_floor_applied": self.was_floor_applied,
            "was_cap_applied": self.was_cap_applied,
        }


@dataclass
class EmissionCycle:
    """Full emission cycle result for all miners."""

    emissions: list[MinerEmission]
    total_miners: int
    active_miners: int
    weights: EmissionWeights
    configured_cap: float = 0.40
    effective_cap: float = 0.40
    cap_relaxed: bool = False

    @property
    def weight_sum(self) -> float:
        return sum(e.emission_weight for e in self.emissions)

    @property
    def max_weight(self) -> float:
        if not self.emissions:
            return 0.0
        return max(e.emission_weight for e in self.emissions)

    def top_k(self, k: int) -> list[MinerEmission]:
        _validate_count("k", k, minimum=0)
        return sorted(self.emissions, key=lambda e: e.emission_weight, reverse=True)[:k]

    def as_weight_dict(self) -> dict[str, float]:
        return {e.miner_uid: e.emission_weight for e in self.emissions}

    def summary(self) -> dict[str, Any]:
        return {
            "total_miners": self.total_miners,
            "active_miners": self.active_miners,
            "weight_sum": round(self.weight_sum, 9),
            "max_weight": round(self.max_weight, 6),
            "configured_cap": self.configured_cap,
            "effective_cap": self.effective_cap,
            "cap_relaxed": self.cap_relaxed,
            "top_3": [
                {"miner": e.miner_uid, "weight": round(e.emission_weight, 6)} for e in self.top_k(3)
            ],
        }


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class EmissionCalculator:
    """Computes TAO emission weights for all subnet miners.

    Usage::

        calc = EmissionCalculator(
            weights=DEFAULT_EMISSION_WEIGHTS,
            min_weight_fraction=0.01,    # floor: 1% total reserve across eligible miners
            max_weight_fraction=0.40,    # cap:  40% per miner
            minimum_tier=MinerTier.APPRENTICE,
        )

        inputs = [
            MinerEmissionInput("miner-01", tier=MinerTier.MASTER,
                               manifold_trust=0.8, reputation=1.5,
                               precedent_contributions=12, avg_authenticity=0.73),
            MinerEmissionInput("miner-02", tier=MinerTier.JOURNEYMAN,
                               manifold_trust=0.5, reputation=1.2,
                               precedent_contributions=3, avg_authenticity=0.61),
        ]
        cycle = calc.compute(inputs)
        print(cycle.as_weight_dict())
        # {"miner-01": 0.5, "miner-02": 0.5} (40% cap relaxes to feasible 50%)
    """

    def __init__(
        self,
        weights: EmissionWeights = DEFAULT_EMISSION_WEIGHTS,
        min_weight_fraction: float = 0.01,
        max_weight_fraction: float = 0.40,
        minimum_tier: MinerTier = MinerTier.APPRENTICE,
        registered_miners: set[str] | None = None,
    ) -> None:
        _validate_finite(
            "min_weight_fraction", min_weight_fraction, minimum=0.0, maximum=1.0
        )
        _validate_finite(
            "max_weight_fraction", max_weight_fraction, minimum=0.0, maximum=1.0
        )
        if max_weight_fraction == 0.0:
            raise ValueError("max_weight_fraction must be greater than 0")
        if not isinstance(minimum_tier, MinerTier):
            raise ValueError("minimum_tier must be a MinerTier")
        self._weights = weights
        self._min_frac = float(min_weight_fraction)
        self._max_frac = float(max_weight_fraction)
        self._min_tier = minimum_tier
        self._min_tier_order = _TIER_ORDER[minimum_tier]
        self._registered: set[str] | None = (
            None if registered_miners is None else set(registered_miners)
        )

    def compute(self, inputs: list[MinerEmissionInput]) -> EmissionCycle:
        """Compute emission weights for all miners.

        Steps:
          0. Filter unregistered miners → zero weight (Sybil resistance)
          1. Filter inactive + below-minimum-tier miners → zero weight
          2. Normalize each signal dimension to [0, 1]
          3. Apply formula weights → raw_score per miner
          4. Apply tier multiplier
          5. Normalize raw_scores → weights summing to 1.0
          6. Apply floor (min_weight_fraction / active count) and effective cap
          7. Redistribute the remaining mass without violating either bound

        Returns EmissionCycle with all MinerEmission records.
        """
        seen: set[str] = set()
        for inp in inputs:
            _validate_miner_input(inp)
            if inp.miner_uid in seen:
                raise ValueError(f"duplicate miner_uid {inp.miner_uid!r}")
            seen.add(inp.miner_uid)

        active = [
            inp
            for inp in inputs
            if inp.is_active
            and _TIER_ORDER[inp.tier] >= self._min_tier_order
            and (self._registered is None or inp.miner_uid in self._registered)
        ]

        if not active:
            return EmissionCycle(
                emissions=[
                    MinerEmission(
                        miner_uid=inp.miner_uid,
                        raw_score=0.0,
                        emission_weight=0.0,
                        tier_multiplier=TIER_TAO_MULTIPLIER[inp.tier],
                        was_floor_applied=False,
                        was_cap_applied=False,
                    )
                    for inp in inputs
                ],
                total_miners=len(inputs),
                active_miners=0,
                weights=self._weights,
                configured_cap=self._max_frac,
                effective_cap=self._max_frac,
                cap_relaxed=False,
            )

        # --- Step 2: normalize each signal across active miners ---
        trust_vals = [inp.manifold_trust for inp in active]
        rep_vals = [inp.reputation for inp in active]
        prec_vals = [float(inp.precedent_contributions) for inp in active]
        auth_vals = [inp.avg_authenticity for inp in active]
        tier_vals = [TIER_TAO_MULTIPLIER[inp.tier] for inp in active]

        n_trust = _normalize_vec(trust_vals)
        n_rep = _normalize_vec(rep_vals)
        n_prec = _normalize_vec(prec_vals)
        n_auth = _normalize_vec(auth_vals)
        n_tier = _normalize_vec(tier_vals)

        # --- Step 3+4: raw score ---
        w = self._weights
        raw: list[float] = []
        for i, inp in enumerate(active):
            score = (
                w.manifold_trust * n_trust[i]
                + w.reputation * n_rep[i]
                + w.tier * n_tier[i]
                + w.precedent * n_prec[i]
                + w.authenticity * n_auth[i]
            )
            # Tier multiplier boosts relative score
            score *= TIER_TAO_MULTIPLIER[inp.tier]
            raw.append(score)

        # --- Step 5: normalize to sum 1.0 ---
        raw_weights = _safe_normalize(raw)

        # --- Step 6: floor and cap (iterative until stable) ---
        n = len(active)
        floor = self._min_frac / n if n > 0 else 0.0
        cap = max(self._max_frac, 1.0 / n)
        final = _apply_floor_cap(raw_weights, floor, cap)

        # --- Build results ---
        emissions_active = []
        for i, inp in enumerate(active):
            emissions_active.append(
                MinerEmission(
                    miner_uid=inp.miner_uid,
                    raw_score=raw[i],
                    emission_weight=final[i],
                    tier_multiplier=TIER_TAO_MULTIPLIER[inp.tier],
                    was_floor_applied=(final[i] > raw_weights[i] and raw_weights[i] < floor + 1e-9),
                    was_cap_applied=(final[i] < raw_weights[i] - 1e-9),
                )
            )

        # Zero weight for inactive / below-tier miners
        active_uids = {inp.miner_uid for inp in active}
        inactive_emissions = [
            MinerEmission(
                miner_uid=inp.miner_uid,
                raw_score=0.0,
                emission_weight=0.0,
                tier_multiplier=TIER_TAO_MULTIPLIER[inp.tier],
                was_floor_applied=False,
                was_cap_applied=False,
            )
            for inp in inputs
            if inp.miner_uid not in active_uids
        ]

        return EmissionCycle(
            emissions=emissions_active + inactive_emissions,
            total_miners=len(inputs),
            active_miners=len(active),
            weights=self._weights,
            configured_cap=self._max_frac,
            effective_cap=cap,
            cap_relaxed=cap > self._max_frac,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_TIER_ORDER: dict[MinerTier, int] = {
    MinerTier.APPRENTICE: 0,
    MinerTier.JOURNEYMAN: 1,
    MinerTier.MASTER: 2,
    MinerTier.ELDER: 3,
}


def _validate_miner_input(inp: MinerEmissionInput) -> None:
    if not isinstance(inp.miner_uid, str) or not inp.miner_uid:
        raise ValueError("miner_uid must be a non-empty string")
    if not isinstance(inp.tier, MinerTier):
        raise ValueError("tier must be a MinerTier")
    if not isinstance(inp.is_active, bool):
        raise ValueError("is_active must be a bool")
    _validate_finite("manifold_trust", inp.manifold_trust, minimum=0.0)
    _validate_finite("reputation", inp.reputation, minimum=0.0, maximum=2.0)
    _validate_count("precedent_contributions", inp.precedent_contributions, minimum=0)
    _validate_finite("avg_authenticity", inp.avg_authenticity, minimum=0.0, maximum=1.0)


def _apply_floor_cap(
    weights: list[float],
    floor: float,
    cap: float,
) -> list[float]:
    """Allocate one unit of mass on a feasible floor/cap bounded simplex."""
    if not weights:
        return []
    n = len(weights)
    _validate_finite("floor", floor, minimum=0.0, maximum=1.0)
    _validate_finite("cap", cap, minimum=0.0, maximum=1.0)
    if floor * n > 1.0 + 1e-12 or cap * n < 1.0 - 1e-12 or floor > cap:
        raise ValueError("floor and cap do not define a feasible bounded simplex")

    preferences = _safe_normalize(weights)
    if all(floor <= weight <= cap for weight in preferences):
        return preferences

    allocation = [floor] * n
    capacity = [cap - floor] * n
    remaining = 1.0 - math.fsum(allocation)
    available = {i for i, headroom in enumerate(capacity) if headroom > 1e-15}

    while remaining > 1e-15:
        if not available:
            raise RuntimeError("bounded simplex allocation exhausted capacity")
        preference_total = math.fsum(preferences[i] for i in available)
        shares = (
            {i: remaining / len(available) for i in available}
            if preference_total == 0.0
            else {
                i: remaining * preferences[i] / preference_total for i in available
            }
        )
        saturated = {i for i, share in shares.items() if share > capacity[i] + 1e-15}
        if not saturated:
            for i, share in shares.items():
                allocation[i] += share
            remaining = 0.0
            break
        for i in saturated:
            allocation[i] += capacity[i]
            remaining -= capacity[i]
            capacity[i] = 0.0
        available.difference_update(saturated)

    residual = 1.0 - math.fsum(allocation)
    if residual > 0.0:
        for i in range(n):
            adjustment = min(residual, cap - allocation[i])
            allocation[i] += adjustment
            residual -= adjustment
            if residual <= 1e-15:
                break
    elif residual < 0.0:
        for i in range(n):
            adjustment = min(-residual, allocation[i] - floor)
            allocation[i] -= adjustment
            residual += adjustment
            if residual >= -1e-15:
                break
    total = math.fsum(allocation)
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise RuntimeError(f"bounded simplex allocation failed conservation: {total}")
    if any(weight < floor - 1e-12 or weight > cap + 1e-12 for weight in allocation):
        raise RuntimeError("bounded simplex allocation violated floor or cap")
    return allocation


def _normalize_vec(values: list[float]) -> list[float]:
    """Min-max normalize a list to [0, 1]. All-equal → uniform 0.5."""
    if not values:
        return []
    validated = [_validate_finite("value", value, minimum=0.0) for value in values]
    lo, hi = min(validated), max(validated)
    if hi == lo:
        return [0.5] * len(validated)
    return [(value - lo) / (hi - lo) for value in validated]


def _safe_normalize(weights: list[float]) -> list[float]:
    """Normalize weights to sum 1.0. All-zero → uniform."""
    if not weights:
        return []
    validated = [_validate_finite("weight", weight, minimum=0.0) for weight in weights]
    scale = max(validated)
    if scale == 0.0:
        n = len(weights)
        return [1.0 / n] * n
    scaled = [weight / scale for weight in validated]
    total = math.fsum(scaled)
    return [weight / total for weight in scaled]
