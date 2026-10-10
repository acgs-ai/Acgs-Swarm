"""Bayesian Threshold Updater — Phase 3.2.

Updates 7-vector governance scoring weights from evidence in the
PrecedentStore. Zero-retraining: deterministic, reversible, transparent,
bounded updates to a weight lookup table.

Formula (per dimension d, per domain):
    observation_rate = confirmed / (confirmed + overblown)
    shift = (2 x observation_rate - 1) x max_shift_per_cycle
    posterior = bounded_simplex_projection(prior + shift)

Evidence admission:
    Precedents are resolved through an injected PrecedentStore
    (``require_canonical_records``): unknown, altered, revoked or repeated
    records are rejected, so only canonical admitted grades count.

Evidence classification (from PrecedentRecord):
    dimension d is "ambiguous" if d ∈ precedent.ambiguous_dimensions
    "confirmed"  if impact_vector[d] ≥ 0.5  (the elevated score was justified)
    "overblown"  if impact_vector[d] < 0.5   (false alarm — human dismissed it)
    Weighted by validator_grade for higher-quality signal.

Example (matches Q&A doc §5 Mechanism 2):
    Prior security_weight = 0.20
    Evidence: 47 healthcare cases, 41 confirmed (87%), 6 overblown (13%)
    shift = (2 x 0.87 - 1) x 0.08 = 0.059
    Posterior = 0.259 (before any required balancing)

Design invariants:
    • Deterministic — same inputs, same output
    • Reversible — rollback returns to any prior snapshot
    • Transparent — every update logged with human-readable explanation
    • Bounded — max_shift_per_cycle caps per-cycle movement
    • Domain-scoped — domains get independent weight tables, and an update
      for a domain only accepts evidence collected for exactly that domain

Roadmap: 08-subnet-implementation-roadmap.md § Phase 3.2
Q&A:     07-subnet-concept-qa-responses.md § 5 Mechanism 2
"""

from __future__ import annotations

import math
import time
import uuid
from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from constitutional_swarm.bittensor._validation import _validate_count, _validate_finite
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore
from constitutional_swarm.bittensor.rule_codifier import _DIMENSIONS

# Default weights matching the Q&A doc and impact_scorer.py
DEFAULT_WEIGHTS: dict[str, float] = {
    "safety": 0.20,
    "security": 0.20,
    "privacy": 0.15,
    "fairness": 0.15,
    "reliability": 0.10,
    "transparency": 0.10,
    "efficiency": 0.10,
}

_MIN_WEIGHT = 0.02  # floor: no dimension can be ignored entirely
_MAX_WEIGHT = 0.40  # ceiling: no dimension monopolizes scoring


# ---------------------------------------------------------------------------
# Evidence dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DimensionEvidence:
    """Evidence for one dimension in one domain, aggregated from precedents."""

    dimension: str
    domain: str
    total_cases: int  # total precedents with this dim ambiguous
    confirmed_count: float  # weighted sum of confirmed observations
    overblown_count: float  # weighted sum of overblown observations

    def __post_init__(self) -> None:
        if self.dimension not in _DIMENSIONS:
            raise ValueError(f"unknown governance dimension: {self.dimension!r}")
        if not isinstance(self.domain, str):
            raise TypeError("domain must be a string")
        total_cases = _validate_count("total_cases", self.total_cases)
        confirmed = _validate_finite("confirmed_count", self.confirmed_count)
        overblown = _validate_finite("overblown_count", self.overblown_count)
        if confirmed + overblown > total_cases + 1e-12:
            raise ValueError("weighted evidence counts cannot exceed total_cases")

    @property
    def observation_rate(self) -> float:
        """Fraction of cases where the concern was confirmed valid.

        Returns 0.5 (neutral) when there is insufficient evidence.
        """
        total = self.confirmed_count + self.overblown_count
        if total == 0.0:
            return 0.5
        return self.confirmed_count / total

    @property
    def is_sufficient(self) -> bool:
        """True when there is enough evidence to update weights."""
        return self.total_cases >= 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "domain": self.domain,
            "total_cases": self.total_cases,
            "confirmed": round(self.confirmed_count, 4),
            "overblown": round(self.overblown_count, 4),
            "observation_rate": round(self.observation_rate, 4),
        }


# ---------------------------------------------------------------------------
# Weight update record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WeightUpdate:
    """Record of a single dimension's weight change."""

    dimension: str
    domain: str
    prior: float
    posterior: float
    shift: float
    observation_rate: float
    evidence_cases: int
    was_capped: bool  # True if evidence request was clipped by coordinate bounds
    explanation: str

    @property
    def direction(self) -> str:
        if self.shift > 0.001:
            return "increased"
        if self.shift < -0.001:
            return "decreased"
        return "unchanged"


# ---------------------------------------------------------------------------
# Update cycle (full run for one domain)
# ---------------------------------------------------------------------------


@dataclass
class UpdateCycle:
    """Result of one full Bayesian update cycle for a domain."""

    cycle_id: str
    domain: str
    prior_weights: dict[str, float]
    posterior_weights: dict[str, float]  # normalized
    updates: list[WeightUpdate]
    evidence_summary: list[DimensionEvidence]
    ran_at: float = field(default_factory=time.time)
    total_precedents_used: int = 0

    @property
    def changed_dimensions(self) -> list[str]:
        return [u.dimension for u in self.updates if abs(u.shift) > 1e-6]

    @property
    def capped_dimensions(self) -> list[str]:
        return [u.dimension for u in self.updates if u.was_capped]

    def summary(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "domain": self.domain,
            "ran_at": self.ran_at,
            "total_precedents": self.total_precedents_used,
            "changed": self.changed_dimensions,
            "capped": self.capped_dimensions,
            "prior": self.prior_weights,
            "posterior": self.posterior_weights,
        }


# ---------------------------------------------------------------------------
# Core updater
# ---------------------------------------------------------------------------


class BayesianThresholdUpdater:
    """Bayesian weight updater for 7-vector governance scoring.

    Maintains a weight table per domain (plus a global/default).
    Each call to update_from_precedents() produces an UpdateCycle
    that can be inspected, applied, or rolled back.

    Usage::

        updater = BayesianThresholdUpdater(precedent_store=trusted_store)

        # Collect evidence from records admitted to that PrecedentStore
        evidence = updater.collect_evidence(
            precedents,
            domain="healthcare",
            case_domains=authoritative_case_domains,
        )

        # Run one update cycle (evidence domain must equal the update domain)
        cycle = updater.update(evidence, domain="healthcare")

        # Inspect what changed
        print(cycle.summary())
        for u in cycle.updates:
            print(u.explanation)

        # Get current weights for a domain
        weights = updater.weights("healthcare")

        # Rollback if needed (Governor action)
        updater.rollback("healthcare")
    """

    #: Upper bound on retained UpdateCycle audit records (oldest dropped first).
    _MAX_CYCLE_HISTORY = 1000

    def __init__(
        self,
        base_weights: dict[str, float] | None = None,
        max_shift_per_cycle: float = 0.08,
        min_evidence_count: int = 5,
        confirmation_threshold: float = 0.5,
        precedent_store: PrecedentStore | None = None,
    ) -> None:
        if precedent_store is not None and not isinstance(precedent_store, PrecedentStore):
            raise TypeError("precedent_store must be a PrecedentStore")
        self._precedent_store = precedent_store
        supplied = base_weights or {}
        unknown = set(supplied) - set(_DIMENSIONS)
        if unknown:
            raise ValueError(f"unknown governance dimensions: {sorted(unknown)}")
        filled = _fill_defaults(supplied)
        for dimension, value in filled.items():
            _validate_finite(
                f"base_weights[{dimension!r}]",
                value,
                minimum=_MIN_WEIGHT,
                maximum=_MAX_WEIGHT,
            )
        normalized = _normalize(filled)
        for dimension, value in normalized.items():
            _validate_finite(
                f"normalized base_weights[{dimension!r}]",
                value,
                minimum=_MIN_WEIGHT,
                maximum=_MAX_WEIGHT,
            )

        self._base = normalized
        self._max_shift = _validate_finite(
            "max_shift_per_cycle", max_shift_per_cycle, maximum=1.0
        )
        self._min_evidence = _validate_count(
            "min_evidence_count", min_evidence_count, minimum=1
        )
        self._confirm_threshold = _validate_finite(
            "confirmation_threshold", confirmation_threshold, maximum=1.0
        )

        # domain → current weights (starts from base)
        self._domain_weights: dict[str, dict[str, float]] = {}
        # domain → stack of (weights, cycle_id) for rollback
        self._history: dict[str, list[tuple[dict[str, float], str]]] = {}
        # most recent cycles (bounded audit trail)
        self._cycles: deque[UpdateCycle] = deque(maxlen=self._MAX_CYCLE_HISTORY)
        self._cycle_count = 0
        self._lock = RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def precedent_store(self) -> PrecedentStore:
        """Return the injected admission store or fail before evidence use."""
        if self._precedent_store is None:
            raise ValueError(
                "precedent evidence requires an injected trusted PrecedentStore"
            )
        return self._precedent_store

    def weights(self, domain: str = "") -> dict[str, float]:
        """Current weights for a domain (falls back to global base)."""
        if not isinstance(domain, str):
            raise TypeError("domain must be a string")
        with self._lock:
            return dict(self._domain_weights.get(domain, self._base))

    def collect_evidence(
        self,
        precedents: list[PrecedentRecord],
        domain: str = "",
        *,
        case_domains: dict[str, str] | None = None,
    ) -> list[DimensionEvidence]:
        """Aggregate evidence for each dimension from a list of PrecedentRecords.

        Evidence is weighted by validator_grade so higher-quality judgments
        contribute more signal than low-grade ones.

        A dimension d is "ambiguous" if d ∈ precedent.ambiguous_dimensions.
          confirmed  if impact_vector[d] ≥ confirmation_threshold
          overblown  if impact_vector[d] < confirmation_threshold

        Args:
            precedents: exact active records admitted to the injected store;
                    unknown, altered, revoked or duplicated records raise
            domain: filter to only precedents matching this domain
                    (empty string = all active precedents)
            case_domains: authoritative case-id to domain mapping, required
                    whenever ``domain`` is nonempty

        Returns:
            list of DimensionEvidence, one per governance dimension
        """
        if not isinstance(domain, str):
            raise TypeError("domain must be a string")
        if domain and case_domains is None:
            raise ValueError("case_domains is required for domain-scoped evidence")
        if case_domains is not None:
            for case_id, mapped_domain in case_domains.items():
                if not isinstance(case_id, str) or not isinstance(mapped_domain, str):
                    raise TypeError("case_domains must map strings to strings")

        canonical = (
            self.precedent_store.require_canonical_records(list(precedents)) if precedents else ()
        )
        filtered = [
            precedent
            for precedent in canonical
            if precedent.is_active
            and (
                not domain
                or case_domains is not None
                and case_domains.get(precedent.case_id) == domain
            )
        ]

        evidence: dict[str, dict] = {
            d: {"total": 0, "confirmed": 0.0, "overblown": 0.0} for d in _DIMENSIONS
        }

        for rec in filtered:
            for dim in rec.ambiguous_dimensions:
                if dim not in evidence:
                    continue
                score = rec.impact_vector.get(dim, 0.0)
                grade = rec.validator_grade  # weight by quality
                _validate_finite(
                    f"precedent {rec.case_id!r} impact_vector[{dim!r}]",
                    score,
                    maximum=1.0,
                )
                _validate_finite(
                    f"precedent {rec.case_id!r} validator_grade", grade, maximum=1.0
                )
                evidence[dim]["total"] += 1
                if score >= self._confirm_threshold:
                    evidence[dim]["confirmed"] += grade
                else:
                    evidence[dim]["overblown"] += grade

        return [
            DimensionEvidence(
                dimension=d,
                domain=domain,
                total_cases=evidence[d]["total"],
                confirmed_count=evidence[d]["confirmed"],
                overblown_count=evidence[d]["overblown"],
            )
            for d in _DIMENSIONS
        ]

    def update(
        self,
        evidence: list[DimensionEvidence],
        domain: str = "",
    ) -> UpdateCycle:
        """Run one Bayesian update cycle.

        For each dimension with sufficient evidence, compute the posterior
        weight and record the shift. Updates are bounded by max_shift_per_cycle.
        Domain weights are normalized to sum to 1.0 after all shifts.

        Args:
            evidence: list of DimensionEvidence (from collect_evidence)
            domain: the domain these weights apply to (empty = global)

        Returns:
            UpdateCycle with full audit trail
        """
        if not isinstance(domain, str):
            raise TypeError("domain must be a string")
        evidence_map: dict[str, DimensionEvidence] = {}
        for item in evidence:
            if not isinstance(item, DimensionEvidence):
                raise TypeError("evidence entries must be DimensionEvidence instances")
            if item.dimension not in _DIMENSIONS:
                raise ValueError(f"unknown governance dimension: {item.dimension!r}")
            if not isinstance(item.domain, str):
                raise TypeError("evidence domain must be a string")
            if item.dimension in evidence_map:
                raise ValueError(f"duplicate evidence for dimension {item.dimension!r}")
            if item.domain != domain:
                raise ValueError(
                    f"evidence domain {item.domain!r} does not match update domain {domain!r}"
                )
            evidence_map[item.dimension] = item

        with self._lock:
            prior = dict(self._domain_weights.get(domain, self._base))
            requested = dict(prior)
            lower = {
                dim: max(_MIN_WEIGHT, prior[dim] - self._max_shift) for dim in _DIMENSIONS
            }
            upper = {
                dim: min(_MAX_WEIGHT, prior[dim] + self._max_shift) for dim in _DIMENSIONS
            }
            raw_shifts = dict.fromkeys(_DIMENSIONS, 0.0)
            protected: set[str] = set()

            for dim, evidence_item in evidence_map.items():
                if evidence_item.total_cases < self._min_evidence:
                    continue
                protected.add(dim)
                raw_shift = (2.0 * evidence_item.observation_rate - 1.0) * self._max_shift
                raw_shifts[dim] = raw_shift
                requested[dim] = max(lower[dim], min(upper[dim], prior[dim] + raw_shift))

            posterior = _project_bounded_simplex(requested, lower, upper, protected)
            updates: list[WeightUpdate] = []
            for dim in _DIMENSIONS:
                ev = evidence_map.get(dim)
                obs_rate = ev.observation_rate if ev is not None else 0.5
                evidence_cases = ev.total_cases if ev is not None else 0
                actual_shift = posterior[dim] - prior[dim]
                unbounded_request = prior[dim] + raw_shifts[dim]
                was_capped = abs(requested[dim] - unbounded_request) > 1e-12
                was_balanced = abs(posterior[dim] - requested[dim]) > 1e-12
                sufficient = ev is not None and ev.total_cases >= self._min_evidence
                if sufficient:
                    pct = round(obs_rate * 100, 1)
                    direction = "confirmed valid" if obs_rate >= 0.5 else "found overblown"
                    adjustments = ""
                    if was_capped:
                        adjustments += ", bounded"
                    if was_balanced:
                        adjustments += ", balanced"
                    explanation = (
                        f"{dim}: {evidence_cases} cases, {pct}% {direction}. "
                        f"Weight {prior[dim]:.3f} → {posterior[dim]:.3f} "
                        f"(shift={actual_shift:+.3f}"
                        + adjustments
                        + ")."
                    )
                elif abs(actual_shift) > 1e-12:
                    explanation = (
                        f"{dim}: insufficient direct evidence; weight balanced "
                        f"{prior[dim]:.3f} → {posterior[dim]:.3f} "
                        f"(shift={actual_shift:+.3f})."
                    )
                else:
                    explanation = (
                        f"{dim}: insufficient evidence "
                        f"({evidence_cases} < {self._min_evidence}), weight unchanged."
                    )
                updates.append(
                    WeightUpdate(
                        dimension=dim,
                        domain=domain,
                        prior=prior[dim],
                        posterior=posterior[dim],
                        shift=actual_shift,
                        observation_rate=obs_rate,
                        evidence_cases=evidence_cases,
                        was_capped=was_capped,
                        explanation=explanation,
                    )
                )

            self._history.setdefault(domain, []).append(
                (dict(prior), "pre-" + str(self._cycle_count))
            )
            self._cycle_count += 1
            self._domain_weights[domain] = dict(posterior)
            cycle = UpdateCycle(
                cycle_id=uuid.uuid4().hex[:8],
                domain=domain,
                prior_weights=dict(prior),
                posterior_weights=dict(posterior),
                updates=updates,
                evidence_summary=list(evidence),
                total_precedents_used=max((item.total_cases for item in evidence), default=0),
            )
            self._cycles.append(deepcopy(cycle))
            return deepcopy(cycle)

    def update_from_precedents(
        self,
        precedents: list[PrecedentRecord],
        domain: str = "",
        *,
        case_domains: dict[str, str] | None = None,
    ) -> UpdateCycle:
        """Convenience: collect evidence + run one update cycle."""
        evidence = self.collect_evidence(
            precedents, domain=domain, case_domains=case_domains
        )
        return self.update(evidence, domain=domain)

    def rollback(self, domain: str = "") -> bool:
        """Roll back the last update cycle for a domain.

        Returns True if rollback succeeded, False if no history exists.
        """
        with self._lock:
            history = self._history.get(domain, [])
            if not history:
                return False
            prev_weights, _ = history.pop()
            self._domain_weights[domain] = dict(prev_weights)
            return True

    def all_cycles(self) -> list[UpdateCycle]:
        """Return the retained (most recent) update cycles, oldest first."""
        with self._lock:
            return deepcopy(list(self._cycles))

    def summary(self) -> dict[str, Any]:
        with self._lock:
            domains = list(self._domain_weights)
            return {
                "domains_tracked": domains,
                "cycles_run": self._cycle_count,
                "max_shift_per_cycle": self._max_shift,
                "min_evidence_count": self._min_evidence,
                "current_weights": {
                    domain: dict(self._domain_weights.get(domain, self._base))
                    for domain in (domains or [""])
                },
            }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fill_defaults(weights: dict[str, float]) -> dict[str, float]:
    """Fill missing dimensions with DEFAULT_WEIGHTS values."""
    result = dict(DEFAULT_WEIGHTS)
    result.update(weights)
    return result


def _normalize(weights: dict[str, float]) -> dict[str, float]:
    """Normalize a weight dict so values sum to 1.0."""
    total = math.fsum(weights.values())
    if total == 0:
        n = len(weights)
        return {k: 1.0 / n for k in weights}
    return {k: v / total for k, v in weights.items()}


def _project_bounded_simplex(
    requested: dict[str, float],
    lower: dict[str, float],
    upper: dict[str, float],
    protected: set[str],
) -> dict[str, float]:
    """Project onto sum=1 bounds, preserving evidenced requests when feasible."""
    result = {
        dimension: max(lower[dimension], min(upper[dimension], requested[dimension]))
        for dimension in _DIMENSIONS
    }
    difference = 1.0 - math.fsum(result.values())
    if abs(difference) <= 1e-12:
        return result

    preferred = [dimension for dimension in _DIMENSIONS if dimension not in protected]
    fallback = [dimension for dimension in _DIMENSIONS if dimension in protected]
    for candidates in (preferred, fallback):
        difference = _redistribute(result, lower, upper, candidates, difference)
        if abs(difference) <= 1e-12:
            break
    if abs(difference) > 1e-9:
        raise ValueError("weight constraints cannot conserve a total weight of 1.0")
    return result


def _redistribute(
    values: dict[str, float],
    lower: dict[str, float],
    upper: dict[str, float],
    candidates: list[str],
    amount: float,
) -> float:
    """Distribute ``amount`` evenly across available coordinate capacity."""
    remaining = amount
    active = list(candidates)
    while active and abs(remaining) > 1e-12:
        share = remaining / len(active)
        next_active: list[str] = []
        applied = 0.0
        for dimension in active:
            bound = upper[dimension] if share > 0 else lower[dimension]
            if share > 0:
                delta = min(share, bound - values[dimension])
            else:
                delta = max(share, bound - values[dimension])
            values[dimension] += delta
            applied += delta
            if share > 0 and values[dimension] < upper[dimension] - 1e-12:
                next_active.append(dimension)
            elif share < 0 and values[dimension] > lower[dimension] + 1e-12:
                next_active.append(dimension)
        if abs(applied) <= 1e-15:
            break
        remaining -= applied
        active = next_active
    return remaining
