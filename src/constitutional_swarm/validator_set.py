"""Sybil-resilient validator set with VRF-based committee selection.

Phase 7.1 breakthrough: current ``ConstitutionalMesh`` assumes Byzantine
tolerance at < 1/3 of *identities*. Under sybil attack, a single
adversary can inflate raw identity count cheaply and break that bound.

This module introduces:

- :class:`ValidatorIdentity` — a validator with stake, reputation, and
  a fault-domain tag (IP prefix, AS number, organization, credential
  issuer, etc.) used to bound per-domain influence.
- :class:`FaultDomainPolicy` — caps the effective weight contributed
  by any single fault domain. This is the key sybil defense: raw
  identity count no longer dominates.
- :class:`ValidatorSet` — the membership with total weights and
  per-domain weights.
- :class:`CommitteeSelector` — VRF-style deterministic committee
  sampling from a public seed.

References
----------
- Lamport, Shostak, Pease (1982) "The Byzantine Generals Problem"
- Generalized Byzantine Quorums (Alchieri et al. 2020) — asymmetric trust
- Sybil-Resilient Reality-Aware Social Choice (Shahaf et al. 2018)

This is a tractable MVP — we use a domain-separated, length-framed SHA-256
digest of ``(seed, validator_id)`` (:func:`~constitutional_swarm.framing.framed_digest`)
as the VRF surrogate. A production deployment would swap in RFC 9381
ECVRF or BLS-based sortition. The committee selection contract
(deterministic from public seed + verifiable by anyone with the seed)
is preserved under either implementation.
"""

from __future__ import annotations

import heapq
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from constitutional_swarm.framing import framed_digest

_VRF_DOMAIN = b"acgs-swarm/committee-vrf/v1"
_VRF_RETRY_DOMAIN = b"acgs-swarm/committee-vrf-retry/v1"

__all__ = [
    "CommitteeSelection",
    "CommitteeSelector",
    "FaultDomainPolicy",
    "SybilBoundViolation",
    "ValidatorIdentity",
    "ValidatorSet",
    "domain_share_exceeded",
]


class SybilBoundViolation(ValueError):
    """Raised when a committee would exceed the fault-domain weight cap."""


@dataclass(frozen=True)
class ValidatorIdentity:
    """A single validator with stake, reputation, and fault-domain tag.

    Parameters
    ----------
    agent_id:
        Canonical agent identifier (matches ``ConstitutionalMesh``).
    stake:
        Non-negative stake weight. Raw weight in quorum calculations.
    reputation:
        Multiplier in ``[0.0, 1.0]`` — recent good behavior amplifies
        effective weight; misbehavior shrinks it.
    fault_domain:
        Opaque tag identifying the validator's independence class
        (e.g. ``"as:AS15169"``, ``"org:ourcorp"``, ``"issuer:acme-ca"``).
        Multiple validators sharing a fault_domain are not independent
        fault domains and must be collectively capped.
    """

    agent_id: str
    stake: float
    reputation: float = 1.0
    fault_domain: str = ""
    public_key_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if type(self.agent_id) is not str or not self.agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if "\x00" in self.agent_id:
            raise ValueError("agent_id must not contain NUL characters")
        if self.stake < 0.0:
            raise ValueError(f"stake must be non-negative, got {self.stake}")
        if not 0.0 <= self.reputation <= 1.0:
            raise ValueError(f"reputation must be in [0, 1], got {self.reputation}")
        if self.public_key_bytes is not None and len(self.public_key_bytes) != 32:
            raise ValueError("public_key_bytes must be a raw Ed25519 public key")

    @property
    def effective_weight(self) -> float:
        """Raw effective weight before fault-domain capping."""
        return self.stake * self.reputation


@dataclass(frozen=True)
class FaultDomainPolicy:
    """Cap on per-fault-domain contribution to committee weight.

    ``max_fraction`` caps any single fault_domain's *counted* weight at
    ``max_fraction`` times the total *raw* (uncapped) effective weight of
    the committee or set. Setting ``max_fraction=0.2`` means no single
    AS / issuer / org can contribute more than 20 % of the raw weight to a
    quorum, no matter how many validator identities they register; the
    excess is discarded. This bounds the adversary's absolute contribution,
    which is what makes the scheme sybil-resistant: an attacker must
    actually spread across independent fault domains.

    Note that this is *not* a bound on a domain's share of the counted
    (post-cap) total: when other domains are small, a capped domain can
    still hold more than ``max_fraction`` of the counted weight. Callers
    that need the stronger guarantee (no domain holds more than
    ``max_fraction`` of the raw weight at all) opt in with
    ``CommitteeSelection.has_quorum(..., enforce_domain_share=True)`` or
    ``CertificateVerificationPolicy(enforce_domain_share=True)``.

    ``untagged_policy`` controls how validators with empty
    ``fault_domain`` are treated:

    - ``"strict"`` (default) — treat every untagged validator as its
      own domain ``"__untagged__:<agent_id>"``; safest when tags are
      optional but incomplete.
    - ``"lenient"`` — treat all untagged validators as a single
      shared domain ``"__untagged__"``. Useful for backward-compat
      with pre-Phase-7 agent registrations.
    """

    max_fraction: float = 0.34
    untagged_policy: str = "strict"

    def __post_init__(self) -> None:
        if not 0.0 < self.max_fraction <= 1.0:
            raise ValueError(f"max_fraction must be in (0, 1], got {self.max_fraction}")
        if self.untagged_policy not in ("strict", "lenient"):
            raise ValueError(
                f"untagged_policy must be 'strict' or 'lenient', got {self.untagged_policy!r}"
            )

    def resolve_domain(self, validator: ValidatorIdentity) -> str:
        """Resolve the effective fault-domain tag for a validator."""
        if validator.fault_domain:
            return validator.fault_domain
        if self.untagged_policy == "strict":
            return f"__untagged__:{validator.agent_id}"
        return "__untagged__"


@dataclass(frozen=True)
class CommitteeSelection:
    """Result of :meth:`CommitteeSelector.select`.

    ``members`` is the committee (subset of validator ids). ``weight``
    is the total raw effective weight (before fault-domain capping).
    ``capped_weight`` applies the policy cap per domain — this is the
    value that matters for the safety threshold. ``domain_weights``
    maps fault_domain → the weight actually counted (post-cap).
    ``raw_domain_weights`` maps fault_domain → the uncapped weight and
    ``max_fraction`` records the policy cap used; both are required by
    ``has_quorum(..., enforce_domain_share=True)``.
    """

    members: tuple[str, ...]
    weight: float
    capped_weight: float
    domain_weights: Mapping[str, float]
    seed: str
    raw_domain_weights: Mapping[str, float] = field(default_factory=dict)
    max_fraction: float | None = None

    def exceeds_domain_share(self) -> bool:
        """True if any domain holds more than ``max_fraction`` of raw weight.

        Fails closed: returns True when the raw per-domain data or the
        policy cap needed to decide is missing.
        """
        if self.max_fraction is None or not self.raw_domain_weights or self.weight <= 0:
            return True
        return domain_share_exceeded(
            self.raw_domain_weights.values(), self.weight, self.max_fraction
        )

    def has_quorum(
        self,
        threshold_fraction: float = 2 / 3,
        *,
        enforce_domain_share: bool = False,
    ) -> bool:
        """True if capped weight meets the threshold fraction of raw weight.

        A committee ``has_quorum(2/3)`` when the honest lower bound,
        computed under the fault-domain cap, is at least 2/3 of the
        raw uncapped weight. With ``enforce_domain_share=True`` the
        committee is additionally rejected when any single fault domain
        holds more than ``max_fraction`` of the raw committee weight.
        """
        if self.weight <= 0:
            return False
        if enforce_domain_share and self.exceeds_domain_share():
            return False
        return self.capped_weight / self.weight >= threshold_fraction


def domain_share_exceeded(
    raw_domain_weights: Iterable[float],
    raw_total: float,
    max_fraction: float,
) -> bool:
    """True if any raw domain weight exceeds ``max_fraction * raw_total``.

    Shared by :meth:`CommitteeSelection.has_quorum` and the quorum
    certificate verifier so both apply the identical rule. Equality within
    floating-point tolerance is permitted.
    """
    ceiling = max_fraction * raw_total
    return any(
        w > ceiling and not math.isclose(w, ceiling, rel_tol=1e-12, abs_tol=0.0)
        for w in raw_domain_weights
    )


class ValidatorSet:
    """A sybil-aware validator membership with fault-domain caps.

    The set maintains:

    - all registered validators
    - per-domain weight totals
    - a total raw effective weight

    Add / remove validators as membership changes; committee selection
    is then performed against the current set.
    """

    def __init__(
        self,
        validators: Iterable[ValidatorIdentity] = (),
        *,
        policy: FaultDomainPolicy | None = None,
    ) -> None:
        self._policy = policy or FaultDomainPolicy()
        self._validators: dict[str, ValidatorIdentity] = {}
        # Keys of removed validators: re-registering a removed id with a
        # different key requires an explicit ``rekey=True``.
        self._retired_keys: dict[str, bytes] = {}
        for v in validators:
            self.add(v)

    @property
    def policy(self) -> FaultDomainPolicy:
        return self._policy

    def __len__(self) -> int:
        return len(self._validators)

    def __contains__(self, agent_id: object) -> bool:
        return isinstance(agent_id, str) and agent_id in self._validators

    def __iter__(self):
        return iter(self._validators.values())

    def add(
        self,
        validator: ValidatorIdentity,
        *,
        replace: bool = False,
        rekey: bool = False,
    ) -> None:
        """Register a validator.

        Raises ``ValueError`` if ``agent_id`` is already registered, unless
        ``replace=True`` is passed explicitly. Even with ``replace=True`` a
        registered (non-None) public key of a *live* identity can never change
        or be dropped: that key is the trust root quorum certificates verify
        against. Re-registering a previously removed ``agent_id`` with a
        different key (including dropping it to ``None``) raises unless
        ``rekey=True`` is passed explicitly; ``rekey`` has no effect on live
        identities, so re-keying always takes a ``remove`` plus an explicit
        ``add(..., rekey=True)``.
        """
        retired = self._retired_keys.get(validator.agent_id)
        if (
            validator.agent_id not in self._validators
            and retired is not None
            and validator.public_key_bytes != retired
            and not rekey
        ):
            raise ValueError(
                f"validator {validator.agent_id!r} was removed with a different public key; "
                "pass rekey=True to re-register it under a new key"
            )
        existing = self._validators.get(validator.agent_id)
        if existing is not None:
            if not replace:
                raise ValueError(
                    f"validator {validator.agent_id!r} is already registered; "
                    "pass replace=True to update it"
                )
            if (
                existing.public_key_bytes is not None
                and validator.public_key_bytes != existing.public_key_bytes
            ):
                raise ValueError(
                    f"cannot change the registered public key of validator "
                    f"{validator.agent_id!r}"
                )
        self._validators[validator.agent_id] = validator
        self._retired_keys.pop(validator.agent_id, None)

    def remove(self, agent_id: str) -> None:
        """Remove a validator. Silent if not registered.

        The removed identity's public key is remembered so that a later
        :meth:`add` cannot silently re-key it (see ``rekey``).
        """
        removed = self._validators.pop(agent_id, None)
        if removed is not None and removed.public_key_bytes is not None:
            self._retired_keys[agent_id] = removed.public_key_bytes

    def get(self, agent_id: str) -> ValidatorIdentity | None:
        return self._validators.get(agent_id)

    def total_weight(self) -> float:
        return sum(v.effective_weight for v in self._validators.values())

    def domain_weights(self) -> dict[str, float]:
        """Weight totals per fault-domain across the full set."""
        out: dict[str, float] = {}
        for v in self._validators.values():
            domain = self._policy.resolve_domain(v)
            out[domain] = out.get(domain, 0.0) + v.effective_weight
        return out

    def effective_total_weight(self) -> float:
        """Total weight *after* applying the per-domain cap.

        This is the honest upper bound the validator set as a whole can
        contribute. If the cap is 1/3 and any one domain holds >1/3 of
        raw weight, the excess is discarded — that's the sybil defense.
        """
        cap_frac = self._policy.max_fraction
        raw_total = self.total_weight()
        if raw_total <= 0:
            return 0.0
        ceiling = cap_frac * raw_total
        domain_w = self.domain_weights()
        capped_total = 0.0
        for w in domain_w.values():
            capped_total += min(w, ceiling)
        return capped_total

    def snapshot(self) -> tuple[ValidatorIdentity, ...]:
        """Deterministic ordered tuple of all validators (by agent_id)."""
        return tuple(self._validators[k] for k in sorted(self._validators))


class CommitteeSelector:
    """VRF-style deterministic committee sampling.

    Given a public ``seed`` (e.g. ``assignment_id`` or an epoch beacon)
    and a ``committee_size``, this produces a committee deterministically
    — any other party with the same validator set and seed reproduces
    the same committee. Each validator's selection score is
    :math:`h(\\mathrm{seed} \\| \\mathrm{agent\\_id})` adjusted by
    effective weight.

    We use SHA-256 as a stand-in VRF (not verifiable by a non-operator).
    To upgrade, swap in RFC 9381 ECVRF: the ``_score`` method is the
    only coupling point.
    """

    def __init__(self, validator_set: ValidatorSet) -> None:
        self._set = validator_set

    @staticmethod
    def _score(seed: str, agent_id: str, weight: float) -> float:
        """Weighted VRF score — lower is "sooner-picked".

        Implements the standard weighted sortition transform
        ``-ln(u) / w`` where ``u ~ Uniform(0, 1)``. Equivalent to
        Poisson process priority sampling: the smallest k scores form
        a weighted sample without replacement.
        """
        if weight <= 0:
            return float("inf")
        digest = framed_digest(_VRF_DOMAIN, seed, agent_id)
        # Uniform in (0, 1] — avoid 0 to keep log defined
        raw = int.from_bytes(digest[:8], "big") + 1
        u = raw / (1 << 64)
        # -ln(u)/w priority → weighted sample without replacement
        return -math.log(u) / weight

    def select(
        self,
        seed: str,
        committee_size: int,
        *,
        exclude: Sequence[str] = (),
    ) -> CommitteeSelection:
        """Select a committee of ``committee_size`` validators.

        Parameters
        ----------
        seed:
            Public, reproducible entropy source (e.g. assignment id,
            epoch hash). Same seed + same set => same committee.
        committee_size:
            Target committee size. If the set has fewer eligible
            validators than requested, the full eligible set is used.
        exclude:
            Validator ids to exclude (e.g. the producer under MACI).

        Returns
        -------
        CommitteeSelection
            Committee members, total raw weight, capped weight (per
            fault-domain policy), and per-domain weight breakdown.
        """
        if committee_size <= 0:
            raise ValueError(f"committee_size must be positive, got {committee_size}")
        excluded = frozenset(exclude)
        candidates = [v for v in self._set if v.agent_id not in excluded]
        if not candidates:
            return CommitteeSelection(
                members=(),
                weight=0.0,
                capped_weight=0.0,
                domain_weights={},
                seed=seed,
                max_fraction=self._set.policy.max_fraction,
            )
        # Priority-sample the k lowest-score validators
        k = min(committee_size, len(candidates))
        scored = [(self._score(seed, v.agent_id, v.effective_weight), v) for v in candidates]
        chosen = heapq.nsmallest(k, scored, key=lambda t: t[0])
        picked = [v for _, v in chosen]
        # Sort deterministically by agent_id so serialized committees
        # are independent of Python's heap stability quirks
        picked.sort(key=lambda v: v.agent_id)

        # Compute raw + capped weights
        policy = self._set.policy
        raw_weight = sum(v.effective_weight for v in picked)
        per_domain: dict[str, float] = {}
        for v in picked:
            domain = policy.resolve_domain(v)
            per_domain[domain] = per_domain.get(domain, 0.0) + v.effective_weight
        # Cap each domain at max_fraction * raw_weight
        capped_weight = 0.0
        capped_domain_weights: dict[str, float] = {}
        if raw_weight > 0:
            ceiling = policy.max_fraction * raw_weight
            for domain, w in per_domain.items():
                capped = min(w, ceiling)
                capped_domain_weights[domain] = capped
                capped_weight += capped

        return CommitteeSelection(
            members=tuple(v.agent_id for v in picked),
            weight=raw_weight,
            capped_weight=capped_weight,
            domain_weights=capped_domain_weights,
            seed=seed,
            raw_domain_weights=per_domain,
            max_fraction=policy.max_fraction,
        )

    def select_until_independent(
        self,
        seed: str,
        committee_size: int,
        *,
        exclude: Sequence[str] = (),
        max_retries: int = 8,
        threshold_fraction: float = 2 / 3,
        enforce_domain_share: bool = False,
    ) -> CommitteeSelection:
        """Select a committee with enough fault-domain independence.

        Calls :meth:`select` with seed variants until the committee's
        capped/raw ratio meets ``threshold_fraction`` (and, with
        ``enforce_domain_share=True``, no domain exceeds ``max_fraction``
        of raw weight), or ``max_retries`` is exhausted. Retry ``k >= 1``
        uses the hex of a domain-separated framed digest of ``(seed, k)``
        so retry seeds cannot collide with caller-chosen seeds. If all retries fail, raises
        :class:`SybilBoundViolation` — meaning the validator set itself
        is too sybil-concentrated to produce a safe committee of the
        requested size.
        """
        for attempt in range(max_retries):
            probe_seed = (
                seed if attempt == 0 else framed_digest(_VRF_RETRY_DOMAIN, seed, attempt).hex()
            )
            result = self.select(probe_seed, committee_size, exclude=exclude)
            if result.has_quorum(threshold_fraction, enforce_domain_share=enforce_domain_share):
                return result
        raise SybilBoundViolation(
            f"Could not assemble a committee of size {committee_size} "
            f"with capped/raw ≥ {threshold_fraction:.3f} after "
            f"{max_retries} retries. The validator set is sybil-concentrated."
        )
