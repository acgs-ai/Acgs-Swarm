"""Rule Codifier — Phase 3.3.

Scans the PrecedentStore for clusters of similar precedents that have
reached consensus, then proposes them as new constitutional rules.
No rule is activated without explicit Governor approval.

Pipeline:
  1. Cluster precedents by 7-vector cosine similarity
  2. Filter clusters by size and validator agreement
  3. Generate YAML rule text from cluster centroid + majority judgment
  4. Require Governor approval (pending state)
  5. Activate: append rule to constitution → new constitutional hash

This is rule writing, not model training. Every generated rule is:
  • Explicit — plain-language text, fully auditable
  • Versioned — produces a new constitutional hash on activation
  • Governed — a rostered governor (never the proposer) must approve() and
    activate(); activation only applies to the YAML whose hash is the
    codifier's current constitutional hash
  • Reversible — revoke() marks the rule inactive

Example output YAML (matching Q&A doc §5 Mechanism 3):
  - id: HEALTH-SEC-047
    text: "Healthcare data access requests with both security and fairness
           vectors above 0.60 require explicit consent verification"
    severity: high
    source: precedent_codification
    precedent_cluster: ESC-HEALTH-SEC
    case_count: 53
    validator_agreement: 0.94

Roadmap: 08-subnet-implementation-roadmap.md § Phase 3.3
Q&A:     07-subnet-concept-qa-responses.md § 5 Mechanism 3
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import time
import uuid
from collections import Counter, OrderedDict
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml

from constitutional_swarm.bittensor.nmc_protocol import _deterministic_winner
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore

# The single governance-dimension table shared by the codifier and the
# threshold updater.
_DIMENSIONS = (
    "safety",
    "security",
    "privacy",
    "fairness",
    "reliability",
    "transparency",
    "efficiency",
)

_DEFAULT_PROPOSER_ID = "rule-codifier"


def constitution_hash(constitution_yaml: str) -> str:
    """Return the 16-hex-character constitutional hash of a constitution YAML text."""
    if type(constitution_yaml) is not str:
        raise TypeError("constitution_yaml must be a string")
    return hashlib.sha256(constitution_yaml.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Rule candidate state
# ---------------------------------------------------------------------------


class RuleCandidateStatus(Enum):
    PENDING = "pending"  # awaiting Governor approval
    APPROVED = "approved"  # Governor approved, not yet activated
    ACTIVE = "active"  # activated, has a new constitutional hash
    REJECTED = "rejected"  # Governor rejected
    REVOKED = "revoked"  # was active, Governor revoked


# ---------------------------------------------------------------------------
# Cluster (input to codification)
# ---------------------------------------------------------------------------


@dataclass
class PrecedentCluster:
    """A group of similar precedents that might be codified into a rule."""

    cluster_id: str
    precedent_ids: list[str]
    centroid_vector: dict[str, float]  # mean of all impact vectors
    dominant_dimensions: list[str]  # dims with centroid score > 0.5
    majority_judgment: str  # most common judgment text
    validator_agreement: float  # mean validator_grade
    escalation_type: str
    domain_hint: str = ""
    formed_at: float = field(default_factory=time.time)

    @property
    def size(self) -> int:
        return len(self.precedent_ids)

    @property
    def is_stable(self) -> bool:
        """True when agreement is high enough to propose a rule."""
        return self.validator_agreement >= 0.70

    def summary(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "validator_agreement": round(self.validator_agreement, 3),
            "dominant_dimensions": self.dominant_dimensions,
            "escalation_type": self.escalation_type,
            "majority_judgment": self.majority_judgment[:80] + "...",
        }


# ---------------------------------------------------------------------------
# Rule candidate (output of codification, pending approval)
# ---------------------------------------------------------------------------


@dataclass
class RuleCandidate:
    """A proposed constitutional rule awaiting Governor approval."""

    candidate_id: str
    cluster_id: str
    rule_id: str  # e.g. "PREC-SEC-001"
    rule_text: str
    severity: str  # critical | high | medium | low
    keywords: list[str]
    source_precedent_ids: list[str]
    validator_agreement: float
    dominant_dimensions: list[str]
    escalation_type: str
    status: RuleCandidateStatus
    proposed_at: float
    approved_at: float | None = None
    activated_at: float | None = None
    constitutional_hash_before: str = ""
    constitutional_hash_after: str = ""
    rejection_reason: str = ""
    revocation_reason: str = ""
    proposed_by: str = ""
    approved_by: str = ""
    activated_by: str = ""

    def to_rule_dict(self) -> dict[str, Any]:
        """Return the rule entry appended to a constitution's ``rules`` list."""
        return {
            "id": self.rule_id,
            "text": self.rule_text,
            "severity": self.severity,
            "hardcoded": False,
            "source": "precedent_codification",
            "precedent_cluster": self.cluster_id,
            "case_count": len(self.source_precedent_ids),
            "validator_agreement": round(self.validator_agreement, 2),
            "keywords": list(self.keywords),
        }

    def to_yaml_block(self) -> str:
        """Render the rule as a safely escaped one-item YAML list (for review)."""
        return yaml.safe_dump([self.to_rule_dict()], sort_keys=False, allow_unicode=True)

    def summary(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "status": self.status.value,
            "severity": self.severity,
            "validator_agreement": round(self.validator_agreement, 3),
            "case_count": len(self.source_precedent_ids),
            "dominant_dimensions": self.dominant_dimensions,
        }


# ---------------------------------------------------------------------------
# Main codifier
# ---------------------------------------------------------------------------


class RuleCodifier:
    """Scans PrecedentStore for consensus clusters and proposes new rules.

    Usage::

        codifier = RuleCodifier(
            constitutional_hash="608508a9bd224290",
            min_cluster_size=5,          # lower for testing; 50 in prod
            min_validator_agreement=0.90,
            similarity_threshold=0.80,
        )

        # Find candidate clusters
        clusters = codifier.find_clusters(active_precedents)

        # Generate rule proposals from qualifying clusters
        candidates = codifier.propose_rules(clusters)

        # A rostered governor (configured via ``governors=``) reviews and approves
        for c in candidates:
            print(c.to_yaml_block())
            codifier.approve(c.candidate_id, governor="sn-owner")

        # Activate against the YAML whose hash is codifier.constitutional_hash
        candidate, new_yaml = codifier.activate(
            c.candidate_id, constitution_yaml, governor="sn-owner"
        )
    """

    #: Upper bound on remembered canonical cluster fingerprints (LRU).
    _MAX_CLUSTER_FINGERPRINTS = 1024

    def __init__(
        self,
        constitutional_hash: str,
        min_cluster_size: int = 50,
        min_validator_agreement: float = 0.90,
        similarity_threshold: float = 0.80,
        rule_id_prefix: str = "PREC",
        precedent_store: PrecedentStore | None = None,
        governors: Collection[str] = (),
        proposer_id: str = _DEFAULT_PROPOSER_ID,
    ) -> None:
        if precedent_store is not None and precedent_store.constitutional_hash != constitutional_hash:
            raise ValueError("PrecedentStore constitutional hash does not match RuleCodifier")
        if isinstance(governors, str) or not isinstance(governors, Collection):
            raise TypeError("governors must be a collection of governor identifiers")
        roster = frozenset(governors)
        if any(type(g) is not str or not g for g in roster):
            raise ValueError("governor identifiers must be non-empty strings")
        if type(proposer_id) is not str or not proposer_id:
            raise ValueError("proposer_id must be a non-empty string")
        if proposer_id in roster:
            raise ValueError("the proposer identity cannot also be a governor")
        self._governors = roster
        self._proposer_id = proposer_id
        self._constitutional_hash = constitutional_hash
        self._precedent_constitutional_hash = constitutional_hash
        self._min_size = min_cluster_size
        self._min_agreement = min_validator_agreement
        self._sim_threshold = similarity_threshold
        self._rule_prefix = rule_id_prefix
        self._candidates: dict[str, RuleCandidate] = {}
        self._rule_counter: int = 0
        self._activated_rules: list[RuleCandidate] = []
        self._precedent_store = precedent_store
        self._cluster_fingerprints: OrderedDict[str, tuple[Any, ...]] = OrderedDict()

    @property
    def constitutional_hash(self) -> str:
        return self._constitutional_hash

    @property
    def governors(self) -> frozenset[str]:
        return self._governors

    @property
    def precedent_store(self) -> PrecedentStore:
        return self._require_precedent_store()

    @property
    def pending_candidates(self) -> list[RuleCandidate]:
        return [
            self._copy_candidate(c)
            for c in self._candidates.values()
            if c.status == RuleCandidateStatus.PENDING
        ]

    @property
    def active_rules(self) -> list[RuleCandidate]:
        return [self._copy_candidate(c) for c in self._activated_rules]

    # ------------------------------------------------------------------
    # Step 1: Cluster precedents
    # ------------------------------------------------------------------

    def find_clusters(
        self,
        precedents: list[PrecedentRecord],
        domain: str = "",
    ) -> list[PrecedentCluster]:
        """Group active precedents into similarity clusters.

        Uses greedy agglomerative clustering:
          For each unassigned precedent, if it's within similarity_threshold
          of an existing cluster centroid, add it. Otherwise start a new cluster.

        Args:
            precedents: active PrecedentRecord objects
            domain: optional hint embedded in cluster metadata

        Returns:
            list of PrecedentCluster (all sizes, pre-filtered)
        """
        if not precedents:
            return []
        store = self._require_precedent_store()
        self._ensure_store_current()
        active = list(store.require_canonical_records(precedents))

        clusters: list[dict] = []

        for rec in active:
            vec = rec.impact_vector
            best_idx = -1
            best_sim = -1.0

            for i, cl in enumerate(clusters):
                sim = _cosine(vec, cl["centroid"])
                if sim > best_sim:
                    best_sim = sim
                    best_idx = i

            if best_idx >= 0 and best_sim >= self._sim_threshold:
                clusters[best_idx]["members"].append(rec)
                # Update centroid (running mean)
                n = len(clusters[best_idx]["members"])
                for d in _DIMENSIONS:
                    clusters[best_idx]["centroid"][d] = (
                        clusters[best_idx]["centroid"][d] * (n - 1) / n + vec.get(d, 0.0) / n
                    )
            else:
                clusters.append(
                    {
                        "centroid": {d: vec.get(d, 0.0) for d in _DIMENSIONS},
                        "members": [rec],
                    }
                )

        result: list[PrecedentCluster] = []
        for cl in clusters:
            members: list[PrecedentRecord] = cl["members"]
            centroid: dict[str, float] = cl["centroid"]

            dominant = [d for d in _DIMENSIONS if centroid.get(d, 0.0) >= 0.5]
            avg_grade = sum(m.validator_grade for m in members) / len(members)
            majority_etype = _deterministic_winner(
                Counter(m.escalation_type.value for m in members)
            )

            # Majority judgment: most common judgment text (first 100 chars as key)
            majority_key = _deterministic_winner(Counter(m.judgment[:100] for m in members))
            # Recover a deterministic full-text representative for the key.
            majority_j = min(m.judgment for m in members if m.judgment[:100] == majority_key)

            cluster = PrecedentCluster(
                cluster_id=uuid.uuid4().hex[:8],
                precedent_ids=[m.precedent_id for m in members],
                centroid_vector=centroid,
                dominant_dimensions=dominant,
                majority_judgment=majority_j,
                validator_agreement=avg_grade,
                escalation_type=majority_etype,
                domain_hint=domain,
            )
            self._remember_cluster(cluster)
            result.append(self._copy_cluster(cluster))

        return result

    # ------------------------------------------------------------------
    # Step 2: Propose rules from qualifying clusters
    # ------------------------------------------------------------------

    def propose_rules(
        self,
        clusters: list[PrecedentCluster],
    ) -> list[RuleCandidate]:
        """Generate RuleCandidate proposals from clusters that meet thresholds.

        Only clusters with size ≥ min_cluster_size AND
        validator_agreement ≥ min_validator_agreement are proposed.

        Returns:
            list of RuleCandidate in PENDING state
        """
        if not clusters:
            return []
        store = self._require_precedent_store()
        proposed: list[RuleCandidate] = []

        for cluster in clusters:
            snapshot = self._copy_cluster(cluster)
            self._ensure_store_current()
            self._validate_cluster(snapshot)
            with store.guard_active_sources(snapshot.precedent_ids):
                if snapshot.size < self._min_size:
                    continue
                if snapshot.validator_agreement < self._min_agreement:
                    continue

                candidate = self._generate_candidate(snapshot)
                self._candidates[candidate.candidate_id] = candidate
                proposed.append(self._copy_candidate(candidate))

        return proposed

    # ------------------------------------------------------------------
    # Steps 3-5: Governor approval workflow
    # ------------------------------------------------------------------

    def approve(self, candidate_id: str, *, governor: str) -> RuleCandidate:
        """A rostered governor approves a pending rule candidate.

        Raises KeyError if not found, ValueError if not in PENDING state, and
        PermissionError if ``governor`` is not rostered or proposed the rule.
        """
        self._ensure_store_current()
        c = self._get_candidate(candidate_id, RuleCandidateStatus.PENDING)
        self._require_governor(governor, c)
        with self._require_precedent_store().guard_active_sources(c.source_precedent_ids):
            updated = dataclasses.replace(
                c,
                status=RuleCandidateStatus.APPROVED,
                approved_at=time.time(),
                approved_by=governor,
            )
            self._candidates[candidate_id] = updated
            return self._copy_candidate(updated)

    def reject(self, candidate_id: str, reason: str = "", *, governor: str) -> RuleCandidate:
        """A rostered governor rejects a pending rule candidate.

        Raises KeyError if not found, ValueError if not in PENDING state, and
        PermissionError if ``governor`` is not rostered or proposed the rule.
        """
        c = self._get_candidate(candidate_id, RuleCandidateStatus.PENDING)
        self._require_governor(governor, c)
        updated = dataclasses.replace(
            c,
            status=RuleCandidateStatus.REJECTED,
            rejection_reason=reason,
        )
        self._candidates[candidate_id] = updated
        return self._copy_candidate(updated)

    def activate(
        self,
        candidate_id: str,
        constitution_yaml: str,
        *,
        governor: str,
    ) -> tuple[RuleCandidate, str]:
        """Activate an approved rule: append it to constitution YAML.

        ``constitution_yaml`` must be the constitution the codifier is pinned
        to, i.e. ``constitution_hash(constitution_yaml)`` must equal
        :attr:`constitutional_hash`; this keeps the before/after hash chain
        linked to the base the rule was actually applied to.

        Returns (updated_candidate, new_constitution_yaml).
        The new YAML contains the rule appended to the rules list.
        A new constitutional hash is computed from the new YAML.

        Raises ValueError if candidate is not in APPROVED state, the YAML is
        not the pinned base or cannot be safely extended, and PermissionError
        if ``governor`` is not rostered or proposed the rule.
        """
        self._ensure_store_current()
        c = self._get_candidate(candidate_id, RuleCandidateStatus.APPROVED)
        self._require_governor(governor, c)
        with self._require_precedent_store().guard_active_sources(c.source_precedent_ids):
            if constitution_hash(constitution_yaml) != self._constitutional_hash:
                raise ValueError(
                    "constitution_yaml does not match the codifier's current constitutional hash"
                )
            new_yaml = _append_rule_to_yaml(constitution_yaml, c.to_rule_dict())
            new_hash = constitution_hash(new_yaml)

            activated = dataclasses.replace(
                c,
                status=RuleCandidateStatus.ACTIVE,
                activated_at=time.time(),
                activated_by=governor,
                constitutional_hash_before=self._constitutional_hash,
                constitutional_hash_after=new_hash,
            )
            self._candidates[candidate_id] = activated
            self._activated_rules.append(activated)
            self._constitutional_hash = new_hash
            return self._copy_candidate(activated), new_yaml

    def revoke(
        self,
        candidate_id: str,
        reason: str = "",
        *,
        governor: str,
    ) -> RuleCandidate:
        """A rostered governor revokes an active rule (marks it inactive, no hash change).

        The constitutional hash does NOT change on revocation — a new
        constitution YAML must be provided and re-activated to remove the rule.

        Raises PermissionError if ``governor`` is not rostered or proposed the rule.
        """
        c = self._get_candidate(candidate_id, RuleCandidateStatus.ACTIVE)
        self._require_governor(governor, c)
        revoked = dataclasses.replace(
            c,
            status=RuleCandidateStatus.REVOKED,
            revocation_reason=reason,
        )
        self._candidates[candidate_id] = revoked
        self._activated_rules = [r for r in self._activated_rules if r.candidate_id != candidate_id]
        return self._copy_candidate(revoked)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def all_candidates(self) -> list[RuleCandidate]:
        return [self._copy_candidate(c) for c in self._candidates.values()]

    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in RuleCandidateStatus}
        for c in self._candidates.values():
            counts[c.status.value] += 1
        return {
            "constitutional_hash": self._constitutional_hash,
            "total_candidates": len(self._candidates),
            "active_rules": len(self._activated_rules),
            "status_counts": counts,
            "thresholds": {
                "min_cluster_size": self._min_size,
                "min_validator_agreement": self._min_agreement,
                "similarity_threshold": self._sim_threshold,
            },
        }

    def _generate_candidate(self, cluster: PrecedentCluster) -> RuleCandidate:
        self._rule_counter += 1
        dims = "-".join(d[:3].upper() for d in cluster.dominant_dimensions[:2])
        rule_id = f"{self._rule_prefix}-{dims}-{self._rule_counter:03d}"

        severity = _infer_severity(cluster.dominant_dimensions)
        rule_text = _generate_rule_text(cluster)
        keywords = _extract_keywords(cluster)

        return RuleCandidate(
            candidate_id=uuid.uuid4().hex[:8],
            cluster_id=cluster.cluster_id,
            rule_id=rule_id,
            rule_text=rule_text,
            severity=severity,
            keywords=keywords,
            source_precedent_ids=list(cluster.precedent_ids),
            validator_agreement=cluster.validator_agreement,
            dominant_dimensions=list(cluster.dominant_dimensions),
            escalation_type=cluster.escalation_type,
            status=RuleCandidateStatus.PENDING,
            proposed_at=time.time(),
            constitutional_hash_before=self._constitutional_hash,
            proposed_by=self._proposer_id,
        )

    def _get_candidate(
        self,
        candidate_id: str,
        expected_status: RuleCandidateStatus,
    ) -> RuleCandidate:
        if candidate_id not in self._candidates:
            raise KeyError(f"Candidate {candidate_id!r} not found.")
        c = self._candidates[candidate_id]
        if c.status != expected_status:
            raise ValueError(
                f"Candidate {candidate_id} is {c.status.value}, expected {expected_status.value}."
            )
        return c

    def _require_governor(self, governor: str, candidate: RuleCandidate) -> None:
        if type(governor) is not str or governor not in self._governors:
            raise PermissionError("governor is not on the codifier's governor roster")
        if governor == candidate.proposed_by:
            raise PermissionError("the proposing identity cannot act as governor")

    def _remember_cluster(self, cluster: PrecedentCluster) -> None:
        self._cluster_fingerprints[cluster.cluster_id] = self._cluster_fingerprint(cluster)
        self._cluster_fingerprints.move_to_end(cluster.cluster_id)
        while len(self._cluster_fingerprints) > self._MAX_CLUSTER_FINGERPRINTS:
            self._cluster_fingerprints.popitem(last=False)

    def _validate_cluster(self, cluster: PrecedentCluster) -> None:
        expected = self._cluster_fingerprints.get(cluster.cluster_id)
        if expected is None or expected != self._cluster_fingerprint(cluster):
            raise ValueError(f"Cluster {cluster.cluster_id!r} is not a canonical cluster source")

    def _ensure_store_current(self) -> None:
        store = self._require_precedent_store()
        if store.constitutional_hash != self._precedent_constitutional_hash:
            raise ValueError(
                "PrecedentStore constitutional hash does not match the codifier's "
                "precedent-admission epoch"
            )

    def _require_precedent_store(self) -> PrecedentStore:
        if self._precedent_store is None:
            raise ValueError(
                "precedent admission and codification require an injected trusted "
                "PrecedentStore"
            )
        return self._precedent_store

    @staticmethod
    def _cluster_fingerprint(cluster: PrecedentCluster) -> tuple[Any, ...]:
        return (
            tuple(cluster.precedent_ids),
            tuple(sorted(cluster.centroid_vector.items())),
            tuple(cluster.dominant_dimensions),
            cluster.majority_judgment,
            cluster.validator_agreement,
            cluster.escalation_type,
            cluster.domain_hint,
        )

    @staticmethod
    def _copy_cluster(cluster: PrecedentCluster) -> PrecedentCluster:
        return dataclasses.replace(
            cluster,
            precedent_ids=list(cluster.precedent_ids),
            centroid_vector=dict(cluster.centroid_vector),
            dominant_dimensions=list(cluster.dominant_dimensions),
        )

    @staticmethod
    def _copy_candidate(candidate: RuleCandidate) -> RuleCandidate:
        return dataclasses.replace(
            candidate,
            keywords=list(candidate.keywords),
            source_precedent_ids=list(candidate.source_precedent_ids),
            dominant_dimensions=list(candidate.dominant_dimensions),
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    dot = sum(a.get(d, 0.0) * b.get(d, 0.0) for d in _DIMENSIONS)
    na = math.sqrt(sum(a.get(d, 0.0) ** 2 for d in _DIMENSIONS))
    nb = math.sqrt(sum(b.get(d, 0.0) ** 2 for d in _DIMENSIONS))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _infer_severity(dominant_dimensions: list[str]) -> str:
    if "safety" in dominant_dimensions or "security" in dominant_dimensions:
        return "high"
    if "privacy" in dominant_dimensions or "fairness" in dominant_dimensions:
        return "high"
    return "medium"


def _generate_rule_text(cluster: PrecedentCluster) -> str:
    """Generate a human-readable rule from cluster metadata."""
    dims = cluster.dominant_dimensions
    if not dims:
        return (
            f"Governance decisions of type '{cluster.escalation_type}' "
            f"with elevated impact scores require additional review."
        )
    dims_str = " and ".join(dims[:2])
    threshold = 0.5
    centroid_vals = [cluster.centroid_vector.get(d, 0.0) for d in dims[:2]]
    if centroid_vals:
        threshold = round(sum(centroid_vals) / len(centroid_vals), 1)

    return (
        f"Decisions with {dims_str} impact scores above {threshold:.1f} "
        f"({cluster.escalation_type.replace('_', ' ')}) "
        f"require explicit justification referencing the affected governance dimensions."
    )


def _extract_keywords(cluster: PrecedentCluster) -> list[str]:
    """Extract keywords from dominant dimensions and escalation type."""
    kw: list[str] = list(cluster.dominant_dimensions)
    etype = cluster.escalation_type.replace("_", " ")
    if etype not in kw:
        kw.append(etype)
    # Add dimension-specific keywords
    kw_map = {
        "safety": ["harm", "danger", "risk"],
        "security": ["access", "breach", "unauthorized"],
        "privacy": ["personal data", "PII", "consent"],
        "fairness": ["discriminat", "bias", "equit"],
        "transparency": ["explainab", "disclose", "audit"],
        "reliability": ["uptime", "integrity", "fault"],
        "efficiency": ["resource", "latency", "cost"],
    }
    for d in cluster.dominant_dimensions[:2]:
        kw.extend(kw_map.get(d, [])[:2])
    return list(dict.fromkeys(kw))  # deduplicate, preserve order


def _append_rule_to_yaml(constitution_yaml: str, rule: Mapping[str, Any]) -> str:
    """Parse the constitution, append ``rule`` to its ``rules`` list, re-serialize.

    The base must be a YAML mapping whose ``rules`` key is absent, null, or a
    list; the rule id must be new. The output is canonical ``safe_dump`` YAML
    and must round-trip to exactly the intended document.
    """
    if type(constitution_yaml) is not str:
        raise TypeError("constitution_yaml must be a string")
    try:
        data = yaml.safe_load(constitution_yaml)
    except yaml.YAMLError as exc:
        raise ValueError("constitution_yaml is not valid YAML") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("constitution_yaml must be a YAML mapping")
    rules = data.get("rules")
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        raise ValueError("constitution 'rules' must be a list")
    entry = dict(rule)
    existing_ids = {item.get("id") for item in rules if isinstance(item, dict)}
    if entry.get("id") in existing_ids:
        raise ValueError(f"rule id {entry.get('id')!r} already exists in the constitution")
    data["rules"] = [*rules, entry]
    new_yaml = yaml.safe_dump(data, sort_keys=True, allow_unicode=True)
    if yaml.safe_load(new_yaml) != data:
        raise ValueError("extended constitution does not round-trip through YAML")
    return new_yaml
