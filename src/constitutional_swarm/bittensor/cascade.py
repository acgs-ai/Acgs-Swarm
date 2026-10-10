"""Precedent Cascade — Four-Stage Evolutionary Filter for Constitution Amendment.

New precedents are candidate mutations to the effective constitution.
A four-stage cascade filters them from cheapest (local DNA check) to most
expensive (multi-miner consensus + compatibility verification).

Stage 1: DNA Pre-check       → local DNA check, catches obvious violations
Stage 2: Mesh Validation     → 3-peer quorum, quality filter
Stage 3: Multi-Miner Consensus → N-miner stability check
Stage 4: Constitutional Compatibility → contradiction detection

Evolutionary pattern: Cascade evaluation with ceiling detection.
Only precedents surviving all four stages amend the living constitution.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from acgs_lite import Constitution

from constitutional_swarm.bittensor.synapses import judgment_content_hash, ordered_vote_hashes
from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.mesh import (
    ConstitutionalMesh,
    InsufficientPeersError,
    InvalidVoteSignatureError,
    MeshHaltedError,
    MeshResult,
    MeshSnapshotStaleError,
    SettlementPersistenceError,
    UnauthorizedVoterError,
)
from constitutional_swarm.mesh.vote_envelope import (
    FrozenVoteSignerRegistry,
    VoteSignerRegistry,
    compute_vote_envelope_root,
    normalize_voter_id,
    verify_assignment_vote_envelopes,
)


class CascadeStage(Enum):
    """The four progressive evaluation stages."""

    DNA_PRECHECK = "dna_precheck"
    MESH_VALIDATION = "mesh_validation"
    MULTI_MINER_CONSENSUS = "consensus"
    CONSTITUTIONAL_COMPATIBILITY = "compat"


STAGE_ORDER = [
    CascadeStage.DNA_PRECHECK,
    CascadeStage.MESH_VALIDATION,
    CascadeStage.MULTI_MINER_CONSENSUS,
    CascadeStage.CONSTITUTIONAL_COMPATIBILITY,
]


@dataclass(frozen=True, slots=True)
class CascadeResult:
    """Result of a single cascade stage."""

    stage: CascadeStage
    passed: bool
    latency_ns: int
    detail: str
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class PrecedentCandidate:
    """A proposed precedent moving through the cascade."""

    candidate_id: str
    judgment_text: str
    reasoning_text: str
    domain: str
    miner_uid: str
    constitutional_hash: str
    stage_results: tuple[CascadeResult, ...]
    current_stage: CascadeStage
    alive: bool

    @property
    def stages_passed(self) -> int:
        return sum(1 for r in self.stage_results if r.passed)

    def with_result(self, result: CascadeResult) -> PrecedentCandidate:
        """Return new candidate with the result appended."""
        next_idx = STAGE_ORDER.index(result.stage) + 1
        next_stage = STAGE_ORDER[next_idx] if next_idx < len(STAGE_ORDER) else result.stage
        return PrecedentCandidate(
            candidate_id=self.candidate_id,
            judgment_text=self.judgment_text,
            reasoning_text=self.reasoning_text,
            domain=self.domain,
            miner_uid=self.miner_uid,
            constitutional_hash=self.constitutional_hash,
            stage_results=(*self.stage_results, result),
            current_stage=next_stage,
            alive=self.alive and result.passed,
        )


@dataclass(frozen=True, slots=True)
class ConstitutionDelta:
    """A successfully cascaded precedent, ready for constitution integration."""

    candidate_id: str
    rule_text: str
    domain: str
    source_miner: str
    consensus_strength: float
    compatibility_verified: bool
    constitutional_hash: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class CascadeMetrics:
    """Funnel conversion tracking."""

    submitted: int = 0
    passed_dna: int = 0
    passed_mesh: int = 0
    passed_consensus: int = 0
    passed_compatibility: int = 0
    _improvement_window: list[float] = field(default_factory=list)
    window_size: int = 50

    def record_improvement(self, delta: float) -> None:
        self._improvement_window.append(delta)
        if len(self._improvement_window) > self.window_size:
            self._improvement_window = self._improvement_window[-self.window_size :]

    @property
    def ceiling_detected(self) -> bool:
        """No improvement above epsilon for the full window."""
        if len(self._improvement_window) < self.window_size:
            return False
        epsilon = 0.001
        return all(d < epsilon for d in self._improvement_window)

    def funnel_report(self) -> dict[str, Any]:
        return {
            "submitted": self.submitted,
            "passed_dna": self.passed_dna,
            "passed_mesh": self.passed_mesh,
            "passed_consensus": self.passed_consensus,
            "passed_compatibility": self.passed_compatibility,
            "conversion_rate": (self.passed_compatibility / max(self.submitted, 1)),
            "ceiling_detected": self.ceiling_detected,
        }


class PrecedentCascade:
    """Four-stage evolutionary cascade for constitution amendment.

    Usage:
        cascade = PrecedentCascade(constitution, mesh)
        candidate = cascade.run_full_cascade(
            judgment="Privacy takes precedence",
            reasoning="Article 8 ECHR applies",
            domain="privacy",
            miner_uid="miner-01",
        )
        if candidate.alive:
            delta = cascade.accept(candidate)
    """

    def __init__(
        self,
        constitution: Constitution,
        mesh: ConstitutionalMesh | None = None,
        *,
        consensus_threshold: float = 0.8,
        min_consensus_miners: int = 3,
        seed: int | None = None,
        vote_registry: VoteSignerRegistry | FrozenVoteSignerRegistry | None = None,
    ) -> None:
        if (
            isinstance(consensus_threshold, bool)
            or not isinstance(consensus_threshold, (int, float))
            or not 0.0 < consensus_threshold <= 1.0
        ):
            raise ValueError("consensus_threshold must be in the interval (0, 1]")
        if (
            isinstance(min_consensus_miners, bool)
            or not isinstance(min_consensus_miners, int)
            or min_consensus_miners < 1
        ):
            raise ValueError("min_consensus_miners must be a positive integer")
        self._constitution = constitution
        self._dna = AgentDNA(constitution=constitution, agent_id="cascade-validator", strict=False)
        self._mesh = mesh
        self._consensus_threshold = consensus_threshold
        self._min_consensus_miners = min_consensus_miners
        self._metrics = CascadeMetrics()
        self._accepted: list[ConstitutionDelta] = []
        self._issued: dict[str, PrecedentCandidate] = {}
        self._mesh_results: dict[str, MeshResult] = {}
        self._seed = seed
        self._vote_registry = (
            vote_registry.frozen_copy() if vote_registry is not None else None
        )

    @property
    def metrics(self) -> CascadeMetrics:
        return self._metrics

    @property
    def accepted_deltas(self) -> list[ConstitutionDelta]:
        return list(self._accepted)

    def submit(
        self,
        judgment: str,
        reasoning: str,
        domain: str,
        miner_uid: str,
    ) -> PrecedentCandidate:
        """Create a new candidate at Stage 1."""
        self._metrics.submitted += 1
        candidate = PrecedentCandidate(
            candidate_id=uuid.uuid4().hex[:12],
            judgment_text=judgment,
            reasoning_text=reasoning,
            domain=domain,
            miner_uid=miner_uid,
            constitutional_hash=self._constitution.hash,
            stage_results=(),
            current_stage=CascadeStage.DNA_PRECHECK,
            alive=True,
        )
        self._issued[candidate.candidate_id] = candidate
        return candidate

    def advance(self, candidate: PrecedentCandidate) -> PrecedentCandidate:
        """Advance a candidate through its current stage."""
        if self._issued.get(candidate.candidate_id) is not candidate:
            raise ValueError("candidate is not the current instance issued by this cascade")
        if not candidate.alive:
            return candidate

        stage = candidate.current_stage
        if stage == CascadeStage.DNA_PRECHECK:
            result = self._stage_dna(candidate)
        elif stage == CascadeStage.MESH_VALIDATION:
            result = self._stage_mesh(candidate)
        elif stage == CascadeStage.MULTI_MINER_CONSENSUS:
            result = self._stage_consensus(candidate)
        elif stage == CascadeStage.CONSTITUTIONAL_COMPATIBILITY:
            result = self._stage_compatibility(candidate)
        else:
            return candidate

        return self._record_stage_result(candidate, result)

    def _record_stage_result(
        self,
        candidate: PrecedentCandidate,
        result: CascadeResult,
    ) -> PrecedentCandidate:
        """Apply one stage result while preserving issuance and metric invariants."""
        if self._issued.get(candidate.candidate_id) is not candidate:
            raise ValueError("candidate is not the current instance issued by this cascade")
        if result.stage is not candidate.current_stage:
            raise ValueError("cascade result does not match the candidate's current stage")
        updated = candidate.with_result(result)
        if updated.alive:
            self._issued[candidate.candidate_id] = updated
        else:
            self._issued.pop(candidate.candidate_id, None)
            self._mesh_results.pop(candidate.candidate_id, None)

        # Track funnel
        if result.passed:
            if result.stage == CascadeStage.DNA_PRECHECK:
                self._metrics.passed_dna += 1
            elif result.stage == CascadeStage.MESH_VALIDATION:
                self._metrics.passed_mesh += 1
            elif result.stage == CascadeStage.MULTI_MINER_CONSENSUS:
                self._metrics.passed_consensus += 1
            elif result.stage == CascadeStage.CONSTITUTIONAL_COMPATIBILITY:
                self._metrics.passed_compatibility += 1
        return updated

    def run_full_cascade(
        self,
        judgment: str,
        reasoning: str,
        domain: str,
        miner_uid: str,
    ) -> PrecedentCandidate:
        """Run all four stages, short-circuiting on rejection."""
        candidate = self.submit(judgment, reasoning, domain, miner_uid)
        for _ in STAGE_ORDER:
            candidate = self.advance(candidate)
            if not candidate.alive:
                break
        return candidate

    async def run_full_cascade_remote(
        self,
        judgment: str,
        reasoning: str,
        domain: str,
        miner_uid: str,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: Any | None = None,
        timeout: float = 5.0,
    ) -> PrecedentCandidate:
        """Run the cascade with independent remote voters at mesh validation."""
        candidate = self.submit(judgment, reasoning, domain, miner_uid)
        candidate = self.advance(candidate)
        if not candidate.alive:
            return candidate

        mesh_result = await self._stage_mesh_remote(
            candidate,
            peer_routes=peer_routes,
            client=client,
            timeout=timeout,
        )
        candidate = self._record_stage_result(candidate, mesh_result)
        while candidate.alive and len(candidate.stage_results) < len(STAGE_ORDER):
            candidate = self.advance(candidate)
        return candidate

    def accept(self, candidate: PrecedentCandidate) -> ConstitutionDelta | None:
        """Accept a fully-cascaded candidate as a constitution delta.

        Returns None if the candidate didn't pass all stages.
        """
        current = self._issued.get(candidate.candidate_id)
        stage_sequence = tuple(result.stage for result in candidate.stage_results)
        mesh_result = self._mesh_results.get(candidate.candidate_id)
        if (
            current is not candidate
            or not candidate.alive
            or candidate.current_stage is not STAGE_ORDER[-1]
            or stage_sequence != tuple(STAGE_ORDER)
            or not all(result.passed for result in candidate.stage_results)
            or candidate.constitutional_hash != self._constitution.hash
            or mesh_result is None
            or not self._valid_mesh_result(candidate, mesh_result)
        ):
            return None

        total_votes = mesh_result.votes_for + mesh_result.votes_against
        consensus_strength = mesh_result.votes_for / total_votes

        delta = ConstitutionDelta(
            candidate_id=candidate.candidate_id,
            rule_text=candidate.judgment_text,
            domain=candidate.domain,
            source_miner=candidate.miner_uid,
            consensus_strength=consensus_strength,
            compatibility_verified=True,
            constitutional_hash=candidate.constitutional_hash,
        )
        self._accepted.append(delta)
        self._metrics.record_improvement(1.0)
        self._issued.pop(candidate.candidate_id, None)
        self._mesh_results.pop(candidate.candidate_id, None)
        return delta

    def ceiling_detected(self) -> bool:
        """True when the constitution has converged."""
        return self._metrics.ceiling_detected

    # -- Stage Implementations -----------------------------------------------

    def _stage_dna(self, candidate: PrecedentCandidate) -> CascadeResult:
        """Stage 1: DNA pre-check (local, no published nanosecond target)."""
        start = time.perf_counter_ns()
        result = self._dna.validate(candidate.judgment_text)
        elapsed = time.perf_counter_ns() - start
        return CascadeResult(
            stage=CascadeStage.DNA_PRECHECK,
            passed=result.valid,
            latency_ns=elapsed,
            detail="pass" if result.valid else "; ".join(result.violations),
        )

    def _stage_mesh(self, candidate: PrecedentCandidate) -> CascadeResult:
        """Stage 2: Mesh validation (3-peer quorum)."""
        start = time.perf_counter_ns()
        if self._mesh is None:
            elapsed = time.perf_counter_ns() - start
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=False,
                latency_ns=elapsed,
                detail="no mesh configured",
            )

        try:
            result = self._mesh.full_validation(
                producer_id=candidate.miner_uid,
                content=candidate.judgment_text,
                artifact_id=candidate.candidate_id,
            )
            self._mesh_results[candidate.candidate_id] = result
            elapsed = time.perf_counter_ns() - start
            passed = self._valid_mesh_result(candidate, result)
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=passed,
                latency_ns=elapsed,
                detail=(
                    f"votes: {result.votes_for}/{result.votes_for + result.votes_against}"
                    if passed
                    else "invalid or unbound mesh settlement"
                ),
            )
        except (
            InsufficientPeersError,
            InvalidVoteSignatureError,
            KeyError,
            MeshHaltedError,
            MeshSnapshotStaleError,
            SettlementPersistenceError,
            UnauthorizedVoterError,
            ValueError,
        ) as exc:
            elapsed = time.perf_counter_ns() - start
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=False,
                latency_ns=elapsed,
                detail=f"mesh error: {type(exc).__name__}",
            )

    async def _stage_mesh_remote(
        self,
        candidate: PrecedentCandidate,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: Any | None,
        timeout: float,
    ) -> CascadeResult:
        """Stage 2 using public-key-only peers through the remote vote path."""
        start = time.perf_counter_ns()
        if self._mesh is None:
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=False,
                latency_ns=time.perf_counter_ns() - start,
                detail="no mesh configured",
            )
        try:
            assignment = self._mesh.request_validation(
                producer_id=candidate.miner_uid,
                content=candidate.judgment_text,
                artifact_id=candidate.candidate_id,
                task_id=candidate.candidate_id,
            )
            result = await self._mesh.collect_remote_votes(
                assignment.assignment_id,
                peer_routes=peer_routes,
                client=client,
                timeout=timeout,
            )
            self._mesh_results[candidate.candidate_id] = result
            passed = self._valid_mesh_result(candidate, result)
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=passed,
                latency_ns=time.perf_counter_ns() - start,
                detail=(
                    f"votes: {result.votes_for}/{result.votes_for + result.votes_against}"
                    if passed
                    else "invalid or unbound mesh settlement"
                ),
            )
        except (
            ImportError,
            InsufficientPeersError,
            InvalidVoteSignatureError,
            KeyError,
            MeshHaltedError,
            MeshSnapshotStaleError,
            SettlementPersistenceError,
            TimeoutError,
            UnauthorizedVoterError,
            ValueError,
        ) as exc:
            return CascadeResult(
                stage=CascadeStage.MESH_VALIDATION,
                passed=False,
                latency_ns=time.perf_counter_ns() - start,
                detail=f"mesh error: {type(exc).__name__}",
            )

    def _stage_consensus(self, candidate: PrecedentCandidate) -> CascadeResult:
        """Stage 3: enforce miner count and approval ratio on the mesh result."""
        start = time.perf_counter_ns()
        result = self._mesh_results.get(candidate.candidate_id)
        elapsed = time.perf_counter_ns() - start
        if result is None or not self._valid_mesh_result(candidate, result):
            return CascadeResult(
                stage=CascadeStage.MULTI_MINER_CONSENSUS,
                passed=False,
                latency_ns=elapsed,
                detail="no valid mesh settlement",
            )

        total_votes = result.votes_for + result.votes_against
        approval_ratio = result.votes_for / total_votes if total_votes else 0.0
        passed = (
            total_votes >= self._min_consensus_miners
            and approval_ratio >= self._consensus_threshold
        )
        return CascadeResult(
            stage=CascadeStage.MULTI_MINER_CONSENSUS,
            passed=passed,
            latency_ns=elapsed,
            detail=(
                f"votes={total_votes}/{self._min_consensus_miners}, "
                f"approval={approval_ratio:.3f}/{self._consensus_threshold:.3f}"
            ),
        )

    def _valid_mesh_result(
        self,
        candidate: PrecedentCandidate,
        result: MeshResult,
    ) -> bool:
        """Check settled proof coherence for content and constitution.

        Candidate association is cascade-local state; these checks do not
        establish signed task or candidate provenance.
        """
        proof = result.proof
        if (
            proof is None
            or proof.protocol_version != 2
            or self._vote_registry is None
            or result.signed_assignment is None
        ):
            return False
        if (
            proof.task_id != candidate.candidate_id
            or proof.artifact_id != candidate.candidate_id
            or proof.producer_id != normalize_voter_id(candidate.miner_uid)
        ):
            return False
        expected_content_hash = judgment_content_hash(candidate.judgment_text)
        try:
            envelopes = verify_assignment_vote_envelopes(
                result.signed_assignment,
                result.vote_envelopes,
                self._vote_registry,
                task_id=proof.task_id,
                assignment_id=proof.assignment_id,
                producer_id=proof.producer_id,
                artifact_id=proof.artifact_id,
                content_hash=expected_content_hash,
                constitutional_hash=self._constitution.hash,
                require_independent=True,
            )
        except (IndexError, TypeError, ValueError):
            return False
        electorate_size = len(result.signed_assignment.assigned_peers)
        quorum = result.signed_assignment.quorum
        if (
            electorate_size < self._min_consensus_miners
            or quorum <= electorate_size // 2
            or quorum / electorate_size < self._consensus_threshold
        ):
            return False
        votes_for = sum(envelope.approved for envelope in envelopes)
        votes_against = len(envelopes) - votes_for
        accepted = votes_for >= quorum and votes_for > votes_against
        expected_root = compute_vote_envelope_root(
            task_id=proof.task_id,
            assignment_id=proof.assignment_id,
            producer_id=proof.producer_id,
            artifact_id=proof.artifact_id,
            content_hash=expected_content_hash,
            constitutional_hash=self._constitution.hash,
            accepted=accepted,
            envelopes=envelopes,
        )
        expected_hashes = ordered_vote_hashes(envelopes)
        return (
            accepted
            and result.accepted == accepted
            and result.votes_for == votes_for
            and result.votes_against == votes_against
            and result.pending_votes == 0
            and result.quorum_met
            and result.settled
            and proof.verify()
            and proof.assignment_id == result.assignment_id
            and proof.content_hash == expected_content_hash
            and proof.constitutional_hash == self._constitution.hash
            and result.constitutional_hash == self._constitution.hash
            and proof.accepted == accepted
            and proof.root_hash == expected_root
            and proof.vote_hashes == expected_hashes
        )

    def _stage_compatibility(self, candidate: PrecedentCandidate) -> CascadeResult:
        """Stage 4: Constitutional compatibility.

        Verify the precedent doesn't contradict existing rules.
        Cross-validates by checking if existing rules would be
        violated by the new precedent's text.
        """
        start = time.perf_counter_ns()
        # The judgment must pass DNA validation (already checked in Stage 1,
        # but here we also check the reasoning text)
        reasoning_result = self._dna.validate(candidate.reasoning_text)
        elapsed = time.perf_counter_ns() - start

        return CascadeResult(
            stage=CascadeStage.CONSTITUTIONAL_COMPATIBILITY,
            passed=reasoning_result.valid,
            latency_ns=elapsed,
            detail="compatible"
            if reasoning_result.valid
            else "; ".join(reasoning_result.violations),
        )
