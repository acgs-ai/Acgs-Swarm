"""Constitutional Swarm Subnet Owner — Bittensor SN Owner runtime.

The SN Owner:
  1. Receives escalated governance cases from the ACGS-2 AdaptiveRouter
  2. Packages them as DeliberationSynapses via DAGCompiler
  3. Broadcasts to miners
  4. Collects ValidationSynapses from validators
  5. Records precedent from accepted judgments
  6. Tracks escalation metrics (empirical failure mode distribution)

Bittensor SDK is NOT required — this module uses constitutional_swarm
primitives only.

Accepted results are admitted only after independently verifying authorized
voter signatures, task and artifact bindings, judgment content, canonical
proof root, and tallies recomputed from the signed vote envelopes.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from acgs_lite import Constitution

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.bittensor.protocol import (
    EscalationType,
    SubnetMetrics,
)
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore
from constitutional_swarm.bittensor.synapses import (
    DeliberationSynapse,
    JudgmentSynapse,
    ValidationSynapse,
)
from constitutional_swarm.compiler import DAGCompiler, GoalSpec
from constitutional_swarm.mesh.vote_envelope import (
    FrozenVoteSignerRegistry,
    VoteSignerRegistry,
    normalize_voter_id,
    vote_envelope_hash,
)
from constitutional_swarm.swarm import TaskDAG


@dataclass(frozen=True, slots=True)
class EscalatedCase:
    """An escalated governance case ready for miner deliberation."""

    case_id: str
    synapse: DeliberationSynapse
    dag: TaskDAG
    escalation_type: EscalationType


class SubnetOwner:
    """Bittensor SN Owner runtime for constitutional governance subnet.

    Accepted validation proofs are checked against an independently provisioned
    voter trust registry and cryptographically bound to the task, artifact,
    producer, judgment content, and constitution before precedent admission.

    Usage:
        owner = SubnetOwner(constitution_path="governance.yaml")

        # Package an escalated case
        case = owner.package_case(
            description="Privacy vs. transparency conflict in financial reporting",
            domain="finance",
            escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
            impact_score=0.85,
        )

        # After receiving validation result
        owner.record_result(case, judgment_synapse, validation_synapse)

        # Get empirical escalation distribution
        print(owner.metrics.escalation_distribution())
    """

    def __init__(
        self,
        constitution_path: str,
        *,
        dag_compiler: DAGCompiler | None = None,
        precedent_store: PrecedentStore | None = None,
        vote_registry: VoteSignerRegistry | FrozenVoteSignerRegistry | None = None,
    ) -> None:
        self._constitution = Constitution.from_yaml(constitution_path)
        self._compiler = dag_compiler or DAGCompiler()
        self._store = ArtifactStore()
        self._metrics = SubnetMetrics(constitution_hash=self._constitution.hash)
        if (
            precedent_store is not None
            and precedent_store.constitutional_hash != self._constitution.hash
        ):
            raise ValueError("PrecedentStore constitutional hash does not match owner constitution")
        if (
            precedent_store is not None
            and vote_registry is not None
            and (
                precedent_store.vote_registry is None
                or precedent_store.vote_registry.trust_grants(role="voter")
                != vote_registry.trust_grants(role="voter")
                or precedent_store.vote_registry.trust_grants(role="assigner")
                != vote_registry.trust_grants(role="assigner")
            )
        ):
            raise ValueError(
                "PrecedentStore and owner voter/assigner trust grants must match"
            )
        self._precedent_store = precedent_store or PrecedentStore(
            self._constitution.hash,
            vote_registry=vote_registry,
        )
        self._active_cases: dict[str, EscalatedCase] = {}

    @property
    def constitution_hash(self) -> str:
        return self._constitution.hash

    @property
    def metrics(self) -> SubnetMetrics:
        return self._metrics

    @property
    def precedent_store(self) -> PrecedentStore:
        return self._precedent_store

    @property
    def precedents(self) -> list[PrecedentRecord]:
        return list(self._precedent_store.active_records())

    @property
    def active_cases(self) -> dict[str, EscalatedCase]:
        return dict(self._active_cases)

    def package_case(
        self,
        description: str,
        domain: str,
        *,
        escalation_type: EscalationType = EscalationType.UNKNOWN,
        impact_score: float = 0.0,
        impact_vector: dict[str, float] | None = None,
        required_capabilities: tuple[str, ...] = (),
        deadline_seconds: int = 3600,
        steps: list[dict[str, Any]] | None = None,
    ) -> EscalatedCase:
        """Package an escalated governance case for miner deliberation.

        Compiles the case into a TaskDAG and creates a DeliberationSynapse.
        """
        case_id = uuid.uuid4().hex[:12]
        task_id = uuid.uuid4().hex[:8]

        # Build GoalSpec
        if steps is None:
            steps = [
                {
                    "title": "Analyze governance conflict",
                    "domain": domain,
                    "description": description,
                    "required_capabilities": list(required_capabilities),
                },
            ]

        spec = GoalSpec(
            goal=description,
            domains=[domain],
            steps=steps,
        )
        dag = self._compiler.compile(spec)

        # Create synapse
        synapse = DeliberationSynapse(
            task_id=task_id,
            task_dag_json=_serialize_dag(dag),
            constitution_hash=self._constitution.hash,
            domain=domain,
            required_capabilities=required_capabilities,
            deadline_seconds=deadline_seconds,
            escalation_type=escalation_type.value,
            impact_score=impact_score,
            impact_vector=impact_vector or {},
            context=description,
        )

        # Track
        case = EscalatedCase(
            case_id=case_id,
            synapse=synapse,
            dag=dag,
            escalation_type=escalation_type,
        )
        self._active_cases[case_id] = case
        self._metrics.record_escalation(escalation_type)

        return case

    def record_result(
        self,
        case: EscalatedCase,
        judgment: JudgmentSynapse,
        validation: ValidationSynapse,
    ) -> PrecedentRecord | None:
        """Record the result of a deliberation.

        If accepted, creates a PrecedentRecord. Removes the case from
        active tracking.

        Returns the PrecedentRecord if the judgment was accepted,
        None otherwise.
        """
        tracked = self._active_cases.get(case.case_id)
        if tracked is None or tracked != case:
            raise ValueError(f"Case {case.case_id!r} is not an active owner-issued case")
        task_id = tracked.synapse.task_id
        if judgment.task_id != task_id or validation.task_id != task_id:
            raise ValueError("Judgment and validation task IDs must match the active case task")
        expected_hash = self._constitution.hash
        if (
            tracked.synapse.constitution_hash != expected_hash
            or judgment.constitutional_hash != expected_hash
            or validation.constitutional_hash != expected_hash
        ):
            raise ValueError("Case, judgment, and validation constitutional hash must match")
        if not validation.quorum_met:
            raise ValueError("Completed validation evidence must have validator quorum")
        self._precedent_store.verify_validation_evidence(
            task_id=task_id,
            producer_id=judgment.miner_uid,
            judgment=judgment.judgment,
            votes_for=validation.votes_for,
            votes_against=validation.votes_against,
            accepted=validation.accepted,
            proof_root_hash=validation.proof_root_hash,
            assignment_id=validation.assignment_id,
            artifact_id=judgment.artifact_hash,
            content_hash=validation.proof_content_hash,
            constitutional_hash=expected_hash,
            vote_envelopes=validation.vote_envelopes,
            signed_assignment=validation.signed_assignment,
        )
        self._verify_validation_proof(judgment, validation)
        if validation.accepted:
            precedent = PrecedentRecord.create(
                case_id=case.case_id,
                task_id=task_id,
                miner_uid=judgment.miner_uid,
                judgment=judgment.judgment,
                reasoning=judgment.reasoning,
                votes_for=validation.votes_for,
                votes_against=validation.votes_against,
                proof_root_hash=validation.proof_root_hash,
                escalation_type=case.escalation_type,
                impact_vector=dict(case.synapse.impact_vector),
                constitutional_hash=expected_hash,
                ambiguous_dimensions=tuple(sorted(case.synapse.impact_vector)),
                assignment_id=validation.assignment_id,
                artifact_id=judgment.artifact_hash,
                content_hash=validation.proof_content_hash,
                vote_envelopes=validation.vote_envelopes,
                signed_assignment=validation.signed_assignment,
            )
            precedent = self._precedent_store.admit(precedent)

        self._metrics.total_judgments += 1
        self._metrics.total_validations += 1
        if validation.accepted:
            self._metrics.precedents_created += 1

            # Store the judgment as an artifact
            artifact = Artifact(
                artifact_id=uuid.uuid4().hex[:12],
                task_id=judgment.task_id,
                agent_id=judgment.miner_uid,
                content_type="validated_precedent",
                content=judgment.judgment,
                domain=case.synapse.domain,
                constitutional_hash=judgment.constitutional_hash,
                metadata={
                    "reasoning": judgment.reasoning,
                    "escalation_type": case.escalation_type.value,
                    "votes_for": validation.votes_for,
                    "votes_against": validation.votes_against,
                    "proof_root_hash": validation.proof_root_hash,
                },
            )
            self._store.publish(artifact)

        # Remove from active cases
        self._active_cases.pop(case.case_id, None)

        if validation.accepted:
            return precedent
        return None

    def _verify_validation_proof(
        self,
        judgment: JudgmentSynapse,
        validation: ValidationSynapse,
    ) -> None:
        vote_hashes = validation.proof_vote_hashes
        if validation.signed_assignment is None:
            raise ValueError("validation proof signed assignment is required")
        if not validation.assignment_id:
            raise ValueError("validation proof assignment ID is required")
        if not validation.proof_root_hash or not validation.proof_content_hash:
            raise ValueError("validation proof root and content hashes are required")
        if any(not vote_hash for vote_hash in vote_hashes):
            raise ValueError("validation proof vote hashes must be non-empty")
        if len(set(vote_hashes)) != len(vote_hashes):
            raise ValueError("validation proof vote hashes must be distinct")
        if len(vote_hashes) != len(validation.vote_envelopes):
            raise ValueError("validation proof vote count must match the validation tally")

        expected_content_hash = hashlib.sha256(judgment.judgment.encode("utf-8")).hexdigest()[:32]
        if validation.proof_content_hash != expected_content_hash:
            raise ValueError("validation proof content hash does not bind the judgment")
        expected_vote_hashes = tuple(
            vote_envelope_hash(envelope)
            for envelope in sorted(
                validation.vote_envelopes,
                key=lambda envelope: (normalize_voter_id(envelope.voter_id), envelope.key_id),
            )
        )
        if vote_hashes != expected_vote_hashes:
            raise ValueError("validation proof vote hashes do not match signed vote envelopes")

    def summary(self) -> dict[str, Any]:
        """SN Owner operational summary."""
        return {
            "constitution_hash": self._constitution.hash,
            "active_cases": len(self._active_cases),
            "total_escalations": self._metrics.total_escalations,
            "total_judgments": self._metrics.total_judgments,
            "total_validations": self._metrics.total_validations,
            "precedents_created": self._metrics.precedents_created,
            "escalation_distribution": self._metrics.escalation_distribution(),
            "artifacts_stored": self._store.count,
        }


def _serialize_dag(dag: TaskDAG) -> str:
    """Serialize a TaskDAG to JSON string for synapse transport."""
    import json

    nodes = {}
    for nid, node in dag.nodes.items():
        nodes[nid] = {
            "node_id": node.node_id,
            "title": node.title,
            "description": node.description,
            "domain": node.domain,
            "required_capabilities": list(node.required_capabilities),
            "depends_on": list(node.depends_on),
            "priority": node.priority,
            "status": node.status.value,
        }
    return json.dumps({"dag_id": dag.dag_id, "goal": dag.goal, "nodes": nodes})
