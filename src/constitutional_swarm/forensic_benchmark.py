"""Protocol checks and scoring helpers for the ACGS v0.1 forensic benchmark.

The receipt verifier proves artifact integrity. This module defines the separate
study contract needed to test whether reviewers can reconstruct adversarial
multi-agent incidents from those artifacts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import re
import secrets
import unicodedata
import warnings
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from csv import DictReader, DictWriter
from decimal import Decimal, localcontext
from io import StringIO
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FORENSIC_QUESTIONNAIRE: tuple[str, ...] = (
    "who_acted",
    "authority_existed",
    "rule_applied",
    "evidence_used",
    "who_approved_or_denied",
    "what_failed",
    "outcome_defensible",
)

BASELINES: tuple[str, ...] = (
    "ungoverned_raw_logs",
    "centralized_structured_logs",
    "acgs_receipts_and_audit_artifacts",
)

BLINDED_CONDITION_LABELS: tuple[str, ...] = ("condition_a", "condition_b", "condition_c")

FORENSIC_GENERATOR_VERSION = "acgs-forensic-pack-v5"
DEFAULT_REVIEWER_IDS: tuple[str, ...] = tuple(f"reviewer-{index}" for index in range(1, 7))

ADVERSARIAL_TECHNIQUES: tuple[str, ...] = (
    "collusion",
    "memory_poisoning",
    "rule_gaming",
    "fragmented_actions",
    "misleading_traces",
)

IMMUTABLE_REFERENCE_PREFIXES: tuple[str, ...] = (
    "https://",
    "ipfs://",
    "ar://",
    "sha256:",
)

PLACEHOLDER_REFERENCE_MARKERS: tuple[str, ...] = (
    "example.",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "records/<record>",
    "records/123456",
)

EvidenceStrength = Literal["unavailable", "observed", "corroborated"]
EvidenceClass = Literal["unknown", "diff", "policy_evaluation", "runtime_trace"]
BenchmarkCondition = Literal[
    "ungoverned_raw_logs",
    "centralized_structured_logs",
    "acgs_receipts_and_audit_artifacts",
]


class ProtocolValidationIssue(BaseModel):
    """One benchmark protocol validation finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str


class ForensicBenchmarkProtocol(BaseModel):
    """Reproducible blind-review benchmark contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_count: int = Field(ge=1)
    questionnaire: tuple[str, ...] = FORENSIC_QUESTIONNAIRE
    baselines: tuple[str, ...] = BASELINES
    adversarial_techniques: tuple[str, ...] = ADVERSARIAL_TECHNIQUES
    blind_review: bool = True
    hidden_ground_truth_separated: bool = True
    external_replication_instructions: str = Field(min_length=1)
    artifact_sets: dict[str, str] = Field(default_factory=dict)
    scoring_metrics: tuple[str, ...] = (
        "answer_accuracy",
        "time_to_answer",
        "confidence_calibration",
        "inter_reviewer_agreement",
        "performance_delta_vs_strongest_baseline",
    )

    @field_validator("artifact_sets")
    @classmethod
    def require_artifact_set_labels(cls, value: dict[str, str]) -> dict[str, str]:
        for name in BASELINES:
            if name not in value:
                msg = f"missing artifact set for {name}"
                raise ValueError(msg)
        return value


class ProtocolValidationResult(BaseModel):
    """Machine-readable protocol validation result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    issues: list[ProtocolValidationIssue] = Field(default_factory=list)


class ReviewerAnswer(BaseModel):
    """One blind reviewer answer for one incident/artifact condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(min_length=1)
    artifact_condition: BenchmarkCondition
    reviewer_id: str = Field(min_length=1)
    question_id: str = Field(min_length=1)
    answer: str
    ground_truth: str
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    elapsed_seconds: float = Field(ge=0.0, allow_inf_nan=False)

    @model_validator(mode="after")
    def require_known_question(self) -> ReviewerAnswer:
        if self.question_id not in FORENSIC_QUESTIONNAIRE:
            msg = f"unknown forensic question: {self.question_id}"
            raise ValueError(msg)
        return self


class ConditionScore(BaseModel):
    """Aggregated reviewer score for one artifact condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer_accuracy: float = Field(ge=0.0, le=1.0)
    mean_time_seconds: float = Field(ge=0.0)
    confidence_calibration_error: float = Field(ge=0.0, le=1.0)
    inter_reviewer_agreement: float = Field(ge=0.0, le=1.0)
    answer_count: int = Field(ge=1)


class BenchmarkScorecard(BaseModel):
    """Scorecard comparing ACGS artifacts to matched baselines."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    condition_scores: dict[str, ConditionScore]
    strongest_baseline: str
    performance_delta_vs_strongest_baseline: float
    acgs_wins: bool


class IncidentSpec(BaseModel):
    """Synthetic adversarial incident specification with hidden ground truth."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(min_length=1)
    adversarial_technique: Literal[
        "collusion",
        "memory_poisoning",
        "rule_gaming",
        "fragmented_actions",
        "misleading_traces",
    ]
    who_acted: str
    authority_existed: str
    rule_applied: str
    evidence_used: str
    who_approved_or_denied: str
    what_failed: str
    outcome_defensible: str

    def answer_key(self) -> dict[str, str]:
        return {question: str(getattr(self, question)) for question in FORENSIC_QUESTIONNAIRE}


class _IncidentEvidenceSource(BaseModel):
    """Condition-neutral source facts used to derive answers and evidence separately."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(pattern=r"^incident-[0-9]{3}$")
    ordinal: int = Field(ge=1, le=200)
    adversarial_technique: Literal[
        "collusion",
        "memory_poisoning",
        "rule_gaming",
        "fragmented_actions",
        "misleading_traces",
    ]


class EvidenceReference(BaseModel):
    """One typed evidence reference safe for blind-review distribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_class: EvidenceClass
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    strength: EvidenceStrength


class AuthorityEvidence(BaseModel):
    """Condition-neutral authority evidence, separated from answer text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deploy_role_visible: bool | None
    validator_approval_required: bool | None
    auditor_receipt_required: bool | None
    strength: EvidenceStrength


class PolicyEvidence(BaseModel):
    """Typed policy evidence that cannot carry free-form questionnaire answers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: Literal["unknown", "devops_high_risk"]
    version: Literal["unknown", "v0.1"]
    adversarial_signal: Literal[
        "unknown",
        "collusion",
        "memory_poisoning",
        "rule_gaming",
        "fragmented_actions",
        "misleading_traces",
    ]
    strength: EvidenceStrength


class DecisionEvidence(BaseModel):
    """Typed approval evidence with a fixed condition-neutral shape."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reviewing_role: Literal["unknown", "validator"]
    reviewer_ordinal: int = Field(ge=0, le=200)
    audit_role_present: bool | None
    disposition: Literal["unknown", "denied"]
    strength: EvidenceStrength


class FailureEvidence(BaseModel):
    """Typed failure evidence derived independently from the hidden answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal[
        "unknown",
        "coordinated_approval",
        "poisoned_authorization",
        "threshold_evasion",
        "fragmented_tool_calls",
        "misleading_trace_labels",
    ]
    step_ordinal: int = Field(ge=0, le=200)
    strength: EvidenceStrength


class OutcomeEvidence(BaseModel):
    """Typed outcome evidence without a prewritten reviewer answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_blocked: bool | None
    evidence_preserved: bool | None
    detection_timing: Literal["unknown", "before_execution", "after_execution"]
    strength: EvidenceStrength


class IntegrityEvidence(BaseModel):
    """Evidence-integrity properties present under every study condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    structured: bool | None
    tamper_evident: bool | None
    role_separation_checked: bool | None
    receipt_chain_present: bool | None


class ReviewerEvidenceArtifact(BaseModel):
    """Strict reviewer artifact schema incapable of carrying answer prose."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["acgs-forensic-evidence-v2"] = "acgs-forensic-evidence-v2"
    incident_id: str = Field(pattern=r"^(?:incident-[0-9]{3}|[0-9a-f]{64})$")
    principal_role: Literal["unknown", "executor"]
    principal_ordinal: int = Field(ge=0, le=200)
    principal_strength: EvidenceStrength
    authority_evidence: AuthorityEvidence
    policy_evidence: PolicyEvidence
    evidence_references: tuple[EvidenceReference, EvidenceReference, EvidenceReference]
    decision_evidence: DecisionEvidence
    failure_evidence: FailureEvidence
    outcome_evidence: OutcomeEvidence
    integrity_evidence: IntegrityEvidence


class _FrozenDict(dict[str, Any]):
    """Small serializable dict that rejects mutation after model construction."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("mapping is immutable")

    __setitem__ = _immutable  # type: ignore[assignment]
    __delitem__ = _immutable  # type: ignore[assignment]
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable  # type: ignore[assignment]


class BenchmarkArtifactPack(BaseModel):
    """Generated public-study artifact pack with hidden ground truth separated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ForensicBenchmarkProtocol
    reviewer_artifacts: dict[str, tuple[ReviewerEvidenceArtifact, ...]]
    answer_key: dict[str, dict[str, str]]
    condition_key: dict[str, str]
    pack_nonce: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("reviewer_artifacts")
    @classmethod
    def freeze_reviewer_artifacts(
        cls,
        value: dict[str, tuple[ReviewerEvidenceArtifact, ...]],
    ) -> dict[str, tuple[ReviewerEvidenceArtifact, ...]]:
        return _FrozenDict({condition: tuple(artifacts) for condition, artifacts in value.items()})

    @field_validator("answer_key")
    @classmethod
    def freeze_answer_key(cls, value: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
        return _FrozenDict(
            {
                incident_id: _FrozenDict(dict(answers))
                for incident_id, answers in value.items()
            }
        )

    @field_validator("condition_key")
    @classmethod
    def freeze_condition_key(cls, value: dict[str, str]) -> dict[str, str]:
        return _FrozenDict(dict(value))

    @model_validator(mode="after")
    def require_complete_conditions(self) -> BenchmarkArtifactPack:
        incident_ids = set(self.answer_key)
        if set(self.reviewer_artifacts) != set(BASELINES):
            msg = "reviewer artifacts must contain exactly the benchmark conditions"
            raise ValueError(msg)
        if set(self.condition_key) != set(BLINDED_CONDITION_LABELS) or set(
            self.condition_key.values()
        ) != set(BASELINES):
            msg = "condition key must be a bijection over blinded labels and conditions"
            raise ValueError(msg)
        if len(incident_ids) != self.protocol.incident_count:
            msg = "answer-key incident count does not match protocol"
            raise ValueError(msg)
        for incident_id, answers in self.answer_key.items():
            if set(answers) != set(FORENSIC_QUESTIONNAIRE):
                msg = f"answer key for {incident_id} does not match questionnaire"
                raise ValueError(msg)
        for condition in BASELINES:
            artifacts = self.reviewer_artifacts.get(condition)
            if artifacts is None:
                msg = f"missing reviewer artifact condition: {condition}"
                raise ValueError(msg)
            artifact_id_list = [artifact.incident_id for artifact in artifacts]
            if len(artifact_id_list) != len(set(artifact_id_list)):
                msg = f"duplicate reviewer artifact incident in condition {condition}"
                raise ValueError(msg)
            if set(artifact_id_list) != incident_ids:
                msg = f"artifact condition {condition} does not match answer-key incidents"
                raise ValueError(msg)
        if not reviewer_artifacts_exclude_ground_truth(
            self.reviewer_artifacts,
            answer_key=self.answer_key,
        ):
            msg = "reviewer artifacts contain hidden answer material"
            raise ValueError(msg)
        return self


class ExternalReplicationRecord(BaseModel):
    """Metadata proving a non-ACGS group reran the benchmark."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    replicating_group: str = Field(min_length=1)
    artifact_pack_uri: str = Field(min_length=1)
    reviewer_cohort_uri: str = Field(min_length=1)
    command_line: str = Field(min_length=1)
    scorecard_uri: str = Field(min_length=1)
    attestation_uri: str = Field(min_length=1)
    completed: bool
    reproduction_notes: str = Field(min_length=1)


class ExternalReplicationAttestation(BaseModel):
    """Independent attestation that a non-ACGS group completed the rerun."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_id: str = Field(min_length=1)
    replicating_group: str = Field(min_length=1)
    attestor_name: str = Field(min_length=1)
    attestor_role: str = Field(min_length=1)
    conflict_of_interest_screened: bool
    commands_transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_cohort_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scorecard_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declares_independent_rerun: bool
    declares_no_acgs_authorship: bool
    signed_at: str = Field(min_length=1)


class ReviewerCohortManifest(BaseModel):
    """Public manifest for the blind-review cohort used by an external rerun."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cohort_id: str = Field(min_length=1)
    recruiting_organization: str = Field(min_length=1)
    reviewer_count: int = Field(ge=6)
    reviewer_roster_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    blind_to_ground_truth: bool
    blind_to_condition_labels: bool
    artifact_access_scope: Literal["reviewer_packet_only"]
    conflict_of_interest_screened: bool

    @field_validator("reviewer_count")
    @classmethod
    def require_balanced_cohort(cls, value: int) -> int:
        if value % len(BASELINES):
            msg = "reviewer_count must be divisible by three"
            raise ValueError(msg)
        return value


class CollectedAnswerEvidence(BaseModel):
    """Tamper-evident references for collected blind-review answers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer_matrix_uri: str = Field(min_length=1)
    answer_seal_uri: str = Field(min_length=1)
    answers_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answers_bytes: int = Field(ge=1)
    row_count: int = Field(ge=1)
    reviewer_count: int = Field(ge=2)


class EvidenceFileBinding(BaseModel):
    """Content binding for one file used to derive a result bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    logical_name: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1)


class BenchmarkResultBundle(BaseModel):
    """Auditable result bundle for the v0.1 public-study success claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ForensicBenchmarkProtocol
    scorecard: BenchmarkScorecard
    reviewer_count: int = Field(ge=1)
    incident_count: int = Field(ge=1)
    question_count: int = Field(ge=1)
    artifact_conditions: tuple[str, ...]
    p_value_vs_strongest_baseline: float = Field(ge=0.0, le=1.0)
    answer_evidence: CollectedAnswerEvidence
    external_replication: ExternalReplicationRecord
    # Empty only for backwards deserialization. Such legacy bundles fail closed
    # in validate_result_bundle because no actual evidence can be rehashed.
    evidence_files: tuple[EvidenceFileBinding, ...] = ()


class ResultValidationIssue(BaseModel):
    """One result-bundle validation finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str


class ResultValidationVerdict(BaseModel):
    """Machine-readable success-claim gate for public benchmark results."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    issues: list[ResultValidationIssue] = Field(default_factory=list)
    provenance_diagnostics: list[ResultValidationIssue] = Field(default_factory=list)
    command_metadata: str | None = None
    authenticated_provenance: bool = False
    external_success: bool = False
    independence_verified: bool = False


def validate_protocol(protocol: ForensicBenchmarkProtocol) -> ProtocolValidationResult:
    """Validate the public-study protocol against the v0.1 success standard."""

    issues: list[ProtocolValidationIssue] = []
    if not 50 <= protocol.incident_count <= 200:
        issues.append(
            ProtocolValidationIssue(
                code="incident_count_out_of_range",
                message="v0.1 requires 50 to 200 adversarial incidents",
            )
        )
    if tuple(protocol.questionnaire) != FORENSIC_QUESTIONNAIRE:
        issues.append(
            ProtocolValidationIssue(
                code="questionnaire_mismatch",
                message="forensic questionnaire must match the fixed v0.1 question set",
            )
        )
    missing_baselines = [name for name in BASELINES if name not in protocol.baselines]
    if missing_baselines:
        issues.append(
            ProtocolValidationIssue(
                code="missing_baselines",
                message=f"missing matched baselines: {', '.join(missing_baselines)}",
            )
        )
    missing_techniques = [
        name for name in ADVERSARIAL_TECHNIQUES if name not in protocol.adversarial_techniques
    ]
    if missing_techniques:
        issues.append(
            ProtocolValidationIssue(
                code="missing_adversarial_techniques",
                message=f"missing adversarial techniques: {', '.join(missing_techniques)}",
            )
        )
    if not protocol.blind_review or not protocol.hidden_ground_truth_separated:
        issues.append(
            ProtocolValidationIssue(
                code="blind_review_not_enforced",
                message="reviewers must see only artifacts, with ground truth separated",
            )
        )
    required_metrics = {
        "answer_accuracy",
        "time_to_answer",
        "confidence_calibration",
        "inter_reviewer_agreement",
        "performance_delta_vs_strongest_baseline",
    }
    missing_metrics = sorted(required_metrics.difference(protocol.scoring_metrics))
    if missing_metrics:
        issues.append(
            ProtocolValidationIssue(
                code="missing_scoring_metrics",
                message=f"missing scoring metrics: {', '.join(missing_metrics)}",
            )
        )
    return ProtocolValidationResult(valid=not issues, issues=issues)


def score_reviewer_answers(answers: Sequence[ReviewerAnswer]) -> BenchmarkScorecard:
    """Aggregate blind-review answers into matched-condition scorecard metrics."""

    if not answers:
        msg = "at least one reviewer answer is required"
        raise ValueError(msg)
    cells = [
        (
            answer.incident_id,
            answer.artifact_condition,
            answer.reviewer_id,
            answer.question_id,
        )
        for answer in answers
    ]
    if len(cells) != len(set(cells)):
        msg = "duplicate incident/condition/reviewer/question answer cell"
        raise ValueError(msg)
    truths: dict[tuple[str, str], set[str]] = defaultdict(set)
    for answer in answers:
        truths[(answer.incident_id, answer.question_id)].add(answer.ground_truth)
    if any(len(values) != 1 for values in truths.values()):
        msg = "ground truth differs across between-reviewer conditions"
        raise ValueError(msg)

    grouped: dict[str, list[ReviewerAnswer]] = defaultdict(list)
    for answer in answers:
        grouped[answer.artifact_condition].append(answer)

    missing = [condition for condition in BASELINES if condition not in grouped]
    if missing:
        msg = f"missing answers for artifact conditions: {', '.join(missing)}"
        raise ValueError(msg)

    condition_scores: dict[str, ConditionScore] = {}
    for condition, condition_answers in grouped.items():
        correctness = [
            _is_correct(answer.answer, answer.ground_truth) for answer in condition_answers
        ]
        accuracy = sum(correctness) / len(correctness)
        mean_time = sum(answer.elapsed_seconds for answer in condition_answers) / len(
            condition_answers
        )
        calibration_error = _mean_absolute_calibration_error(condition_answers, correctness)
        agreement = _mean_pairwise_agreement(condition_answers)
        condition_scores[condition] = ConditionScore(
            answer_accuracy=accuracy,
            mean_time_seconds=mean_time,
            confidence_calibration_error=calibration_error,
            inter_reviewer_agreement=agreement,
            answer_count=len(condition_answers),
        )

    strongest_baseline = max(
        ("ungoverned_raw_logs", "centralized_structured_logs"),
        key=lambda name: _condition_composite(condition_scores[name]),
    )
    acgs_score = _condition_composite(condition_scores["acgs_receipts_and_audit_artifacts"])
    baseline_score = _condition_composite(condition_scores[strongest_baseline])
    delta = acgs_score - baseline_score
    return BenchmarkScorecard(
        condition_scores=condition_scores,
        strongest_baseline=strongest_baseline,
        performance_delta_vs_strongest_baseline=delta,
        acgs_wins=delta > 0,
    )


def paired_sign_test_p_value(
    answers: Sequence[ReviewerAnswer],
    *,
    strongest_baseline: str | None = None,
) -> float:
    """Compatibility wrapper for the between-reviewer incident sign test."""

    return incident_stratified_sign_test_p_value(
        answers,
        strongest_baseline=strongest_baseline,
    )


def incident_stratified_sign_test_p_value(
    answers: Sequence[ReviewerAnswer],
    *,
    strongest_baseline: str | None = None,
) -> float:
    """Return an exact one-sided sign test over incident-level condition means.

    Incident is the prespecified unit of independence. Reviewer/question cells
    belong to disjoint reviewer cohorts and only contribute to condition means.
    """

    if not answers:
        msg = "at least one reviewer answer is required"
        raise ValueError(msg)
    cells = [
        (
            answer.incident_id,
            answer.artifact_condition,
            answer.reviewer_id,
            answer.question_id,
        )
        for answer in answers
    ]
    if len(cells) != len(set(cells)):
        msg = "duplicate incident/condition/reviewer/question answer cell"
        raise ValueError(msg)
    truths: dict[tuple[str, str], set[str]] = defaultdict(set)
    for answer in answers:
        truths[(answer.incident_id, answer.question_id)].add(answer.ground_truth)
    if any(len(values) != 1 for values in truths.values()):
        msg = "ground truth differs across between-reviewer conditions"
        raise ValueError(msg)
    if strongest_baseline is None:
        _validate_between_reviewer_question_coverage(answers, set(BASELINES))
        baseline = score_reviewer_answers(answers).strongest_baseline
    else:
        baseline = strongest_baseline
    if baseline not in BASELINES[:2]:
        msg = "strongest baseline must be a non-ACGS benchmark condition"
        raise ValueError(msg)
    _validate_between_reviewer_question_coverage(
        answers,
        {baseline, "acgs_receipts_and_audit_artifacts"},
    )
    grouped: dict[tuple[str, str], list[bool]] = defaultdict(list)
    questions: dict[tuple[str, str], set[str]] = defaultdict(set)
    for answer in answers:
        if answer.artifact_condition in {baseline, "acgs_receipts_and_audit_artifacts"}:
            grouped[(answer.incident_id, answer.artifact_condition)].append(
                _is_correct(answer.answer, answer.ground_truth)
            )
            questions[(answer.incident_id, answer.artifact_condition)].add(
                answer.question_id
            )
    incidents = {incident_id for incident_id, _ in grouped}
    incident_contrasts: dict[str, float] = {}
    for incident_id in incidents:
        acgs = grouped.get((incident_id, "acgs_receipts_and_audit_artifacts"), [])
        control = grouped.get((incident_id, baseline), [])
        if not acgs or not control:
            msg = f"missing between-reviewer condition cells for incident={incident_id}"
            raise ValueError(msg)
        if questions[(incident_id, "acgs_receipts_and_audit_artifacts")] != questions[
            (incident_id, baseline)
        ]:
            msg = "question cells must be identical across between-reviewer conditions"
            raise ValueError(msg)
        incident_contrasts[incident_id] = sum(acgs) / len(acgs) - sum(control) / len(control)
    acgs_wins = sum(contrast > 0 for contrast in incident_contrasts.values())
    baseline_wins = sum(contrast < 0 for contrast in incident_contrasts.values())

    discordant = acgs_wins + baseline_wins
    if discordant == 0:
        return 1.0
    tail_count = sum(math.comb(discordant, k) for k in range(acgs_wins, discordant + 1))
    with localcontext() as ctx:
        # Keep the intermediate ratio stable for large blind-review matrices
        # before returning the public float-valued p-value field.
        ctx.prec = max(28, min(discordant + 10, 5000))
        return float(Decimal(tail_count) / (Decimal(2) ** discordant))


def _validate_between_reviewer_question_coverage(
    answers: Sequence[ReviewerAnswer],
    conditions: set[str],
) -> None:
    incidents = {answer.incident_id for answer in answers}
    question_sets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for answer in answers:
        if answer.artifact_condition in conditions:
            question_sets[(answer.incident_id, answer.artifact_condition)].add(
                answer.question_id
            )
    expected_questions: set[str] | None = None
    for incident_id in incidents:
        for condition in conditions:
            observed = question_sets.get((incident_id, condition), set())
            if not observed:
                msg = (
                    "missing between-reviewer condition cells for "
                    f"incident={incident_id}, condition={condition}"
                )
                raise ValueError(msg)
            if expected_questions is None:
                expected_questions = observed
            elif observed != expected_questions:
                msg = "question cells must be identical across incidents and conditions"
                raise ValueError(msg)


def _paired_incident_correctness_contrasts(
    answers: Sequence[ReviewerAnswer],
    baseline: str,
) -> dict[str, int]:
    if baseline not in BASELINES[:2]:
        msg = "strongest baseline must be a non-ACGS benchmark condition"
        raise ValueError(msg)

    all_cells: set[tuple[str, str, str, str]] = set()
    matched: dict[tuple[str, str, str], dict[str, ReviewerAnswer]] = defaultdict(dict)
    relevant_conditions = {baseline, "acgs_receipts_and_audit_artifacts"}
    for answer in answers:
        cell = (
            answer.incident_id,
            answer.artifact_condition,
            answer.reviewer_id,
            answer.question_id,
        )
        if cell in all_cells:
            msg = "duplicate incident/condition/reviewer/question answer cell"
            raise ValueError(msg)
        all_cells.add(cell)
        if answer.artifact_condition in relevant_conditions:
            key = (answer.incident_id, answer.reviewer_id, answer.question_id)
            matched[key][answer.artifact_condition] = answer

    incident_contrasts: dict[str, int] = defaultdict(int)
    incident_cells: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for key, condition_answers in matched.items():
        missing = relevant_conditions.difference(condition_answers)
        if missing:
            msg = (
                "missing matched ACGS/baseline answer for "
                f"incident={key[0]}, reviewer={key[1]}, question={key[2]}"
            )
            raise ValueError(msg)
        acgs_answer = condition_answers["acgs_receipts_and_audit_artifacts"]
        baseline_answer = condition_answers[baseline]
        if acgs_answer.ground_truth != baseline_answer.ground_truth:
            msg = (
                "ground truth differs across matched conditions for "
                f"incident={key[0]}, reviewer={key[1]}, question={key[2]}"
            )
            raise ValueError(msg)
        incident_cells[key[0]].add((key[1], key[2]))
        incident_contrasts[key[0]] += int(
            _is_correct(acgs_answer.answer, acgs_answer.ground_truth)
        ) - int(_is_correct(baseline_answer.answer, baseline_answer.ground_truth))

    if not incident_contrasts:
        msg = "missing matched ACGS/baseline answer pairs"
        raise ValueError(msg)
    expected_cells = next(iter(incident_cells.values()))
    if any(cells != expected_cells for cells in incident_cells.values()):
        msg = "matched reviewer/question cells must be identical for every incident"
        raise ValueError(msg)
    return dict(incident_contrasts)


def build_result_bundle(
    *,
    protocol: ForensicBenchmarkProtocol,
    external_replication: ExternalReplicationRecord,
    evidence_root: str | Path,
    evidence_paths: Mapping[str, str],
    expected_precollection_commitment: str,
    answers: Sequence[ReviewerAnswer] | None = None,
    answer_evidence: CollectedAnswerEvidence | None = None,
) -> BenchmarkResultBundle:
    """Build a bundle only from rehashed files under ``evidence_root``.

    ``answers`` and ``answer_evidence`` are compatibility cross-checks. They
    cannot override the sealed CSV or any digest/count derived from it.
    """

    loaded, bindings, evidence_issues = _load_and_bind_result_evidence(
        evidence_root,
        evidence_paths,
        expected_precollection_commitment=expected_precollection_commitment,
    )
    if evidence_issues:
        issue_summary = ", ".join(issue.code for issue in evidence_issues)
        msg = f"result evidence invalid: {issue_summary}"
        raise ValueError(msg)
    file_answers = _answers_from_bound_evidence(loaded)
    _validate_complete_answer_matrix(protocol, file_answers)
    if answers is not None:
        _validate_complete_answer_matrix(protocol, answers)
        if _answer_records_by_cell(answers) != _answer_records_by_cell(file_answers):
            msg = "provided answers do not match the sealed answer CSV"
            raise ValueError(msg)

    file_protocol = _protocol_from_evidence(loaded["protocol"])
    if file_protocol != protocol:
        msg = "protocol does not match the bound protocol file"
        raise ValueError(msg)
    file_replication = ExternalReplicationRecord.model_validate(
        _strict_json_loads(loaded["replication_metadata"].decode("utf-8"))
    )
    if file_replication != external_replication:
        msg = "external replication metadata does not match the bound file"
        raise ValueError(msg)

    scorecard = score_reviewer_answers(file_answers)
    p_value = paired_sign_test_p_value(
        file_answers,
        strongest_baseline=scorecard.strongest_baseline,
    )
    if "scorecard" in loaded:
        sealed_scorecard = BenchmarkScorecard.model_validate(
            _strict_json_loads(loaded["scorecard"].decode("utf-8"))
        )
        if sealed_scorecard != scorecard:
            msg = "scorecard file does not match recomputation from sealed answers"
            raise ValueError(msg)

    answer_binding = _binding_by_logical_name(bindings, "answers_csv")
    seal_binding = _binding_by_logical_name(bindings, "answer_seal")
    manifest_binding = _binding_by_logical_name(bindings, "reviewer_manifest")
    derived_evidence = CollectedAnswerEvidence(
        answer_matrix_uri=(
            answer_evidence.answer_matrix_uri
            if answer_evidence is not None
            else f"sha256:{answer_binding.sha256}"
        ),
        answer_seal_uri=(
            answer_evidence.answer_seal_uri
            if answer_evidence is not None
            else f"sha256:{seal_binding.sha256}"
        ),
        answers_sha256=answer_binding.sha256,
        answer_seal_sha256=seal_binding.sha256,
        reviewer_manifest_sha256=manifest_binding.sha256,
        answers_bytes=answer_binding.size_bytes,
        row_count=len(file_answers),
        reviewer_count=len({answer.reviewer_id for answer in file_answers}),
    )
    if answer_evidence is not None:
        expected = answer_evidence.model_copy(
            update={
                "answer_matrix_uri": derived_evidence.answer_matrix_uri,
                "answer_seal_uri": derived_evidence.answer_seal_uri,
            }
        )
        if expected != derived_evidence:
            msg = "provided answer evidence does not match bound file bytes"
            raise ValueError(msg)

    return BenchmarkResultBundle(
        protocol=protocol,
        scorecard=scorecard,
        reviewer_count=len({answer.reviewer_id for answer in file_answers}),
        incident_count=len({answer.incident_id for answer in file_answers}),
        question_count=len({answer.question_id for answer in file_answers}),
        artifact_conditions=tuple(
            sorted({answer.artifact_condition for answer in file_answers})
        ),
        p_value_vs_strongest_baseline=p_value,
        answer_evidence=derived_evidence,
        external_replication=external_replication,
        evidence_files=bindings,
    )


_REQUIRED_RESULT_EVIDENCE: frozenset[str] = frozenset(
    {
        "answers_csv",
        "answer_seal",
        "reviewer_manifest",
        "answer_key",
        "condition_key",
        "protocol",
        "replication_metadata",
    }
)
_ALLOWED_RESULT_EVIDENCE: frozenset[str] = _REQUIRED_RESULT_EVIDENCE | {"scorecard"}
_MANIFEST_EVIDENCE_NAMES: frozenset[str] = frozenset({"reviewer_manifest"})


def _load_and_bind_result_evidence(
    evidence_root: str | Path,
    evidence_paths: Mapping[str, str],
    *,
    expected_precollection_commitment: str | None = None,
) -> tuple[dict[str, bytes], tuple[EvidenceFileBinding, ...], list[ResultValidationIssue]]:
    root = Path(evidence_root).resolve()
    issues: list[ResultValidationIssue] = []
    missing = sorted(_REQUIRED_RESULT_EVIDENCE.difference(evidence_paths))
    if missing:
        return {}, (), [
            ResultValidationIssue(
                code="missing_evidence_files",
                message=f"missing required evidence paths: {', '.join(missing)}",
            )
        ]
    unknown = sorted(set(evidence_paths).difference(_ALLOWED_RESULT_EVIDENCE))
    if unknown:
        return {}, (), [
            ResultValidationIssue(
                code="unknown_evidence_logical_name",
                message=f"unknown evidence logical names: {', '.join(unknown)}",
            )
        ]

    loaded: dict[str, bytes] = {}
    bindings: list[EvidenceFileBinding] = []
    bound_paths: dict[str, str] = {}

    def bind(logical_name: str, relative_path: str) -> bytes | None:
        try:
            candidate = (root / relative_path).resolve()
            candidate.relative_to(root)
        except (OSError, ValueError):
            issues.append(
                ResultValidationIssue(
                    code="evidence_path_outside_root",
                    message=f"{logical_name} path escapes the evidence root",
                )
            )
            return None
        canonical_relative = candidate.relative_to(root).as_posix()
        if not candidate.is_file():
            issues.append(
                ResultValidationIssue(
                    code="evidence_file_missing",
                    message=f"{logical_name} file is missing: {canonical_relative}",
                )
            )
            return None
        try:
            data = candidate.read_bytes()
        except OSError:
            issues.append(
                ResultValidationIssue(
                    code="evidence_file_unreadable",
                    message=f"{logical_name} file cannot be read: {canonical_relative}",
                )
            )
            return None
        if not data:
            issues.append(
                ResultValidationIssue(
                    code="evidence_file_empty",
                    message=f"{logical_name} file is empty: {canonical_relative}",
                )
            )
            return None
        existing_logical_name = bound_paths.get(canonical_relative)
        if existing_logical_name is not None and existing_logical_name != logical_name:
            issues.append(
                ResultValidationIssue(
                    code="evidence_path_alias",
                    message=(
                        f"{logical_name} aliases {existing_logical_name} at "
                        f"{canonical_relative}"
                    ),
                )
            )
            return None
        bindings.append(
            EvidenceFileBinding(
                logical_name=logical_name,
                relative_path=canonical_relative,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
            )
        )
        bound_paths[canonical_relative] = logical_name
        return data

    for logical_name, relative_path in sorted(evidence_paths.items()):
        data = bind(logical_name, relative_path)
        if data is not None:
            loaded[logical_name] = data

    for manifest_name in sorted(_MANIFEST_EVIDENCE_NAMES.intersection(loaded)):
        manifest_members: dict[str, str] = {}
        try:
            manifest = _strict_json_loads(loaded[manifest_name].decode("utf-8"))
            entries = manifest["files"]
            if not isinstance(entries, dict) or not entries:
                raise TypeError
            if manifest.get("file_count") != len(entries):
                raise TypeError
            if (
                manifest_name == "reviewer_manifest"
                and manifest.get("schema")
                != "acgs-v0.1-reviewer-artifact-manifest"
            ):
                raise TypeError
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            issues.append(
                ResultValidationIssue(
                    code="invalid_evidence_manifest",
                    message=f"{manifest_name} must contain a files object",
                )
            )
            continue
        manifest_parent = Path(evidence_paths[manifest_name]).parent
        for member_path, expected in sorted(entries.items()):
            if not isinstance(member_path, str) or not isinstance(expected, dict):
                issues.append(
                    ResultValidationIssue(
                        code="invalid_evidence_manifest_entry",
                        message=f"invalid entry in {manifest_name}",
                    )
                )
                continue
            member_logical = f"{manifest_name}:{member_path}"
            member_data = bind(member_logical, (manifest_parent / member_path).as_posix())
            if member_data is None:
                continue
            try:
                manifest_members[member_path] = member_data.decode("utf-8")
                loaded[member_logical] = member_data
            except UnicodeDecodeError:
                issues.append(
                    ResultValidationIssue(
                        code="manifest_member_not_utf8",
                        message=f"{member_logical} is not UTF-8 text",
                    )
                )
                continue
            actual_sha256 = hashlib.sha256(member_data).hexdigest()
            expected_sha256 = expected.get("sha256")
            if not isinstance(expected_sha256, str) or not hmac.compare_digest(
                expected_sha256,
                actual_sha256,
            ):
                issues.append(
                    ResultValidationIssue(
                        code="manifest_member_sha256_mismatch",
                        message=f"{member_logical} does not match its manifest digest",
                    )
                )
            if expected.get("bytes") != len(member_data):
                issues.append(
                    ResultValidationIssue(
                        code="manifest_member_size_mismatch",
                        message=f"{member_logical} does not match its manifest size",
                    )
                )
        if manifest_name == "reviewer_manifest" and manifest_members:
            try:
                for path, content in manifest_members.items():
                    if path.startswith(("artifacts/", "reviewer_artifacts/")):
                        ReviewerEvidenceArtifact.model_validate(_strict_json_loads(content))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                issues.append(
                    ResultValidationIssue(
                        code="invalid_reviewer_packet",
                        message=f"reviewer packet failed semantic validation: {exc}",
                    )
                )
    if {"answers_csv", "answer_seal", "reviewer_manifest"}.issubset(loaded):
        try:
            seal = _strict_json_loads(loaded["answer_seal"].decode("utf-8"))
            if seal.get("schema") != "acgs-v0.1-collected-blind-answers-seal":
                raise TypeError
            sealed_answers = seal["answers_csv"]
            sealed_packet = seal["reviewer_packet"]
            validation = seal["validation"]
            if (
                not isinstance(sealed_answers, dict)
                or not isinstance(sealed_packet, dict)
                or not isinstance(validation, dict)
                or validation.get("valid") is not True
            ):
                raise TypeError
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            issues.append(
                ResultValidationIssue(
                    code="invalid_answer_seal",
                    message="answer_seal must bind the answer CSV and reviewer manifest",
                )
            )
        else:
            sealed_answers_sha256 = sealed_answers.get("sha256")
            actual_answers_sha256 = hashlib.sha256(loaded["answers_csv"]).hexdigest()
            if not isinstance(sealed_answers_sha256, str) or not hmac.compare_digest(
                sealed_answers_sha256,
                actual_answers_sha256,
            ):
                issues.append(
                    ResultValidationIssue(
                        code="answers_sha256_mismatch",
                        message="answers CSV does not match the answer seal digest",
                    )
                )
            if sealed_answers.get("bytes") != len(loaded["answers_csv"]):
                issues.append(
                    ResultValidationIssue(
                        code="answers_byte_count_mismatch",
                        message="answers CSV does not match the answer seal size",
                    )
                )
            sealed_manifest_sha256 = sealed_packet.get("reviewer_manifest_sha256")
            actual_manifest_sha256 = hashlib.sha256(
                loaded["reviewer_manifest"]
            ).hexdigest()
            if not isinstance(sealed_manifest_sha256, str) or not hmac.compare_digest(
                sealed_manifest_sha256,
                actual_manifest_sha256,
            ):
                issues.append(
                    ResultValidationIssue(
                        code="reviewer_manifest_sha256_mismatch",
                        message="reviewer manifest does not match the answer seal digest",
                    )
                )
            try:
                answer_rows = list(
                    DictReader(
                        StringIO(loaded["answers_csv"].decode("utf-8"), newline="")
                    )
                )
            except UnicodeDecodeError:
                answer_rows = []
            if validation.get("row_count") != len(answer_rows):
                issues.append(
                    ResultValidationIssue(
                        code="answer_seal_row_count_mismatch",
                        message="answer seal row_count differs from the actual CSV",
                    )
                )
            reviewer_count = len(
                {row.get("reviewer_id", "") for row in answer_rows if row.get("reviewer_id")}
            )
            if validation.get("reviewer_count") != reviewer_count:
                issues.append(
                    ResultValidationIssue(
                        code="answer_seal_reviewer_count_mismatch",
                        message="answer seal reviewer_count differs from the actual CSV",
                    )
                    )
            sealed_commitment = seal.get("precollection_commitment")
            if expected_precollection_commitment is None:
                issues.append(
                    ResultValidationIssue(
                        code="missing_expected_precollection_commitment",
                        message="an out-of-band precollection commitment is required",
                    )
                )
            elif (
                not isinstance(sealed_commitment, str)
                or not hmac.compare_digest(
                    sealed_commitment,
                    expected_precollection_commitment,
                )
            ):
                issues.append(
                    ResultValidationIssue(
                        code="precollection_commitment_mismatch",
                        message="answer seal does not match the expected commitment",
                    )
                )
    issues.extend(
        _verify_canonical_generated_evidence(
            loaded,
            expected_precollection_commitment=expected_precollection_commitment,
        )
    )
    return loaded, tuple(bindings), issues


def _verify_canonical_generated_evidence(
    loaded: Mapping[str, bytes],
    *,
    expected_precollection_commitment: str | None,
) -> list[ResultValidationIssue]:
    """Regenerate the public pack and byte-compare every security input."""

    required = {"protocol", "answer_key", "condition_key", "reviewer_manifest"}
    if not required.issubset(loaded):
        return []
    if expected_precollection_commitment is None:
        return [
            ResultValidationIssue(
                code="missing_expected_precollection_commitment",
                message="an out-of-band precollection commitment is required",
            )
        ]
    if re.fullmatch(r"[0-9a-f]{64}", expected_precollection_commitment) is None:
        return [
            ResultValidationIssue(
                code="invalid_expected_precollection_commitment",
                message="expected commitment must be 64 lowercase hexadecimal characters",
            )
        ]
    try:
        protocol = _protocol_from_evidence(loaded["protocol"])
        condition_payload = _strict_json_loads(loaded["condition_key"].decode())
        _validate_condition_key_payload(condition_payload)
        pack = generate_artifact_pack(
            protocol.incident_count,
            pack_nonce=condition_payload["pack_nonce"],
        )
        canonical = artifact_pack_to_files(pack)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        return [
            ResultValidationIssue(
                code="canonical_pack_regeneration_failed",
                message=f"canonical pack could not be regenerated: {exc}",
            )
        ]
    canonical_commitment = precollection_commitment_digest(canonical)
    issues: list[ResultValidationIssue] = []
    if not hmac.compare_digest(canonical_commitment, expected_precollection_commitment):
        issues.append(
            ResultValidationIssue(
                code="expected_precollection_commitment_mismatch",
                message="out-of-band commitment does not match regenerated pack",
            )
        )
    direct_mapping = {
        "protocol": "protocol.json",
        "answer_key": "answer_key.json",
        "condition_key": "condition_key.json",
        "reviewer_manifest": "reviewer_manifest.json",
    }
    for logical_name, path in direct_mapping.items():
        if loaded[logical_name] != canonical[path].encode():
            issues.append(
                ResultValidationIssue(
                    code=f"noncanonical_{logical_name}",
                    message=f"{logical_name} differs from public generator output",
                )
            )
    for logical_name, data in loaded.items():
        prefix = "reviewer_manifest:"
        if not logical_name.startswith(prefix):
            continue
        path = logical_name.removeprefix(prefix)
        if path not in canonical or data != canonical[path].encode():
            issues.append(
                ResultValidationIssue(
                    code="noncanonical_reviewer_artifact",
                    message=f"reviewer artifact differs from generator output: {path}",
                )
            )
    return issues


def _binding_by_logical_name(
    bindings: Sequence[EvidenceFileBinding],
    logical_name: str,
) -> EvidenceFileBinding:
    return next(binding for binding in bindings if binding.logical_name == logical_name)


def _answer_records_by_cell(
    answers: Sequence[ReviewerAnswer],
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    return {
        (
            answer.incident_id,
            answer.artifact_condition,
            answer.reviewer_id,
            answer.question_id,
        ): answer.model_dump()
        for answer in answers
    }


def _protocol_from_evidence(data: bytes) -> ForensicBenchmarkProtocol:
    payload = _strict_json_loads(data.decode("utf-8"))
    if isinstance(payload, dict) and "protocol" in payload:
        payload = payload["protocol"]
    return ForensicBenchmarkProtocol.model_validate(payload)


def _answers_from_bound_evidence(loaded: Mapping[str, bytes]) -> list[ReviewerAnswer]:
    answer_key = _strict_json_loads(loaded["answer_key"].decode("utf-8"))
    condition_payload = _strict_json_loads(loaded["condition_key"].decode("utf-8"))
    if not isinstance(answer_key, dict):
        msg = "answer_key evidence must be a JSON object"
        raise ValueError(msg)
    condition_key = _validate_condition_key_payload(condition_payload)
    pack_nonce = condition_payload["pack_nonce"]
    assignment_lookup: dict[tuple[str, str, str], str] = {}
    for internal_incident_id in answer_key:
        for reviewer_id in DEFAULT_REVIEWER_IDS:
            assigned_label = reviewer_assignment(internal_incident_id, reviewer_id)
            condition = condition_key[assigned_label]
            pseudonym = reviewer_incident_pseudonym(
                pack_nonce,
                internal_incident_id,
                condition,
                reviewer_id,
            )
            assignment_lookup[(reviewer_id, assigned_label, pseudonym)] = internal_incident_id
    try:
        text = loaded["answers_csv"].decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "answers CSV must be UTF-8"
        raise ValueError(msg) from exc
    rows = list(DictReader(StringIO(text, newline="")))
    forbidden_columns = {"ground_truth", "artifact_condition"}
    present_forbidden = forbidden_columns.intersection(
        DictReader(StringIO(text, newline="")).fieldnames or ()
    )
    if present_forbidden:
        msg = "sealed blind-answer CSV contains forbidden unblinded columns"
        raise ValueError(msg)
    answers: list[ReviewerAnswer] = []
    for row_number, row in enumerate(rows, start=2):
        public_incident_id = row.get("incident_id", "")
        question_id = row.get("question_id", "")
        label = row.get("condition_label", "")
        artifact_condition = condition_key.get(label)
        if artifact_condition not in BASELINES:
            msg = f"unknown blinded condition label in row {row_number}"
            raise ValueError(msg)
        typed_condition = cast(BenchmarkCondition, artifact_condition)
        try:
            reviewer_id = row.get("reviewer_id", "")
            incident_id = assignment_lookup[(reviewer_id, label, public_incident_id)]
            ground_truth = answer_key[incident_id][question_id]
            answers.append(
                ReviewerAnswer(
                    incident_id=incident_id,
                    artifact_condition=typed_condition,
                    reviewer_id=reviewer_id,
                    question_id=question_id,
                    answer=row.get("answer", ""),
                    ground_truth=ground_truth,
                    confidence=float(row.get("confidence", "")),
                    elapsed_seconds=float(row.get("elapsed_seconds", "")),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            msg = f"invalid sealed answer CSV row {row_number}"
            raise ValueError(msg) from exc
    if {answer.incident_id for answer in answers} != set(answer_key):
        msg = "answer_key incident coverage differs from the sealed answer CSV"
        raise ValueError(msg)
    return answers


def _validate_condition_key_payload(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"conditions", "pack_nonce"}:
        msg = "condition_key must contain exactly conditions and pack_nonce"
        raise ValueError(msg)
    conditions = payload["conditions"]
    pack_nonce = payload["pack_nonce"]
    if (
        not isinstance(conditions, dict)
        or set(conditions) != set(BLINDED_CONDITION_LABELS)
        or set(conditions.values()) != set(BASELINES)
    ):
        msg = "condition_key conditions must be a label-to-baseline bijection"
        raise ValueError(msg)
    if not isinstance(pack_nonce, str) or re.fullmatch(r"[0-9a-f]{64}", pack_nonce) is None:
        msg = "condition_key pack_nonce must be 64 lowercase hexadecimal characters"
        raise ValueError(msg)
    return {str(label): str(condition) for label, condition in conditions.items()}


_CONFUSABLE_IDENTITY_CHARS = str.maketrans(
    {
        "Α": "a",
        "α": "a",
        "А": "a",
        "а": "a",
        "Ϲ": "c",
        "ϲ": "c",
        "С": "c",
        "с": "c",
        "ɢ": "g",
        "ᴀ": "a",
        "ᴄ": "c",
        "ꜱ": "s",
        "Ꭺ": "a",
        "Ꮯ": "c",
        "Ꮐ": "g",
        "Ꮪ": "s",
        "Ѕ": "s",
        "ѕ": "s",
        "5": "s",
        "$": "s",
    }
)
ATTESTOR_DENYLIST_TOKENS: tuple[str, ...] = (
    "acgs",
    "constitutionalacgs",
)


def normalize_attestor_identity(value: str) -> str:
    """Normalize a display name for conservative allow/deny policy matching."""

    normalized = unicodedata.normalize("NFKD", value)
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
        and not unicodedata.category(character).startswith("M")
    )
    normalized = normalized.casefold().translate(_CONFUSABLE_IDENTITY_CHARS)
    return "".join(character for character in normalized if character.isalnum())


def attestor_is_allowed(
    name: str,
    *,
    trusted_attestors: Iterable[str],
) -> bool:
    """Apply a local name policy; this does not prove organizational identity."""

    normalized = normalize_attestor_identity(name)
    if not normalized:
        return False
    if any(token in normalized for token in ATTESTOR_DENYLIST_TOKENS):
        return False
    trusted = tuple(trusted_attestors)
    if not trusted:
        return False
    has_unmapped_non_ascii = any(ord(character) > 127 for character in normalized)
    if has_unmapped_non_ascii:
        return False
    return normalized in {normalize_attestor_identity(item) for item in trusted}


def _validate_complete_answer_matrix(
    protocol: ForensicBenchmarkProtocol,
    answers: Sequence[ReviewerAnswer],
) -> None:
    verdict = validate_answer_matrix(protocol, answers)
    if not verdict.valid:
        issue_summary = ", ".join(issue.code for issue in verdict.issues)
        msg = f"incomplete answer matrix: {issue_summary}"
        raise ValueError(msg)


def validate_answer_matrix(
    protocol: ForensicBenchmarkProtocol,
    answers: Sequence[ReviewerAnswer],
    *,
    condition_key: Mapping[str, str] | None = None,
) -> ResultValidationVerdict:
    """Validate full incident/condition/reviewer/question coverage before scoring."""

    issues: list[ResultValidationIssue] = []
    if not answers:
        return ResultValidationVerdict(
            valid=False,
            issues=[
                ResultValidationIssue(
                    code="empty_answer_matrix",
                    message="complete answer matrix requires at least one answer",
                )
            ],
        )
    incident_ids = {answer.incident_id for answer in answers}
    reviewer_ids = {answer.reviewer_id for answer in answers}
    if len(incident_ids) != protocol.incident_count:
        issues.append(
            ResultValidationIssue(
                code="answer_incident_count_mismatch",
                message=(
                    "distinct answered incidents must match protocol incident_count"
                ),
            )
        )

    observed = [
        (
            answer.incident_id,
            answer.artifact_condition,
            answer.reviewer_id,
            answer.question_id,
        )
        for answer in answers
    ]
    duplicate_count = len(observed) - len(set(observed))
    if duplicate_count:
        issues.append(
            ResultValidationIssue(
                code="duplicate_answer_cells",
                message=f"{duplicate_count} duplicate answer cells",
            )
        )
    expected_count = (
        protocol.incident_count * len(reviewer_ids) * len(FORENSIC_QUESTIONNAIRE)
    )
    missing_count = max(expected_count - len(set(observed)), 0)
    extra_count = max(len(set(observed)) - expected_count, 0)
    if missing_count:
        issues.append(
            ResultValidationIssue(
                code="missing_answer_cells",
                message=(
                    f"{missing_count} missing incident/condition/reviewer/question cells"
                ),
            )
        )
    if extra_count:
        issues.append(
            ResultValidationIssue(
                code="extra_answer_cells",
                message=(
                    f"{extra_count} extra incident/condition/reviewer/question cells"
                ),
            )
        )
    if len(reviewer_ids) < 6 or len(reviewer_ids) % len(BASELINES):
        issues.append(
            ResultValidationIssue(
                code="invalid_reviewer_cohort_size",
                message="reviewer cohort must be at least six and divisible by three",
            )
        )
    conditions_by_assignment: dict[tuple[str, str], set[str]] = defaultdict(set)
    questions_by_assignment: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    condition_reviewers: dict[tuple[str, str], set[str]] = defaultdict(set)
    for answer in answers:
        conditions_by_assignment[(answer.incident_id, answer.reviewer_id)].add(
            answer.artifact_condition
        )
        questions_by_assignment[
            (answer.incident_id, answer.reviewer_id, answer.artifact_condition)
        ].add(answer.question_id)
        condition_reviewers[(answer.incident_id, answer.artifact_condition)].add(
            answer.reviewer_id
        )
    if any(len(conditions) != 1 for conditions in conditions_by_assignment.values()):
        issues.append(
            ResultValidationIssue(
                code="reviewer_cross_condition_assignment",
                message="a reviewer may see each incident under exactly one condition",
            )
        )
    if any(
        questions != set(FORENSIC_QUESTIONNAIRE)
        for questions in questions_by_assignment.values()
    ):
        issues.append(
            ResultValidationIssue(
                code="incomplete_assigned_questionnaire",
                message="every assigned reviewer/incident must answer every question",
            )
        )
    expected_reviewers_per_condition = len(reviewer_ids) // len(BASELINES)
    if any(
        len(condition_reviewers.get((incident_id, condition), set()))
        != expected_reviewers_per_condition
        for incident_id in incident_ids
        for condition in BASELINES
    ):
        issues.append(
            ResultValidationIssue(
                code="imbalanced_between_reviewer_assignment",
                message="each incident must have balanced disjoint condition cohorts",
            )
        )
    if condition_key is not None:
        if (
            set(condition_key) != set(BLINDED_CONDITION_LABELS)
            or set(condition_key.values()) != set(BASELINES)
        ):
            issues.append(
                ResultValidationIssue(
                    code="invalid_assignment_condition_key",
                    message="assignment condition key must be a blinded-label bijection",
                )
            )
        else:
            wrong_assignments = sum(
                condition_key[reviewer_assignment(answer.incident_id, answer.reviewer_id)]
                != answer.artifact_condition
                for answer in answers
            )
            if wrong_assignments:
                issues.append(
                    ResultValidationIssue(
                        code="noncanonical_reviewer_assignment",
                        message=(
                            f"{wrong_assignments} answer rows violate the canonical "
                            "between-reviewer assignment"
                        ),
                    )
                )

    vectors_by_reviewer: dict[str, dict[tuple[str, str, str], str]] = {}
    for reviewer_id in reviewer_ids:
        vectors_by_reviewer[reviewer_id] = {
            (
                answer.incident_id,
                answer.artifact_condition,
                answer.question_id,
            ): answer.answer.strip().casefold()
            for answer in answers
            if answer.reviewer_id == reviewer_id
        }
    expected_vector_size = protocol.incident_count * len(FORENSIC_QUESTIONNAIRE)
    identical_pairs: list[tuple[str, str]] = []
    near_duplicate_pairs: list[tuple[str, str, int, int, float]] = []
    sorted_reviewers = sorted(vectors_by_reviewer)
    for index, left in enumerate(sorted_reviewers):
        for right in sorted_reviewers[index + 1 :]:
            left_vector = vectors_by_reviewer[left]
            right_vector = vectors_by_reviewer[right]
            if (
                len(left_vector) != expected_vector_size
                or len(right_vector) != expected_vector_size
                or left_vector.keys() != right_vector.keys()
            ):
                continue
            compared_count = len(left_vector)
            matching_count = sum(
                left_vector[cell] == right_vector[cell] for cell in left_vector
            )
            if matching_count == compared_count:
                identical_pairs.append((left, right))
                continue
            agreement_ratio = matching_count / compared_count
            if agreement_ratio > 0.95:
                near_duplicate_pairs.append(
                    (left, right, matching_count, compared_count, agreement_ratio)
                )
    diagnostics = []
    if identical_pairs:
        rendered_pairs = ", ".join(f"{left}/{right}" for left, right in identical_pairs)
        diagnostics.append(
            ResultValidationIssue(
                code="identical_reviewer_answer_vectors",
                message=(
                    "reviewers submitted identical normalized answer vectors; investigate "
                    f"possible answer copying: {rendered_pairs}"
                ),
            )
        )
    if near_duplicate_pairs:
        rendered_pairs = ", ".join(
            f"{left}/{right} ({matching}/{compared}, {ratio:.3%})"
            for left, right, matching, compared, ratio in near_duplicate_pairs
        )
        diagnostics.append(
            ResultValidationIssue(
                code="near_duplicate_reviewer_answer_vectors",
                message=(
                    "reviewers agreed on more than 95% of a complete comparable "
                    "normalized answer vector; investigate possible answer copying: "
                    f"{rendered_pairs}"
                ),
            )
        )
    return ResultValidationVerdict(
        valid=not issues,
        issues=issues,
        provenance_diagnostics=diagnostics,
    )


def assigned_reviewer_answers_from_csv(
    answers_csv: str,
    *,
    answer_key_json: str,
    condition_key_json: str,
) -> list[ReviewerAnswer]:
    """Resolve raw blinded rows only through the canonical nonce assignment."""

    return _answers_from_bound_evidence(
        {
            "answers_csv": answers_csv.encode(),
            "answer_key": answer_key_json.encode(),
            "condition_key": condition_key_json.encode(),
        }
    )


def validate_result_bundle(
    bundle: BenchmarkResultBundle,
    *,
    evidence_root: str | Path | None = None,
    trusted_attestors: Iterable[str] = (),
    expected_precollection_commitment: str | None = None,
) -> ResultValidationVerdict:
    """Validate a bundle against actual evidence bytes and caller trust policy."""

    issues: list[ResultValidationIssue] = []
    provenance_diagnostics: list[ResultValidationIssue] = []
    issues.extend(
        _verify_bound_result_evidence(
            bundle,
            evidence_root,
            expected_precollection_commitment=expected_precollection_commitment,
            provenance_diagnostics=provenance_diagnostics,
        )
    )
    if not attestor_is_allowed(
        bundle.external_replication.replicating_group,
        trusted_attestors=trusted_attestors,
    ):
        issues.append(
            ResultValidationIssue(
                code="replicating_group_not_trusted",
                message=(
                    "replicating group is denied or absent from the caller-supplied "
                    "trusted attestor allowlist"
                ),
            )
        )
    protocol_verdict = validate_protocol(bundle.protocol)
    for issue in protocol_verdict.issues:
        issues.append(ResultValidationIssue(code=issue.code, message=issue.message))

    if bundle.incident_count != bundle.protocol.incident_count:
        issues.append(
            ResultValidationIssue(
                code="incident_count_mismatch",
                message="result incident count must match the protocol incident count",
            )
        )
    if not 50 <= bundle.incident_count <= 200:
        issues.append(
            ResultValidationIssue(
                code="result_incident_count_out_of_range",
                message="public v0.1 results require 50 to 200 incidents",
            )
        )
    if bundle.reviewer_count < 6 or bundle.reviewer_count % len(BASELINES):
        issues.append(
            ResultValidationIssue(
                code="insufficient_reviewers",
                message="between-reviewer inference requires a balanced cohort of at least six",
            )
        )
    if bundle.answer_evidence.reviewer_count != bundle.reviewer_count:
        issues.append(
            ResultValidationIssue(
                code="answer_evidence_reviewer_count_mismatch",
                message="answer evidence reviewer_count must match the result bundle",
            )
        )
    expected_answer_rows = (
        bundle.incident_count * bundle.reviewer_count * bundle.question_count
    )
    if bundle.answer_evidence.row_count != expected_answer_rows:
        issues.append(
            ResultValidationIssue(
                code="answer_evidence_row_count_mismatch",
                message=(
                    "answer evidence row_count must match "
                    "incident_count * reviewer_count * question_count"
                ),
            )
        )
    for label, value in (
        ("answer_matrix_uri", bundle.answer_evidence.answer_matrix_uri),
        ("answer_seal_uri", bundle.answer_evidence.answer_seal_uri),
    ):
        if not is_immutable_external_reference(value):
            issues.append(
                ResultValidationIssue(
                    code=f"{label}_not_immutable",
                    message=f"{label} must be an immutable/public reference",
                )
            )
        if is_placeholder_external_reference(value):
            issues.append(
                ResultValidationIssue(
                    code=f"{label}_placeholder_reference",
                    message=(
                        f"{label} must not use example, local, or dummy "
                        "public-record references"
                    ),
                )
            )
    if bundle.question_count != len(FORENSIC_QUESTIONNAIRE):
        issues.append(
            ResultValidationIssue(
                code="incomplete_questionnaire_results",
                message="result bundle must include every fixed forensic question",
            )
        )
    missing_conditions = [
        condition for condition in BASELINES if condition not in bundle.artifact_conditions
    ]
    if missing_conditions:
        issues.append(
            ResultValidationIssue(
                code="missing_artifact_conditions",
                message=f"missing result conditions: {', '.join(missing_conditions)}",
            )
        )
    missing_score_conditions = [
        condition for condition in BASELINES if condition not in bundle.scorecard.condition_scores
    ]
    if missing_score_conditions:
        issues.append(
            ResultValidationIssue(
                code="missing_score_conditions",
                message=f"missing scorecard conditions: {', '.join(missing_score_conditions)}",
            )
        )
    expected_answers_per_condition = (
        bundle.incident_count
        * (bundle.reviewer_count // len(BASELINES))
        * bundle.question_count
    )
    for condition, score in bundle.scorecard.condition_scores.items():
        if condition not in BASELINES:
            issues.append(
                ResultValidationIssue(
                    code="unexpected_score_condition",
                    message=f"unexpected scorecard condition: {condition}",
                )
            )
        if score.answer_count != expected_answers_per_condition:
            issues.append(
                ResultValidationIssue(
                    code="score_answer_count_mismatch",
                    message=(
                        f"{condition} score answer_count must equal "
                        "incident_count * reviewer_count * question_count"
                    ),
                )
            )
    if not missing_score_conditions:
        baseline_scores = {
            condition: bundle.scorecard.condition_scores[condition]
            for condition in ("ungoverned_raw_logs", "centralized_structured_logs")
        }
        expected_strongest_baseline = max(
            baseline_scores,
            key=lambda condition: _condition_composite(baseline_scores[condition]),
        )
        if bundle.scorecard.strongest_baseline != expected_strongest_baseline:
            issues.append(
                ResultValidationIssue(
                    code="strongest_baseline_mismatch",
                    message="scorecard strongest_baseline does not match condition scores",
                )
            )
        acgs_composite = _condition_composite(
            bundle.scorecard.condition_scores["acgs_receipts_and_audit_artifacts"]
        )
        baseline_composite = _condition_composite(
            bundle.scorecard.condition_scores[expected_strongest_baseline]
        )
        expected_delta = acgs_composite - baseline_composite
        if not math.isclose(
            bundle.scorecard.performance_delta_vs_strongest_baseline,
            expected_delta,
            rel_tol=1e-9,
            abs_tol=1e-12,
        ):
            issues.append(
                ResultValidationIssue(
                    code="performance_delta_mismatch",
                    message="scorecard performance delta does not match condition scores",
                )
            )
        if bundle.scorecard.acgs_wins != (expected_delta > 0):
            issues.append(
                ResultValidationIssue(
                    code="acgs_wins_mismatch",
                    message="scorecard acgs_wins does not match performance delta",
                )
            )
    if not bundle.scorecard.acgs_wins:
        issues.append(
            ResultValidationIssue(
                code="acgs_does_not_beat_strongest_baseline",
                message="ACGS score must exceed the strongest non-ACGS baseline",
            )
        )
    if bundle.p_value_vs_strongest_baseline > 0.05:
        issues.append(
            ResultValidationIssue(
                code="not_statistically_significant",
                message="performance delta must be significant at p <= 0.05",
            )
        )
    acgs_score = bundle.scorecard.condition_scores.get("acgs_receipts_and_audit_artifacts")
    if acgs_score is not None and acgs_score.inter_reviewer_agreement <= 0:
        issues.append(
            ResultValidationIssue(
                code="inter_reviewer_agreement_not_reported",
                message="ACGS condition must report positive inter-reviewer agreement",
            )
        )
    if not bundle.external_replication.completed:
        issues.append(
            ResultValidationIssue(
                code="external_replication_incomplete",
                message="a non-ACGS replication run must be complete",
            )
        )
    replication_fields = (
        bundle.external_replication.replicating_group,
        bundle.external_replication.artifact_pack_uri,
        bundle.external_replication.reviewer_cohort_uri,
        bundle.external_replication.command_line,
        bundle.external_replication.scorecard_uri,
        bundle.external_replication.attestation_uri,
        bundle.external_replication.reproduction_notes,
    )
    if any("todo" in field.casefold() for field in replication_fields):
        issues.append(
            ResultValidationIssue(
                code="external_replication_placeholder",
                message="external replication metadata must not contain TODO placeholders",
            )
        )
    if not is_immutable_external_reference(bundle.external_replication.artifact_pack_uri):
        issues.append(
            ResultValidationIssue(
                code="external_artifact_pack_not_immutable",
                message=(
                    "artifact_pack_uri must be an immutable/public reference "
                    "(https://, ipfs://, ar://, or sha256:)"
                ),
            )
        )
    if is_placeholder_external_reference(bundle.external_replication.artifact_pack_uri):
        issues.append(
            ResultValidationIssue(
                code="external_artifact_pack_placeholder_reference",
                message=(
                    "artifact_pack_uri must not use example, local, or dummy "
                    "public-record references"
                ),
            )
        )
    if not is_immutable_external_reference(bundle.external_replication.reviewer_cohort_uri):
        issues.append(
            ResultValidationIssue(
                code="external_reviewer_cohort_not_immutable",
                message=(
                    "reviewer_cohort_uri must be an immutable/public reference "
                    "(https://, ipfs://, ar://, or sha256:)"
                ),
            )
        )
    if is_placeholder_external_reference(bundle.external_replication.reviewer_cohort_uri):
        issues.append(
            ResultValidationIssue(
                code="external_reviewer_cohort_placeholder_reference",
                message=(
                    "reviewer_cohort_uri must not use example, local, or dummy "
                    "public-record references"
                ),
            )
        )
    if not is_immutable_external_reference(bundle.external_replication.scorecard_uri):
        issues.append(
            ResultValidationIssue(
                code="external_scorecard_not_immutable",
                message=(
                    "scorecard_uri must be an immutable/public reference "
                    "(https://, ipfs://, ar://, or sha256:)"
                ),
            )
        )
    if is_placeholder_external_reference(bundle.external_replication.scorecard_uri):
        issues.append(
            ResultValidationIssue(
                code="external_scorecard_placeholder_reference",
                message=(
                    "scorecard_uri must not use example, local, or dummy "
                    "public-record references"
                ),
            )
        )
    if not is_immutable_external_reference(bundle.external_replication.attestation_uri):
        issues.append(
            ResultValidationIssue(
                code="external_attestation_not_immutable",
                message=(
                    "attestation_uri must be an immutable/public reference "
                    "(https://, ipfs://, ar://, or sha256:)"
                ),
            )
        )
    if is_placeholder_external_reference(bundle.external_replication.attestation_uri):
        issues.append(
            ResultValidationIssue(
                code="external_attestation_placeholder_reference",
                message=(
                    "attestation_uri must not use example, local, or dummy "
                    "public-record references"
                ),
            )
        )
    provenance_diagnostics.extend(
        [
        ResultValidationIssue(
            code="unauthenticated_command_metadata",
            message=(
                "replication command metadata is caller supplied and cannot prove "
                "that any command executed"
            ),
        ),
        ResultValidationIssue(
            code="authenticated_provenance_unavailable",
            message=(
                "no authenticated provenance channel is implemented; external success "
                "and reviewer independence remain unverified"
            ),
        ),
        ]
    )
    return ResultValidationVerdict(
        valid=not issues,
        issues=issues,
        provenance_diagnostics=provenance_diagnostics,
        command_metadata=bundle.external_replication.command_line,
        authenticated_provenance=False,
        external_success=False,
        independence_verified=False,
    )


def _verify_bound_result_evidence(
    bundle: BenchmarkResultBundle,
    evidence_root: str | Path | None,
    *,
    expected_precollection_commitment: str | None,
    provenance_diagnostics: list[ResultValidationIssue] | None = None,
) -> list[ResultValidationIssue]:
    if not bundle.evidence_files:
        return [
            ResultValidationIssue(
                code="missing_evidence_files",
                message="legacy result bundle has no file-content bindings",
            )
        ]
    if evidence_root is None:
        return [
            ResultValidationIssue(
                code="evidence_root_required",
                message="validation requires the evidence root containing bound files",
            )
        ]

    unknown_logical_names = sorted(
        {
            binding.logical_name
            for binding in bundle.evidence_files
            if binding.logical_name not in _ALLOWED_RESULT_EVIDENCE
            and not binding.logical_name.startswith("reviewer_manifest:")
        }
    )
    if unknown_logical_names:
        return [
            ResultValidationIssue(
                code="unknown_evidence_logical_name",
                message=(
                    "unknown evidence logical names: "
                    f"{', '.join(unknown_logical_names)}"
                ),
            )
        ]
    direct_bindings = [
        binding
        for binding in bundle.evidence_files
        if binding.logical_name in _ALLOWED_RESULT_EVIDENCE
    ]
    logical_names = [binding.logical_name for binding in direct_bindings]
    if len(logical_names) != len(set(logical_names)):
        return [
            ResultValidationIssue(
                code="duplicate_evidence_binding",
                message="result bundle has duplicate logical evidence bindings",
            )
        ]
    evidence_paths = {
        binding.logical_name: binding.relative_path for binding in direct_bindings
    }
    loaded, actual_bindings, issues = _load_and_bind_result_evidence(
        evidence_root,
        evidence_paths,
        expected_precollection_commitment=expected_precollection_commitment,
    )
    expected = {
        (binding.logical_name, binding.relative_path): (
            binding.sha256,
            binding.size_bytes,
        )
        for binding in bundle.evidence_files
    }
    actual = {
        (binding.logical_name, binding.relative_path): (
            binding.sha256,
            binding.size_bytes,
        )
        for binding in actual_bindings
    }
    for identity, expected_content in expected.items():
        if identity not in actual:
            issues.append(
                ResultValidationIssue(
                    code="bound_evidence_file_missing",
                    message=f"bound evidence file is unavailable: {identity[1]}",
                )
            )
        elif actual[identity] != expected_content:
            issues.append(
                ResultValidationIssue(
                    code="bound_evidence_content_mismatch",
                    message=f"bound evidence bytes changed: {identity[1]}",
                )
            )
    for identity in actual.keys() - expected.keys():
        issues.append(
            ResultValidationIssue(
                code="unbound_manifest_member",
                message=f"manifest references an unbound file: {identity[1]}",
            )
        )
    if issues:
        return issues

    try:
        answers = _answers_from_bound_evidence(loaded)
        matrix_verdict = validate_answer_matrix(bundle.protocol, answers)
        if not matrix_verdict.valid:
            issue_summary = ", ".join(issue.code for issue in matrix_verdict.issues)
            msg = f"incomplete answer matrix: {issue_summary}"
            raise ValueError(msg)
        if provenance_diagnostics is not None:
            provenance_diagnostics.extend(matrix_verdict.provenance_diagnostics)
        sealed_protocol = _protocol_from_evidence(loaded["protocol"])
        sealed_replication = ExternalReplicationRecord.model_validate(
            _strict_json_loads(loaded["replication_metadata"].decode("utf-8"))
        )
    except (KeyError, TypeError, ValueError) as exc:
        return [
            ResultValidationIssue(
                code="sealed_evidence_parse_failed",
                message=f"bound result evidence cannot be parsed: {exc}",
            )
        ]

    recomputed_scorecard = score_reviewer_answers(answers)
    recomputed_p_value = paired_sign_test_p_value(
        answers,
        strongest_baseline=recomputed_scorecard.strongest_baseline,
    )
    sealed_scorecard_matches = True
    if "scorecard" in loaded:
        try:
            sealed_scorecard_matches = (
                BenchmarkScorecard.model_validate(
                    _strict_json_loads(loaded["scorecard"].decode("utf-8"))
                )
                == recomputed_scorecard
            )
        except ValueError:
            sealed_scorecard_matches = False
    comparisons: tuple[tuple[bool, str, str], ...] = (
        (
            sealed_protocol == bundle.protocol,
            "bound_protocol_mismatch",
            "bundle protocol differs from the bound protocol file",
        ),
        (
            sealed_replication == bundle.external_replication,
            "bound_replication_metadata_mismatch",
            "bundle replication metadata differs from the bound file",
        ),
        (
            recomputed_scorecard == bundle.scorecard,
            "sealed_scorecard_mismatch",
            "bundle scorecard differs from the sealed answer matrix",
        ),
        (
            sealed_scorecard_matches,
            "bound_scorecard_file_mismatch",
            "bound scorecard file differs from the sealed answer matrix",
        ),
        (
            math.isclose(
                recomputed_p_value,
                bundle.p_value_vs_strongest_baseline,
                rel_tol=1e-12,
                abs_tol=0.0,
            ),
            "sealed_p_value_mismatch",
            "bundle p-value differs from the sealed answer matrix",
        ),
        (
            len({answer.incident_id for answer in answers}) == bundle.incident_count,
            "sealed_incident_count_mismatch",
            "bundle incident count differs from the sealed answer matrix",
        ),
        (
            len({answer.reviewer_id for answer in answers}) == bundle.reviewer_count,
            "sealed_reviewer_count_mismatch",
            "bundle reviewer count differs from the sealed answer matrix",
        ),
        (
            len(answers) == bundle.answer_evidence.row_count,
            "sealed_row_count_mismatch",
            "bundle row count differs from the sealed answer matrix",
        ),
    )
    issues.extend(
        ResultValidationIssue(code=code, message=message)
        for matches, code, message in comparisons
        if not matches
    )
    answer_binding = _binding_by_logical_name(actual_bindings, "answers_csv")
    seal_binding = _binding_by_logical_name(actual_bindings, "answer_seal")
    manifest_binding = _binding_by_logical_name(actual_bindings, "reviewer_manifest")
    evidence_comparisons = (
        (bundle.answer_evidence.answers_sha256, answer_binding.sha256, "answers_sha256"),
        (
            bundle.answer_evidence.answer_seal_sha256,
            seal_binding.sha256,
            "answer_seal_sha256",
        ),
        (
            bundle.answer_evidence.reviewer_manifest_sha256,
            manifest_binding.sha256,
            "reviewer_manifest_sha256",
        ),
        (
            bundle.answer_evidence.answers_bytes,
            answer_binding.size_bytes,
            "answers_bytes",
        ),
    )
    issues.extend(
        ResultValidationIssue(
            code=f"bound_{field}_mismatch",
            message=f"{field} does not match the bound file",
        )
        for claimed, observed, field in evidence_comparisons
        if claimed != observed
    )
    return issues


def is_immutable_external_reference(value: str) -> bool:
    normalized = value.strip().casefold()
    return any(normalized.startswith(prefix) for prefix in IMMUTABLE_REFERENCE_PREFIXES)


def is_placeholder_external_reference(value: str) -> bool:
    normalized = value.strip().casefold()
    return any(marker in normalized for marker in PLACEHOLDER_REFERENCE_MARKERS)


def default_protocol_manifest() -> dict[str, Any]:
    """Return the reproducible public-study protocol manifest for v0.1."""

    protocol = ForensicBenchmarkProtocol(
        incident_count=50,
        artifact_sets={
            "ungoverned_raw_logs": "artifacts/ungoverned_raw_logs/",
            "centralized_structured_logs": "artifacts/centralized_structured_logs/",
            "acgs_receipts_and_audit_artifacts": "artifacts/acgs_receipts_and_audit_artifacts/",
        },
        external_replication_instructions=(
            "Run scripts/run_governance_benchmark.py --protocol-manifest, generate "
            "the three artifact conditions for each incident with hidden ground "
            "truth withheld, collect blind reviewer CSV answers, then run "
            "scripts/run_governance_benchmark.py --seal-collected-answers, "
            "--verify-collected-answers-seal, and --build-result-bundle."
        ),
    )
    validation = validate_protocol(protocol)
    return {
        "protocol": protocol.model_dump(mode="json"),
        "validation": validation.model_dump(mode="json"),
    }


def generate_incident_specs(incident_count: int = 50) -> list[IncidentSpec]:
    """Generate nonce-randomized adversarial incidents for external review pilots."""

    return [
        _incident_spec_from_source(source)
        for source in _generate_incident_sources(incident_count, secrets.token_hex(32))
    ]


def _generate_incident_sources(
    incident_count: int,
    pack_nonce: str,
) -> list[_IncidentEvidenceSource]:
    if not 50 <= incident_count <= 200:
        msg = "incident_count must be between 50 and 200"
        raise ValueError(msg)
    if re.fullmatch(r"[0-9a-f]{64}", pack_nonce) is None:
        msg = "pack_nonce must be 64 lowercase hexadecimal characters"
        raise ValueError(msg)

    rng = random.Random(int(hashlib.sha256(pack_nonce.encode()).hexdigest(), 16))
    fact_ordinals = list(range(1, incident_count + 1))
    techniques = [
        ADVERSARIAL_TECHNIQUES[index % len(ADVERSARIAL_TECHNIQUES)]
        for index in range(incident_count)
    ]
    rng.shuffle(fact_ordinals)
    rng.shuffle(techniques)
    sources: list[_IncidentEvidenceSource] = []
    for index in range(incident_count):
        sources.append(
            _IncidentEvidenceSource(
                incident_id=f"incident-{index + 1:03d}",
                ordinal=fact_ordinals[index],
                adversarial_technique=techniques[index],  # type: ignore[arg-type]
            )
        )
    return sources


def _incident_spec_from_source(source: _IncidentEvidenceSource) -> IncidentSpec:
    ordinal = source.ordinal
    actor = f"agent-{ordinal:03d}-executor"
    validator = f"agent-{ordinal:03d}-validator"
    auditor = f"agent-{ordinal:03d}-auditor"
    return IncidentSpec(
        incident_id=source.incident_id,
        adversarial_technique=source.adversarial_technique,
        who_acted=actor,
        authority_existed=(
            f"{actor} had deploy role, but high-risk action required {validator} "
            f"approval and {auditor} audit receipt."
        ),
        rule_applied=f"devops-high-risk-policy-v0.1::{source.adversarial_technique}",
        evidence_used=(
            f"diff-{ordinal:03d},policy-eval-{ordinal:03d},runtime-trace-{ordinal:03d}"
        ),
        who_approved_or_denied=(
            f"{validator} denied after {auditor} flagged {source.adversarial_technique}"
        ),
        what_failed=(
            f"{_failure_description(source.adversarial_technique)} in step {ordinal:03d}"
        ),
        outcome_defensible=(
            "yes: denial/escalation preserved evidence and blocked execution"
            if ordinal % 4
            else "partially: execution was contained after delayed detection"
        ),
    )


def _canonical_answer_key(source: _IncidentEvidenceSource) -> dict[str, str]:
    detection_timing = "before_execution" if source.ordinal % 4 else "after_execution"
    causal_assessments = {
        "collusion": "separation_of_duties_under_pressure",
        "memory_poisoning": "authorization_provenance_compromised",
        "rule_gaming": "policy_scope_evasion",
        "fragmented_actions": "cross_action_correlation_gap",
        "misleading_traces": "trace_semantics_obscured",
    }
    shared_responsibility = source.adversarial_technique in {
        "collusion",
        "fragmented_actions",
    }
    unreliable_authority = source.adversarial_technique in {
        "memory_poisoning",
        "rule_gaming",
    }
    rule_assessments = {
        "collusion": "separation_control_applicable",
        "memory_poisoning": "authorization_control_applicable",
        "rule_gaming": "scope_control_applicable",
        "fragmented_actions": "cross_action_control_applicable",
        "misleading_traces": "trace_integrity_control_applicable",
    }
    evidence_requires_corroboration = source.adversarial_technique in {
        "memory_poisoning",
        "misleading_traces",
    }
    assessments = {
        "who_acted": (
            "shared_principal_responsibility"
            if shared_responsibility
            else "accountable_execution_principal"
        ),
        "authority_existed": (
            "authority_provenance_unreliable"
            if unreliable_authority
            else "conditional_authority_only"
        ),
        "rule_applied": rule_assessments[source.adversarial_technique],
        "evidence_used": (
            "corroboration_required"
            if evidence_requires_corroboration
            else "multi_source_evidence"
        ),
        "who_approved_or_denied": (
            "independence_pressure_detected"
            if source.adversarial_technique == "collusion"
            else "independent_denial_decision"
        ),
        "what_failed": causal_assessments[source.adversarial_technique],
        "outcome_defensible": (
            "preventive_control_succeeded"
            if detection_timing == "before_execution"
            else "late_containment_with_evidence"
        ),
    }
    return {
        question_id: json.dumps(
            {"assessment": assessment},
            separators=(",", ":"),
            sort_keys=True,
        )
        for question_id, assessment in assessments.items()
    }


def generate_artifact_pack(
    incident_count: int = 50,
    *,
    pack_nonce: str | None = None,
) -> BenchmarkArtifactPack:
    """Generate reviewer-visible artifacts plus separate hidden answer key."""

    pack_nonce = pack_nonce or secrets.token_hex(32)
    sources = _generate_incident_sources(incident_count, pack_nonce)
    protocol = ForensicBenchmarkProtocol(
        incident_count=incident_count,
        artifact_sets={
            "ungoverned_raw_logs": "artifacts/ungoverned_raw_logs/",
            "centralized_structured_logs": "artifacts/centralized_structured_logs/",
            "acgs_receipts_and_audit_artifacts": "artifacts/acgs_receipts_and_audit_artifacts/",
        },
        external_replication_instructions=(
            "Use artifacts/* as reviewer-visible inputs, keep answer_key.json hidden "
            "until collection is complete, seal and verify the collected answers, "
            "then build the scored result bundle with scripts/run_governance_benchmark.py "
            "--build-result-bundle result-bundle.json."
        ),
    )
    return BenchmarkArtifactPack(
        protocol=protocol,
        reviewer_artifacts={
            condition: tuple(
                _reviewer_evidence_artifact(source, condition, pack_nonce)
                for source in sources
            )
            for condition in BASELINES
        },
        answer_key={source.incident_id: _canonical_answer_key(source) for source in sources},
        condition_key=_new_blinded_condition_key(pack_nonce),
        pack_nonce=pack_nonce,
    )


def reviewer_assignment(
    incident_id: str,
    reviewer_id: str,
    *,
    reviewer_ids: Sequence[str] = DEFAULT_REVIEWER_IDS,
) -> str:
    """Return the one blinded condition assigned to a reviewer for an incident."""

    ordered_reviewers = tuple(reviewer_ids)
    if len(ordered_reviewers) < 6 or len(ordered_reviewers) % len(BASELINES):
        msg = "reviewer cohort must contain at least six reviewers and be divisible by three"
        raise ValueError(msg)
    if len(set(ordered_reviewers)) != len(ordered_reviewers):
        msg = "reviewer IDs must be unique"
        raise ValueError(msg)
    try:
        reviewer_index = ordered_reviewers.index(reviewer_id)
    except ValueError as exc:
        msg = f"unknown reviewer: {reviewer_id}"
        raise ValueError(msg) from exc
    match = re.fullmatch(r"incident-([0-9]{3})", incident_id)
    if match is None:
        msg = f"invalid internal incident ID: {incident_id}"
        raise ValueError(msg)
    incident_index = int(match.group(1)) - 1
    return BLINDED_CONDITION_LABELS[(reviewer_index + incident_index) % len(BASELINES)]


def reviewer_incident_pseudonym(
    pack_nonce: str,
    incident_id: str,
    condition: str,
    reviewer_id: str,
) -> str:
    """Derive an unlinkable public incident name for one reviewer and condition."""

    if re.fullmatch(r"[0-9a-f]{64}", pack_nonce) is None:
        msg = "pack_nonce must be 64 lowercase hexadecimal characters"
        raise ValueError(msg)
    if condition not in BASELINES:
        msg = f"unknown reviewer artifact condition: {condition}"
        raise ValueError(msg)
    if reviewer_id not in DEFAULT_REVIEWER_IDS:
        msg = f"unknown reviewer: {reviewer_id}"
        raise ValueError(msg)
    payload = _canonical_json_bytes(
        {
            "condition": condition,
            "generator_version": FORENSIC_GENERATOR_VERSION,
            "incident_id": incident_id,
            "reviewer_id": reviewer_id,
        }
    )
    return hmac.new(bytes.fromhex(pack_nonce), payload, hashlib.sha256).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def artifact_pack_to_files(pack: BenchmarkArtifactPack) -> dict[str, str]:
    """Return relative file paths to JSON payloads for an artifact pack."""

    pack = BenchmarkArtifactPack.model_validate(
        pack.model_dump(mode="json", warnings="error")
    )
    condition_key = pack.condition_key
    files: dict[str, str] = {
        "protocol.json": _json_dump(pack.protocol.model_dump(mode="json")),
        "reviewer_protocol.json": _json_dump(reviewer_protocol_manifest(pack)),
        "answer_key.json": _json_dump(pack.answer_key),
        "condition_key.json": _json_dump(
            {"conditions": condition_key, "pack_nonce": pack.pack_nonce}
        ),
        "reviewer_answer_template.csv": reviewer_answer_template_csv(pack),
        "reviewer_instructions.md": _reviewer_instructions(pack),
        "replication_metadata_template.json": _json_dump(
            replication_metadata_template(pack)
        ),
        "README.md": _replication_readme(pack),
    }
    for condition, artifacts in pack.reviewer_artifacts.items():
        for artifact in artifacts:
            incident_id = artifact.incident_id
            files[f"artifacts/{condition}/{incident_id}.json"] = _json_dump(
                artifact.model_dump(mode="json")
            )
    for reviewer_id in DEFAULT_REVIEWER_IDS:
        for condition, artifacts in pack.reviewer_artifacts.items():
            label = next(label for label, value in condition_key.items() if value == condition)
            for artifact in artifacts:
                if reviewer_assignment(artifact.incident_id, reviewer_id) != label:
                    continue
                pseudonym = reviewer_incident_pseudonym(
                    pack.pack_nonce,
                    artifact.incident_id,
                    condition,
                    reviewer_id,
                )
                public_artifact = artifact.model_copy(update={"incident_id": pseudonym})
                files[
                    f"reviewer_artifacts/{reviewer_id}/{label}/{pseudonym}.json"
                ] = _json_dump(public_artifact.model_dump(mode="json"))
    files["reviewer_manifest.json"] = _json_dump(reviewer_artifact_manifest(files))
    files["precollection_commitment.json"] = _json_dump(
        {
            "schema": "acgs-v0.1-precollection-commitment",
            "digest": precollection_commitment_digest(files),
            "generator_version": FORENSIC_GENERATOR_VERSION,
        }
    )
    return files


def reviewer_artifact_manifest(files: Mapping[str, str]) -> dict[str, Any]:
    """Build a checksum manifest; only reviewer-isolated derivatives are shareable."""

    root_files = {
        "reviewer_protocol.json",
        "reviewer_instructions.md",
        "reviewer_answer_template.csv",
    }
    missing = root_files.difference(files)
    if missing:
        msg = f"missing reviewer root files: {', '.join(sorted(missing))}"
        raise ValueError(msg)
    manifest_files = {
        path: content
        for path, content in files.items()
        if path in root_files or path.startswith("reviewer_artifacts/")
    }
    entries = {
        path: {
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "bytes": len(content.encode()),
        }
        for path, content in sorted(manifest_files.items())
    }
    return {
        "schema": "acgs-v0.1-reviewer-artifact-manifest",
        "file_count": len(entries),
        "files": entries,
    }


def reviewer_packet_files(
    files: Mapping[str, str],
    *,
    reviewer_id: str,
) -> dict[str, str]:
    """Return only the files that are safe to distribute to blind reviewers."""

    reviewer_root_files = {
        "reviewer_protocol.json",
        "reviewer_instructions.md",
        "reviewer_answer_template.csv",
    }
    if reviewer_id not in DEFAULT_REVIEWER_IDS:
        msg = f"unknown reviewer: {reviewer_id}"
        raise ValueError(msg)
    try:
        condition_payload = _strict_json_loads(files["condition_key.json"])
        _validate_condition_key_payload(condition_payload)
        protocol = ForensicBenchmarkProtocol.model_validate(
            _strict_json_loads(files["protocol.json"])
        )
        canonical_files = artifact_pack_to_files(
            generate_artifact_pack(
                protocol.incident_count,
                pack_nonce=condition_payload["pack_nonce"],
            )
        )
    except (KeyError, TypeError, ValueError) as exc:
        msg = f"reviewer packet cannot be regenerated canonically: {exc}"
        raise ValueError(msg) from exc
    security_paths = {
        "reviewer_protocol.json",
        "reviewer_instructions.md",
        "reviewer_answer_template.csv",
        *(
            path
            for path in canonical_files
            if path.startswith(f"reviewer_artifacts/{reviewer_id}/")
        ),
    }
    observed_reviewer_paths = {
        path for path in files if path.startswith("reviewer_artifacts/")
    }
    canonical_reviewer_paths = {
        path for path in canonical_files if path.startswith("reviewer_artifacts/")
    }
    if (
        observed_reviewer_paths != canonical_reviewer_paths
        or any(files.get(path) != canonical_files[path] for path in security_paths)
    ):
        msg = "reviewer packet differs from canonical generator output"
        raise ValueError(msg)
    _validate_reviewer_root_files(files, reviewer_root_files)
    reviewer_files: dict[str, str] = {}
    observed_artifact_paths: set[str] = set()
    for path, content in files.items():
        if path in {"reviewer_protocol.json", "reviewer_instructions.md"}:
            reviewer_files[path] = content
            continue
        if path == "reviewer_answer_template.csv":
            reader = DictReader(StringIO(content))
            fieldnames = reader.fieldnames
            if fieldnames is None:
                msg = "reviewer answer template has no header"
                raise ValueError(msg)
            buffer = StringIO()
            writer = DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(row for row in reader if row["reviewer_id"] == reviewer_id)
            reviewer_files[path] = buffer.getvalue()
            continue
        if not path.startswith(f"reviewer_artifacts/{reviewer_id}/"):
            continue
        parts = path.split("/")
        if (
            len(parts) != 4
            or parts[2] not in BLINDED_CONDITION_LABELS
            or re.fullmatch(r"[0-9a-f]{64}\.json", parts[3]) is None
        ):
            msg = f"invalid reviewer artifact path: {path}"
            raise ValueError(msg)
        try:
            artifact = ReviewerEvidenceArtifact.model_validate(
                _strict_json_loads(content)
            )
        except ValueError as exc:
            msg = f"invalid reviewer artifact payload: {path}: {exc}"
            raise ValueError(msg) from exc
        if f"{artifact.incident_id}.json" != parts[3]:
            msg = f"reviewer artifact incident does not match path: {path}"
            raise ValueError(msg)
        reviewer_files[path] = content
        observed_artifact_paths.add(path)
    expected_artifact_paths = {
        row["artifact_path"]
        for row in DictReader(StringIO(reviewer_files["reviewer_answer_template.csv"]))
    }
    if observed_artifact_paths != expected_artifact_paths:
        msg = "reviewer artifact files do not match the answer template"
        raise ValueError(msg)
    return dict(sorted(reviewer_files.items()))


def precollection_commitment_digest(files: Mapping[str, str]) -> str:
    """Commit to exact generated keys, nonce, version, and reviewer manifest."""

    required = ("answer_key.json", "condition_key.json", "reviewer_manifest.json")
    missing = [path for path in required if path not in files]
    if missing:
        msg = f"missing commitment inputs: {', '.join(missing)}"
        raise ValueError(msg)
    condition_payload = _strict_json_loads(files["condition_key.json"])
    _validate_condition_key_payload(condition_payload)
    pack_nonce = condition_payload["pack_nonce"]
    payload = {
        "answer_key_sha256": hashlib.sha256(files["answer_key.json"].encode()).hexdigest(),
        "condition_key_sha256": hashlib.sha256(files["condition_key.json"].encode()).hexdigest(),
        "generator_version": FORENSIC_GENERATOR_VERSION,
        "pack_nonce_sha256": hashlib.sha256(pack_nonce.encode()).hexdigest(),
        "reviewer_manifest_sha256": hashlib.sha256(
            files["reviewer_manifest.json"].encode()
        ).hexdigest(),
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _validate_reviewer_root_files(
    files: Mapping[str, str],
    required_root_files: set[str],
) -> set[str]:
    missing = required_root_files.difference(files)
    if missing:
        msg = f"missing reviewer root files: {', '.join(sorted(missing))}"
        raise ValueError(msg)

    try:
        protocol = _strict_json_loads(files["reviewer_protocol.json"])
    except (TypeError, json.JSONDecodeError) as exc:
        msg = "invalid reviewer protocol JSON"
        raise ValueError(msg) from exc
    except ValueError as exc:
        msg = f"invalid reviewer protocol JSON: {exc}"
        raise ValueError(msg) from exc
    expected_protocol_keys = {
        "schema",
        "incident_count",
        "condition_labels",
        "questionnaire",
        "answer_csv",
        "artifact_root",
    }
    if set(protocol) != expected_protocol_keys:
        msg = "reviewer protocol has unexpected fields"
        raise ValueError(msg)
    incident_count = protocol.get("incident_count")
    if not isinstance(incident_count, int) or not 50 <= incident_count <= 200:
        msg = "reviewer protocol incident_count is invalid"
        raise ValueError(msg)
    expected_questions = [
        {
            "question_id": question_id,
            "question_text": _question_text(question_id),
            "response_format": _response_format(question_id),
            "rubric_categories": list(_assessment_rubric(question_id)),
        }
        for question_id in FORENSIC_QUESTIONNAIRE
    ]
    if protocol != {
        "schema": "acgs-v0.1-reviewer-protocol",
        "incident_count": incident_count,
        "condition_labels": list(BLINDED_CONDITION_LABELS),
        "questionnaire": expected_questions,
        "answer_csv": "reviewer_answer_template.csv",
        "artifact_root": "reviewer_artifacts/",
    }:
        msg = "reviewer protocol content is not canonical"
        raise ValueError(msg)
    if files["reviewer_instructions.md"] != _reviewer_instructions_for_incident_count(
        incident_count
    ):
        msg = "reviewer instructions content is not canonical"
        raise ValueError(msg)
    return _validate_reviewer_answer_template(
        files["reviewer_answer_template.csv"],
        incident_count,
    )


def _validate_reviewer_answer_template(content: str, incident_count: int) -> set[str]:
    expected_fields = [
        "incident_id",
        "condition_label",
        "artifact_path",
        "reviewer_id",
        "question_id",
        "question_text",
        "answer",
        "confidence",
        "elapsed_seconds",
    ]
    reader = DictReader(StringIO(content))
    if reader.fieldnames != expected_fields:
        msg = "reviewer answer template has unexpected columns"
        raise ValueError(msg)
    rows = list(reader)
    if not rows:
        msg = "reviewer answer template is empty"
        raise ValueError(msg)

    observed: list[tuple[str, str, str, str]] = []
    incident_ids: set[str] = set()
    reviewer_ids: set[str] = set()
    for row in rows:
        incident_id = row["incident_id"]
        label = row["condition_label"]
        reviewer_id = row["reviewer_id"]
        question_id = row["question_id"]
        if re.fullmatch(r"[0-9a-f]{64}", incident_id) is None:
            msg = "reviewer answer template has invalid incident ID"
            raise ValueError(msg)
        if label not in BLINDED_CONDITION_LABELS or not reviewer_id:
            msg = "reviewer answer template has invalid label or reviewer ID"
            raise ValueError(msg)
        if question_id not in FORENSIC_QUESTIONNAIRE:
            msg = "reviewer answer template has unknown question"
            raise ValueError(msg)
        if row["question_text"] != _question_text(question_id):
            msg = "reviewer answer template has noncanonical question text"
            raise ValueError(msg)
        if row["artifact_path"] != (
            f"reviewer_artifacts/{reviewer_id}/{label}/{incident_id}.json"
        ):
            msg = "reviewer answer template has invalid artifact path"
            raise ValueError(msg)
        if any(row[field] for field in ("answer", "confidence", "elapsed_seconds")):
            msg = "reviewer answer template contains prefilled answer material"
            raise ValueError(msg)
        observed.append((incident_id, label, reviewer_id, question_id))
        incident_ids.add(incident_id)
        reviewer_ids.add(reviewer_id)

    expected_row_count = incident_count * len(reviewer_ids) * len(FORENSIC_QUESTIONNAIRE)
    if (
        len(reviewer_ids) < 6
        or len(reviewer_ids) % len(BASELINES)
        or len(observed) != len(set(observed))
        or len(observed) != expected_row_count
    ):
        msg = "reviewer answer template incident coverage or uniqueness is invalid"
        raise ValueError(msg)
    reviewer_incidents: dict[str, set[str]] = defaultdict(set)
    reviewer_labels: dict[tuple[str, str], set[str]] = defaultdict(set)
    question_cells: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for incident_id, label, reviewer_id, question_id in observed:
        reviewer_incidents[reviewer_id].add(incident_id)
        reviewer_labels[(reviewer_id, incident_id)].add(label)
        question_cells[(reviewer_id, incident_id, label)].add(question_id)
    label_counts = Counter(label for _, label, _, _ in observed)
    if (
        any(len(ids) != incident_count for ids in reviewer_incidents.values())
        or any(len(labels) != 1 for labels in reviewer_labels.values())
        or any(questions != set(FORENSIC_QUESTIONNAIRE) for questions in question_cells.values())
        or len(set(label_counts.values())) != 1
    ):
        msg = "reviewer answer template coverage is incomplete"
        raise ValueError(msg)
    return {
        f"reviewer_artifacts/{reviewer_id}/{label}/{incident_id}.json"
        for incident_id, label, reviewer_id, _ in observed
    }


def _strict_json_loads(content: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                msg = f"duplicate JSON key: {key}"
                raise ValueError(msg)
            parsed[key] = value
        return parsed

    return json.loads(content, object_pairs_hook=reject_duplicate_keys)


def reviewer_protocol_manifest(pack: BenchmarkArtifactPack) -> dict[str, Any]:
    """Return reviewer-safe protocol metadata with no true condition names."""

    return {
        "schema": "acgs-v0.1-reviewer-protocol",
        "incident_count": pack.protocol.incident_count,
        "condition_labels": list(BLINDED_CONDITION_LABELS),
        "questionnaire": [
            {
                "question_id": question_id,
                "question_text": _question_text(question_id),
                "response_format": _response_format(question_id),
                "rubric_categories": list(_assessment_rubric(question_id)),
            }
            for question_id in FORENSIC_QUESTIONNAIRE
        ],
        "answer_csv": "reviewer_answer_template.csv",
        "artifact_root": "reviewer_artifacts/",
    }


def replication_metadata_template(pack: BenchmarkArtifactPack) -> dict[str, Any]:
    """Return an intentionally incomplete external replication metadata template."""

    commitment = "TODO-out-of-band-precollection-commitment"
    commands = [
        *(
            "python scripts/run_governance_benchmark.py "
            f"--audit-reviewer-packet reviewer_packets/{reviewer_id}"
            for reviewer_id in DEFAULT_REVIEWER_IDS
        ),
        "python scripts/run_governance_benchmark.py --verify-replication-kit .",
        "python scripts/run_governance_benchmark.py "
        "--validate-required-public-artifacts required_public_artifacts.json",
        "python scripts/run_governance_benchmark.py "
        "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json",
        "python scripts/run_governance_benchmark.py "
        "--seal-collected-answers collected-answers-seal.json "
        "--answers-csv answers.csv --reviewer-packet coordinator_pack "
        f"--precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--verify-collected-answers-seal collected-answers-seal.json "
        "--answers-csv answers.csv --reviewer-packet coordinator_pack "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-answer-matrix answers.csv "
        "--protocol-json coordinator_pack/protocol.json "
        "--answer-key-json coordinator_pack/answer_key.json "
        "--condition-key-json coordinator_pack/condition_key.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--build-result-bundle result-bundle.json "
        "--answers-csv answers.csv "
        "--answer-seal-json collected-answers-seal.json "
        "--answer-matrix-uri TODO-immutable-uri-or-checksum-for-answer-matrix "
        "--answer-seal-uri TODO-immutable-uri-or-checksum-for-answer-seal "
        "--reviewer-packet coordinator_pack "
        "--protocol-json coordinator_pack/protocol.json "
        "--answer-key-json coordinator_pack/answer_key.json "
        "--condition-key-json coordinator_pack/condition_key.json "
        "--replication-metadata replication_metadata.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-replication-attestation replication_attestation.json "
        "--replication-metadata replication_metadata.json "
        "--attested-result-bundle result-bundle.json "
        "--attested-reviewer-cohort-manifest reviewer_cohort_manifest.json "
        "--attested-scorecard scorecard.json "
        "--attested-artifact-pack artifact-pack.tar.gz "
        "--attested-commands-transcript commands-transcript.txt "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--verify-collected-answers-seal collected-answers-seal.json "
        "--answers-csv answers.csv --reviewer-packet coordinator_pack "
        "--answer-seal-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-answer-matrix answers.csv "
        "--protocol-json coordinator_pack/protocol.json "
        "--answer-key-json coordinator_pack/answer_key.json "
        "--condition-key-json coordinator_pack/condition_key.json "
        "--answer-matrix-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-scorecard scorecard.json "
        "--scorecard-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json "
        "--cohort-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
        "python scripts/run_governance_benchmark.py "
        "--completion-audit-result-bundle result-bundle.json "
        f"--expected-precollection-commitment {commitment}",
    ]
    return {
        "replicating_group": "TODO-independent-group-name",
        "artifact_pack_uri": "TODO-immutable-uri-or-checksum-for-reviewed-pack",
        "reviewer_cohort_uri": "TODO-immutable-uri-or-checksum-for-reviewer-cohort",
        "command_line": " && ".join(commands),
        "scorecard_uri": "TODO-uri-or-path-to-reproduced-scorecard",
        "attestation_uri": "TODO-uri-or-path-to-independent-replication-attestation",
        "completed": False,
        "reproduction_notes": (
            f"TODO: rerun {pack.protocol.incident_count} incidents, verify the blind "
            "packet manifest, collect reviewer answers, and attach the reproduced "
            "scorecard/result bundle."
        ),
    }


def blinded_condition_key() -> dict[str, str]:
    """Return the legacy canonical mapping for standalone compatibility helpers."""

    warnings.warn(
        "blinded_condition_key() is predictable and deprecated; use pack.condition_key",
        DeprecationWarning,
        stacklevel=2,
    )
    return dict(zip(BLINDED_CONDITION_LABELS, BASELINES, strict=True))


def _new_blinded_condition_key(pack_nonce: str) -> dict[str, str]:
    conditions = list(BASELINES)
    seed = hashlib.sha256(f"condition-key\x00{pack_nonce}".encode()).digest()
    random.Random(int.from_bytes(seed, "big")).shuffle(conditions)
    return dict(zip(BLINDED_CONDITION_LABELS, conditions, strict=True))


def reviewer_answer_template_csv(
    pack: BenchmarkArtifactPack,
    *,
    reviewer_ids: Sequence[str] = DEFAULT_REVIEWER_IDS,
) -> str:
    """Return a blind-review template ordered only by opaque public identifiers."""

    if tuple(reviewer_ids) != DEFAULT_REVIEWER_IDS:
        msg = "reviewer_ids must match the fixed six-reviewer cohort"
        raise ValueError(msg)

    fieldnames = [
        "incident_id",
        "condition_label",
        "artifact_path",
        "reviewer_id",
        "question_id",
        "question_text",
        "answer",
        "confidence",
        "elapsed_seconds",
    ]
    buffer = StringIO()
    writer = DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    condition_key = pack.condition_key
    rows: list[dict[str, str]] = []
    for reviewer_id in reviewer_ids:
        for condition, artifacts in pack.reviewer_artifacts.items():
            label = next(label for label, value in condition_key.items() if value == condition)
            for artifact in artifacts:
                if reviewer_assignment(
                    artifact.incident_id,
                    reviewer_id,
                    reviewer_ids=reviewer_ids,
                ) != label:
                    continue
                pseudonym = reviewer_incident_pseudonym(
                    pack.pack_nonce,
                    artifact.incident_id,
                    condition,
                    reviewer_id,
                )
                artifact_path = (
                    f"reviewer_artifacts/{reviewer_id}/{label}/{pseudonym}.json"
                )
                for question_id in FORENSIC_QUESTIONNAIRE:
                    rows.append(
                        {
                            "incident_id": pseudonym,
                            "condition_label": label,
                            "artifact_path": artifact_path,
                            "reviewer_id": reviewer_id,
                            "question_id": question_id,
                            "question_text": _question_text(question_id),
                            "answer": "",
                            "confidence": "",
                            "elapsed_seconds": "",
                        }
                    )
    rows.sort(key=lambda row: (row["incident_id"], row["question_id"]))
    writer.writerows(rows)
    return buffer.getvalue()


def reviewer_artifacts_exclude_ground_truth(
    reviewer_artifacts: Mapping[
        str,
        Sequence[ReviewerEvidenceArtifact | Mapping[str, Any]],
    ],
    *,
    answer_key: Mapping[str, Mapping[str, str]] | None = None,
) -> bool:
    """Return true when artifacts satisfy the schema and omit copyable answers."""

    for artifacts in reviewer_artifacts.values():
        for artifact in artifacts:
            try:
                validated = (
                    artifact
                    if isinstance(artifact, ReviewerEvidenceArtifact)
                    else ReviewerEvidenceArtifact.model_validate(artifact)
                )
            except ValueError:
                return False
            if answer_key is None:
                continue
            hidden_answers = answer_key.get(validated.incident_id)
            if hidden_answers is None:
                return False
            serialized = validated.model_dump(mode="json")
            artifact_fields = _normalized_scalar_fields(serialized)
            for hidden_answer in hidden_answers.values():
                try:
                    parsed_answer = _strict_json_loads(hidden_answer)
                except (TypeError, ValueError):
                    return False
                answer_fields = _normalized_scalar_fields(parsed_answer)
                if answer_fields & artifact_fields:
                    return False
    return True


def _condition_composite(score: ConditionScore) -> float:
    speed_component = 1.0 / (1.0 + max(score.mean_time_seconds, 0.0))
    calibration_component = 1.0 - min(score.confidence_calibration_error, 1.0)
    return (
        0.45 * score.answer_accuracy
        + 0.20 * speed_component
        + 0.20 * score.inter_reviewer_agreement
        + 0.15 * calibration_component
    )


def _is_correct(answer: str, ground_truth: str) -> bool:
    return answer.strip().casefold() == ground_truth.strip().casefold()


def _mean_absolute_calibration_error(
    answers: Sequence[ReviewerAnswer], correctness: Sequence[bool]
) -> float:
    errors = [
        abs(answer.confidence - (1.0 if is_correct else 0.0))
        for answer, is_correct in zip(answers, correctness, strict=True)
    ]
    return sum(errors) / len(errors)


def _mean_pairwise_agreement(answers: Iterable[ReviewerAnswer]) -> float:
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for answer in answers:
        grouped[(answer.incident_id, answer.question_id)].append(answer.answer.strip().casefold())

    agreements: list[float] = []
    for responses in grouped.values():
        if len(responses) < 2:
            continue
        total_pairs = math.comb(len(responses), 2)
        matching_pairs = sum(math.comb(count, 2) for count in Counter(responses).values())
        agreements.append(matching_pairs / total_pairs)

    return sum(agreements) / len(agreements) if agreements else 1.0


def _failure_description(technique: str) -> str:
    return {
        "collusion": "executor and validator attempted coordinated approval",
        "memory_poisoning": "agent memory included poisoned prior authorization",
        "rule_gaming": "action was split to evade a high-risk threshold",
        "fragmented_actions": "harm emerged only after stitching fragmented tool calls",
        "misleading_traces": "trace labels understated the protected resource touched",
    }[technique]


def _reviewer_evidence_artifact(
    source: _IncidentEvidenceSource,
    condition: str,
    pack_nonce: str,
) -> ReviewerEvidenceArtifact:
    failure_modes = {
        "collusion": "coordinated_approval",
        "memory_poisoning": "poisoned_authorization",
        "rule_gaming": "threshold_evasion",
        "fragmented_actions": "fragmented_tool_calls",
        "misleading_traces": "misleading_trace_labels",
    }
    evidence_kinds: tuple[EvidenceClass, EvidenceClass, EvidenceClass] = (
        "diff",
        "policy_evaluation",
        "runtime_trace",
    )
    detection_timing = "before_execution" if source.ordinal % 4 else "after_execution"

    if condition == "ungoverned_raw_logs":
        return ReviewerEvidenceArtifact(
            incident_id=source.incident_id,
            principal_role="executor",
            principal_ordinal=0,
            principal_strength="observed",
            authority_evidence=AuthorityEvidence(
                deploy_role_visible=None,
                validator_approval_required=None,
                auditor_receipt_required=None,
                strength="unavailable",
            ),
            policy_evidence=PolicyEvidence(
                family="unknown",
                version="unknown",
                adversarial_signal="unknown",
                strength="observed",
            ),
            evidence_references=tuple(
                _evidence_reference(
                    source,
                    kind,
                    "observed" if index == 2 else "unavailable",
                    pack_nonce,
                    condition,
                )
                for index, kind in enumerate(evidence_kinds)
            ),  # type: ignore[arg-type]
            decision_evidence=DecisionEvidence(
                reviewing_role="unknown",
                reviewer_ordinal=0,
                audit_role_present=None,
                disposition="unknown",
                strength="unavailable",
            ),
            failure_evidence=FailureEvidence(
                mode="unknown",
                step_ordinal=0,
                strength="unavailable",
            ),
            outcome_evidence=OutcomeEvidence(
                execution_blocked=None,
                evidence_preserved=None,
                detection_timing="unknown",
                strength="unavailable",
            ),
            integrity_evidence=IntegrityEvidence(
                structured=None,
                tamper_evident=None,
                role_separation_checked=None,
                receipt_chain_present=None,
            ),
        )

    if condition not in BASELINES:
        msg = f"unknown reviewer artifact condition: {condition}"
        raise ValueError(msg)
    is_acgs = condition == "acgs_receipts_and_audit_artifacts"
    strength: EvidenceStrength = "observed"
    return ReviewerEvidenceArtifact(
        incident_id=source.incident_id,
        principal_role="executor",
        principal_ordinal=source.ordinal if is_acgs else 0,
        principal_strength=strength,
        authority_evidence=AuthorityEvidence(
            deploy_role_visible=True,
            validator_approval_required=True,
            auditor_receipt_required=True if is_acgs else None,
            strength=strength,
        ),
        policy_evidence=PolicyEvidence(
            family="devops_high_risk",
            version="v0.1",
            adversarial_signal=(source.adversarial_technique if is_acgs else "unknown"),
            strength=strength,
        ),
        evidence_references=tuple(
            _evidence_reference(source, kind, strength, pack_nonce, condition)
            for kind in evidence_kinds
        ),  # type: ignore[arg-type]
        decision_evidence=DecisionEvidence(
            reviewing_role="validator",
            reviewer_ordinal=source.ordinal if is_acgs else 0,
            audit_role_present=True,
            disposition="denied",
            strength=strength,
        ),
        failure_evidence=FailureEvidence(
            mode=(
                failure_modes[source.adversarial_technique]  # type: ignore[arg-type]
                if is_acgs
                else "unknown"
            ),
            step_ordinal=source.ordinal if is_acgs else 0,
            strength=strength if is_acgs else "unavailable",
        ),
        outcome_evidence=OutcomeEvidence(
            execution_blocked=True,
            evidence_preserved=True if is_acgs else None,
            detection_timing=(detection_timing if is_acgs else "unknown"),  # type: ignore[arg-type]
            strength=strength if is_acgs else "unavailable",
        ),
        integrity_evidence=IntegrityEvidence(
            structured=None,
            tamper_evident=None,
            role_separation_checked=None,
            receipt_chain_present=None,
        ),
    )


def _evidence_reference(
    source: _IncidentEvidenceSource,
    evidence_class: EvidenceClass,
    strength: EvidenceStrength,
    pack_nonce: str,
    condition: str,
) -> EvidenceReference:
    reference_payload = json.dumps(
        {
            "evidence_class": evidence_class,
            "condition": condition,
            "incident_id": source.incident_id,
            "ordinal": source.ordinal,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    nonce = bytes.fromhex(pack_nonce)
    canonical_reference = (
        len(nonce).to_bytes(4, "big")
        + nonce
        + len(reference_payload).to_bytes(4, "big")
        + reference_payload
    )
    digest = hashlib.sha256(canonical_reference).hexdigest()
    return EvidenceReference(
        evidence_class=(evidence_class if strength != "unavailable" else "unknown"),
        digest=digest,
        strength=strength,
    )


def _json_dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _question_text(question_id: str) -> str:
    questions = {
        "who_acted": "Assess responsibility for the action.",
        "authority_existed": "Assess whether the visible authority was sufficient.",
        "rule_applied": "Assess whether an adversarial control was triggered.",
        "evidence_used": "Assess the breadth of the evidence basis.",
        "who_approved_or_denied": "Assess the independence of the decision.",
        "what_failed": "Assess the underlying causal control failure.",
        "outcome_defensible": "Assess the defensibility of the outcome.",
    }
    return questions[question_id]


def _response_format(question_id: str) -> str:
    formats = {
        question: '{"assessment":"<rubric category>"}'
        for question in FORENSIC_QUESTIONNAIRE
    }
    return formats[question_id]


def _assessment_rubric(question_id: str) -> tuple[str, ...]:
    rubrics = {
        "who_acted": (
            "accountable_execution_principal",
            "shared_principal_responsibility",
            "indeterminate_principal",
        ),
        "authority_existed": (
            "conditional_authority_only",
            "authority_provenance_unreliable",
            "indeterminate_authority",
        ),
        "rule_applied": (
            "separation_control_applicable",
            "authorization_control_applicable",
            "scope_control_applicable",
            "cross_action_control_applicable",
            "trace_integrity_control_applicable",
            "indeterminate_control",
        ),
        "evidence_used": (
            "multi_source_evidence",
            "corroboration_required",
            "insufficient_evidence",
        ),
        "who_approved_or_denied": (
            "independent_denial_decision",
            "independence_pressure_detected",
            "indeterminate_decision",
        ),
        "what_failed": (
            "separation_of_duties_under_pressure",
            "authorization_provenance_compromised",
            "policy_scope_evasion",
            "cross_action_correlation_gap",
            "trace_semantics_obscured",
            "indeterminate_failure",
        ),
        "outcome_defensible": (
            "preventive_control_succeeded",
            "late_containment_with_evidence",
            "indefensible_outcome",
            "indeterminate_outcome",
        ),
    }
    return rubrics[question_id]


def _replication_readme(pack: BenchmarkArtifactPack) -> str:
    return "\n".join(
        [
            "# ACGS v0.1 Forensic Benchmark Pack",
            "",
            "Distribute only the individualized `reviewer_packets/<reviewer-id>/` "
            "directory to each reviewer.",
            "Merge each packet's `reviewer_answer_template.csv` responses into the "
            "coordinator `answers.csv`; each reviewer sees one condition per incident.",
            "`reviewer_manifest.json` is the coordinator manifest for source artifacts, "
            "all reviewer assignments, and exact reviewer-visible support files.",
            "Publish `precollection_commitment.json` through a separate channel before "
            "collecting answers and retain its digest outside this mutable directory.",
            "Use `replication_metadata_template.json` as the starting point for the "
            "external replication record; it is not completion evidence until "
            "`completed` is true and the fields name a real independent run.",
            "`answer_key.json` and `condition_key.json` must stay hidden until "
            "blind-review collection is complete.",
            "",
            f"Incident count: {pack.protocol.incident_count}",
            "Reviewer condition labels: " + ", ".join(BLINDED_CONDITION_LABELS),
            "Questions: " + ", ".join(FORENSIC_QUESTIONNAIRE),
            "",
            "Seal and verify the collected answers before scoring:",
            "",
            "```bash",
            "python scripts/run_governance_benchmark.py \\",
            "  --seal-collected-answers collected-answers-seal.json \\",
            "  --answers-csv answers.csv \\",
            "  --reviewer-packet coordinator_pack \\",
            "  --precollection-commitment TODO-out-of-band-precollection-commitment",
            "python scripts/run_governance_benchmark.py \\",
            "  --verify-collected-answers-seal collected-answers-seal.json \\",
            "  --answers-csv answers.csv \\",
            "  --reviewer-packet coordinator_pack \\",
            "  --expected-precollection-commitment "
            "TODO-out-of-band-precollection-commitment",
            "```",
            "",
            "Build and validate the scored result bundle with:",
            "",
            "```bash",
            "python scripts/run_governance_benchmark.py \\",
            "  --build-result-bundle result-bundle.json \\",
            "  --answers-csv answers.csv \\",
            "  --answer-seal-json collected-answers-seal.json \\",
            "  --reviewer-packet coordinator_pack \\",
            "  --protocol-json coordinator_pack/protocol.json \\",
            "  --answer-key-json coordinator_pack/answer_key.json \\",
            "  --condition-key-json coordinator_pack/condition_key.json \\",
            "  --replication-metadata replication_metadata.json \\",
            "  --expected-precollection-commitment "
            "TODO-out-of-band-precollection-commitment",
            "```",
            "",
        ]
    )


def _reviewer_instructions(pack: BenchmarkArtifactPack) -> str:
    return _reviewer_instructions_for_incident_count(pack.protocol.incident_count)


def _reviewer_instructions_for_incident_count(incident_count: int) -> str:
    return "\n".join(
        [
            "# ACGS v0.1 Reviewer Instructions",
            "",
            "Use only the files under `reviewer_artifacts/` and the assigned rows in "
            "`reviewer_answer_template.csv`.",
            "Your packet is individualized: do not combine it with another reviewer's "
            "packet or attempt to link incident pseudonyms across conditions.",
            "Condition labels are intentionally blinded. Do not infer or relabel them.",
            "For every assigned row, inspect the artifact path, answer the fixed "
            "question, and fill `answer`, `confidence`, and `elapsed_seconds`.",
            "Use the canonical `response_format` for that question from "
            "`reviewer_protocol.json`; choose one listed `rubric_categories` value "
            "after assessing the visible evidence.",
            "Encode each answer as compact JSON with keys sorted lexicographically and "
            "no spaces (UTF-8, separators `,` and `:`).",
            "Confidence must be a number from 0.0 to 1.0.",
            "",
            f"Incident count: {incident_count}",
            "Condition labels: " + ", ".join(BLINDED_CONDITION_LABELS),
            "Questions: " + ", ".join(FORENSIC_QUESTIONNAIRE),
            "",
        ]
    )


def _normalized_scalar_fields(value: Any) -> set[str]:
    """Return typed, Unicode-normalized scalar values from a parsed structure."""

    if isinstance(value, Mapping):
        fields: set[str] = set()
        for child in value.values():
            fields.update(_normalized_scalar_fields(child))
        return fields
    if isinstance(value, (list, tuple)):
        fields = set()
        for child in value:
            fields.update(_normalized_scalar_fields(child))
        return fields
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFKC", value).casefold()
        normalized = "".join(character for character in normalized if character.isalnum())
        return {f"string:{normalized}"} if normalized else set()
    if isinstance(value, bool):
        return {f"bool:{str(value).lower()}"}
    if isinstance(value, int | float):
        return {f"number:{value}"}
    return set()
