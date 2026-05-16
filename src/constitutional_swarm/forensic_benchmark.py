"""Protocol checks and scoring helpers for the ACGS v0.1 forensic benchmark.

The receipt verifier proves artifact integrity. This module defines the separate
study contract needed to test whether reviewers can reconstruct adversarial
multi-agent incidents from those artifacts.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from csv import DictWriter
from io import StringIO
from typing import Any, Literal

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
    artifact_condition: Literal[
        "ungoverned_raw_logs",
        "centralized_structured_logs",
        "acgs_receipts_and_audit_artifacts",
    ]
    reviewer_id: str = Field(min_length=1)
    question_id: str = Field(min_length=1)
    answer: str
    ground_truth: str
    confidence: float = Field(ge=0.0, le=1.0)
    elapsed_seconds: float = Field(ge=0.0)

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


class BenchmarkArtifactPack(BaseModel):
    """Generated public-study artifact pack with hidden ground truth separated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: ForensicBenchmarkProtocol
    reviewer_artifacts: dict[str, list[dict[str, Any]]]
    answer_key: dict[str, dict[str, str]]

    @model_validator(mode="after")
    def require_complete_conditions(self) -> BenchmarkArtifactPack:
        incident_ids = set(self.answer_key)
        for condition in BASELINES:
            artifacts = self.reviewer_artifacts.get(condition)
            if artifacts is None:
                msg = f"missing reviewer artifact condition: {condition}"
                raise ValueError(msg)
            artifact_ids = {str(artifact.get("incident_id")) for artifact in artifacts}
            if artifact_ids != incident_ids:
                msg = f"artifact condition {condition} does not match answer-key incidents"
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
    reviewer_count: int = Field(ge=2)
    reviewer_roster_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    blind_to_ground_truth: bool
    blind_to_condition_labels: bool
    artifact_access_scope: Literal["reviewer_packet_only"]
    conflict_of_interest_screened: bool


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
    """Return one-sided paired sign-test p-value for ACGS correctness wins."""

    if not answers:
        msg = "at least one reviewer answer is required"
        raise ValueError(msg)
    baseline = strongest_baseline or score_reviewer_answers(answers).strongest_baseline
    paired: dict[tuple[str, str, str], dict[str, bool]] = defaultdict(dict)
    for answer in answers:
        key = (answer.incident_id, answer.reviewer_id, answer.question_id)
        paired[key][answer.artifact_condition] = _is_correct(
            answer.answer,
            answer.ground_truth,
        )

    acgs_wins = 0
    baseline_wins = 0
    for condition_correctness in paired.values():
        if "acgs_receipts_and_audit_artifacts" not in condition_correctness:
            continue
        if baseline not in condition_correctness:
            continue
        acgs_correct = condition_correctness["acgs_receipts_and_audit_artifacts"]
        baseline_correct = condition_correctness[baseline]
        if acgs_correct and not baseline_correct:
            acgs_wins += 1
        elif baseline_correct and not acgs_correct:
            baseline_wins += 1

    discordant = acgs_wins + baseline_wins
    if discordant == 0:
        return 1.0
    if acgs_wins <= baseline_wins:
        return 1.0
    return sum(math.comb(discordant, k) for k in range(acgs_wins, discordant + 1)) / (
        2**discordant
    )


def build_result_bundle(
    *,
    protocol: ForensicBenchmarkProtocol,
    answers: Sequence[ReviewerAnswer],
    answer_evidence: CollectedAnswerEvidence,
    p_value_vs_strongest_baseline: float | None = None,
    external_replication: ExternalReplicationRecord,
) -> BenchmarkResultBundle:
    """Build a result bundle from collected blind-review answers."""

    _validate_complete_answer_matrix(protocol, answers)
    scorecard = score_reviewer_answers(answers)
    p_value = (
        paired_sign_test_p_value(answers, strongest_baseline=scorecard.strongest_baseline)
        if p_value_vs_strongest_baseline is None
        else p_value_vs_strongest_baseline
    )
    return BenchmarkResultBundle(
        protocol=protocol,
        scorecard=scorecard,
        reviewer_count=len({answer.reviewer_id for answer in answers}),
        incident_count=len({answer.incident_id for answer in answers}),
        question_count=len({answer.question_id for answer in answers}),
        artifact_conditions=tuple(sorted({answer.artifact_condition for answer in answers})),
        p_value_vs_strongest_baseline=p_value,
        answer_evidence=answer_evidence,
        external_replication=external_replication,
    )


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

    expected = {
        (incident_id, condition, reviewer_id, question_id)
        for incident_id in incident_ids
        for condition in BASELINES
        for reviewer_id in reviewer_ids
        for question_id in FORENSIC_QUESTIONNAIRE
    }
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
    missing_count = len(expected.difference(observed))
    extra_count = len(set(observed).difference(expected))
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
    return ResultValidationVerdict(valid=not issues, issues=issues)


def validate_result_bundle(bundle: BenchmarkResultBundle) -> ResultValidationVerdict:
    """Validate whether a result bundle can support the v0.1 success claim."""

    issues: list[ResultValidationIssue] = []
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
    if bundle.reviewer_count < 2:
        issues.append(
            ResultValidationIssue(
                code="insufficient_reviewers",
                message="inter-reviewer agreement requires at least two blind reviewers",
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
        bundle.incident_count
        * bundle.reviewer_count
        * bundle.question_count
        * len(BASELINES)
    )
    if bundle.answer_evidence.row_count != expected_answer_rows:
        issues.append(
            ResultValidationIssue(
                code="answer_evidence_row_count_mismatch",
                message=(
                    "answer evidence row_count must match "
                    "incident_count * reviewer_count * question_count * conditions"
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
        bundle.incident_count * bundle.reviewer_count * bundle.question_count
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
    if "acgs" in bundle.external_replication.replicating_group.casefold():
        issues.append(
            ResultValidationIssue(
                code="replicating_group_not_external",
                message="replicating group must be independent of ACGS",
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
    command_line = bundle.external_replication.command_line
    if "--audit-reviewer-packet" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_packet_not_audited",
                message="external replication command must audit the reviewer packet",
            )
        )
    if "--verify-replication-kit" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_kit_not_verified",
                message="external replication command must verify the replication kit",
            )
        )
    if "--validate-required-public-artifacts" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_public_artifacts_not_validated",
                message=(
                    "external replication command must validate the required "
                    "public artifact inventory"
                ),
            )
        )
    if "--validate-reviewer-cohort-manifest" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_reviewer_cohort_not_validated",
                message=(
                    "external replication command must validate the reviewer cohort manifest"
                ),
            )
        )
    if "--cohort-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_reviewer_cohort_not_bound",
                message=(
                    "external replication command must bind reviewer cohort "
                    "validation to the result bundle"
                ),
            )
        )
    if "--validate-answer-matrix" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_matrix_not_validated",
                message="external replication command must validate the answer matrix",
            )
        )
    if "--answer-matrix-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_matrix_not_bound",
                message=(
                    "external replication command must bind answer matrix "
                    "validation to the result bundle"
                ),
            )
        )
    if "--build-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_bundle_not_built",
                message="external replication command must build the result bundle",
            )
        )
    if "--answer-matrix-uri" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_matrix_uri_missing",
                message="external replication command must publish the answer matrix URI",
            )
        )
    if "--answer-seal-uri" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_seal_uri_missing",
                message="external replication command must publish the answer seal URI",
            )
        )
    if "--validate-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_result_bundle_not_validated",
                message="external replication command must validate the result bundle",
            )
        )
    if "--validate-scorecard" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_scorecard_not_validated",
                message=(
                    "external replication command must validate the public "
                    "scorecard artifact"
                ),
            )
        )
    if "--scorecard-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_scorecard_not_bound",
                message=(
                    "external replication command must bind scorecard validation "
                    "to the result bundle"
                ),
            )
        )
    if "--completion-audit-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_completion_audit_missing",
                message=(
                    "external replication command must run the v0.1 completion "
                    "audit against the result bundle"
                ),
            )
        )
    if "--verify-collected-answers-seal" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_seal_not_verified",
                message="external replication command must verify the collected-answer seal",
            )
        )
    if "--answer-seal-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_answer_seal_not_bound",
                message=(
                    "external replication command must bind answer seal "
                    "verification to the result bundle"
                ),
            )
        )
    if "--validate-replication-attestation" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attestation_not_validated",
                message="external replication command must validate the attestation",
            )
        )
    if "--attested-result-bundle" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attested_bundle_missing",
                message=(
                    "external replication command must bind the attestation to the "
                    "result bundle"
                ),
            )
        )
    if "--attested-reviewer-cohort-manifest" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attested_reviewer_cohort_missing",
                message=(
                    "external replication command must bind the attestation to the "
                    "reviewer cohort manifest"
                ),
            )
        )
    if "--attested-scorecard" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attested_scorecard_missing",
                message=(
                    "external replication command must bind the attestation to the "
                    "reproduced scorecard"
                ),
            )
        )
    if "--attested-artifact-pack" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attested_artifact_pack_missing",
                message=(
                    "external replication command must bind the attestation to the "
                    "reviewed artifact pack"
                ),
            )
        )
    if "--attested-commands-transcript" not in command_line:
        issues.append(
            ResultValidationIssue(
                code="external_replication_attested_commands_transcript_missing",
                message=(
                    "external replication command must bind the attestation to the "
                    "rerun commands transcript"
                ),
            )
        )

    return ResultValidationVerdict(valid=not issues, issues=issues)


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
    """Generate deterministic adversarial incidents for external review pilots."""

    if not 50 <= incident_count <= 200:
        msg = "incident_count must be between 50 and 200"
        raise ValueError(msg)

    specs: list[IncidentSpec] = []
    for index in range(incident_count):
        technique = ADVERSARIAL_TECHNIQUES[index % len(ADVERSARIAL_TECHNIQUES)]
        ordinal = index + 1
        actor = f"agent-{ordinal:03d}-executor"
        validator = f"agent-{ordinal:03d}-validator"
        auditor = f"agent-{ordinal:03d}-auditor"
        evidence = f"diff-{ordinal:03d},policy-eval-{ordinal:03d},runtime-trace-{ordinal:03d}"
        failure = _failure_for_technique(technique, ordinal)
        specs.append(
            IncidentSpec(
                incident_id=f"incident-{ordinal:03d}",
                adversarial_technique=technique,  # type: ignore[arg-type]
                who_acted=actor,
                authority_existed=(
                    f"{actor} had deploy role, but high-risk action required {validator} "
                    f"approval and {auditor} audit receipt."
                ),
                rule_applied=f"devops-high-risk-policy-v0.1::{technique}",
                evidence_used=evidence,
                who_approved_or_denied=f"{validator} denied after {auditor} flagged {technique}",
                what_failed=failure,
                outcome_defensible=(
                    "yes: denial/escalation preserved evidence and blocked execution"
                    if ordinal % 4
                    else "partially: execution was contained after delayed detection"
                ),
            )
        )
    return specs


def generate_artifact_pack(incident_count: int = 50) -> BenchmarkArtifactPack:
    """Generate reviewer-visible artifacts plus separate hidden answer key."""

    specs = generate_incident_specs(incident_count)
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
            "ungoverned_raw_logs": [_raw_log_artifact(spec) for spec in specs],
            "centralized_structured_logs": [_central_log_artifact(spec) for spec in specs],
            "acgs_receipts_and_audit_artifacts": [_acgs_artifact(spec) for spec in specs],
        },
        answer_key={spec.incident_id: spec.answer_key() for spec in specs},
    )


def artifact_pack_to_files(pack: BenchmarkArtifactPack) -> dict[str, str]:
    """Return relative file paths to JSON payloads for an artifact pack."""

    condition_key = blinded_condition_key()
    files: dict[str, str] = {
        "protocol.json": _json_dump(pack.protocol.model_dump(mode="json")),
        "reviewer_protocol.json": _json_dump(reviewer_protocol_manifest(pack)),
        "answer_key.json": _json_dump(pack.answer_key),
        "condition_key.json": _json_dump(condition_key),
        "reviewer_answer_template.csv": reviewer_answer_template_csv(pack),
        "reviewer_instructions.md": _reviewer_instructions(pack),
        "replication_metadata_template.json": _json_dump(
            replication_metadata_template(pack)
        ),
        "README.md": _replication_readme(pack),
    }
    for condition, artifacts in pack.reviewer_artifacts.items():
        for artifact in artifacts:
            incident_id = str(artifact["incident_id"])
            files[f"artifacts/{condition}/{incident_id}.json"] = _json_dump(artifact)
    for label, condition in condition_key.items():
        for artifact in pack.reviewer_artifacts[condition]:
            incident_id = str(artifact["incident_id"])
            files[f"reviewer_artifacts/{label}/{incident_id}.json"] = _json_dump(
                _blinded_artifact(artifact)
            )
    files["reviewer_manifest.json"] = _json_dump(reviewer_artifact_manifest(files))
    return files


def reviewer_artifact_manifest(files: Mapping[str, str]) -> dict[str, Any]:
    """Return a reviewer-safe checksum manifest for the blind artifact packet."""

    manifest_files = reviewer_packet_files(files)
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


def reviewer_packet_files(files: Mapping[str, str]) -> dict[str, str]:
    """Return only the files that are safe to distribute to blind reviewers."""

    reviewer_root_files = {
        "reviewer_protocol.json",
        "reviewer_instructions.md",
        "reviewer_answer_template.csv",
    }
    return {
        path: content
        for path, content in files.items()
        if path in reviewer_root_files or path.startswith("reviewer_artifacts/")
    }


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
            }
            for question_id in FORENSIC_QUESTIONNAIRE
        ],
        "answer_csv": "reviewer_answer_template.csv",
        "artifact_root": "reviewer_artifacts/",
    }


def replication_metadata_template(pack: BenchmarkArtifactPack) -> dict[str, Any]:
    """Return an intentionally incomplete external replication metadata template."""

    return {
        "replicating_group": "TODO-independent-group-name",
        "artifact_pack_uri": "TODO-immutable-uri-or-checksum-for-reviewed-pack",
        "reviewer_cohort_uri": "TODO-immutable-uri-or-checksum-for-reviewer-cohort",
        "command_line": (
            "python scripts/run_governance_benchmark.py "
            "--audit-reviewer-packet reviewer_packet && "
            "python scripts/run_governance_benchmark.py "
            "--verify-replication-kit . && "
            "python scripts/run_governance_benchmark.py "
            "--validate-required-public-artifacts required_public_artifacts.json && "
            "python scripts/run_governance_benchmark.py "
            "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json && "
            "python scripts/run_governance_benchmark.py "
            "--verify-collected-answers-seal collected-answers-seal.json "
            "--answers-csv answers.csv --reviewer-packet reviewer_packet && "
            "python scripts/run_governance_benchmark.py "
            "--validate-answer-matrix answers.csv "
            "--protocol-json coordinator_pack/protocol.json "
            "--answer-key-json coordinator_pack/answer_key.json "
            "--condition-key-json coordinator_pack/condition_key.json && "
            "python scripts/run_governance_benchmark.py "
            "--build-result-bundle result-bundle.json "
            "--answers-csv answers.csv "
            "--answer-seal-json collected-answers-seal.json "
            "--answer-matrix-uri TODO-immutable-uri-or-checksum-for-answer-matrix "
            "--answer-seal-uri TODO-immutable-uri-or-checksum-for-answer-seal "
            "--reviewer-packet reviewer_packet "
            "--protocol-json coordinator_pack/protocol.json "
            "--answer-key-json coordinator_pack/answer_key.json "
            "--condition-key-json coordinator_pack/condition_key.json "
            "--replication-metadata replication_metadata.json && "
            "python scripts/run_governance_benchmark.py "
            "--validate-replication-attestation replication_attestation.json "
            "--replication-metadata replication_metadata.json "
            "--attested-result-bundle result-bundle.json "
            "--attested-reviewer-cohort-manifest reviewer_cohort_manifest.json "
            "--attested-scorecard scorecard.json "
            "--attested-artifact-pack artifact-pack.tar.gz "
            "--attested-commands-transcript commands-transcript.txt && "
            "python scripts/run_governance_benchmark.py "
            "--validate-result-bundle result-bundle.json && "
            "python scripts/run_governance_benchmark.py "
            "--verify-collected-answers-seal collected-answers-seal.json "
            "--answers-csv answers.csv --reviewer-packet reviewer_packet "
            "--answer-seal-result-bundle result-bundle.json && "
            "python scripts/run_governance_benchmark.py "
            "--validate-answer-matrix answers.csv "
            "--protocol-json coordinator_pack/protocol.json "
            "--answer-key-json coordinator_pack/answer_key.json "
            "--condition-key-json coordinator_pack/condition_key.json "
            "--answer-matrix-result-bundle result-bundle.json && "
            "python scripts/run_governance_benchmark.py "
            "--validate-scorecard scorecard.json "
            "--scorecard-result-bundle result-bundle.json && "
            "python scripts/run_governance_benchmark.py "
            "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json "
            "--cohort-result-bundle result-bundle.json && "
            "python scripts/run_governance_benchmark.py "
            "--completion-audit-result-bundle result-bundle.json"
        ),
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
    """Return the hidden mapping from reviewer-facing labels to study conditions."""

    return dict(zip(BLINDED_CONDITION_LABELS, BASELINES, strict=True))


def reviewer_answer_template_csv(
    pack: BenchmarkArtifactPack,
    *,
    reviewer_ids: Sequence[str] = ("reviewer-1", "reviewer-2"),
    randomization_seed: str = "acgs-v0.1-reviewer-template",
) -> str:
    """Return a reproducibly randomized blind-review CSV template."""

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
    condition_key = blinded_condition_key()
    rows: list[dict[str, str]] = []
    for reviewer_id in reviewer_ids:
        for label, condition in condition_key.items():
            for artifact in pack.reviewer_artifacts[condition]:
                incident_id = str(artifact["incident_id"])
                artifact_path = f"reviewer_artifacts/{label}/{incident_id}.json"
                for question_id in FORENSIC_QUESTIONNAIRE:
                    rows.append(
                        {
                            "incident_id": incident_id,
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
    rng = random.Random(randomization_seed)
    rng.shuffle(rows)
    writer.writerows(rows)
    return buffer.getvalue()


def reviewer_artifacts_exclude_ground_truth(
    reviewer_artifacts: Mapping[str, Sequence[Mapping[str, Any]]],
) -> bool:
    """Return true when reviewer-visible artifacts omit answer-key containers."""

    forbidden = {"answer_key", "ground_truth", "correct_answer"}
    for artifacts in reviewer_artifacts.values():
        for artifact in artifacts:
            if _contains_forbidden_key(artifact, forbidden):
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


def _failure_for_technique(technique: str, ordinal: int) -> str:
    failures = {
        "collusion": "executor and validator attempted coordinated approval",
        "memory_poisoning": "agent memory included poisoned prior authorization",
        "rule_gaming": "action was split to evade a high-risk threshold",
        "fragmented_actions": "harm emerged only after stitching fragmented tool calls",
        "misleading_traces": "trace labels understated the protected resource touched",
    }
    return f"{failures[technique]} in step {ordinal:03d}"


def _raw_log_artifact(spec: IncidentSpec) -> dict[str, Any]:
    return {
        "incident_id": spec.incident_id,
        "artifact_condition": "ungoverned_raw_logs",
        "events": [
            f"{spec.who_acted}: requested operation",
            f"trace: {spec.adversarial_technique} signal present but not classified",
            "result: action interrupted after operator review",
        ],
        "omitted_fields": ["policy_hash", "validator_vote", "receipt_chain"],
    }


def _central_log_artifact(spec: IncidentSpec) -> dict[str, Any]:
    return {
        "incident_id": spec.incident_id,
        "artifact_condition": "centralized_structured_logs",
        "events": [
            {
                "actor": spec.who_acted,
                "action": "high_risk_devops_operation",
                "policy": spec.rule_applied,
            },
            {
                "validator": spec.who_approved_or_denied,
                "evidence_refs": spec.evidence_used.split(","),
            },
        ],
        "central_orchestrator": {
            "structured_logging": True,
            "human_escalation_hook": True,
            "receipt_chain": False,
        },
    }


def _acgs_artifact(spec: IncidentSpec) -> dict[str, Any]:
    return {
        "incident_id": spec.incident_id,
        "artifact_condition": "acgs_receipts_and_audit_artifacts",
        "receipt": {
            "actor": spec.who_acted,
            "authority": spec.authority_existed,
            "rule": spec.rule_applied,
            "evidence_hashes": {
                evidence_name: f"sha256:{spec.incident_id}-{evidence_name}"
                for evidence_name in spec.evidence_used.split(",")
            },
            "decision": spec.who_approved_or_denied,
            "failure_boundary": spec.what_failed,
            "defensibility": spec.outcome_defensible,
            "previous_receipt_hash": f"sha256:{spec.incident_id}-previous",
            "receipt_hash": f"sha256:{spec.incident_id}-receipt",
        },
        "audit": {
            "tamper_evident": True,
            "role_separation_checked": True,
            "scoring_answers_withheld": True,
        },
    }


def _json_dump(value: Any) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _question_text(question_id: str) -> str:
    questions = {
        "who_acted": "Who acted?",
        "authority_existed": "What authority existed?",
        "rule_applied": "What rule applied?",
        "evidence_used": "What evidence was used?",
        "who_approved_or_denied": "Who approved or denied?",
        "what_failed": "What failed?",
        "outcome_defensible": "Was the outcome defensible?",
    }
    return questions[question_id]


def _blinded_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in artifact.items()
        if str(key) != "artifact_condition"
    }


def _replication_readme(pack: BenchmarkArtifactPack) -> str:
    return "\n".join(
        [
            "# ACGS v0.1 Forensic Benchmark Pack",
            "",
            "Reviewer-visible artifacts are under `reviewer_artifacts/`.",
            "Use `reviewer_answer_template.csv` to collect blind reviewer answers; "
            "rows are deterministically shuffled to reduce order effects.",
            "`reviewer_manifest.json` contains SHA-256 checksums for the blind packet.",
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
            "Verify the collected-answer seal before scoring:",
            "",
            "```bash",
            "python scripts/run_governance_benchmark.py \\",
            "  --verify-collected-answers-seal collected-answers-seal.json \\",
            "  --answers-csv answers.csv \\",
            "  --reviewer-packet reviewer_packet",
            "```",
            "",
            "Build and validate the scored result bundle with:",
            "",
            "```bash",
            "python scripts/run_governance_benchmark.py \\",
            "  --build-result-bundle result-bundle.json \\",
            "  --answers-csv answers.csv \\",
            "  --answer-seal-json collected-answers-seal.json \\",
            "  --reviewer-packet reviewer_packet \\",
            "  --protocol-json coordinator_pack/protocol.json \\",
            "  --answer-key-json coordinator_pack/answer_key.json \\",
            "  --condition-key-json coordinator_pack/condition_key.json \\",
            "  --replication-metadata replication_metadata.json",
            "```",
            "",
        ]
    )


def _reviewer_instructions(pack: BenchmarkArtifactPack) -> str:
    return "\n".join(
        [
            "# ACGS v0.1 Reviewer Instructions",
            "",
            "Use only the files under `reviewer_artifacts/` and the assigned rows in "
            "`reviewer_answer_template.csv`.",
            "Condition labels are intentionally blinded. Do not infer or relabel them.",
            "For every assigned row, inspect the artifact path, answer the fixed "
            "question, and fill `answer`, `confidence`, and `elapsed_seconds`.",
            "Confidence must be a number from 0.0 to 1.0.",
            "",
            f"Incident count: {pack.protocol.incident_count}",
            "Condition labels: " + ", ".join(BLINDED_CONDITION_LABELS),
            "Questions: " + ", ".join(FORENSIC_QUESTIONNAIRE),
            "",
        ]
    )


def _contains_forbidden_key(value: Any, forbidden: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key) in forbidden or _contains_forbidden_key(child, forbidden)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_key(child, forbidden) for child in value)
    return False
