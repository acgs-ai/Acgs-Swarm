from __future__ import annotations

import csv
import hashlib
import json
import inspect
import math
from collections.abc import Mapping, Sequence
from io import StringIO
from typing import Any

import pytest
from pydantic import ValidationError

import constitutional_swarm.forensic_benchmark as forensic_benchmark

from constitutional_swarm.forensic_benchmark import (
    BASELINES,
    FORENSIC_QUESTIONNAIRE,
    ReviewerAnswer,
    artifact_pack_to_files,
    blinded_condition_key,
    generate_artifact_pack,
    paired_sign_test_p_value,
    reviewer_artifacts_exclude_ground_truth,
    reviewer_packet_files,
)


def _shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), _shape(child)) for key, child in value.items()))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return ("sequence", tuple(_shape(child) for child in value))
    return "value"


def _answer(
    *,
    incident_id: str,
    condition: str,
    reviewer_id: str = "reviewer-1",
    question_id: str = "who_acted",
    correct: bool,
    ground_truth: str = "executor",
) -> ReviewerAnswer:
    return ReviewerAnswer(
        incident_id=incident_id,
        artifact_condition=condition,
        reviewer_id=reviewer_id,
        question_id=question_id,
        answer=ground_truth if correct else "incorrect",
        ground_truth=ground_truth,
        confidence=0.8,
        elapsed_seconds=10.0,
    )


def _paired_incident(
    incident_id: str,
    *,
    acgs_correct: bool,
    baseline_correct: bool,
    reviewer_id: str = "reviewer-1",
    question_id: str = "who_acted",
) -> list[ReviewerAnswer]:
    return [
        _answer(
            incident_id=incident_id,
            condition="centralized_structured_logs",
            reviewer_id=reviewer_id,
            question_id=question_id,
            correct=baseline_correct,
        ),
        _answer(
            incident_id=incident_id,
            condition="acgs_receipts_and_audit_artifacts",
            reviewer_id=reviewer_id,
            question_id=question_id,
            correct=acgs_correct,
        ),
    ]


def _public_code_answer_reconstruction(artifact: Any) -> dict[str, str] | None:
    """Model the reported attack using only reviewer-visible artifact fields."""

    failure_mode_to_technique = {
        "coordinated_approval": "collusion",
        "poisoned_authorization": "memory_poisoning",
        "threshold_evasion": "rule_gaming",
        "fragmented_tool_calls": "fragmented_actions",
        "misleading_trace_labels": "misleading_traces",
    }
    signal = artifact.policy_evidence.adversarial_signal
    technique = signal if signal != "unknown" else failure_mode_to_technique.get(
        artifact.failure_evidence.mode
    )
    if technique is None:
        return None
    timing = artifact.outcome_evidence.detection_timing
    if timing == "unknown" and artifact.principal_ordinal:
        timing = (
            "before_execution"
            if artifact.principal_ordinal % 4
            else "after_execution"
        )
    if timing == "unknown":
        return None

    failure_assessment = {
        "collusion": "separation_of_duties_under_pressure",
        "memory_poisoning": "authorization_provenance_compromised",
        "rule_gaming": "policy_scope_evasion",
        "fragmented_actions": "cross_action_correlation_gap",
        "misleading_traces": "trace_semantics_obscured",
    }
    rule_assessment = {
        "collusion": "separation_control_applicable",
        "memory_poisoning": "authorization_control_applicable",
        "rule_gaming": "scope_control_applicable",
        "fragmented_actions": "cross_action_control_applicable",
        "misleading_traces": "trace_integrity_control_applicable",
    }
    assessments = {
        "who_acted": (
            "shared_principal_responsibility"
            if technique in {"collusion", "fragmented_actions"}
            else "accountable_execution_principal"
        ),
        "authority_existed": (
            "authority_provenance_unreliable"
            if technique in {"memory_poisoning", "rule_gaming"}
            else "conditional_authority_only"
        ),
        "rule_applied": rule_assessment[technique],
        "evidence_used": (
            "corroboration_required"
            if technique in {"memory_poisoning", "misleading_traces"}
            else "multi_source_evidence"
        ),
        "who_approved_or_denied": (
            "independence_pressure_detected"
            if technique == "collusion"
            else "independent_denial_decision"
        ),
        "what_failed": failure_assessment[technique],
        "outcome_defensible": (
            "preventive_control_succeeded"
            if timing == "before_execution"
            else "late_containment_with_evidence"
        ),
    }
    return {
        question_id: json.dumps(
            {"assessment": assessment}, separators=(",", ":"), sort_keys=True
        )
        for question_id, assessment in assessments.items()
    }


def test_reviewer_artifacts_have_one_strict_condition_neutral_shape() -> None:
    pack = generate_artifact_pack()

    condition_shapes = {
        condition: {_shape(artifact.model_dump(mode="json")) for artifact in artifacts}
        for condition, artifacts in pack.reviewer_artifacts.items()
    }

    assert set(condition_shapes) == set(BASELINES)
    assert all(len(shapes) == 1 for shapes in condition_shapes.values())
    assert len({next(iter(shapes)) for shapes in condition_shapes.values()}) == 1
    serialized = "\n".join(
        artifact.model_dump_json()
        for artifacts in pack.reviewer_artifacts.values()
        for artifact in artifacts
    )
    assert all(condition not in serialized for condition in BASELINES)


def test_reviewer_artifacts_never_copy_normalized_hidden_answer_fields() -> None:
    pack = generate_artifact_pack()
    copied_answer_key = pack.model_dump(mode="json")["answer_key"]
    copied_mode = pack.reviewer_artifacts["acgs_receipts_and_audit_artifacts"][
        0
    ].failure_evidence.mode
    copied_answer_key["incident-001"]["what_failed"] = json.dumps(
        {"assessment": copied_mode.replace("_", "-").title()},
        separators=(",", ":"),
        sort_keys=True,
    )

    assert reviewer_artifacts_exclude_ground_truth(
        pack.reviewer_artifacts,
        answer_key=pack.answer_key,
    )
    assert not reviewer_artifacts_exclude_ground_truth(
        pack.reviewer_artifacts,
        answer_key=copied_answer_key,
    )


def test_canonical_rubric_requires_judgment_instead_of_field_transcription() -> None:
    pack = generate_artifact_pack()
    artifact = pack.reviewer_artifacts["acgs_receipts_and_audit_artifacts"][0]
    answers = pack.answer_key[artifact.incident_id]

    parsed_answers = {key: json.loads(value) for key, value in answers.items()}
    assert set(parsed_answers) == set(FORENSIC_QUESTIONNAIRE)
    assert all(set(value) == {"assessment"} for value in parsed_answers.values())
    assert parsed_answers["what_failed"]["assessment"] != artifact.failure_evidence.mode
    protocol = json.loads(artifact_pack_to_files(pack)["reviewer_protocol.json"])
    assert all(question["response_format"] for question in protocol["questionnaire"])


def test_condition_fingerprints_are_removed_from_integrity_and_strength_fields() -> None:
    pack = generate_artifact_pack(pack_nonce="a" * 64)
    first_artifacts = [pack.reviewer_artifacts[condition][0] for condition in BASELINES]

    integrity_values = {
        json.dumps(artifact.integrity_evidence.model_dump(mode="json"), sort_keys=True)
        for artifact in first_artifacts
    }
    serialized = "\n".join(artifact.model_dump_json() for artifact in first_artifacts)

    assert len(integrity_values) == 1
    assert "corroborated" not in serialized
    raw = pack.reviewer_artifacts["ungoverned_raw_logs"][0]
    assert raw.outcome_evidence.detection_timing == "unknown"
    assert raw.outcome_evidence.strength == "unavailable"
    central = pack.reviewer_artifacts["centralized_structured_logs"][0]
    acgs = pack.reviewer_artifacts["acgs_receipts_and_audit_artifacts"][0]
    assert central.principal_strength == acgs.principal_strength == "observed"


def test_pack_nonce_salts_incident_facts_digests_and_condition_key_export() -> None:
    first = generate_artifact_pack(pack_nonce="a" * 64)
    second = generate_artifact_pack(pack_nonce="b" * 64)
    first_artifact = first.reviewer_artifacts["acgs_receipts_and_audit_artifacts"][0]
    second_artifact = second.reviewer_artifacts["acgs_receipts_and_audit_artifacts"][0]

    assert first.pack_nonce == "a" * 64
    assert second.pack_nonce == "b" * 64
    for question_id in FORENSIC_QUESTIONNAIRE:
        assert len(
            {
                answers[question_id]
                for answers in first.answer_key.values()
            }
        ) > 1
    assert dict(first.answer_key) != dict(second.answer_key)
    assert [
        (artifact.principal_ordinal, artifact.policy_evidence.adversarial_signal)
        for artifact in first.reviewer_artifacts["acgs_receipts_and_audit_artifacts"]
    ] != [
        (artifact.principal_ordinal, artifact.policy_evidence.adversarial_signal)
        for artifact in second.reviewer_artifacts["acgs_receipts_and_audit_artifacts"]
    ]
    assert first_artifact.evidence_references[0].digest != (
        second_artifact.evidence_references[0].digest
    )
    assert json.loads(artifact_pack_to_files(first)["condition_key.json"]) == {
        "conditions": dict(first.condition_key),
        "pack_nonce": first.pack_nonce,
    }


def test_baselines_do_not_expose_nonce_derived_hidden_facts() -> None:
    pack = generate_artifact_pack(pack_nonce="a" * 64)

    for condition in ("ungoverned_raw_logs", "centralized_structured_logs"):
        for artifact in pack.reviewer_artifacts[condition]:
            assert artifact.principal_ordinal == 0
            assert artifact.policy_evidence.adversarial_signal == "unknown"
            assert artifact.decision_evidence.reviewer_ordinal == 0
            assert artifact.failure_evidence.mode == "unknown"
            assert artifact.failure_evidence.step_ordinal == 0
            assert artifact.outcome_evidence.detection_timing == "unknown"


def test_public_code_attack_cannot_reconstruct_baseline_answer_keys() -> None:
    pack = generate_artifact_pack(pack_nonce="a" * 64)

    acgs_reconstructed_cells = 0
    for condition, artifacts in pack.reviewer_artifacts.items():
        for artifact in artifacts:
            reconstructed = _public_code_answer_reconstruction(artifact)
            if condition == "acgs_receipts_and_audit_artifacts":
                assert reconstructed == pack.answer_key[artifact.incident_id]
                acgs_reconstructed_cells += len(reconstructed)
            else:
                assert reconstructed is None

    assert acgs_reconstructed_cells == 50 * len(FORENSIC_QUESTIONNAIRE)


def test_pack_generation_is_fully_deterministic_from_nonce() -> None:
    first = generate_artifact_pack(pack_nonce="b" * 64)
    second = generate_artifact_pack(pack_nonce="b" * 64)

    assert artifact_pack_to_files(first) == artifact_pack_to_files(second)


def test_legacy_blinded_condition_key_warns() -> None:
    with pytest.warns(DeprecationWarning, match="pack.condition_key"):
        mapping = blinded_condition_key()

    assert set(mapping) == {"condition_a", "condition_b", "condition_c"}


def test_artifact_pack_rejects_answer_bearing_or_duplicate_artifacts() -> None:
    pack = generate_artifact_pack()
    dumped = pack.model_dump(mode="json")
    condition = BASELINES[0]
    answer_bearing = dict(dumped["reviewer_artifacts"][condition][0])
    answer_bearing["renamed_container"] = {
        "payload": next(iter(pack.answer_key[answer_bearing["incident_id"]].values()))
    }
    dumped["reviewer_artifacts"][condition][0] = answer_bearing

    with pytest.raises(ValidationError):
        type(pack).model_validate(dumped)

    dumped = pack.model_dump(mode="json")
    dumped["reviewer_artifacts"][condition].append(
        dumped["reviewer_artifacts"][condition][0]
    )
    with pytest.raises(ValidationError, match="duplicate"):
        type(pack).model_validate(dumped)


def test_artifact_pack_nested_content_is_immutable_and_export_is_revalidated() -> None:
    pack = generate_artifact_pack()
    condition = BASELINES[0]

    with pytest.raises((TypeError, ValidationError)):
        pack.reviewer_artifacts[condition][0].incident_id = "incident-999"

    corrupted = pack.model_dump(mode="json")
    corrupted["reviewer_artifacts"][condition][0]["answer_payload"] = "hidden"
    bypassed = pack.model_copy(update={"reviewer_artifacts": corrupted["reviewer_artifacts"]})
    with pytest.raises((TypeError, ValueError, ValidationError)):
        artifact_pack_to_files(bypassed)


def test_condition_key_is_pack_bound_and_reused_for_every_reviewer_output() -> None:
    pack = generate_artifact_pack()
    files = artifact_pack_to_files(pack)
    exported = json.loads(files["condition_key.json"])
    exported_key = exported["conditions"]

    assert exported_key == dict(pack.condition_key)
    assert exported["pack_nonce"] == pack.pack_nonce
    template = files["reviewer_answer_template.csv"]
    for label in exported_key:
        assert f"/{label}/" in template
        assert any(f"/{label}/" in path for path in files if path.startswith("reviewer_artifacts/"))


def test_reviewer_packet_filter_rejects_arbitrary_json_under_artifact_prefix() -> None:
    files = artifact_pack_to_files(generate_artifact_pack())
    files["reviewer_artifacts/condition_a/injected.json"] = json.dumps(
        {"renamed_container": {"payload": "the hidden answer"}}
    )

    with pytest.raises(ValueError, match="reviewer"):
        reviewer_packet_files(files, reviewer_id="reviewer-1")

    files = artifact_pack_to_files(generate_artifact_pack())
    files["reviewer_artifacts/../../answer_key.json"] = "{}"
    with pytest.raises(ValueError, match="reviewer"):
        reviewer_packet_files(files, reviewer_id="reviewer-1")


@pytest.mark.parametrize(
    "root_file",
    [
        "reviewer_protocol.json",
        "reviewer_instructions.md",
        "reviewer_answer_template.csv",
    ],
)
def test_reviewer_packet_filter_rejects_answer_injection_in_root_files(
    root_file: str,
) -> None:
    files = artifact_pack_to_files(generate_artifact_pack())
    if root_file == "reviewer_protocol.json":
        payload = json.loads(files[root_file])
        payload["hidden_answer"] = "answer prose"
        files[root_file] = json.dumps(payload)
    elif root_file == "reviewer_instructions.md":
        files[root_file] += "\nHidden answer: answer prose\n"
    else:
        files[root_file] = files[root_file].replace(",,,\n", ",answer prose,0.5,1\n", 1)

    with pytest.raises(ValueError, match="reviewer"):
        reviewer_packet_files(files, reviewer_id="reviewer-1")


def test_reviewer_packet_filter_rejects_missing_artifact_file() -> None:
    files = artifact_pack_to_files(generate_artifact_pack())
    missing_path = next(
        path for path in files if path.startswith("reviewer_artifacts/")
    )
    del files[missing_path]

    with pytest.raises(ValueError, match="canonical generator"):
        reviewer_packet_files(files, reviewer_id="reviewer-1")


@pytest.mark.parametrize(
    ("target", "needle", "replacement"),
    [
        (
            "artifact",
            '"principal_role": "executor",',
            '"principal_role":"hidden answer","principal_role":"executor",',
        ),
        (
            "artifact",
            '"deploy_role_visible": true,',
            '"deploy_role_visible":"hidden answer","deploy_role_visible":true,',
        ),
        (
            "protocol",
            '"schema": "acgs-v0.1-reviewer-protocol"',
            '"schema":"hidden answer","schema":"acgs-v0.1-reviewer-protocol"',
        ),
    ],
)
def test_reviewer_packet_filter_rejects_duplicate_json_keys(
    target: str,
    needle: str,
    replacement: str,
) -> None:
    files = artifact_pack_to_files(generate_artifact_pack())
    path = (
        next(
            path
            for path, content in files.items()
            if path.startswith("reviewer_artifacts/") and needle in content
        )
        if target == "artifact"
        else "reviewer_protocol.json"
    )
    files[path] = files[path].replace(needle, replacement, 1)

    with pytest.raises(ValueError, match="canonical generator"):
        reviewer_packet_files(files, reviewer_id="reviewer-1")


def test_sign_test_uses_incidents_as_independent_units() -> None:
    one_cell = _paired_incident(
        "incident-001", acgs_correct=True, baseline_correct=False
    )
    replicated: list[ReviewerAnswer] = []
    for reviewer_index in range(100):
        for question_id in FORENSIC_QUESTIONNAIRE:
            replicated.extend(
                _paired_incident(
                    "incident-001",
                    acgs_correct=True,
                    baseline_correct=False,
                    reviewer_id=f"reviewer-{reviewer_index}",
                    question_id=question_id,
                )
            )

    assert paired_sign_test_p_value(one_cell, strongest_baseline="centralized_structured_logs") == 0.5
    assert paired_sign_test_p_value(
        replicated, strongest_baseline="centralized_structured_logs"
    ) == 0.5


def test_sign_test_exact_tail_counts_discordant_incidents() -> None:
    all_wins = [
        answer
        for index in range(50)
        for answer in _paired_incident(
            f"incident-{index:03d}", acgs_correct=True, baseline_correct=False
        )
    ]
    mixed = [
        *_paired_incident("incident-win-1", acgs_correct=True, baseline_correct=False),
        *_paired_incident("incident-win-2", acgs_correct=True, baseline_correct=False),
        *_paired_incident("incident-loss", acgs_correct=False, baseline_correct=True),
        *_paired_incident("incident-tie", acgs_correct=True, baseline_correct=True),
    ]
    losing = [
        *_paired_incident("incident-win", acgs_correct=True, baseline_correct=False),
        *_paired_incident("incident-loss-1", acgs_correct=False, baseline_correct=True),
        *_paired_incident("incident-loss-2", acgs_correct=False, baseline_correct=True),
    ]

    assert paired_sign_test_p_value(
        all_wins, strongest_baseline="centralized_structured_logs"
    ) == 2.0**-50
    assert paired_sign_test_p_value(
        mixed, strongest_baseline="centralized_structured_logs"
    ) == 0.5
    assert paired_sign_test_p_value(
        losing, strongest_baseline="centralized_structured_logs"
    ) == 0.875


@pytest.mark.parametrize(
    "answers, message",
    [
        (
            [
                *_paired_incident(
                    "incident-duplicate", acgs_correct=True, baseline_correct=False
                ),
                _answer(
                    incident_id="incident-duplicate",
                    condition="centralized_structured_logs",
                    correct=False,
                ),
            ],
            "duplicate",
        ),
        (
            [
                _answer(
                    incident_id="incident-unmatched",
                    condition="acgs_receipts_and_audit_artifacts",
                    correct=True,
                )
            ],
            "missing",
        ),
        (
            [
                _answer(
                    incident_id="incident-ground-truth",
                    condition="centralized_structured_logs",
                    correct=True,
                    ground_truth="first",
                ),
                _answer(
                    incident_id="incident-ground-truth",
                    condition="acgs_receipts_and_audit_artifacts",
                    correct=True,
                    ground_truth="second",
                ),
            ],
            "ground truth",
        ),
    ],
)
def test_sign_test_rejects_invalid_pairing(
    answers: list[ReviewerAnswer], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        paired_sign_test_p_value(
            answers, strongest_baseline="centralized_structured_logs"
        )


def test_sign_test_rejects_acgs_as_its_own_baseline() -> None:
    answers = _paired_incident(
        "incident-001", acgs_correct=True, baseline_correct=False
    )

    with pytest.raises(ValueError, match="baseline"):
        paired_sign_test_p_value(
            answers,
            strongest_baseline="acgs_receipts_and_audit_artifacts",
        )


def test_sign_test_rejects_selectively_omitted_cells_between_incidents() -> None:
    answers = [
        *_paired_incident(
            "incident-001",
            acgs_correct=True,
            baseline_correct=False,
            question_id="who_acted",
        ),
        *_paired_incident(
            "incident-002",
            acgs_correct=True,
            baseline_correct=False,
            question_id="rule_applied",
        ),
    ]

    with pytest.raises(ValueError, match="identical"):
        paired_sign_test_p_value(
            answers,
            strongest_baseline="centralized_structured_logs",
        )


def test_sign_test_rejects_incomplete_nonselected_baseline_before_selection() -> None:
    answers: list[ReviewerAnswer] = []
    for incident_id in ("incident-001", "incident-002"):
        answers.extend(
            _paired_incident(
                incident_id,
                acgs_correct=True,
                baseline_correct=False,
            )
        )
        answers.append(
            _answer(
                incident_id=incident_id,
                condition="ungoverned_raw_logs",
                correct=False,
            )
        )
    answers = [
        answer
        for answer in answers
        if not (
            answer.incident_id == "incident-002"
            and answer.artifact_condition == "centralized_structured_logs"
        )
    ]

    with pytest.raises(ValueError, match="missing"):
        paired_sign_test_p_value(answers)


@pytest.mark.parametrize(
    ("field", "value"),
    [("confidence", math.nan), ("elapsed_seconds", math.inf)],
)
def test_reviewer_answer_rejects_non_finite_statistics(
    field: str, value: float
) -> None:
    payload = {
        "incident_id": "incident-001",
        "artifact_condition": "centralized_structured_logs",
        "reviewer_id": "reviewer-1",
        "question_id": "who_acted",
        "answer": "executor",
        "ground_truth": "executor",
        "confidence": 0.8,
        "elapsed_seconds": 10.0,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        ReviewerAnswer.model_validate(payload)


def test_result_bundle_builder_has_no_p_value_override() -> None:
    assert "p_value_vs_strongest_baseline" not in inspect.signature(
        forensic_benchmark.build_result_bundle
    ).parameters


@pytest.mark.parametrize(
    "spoof",
    [
        "Acg5 Independent Lab",
        "ΑCGS Lab",
        "ＡＣＧＳ Lab",
        "A-C-G-S Lab",
        "A\u200bC\u200bG\u200bS Lab",
        "ᴀᴄɢꜱ Independent Lab",
        "ᎪᏟᏀᏚ Independent Lab",
        "ÁCGS Independent Lab",
        "ACG$ Independent Lab",
    ],
)
def test_attestor_name_policy_rejects_acgs_lookalikes(spoof: str) -> None:
    assert forensic_benchmark.attestor_is_allowed(
        spoof,
        trusted_attestors=(spoof, "Independent Systems Lab"),
    ) is False


@pytest.mark.parametrize("empty_after_normalization", ["---", "\u200b", "\N{COMBINING ACUTE ACCENT}"])
def test_attestor_name_policy_rejects_empty_normalized_identity(
    empty_after_normalization: str,
) -> None:
    assert forensic_benchmark.attestor_is_allowed(
        empty_after_normalization,
        trusted_attestors=(empty_after_normalization,),
    ) is False


def test_result_bundle_builder_requires_real_evidence_root(tmp_path) -> None:
    pack = generate_artifact_pack()
    with pytest.raises(ValueError, match="evidence"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=forensic_benchmark.ExternalReplicationRecord(
                replicating_group="Independent Systems Lab",
                artifact_pack_uri="sha256:" + "1" * 64,
                reviewer_cohort_uri="sha256:" + "2" * 64,
                command_line="reproduce",
                scorecard_uri="sha256:" + "3" * 64,
                attestation_uri="sha256:" + "4" * 64,
                completed=True,
                reproduction_notes="independent rerun",
            ),
            evidence_root=tmp_path,
            evidence_paths={},
            expected_precollection_commitment="0" * 64,
        )


def _integrity_replication_record():
    flags = (
        "--audit-reviewer-packet",
        "--verify-replication-kit",
        "--validate-required-public-artifacts",
        "--validate-reviewer-cohort-manifest",
        "--cohort-result-bundle",
        "--validate-answer-matrix",
        "--answer-matrix-result-bundle",
        "--build-result-bundle",
        "--answer-matrix-uri",
        "--answer-seal-uri",
        "--validate-result-bundle",
        "--validate-scorecard",
        "--scorecard-result-bundle",
        "--completion-audit-result-bundle",
        "--verify-collected-answers-seal",
        "--answer-seal-result-bundle",
        "--validate-replication-attestation",
        "--attested-result-bundle",
        "--attested-reviewer-cohort-manifest",
        "--attested-scorecard",
        "--attested-artifact-pack",
        "--attested-commands-transcript",
    )
    return forensic_benchmark.ExternalReplicationRecord(
        replicating_group="Independent Systems Lab",
        artifact_pack_uri="sha256:" + "1" * 64,
        reviewer_cohort_uri="sha256:" + "2" * 64,
        command_line="python benchmark.py " + " ".join(flags),
        scorecard_uri="sha256:" + "3" * 64,
        attestation_uri="sha256:" + "4" * 64,
        completed=True,
        reproduction_notes="Independent rerun from the sealed evidence pack.",
    )


def _write_integrity_evidence(tmp_path):
    pack = generate_artifact_pack()
    pack_files = artifact_pack_to_files(pack)
    condition_payload = json.loads(pack_files["condition_key.json"])
    condition_key = condition_payload["conditions"]
    answers_path = tmp_path / "answers.csv"
    with answers_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "incident_id",
                "condition_label",
                "reviewer_id",
                "question_id",
                "answer",
                "confidence",
                "elapsed_seconds",
            ),
        )
        writer.writeheader()
        for row in csv.DictReader(StringIO(pack_files["reviewer_answer_template.csv"])):
            label = row["condition_label"]
            condition = condition_key[label]
            internal_id = next(
                incident_id
                for incident_id in pack.answer_key
                if forensic_benchmark.reviewer_incident_pseudonym(
                    pack.pack_nonce,
                    incident_id,
                    condition,
                    row["reviewer_id"],
                )
                == row["incident_id"]
            )
            ground_truth = pack.answer_key[internal_id][row["question_id"]]
            writer.writerow(
                {
                    "incident_id": row["incident_id"],
                    "condition_label": label,
                    "reviewer_id": row["reviewer_id"],
                    "question_id": row["question_id"],
                    "answer": (
                        ground_truth
                        if condition == "acgs_receipts_and_audit_artifacts"
                        else "incorrect"
                    ),
                    "confidence": "0.9",
                    "elapsed_seconds": "10",
                }
            )
    packet_dir = tmp_path / "reviewer_packet"
    packet_dir.mkdir()
    manifest = json.loads(pack_files["reviewer_manifest.json"])
    packet_files = {
        path: pack_files[path]
        for path in manifest["files"]
    }
    for relative_path, content in packet_files.items():
        output_path = packet_dir / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
    manifest_path = packet_dir / "reviewer_manifest.json"
    manifest_path.write_text(pack_files["reviewer_manifest.json"])
    (tmp_path / "answer_key.json").write_text(pack_files["answer_key.json"])
    (tmp_path / "condition_key.json").write_text(pack_files["condition_key.json"])
    (tmp_path / "protocol.json").write_text(pack_files["protocol.json"])
    replication = _integrity_replication_record()
    (tmp_path / "replication.json").write_text(replication.model_dump_json())
    answer_bytes = answers_path.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    (tmp_path / "answer-seal.json").write_text(
        json.dumps(
            {
                "schema": "acgs-v0.1-collected-blind-answers-seal",
                "answers_csv": {
                    "sha256": hashlib.sha256(answer_bytes).hexdigest(),
                    "bytes": len(answer_bytes),
                },
                "reviewer_packet": {
                    "reviewer_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest()
                },
                "precollection_commitment": forensic_benchmark.precollection_commitment_digest(
                    pack_files
                ),
                "validation": {
                    "valid": True,
                    "row_count": 50 * 6 * len(FORENSIC_QUESTIONNAIRE),
                    "reviewer_count": 6,
                },
            },
            sort_keys=True,
        )
    )
    evidence_paths = {
        "answers_csv": "answers.csv",
        "answer_seal": "answer-seal.json",
        "reviewer_manifest": "reviewer_packet/reviewer_manifest.json",
        "answer_key": "answer_key.json",
        "condition_key": "condition_key.json",
        "protocol": "protocol.json",
        "replication_metadata": "replication.json",
    }
    member_path = next((packet_dir / path for path in packet_files if path.startswith("reviewer_artifacts/")))
    return pack, replication, evidence_paths, member_path


def _expected_precollection_commitment(tmp_path) -> str:
    return json.loads((tmp_path / "answer-seal.json").read_text())[
        "precollection_commitment"
    ]


def test_result_bundle_rehashes_actual_files_and_recomputes_statistics(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is True
    assert verdict.issues == []
    assert verdict.authenticated_provenance is False
    assert verdict.external_success is False
    assert verdict.independence_verified is False
    assert verdict.command_metadata == replication.command_line
    assert {diagnostic.code for diagnostic in verdict.provenance_diagnostics} == {
        "authenticated_provenance_unavailable",
        "identical_reviewer_answer_vectors",
        "unauthenticated_command_metadata",
    }
    assert bundle.answer_evidence.answers_sha256 == hashlib.sha256(
        (tmp_path / "answers.csv").read_bytes()
    ).hexdigest()
    assert bundle.p_value_vs_strongest_baseline == 2**-50


def test_result_bundle_rejects_tampered_manifest_member(tmp_path) -> None:
    pack, replication, evidence_paths, member_path = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    member_path.write_text('{"evidence":"tampered"}\n')

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "manifest_member_sha256_mismatch",
        "bound_evidence_content_mismatch",
    }


def test_result_bundle_rejects_fabricated_hash_and_p_value(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    fake_binding = bundle.evidence_files[0].model_copy(update={"sha256": "a" * 64})
    tampered = bundle.model_copy(
        update={
            "evidence_files": (fake_binding, *bundle.evidence_files[1:]),
            "p_value_vs_strongest_baseline": 0.01,
        }
    )

    verdict = forensic_benchmark.validate_result_bundle(
        tampered,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "bound_evidence_content_mismatch",
    }


def test_result_bundle_rejects_untrusted_replication_group(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=(),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is False
    assert "replicating_group_not_trusted" in {issue.code for issue in verdict.issues}


def test_result_bundle_rejects_p_value_not_computed_from_sealed_csv(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    ).model_copy(update={"p_value_vs_strongest_baseline": 0.01})

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is False
    assert "sealed_p_value_mismatch" in {issue.code for issue in verdict.issues}


def test_result_bundle_builder_rejects_malformed_seal(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    expected_commitment = _expected_precollection_commitment(tmp_path)
    (tmp_path / "answer-seal.json").write_text('{"schema":"wrong"}')

    with pytest.raises(ValueError, match="invalid_answer_seal"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=expected_commitment,
        )


def test_result_bundle_builder_rejects_empty_manifest(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    expected_commitment = _expected_precollection_commitment(tmp_path)
    manifest_path = tmp_path / "reviewer_packet" / "reviewer_manifest.json"
    manifest_path.write_text('{"files":{}}')
    answer_bytes = (tmp_path / "answers.csv").read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    (tmp_path / "answer-seal.json").write_text(
        json.dumps(
            {
                "schema": "acgs-v0.1-collected-blind-answers-seal",
                "answers_csv": {
                    "sha256": hashlib.sha256(answer_bytes).hexdigest(),
                    "bytes": len(answer_bytes),
                },
                "reviewer_packet": {
                    "reviewer_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest()
                },
                "validation": {
                    "valid": True,
                    "row_count": 50 * 3 * 2 * len(FORENSIC_QUESTIONNAIRE),
                    "reviewer_count": 2,
                },
            }
        )
    )

    with pytest.raises(ValueError, match="invalid_evidence_manifest"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=expected_commitment,
        )


def test_result_bundle_rejects_missing_bound_file(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    (tmp_path / "answer_key.json").unlink()

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "evidence_file_missing",
        "bound_evidence_file_missing",
    }


def test_result_bundle_builder_rejects_hashed_but_malformed_reviewer_packet(
    tmp_path,
) -> None:
    pack, replication, evidence_paths, member_path = _write_integrity_evidence(tmp_path)
    original_bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    malformed = b'{"evidence":"sealed"}\n'
    member_path.write_bytes(malformed)
    manifest_path = tmp_path / "reviewer_packet" / "reviewer_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    relative_member = member_path.relative_to(manifest_path.parent).as_posix()
    manifest["files"][relative_member] = {
        "sha256": hashlib.sha256(malformed).hexdigest(),
        "bytes": len(malformed),
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    seal_path = tmp_path / "answer-seal.json"
    seal = json.loads(seal_path.read_text())
    seal["reviewer_packet"]["reviewer_manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    seal_path.write_text(json.dumps(seal, sort_keys=True))

    with pytest.raises(ValueError, match="invalid_reviewer_packet"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
        )

    rebound = []
    for binding in original_bundle.evidence_files:
        actual_path = tmp_path / binding.relative_path
        actual_bytes = actual_path.read_bytes()
        rebound.append(
            binding.model_copy(
                update={
                    "sha256": hashlib.sha256(actual_bytes).hexdigest(),
                    "size_bytes": len(actual_bytes),
                }
            )
        )
    forged_bundle = original_bundle.model_copy(update={"evidence_files": tuple(rebound)})
    verdict = forensic_benchmark.validate_result_bundle(
        forged_bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    assert verdict.valid is False
    assert "invalid_reviewer_packet" in {issue.code for issue in verdict.issues}


def test_result_bundle_builder_rejects_condition_key_without_pack_nonce(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    expected_commitment = _expected_precollection_commitment(tmp_path)
    condition_path = tmp_path / "condition_key.json"
    envelope = json.loads(condition_path.read_text())
    condition_path.write_text(json.dumps(envelope["conditions"], sort_keys=True))

    with pytest.raises(ValueError, match="canonical_pack_regeneration_failed"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=expected_commitment,
        )


def test_result_bundle_builder_rejects_duplicate_condition_key_fields(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    expected_commitment = _expected_precollection_commitment(tmp_path)
    condition_path = tmp_path / "condition_key.json"
    envelope = json.loads(condition_path.read_text())
    condition_path.write_text(
        "{"
        f'"conditions":{json.dumps(envelope["conditions"])},'
        f'"pack_nonce":"{envelope["pack_nonce"]}",'
        f'"pack_nonce":"{envelope["pack_nonce"]}"'
        "}"
    )

    with pytest.raises(ValueError, match="canonical_pack_regeneration_failed"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=expected_commitment,
        )


def test_result_bundle_optional_answers_crosscheck_is_order_independent(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    loaded = {
        name: (tmp_path / relative_path).read_bytes()
        for name, relative_path in evidence_paths.items()
    }
    answers = forensic_benchmark._answers_from_bound_evidence(loaded)

    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
        answers=list(reversed(answers)),
    )

    assert bundle.answer_evidence.row_count == len(answers)


def test_result_bundle_optional_answers_crosscheck_rejects_changed_value(tmp_path) -> None:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    loaded = {
        name: (tmp_path / relative_path).read_bytes()
        for name, relative_path in evidence_paths.items()
    }
    answers = forensic_benchmark._answers_from_bound_evidence(loaded)
    answers[0] = answers[0].model_copy(update={"answer": "forged"})

    with pytest.raises(ValueError, match="do not match the sealed answer CSV"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
            answers=answers,
        )


def test_cli_rejects_removed_p_value_override(capsys) -> None:
    from scripts import run_governance_benchmark as benchmark_cli

    with pytest.raises(SystemExit) as exc_info:
        benchmark_cli.main(["--p-value", "0.01"])

    assert exc_info.value.code == 2
    assert "unrecognized arguments: --p-value 0.01" in capsys.readouterr().err


def test_cli_condition_key_loader_rejects_legacy_flat_map(tmp_path) -> None:
    from scripts import run_governance_benchmark as benchmark_cli

    condition_key_path = tmp_path / "condition_key.json"
    condition_key_path.write_text(
        json.dumps(
            dict(
                zip(
                    forensic_benchmark.BLINDED_CONDITION_LABELS,
                    BASELINES,
                    strict=True,
                )
            )
        )
    )

    with pytest.raises(ValueError, match="conditions and pack_nonce"):
        benchmark_cli._load_condition_key(condition_key_path)


def test_cli_kit_verifier_requires_condition_key_outside_manifest(tmp_path) -> None:
    from scripts import run_governance_benchmark as benchmark_cli

    kit_dir = tmp_path / "kit"
    result = benchmark_cli._write_replication_kit(kit_dir, 50)
    assert result["reviewer_packet_audit_valid"] is True

    (kit_dir / "coordinator_pack" / "condition_key.json").unlink()
    manifest_path = kit_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"].pop("coordinator_pack/condition_key.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    verdict = benchmark_cli._verify_replication_kit(kit_dir)

    assert verdict["valid"] is False
    assert "missing_condition_key" in {
        issue["code"] for issue in verdict["issues"]
    }


@pytest.mark.parametrize(
    ("organization", "expected_valid"),
    [
        ("Independent Review Lab", True),
        ("Acg5 Independent Lab", False),
        ("ΑCGS Lab", False),
        ("ＡＣＧＳ Lab", False),
        ("A-C-G-S Lab", False),
        ("A\u200bC\u200bG\u200bS Lab", False),
    ],
)
def test_cli_cohort_identity_policy_rejects_acgs_lookalikes(
    tmp_path,
    capsys,
    organization: str,
    expected_valid: bool,
) -> None:
    from scripts import run_governance_benchmark as benchmark_cli

    manifest_path = tmp_path / "reviewer_cohort_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "artifact_access_scope": "reviewer_packet_only",
                "blind_to_condition_labels": True,
                "blind_to_ground_truth": True,
                "cohort_id": "cohort-2026-10",
                "conflict_of_interest_screened": True,
                "recruiting_organization": organization,
                "reviewer_count": 6,
                "reviewer_roster_sha256": "a" * 64,
            }
        )
    )

    return_code = benchmark_cli.main(
        [
            "--validate-reviewer-cohort-manifest",
            str(manifest_path),
            "--trusted-attestor",
            organization,
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert return_code == (0 if expected_valid else 1)
    assert payload["valid"] is expected_valid
    assert payload["success_evidence"] is False
    assert payload["authenticated_provenance"] is False
    assert payload["independence_verified"] is False
    assert payload["diagnostics"]
    if not expected_valid:
        assert "reviewer_cohort_not_trusted" in {
            issue["code"] for issue in payload["issues"]
        }


def _cli_bound_bundle_args(tmp_path, mode: str, *, tampered: bool) -> list[str]:
    pack, replication, evidence_paths, _ = _write_integrity_evidence(tmp_path)
    answers_path = tmp_path / "answers.csv"
    template_path = tmp_path / "reviewer_packet" / "reviewer_answer_template.csv"
    with template_path.open(newline="") as handle:
        template_rows = {
            (
                row["incident_id"],
                row["condition_label"],
                row["reviewer_id"],
                row["question_id"],
            ): row
            for row in csv.DictReader(handle)
        }
    with answers_path.open(newline="") as handle:
        answer_rows = list(csv.DictReader(handle))
    fieldnames = (
        "incident_id",
        "condition_label",
        "reviewer_id",
        "question_id",
        "question_text",
        "artifact_path",
        "answer",
        "confidence",
        "elapsed_seconds",
    )
    with answers_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in answer_rows:
            key = (
                row["incident_id"],
                row["condition_label"],
                row["reviewer_id"],
                row["question_id"],
            )
            template = template_rows[key]
            writer.writerow(
                {
                    **row,
                    "question_text": template["question_text"],
                    "artifact_path": template["artifact_path"],
                }
            )
    seal_path = tmp_path / "answer-seal.json"
    seal = json.loads(seal_path.read_text())
    answer_bytes = answers_path.read_bytes()
    seal["answers_csv"] = {
        "sha256": hashlib.sha256(answer_bytes).hexdigest(),
        "bytes": len(answer_bytes),
    }
    seal_path.write_text(json.dumps(seal, sort_keys=True))
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=_expected_precollection_commitment(tmp_path),
    )
    if tampered:
        bundle = bundle.model_copy(update={"p_value_vs_strongest_baseline": 0.01})
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())
    common = [
        "--evidence-root",
        str(tmp_path),
        "--expected-precollection-commitment",
        _expected_precollection_commitment(tmp_path),
        "--trusted-attestor",
        "Independent Systems Lab",
    ]

    if mode == "scorecard":
        scorecard_path = tmp_path / "scorecard.json"
        scorecard_path.write_text(bundle.scorecard.model_dump_json())
        return [
            "--validate-scorecard",
            str(scorecard_path),
            "--scorecard-result-bundle",
            str(bundle_path),
            *common,
        ]
    if mode == "cohort":
        cohort_path = tmp_path / "reviewer-cohort.json"
        cohort_path.write_text(
            json.dumps(
                {
                    "artifact_access_scope": "reviewer_packet_only",
                    "blind_to_condition_labels": True,
                    "blind_to_ground_truth": True,
                    "cohort_id": "cohort-2026-10",
                    "conflict_of_interest_screened": True,
                    "recruiting_organization": "Independent Systems Lab",
                    "reviewer_count": 6,
                    "reviewer_roster_sha256": "b" * 64,
                }
            )
        )
        return [
            "--validate-reviewer-cohort-manifest",
            str(cohort_path),
            "--cohort-result-bundle",
            str(bundle_path),
            *common,
        ]
    if mode == "answer_seal":
        return [
            "--verify-collected-answers-seal",
            str(tmp_path / "answer-seal.json"),
            "--answers-csv",
            str(tmp_path / "answers.csv"),
            "--reviewer-packet",
            str(tmp_path / "reviewer_packet"),
            "--protocol-json",
            str(tmp_path / "protocol.json"),
            "--answer-key-json",
            str(tmp_path / "answer_key.json"),
            "--condition-key-json",
            str(tmp_path / "condition_key.json"),
            "--answer-seal-result-bundle",
            str(bundle_path),
            *common,
        ]
    if mode == "answer_matrix":
        return [
            "--validate-answer-matrix",
            str(tmp_path / "answers.csv"),
            "--protocol-json",
            str(tmp_path / "protocol.json"),
            "--answer-key-json",
            str(tmp_path / "answer_key.json"),
            "--condition-key-json",
            str(tmp_path / "condition_key.json"),
            "--answer-matrix-result-bundle",
            str(bundle_path),
            *common,
        ]
    if mode == "attestation":
        scorecard_path = tmp_path / "scorecard.json"
        cohort_path = tmp_path / "reviewer-cohort.json"
        artifact_path = tmp_path / "artifact-pack.tar.gz"
        transcript_path = tmp_path / "commands-transcript.txt"
        attestation_path = tmp_path / "attestation.json"
        scorecard_path.write_text(bundle.scorecard.model_dump_json())
        cohort_path.write_text("cohort evidence")
        artifact_path.write_text("artifact evidence")
        transcript_path.write_text(replication.command_line)
        attestation_path.write_text(
            json.dumps(
                {
                    "artifact_pack_sha256": hashlib.sha256(
                        artifact_path.read_bytes()
                    ).hexdigest(),
                    "attestation_id": "attestation-2026-10",
                    "attestor_name": "Independent Attestor",
                    "attestor_role": "External reviewer",
                    "commands_transcript_sha256": hashlib.sha256(
                        transcript_path.read_bytes()
                    ).hexdigest(),
                    "conflict_of_interest_screened": True,
                    "declares_independent_rerun": True,
                    "declares_no_acgs_authorship": True,
                    "replicating_group": replication.replicating_group,
                    "result_bundle_sha256": hashlib.sha256(
                        bundle_path.read_bytes()
                    ).hexdigest(),
                    "reviewer_cohort_manifest_sha256": hashlib.sha256(
                        cohort_path.read_bytes()
                    ).hexdigest(),
                    "scorecard_sha256": hashlib.sha256(
                        scorecard_path.read_bytes()
                    ).hexdigest(),
                    "signed_at": "2026-10-08T00:00:00Z",
                }
            )
        )
        return [
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(tmp_path / "replication.json"),
            "--attested-result-bundle",
            str(bundle_path),
            "--attested-reviewer-cohort-manifest",
            str(cohort_path),
            "--attested-scorecard",
            str(scorecard_path),
            "--attested-artifact-pack",
            str(artifact_path),
            "--attested-commands-transcript",
            str(transcript_path),
            "--trusted-attestor",
            "Independent Attestor",
            *common,
        ]
    raise AssertionError(f"unknown mode: {mode}")


@pytest.mark.parametrize(
    "mode",
    ["scorecard", "cohort", "answer_seal", "answer_matrix", "attestation"],
)
@pytest.mark.parametrize("tampered", [False, True])
def test_cli_bundle_consumers_validate_bound_evidence(
    tmp_path,
    capsys,
    mode: str,
    tampered: bool,
) -> None:
    from scripts import run_governance_benchmark as benchmark_cli

    return_code = benchmark_cli.main(
        _cli_bound_bundle_args(tmp_path, mode, tampered=tampered)
    )
    payload = json.loads(capsys.readouterr().out)

    assert return_code == (1 if tampered else 0)
    if tampered:
        assert "sealed_p_value_mismatch" in {
            issue["code"] for issue in payload["issues"]
        }
