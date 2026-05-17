from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from constitutional_swarm.forensic_benchmark import (
    ADVERSARIAL_TECHNIQUES,
    BASELINES,
    FORENSIC_QUESTIONNAIRE,
    BenchmarkResultBundle,
    CollectedAnswerEvidence,
    ConditionScore,
    ExternalReplicationRecord,
    ForensicBenchmarkProtocol,
    ReviewerAnswer,
    ReviewerCohortManifest,
    artifact_pack_to_files,
    blinded_condition_key,
    build_result_bundle,
    generate_artifact_pack,
    paired_sign_test_p_value,
    replication_metadata_template,
    reviewer_answer_template_csv,
    reviewer_artifacts_exclude_ground_truth,
    reviewer_packet_files,
    score_reviewer_answers,
    validate_answer_matrix,
    validate_protocol,
    validate_result_bundle,
)
from constitutional_swarm.governance_fixtures import (
    collusion_bundle,
    fixture_trusted_signers,
    forged_provenance_bundle,
    slow_burn_bundle,
    valid_provenance_bundle,
)
from constitutional_swarm.governance_receipts import (
    GovernanceReceiptBundle,
    SignatureRecord,
    build_receipt,
    bundle_to_json,
    payload_canonical_bytes,
    payload_digest,
    verify_bundle,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.run_governance_benchmark import (
    required_public_artifact_verification_commands,
)

REPLICATION_RELEASE_TAG_URL = (
    "https://github.com/dislovelhl/Acgs-Swarm/releases/tag/"
    "acgs-v0.1-benchmark-kit-2026-05-16"
)
REPLICATION_RELEASE_DOWNLOAD_BASE = REPLICATION_RELEASE_TAG_URL.replace(
    "/releases/tag/",
    "/releases/download/",
)


def test_golden_payload_canonical_bytes_are_deterministic() -> None:
    bundle = valid_provenance_bundle()
    payload = bundle.receipts[0].payload

    first = payload_canonical_bytes(payload)
    second = payload_canonical_bytes(payload.model_copy())

    assert first == second
    assert (
        payload_digest(payload)
        == "18bda95d0abc073b2125f6caedcad7701927e030f8ed952453a760a7aa8d3939"
    )


def test_valid_bundle_verifies_with_role_separation_and_chain() -> None:
    verdict = verify_bundle(
        valid_provenance_bundle(),
        trusted_signers=fixture_trusted_signers(),
    )

    assert verdict.valid is True
    assert verdict.signature_status == "valid"
    assert verdict.receipt_count == 2
    assert verdict.issues == []


def test_forged_payload_is_rejected_fail_closed() -> None:
    verdict = verify_bundle(
        forged_provenance_bundle(),
        trusted_signers=fixture_trusted_signers(),
    )

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "payload_digest_mismatch",
        "signature_invalid",
    }


def test_broken_hash_chain_is_rejected() -> None:
    bundle = valid_provenance_bundle()
    broken_payload = bundle.receipts[1].payload.model_copy(
        update={"previous_receipt_hash": "sha256:not-the-previous-receipt"}
    )
    broken_receipt = bundle.receipts[1].model_copy(update={"payload": broken_payload})
    broken_bundle = bundle.model_copy(update={"receipts": [bundle.receipts[0], broken_receipt]})

    verdict = verify_bundle(broken_bundle, trusted_signers=fixture_trusted_signers())

    assert verdict.valid is False
    assert "broken_hash_chain" in {issue.code for issue in verdict.issues}


def test_role_separation_violation_is_rejected() -> None:
    bundle = valid_provenance_bundle()
    payload = bundle.receipts[0].payload
    same_identity_roles = {
        role: identity.model_copy(update={"identity_id": "same-agent"})
        for role, identity in payload.roles.items()
    }
    broken_payload = payload.model_copy(update={"roles": same_identity_roles})
    broken_receipt = bundle.receipts[0].model_copy(update={"payload": broken_payload})
    broken_bundle = bundle.model_copy(update={"receipts": [broken_receipt]})

    verdict = verify_bundle(broken_bundle, trusted_signers=fixture_trusted_signers())

    assert verdict.valid is False
    assert "role_separation_violation" in {issue.code for issue in verdict.issues}


def test_signature_unverifiable_fails_closed_but_report_mode_passes() -> None:
    bundle = valid_provenance_bundle()
    unsigned = bundle.receipts[0].model_copy(
        update={"signatures": [SignatureRecord(key_id="unsigned", algorithm="none")]}
    )
    unsigned_bundle = bundle.model_copy(update={"receipts": [unsigned]})

    fail_closed = verify_bundle(unsigned_bundle, trusted_signers=fixture_trusted_signers())
    report = verify_bundle(
        unsigned_bundle,
        report_mode=True,
        trusted_signers=fixture_trusted_signers(),
    )

    assert fail_closed.valid is False
    assert fail_closed.signature_status == "unverifiable"
    assert report.valid is True
    assert report.signature_status == "unverifiable"


def test_bundle_json_round_trip_preserves_profile() -> None:
    bundle = valid_provenance_bundle()

    round_tripped = GovernanceReceiptBundle.model_validate_json(bundle_to_json(bundle))

    assert round_tripped == bundle


def test_devops_fixtures_are_offline_and_verifiable() -> None:
    trusted = fixture_trusted_signers()

    assert verify_bundle(collusion_bundle(), trusted_signers=trusted).valid is True
    assert verify_bundle(slow_burn_bundle(), trusted_signers=trusted).valid is True
    assert verify_bundle(forged_provenance_bundle(), trusted_signers=trusted).valid is False


def test_resigned_tampering_with_unknown_key_fails_closed() -> None:
    bundle = valid_provenance_bundle()
    forged_payload = bundle.receipts[1].payload.model_copy(update={"decision": "approved"})
    attacker_key = Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32)
    attacker_public = attacker_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    attacker_signature = SignatureRecord(
        key_id="attacker-key",
        algorithm="ed25519",
        public_key_hex=attacker_public.hex(),
        signature_hex=attacker_key.sign(payload_canonical_bytes(forged_payload)).hex(),
    )
    forged_receipt = build_receipt(payload=forged_payload, signatures=[attacker_signature])
    forged_bundle = bundle.model_copy(update={"receipts": [bundle.receipts[0], forged_receipt]})

    verdict = verify_bundle(forged_bundle, trusted_signers=fixture_trusted_signers())

    assert verdict.valid is False
    assert "signature_unverifiable" in {issue.code for issue in verdict.issues}


def test_verifier_without_external_trust_root_fails_closed() -> None:
    verdict = verify_bundle(valid_provenance_bundle())

    assert verdict.valid is False
    assert verdict.signature_status == "unverifiable"


def test_verifier_cli_exit_codes_and_deterministic_json(tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    trusted_path = tmp_path / "trusted-signers.json"
    bundle_path.write_text(bundle_to_json(valid_provenance_bundle()))
    trusted_path.write_text(json.dumps(fixture_trusted_signers(), sort_keys=True))

    first = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            str(bundle_path),
            "--trusted-signers",
            str(trusted_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            str(bundle_path),
            "--trusted-signers",
            str(trusted_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert first.returncode == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["valid"] is True


def test_verifier_cli_rejects_forged_bundle(tmp_path) -> None:
    bundle_path = tmp_path / "forged.json"
    trusted_path = tmp_path / "trusted-signers.json"
    bundle_path.write_text(bundle_to_json(forged_provenance_bundle()))
    trusted_path.write_text(json.dumps(fixture_trusted_signers(), sort_keys=True))

    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            str(bundle_path),
            "--trusted-signers",
            str(trusted_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["valid"] is False


def test_governance_benchmark_runner_emits_required_metrics() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/run_governance_benchmark.py"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["pass"] is True
    assert payload["official_swebench_claimed"] is False
    assert payload["healthcare_compliance_claimed"] is False
    assert payload["production_grade_governance_claimed"] is False
    assert payload["reconstructability"]["score"] == 1.0
    assert payload["containment_delta"]["delta"] > 0
    assert payload["k_of_n_compromise"]["first_failure_k"] == 1
    assert payload["overhead_curve"]["token_estimate"] == 0
    assert payload["baseline"]["general_orchestrator_exported"] is False


def test_public_forensic_protocol_covers_v0_1_success_standard() -> None:
    protocol = ForensicBenchmarkProtocol(
        incident_count=50,
        questionnaire=FORENSIC_QUESTIONNAIRE,
        baselines=BASELINES,
        adversarial_techniques=ADVERSARIAL_TECHNIQUES,
        blind_review=True,
        hidden_ground_truth_separated=True,
        artifact_sets={
            "ungoverned_raw_logs": "artifacts/ungoverned_raw_logs/",
            "centralized_structured_logs": "artifacts/centralized_structured_logs/",
            "acgs_receipts_and_audit_artifacts": "artifacts/acgs_receipts_and_audit_artifacts/",
        },
        external_replication_instructions="external group reruns with hidden ground truth",
    )

    verdict = validate_protocol(protocol)

    assert verdict.valid is True
    assert verdict.issues == []


def test_public_forensic_protocol_rejects_conformance_only_shortcuts() -> None:
    protocol = ForensicBenchmarkProtocol(
        incident_count=3,
        questionnaire=("who_acted",),
        baselines=("acgs_receipts_and_audit_artifacts",),
        adversarial_techniques=("collusion",),
        blind_review=False,
        hidden_ground_truth_separated=False,
        artifact_sets={
            "ungoverned_raw_logs": "artifacts/ungoverned_raw_logs/",
            "centralized_structured_logs": "artifacts/centralized_structured_logs/",
            "acgs_receipts_and_audit_artifacts": "artifacts/acgs_receipts_and_audit_artifacts/",
        },
        external_replication_instructions="local verifier only",
        scoring_metrics=("answer_accuracy",),
    )

    verdict = validate_protocol(protocol)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "incident_count_out_of_range",
        "questionnaire_mismatch",
        "missing_baselines",
        "missing_adversarial_techniques",
        "blind_review_not_enforced",
        "missing_scoring_metrics",
    }


def test_reviewer_scorecard_reports_delta_against_strongest_baseline() -> None:
    answers = [
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="ungoverned_raw_logs",
            reviewer_id="r1",
            question_id="who_acted",
            answer="unknown",
            ground_truth="deploy-agent",
            confidence=0.7,
            elapsed_seconds=90,
        ),
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="ungoverned_raw_logs",
            reviewer_id="r2",
            question_id="who_acted",
            answer="unknown",
            ground_truth="deploy-agent",
            confidence=0.6,
            elapsed_seconds=95,
        ),
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="centralized_structured_logs",
            reviewer_id="r1",
            question_id="who_acted",
            answer="deploy-agent",
            ground_truth="deploy-agent",
            confidence=0.6,
            elapsed_seconds=75,
        ),
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="centralized_structured_logs",
            reviewer_id="r2",
            question_id="who_acted",
            answer="review-agent",
            ground_truth="deploy-agent",
            confidence=0.6,
            elapsed_seconds=80,
        ),
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="acgs_receipts_and_audit_artifacts",
            reviewer_id="r1",
            question_id="who_acted",
            answer="deploy-agent",
            ground_truth="deploy-agent",
            confidence=0.9,
            elapsed_seconds=30,
        ),
        ReviewerAnswer(
            incident_id="incident-001",
            artifact_condition="acgs_receipts_and_audit_artifacts",
            reviewer_id="r2",
            question_id="who_acted",
            answer="deploy-agent",
            ground_truth="deploy-agent",
            confidence=0.8,
            elapsed_seconds=32,
        ),
    ]

    scorecard = score_reviewer_answers(answers)

    assert scorecard.strongest_baseline == "centralized_structured_logs"
    assert scorecard.acgs_wins is True
    assert scorecard.performance_delta_vs_strongest_baseline > 0


def test_governance_benchmark_runner_emits_public_protocol_manifest() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/run_governance_benchmark.py", "--protocol-manifest"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["validation"]["valid"] is True
    assert payload["protocol"]["incident_count"] == 50
    assert payload["protocol"]["questionnaire"] == list(FORENSIC_QUESTIONNAIRE)
    assert payload["protocol"]["baselines"] == list(BASELINES)
    assert payload["protocol"]["adversarial_techniques"] == list(ADVERSARIAL_TECHNIQUES)


def test_governance_benchmark_runner_scores_reviewer_answer_csv(tmp_path) -> None:
    answers_path = tmp_path / "answers.csv"
    answers_path.write_text(
        "\n".join(
            [
                "incident_id,artifact_condition,reviewer_id,question_id,answer,ground_truth,confidence,elapsed_seconds",
                "incident-001,ungoverned_raw_logs,r1,who_acted,unknown,deploy-agent,0.7,90",
                "incident-001,centralized_structured_logs,r1,who_acted,deploy-agent,deploy-agent,0.6,75",
                "incident-001,acgs_receipts_and_audit_artifacts,r1,who_acted,deploy-agent,deploy-agent,0.9,30",
            ]
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--score-reviewer-answers",
            str(answers_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["strongest_baseline"] == "centralized_structured_logs"
    assert payload["acgs_wins"] is True
    assert payload["performance_delta_vs_strongest_baseline"] > 0


def test_governance_benchmark_runner_scores_blind_csv_with_hidden_answer_key(tmp_path) -> None:
    pack = generate_artifact_pack()
    answers_path = tmp_path / "blind-answers.csv"
    answer_key_path = tmp_path / "answer-key.json"
    answer_key_path.write_text(json.dumps(pack.answer_key))
    _write_blind_answers_csv(
        answers_path,
        [
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="ungoverned_raw_logs",
                reviewer_id="r1",
                question_id="who_acted",
                answer="unknown",
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.7,
                elapsed_seconds=90,
            ),
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="centralized_structured_logs",
                reviewer_id="r1",
                question_id="who_acted",
                answer=pack.answer_key["incident-001"]["who_acted"],
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.6,
                elapsed_seconds=75,
            ),
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="acgs_receipts_and_audit_artifacts",
                reviewer_id="r1",
                question_id="who_acted",
                answer=pack.answer_key["incident-001"]["who_acted"],
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.9,
                elapsed_seconds=30,
            ),
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--score-reviewer-answers",
            str(answers_path),
            "--answer-key-json",
            str(answer_key_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["acgs_wins"] is True


def test_governance_benchmark_runner_scores_condition_blinded_csv(tmp_path) -> None:
    pack = generate_artifact_pack()
    answers_path = tmp_path / "condition-blinded-answers.csv"
    answer_key_path = tmp_path / "answer-key.json"
    condition_key_path = tmp_path / "condition-key.json"
    answer_key_path.write_text(json.dumps(pack.answer_key))
    condition_key_path.write_text(json.dumps(blinded_condition_key()))
    _write_condition_blinded_answers_csv(
        answers_path,
        [
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="ungoverned_raw_logs",
                reviewer_id="r1",
                question_id="who_acted",
                answer="unknown",
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.7,
                elapsed_seconds=90,
            ),
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="centralized_structured_logs",
                reviewer_id="r1",
                question_id="who_acted",
                answer=pack.answer_key["incident-001"]["who_acted"],
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.6,
                elapsed_seconds=75,
            ),
            ReviewerAnswer(
                incident_id="incident-001",
                artifact_condition="acgs_receipts_and_audit_artifacts",
                reviewer_id="r1",
                question_id="who_acted",
                answer=pack.answer_key["incident-001"]["who_acted"],
                ground_truth=pack.answer_key["incident-001"]["who_acted"],
                confidence=0.9,
                elapsed_seconds=30,
            ),
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--score-reviewer-answers",
            str(answers_path),
            "--answer-key-json",
            str(answer_key_path),
            "--condition-key-json",
            str(condition_key_path),
            "--p-value",
            "0.01",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["acgs_wins"] is True


def test_generated_artifact_pack_has_50_incidents_and_hidden_answer_key() -> None:
    pack = generate_artifact_pack()

    assert pack.protocol.incident_count == 50
    assert set(pack.reviewer_artifacts) == set(BASELINES)
    assert len(pack.answer_key) == 50
    assert reviewer_artifacts_exclude_ground_truth(pack.reviewer_artifacts) is True
    for condition in BASELINES:
        assert len(pack.reviewer_artifacts[condition]) == 50
        assert {
            artifact["incident_id"] for artifact in pack.reviewer_artifacts[condition]
        } == set(pack.answer_key)

    files = artifact_pack_to_files(pack)
    assert "answer_key.json" in files
    assert "condition_key.json" in files
    assert "protocol.json" in files
    assert "reviewer_protocol.json" in files
    assert "reviewer_instructions.md" in files
    assert "reviewer_manifest.json" in files
    assert "reviewer_answer_template.csv" in files
    assert "replication_metadata_template.json" in files
    assert len(
        [
            path
            for path in files
            if path.startswith("artifacts/acgs_receipts_and_audit_artifacts/")
        ]
    ) == 50
    assert len(
        [
            path
            for path in files
            if path.startswith("reviewer_artifacts/condition_c/")
        ]
    ) == 50
    blinded_artifact = json.loads(files["reviewer_artifacts/condition_c/incident-001.json"])
    assert "artifact_condition" not in blinded_artifact
    manifest = json.loads(files["reviewer_manifest.json"])
    assert manifest["schema"] == "acgs-v0.1-reviewer-artifact-manifest"
    assert manifest["file_count"] == 153
    assert "answer_key.json" not in manifest["files"]
    assert "condition_key.json" not in manifest["files"]
    assert "protocol.json" not in manifest["files"]
    assert "README.md" not in manifest["files"]
    assert "reviewer_protocol.json" in manifest["files"]
    assert "reviewer_instructions.md" in manifest["files"]
    assert "artifacts/acgs_receipts_and_audit_artifacts/incident-001.json" not in manifest[
        "files"
    ]
    reviewer_protocol = json.loads(files["reviewer_protocol.json"])
    assert reviewer_protocol["condition_labels"] == ["condition_a", "condition_b", "condition_c"]
    assert "ungoverned_raw_logs" not in files["reviewer_protocol.json"]
    assert "centralized_structured_logs" not in files["reviewer_protocol.json"]
    assert "acgs_receipts_and_audit_artifacts" not in files["reviewer_protocol.json"]
    assert "ungoverned_raw_logs" not in files["reviewer_instructions.md"]
    assert "centralized_structured_logs" not in files["reviewer_instructions.md"]
    assert "acgs_receipts_and_audit_artifacts" not in files["reviewer_instructions.md"]
    template_entry = manifest["files"]["reviewer_answer_template.csv"]
    assert template_entry["sha256"] == hashlib.sha256(
        files["reviewer_answer_template.csv"].encode()
    ).hexdigest()
    assert "replication_metadata_template.json" not in manifest["files"]
    replication_template = ExternalReplicationRecord.model_validate_json(
        files["replication_metadata_template.json"]
    )
    assert replication_template.completed is False
    assert "TODO" in replication_template.replicating_group


def test_reviewer_packet_files_exclude_coordinator_only_material() -> None:
    files = artifact_pack_to_files(generate_artifact_pack())
    reviewer_files = reviewer_packet_files(files)

    assert set(reviewer_files) == set(json.loads(files["reviewer_manifest.json"])["files"])
    assert "answer_key.json" not in reviewer_files
    assert "condition_key.json" not in reviewer_files
    assert "protocol.json" not in reviewer_files
    assert "README.md" not in reviewer_files
    assert "replication_metadata_template.json" not in reviewer_files


def test_replication_template_is_not_success_evidence() -> None:
    pack = generate_artifact_pack()
    replication_template = ExternalReplicationRecord.model_validate(
        replication_metadata_template(pack)
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=replication_template,
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert "external_replication_incomplete" in {
        issue.code for issue in verdict.issues
    }


def test_reviewer_answer_template_is_blind_and_complete() -> None:
    pack = generate_artifact_pack()

    template = reviewer_answer_template_csv(pack)
    rows = list(csv.DictReader(template.splitlines()))

    assert len(rows) == 50 * len(BASELINES) * len(FORENSIC_QUESTIONNAIRE) * 2
    assert "ground_truth" not in rows[0]
    assert "answer_key" not in rows[0]
    assert "correct_answer" not in rows[0]
    assert "artifact_condition" not in rows[0]
    assert rows[0]["condition_label"] in blinded_condition_key()
    assert rows[0]["artifact_path"].startswith("reviewer_artifacts/condition_")
    assert rows[0]["answer"] == ""
    assert rows[0]["confidence"] == ""
    assert rows[0]["elapsed_seconds"] == ""
    assert {
        row["condition_label"] for row in rows
    } == set(blinded_condition_key())
    assert {row["question_id"] for row in rows} == set(FORENSIC_QUESTIONNAIRE)
    assert template == reviewer_answer_template_csv(pack)
    assert [row["condition_label"] for row in rows[:3]] != [
        "condition_a",
        "condition_a",
        "condition_a",
    ]


def test_governance_benchmark_runner_generates_incident_pack(tmp_path) -> None:
    output_dir = tmp_path / "pack"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-incident-pack",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["incident_count"] == 50
    assert (output_dir / "protocol.json").exists()
    assert (output_dir / "reviewer_protocol.json").exists()
    assert (output_dir / "reviewer_instructions.md").exists()
    assert (output_dir / "answer_key.json").exists()
    assert (output_dir / "condition_key.json").exists()
    assert (output_dir / "reviewer_manifest.json").exists()
    assert (output_dir / "reviewer_answer_template.csv").exists()
    assert (output_dir / "replication_metadata_template.json").exists()
    assert (
        output_dir
        / "artifacts"
        / "acgs_receipts_and_audit_artifacts"
        / "incident-001.json"
    ).exists()
    reviewer_artifact = json.loads(
        (
            output_dir
            / "artifacts"
            / "acgs_receipts_and_audit_artifacts"
            / "incident-001.json"
        ).read_text()
    )
    assert "ground_truth" not in reviewer_artifact
    assert "answer_key" not in reviewer_artifact
    blinded_artifact = json.loads(
        (output_dir / "reviewer_artifacts" / "condition_c" / "incident-001.json").read_text()
    )
    assert "artifact_condition" not in blinded_artifact


def test_governance_benchmark_runner_generates_reviewer_only_packet(tmp_path) -> None:
    output_dir = tmp_path / "reviewer-packet"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-reviewer-packet",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "files_written": 154,
        "hidden_files_written": False,
        "incident_count": 50,
        "output_dir": str(output_dir),
    }
    assert (output_dir / "reviewer_manifest.json").exists()
    assert (output_dir / "reviewer_protocol.json").exists()
    assert (output_dir / "reviewer_instructions.md").exists()
    assert (output_dir / "reviewer_answer_template.csv").exists()
    assert not (output_dir / "answer_key.json").exists()
    assert not (output_dir / "condition_key.json").exists()
    assert not (output_dir / "protocol.json").exists()
    assert not (output_dir / "artifacts").exists()


def test_governance_benchmark_runner_verifies_reviewer_manifest(tmp_path) -> None:
    output_dir = tmp_path / "pack"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-incident-pack",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-reviewer-manifest",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 0
    payload = json.loads(verify.stdout)
    assert payload == {
        "checked_files": 153,
        "issues": [],
        "valid": True,
    }


def test_governance_benchmark_runner_audits_reviewer_only_packet(tmp_path) -> None:
    output_dir = tmp_path / "reviewer-packet"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-reviewer-packet",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    audit = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--audit-reviewer-packet",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert audit.returncode == 0
    payload = json.loads(audit.stdout)
    assert payload["valid"] is True
    assert payload["manifest"] == {
        "checked_files": 153,
        "issues": [],
        "valid": True,
    }
    assert payload["privacy"] == {"issues": [], "valid": True}


def test_governance_benchmark_runner_rejects_coordinator_pack_as_reviewer_packet(
    tmp_path,
) -> None:
    output_dir = tmp_path / "full-pack"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-incident-pack",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    audit = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--audit-reviewer-packet",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert audit.returncode == 1
    payload = json.loads(audit.stdout)
    assert payload["valid"] is False
    assert payload["manifest"]["valid"] is True
    assert payload["privacy"]["valid"] is False
    assert "forbidden_reviewer_file" in {
        issue["code"] for issue in payload["privacy"]["issues"]
    }


def test_governance_benchmark_runner_writes_external_replication_kit(tmp_path) -> None:
    output_dir = tmp_path / "replication-kit"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "completed_external_replication": False,
        "coordinator_files_written": 309,
        "incident_count": 50,
        "kit_manifest": str(output_dir / "kit_manifest.json"),
        "output_dir": str(output_dir),
        "replication_metadata": str(output_dir / "replication_metadata.json"),
        "reviewer_files_written": 154,
        "reviewer_packet_audit_valid": True,
    }
    assert (output_dir / "coordinator_pack" / "answer_key.json").exists()
    assert (output_dir / "coordinator_pack" / "condition_key.json").exists()
    assert (output_dir / "reviewer_packet" / "reviewer_manifest.json").exists()
    assert (output_dir / "reviewer_cohort_manifest.json").exists()
    assert (output_dir / "replication_attestation.json").exists()
    assert (output_dir / "required_public_artifacts.json").exists()
    assert not (output_dir / "reviewer_packet" / "answer_key.json").exists()
    assert not (output_dir / "reviewer_packet" / "condition_key.json").exists()

    kit_manifest = json.loads((output_dir / "kit_manifest.json").read_text())
    assert kit_manifest["schema"] == "acgs-v0.1-external-replication-kit"
    assert kit_manifest["incident_count"] == 50
    assert kit_manifest["reviewer_packet_audit"]["valid"] is True
    assert "kit_manifest.json" not in kit_manifest["files"]
    assert "required_public_artifacts.json" in kit_manifest["files"]
    assert "reviewer_packet/reviewer_manifest.json" in kit_manifest["files"]
    assert "coordinator_pack/answer_key.json" in kit_manifest["files"]
    assert any(
        "--audit-reviewer-packet reviewer_packet" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--cohort-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--validate-replication-attestation replication_attestation.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--validate-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--answer-matrix-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--validate-scorecard scorecard.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--scorecard-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--completion-audit-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )
    assert any("--verify-replication-kit ." in command for command in kit_manifest["commands"])
    assert any(
        "--validate-required-public-artifacts required_public_artifacts.json" in command
        for command in kit_manifest["commands"]
    )
    assert any("--study-readiness-report ." in command for command in kit_manifest["commands"])
    assert any(
        "--seal-collected-answers collected-answers-seal.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--verify-collected-answers-seal collected-answers-seal.json" in command
        for command in kit_manifest["commands"]
    )
    assert any(
        "--answer-seal-result-bundle result-bundle.json" in command
        for command in kit_manifest["commands"]
    )

    replication = ExternalReplicationRecord.model_validate_json(
        (output_dir / "replication_metadata.json").read_text()
    )
    assert replication.completed is False
    assert "TODO" in replication.replicating_group
    assert "--audit-reviewer-packet reviewer_packet" in replication.command_line
    assert "--verify-replication-kit ." in replication.command_line
    assert (
        "--validate-required-public-artifacts required_public_artifacts.json"
        in replication.command_line
    )
    assert "--validate-reviewer-cohort-manifest" in replication.command_line
    assert "--cohort-result-bundle result-bundle.json" in replication.command_line
    assert "--validate-replication-attestation" in replication.command_line
    assert "--build-result-bundle result-bundle.json" in replication.command_line
    assert "--answer-seal-result-bundle result-bundle.json" in replication.command_line
    assert "--answer-matrix-result-bundle result-bundle.json" in replication.command_line
    assert "--validate-scorecard scorecard.json" in replication.command_line
    assert "--scorecard-result-bundle result-bundle.json" in replication.command_line
    assert "--completion-audit-result-bundle result-bundle.json" in replication.command_line

    required_artifacts = json.loads(
        (output_dir / "required_public_artifacts.json").read_text()
    )
    assert required_artifacts["schema"] == "acgs-v0.1-required-public-artifacts"
    required_artifact_list = required_artifacts["artifacts"]
    artifact_names = {
        artifact["artifact"] for artifact in required_artifact_list
    }
    required_artifacts = {
        artifact["artifact"]: artifact for artifact in required_artifact_list
    }
    assert artifact_names == {
        "public_blind_answer_matrix",
        "pre_unblinding_answer_seal",
        "external_reviewer_cohort_manifest",
        "public_scorecard",
        "external_replication_attestation",
    }
    expected_commands = required_public_artifact_verification_commands()
    assert (
        required_artifacts["public_blind_answer_matrix"]["required_reference"]
        == "answer_matrix_uri"
    )
    assert (
        required_artifacts["pre_unblinding_answer_seal"]["required_reference"]
        == "answer_seal_uri"
    )
    assert (
        required_artifacts["external_reviewer_cohort_manifest"]["required_reference"]
        == "reviewer_cohort_uri"
    )
    assert (
        required_artifacts["public_scorecard"]["required_reference"]
        == "scorecard_uri"
    )
    assert (
        required_artifacts["external_replication_attestation"]["required_reference"]
        == "attestation_uri"
    )
    assert (
        required_artifacts["public_blind_answer_matrix"]["verification_commands"]
        == list(expected_commands["public_blind_answer_matrix"])
    )
    assert (
        required_artifacts["pre_unblinding_answer_seal"]["verification_commands"]
        == list(expected_commands["pre_unblinding_answer_seal"])
    )
    assert (
        required_artifacts["external_reviewer_cohort_manifest"][
            "verification_commands"
        ]
        == list(expected_commands["external_reviewer_cohort_manifest"])
    )
    assert (
        required_artifacts["public_scorecard"]["verification_commands"]
        == list(expected_commands["public_scorecard"])
    )
    assert (
        required_artifacts["external_replication_attestation"][
            "verification_commands"
        ]
        == list(expected_commands["external_replication_attestation"])
    )
    assert all(
        artifact["bundle_reference"] is None
        for artifact in required_artifact_list
    )
    validate_inventory = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-required-public-artifacts",
            str(output_dir / "required_public_artifacts.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate_inventory.returncode == 0
    inventory_payload = json.loads(validate_inventory.stdout)
    assert inventory_payload["valid"] is True
    assert inventory_payload["artifact_count"] == 5


def test_governance_benchmark_runner_verifies_external_replication_kit(tmp_path) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 0
    payload = json.loads(verify.stdout)
    assert payload["valid"] is True
    assert payload["checked_files"] == 468
    assert payload["issues"] == []
    assert payload["reviewer_packet_audit"]["valid"] is True
    assert payload["required_public_artifacts"]["valid"] is True
    assert payload["required_public_artifacts"]["artifact_count"] == 5


def test_governance_benchmark_runner_writes_external_replication_submission_package(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.01,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())

    output_dir = tmp_path / "submission-package"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-external-replication-submission",
            str(output_dir),
            "--submission-result-bundle",
            str(bundle_path),
            "--submission-result-bundle-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/result-bundle.json",
            "--submission-replication-metadata-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/replication_metadata.json",
            "--submission-commands-transcript-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/commands-transcript.txt",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["missing_fields"] == []
    assert payload["output_dir"] == str(output_dir)
    assert payload["submission_json"] == str(output_dir / "submission.json")
    assert payload["submission_md"] == str(output_dir / "submission.md")
    assert payload["submission_fields"]["replicating_group_name"] == (
        "Independent Systems Lab"
    )
    assert payload["submission_fields"]["release_url"] == REPLICATION_RELEASE_TAG_URL
    assert payload["submission_fields"]["result_bundle_url"] == (
        f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/result-bundle.json"
    )
    assert payload["submission_fields"]["scorecard_url"] == (
        "https://zenodo.org/records/987654321/files/acgs-v0-1-scorecard.json"
    )
    assert payload["submission_fields"]["reviewer_cohort_url"] == (
        "https://zenodo.org/records/987654321/files/acgs-v0-1-reviewer-cohort.json"
    )
    assert payload["submission_fields"]["artifact_pack_url"] == (
        "https://zenodo.org/records/987654321/files/acgs-v0-1-pack.tar.gz"
    )
    assert payload["submission_fields"]["commands"][0].startswith(
        "python scripts/run_governance_benchmark.py --validate-result-bundle"
    )
    assert payload["validation"]["valid"] is True
    markdown = (output_dir / "submission.md").read_text()
    assert "# External replication submission" in markdown
    assert "Independent Systems Lab" in markdown
    assert f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/result-bundle.json" in markdown
    assert (
        f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/replication_metadata.json"
        in markdown
    )
    assert (
        f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/commands-transcript.txt"
        in markdown
    )
    submission_json = json.loads((output_dir / "submission.json").read_text())
    assert submission_json["schema"] == "acgs-v0.1-external-replication-submission"
    assert submission_json["public_request"]["release_url"] == REPLICATION_RELEASE_TAG_URL
    assert submission_json["required_public_artifacts"][0]["artifact"] == (
        "public_blind_answer_matrix"
    )


def test_governance_benchmark_runner_validates_external_replication_submission_package(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.01,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())

    output_dir = tmp_path / "submission-package"
    write = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-external-replication-submission",
            str(output_dir),
            "--submission-result-bundle",
            str(bundle_path),
            "--submission-result-bundle-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/result-bundle.json",
            "--submission-replication-metadata-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/replication_metadata.json",
            "--submission-commands-transcript-url",
            f"{REPLICATION_RELEASE_DOWNLOAD_BASE}/commands-transcript.txt",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert write.returncode == 0

    validate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-external-replication-submission",
            str(output_dir),
            "--submission-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate.returncode == 0
    payload = json.loads(validate.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []
    assert payload["submission_json"] == str(output_dir / "submission.json")
    assert payload["submission_md"] == str(output_dir / "submission.md")
    assert payload["result_bundle_summary"]["acgs_wins"] is True
    assert payload["result_bundle_summary"]["external_replication_completed"] is True


def test_governance_benchmark_runner_rejects_placeholder_submission_urls(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.01,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())

    output_dir = tmp_path / "submission-package"
    write = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-external-replication-submission",
            str(output_dir),
            "--submission-result-bundle",
            str(bundle_path),
            "--submission-result-bundle-url",
            "TODO-result-bundle-url",
            "--submission-replication-metadata-url",
            "https://example.org/replication_metadata.json",
            "--submission-commands-transcript-url",
            "https://example.org/commands-transcript.txt",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert write.returncode == 0

    validate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-external-replication-submission",
            str(output_dir),
            "--submission-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate.returncode == 1
    payload = json.loads(validate.stdout)
    assert payload["valid"] is False
    issue_codes = {issue["code"] for issue in payload["issues"]}
    assert "submission_field_result_bundle_url_placeholder" in issue_codes
    assert "submission_field_result_bundle_url_not_immutable" in issue_codes
    assert "submission_field_replication_metadata_url_placeholder_reference" in issue_codes
    assert "submission_field_commands_transcript_url_placeholder_reference" in issue_codes


def test_governance_benchmark_runner_rejects_tampered_replication_kit(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    target = (
        output_dir
        / "reviewer_packet"
        / "reviewer_artifacts"
        / "condition_a"
        / "incident-001.json"
    )
    target.write_text(target.read_text().replace("requested operation", "altered operation"))

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    issue_codes = {issue["code"] for issue in payload["issues"]}
    assert "kit_sha256_mismatch" in issue_codes
    assert "reviewer_packet_audit_failed" in issue_codes


def test_governance_benchmark_runner_rejects_incomplete_public_artifacts_inventory(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["artifacts"] = [
        artifact
        for artifact in inventory["artifacts"]
        if artifact["artifact"] != "external_replication_attestation"
    ]
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    assert "required_public_artifacts_invalid" in {
        issue["code"] for issue in payload["issues"]
    }
    assert "required_public_artifact_missing" in {
        issue["code"]
        for issue in payload["required_public_artifacts"]["issues"]
    }


def test_governance_benchmark_runner_rejects_public_artifact_missing_proof_claim(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    for artifact in inventory["artifacts"]:
        if artifact["artifact"] == "public_scorecard":
            artifact["proves"].remove("inter_reviewer_agreement_reported")
            break
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    validate_inventory = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-required-public-artifacts",
            str(inventory_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate_inventory.returncode == 1
    inventory_payload = json.loads(validate_inventory.stdout)
    assert "required_public_artifact_proof_missing" in {
        issue["code"] for issue in inventory_payload["issues"]
    }
    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    assert "required_public_artifacts_invalid" in {
        issue["code"] for issue in payload["issues"]
    }
    assert "required_public_artifact_proof_missing" in {
        issue["code"]
        for issue in payload["required_public_artifacts"]["issues"]
    }


def test_governance_benchmark_runner_rejects_noncanonical_public_artifact_inventory(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["artifacts"].append(dict(inventory["artifacts"][0]))
    inventory["artifacts"].append(
        {
            "artifact": "private_lab_notes",
            "proves": ["not_part_of_v0_1_public_evidence_contract"],
            "required_reference": "notes_uri",
            "bundle_reference": None,
            "verification_commands": ["echo not-a-v0.1-verifier"],
        }
    )
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    assert "required_public_artifacts_invalid" in {
        issue["code"] for issue in payload["issues"]
    }
    nested_codes = {
        issue["code"]
        for issue in payload["required_public_artifacts"]["issues"]
    }
    assert "required_public_artifact_duplicate" in nested_codes
    assert "required_public_artifact_unknown" in nested_codes


def test_governance_benchmark_runner_rejects_public_artifact_missing_verifier_command(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    for artifact in inventory["artifacts"]:
        if artifact["artifact"] == "public_scorecard":
            artifact["verification_commands"] = [
                command.replace(" --scorecard-result-bundle result-bundle.json", "")
                for command in artifact["verification_commands"]
            ]
            break
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    validate_inventory = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-required-public-artifacts",
            str(inventory_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate_inventory.returncode == 1
    payload = json.loads(validate_inventory.stdout)
    assert "required_public_artifact_command_missing" in {
        issue["code"] for issue in payload["issues"]
    }
    assert any(
        issue["code"] == "required_public_artifact_command_missing"
        and "--scorecard-result-bundle" in issue["message"]
        for issue in payload["issues"]
    )


def test_governance_benchmark_runner_rejects_extra_public_artifact_verifier_command(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    for artifact in inventory["artifacts"]:
        if artifact["artifact"] == "public_scorecard":
            artifact["verification_commands"].append("echo unexpected verifier")
            break
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    validate_inventory = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-required-public-artifacts",
            str(inventory_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate_inventory.returncode == 1
    payload = json.loads(validate_inventory.stdout)
    issue_codes = {issue["code"] for issue in payload["issues"]}
    assert "required_public_artifact_commands_mismatch" in issue_codes


def test_governance_benchmark_runner_rejects_public_artifact_reference_mismatch(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    for artifact in inventory["artifacts"]:
        if artifact["artifact"] == "public_blind_answer_matrix":
            artifact["required_reference"] = "scorecard_uri"
            break
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))
    manifest_path = output_dir / "kit_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["required_public_artifacts.json"] = {
        "bytes": inventory_path.stat().st_size,
        "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    assert "required_public_artifacts_invalid" in {
        issue["code"] for issue in payload["issues"]
    }
    assert any(
        issue["code"] == "required_public_artifact_reference_mismatch"
        and "answer_matrix_uri" in issue["message"]
        for issue in payload["required_public_artifacts"]["issues"]
    )


def test_governance_benchmark_runner_rejects_placeholder_public_artifact_bundle_reference(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    inventory_path = output_dir / "required_public_artifacts.json"
    inventory = json.loads(inventory_path.read_text())
    for artifact in inventory["artifacts"]:
        if artifact["artifact"] == "public_scorecard":
            artifact["bundle_reference"] = "https://example.com/acgs-v0-1-scorecard.json"
            artifact["bundle_sha256"] = "not-a-sha256"
            break
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True))

    validate_inventory = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-required-public-artifacts",
            str(inventory_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validate_inventory.returncode == 1
    payload = json.loads(validate_inventory.stdout)
    issue_codes = {issue["code"] for issue in payload["issues"]}
    assert "required_public_artifact_reference_placeholder" in issue_codes
    assert "required_public_artifact_sha256_invalid" in issue_codes


def test_governance_benchmark_runner_reports_study_readiness_without_success_claim(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--study-readiness-report",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ready_for_blind_review"] is True
    assert payload["success_evidence"] is False
    assert payload["issues"] == []
    assert payload["protocol"]["incident_count"] == 50
    assert payload["protocol"]["question_count"] == 7
    assert payload["protocol"]["condition_count"] == 3
    assert payload["kit_verification"]["valid"] is True
    assert payload["answer_template"]["row_count"] == 50 * 3 * 7 * 2
    assert payload["answer_template"]["filled_response_cells"] == 0
    assert payload["replication_metadata"]["success_evidence"] is False
    assert "collect blind-review answers from real reviewers" in payload["open_requirements"]


def test_governance_benchmark_runner_validates_collected_blind_answers(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-collected-answers",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["success_evidence"] is False
    assert payload["issues"] == []
    assert payload["row_count"] == 50 * 3 * 7 * 2
    assert payload["expected_row_count"] == 50 * 3 * 7 * 2
    assert payload["reviewer_count"] == 2


def test_governance_benchmark_runner_rejects_unblinded_collected_answers(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
        extra_fields={"ground_truth": "leaked"},
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-collected-answers",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "forbidden_answer_column" in {issue["code"] for issue in payload["issues"]}


def test_governance_benchmark_runner_seals_collected_blind_answers(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    seal_path = tmp_path / "collected-answers-seal.json"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["seal_path"] == str(seal_path)
    assert payload["success_evidence"] is False
    seal = json.loads(seal_path.read_text())
    assert seal["schema"] == "acgs-v0.1-collected-blind-answers-seal"
    assert seal["answers_csv"]["sha256"] == payload["answers_sha256"]
    assert seal["reviewer_packet"]["reviewer_manifest_sha256"] == payload[
        "reviewer_manifest_sha256"
    ]
    assert seal["validation"]["valid"] is True
    assert seal["success_evidence"] is False


def test_governance_benchmark_runner_verifies_collected_answer_seal(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    seal_path = tmp_path / "collected-answers-seal.json"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
    )
    seal = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert seal.returncode == 0

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []
    assert payload["validation"]["valid"] is True
    assert payload["success_evidence"] is False


def test_governance_benchmark_runner_rejects_answer_seal_bundle_hash_mismatch(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    seal_path = tmp_path / "collected-answers-seal.json"
    bundle_path = tmp_path / "result-bundle.json"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
    )
    seal = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert seal.returncode == 0
    pack = generate_artifact_pack()
    answers = _full_blind_review_answers(pack.answer_key)
    bundle_path.write_text(
        build_result_bundle(
            protocol=pack.protocol,
            answers=answers,
            answer_evidence=_complete_answer_evidence().model_copy(
                update={
                    "answers_sha256": json.loads(seal.stdout)["answers_sha256"],
                    "answers_bytes": answers_path.stat().st_size,
                    "reviewer_manifest_sha256": json.loads(seal.stdout)[
                        "reviewer_manifest_sha256"
                    ],
                    "row_count": len(answers),
                    "reviewer_count": len({answer.reviewer_id for answer in answers}),
                }
            ),
            external_replication=_complete_external_replication_record(),
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
            "--answer-seal-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "answer_seal_sha256_mismatch"
    }


def test_governance_benchmark_runner_rejects_tampered_collected_answer_seal(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    answers_path = tmp_path / "answers.csv"
    seal_path = tmp_path / "collected-answers-seal.json"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0
    _write_filled_reviewer_template_csv(
        answers_path,
        output_dir / "reviewer_packet" / "reviewer_answer_template.csv",
    )
    seal = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert seal.returncode == 0
    answers_path.write_text(answers_path.read_text().replace("answer,0.8", "tampered,0.8", 1))

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(output_dir / "reviewer_packet"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "answers_sha256_mismatch" in {issue["code"] for issue in payload["issues"]}


def test_governance_benchmark_runner_validates_replication_metadata_template(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(output_dir / "replication_metadata.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {
        "external_replication_incomplete",
        "external_replication_placeholder",
    } <= {issue["code"] for issue in payload["issues"]}


def test_governance_benchmark_runner_validates_reviewer_cohort_manifest(
    tmp_path,
) -> None:
    manifest_path = tmp_path / "reviewer_cohort_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "artifact_access_scope": "reviewer_packet_only",
                "blind_to_condition_labels": True,
                "blind_to_ground_truth": True,
                "cohort_id": "independent-systems-lab-2026-05",
                "conflict_of_interest_screened": True,
                "recruiting_organization": "Independent Systems Lab",
                "reviewer_count": 3,
                "reviewer_roster_sha256": "a" * 64,
            }
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-reviewer-cohort-manifest",
            str(manifest_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is True
    assert payload["manifest"]["reviewer_count"] == 3


def test_governance_benchmark_runner_rejects_reviewer_cohort_count_mismatch(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    manifest_path = tmp_path / "reviewer_cohort_manifest.json"
    bundle_path = tmp_path / "result-bundle.json"
    manifest_path.write_text(
        ReviewerCohortManifest(
            artifact_access_scope="reviewer_packet_only",
            blind_to_condition_labels=True,
            blind_to_ground_truth=True,
            cohort_id="independent-systems-lab-2026-05",
            conflict_of_interest_screened=True,
            recruiting_organization="Independent Systems Lab",
            reviewer_count=3,
            reviewer_roster_sha256="a" * 64,
        ).model_dump_json()
    )
    bundle_path.write_text(
        build_result_bundle(
            protocol=pack.protocol,
            answers=_full_blind_review_answers(pack.answer_key),
            answer_evidence=_complete_answer_evidence(),
            external_replication=_complete_external_replication_record(),
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-reviewer-cohort-manifest",
            str(manifest_path),
            "--cohort-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "reviewer_cohort_count_mismatch"
    }


def test_governance_benchmark_runner_rejects_scorecard_result_bundle_mismatch(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    scorecard_path = tmp_path / "scorecard.json"
    bundle_path = tmp_path / "result-bundle.json"
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    tampered_scorecard = bundle.scorecard.model_copy(
        update={"strongest_baseline": "ungoverned_raw_logs"}
    )
    scorecard_path.write_text(tampered_scorecard.model_dump_json())
    bundle_path.write_text(bundle.model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-scorecard",
            str(scorecard_path),
            "--scorecard-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "scorecard_result_bundle_mismatch"
    }


def test_governance_benchmark_runner_rejects_placeholder_reviewer_cohort_manifest(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-reviewer-cohort-manifest",
            str(output_dir / "reviewer_cohort_manifest.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is False
    assert payload["success_evidence"] is False
    assert "reviewer_cohort_manifest_invalid" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_validates_replication_attestation(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    result_bundle_path = tmp_path / "result-bundle.json"
    cohort_manifest_path = tmp_path / "reviewer_cohort_manifest.json"
    scorecard_path = tmp_path / "scorecard.json"
    artifact_pack_path = tmp_path / "artifact-pack.tar.gz"
    commands_transcript_path = tmp_path / "commands-transcript.txt"
    result_bundle_path.write_text('{"schema":"acgs-v0.1-result-bundle"}')
    cohort_manifest_path.write_text('{"schema":"reviewer-cohort-manifest"}')
    scorecard_path.write_text('{"schema":"scorecard"}')
    artifact_pack_path.write_text("artifact pack bytes")
    commands_transcript_path.write_text(_complete_replication_command())
    result_bundle_sha256 = hashlib.sha256(result_bundle_path.read_bytes()).hexdigest()
    cohort_manifest_sha256 = hashlib.sha256(cohort_manifest_path.read_bytes()).hexdigest()
    scorecard_sha256 = hashlib.sha256(scorecard_path.read_bytes()).hexdigest()
    artifact_pack_sha256 = hashlib.sha256(artifact_pack_path.read_bytes()).hexdigest()
    commands_transcript_sha256 = hashlib.sha256(
        commands_transcript_path.read_bytes()
    ).hexdigest()
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": artifact_pack_sha256,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": commands_transcript_sha256,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": result_bundle_sha256,
                "reviewer_cohort_manifest_sha256": cohort_manifest_sha256,
                "scorecard_sha256": scorecard_sha256,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-result-bundle",
            str(result_bundle_path),
            "--attested-reviewer-cohort-manifest",
            str(cohort_manifest_path),
            "--attested-scorecard",
            str(scorecard_path),
            "--attested-artifact-pack",
            str(artifact_pack_path),
            "--attested-commands-transcript",
            str(commands_transcript_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is True
    assert payload["attestation"]["declares_independent_rerun"] is True


def test_governance_benchmark_runner_rejects_attestation_transcript_missing_command_line(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    commands_transcript_path = tmp_path / "commands-transcript.txt"
    commands_transcript_path.write_text("pytest tests/test_governance_receipts.py\n")
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": hashlib.sha256(
                    commands_transcript_path.read_bytes()
                ).hexdigest(),
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-commands-transcript",
            str(commands_transcript_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert "attestation_commands_transcript_missing_command_line" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_attestation_metadata_group_mismatch(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": "b" * 64,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Different Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert "attestation_replicating_group_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_attestation_result_bundle_hash_mismatch(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    result_bundle_path = tmp_path / "result-bundle.json"
    result_bundle_path.write_text('{"schema":"tampered-result-bundle"}')
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": "b" * 64,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-result-bundle",
            str(result_bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert "attestation_result_bundle_sha256_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_attestation_cohort_manifest_hash_mismatch(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    cohort_manifest_path = tmp_path / "reviewer_cohort_manifest.json"
    cohort_manifest_path.write_text('{"schema":"tampered-cohort-manifest"}')
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": "b" * 64,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-reviewer-cohort-manifest",
            str(cohort_manifest_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert "attestation_reviewer_cohort_manifest_sha256_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_attestation_scorecard_hash_mismatch(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    scorecard_path = tmp_path / "scorecard.json"
    scorecard_path.write_text('{"schema":"tampered-scorecard"}')
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": "b" * 64,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-scorecard",
            str(scorecard_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert "attestation_scorecard_sha256_mismatch" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_attestation_pack_and_transcript_hash_mismatch(
    tmp_path,
) -> None:
    attestation_path = tmp_path / "replication_attestation.json"
    metadata_path = tmp_path / "replication_metadata.json"
    artifact_pack_path = tmp_path / "artifact-pack.tar.gz"
    commands_transcript_path = tmp_path / "commands-transcript.txt"
    artifact_pack_path.write_text("tampered artifact pack bytes")
    commands_transcript_path.write_text("tampered commands transcript")
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": "a" * 64,
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": "b" * 64,
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": "c" * 64,
                "reviewer_cohort_manifest_sha256": "d" * 64,
                "scorecard_sha256": "e" * 64,
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    metadata_path.write_text(_complete_external_replication_record().model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(metadata_path),
            "--attested-artifact-pack",
            str(artifact_pack_path),
            "--attested-commands-transcript",
            str(commands_transcript_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "attestation_artifact_pack_sha256_mismatch",
        "attestation_commands_transcript_sha256_mismatch",
    }


def test_governance_benchmark_runner_rejects_placeholder_replication_attestation(
    tmp_path,
) -> None:
    output_dir = tmp_path / "replication-kit"
    generate = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--write-replication-kit",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(output_dir / "replication_attestation.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is False
    assert payload["success_evidence"] is False
    assert "external_replication_attestation_invalid" in {
        issue["code"] for issue in payload["issues"]
    }


def test_governance_benchmark_runner_rejects_weak_replication_metadata_references(
    tmp_path,
) -> None:
    metadata_path = tmp_path / "replication.json"
    metadata_path.write_text(
        ExternalReplicationRecord(
            replicating_group="Independent Systems Lab",
            artifact_pack_uri="reviewed-pack.tar.gz",
            reviewer_cohort_uri="reviewer-cohort.json",
            command_line=(
                "python scripts/run_governance_benchmark.py "
                "--audit-reviewer-packet reviewer_packet && "
                "python scripts/run_governance_benchmark.py "
                "--verify-collected-answers-seal collected-answers-seal.json "
                "--answers-csv answers.csv --reviewer-packet reviewer_packet && "
                "python scripts/run_governance_benchmark.py "
                "--build-result-bundle result-bundle.json"
            ),
            scorecard_uri="scorecard.json",
            attestation_uri="attestation.json",
            completed=True,
            reproduction_notes="Reran generated pack and reproduced ACGS advantage.",
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "external_artifact_pack_not_immutable",
        "external_reviewer_cohort_not_immutable",
        "external_scorecard_not_immutable",
        "external_attestation_not_immutable",
    }


def test_governance_benchmark_runner_rejects_placeholder_metadata_hosts(
    tmp_path,
) -> None:
    metadata_path = tmp_path / "replication.json"
    metadata_path.write_text(
        ExternalReplicationRecord(
            replicating_group="Independent Systems Lab",
            artifact_pack_uri="https://example.org/reviewed-pack.tar.gz",
            reviewer_cohort_uri="https://localhost/reviewer-cohort.json",
            command_line=_complete_replication_command(),
            scorecard_uri="https://127.0.0.1/scorecard.json",
            attestation_uri="https://example.org/attestation.json",
            completed=True,
            reproduction_notes="Reran generated pack and reproduced ACGS advantage.",
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "external_artifact_pack_placeholder_reference",
        "external_reviewer_cohort_placeholder_reference",
        "external_scorecard_placeholder_reference",
        "external_attestation_placeholder_reference",
    }


def test_governance_benchmark_runner_rejects_dummy_metadata_public_record_references(
    tmp_path,
) -> None:
    metadata_path = tmp_path / "replication.json"
    metadata_path.write_text(
        ExternalReplicationRecord(
            replicating_group="Independent Systems Lab",
            artifact_pack_uri=(
                "https://zenodo.org/records/123456/files/acgs-v0-1-pack.tar.gz"
            ),
            reviewer_cohort_uri=(
                "https://zenodo.org/records/123456/files/"
                "acgs-v0-1-reviewer-cohort.json"
            ),
            command_line=_complete_replication_command(),
            scorecard_uri=(
                "https://zenodo.org/records/123456/files/acgs-v0-1-scorecard.json"
            ),
            attestation_uri=(
                "https://zenodo.org/records/123456/files/acgs-v0-1-attestation.json"
            ),
            completed=True,
            reproduction_notes="Reran generated pack and reproduced ACGS advantage.",
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "external_artifact_pack_placeholder_reference",
        "external_reviewer_cohort_placeholder_reference",
        "external_scorecard_placeholder_reference",
        "external_attestation_placeholder_reference",
    }


def test_governance_benchmark_runner_requires_metadata_completion_audit_command(
    tmp_path,
) -> None:
    metadata_path = tmp_path / "replication.json"
    command_without_completion_audit = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--completion-audit-result-bundle result-bundle.json",
        "",
    )
    metadata_path.write_text(
        _complete_external_replication_record()
        .model_copy(update={"command_line": command_without_completion_audit})
        .model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "external_replication_completion_audit_missing"
    }


def test_governance_benchmark_runner_requires_metadata_public_artifact_validation(
    tmp_path,
) -> None:
    metadata_path = tmp_path / "replication.json"
    command_without_public_artifact_validation = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--validate-required-public-artifacts required_public_artifacts.json",
        "",
    )
    metadata_path.write_text(
        _complete_external_replication_record()
        .model_copy(update={"command_line": command_without_public_artifact_validation})
        .model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-metadata",
            str(metadata_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid_shape"] is True
    assert payload["success_evidence"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "external_replication_public_artifacts_not_validated"
    }


def test_governance_benchmark_runner_rejects_tampered_reviewer_manifest_file(
    tmp_path,
) -> None:
    output_dir = tmp_path / "pack"
    subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--generate-incident-pack",
            str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    target = output_dir / "reviewer_artifacts" / "condition_a" / "incident-001.json"
    target.write_text(target.read_text().replace("requested operation", "altered operation"))

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-reviewer-manifest",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert verify.returncode == 1
    payload = json.loads(verify.stdout)
    assert payload["valid"] is False
    assert "sha256_mismatch" in {issue["code"] for issue in payload["issues"]}


def test_result_bundle_validates_only_complete_public_study_evidence() -> None:
    pack = generate_artifact_pack()
    answers = _full_blind_review_answers(pack.answer_key)
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=answers,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is True
    assert verdict.issues == []
    assert bundle.incident_count == 50
    assert bundle.question_count == len(FORENSIC_QUESTIONNAIRE)
    assert bundle.reviewer_count == 2
    assert bundle.scorecard.acgs_wins is True
    assert bundle.p_value_vs_strongest_baseline <= 0.05


def test_result_bundle_requires_external_completion_audit_command() -> None:
    pack = generate_artifact_pack()
    command_without_completion_audit = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--completion-audit-result-bundle result-bundle.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_completion_audit}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_completion_audit_missing"
    }


def test_result_bundle_requires_external_replication_kit_verification() -> None:
    pack = generate_artifact_pack()
    command_without_kit_verification = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py --verify-replication-kit .",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_kit_verification}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_kit_not_verified"
    }


def test_result_bundle_requires_external_public_artifact_validation() -> None:
    pack = generate_artifact_pack()
    command_without_public_artifact_validation = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--validate-required-public-artifacts required_public_artifacts.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_public_artifact_validation}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_public_artifacts_not_validated"
    }


def test_result_bundle_requires_external_reviewer_cohort_bundle_binding() -> None:
    pack = generate_artifact_pack()
    command_without_cohort_binding = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--validate-reviewer-cohort-manifest reviewer_cohort_manifest.json "
        "--cohort-result-bundle result-bundle.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_cohort_binding}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_reviewer_cohort_not_bound"
    }


def test_result_bundle_requires_external_answer_matrix_bundle_binding() -> None:
    pack = generate_artifact_pack()
    command_without_answer_matrix_binding = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--validate-answer-matrix answers.csv "
        "--protocol-json coordinator_pack/protocol.json "
        "--answer-key-json coordinator_pack/answer_key.json "
        "--condition-key-json coordinator_pack/condition_key.json "
        "--answer-matrix-result-bundle result-bundle.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_answer_matrix_binding}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_answer_matrix_not_bound"
    }


def test_result_bundle_requires_external_answer_seal_bundle_binding() -> None:
    pack = generate_artifact_pack()
    command_without_answer_seal_binding = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--verify-collected-answers-seal collected-answers-seal.json "
        "--answers-csv answers.csv --reviewer-packet reviewer_packet "
        "--answer-seal-result-bundle result-bundle.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_answer_seal_binding}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_answer_seal_not_bound"
    }


def test_result_bundle_requires_external_scorecard_bundle_binding() -> None:
    pack = generate_artifact_pack()
    command_without_scorecard_binding = _complete_replication_command().replace(
        " && python scripts/run_governance_benchmark.py "
        "--validate-scorecard scorecard.json "
        "--scorecard-result-bundle result-bundle.json",
        "",
    )
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record().model_copy(
            update={"command_line": command_without_scorecard_binding}
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_scorecard_not_validated",
        "external_replication_scorecard_not_bound",
    }


def test_paired_sign_test_p_value_is_computed_from_matched_answers() -> None:
    pack = generate_artifact_pack()
    answers = _full_blind_review_answers(pack.answer_key)

    p_value = paired_sign_test_p_value(answers)

    assert p_value <= 0.05


def test_result_bundle_rejects_toy_or_non_external_success_claim() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.20,
        answer_evidence=_complete_answer_evidence(),
        external_replication=ExternalReplicationRecord(
            replicating_group="ACGS internal team",
            artifact_pack_uri="local",
            reviewer_cohort_uri="local",
            command_line="python scripts/run_governance_benchmark.py",
            scorecard_uri="local",
            attestation_uri="local",
            completed=False,
            reproduction_notes="Demo-only run.",
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "not_statistically_significant",
        "external_replication_incomplete",
        "replicating_group_not_external",
        "external_artifact_pack_not_immutable",
        "external_reviewer_cohort_not_immutable",
        "external_scorecard_not_immutable",
        "external_attestation_not_immutable",
        "external_replication_packet_not_audited",
        "external_replication_kit_not_verified",
        "external_replication_public_artifacts_not_validated",
        "external_replication_reviewer_cohort_not_bound",
        "external_replication_answer_matrix_not_validated",
        "external_replication_answer_matrix_not_bound",
        "external_replication_bundle_not_built",
        "external_replication_result_bundle_not_validated",
        "external_replication_scorecard_not_validated",
        "external_replication_scorecard_not_bound",
        "external_replication_completion_audit_missing",
        "external_replication_answer_seal_not_verified",
        "external_replication_answer_seal_not_bound",
        "external_replication_attestation_not_validated",
        "external_replication_attested_bundle_missing",
        "external_replication_attested_reviewer_cohort_missing",
        "external_replication_attested_scorecard_missing",
        "external_replication_attested_artifact_pack_missing",
        "external_replication_attested_commands_transcript_missing",
    }


def test_result_bundle_rejects_placeholder_external_replication_metadata() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=ExternalReplicationRecord(
            replicating_group="TODO-independent-group-name",
            artifact_pack_uri="TODO-immutable-uri-or-checksum-for-reviewed-pack",
            reviewer_cohort_uri="TODO-immutable-uri-or-checksum-for-reviewer-cohort",
            command_line=(
                "python scripts/run_governance_benchmark.py "
                "--score-reviewer-answers answers.csv"
            ),
            scorecard_uri="TODO-uri-or-path-to-reproduced-scorecard",
            attestation_uri="TODO-uri-or-path-to-independent-replication-attestation",
            completed=True,
            reproduction_notes="TODO: attach reproduced scorecard.",
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_replication_placeholder",
        "external_replication_packet_not_audited",
        "external_replication_kit_not_verified",
        "external_replication_public_artifacts_not_validated",
        "external_replication_reviewer_cohort_not_bound",
        "external_replication_answer_matrix_not_validated",
        "external_replication_answer_matrix_not_bound",
        "external_replication_bundle_not_built",
        "external_replication_result_bundle_not_validated",
        "external_replication_scorecard_not_validated",
        "external_replication_scorecard_not_bound",
        "external_replication_completion_audit_missing",
        "external_replication_attestation_not_validated",
        "external_replication_answer_seal_not_bound",
        "external_replication_attested_bundle_missing",
        "external_replication_attested_reviewer_cohort_missing",
        "external_replication_attested_scorecard_missing",
        "external_replication_attested_artifact_pack_missing",
        "external_replication_attested_commands_transcript_missing",
    }


def test_result_bundle_rejects_non_immutable_external_references() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(
            artifact_pack_uri="reviewed-pack.tar.gz",
            reviewer_cohort_uri="reviewer-cohort.json",
            scorecard_uri="scorecard.json",
            attestation_uri="attestation.json",
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_artifact_pack_not_immutable",
        "external_reviewer_cohort_not_immutable",
        "external_scorecard_not_immutable",
        "external_attestation_not_immutable",
    }


def test_result_bundle_rejects_placeholder_external_reference_hosts() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(
            artifact_pack_uri="https://example.org/acgs-v0-1-pack.tar.gz",
            reviewer_cohort_uri="https://localhost/acgs-v0-1-reviewer-cohort.json",
            scorecard_uri="https://127.0.0.1/acgs-v0-1-scorecard.json",
            attestation_uri="https://0.0.0.0/acgs-v0-1-attestation.json",
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_artifact_pack_placeholder_reference",
        "external_reviewer_cohort_placeholder_reference",
        "external_scorecard_placeholder_reference",
        "external_attestation_placeholder_reference",
    }


def test_result_bundle_rejects_dummy_public_record_references() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(
            artifact_pack_uri="https://zenodo.org/records/123456/files/acgs-v0-1-pack.tar.gz",
            reviewer_cohort_uri=(
                "https://zenodo.org/records/123456/files/"
                "acgs-v0-1-reviewer-cohort.json"
            ),
            scorecard_uri="https://zenodo.org/records/123456/files/acgs-v0-1-scorecard.json",
            attestation_uri=(
                "https://zenodo.org/records/123456/files/acgs-v0-1-attestation.json"
            ),
        ),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "external_artifact_pack_placeholder_reference",
        "external_reviewer_cohort_placeholder_reference",
        "external_scorecard_placeholder_reference",
        "external_attestation_placeholder_reference",
    }


def test_result_bundle_rejects_dummy_answer_evidence_references() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence().model_copy(
            update={
                "answer_matrix_uri": (
                    "https://zenodo.org/records/123456/files/acgs-v0-1-answers.csv"
                ),
                "answer_seal_uri": (
                    "https://zenodo.org/records/123456/files/"
                    "acgs-v0-1-answer-seal.json"
                ),
            }
        ),
        external_replication=_complete_external_replication_record(),
    )

    verdict = validate_result_bundle(bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "answer_matrix_uri_placeholder_reference",
        "answer_seal_uri_placeholder_reference",
    }


def test_result_bundle_rejects_scorecard_answer_count_mismatch() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    acgs_score = bundle.scorecard.condition_scores["acgs_receipts_and_audit_artifacts"]
    tampered_scorecard = bundle.scorecard.model_copy(
        update={
            "condition_scores": {
                **bundle.scorecard.condition_scores,
                "acgs_receipts_and_audit_artifacts": acgs_score.model_copy(
                    update={"answer_count": 1}
                ),
            }
        }
    )
    tampered_bundle = bundle.model_copy(update={"scorecard": tampered_scorecard})

    verdict = validate_result_bundle(tampered_bundle)

    assert verdict.valid is False
    assert "score_answer_count_mismatch" in {issue.code for issue in verdict.issues}


def test_result_bundle_rejects_inconsistent_scorecard_claims() -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    tampered_scorecard = bundle.scorecard.model_copy(
        update={
            "strongest_baseline": "ungoverned_raw_logs",
            "performance_delta_vs_strongest_baseline": 999,
            "acgs_wins": False,
        }
    )
    tampered_bundle = bundle.model_copy(update={"scorecard": tampered_scorecard})

    verdict = validate_result_bundle(tampered_bundle)

    assert verdict.valid is False
    assert {issue.code for issue in verdict.issues} >= {
        "strongest_baseline_mismatch",
        "performance_delta_mismatch",
        "acgs_wins_mismatch",
        "acgs_does_not_beat_strongest_baseline",
    }


def test_condition_score_rejects_impossible_metric_values() -> None:
    with pytest.raises(ValueError):
        ConditionScore(
            answer_accuracy=1.2,
            mean_time_seconds=-1,
            confidence_calibration_error=1.1,
            inter_reviewer_agreement=-0.1,
            answer_count=0,
        )


def test_result_bundle_builder_rejects_incomplete_answer_matrix() -> None:
    pack = generate_artifact_pack()
    answers = _full_blind_review_answers(pack.answer_key)

    with pytest.raises(ValueError, match="incomplete answer matrix"):
        build_result_bundle(
            protocol=pack.protocol,
            answers=answers[:-1],
            answer_evidence=_complete_answer_evidence(),
            external_replication=_complete_external_replication_record(),
        )


def test_answer_matrix_verdict_reports_missing_cells() -> None:
    pack = generate_artifact_pack()

    verdict = validate_answer_matrix(
        pack.protocol,
        _full_blind_review_answers(pack.answer_key)[:-1],
    )

    assert verdict.valid is False
    assert "missing_answer_cells" in {issue.code for issue in verdict.issues}


def test_governance_benchmark_runner_validates_result_bundle_json(tmp_path) -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.01,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["issues"] == []
    assert payload["summary"]["incident_count"] == 50
    assert payload["summary"]["reviewer_count"] == 2
    assert payload["summary"]["question_count"] == len(FORENSIC_QUESTIONNAIRE)
    assert payload["summary"]["acgs_wins"] is True
    assert payload["summary"]["external_replication_completed"] is True
    assert (
        payload["summary"]["answer_matrix_uri"]
        == "https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv"
    )
    assert payload["summary"]["answers_sha256"] == "a" * 64
    assert payload["summary"]["replicating_group"] == "Independent Systems Lab"
    assert (
        payload["summary"]["reviewer_cohort_uri"]
        == "https://zenodo.org/records/987654321/files/acgs-v0-1-reviewer-cohort.json"
    )


def test_governance_benchmark_completion_audit_remains_blocked_for_local_bundle(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    bundle = build_result_bundle(
        protocol=pack.protocol,
        answers=_full_blind_review_answers(pack.answer_key),
        p_value_vs_strongest_baseline=0.01,
        answer_evidence=_complete_answer_evidence(),
        external_replication=_complete_external_replication_record(),
    )
    bundle_path = tmp_path / "result-bundle.json"
    bundle_path.write_text(bundle.model_dump_json())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--completion-audit-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["schema"] == "acgs-v0.1-completion-audit"
    assert payload["complete"] is False
    assert "50 to 200 adversarial incidents" in payload["objective"]
    assert payload["local_result_bundle_valid"] is True
    assert payload["blockers"] == [
        "non_acgs_external_replication_verified",
    ]
    checklist = {item["requirement"]: item for item in payload["checklist"]}
    assert all(item["objective_text"] for item in checklist.values())
    assert all(item["artifacts"] for item in checklist.values())
    assert all(item["verification_commands"] for item in checklist.values())
    assert checklist["fixed_forensic_questionnaire"]["evidence"]["actual_questions"] == list(
        FORENSIC_QUESTIONNAIRE
    )
    assert checklist["high_risk_action_policy_gated"]["satisfied"] is True
    assert checklist["high_risk_action_policy_gated"]["evidence"]["fixture_valid"] is True
    assert (
        checklist["high_risk_action_policy_gated"]["evidence"]["signature_status"]
        == "valid"
    )
    assert (
        checklist["high_risk_action_policy_gated"]["evidence"]["receipt_hash_count"]
        == checklist["high_risk_action_policy_gated"]["evidence"]["receipt_count"]
    )
    assert checklist["forensic_reconstruction_fields_bound"]["satisfied"] is True
    assert set(
        checklist["forensic_reconstruction_fields_bound"]["evidence"]["required_fields"]
    ).issubset(
        set(checklist["forensic_reconstruction_fields_bound"]["evidence"]["answer_key_fields"])
    )
    assert {
        "rule_followed_or_bypassed",
        "failure_became_inevitable",
        "outcome_defensible",
    }.issubset(
        set(checklist["forensic_reconstruction_fields_bound"]["evidence"]["answer_key_fields"])
    )
    assert "src/constitutional_swarm/governance_receipts.py:verify_bundle" in (
        checklist["high_risk_action_policy_gated"]["artifacts"]
    )
    assert set(checklist["matched_baselines"]["evidence"]["actual_baselines"]) == set(
        BASELINES
    )
    assert set(
        checklist["adversarial_incident_techniques"]["evidence"]["actual_techniques"]
    ) == set(ADVERSARIAL_TECHNIQUES)
    assert "src/constitutional_swarm/forensic_benchmark.py:FORENSIC_QUESTIONNAIRE" in (
        checklist["fixed_forensic_questionnaire"]["artifacts"]
    )
    assert "--validate-replication-attestation" in checklist[
        "non_acgs_external_replication_verified"
    ]["verification_commands"][1]
    assert checklist["incident_count_50_to_200"]["satisfied"] is True
    assert checklist["incident_count_50_to_200"]["evidence"] == {
        "incident_count": 50,
        "required_minimum": 50,
        "required_maximum": 200,
    }
    assert checklist["acgs_significantly_beats_strongest_baseline"][
        "satisfied"
    ] is True
    assert checklist["acgs_significantly_beats_strongest_baseline"]["evidence"][
        "acgs_wins"
    ] is True
    assert checklist["acgs_significantly_beats_strongest_baseline"]["evidence"][
        "p_value_vs_strongest_baseline"
    ] == 0.01
    assert checklist["inter_reviewer_agreement_reported"]["satisfied"] is True
    assert (
        checklist["inter_reviewer_agreement_reported"]["evidence"][
            "acgs_inter_reviewer_agreement"
        ]
        > 0
    )
    assert checklist["public_blind_review_data_verified"]["satisfied"] is True
    assert checklist["public_blind_review_data_verified"]["artifacts"] == [
        "public answer matrix",
        "pre-unblinding answer seal",
        "reviewer cohort manifest",
    ]
    assert checklist["public_blind_review_data_verified"]["evidence"] == {
        "incident_count": 50,
        "reviewer_count": 2,
        "answer_matrix_uri": "https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv",
        "answer_seal_uri": "https://zenodo.org/records/987654321/files/acgs-v0-1-answer-seal.json",
        "reviewer_cohort_uri": "https://zenodo.org/records/987654321/files/acgs-v0-1-reviewer-cohort.json",
    }
    assert checklist["non_acgs_external_replication_verified"]["satisfied"] is False
    assert checklist["non_acgs_external_replication_verified"]["artifacts"] == [
        "replication_metadata.json",
        "replication_attestation.json",
        "commands-transcript.txt",
        "artifact-pack.tar.gz",
    ]
    assert checklist["non_acgs_external_replication_verified"]["evidence"] == (
        "local metadata can name an external group, but independent rerun artifacts "
        "must be verified outside this checkout before completion"
    )
    required_artifacts = {
        artifact["artifact"]: artifact for artifact in payload["required_public_artifacts"]
    }
    assert set(required_artifacts) == {
        "public_blind_answer_matrix",
        "pre_unblinding_answer_seal",
        "external_reviewer_cohort_manifest",
        "public_scorecard",
        "external_replication_attestation",
    }
    expected_required_references = {
        "public_blind_answer_matrix": "answer_matrix_uri",
        "pre_unblinding_answer_seal": "answer_seal_uri",
        "external_reviewer_cohort_manifest": "reviewer_cohort_uri",
        "public_scorecard": "scorecard_uri",
        "external_replication_attestation": "attestation_uri",
    }
    expected_bundle_references = {
        "public_blind_answer_matrix": "https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv",
        "pre_unblinding_answer_seal": "https://zenodo.org/records/987654321/files/acgs-v0-1-answer-seal.json",
        "external_reviewer_cohort_manifest": "https://zenodo.org/records/987654321/files/acgs-v0-1-reviewer-cohort.json",
        "public_scorecard": "https://zenodo.org/records/987654321/files/acgs-v0-1-scorecard.json",
        "external_replication_attestation": "https://zenodo.org/records/987654321/files/acgs-v0-1-attestation.json",
    }
    expected_related_bundle_references = {
        "external_replication_attestation": "https://zenodo.org/records/987654321/files/acgs-v0-1-pack.tar.gz",
    }
    expected_bundle_sha256 = {
        "public_blind_answer_matrix": "a" * 64,
        "pre_unblinding_answer_seal": "b" * 64,
    }
    expected_proves = {
        "public_blind_answer_matrix": {
            "blind_reviewers_answered_fixed_questionnaire",
            "answer_accuracy_time_confidence_inputs_exist",
            "inter_reviewer_agreement_can_be_computed",
        },
        "pre_unblinding_answer_seal": {
            "answers_collected_before_ground_truth_join",
            "answer_matrix_not_tampered_before_scoring",
        },
        "external_reviewer_cohort_manifest": {
            "reviewer_count_at_least_two",
            "reviewers_blind_to_ground_truth",
            "reviewers_blind_to_condition_labels",
            "conflict_screening_recorded",
        },
        "public_scorecard": {
            "acgs_beats_strongest_baseline",
            "p_value_at_or_below_0_05",
            "confidence_calibration_reported",
            "inter_reviewer_agreement_reported",
        },
        "external_replication_attestation": {
            "non_acgs_group_reran_benchmark",
            "result_bundle_hash_bound",
            "reviewer_cohort_hash_bound",
            "scorecard_hash_bound",
            "artifact_pack_hash_bound",
            "commands_transcript_hash_bound",
            "commands_transcript_command_line_bound",
        },
    }
    expected_commands = required_public_artifact_verification_commands()
    for artifact_name, artifact in required_artifacts.items():
        assert artifact["required_reference"] == expected_required_references[artifact_name]
        assert artifact["bundle_reference"] == expected_bundle_references[artifact_name]
        assert artifact.get("related_bundle_reference") == expected_related_bundle_references.get(
            artifact_name
        )
        assert artifact.get("bundle_sha256") == expected_bundle_sha256.get(artifact_name)
        assert tuple(artifact["verification_commands"]) == expected_commands[artifact_name]
        assert set(artifact["proves"]) == expected_proves[artifact_name]
    assert (
        required_artifacts["external_replication_attestation"]["current_status"]
        == "not_verified_from_this_checkout"
    )


def test_governance_benchmark_completion_audit_fails_closed_without_bundle() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--completion-audit",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["schema"] == "acgs-v0.1-completion-audit"
    assert payload["complete"] is False
    assert payload["local_result_bundle_valid"] is False
    assert set(payload["blockers"]) >= {
        "scored_result_bundle",
        "incident_count_50_to_200",
        "acgs_significantly_beats_strongest_baseline",
        "inter_reviewer_agreement_reported",
        "public_blind_review_data_verified",
        "non_acgs_external_replication_verified",
    }
    scored_result = next(
        item for item in payload["checklist"] if item["requirement"] == "scored_result_bundle"
    )
    assert scored_result["satisfied"] is False
    assert scored_result["artifacts"] == [
        "src/constitutional_swarm/forensic_benchmark.py:BenchmarkResultBundle",
        "src/constitutional_swarm/forensic_benchmark.py:BenchmarkScorecard",
        "scripts/run_governance_benchmark.py:--validate-result-bundle",
        "scripts/run_governance_benchmark.py:--completion-audit-result-bundle",
    ]
    assert scored_result["verification_commands"] == [
        "python scripts/run_governance_benchmark.py "
        "--validate-result-bundle result-bundle.json",
        "python scripts/run_governance_benchmark.py "
        "--completion-audit-result-bundle result-bundle.json",
    ]
    assert scored_result["issues"] == [
        {
            "code": "result_bundle_not_supplied",
            "message": "supply --completion-audit-result-bundle to audit score evidence",
        }
    ]
    checklist = {item["requirement"]: item for item in payload["checklist"]}
    assert checklist["incident_count_50_to_200"]["satisfied"] is False
    assert checklist["incident_count_50_to_200"]["evidence"]["incident_count"] is None
    assert checklist["acgs_significantly_beats_strongest_baseline"][
        "satisfied"
    ] is False
    assert checklist["inter_reviewer_agreement_reported"]["satisfied"] is False
    assert all(
        artifact["bundle_reference"] is None
        for artifact in payload["required_public_artifacts"]
    )


def test_governance_benchmark_runner_validates_answer_matrix_csv(tmp_path) -> None:
    pack = generate_artifact_pack()
    protocol_path = tmp_path / "protocol.json"
    answers_path = tmp_path / "answers.csv"
    answer_key_path = tmp_path / "answer-key.json"

    protocol_path.write_text(pack.protocol.model_dump_json())
    answer_key_path.write_text(json.dumps(pack.answer_key))
    _write_blind_answers_csv(answers_path, _full_blind_review_answers(pack.answer_key))

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-answer-matrix",
            str(answers_path),
            "--protocol-json",
            str(protocol_path),
            "--answer-key-json",
            str(answer_key_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout) == {"issues": [], "valid": True}


def test_governance_benchmark_runner_rejects_incomplete_answer_matrix_csv(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    protocol_path = tmp_path / "protocol.json"
    answers_path = tmp_path / "answers.csv"
    answer_key_path = tmp_path / "answer-key.json"

    protocol_path.write_text(pack.protocol.model_dump_json())
    answer_key_path.write_text(json.dumps(pack.answer_key))
    _write_blind_answers_csv(answers_path, _full_blind_review_answers(pack.answer_key)[:-1])

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-answer-matrix",
            str(answers_path),
            "--protocol-json",
            str(protocol_path),
            "--answer-key-json",
            str(answer_key_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "missing_answer_cells" in {issue["code"] for issue in payload["issues"]}


def test_governance_benchmark_runner_rejects_answer_matrix_bundle_hash_mismatch(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    protocol_path = tmp_path / "protocol.json"
    answers_path = tmp_path / "answers.csv"
    answer_key_path = tmp_path / "answer-key.json"
    bundle_path = tmp_path / "result-bundle.json"
    answers = _full_blind_review_answers(pack.answer_key)

    protocol_path.write_text(pack.protocol.model_dump_json())
    answer_key_path.write_text(json.dumps(pack.answer_key))
    _write_blind_answers_csv(answers_path, answers)
    bundle_path.write_text(
        build_result_bundle(
            protocol=pack.protocol,
            answers=answers,
            answer_evidence=_complete_answer_evidence().model_copy(
                update={
                    "answers_bytes": answers_path.stat().st_size,
                    "row_count": len(answers),
                    "reviewer_count": len({answer.reviewer_id for answer in answers}),
                }
            ),
            external_replication=_complete_external_replication_record(),
        ).model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-answer-matrix",
            str(answers_path),
            "--protocol-json",
            str(protocol_path),
            "--answer-key-json",
            str(answer_key_path),
            "--answer-matrix-result-bundle",
            str(bundle_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert {issue["code"] for issue in payload["issues"]} >= {
        "answer_matrix_sha256_mismatch"
    }


def test_governance_benchmark_runner_reports_blank_answer_template_as_invalid(
    tmp_path,
) -> None:
    pack = generate_artifact_pack()
    protocol_path = tmp_path / "protocol.json"
    answers_path = tmp_path / "reviewer-template.csv"
    answer_key_path = tmp_path / "answer-key.json"
    condition_key_path = tmp_path / "condition-key.json"

    protocol_path.write_text(pack.protocol.model_dump_json())
    answers_path.write_text(reviewer_answer_template_csv(pack))
    answer_key_path.write_text(json.dumps(pack.answer_key))
    condition_key_path.write_text(json.dumps(blinded_condition_key()))

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-answer-matrix",
            str(answers_path),
            "--protocol-json",
            str(protocol_path),
            "--answer-key-json",
            str(answer_key_path),
            "--condition-key-json",
            str(condition_key_path),
            "--p-value",
            "0.01",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert payload["issues"][0]["code"] == "invalid_answer_csv"


def test_governance_benchmark_runner_builds_result_bundle_from_files(tmp_path) -> None:
    pack = generate_artifact_pack()
    protocol_path = tmp_path / "protocol.json"
    answers_path = tmp_path / "answers.csv"
    answer_key_path = tmp_path / "answer-key.json"
    condition_key_path = tmp_path / "condition-key.json"
    reviewer_packet_dir = tmp_path / "reviewer-packet"
    seal_path = tmp_path / "collected-answers-seal.json"
    replication_path = tmp_path / "replication.json"
    bundle_path = tmp_path / "result-bundle.json"
    cohort_manifest_path = tmp_path / "reviewer-cohort-manifest.json"
    scorecard_path = tmp_path / "scorecard.json"
    artifact_pack_path = tmp_path / "artifact-pack.tar.gz"
    commands_transcript_path = tmp_path / "commands-transcript.txt"

    protocol_path.write_text(pack.protocol.model_dump_json())
    answer_key_path.write_text(json.dumps(pack.answer_key))
    condition_key_path.write_text(json.dumps(blinded_condition_key()))
    full_files = artifact_pack_to_files(pack)
    reviewer_files = reviewer_packet_files(full_files)
    reviewer_files["reviewer_manifest.json"] = full_files["reviewer_manifest.json"]
    _write_text_tree(reviewer_packet_dir, reviewer_files)
    _write_successful_reviewer_template_csv(
        answers_path,
        reviewer_packet_dir / "reviewer_answer_template.csv",
        pack.answer_key,
    )
    seal = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(seal_path),
            "--answers-csv",
            str(answers_path),
            "--reviewer-packet",
            str(reviewer_packet_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert seal.returncode == 0
    replication_path.write_text(
        _complete_external_replication_record().model_dump_json()
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--build-result-bundle",
            str(bundle_path),
            "--answers-csv",
            str(answers_path),
            "--answer-seal-json",
            str(seal_path),
            "--answer-matrix-uri",
            "https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv",
            "--answer-seal-uri",
            "https://zenodo.org/records/987654321/files/acgs-v0-1-answer-seal.json",
            "--reviewer-packet",
            str(reviewer_packet_dir),
            "--protocol-json",
            str(protocol_path),
            "--replication-metadata",
            str(replication_path),
            "--answer-key-json",
            str(answer_key_path),
            "--condition-key-json",
            str(condition_key_path),
            "--p-value",
            "0.01",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["validation"]["valid"] is True
    assert bundle_path.exists()
    bundle = BenchmarkResultBundle.model_validate_json(bundle_path.read_text())
    assert bundle.incident_count == 50
    assert bundle.answer_evidence.answer_matrix_uri.endswith("acgs-v0-1-answers.csv")
    assert bundle.answer_evidence.answers_sha256 == payload["answer_seal"]["answers_sha256"]
    assert bundle.external_replication.replicating_group == "Independent Systems Lab"

    attestation_path = tmp_path / "replication-attestation.json"
    cohort_manifest_path.write_text('{"schema":"reviewer-cohort-manifest"}')
    scorecard_path.write_text('{"schema":"scorecard"}')
    artifact_pack_path.write_text("artifact pack bytes")
    commands_transcript_path.write_text(_complete_replication_command())
    attestation_path.write_text(
        json.dumps(
            {
                "artifact_pack_sha256": hashlib.sha256(
                    artifact_pack_path.read_bytes()
                ).hexdigest(),
                "attestation_id": "independent-systems-lab-2026-05",
                "attestor_name": "Dr. Ada Reviewer",
                "attestor_role": "External replication lead",
                "commands_transcript_sha256": hashlib.sha256(
                    commands_transcript_path.read_bytes()
                ).hexdigest(),
                "conflict_of_interest_screened": True,
                "declares_independent_rerun": True,
                "declares_no_acgs_authorship": True,
                "replicating_group": "Independent Systems Lab",
                "result_bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                "reviewer_cohort_manifest_sha256": hashlib.sha256(
                    cohort_manifest_path.read_bytes()
                ).hexdigest(),
                "scorecard_sha256": hashlib.sha256(scorecard_path.read_bytes()).hexdigest(),
                "signed_at": "2026-05-16T00:00:00Z",
            }
        )
    )
    attestation = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-replication-attestation",
            str(attestation_path),
            "--replication-metadata",
            str(replication_path),
            "--attested-result-bundle",
            str(bundle_path),
            "--attested-reviewer-cohort-manifest",
            str(cohort_manifest_path),
            "--attested-scorecard",
            str(scorecard_path),
            "--attested-artifact-pack",
            str(artifact_pack_path),
            "--attested-commands-transcript",
            str(commands_transcript_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert attestation.returncode == 0
    attestation_payload = json.loads(attestation.stdout)
    assert attestation_payload["success_evidence"] is True


def _full_blind_review_answers(answer_key: dict[str, dict[str, str]]) -> list[ReviewerAnswer]:
    answers: list[ReviewerAnswer] = []
    for incident_id, incident_answers in answer_key.items():
        for question_id, ground_truth in incident_answers.items():
            for reviewer_id in ("r1", "r2"):
                answers.append(
                    ReviewerAnswer(
                        incident_id=incident_id,
                        artifact_condition="ungoverned_raw_logs",
                        reviewer_id=reviewer_id,
                        question_id=question_id,
                        answer="unknown",
                        ground_truth=ground_truth,
                        confidence=0.4,
                        elapsed_seconds=90,
                    )
                )
                central_answer = ground_truth if reviewer_id == "r1" else "ambiguous"
                answers.append(
                    ReviewerAnswer(
                        incident_id=incident_id,
                        artifact_condition="centralized_structured_logs",
                        reviewer_id=reviewer_id,
                        question_id=question_id,
                        answer=central_answer,
                        ground_truth=ground_truth,
                        confidence=0.6,
                        elapsed_seconds=75,
                    )
                )
                answers.append(
                    ReviewerAnswer(
                        incident_id=incident_id,
                        artifact_condition="acgs_receipts_and_audit_artifacts",
                        reviewer_id=reviewer_id,
                        question_id=question_id,
                        answer=ground_truth,
                        ground_truth=ground_truth,
                        confidence=0.9,
                        elapsed_seconds=30,
                    )
                )
    return answers


def _write_answers_csv(path: Path, answers: list[ReviewerAnswer]) -> None:
    fieldnames = [
        "incident_id",
        "artifact_condition",
        "reviewer_id",
        "question_id",
        "answer",
        "ground_truth",
        "confidence",
        "elapsed_seconds",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for answer in answers:
            writer.writerow(answer.model_dump(mode="json"))


def _write_blind_answers_csv(path: Path, answers: list[ReviewerAnswer]) -> None:
    fieldnames = [
        "incident_id",
        "artifact_condition",
        "reviewer_id",
        "question_id",
        "answer",
        "confidence",
        "elapsed_seconds",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for answer in answers:
            row = answer.model_dump(mode="json")
            row.pop("ground_truth")
            writer.writerow(row)


def _write_condition_blinded_answers_csv(path: Path, answers: list[ReviewerAnswer]) -> None:
    inverse_condition_key = {
        condition: label for label, condition in blinded_condition_key().items()
    }
    fieldnames = [
        "incident_id",
        "condition_label",
        "reviewer_id",
        "question_id",
        "answer",
        "confidence",
        "elapsed_seconds",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for answer in answers:
            writer.writerow(
                {
                    "incident_id": answer.incident_id,
                    "condition_label": inverse_condition_key[answer.artifact_condition],
                    "reviewer_id": answer.reviewer_id,
                    "question_id": answer.question_id,
                    "answer": answer.answer,
                    "confidence": answer.confidence,
                    "elapsed_seconds": answer.elapsed_seconds,
                }
            )


def _write_text_tree(root: Path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def _complete_replication_command() -> str:
    return (
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
        "--answer-matrix-uri https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv "
        "--answer-seal-uri https://zenodo.org/records/987654321/files/acgs-v0-1-answer-seal.json "
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
    )


def _complete_external_replication_record(
    *,
    artifact_pack_uri: str = "https://zenodo.org/records/987654321/files/acgs-v0-1-pack.tar.gz",
    reviewer_cohort_uri: str = "https://zenodo.org/records/987654321/files/acgs-v0-1-reviewer-cohort.json",
    scorecard_uri: str = "https://zenodo.org/records/987654321/files/acgs-v0-1-scorecard.json",
    attestation_uri: str = "https://zenodo.org/records/987654321/files/acgs-v0-1-attestation.json",
) -> ExternalReplicationRecord:
    return ExternalReplicationRecord(
        replicating_group="Independent Systems Lab",
        artifact_pack_uri=artifact_pack_uri,
        reviewer_cohort_uri=reviewer_cohort_uri,
        command_line=_complete_replication_command(),
        scorecard_uri=scorecard_uri,
        attestation_uri=attestation_uri,
        completed=True,
        reproduction_notes="Reran generated pack and reproduced ACGS advantage.",
    )


def _complete_answer_evidence() -> CollectedAnswerEvidence:
    return CollectedAnswerEvidence(
        answer_matrix_uri="https://zenodo.org/records/987654321/files/acgs-v0-1-answers.csv",
        answer_seal_uri="https://zenodo.org/records/987654321/files/acgs-v0-1-answer-seal.json",
        answers_sha256="a" * 64,
        answer_seal_sha256="b" * 64,
        reviewer_manifest_sha256="c" * 64,
        answers_bytes=365655,
        row_count=50 * 2 * len(FORENSIC_QUESTIONNAIRE) * len(BASELINES),
        reviewer_count=2,
    )


def _write_filled_reviewer_template_csv(
    path: Path,
    template_path: Path,
    *,
    extra_fields: dict[str, str] | None = None,
) -> None:
    with template_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(csv.DictReader(template_path.read_text().splitlines()).fieldnames or [])
    extra_fields = extra_fields or {}
    fieldnames = [*fieldnames, *extra_fields]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row.update(
                {
                    "answer": "reviewed answer",
                    "confidence": "0.8",
                    "elapsed_seconds": "30",
                    **extra_fields,
                }
            )
            writer.writerow(row)


def _write_successful_reviewer_template_csv(
    path: Path,
    template_path: Path,
    answer_key: dict[str, dict[str, str]],
) -> None:
    condition_key = blinded_condition_key()
    with template_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(rows[0])
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            artifact_condition = condition_key[row["condition_label"]]
            ground_truth = answer_key[row["incident_id"]][row["question_id"]]
            if artifact_condition == "acgs_receipts_and_audit_artifacts":
                answer, confidence, elapsed_seconds = ground_truth, "0.9", "30"
            elif artifact_condition == "centralized_structured_logs":
                answer, confidence, elapsed_seconds = ground_truth, "0.6", "75"
            else:
                answer, confidence, elapsed_seconds = "unknown", "0.4", "90"
            row.update(
                {
                    "answer": answer,
                    "confidence": confidence,
                    "elapsed_seconds": elapsed_seconds,
                }
            )
            writer.writerow(row)
