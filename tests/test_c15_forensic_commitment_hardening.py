from __future__ import annotations

import csv
import hashlib
import hmac
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
from collections.abc import Callable
from io import StringIO

import pytest

import constitutional_swarm.forensic_benchmark as forensic_benchmark
from constitutional_swarm.forensic_benchmark import (
    BASELINES,
    BLINDED_CONDITION_LABELS,
    DEFAULT_REVIEWER_IDS,
    EvidenceFileBinding,
    FORENSIC_QUESTIONNAIRE,
    ForensicBenchmarkProtocol,
    ReviewerAnswer,
    assigned_reviewer_answers_from_csv,
    artifact_pack_to_files,
    generate_artifact_pack,
    precollection_commitment_digest,
    reviewer_answer_template_csv,
    reviewer_assignment,
    reviewer_incident_pseudonym,
    reviewer_packet_files,
    validate_answer_matrix,
)


NONCE = "15" * 32
ABSOLUTE_SRC = (
    "/home/martin/Acgs-Swarm/.worktrees/fix-C15-forensic-commitment/src"
)


def _rows(content: str) -> list[dict[str, str]]:
    return list(csv.DictReader(StringIO(content)))


def _public_template_order_attack(
    reviewer_id: str,
    rows: list[dict[str, str]],
    *,
    incident_count: int,
) -> list[tuple[dict[str, str], dict[str, str]]]:
    """Model the reviewer's public-seed permutation attack from review cycle 1."""

    sequence = [(row["condition_label"], row["question_id"]) for row in rows]
    hits: list[tuple[dict[str, str], dict[str, str]]] = []
    for permutation in itertools.permutations(BASELINES):
        condition_key = dict(zip(BLINDED_CONDITION_LABELS, permutation, strict=True))
        inverse = {condition: label for label, condition in condition_key.items()}
        ordered: list[tuple[str, str, int, str]] = []
        for reviewer_index, candidate_reviewer in enumerate(DEFAULT_REVIEWER_IDS):
            for condition in BASELINES:
                label = inverse[condition]
                for incident_index in range(incident_count):
                    if (
                        BLINDED_CONDITION_LABELS[
                            (reviewer_index + incident_index) % len(BASELINES)
                        ]
                        != label
                    ):
                        continue
                    for question_id in FORENSIC_QUESTIONNAIRE:
                        ordered.append(
                            (candidate_reviewer, label, incident_index, question_id)
                        )
        random.Random("acgs-v0.1-reviewer-template").shuffle(ordered)
        reviewer_rows = [item for item in ordered if item[0] == reviewer_id]
        if [(item[1], item[3]) for item in reviewer_rows] != sequence:
            continue
        mapping = {
            rows[index]["incident_id"]: f"incident-{item[2] + 1:03d}"
            for index, item in enumerate(reviewer_rows)
        }
        hits.append((condition_key, mapping))
    return hits


def _legacy_public_seed_rows(
    pack: forensic_benchmark.BenchmarkArtifactPack,
    reviewer_id: str,
) -> list[dict[str, str]]:
    """Construct the vulnerable pre-rework ordering as an attack positive control."""

    rows: list[dict[str, str]] = []
    for candidate_reviewer in DEFAULT_REVIEWER_IDS:
        for condition, artifacts in pack.reviewer_artifacts.items():
            label = next(
                label for label, value in pack.condition_key.items() if value == condition
            )
            for artifact in artifacts:
                if reviewer_assignment(artifact.incident_id, candidate_reviewer) != label:
                    continue
                legacy_payload = forensic_benchmark._canonical_json_bytes(
                    {
                        "condition": condition,
                        "generator_version": "acgs-forensic-pack-v3",
                        "incident_id": artifact.incident_id,
                    }
                )
                pseudonym = hmac.new(
                    bytes.fromhex(pack.pack_nonce),
                    legacy_payload,
                    hashlib.sha256,
                ).hexdigest()
                for question_id in FORENSIC_QUESTIONNAIRE:
                    rows.append(
                        {
                            "incident_id": pseudonym,
                            "condition_label": label,
                            "reviewer_id": candidate_reviewer,
                            "question_id": question_id,
                        }
                    )
    random.Random("acgs-v0.1-reviewer-template").shuffle(rows)
    return [row for row in rows if row["reviewer_id"] == reviewer_id]


def _loaded_pack(files: dict[str, str]) -> dict[str, bytes]:
    loaded = {
        "protocol": files["protocol.json"].encode(),
        "answer_key": files["answer_key.json"].encode(),
        "condition_key": files["condition_key.json"].encode(),
        "reviewer_manifest": files["reviewer_manifest.json"].encode(),
    }
    for path in json.loads(files["reviewer_manifest.json"])["files"]:
        loaded[f"reviewer_manifest:{path}"] = files[path].encode()
    return loaded


def _completed_answers_csv(pack: forensic_benchmark.BenchmarkArtifactPack) -> str:
    rows = _rows(reviewer_answer_template_csv(pack))
    for row in rows:
        row["answer"] = "unknown"
        row["confidence"] = "1.0"
        row["elapsed_seconds"] = "1.0"
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _runner_env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": ABSOLUTE_SRC}


def _canonical_cli_args(root, commitment: str) -> list[str]:
    return [
        "--protocol-json",
        str(root / "protocol.json"),
        "--answer-key-json",
        str(root / "answer_key.json"),
        "--condition-key-json",
        str(root / "condition_key.json"),
        "--expected-precollection-commitment",
        commitment,
    ]


def _write_result_evidence(tmp_path, *, nonce: str = NONCE):
    pack = generate_artifact_pack(pack_nonce=nonce)
    files = artifact_pack_to_files(pack)
    condition_key = json.loads(files["condition_key.json"])["conditions"]
    reverse = {
        reviewer_incident_pseudonym(
            nonce,
            incident_id,
            condition,
            reviewer_id,
        ): incident_id
        for incident_id in pack.answer_key
        for condition in BASELINES
        for reviewer_id in DEFAULT_REVIEWER_IDS
    }
    answer_rows = _rows(files["reviewer_answer_template.csv"])
    answers_path = tmp_path / "answers.csv"
    with answers_path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "incident_id",
                "condition_label",
                "artifact_path",
                "reviewer_id",
                "question_id",
                "question_text",
                "answer",
                "confidence",
                "elapsed_seconds",
            ),
        )
        writer.writeheader()
        for row in answer_rows:
            condition = condition_key[row["condition_label"]]
            truth = pack.answer_key[reverse[row["incident_id"]]][row["question_id"]]
            writer.writerow(
                {
                    "incident_id": row["incident_id"],
                    "condition_label": row["condition_label"],
                    "artifact_path": row["artifact_path"],
                    "reviewer_id": row["reviewer_id"],
                    "question_id": row["question_id"],
                    "question_text": row["question_text"],
                    "answer": (
                        truth
                        if condition == "acgs_receipts_and_audit_artifacts"
                        else "incorrect"
                    ),
                    "confidence": "0.9",
                    "elapsed_seconds": "10",
                }
            )
    packet_dir = tmp_path / "reviewer_packet"
    packet_dir.mkdir()
    manifest = json.loads(files["reviewer_manifest.json"])
    for relative_path in manifest["files"]:
        destination = packet_dir / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(files[relative_path])
    manifest_path = packet_dir / "reviewer_manifest.json"
    manifest_path.write_text(files["reviewer_manifest.json"])
    for name in ("answer_key.json", "condition_key.json", "protocol.json"):
        (tmp_path / name).write_text(files[name])
    replication = forensic_benchmark.ExternalReplicationRecord(
        replicating_group="Independent Systems Lab",
        artifact_pack_uri="sha256:" + "1" * 64,
        reviewer_cohort_uri="sha256:" + "2" * 64,
        command_line="claimed external command",
        scorecard_uri="sha256:" + "3" * 64,
        attestation_uri="sha256:" + "4" * 64,
        completed=True,
        reproduction_notes="Independent rerun from sealed evidence.",
    )
    (tmp_path / "replication.json").write_text(replication.model_dump_json())
    commitment = precollection_commitment_digest(files)
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
                    "reviewer_manifest_sha256": hashlib.sha256(
                        manifest_bytes
                    ).hexdigest()
                },
                "precollection_commitment": commitment,
                "validation": {
                    "valid": True,
                    "row_count": len(answer_rows),
                    "reviewer_count": len(DEFAULT_REVIEWER_IDS),
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
    return pack, replication, evidence_paths, commitment


def test_between_reviewer_assignment_is_balanced_and_single_condition() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    rows = _rows(reviewer_answer_template_csv(pack))

    assert len(rows) == 50 * len(DEFAULT_REVIEWER_IDS) * len(FORENSIC_QUESTIONNAIRE)
    by_reviewer_pseudonym: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        key = (row["reviewer_id"], row["incident_id"])
        by_reviewer_pseudonym.setdefault(key, set()).add(row["condition_label"])

    assert all(len(labels) == 1 for labels in by_reviewer_pseudonym.values())
    for ordinal in range(1, 51):
        labels = [
            reviewer_assignment(f"incident-{ordinal:03d}", reviewer_id)
            for reviewer_id in DEFAULT_REVIEWER_IDS
        ]
        assert {label: labels.count(label) for label in set(labels)} == {
            "condition_a": 2,
            "condition_b": 2,
            "condition_c": 2,
        }


def test_reviewer_packet_is_individualized_and_nonce_free() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    packet = reviewer_packet_files(files, reviewer_id=DEFAULT_REVIEWER_IDS[0])
    rows = _rows(packet["reviewer_answer_template.csv"])

    assert {row["reviewer_id"] for row in rows} == {DEFAULT_REVIEWER_IDS[0]}
    assert len(rows) == 50 * len(FORENSIC_QUESTIONNAIRE)
    assert NONCE not in "".join(packet.values())
    assert all("condition_key" not in path and "answer_key" not in path for path in packet)


def test_public_template_order_attack_cannot_recover_keys_or_join_colluders() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    first_reviewer = DEFAULT_REVIEWER_IDS[0]

    positive_control = _public_template_order_attack(
        first_reviewer,
        _legacy_public_seed_rows(pack, first_reviewer),
        incident_count=pack.protocol.incident_count,
    )
    assert len(positive_control) == 1
    assert len(positive_control[0][1]) == pack.protocol.incident_count
    recovered_condition_key, recovered_mapping = positive_control[0]
    assert recovered_condition_key == pack.condition_key
    assert set(recovered_mapping.values()) == set(pack.answer_key)

    legacy_recovered: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
    for reviewer_id in DEFAULT_REVIEWER_IDS[:3]:
        hits = _public_template_order_attack(
            reviewer_id,
            _legacy_public_seed_rows(pack, reviewer_id),
            incident_count=pack.protocol.incident_count,
        )
        assert len(hits) == 1
        legacy_recovered[reviewer_id] = hits[0]

    acgs_condition = "acgs_receipts_and_audit_artifacts"
    acgs_sources: dict[str, forensic_benchmark._IncidentEvidenceSource] = {}
    for reviewer_id, (condition_key, mapping) in legacy_recovered.items():
        acgs_label = next(
            label for label, condition in condition_key.items() if condition == acgs_condition
        )
        artifacts = pack.reviewer_artifacts[acgs_condition]
        for artifact in artifacts:
            if reviewer_assignment(artifact.incident_id, reviewer_id) != acgs_label:
                continue
            legacy_pseudonym = next(
                row["incident_id"]
                for row in _legacy_public_seed_rows(pack, reviewer_id)
                if row["condition_label"] == acgs_label
                and mapping[row["incident_id"]] == artifact.incident_id
            )
            internal_id = mapping[legacy_pseudonym]
            acgs_sources[internal_id] = forensic_benchmark._IncidentEvidenceSource(
                incident_id=internal_id,
                ordinal=artifact.principal_ordinal,
                adversarial_technique=artifact.policy_evidence.adversarial_signal,
            )
    derived_answer_key = {
        incident_id: forensic_benchmark._canonical_answer_key(source)
        for incident_id, source in acgs_sources.items()
    }
    reconstructed = total_baseline = 0
    for reviewer_id, (condition_key, mapping) in legacy_recovered.items():
        for row in _legacy_public_seed_rows(pack, reviewer_id):
            if condition_key[row["condition_label"]] == acgs_condition:
                continue
            internal_id = mapping[row["incident_id"]]
            total_baseline += 1
            reconstructed += (
                derived_answer_key[internal_id][row["question_id"]]
                == pack.answer_key[internal_id][row["question_id"]]
            )
    assert len(acgs_sources) == pack.protocol.incident_count
    assert (reconstructed, total_baseline) == (700, 700)

    recovered_maps: dict[str, dict[str, str]] = {}
    for reviewer_id in DEFAULT_REVIEWER_IDS:
        packet_rows = _rows(
            reviewer_packet_files(files, reviewer_id=reviewer_id)[
                "reviewer_answer_template.csv"
            ]
        )
        hits = _public_template_order_attack(
            reviewer_id,
            packet_rows,
            incident_count=pack.protocol.incident_count,
        )
        assert hits == []
        if len(hits) == 1:
            recovered_maps[reviewer_id] = hits[0][1]

    joined_internal_incidents = (
        set.intersection(*(set(mapping.values()) for mapping in recovered_maps.values()))
        if recovered_maps
        else set()
    )
    assert joined_internal_incidents == set()


def test_reviewer_packet_order_uses_only_opaque_public_names() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    packet = reviewer_packet_files(files, reviewer_id=DEFAULT_REVIEWER_IDS[0])
    rows = _rows(packet["reviewer_answer_template.csv"])
    manifest = json.loads(files["reviewer_manifest.json"])

    assert list(packet) == sorted(packet)
    assert list(manifest["files"]) == sorted(manifest["files"])
    assert [(row["incident_id"], row["question_id"]) for row in rows] == sorted(
        (row["incident_id"], row["question_id"]) for row in rows
    )


def test_twin_cohort_reviewers_receive_distinct_pseudonyms_and_packets() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    left = _rows(
        reviewer_packet_files(files, reviewer_id="reviewer-1")[
            "reviewer_answer_template.csv"
        ]
    )
    right = _rows(
        reviewer_packet_files(files, reviewer_id="reviewer-4")[
            "reviewer_answer_template.csv"
        ]
    )

    left_cells = {(row["condition_label"], row["question_id"]) for row in left}
    right_cells = {(row["condition_label"], row["question_id"]) for row in right}
    assert left_cells == right_cells
    assert {row["incident_id"] for row in left}.isdisjoint(
        row["incident_id"] for row in right
    )


def test_relabeling_reviewer_rows_without_rekeying_pseudonyms_is_rejected() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    rows = _rows(_completed_answers_csv(pack))
    for row in rows:
        if row["reviewer_id"] == "reviewer-1":
            row["reviewer_id"] = "reviewer-4"
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

    with pytest.raises(ValueError, match="invalid sealed answer CSV row"):
        assigned_reviewer_answers_from_csv(
            output.getvalue(),
            answer_key_json=files["answer_key.json"],
            condition_key_json=files["condition_key.json"],
        )


def test_hmac_positive_control_resolves_exactly_one_condition_per_reviewer_incident() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    reverse = {
        reviewer_incident_pseudonym(NONCE, incident_id, condition, reviewer_id): (
            incident_id,
            condition,
        )
        for incident_id in pack.answer_key
        for condition in pack.condition_key.values()
        for reviewer_id in DEFAULT_REVIEWER_IDS
    }

    for reviewer_id in DEFAULT_REVIEWER_IDS:
        packet = reviewer_packet_files(files, reviewer_id=reviewer_id)
        resolved: dict[str, set[str]] = {}
        for row in _rows(packet["reviewer_answer_template.csv"]):
            internal_id, condition = reverse[row["incident_id"]]
            resolved.setdefault(internal_id, set()).add(condition)
        assert len(resolved) == pack.protocol.incident_count
        assert all(len(conditions) == 1 for conditions in resolved.values())


def test_precollection_commitment_is_deterministic_and_binds_all_keys() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    digest = precollection_commitment_digest(files)
    assert digest == precollection_commitment_digest(files)

    for path in ("answer_key.json", "condition_key.json", "reviewer_manifest.json"):
        edited = dict(files)
        edited[path] += " "
        assert precollection_commitment_digest(edited) != digest

    regenerated = artifact_pack_to_files(generate_artifact_pack(pack_nonce="16" * 32))
    assert precollection_commitment_digest(regenerated) != digest


@pytest.mark.parametrize(
    "mutation",
    ("answer_key", "condition_key", "reviewer_artifact", "different_nonce"),
)
def test_canonical_regeneration_rejects_coherent_local_rewrites(mutation: str) -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    expected = precollection_commitment_digest(files)
    loaded = _loaded_pack(files)
    assert forensic_benchmark._verify_canonical_generated_evidence(
        loaded,
        expected_precollection_commitment=expected,
    ) == []

    if mutation == "answer_key":
        payload = json.loads(loaded["answer_key"])
        payload["incident-001"]["who_acted"] = '{"assessment":"indeterminate_principal"}'
        loaded["answer_key"] = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    elif mutation == "condition_key":
        payload = json.loads(loaded["condition_key"])
        first, second = tuple(payload["conditions"])[:2]
        payload["conditions"][first], payload["conditions"][second] = (
            payload["conditions"][second],
            payload["conditions"][first],
        )
        loaded["condition_key"] = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    elif mutation == "reviewer_artifact":
        key = next(key for key in loaded if key.startswith("reviewer_manifest:reviewer_artifacts/"))
        loaded[key] += b" "
    else:
        replacement = artifact_pack_to_files(generate_artifact_pack(pack_nonce="16" * 32))
        loaded = _loaded_pack(replacement)

    issues = forensic_benchmark._verify_canonical_generated_evidence(
        loaded,
        expected_precollection_commitment=expected,
    )
    assert issues


def test_canonical_regeneration_requires_external_commitment() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    issues = forensic_benchmark._verify_canonical_generated_evidence(
        _loaded_pack(files),
        expected_precollection_commitment=None,
    )
    assert {issue.code for issue in issues} == {"missing_expected_precollection_commitment"}


def test_honest_anchored_result_bundle_is_valid_with_provenance_diagnostics(
    tmp_path,
) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=commitment,
    )

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=commitment,
    )

    assert verdict.valid is True
    assert verdict.command_metadata == "claimed external command"
    assert verdict.authenticated_provenance is False
    assert verdict.external_success is False
    assert verdict.independence_verified is False
    assert {item.code for item in verdict.provenance_diagnostics} == {
        "authenticated_provenance_unavailable",
        "identical_reviewer_answer_vectors",
        "unauthenticated_command_metadata",
    }


@pytest.mark.parametrize("mutation", ("answer_key", "condition_key", "artifact"))
def test_result_builder_rejects_locally_resealed_post_commitment_rewrite(
    tmp_path,
    mutation: str,
) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    if mutation == "answer_key":
        path = tmp_path / "answer_key.json"
        payload = json.loads(path.read_text())
        payload["incident-001"]["who_acted"] = '{"assessment":"forged"}'
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    elif mutation == "condition_key":
        path = tmp_path / "condition_key.json"
        payload = json.loads(path.read_text())
        first, second = tuple(payload["conditions"])[:2]
        payload["conditions"][first], payload["conditions"][second] = (
            payload["conditions"][second],
            payload["conditions"][first],
        )
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        manifest_path = tmp_path / "reviewer_packet" / "reviewer_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        relative_path = next(
            path for path in manifest["files"] if path.startswith("reviewer_artifacts/")
        )
        artifact_path = manifest_path.parent / relative_path
        artifact_path.write_text(artifact_path.read_text() + " ")
        artifact_bytes = artifact_path.read_bytes()
        manifest["files"][relative_path] = {
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "bytes": len(artifact_bytes),
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        seal_path = tmp_path / "answer-seal.json"
        seal = json.loads(seal_path.read_text())
        seal["reviewer_packet"]["reviewer_manifest_sha256"] = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        seal_path.write_text(json.dumps(seal, sort_keys=True))

    with pytest.raises(ValueError, match="noncanonical_|commitment_mismatch"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=commitment,
        )


def test_result_builder_rejects_regenerated_bundle_against_old_commitment(tmp_path) -> None:
    old_files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    old_commitment = precollection_commitment_digest(old_files)
    pack, replication, evidence_paths, _ = _write_result_evidence(
        tmp_path,
        nonce="16" * 32,
    )

    with pytest.raises(ValueError, match="commitment_mismatch"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=old_commitment,
        )


@pytest.mark.parametrize("sealed_value", (None, "x"))
def test_result_builder_rejects_missing_or_malformed_sealed_commitment(
    tmp_path,
    sealed_value: str | None,
) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    seal_path = tmp_path / "answer-seal.json"
    seal = json.loads(seal_path.read_text())
    if sealed_value is None:
        del seal["precollection_commitment"]
    else:
        seal["precollection_commitment"] = sealed_value
    seal_path.write_text(json.dumps(seal, sort_keys=True))

    with pytest.raises(ValueError, match="precollection_commitment_mismatch"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths=evidence_paths,
            expected_precollection_commitment=commitment,
        )


def test_result_validation_rejects_absent_external_commitment(tmp_path) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=commitment,
    )

    verdict = forensic_benchmark.validate_result_bundle(
        bundle,
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=None,
    )

    assert verdict.valid is False
    assert "missing_expected_precollection_commitment" in {
        issue.code for issue in verdict.issues
    }


def test_answer_matrix_rejects_alternate_condition_for_assigned_reviewer() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    answers: list[ReviewerAnswer] = []
    for incident_id, truth in pack.answer_key.items():
        for reviewer_id in DEFAULT_REVIEWER_IDS:
            label = reviewer_assignment(incident_id, reviewer_id)
            condition = pack.condition_key[label]
            for question_id, ground_truth in truth.items():
                answers.append(
                    ReviewerAnswer(
                        incident_id=incident_id,
                        artifact_condition=condition,
                        reviewer_id=reviewer_id,
                        question_id=question_id,
                        answer=ground_truth,
                        ground_truth=ground_truth,
                        confidence=0.5 if reviewer_id == "reviewer-4" else 1.0,
                        elapsed_seconds=2.0 if reviewer_id == "reviewer-4" else 1.0,
                    )
                )
    protocol = ForensicBenchmarkProtocol.model_validate(pack.protocol)
    honest_verdict = validate_answer_matrix(protocol, answers)
    assert honest_verdict.valid is True
    assert "identical_reviewer_answer_vectors" in {
        item.code for item in honest_verdict.provenance_diagnostics
    }
    alternate = next(condition for condition in BASELINES if condition != answers[0].artifact_condition)
    answers[0] = answers[0].model_copy(update={"artifact_condition": alternate})
    verdict = validate_answer_matrix(protocol, answers)
    assert verdict.valid is False
    assert "reviewer_cross_condition_assignment" in {issue.code for issue in verdict.issues}


def test_result_builder_rejects_unknown_logical_evidence_name(tmp_path) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    (tmp_path / "forged-validator.json").write_text('{"valid":true}')

    with pytest.raises(ValueError, match="unknown_evidence_logical_name"):
        forensic_benchmark.build_result_bundle(
            protocol=pack.protocol,
            external_replication=replication,
            evidence_root=tmp_path,
            evidence_paths={
                **evidence_paths,
                "validator_attestation": "forged-validator.json",
            },
            expected_precollection_commitment=commitment,
        )


def test_result_validation_rejects_forged_unknown_evidence_binding(tmp_path) -> None:
    pack, replication, evidence_paths, commitment = _write_result_evidence(tmp_path)
    bundle = forensic_benchmark.build_result_bundle(
        protocol=pack.protocol,
        external_replication=replication,
        evidence_root=tmp_path,
        evidence_paths=evidence_paths,
        expected_precollection_commitment=commitment,
    )
    forged = b'{"valid":true}'
    (tmp_path / "forged-validator.json").write_bytes(forged)
    binding = EvidenceFileBinding(
        logical_name="validator_attestation",
        relative_path="forged-validator.json",
        sha256=hashlib.sha256(forged).hexdigest(),
        size_bytes=len(forged),
    )

    verdict = forensic_benchmark.validate_result_bundle(
        bundle.model_copy(update={"evidence_files": (*bundle.evidence_files, binding)}),
        evidence_root=tmp_path,
        trusted_attestors=("Independent Systems Lab",),
        expected_precollection_commitment=commitment,
    )

    assert verdict.valid is False
    assert "unknown_evidence_logical_name" in {
        issue.code for issue in verdict.issues
    }


def test_answer_matrix_rejects_balanced_wrong_latin_square() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    rotated_condition = {
        BASELINES[index]: BASELINES[(index + 1) % len(BASELINES)]
        for index in range(len(BASELINES))
    }
    answers = [
        ReviewerAnswer(
            incident_id=incident_id,
            artifact_condition=rotated_condition[
                pack.condition_key[reviewer_assignment(incident_id, reviewer_id)]
            ],
            reviewer_id=reviewer_id,
            question_id=question_id,
            answer=ground_truth,
            ground_truth=ground_truth,
            confidence=1.0,
            elapsed_seconds=1.0,
        )
        for incident_id, truth in pack.answer_key.items()
        for reviewer_id in DEFAULT_REVIEWER_IDS
        for question_id, ground_truth in truth.items()
    ]
    protocol = ForensicBenchmarkProtocol.model_validate(pack.protocol)

    structural_verdict = validate_answer_matrix(protocol, answers)
    canonical_verdict = validate_answer_matrix(
        protocol,
        answers,
        condition_key=pack.condition_key,
    )

    assert structural_verdict.valid is True
    assert canonical_verdict.valid is False
    assert "noncanonical_reviewer_assignment" in {
        issue.code for issue in canonical_verdict.issues
    }


def test_raw_answer_resolution_rejects_internal_coordinator_incident_id() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    rows = _rows(_completed_answers_csv(pack))
    rows[0]["incident_id"] = "incident-001"
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

    with pytest.raises(ValueError, match="invalid sealed answer CSV row 2"):
        assigned_reviewer_answers_from_csv(
            output.getvalue(),
            answer_key_json=files["answer_key.json"],
            condition_key_json=files["condition_key.json"],
        )


def test_raw_answer_resolution_rejects_attacker_supplied_unblinded_columns() -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    rows = _rows(_completed_answers_csv(pack))
    for row in rows:
        row["artifact_condition"] = "acgs_receipts_and_audit_artifacts"
        row["ground_truth"] = row["answer"]
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

    with pytest.raises(ValueError, match="forbidden unblinded columns"):
        assigned_reviewer_answers_from_csv(
            output.getvalue(),
            answer_key_json=files["answer_key.json"],
            condition_key_json=files["condition_key.json"],
        )


@pytest.mark.parametrize("include_trusted_columns", (False, True))
def test_cli_rejects_balanced_wrong_assignment_with_internal_incident_ids(
    tmp_path,
    include_trusted_columns: bool,
) -> None:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    files = artifact_pack_to_files(pack)
    rotated_label = {
        "condition_a": "condition_b",
        "condition_b": "condition_c",
        "condition_c": "condition_a",
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
    if include_trusted_columns:
        fieldnames.extend(("artifact_condition", "ground_truth"))
    answers_path = tmp_path / "answers.csv"
    with answers_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for incident_id, truth in pack.answer_key.items():
            for reviewer_id in DEFAULT_REVIEWER_IDS:
                label = rotated_label[reviewer_assignment(incident_id, reviewer_id)]
                for question_id, ground_truth in truth.items():
                    row = {
                        "incident_id": incident_id,
                        "condition_label": label,
                        "reviewer_id": reviewer_id,
                        "question_id": question_id,
                        "answer": "fabricated",
                        "confidence": "1.0",
                        "elapsed_seconds": "1.0",
                    }
                    if include_trusted_columns:
                        row.update(
                            artifact_condition=pack.condition_key[label],
                            ground_truth=ground_truth,
                        )
                    writer.writerow(row)
    for name in ("protocol.json", "answer_key.json", "condition_key.json"):
        (tmp_path / name).write_text(files[name])

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--validate-answer-matrix",
            str(answers_path),
            "--protocol-json",
            str(tmp_path / "protocol.json"),
            "--answer-key-json",
            str(tmp_path / "answer_key.json"),
            "--condition-key-json",
            str(tmp_path / "condition_key.json"),
            "--expected-precollection-commitment",
            precollection_commitment_digest(files),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert {issue["code"] for issue in payload["issues"]} == {"invalid_answer_csv"}


def test_cli_seal_verification_rejects_malformed_external_commitment(tmp_path) -> None:
    _pack, _replication, _paths, _commitment = _write_result_evidence(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
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
            "--expected-precollection-commitment",
            "x",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "invalid_expected_precollection_commitment" in {
        issue["code"] for issue in payload["issues"]
    }


def test_cli_seal_and_verify_reject_cross_nonce_packet_substitution(tmp_path) -> None:
    pack_a_root = tmp_path / "pack-a"
    pack_b_root = tmp_path / "pack-b"
    pack_a_root.mkdir()
    pack_b_root.mkdir()
    _pack_a, _replication_a, _paths_a, commitment_a = _write_result_evidence(
        pack_a_root,
        nonce=NONCE,
    )
    _pack_b, _replication_b, _paths_b, commitment_b = _write_result_evidence(
        pack_b_root,
        nonce="16" * 32,
    )

    honest = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(pack_b_root / "answer-seal.json"),
            "--answers-csv",
            str(pack_b_root / "answers.csv"),
            "--reviewer-packet",
            str(pack_b_root / "reviewer_packet"),
            *_canonical_cli_args(pack_b_root, commitment_b),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_runner_env(),
    )
    assert honest.returncode == 0, honest.stdout + honest.stderr

    cross_seal = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--seal-collected-answers",
            str(pack_b_root / "cross-nonce-seal.json"),
            "--answers-csv",
            str(pack_b_root / "answers.csv"),
            "--reviewer-packet",
            str(pack_b_root / "reviewer_packet"),
            "--precollection-commitment",
            commitment_a,
            "--protocol-json",
            str(pack_b_root / "protocol.json"),
            "--answer-key-json",
            str(pack_b_root / "answer_key.json"),
            "--condition-key-json",
            str(pack_b_root / "condition_key.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_runner_env(),
    )
    assert cross_seal.returncode == 1
    assert "precollection_commitment_mismatch" in {
        issue["code"] for issue in json.loads(cross_seal.stdout)["issues"]
    }

    forged_seal_path = pack_b_root / "fully-resealed-cross-nonce.json"
    forged_seal = json.loads((pack_b_root / "answer-seal.json").read_text())
    forged_seal["precollection_commitment"] = commitment_a
    forged_seal_path.write_text(json.dumps(forged_seal, sort_keys=True))
    cross_verify = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(forged_seal_path),
            "--answers-csv",
            str(pack_b_root / "answers.csv"),
            "--reviewer-packet",
            str(pack_b_root / "reviewer_packet"),
            *_canonical_cli_args(pack_b_root, commitment_a),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_runner_env(),
    )
    assert cross_verify.returncode == 1
    assert "precollection_commitment_mismatch" in {
        issue["code"] for issue in json.loads(cross_verify.stdout)["issues"]
    }


@pytest.mark.parametrize("mutation", ("template", "manifest", "artifact"))
def test_cli_verify_rejects_fully_rehashed_packet_edits(tmp_path, mutation: str) -> None:
    _pack, _replication, _paths, commitment = _write_result_evidence(tmp_path)
    packet_root = tmp_path / "reviewer_packet"
    manifest_path = packet_root / "reviewer_manifest.json"
    manifest = json.loads(manifest_path.read_text())

    if mutation == "manifest":
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")))
    else:
        relative_path = (
            "reviewer_answer_template.csv"
            if mutation == "template"
            else next(
                path
                for path in manifest["files"]
                if path.startswith("reviewer_artifacts/")
            )
        )
        edited_path = packet_root / relative_path
        if mutation == "template":
            content = edited_path.read_text()
            edited_path.write_text(content.replace("Assess", "Review", 1))
        else:
            edited_path.write_text(edited_path.read_text() + " ")
        edited_bytes = edited_path.read_bytes()
        manifest["files"][relative_path] = {
            "bytes": len(edited_bytes),
            "sha256": hashlib.sha256(edited_bytes).hexdigest(),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    seal_path = tmp_path / "answer-seal.json"
    seal = json.loads(seal_path.read_text())
    seal["reviewer_packet"]["reviewer_manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    seal_path.write_text(json.dumps(seal, sort_keys=True))

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_governance_benchmark.py",
            "--verify-collected-answers-seal",
            str(seal_path),
            "--answers-csv",
            str(tmp_path / "answers.csv"),
            "--reviewer-packet",
            str(packet_root),
            *_canonical_cli_args(tmp_path, commitment),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_runner_env(),
    )

    assert result.returncode == 1
    assert "noncanonical_reviewer_packet_file" in {
        issue["code"] for issue in json.loads(result.stdout)["issues"]
    }


def test_reviewer_packet_requires_explicit_known_reviewer() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    with pytest.raises(TypeError):
        reviewer_packet_files(files)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="unknown reviewer"):
        reviewer_packet_files(files, reviewer_id="mallory")


def _manifest_incident_hash_inversion_count(
    files: dict[str, str],
    manifest: dict[str, object],
    *,
    reviewer_id: str,
) -> int:
    manifest_entries = manifest["files"]
    assert isinstance(manifest_entries, dict)
    indexed_hashes = {
        entry["sha256"]
        for entry in manifest_entries.values()
    }
    recovered = 0
    for path, content in files.items():
        if not path.startswith(f"reviewer_artifacts/{reviewer_id}/"):
            continue
        public_artifact = json.loads(content)
        for ordinal in range(1, 51):
            candidate = {
                **public_artifact,
                "incident_id": f"incident-{ordinal:03d}",
            }
            canonical = forensic_benchmark._json_dump(
                forensic_benchmark.ReviewerEvidenceArtifact.model_validate(
                    candidate
                ).model_dump(mode="json")
            )
            if hashlib.sha256(canonical.encode()).hexdigest() in indexed_hashes:
                recovered += 1
                break
    return recovered


def test_reviewer_manifest_cannot_invert_reviewer_pseudonyms() -> None:
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    vulnerable_manifest = {
        "files": {
            path: {"sha256": hashlib.sha256(content.encode()).hexdigest()}
            for path, content in files.items()
            if path.startswith("artifacts/")
        }
    }
    reviewer_id = DEFAULT_REVIEWER_IDS[0]

    assert (
        _manifest_incident_hash_inversion_count(
            files,
            vulnerable_manifest,
            reviewer_id=reviewer_id,
        )
        == 50
    )
    reviewer_manifest = json.loads(files["reviewer_manifest.json"])
    assert not any(path.startswith("artifacts/") for path in reviewer_manifest["files"])
    assert (
        _manifest_incident_hash_inversion_count(
            files,
            reviewer_manifest,
            reviewer_id=reviewer_id,
        )
        == 0
    )


def _complete_six_reviewer_answers(
    *,
    answer_for: Callable[[str, str, str, str], str],
) -> tuple[ForensicBenchmarkProtocol, list[ReviewerAnswer]]:
    pack = generate_artifact_pack(pack_nonce=NONCE)
    answers = [
        ReviewerAnswer(
            incident_id=incident_id,
            artifact_condition=pack.condition_key[
                reviewer_assignment(incident_id, reviewer_id)
            ],
            reviewer_id=reviewer_id,
            question_id=question_id,
            answer=answer_for(reviewer_id, incident_id, question_id, ground_truth),
            ground_truth=ground_truth,
            confidence=1.0,
            elapsed_seconds=1.0,
        )
        for incident_id, truth in pack.answer_key.items()
        for reviewer_id in DEFAULT_REVIEWER_IDS
        for question_id, ground_truth in truth.items()
    ]
    return ForensicBenchmarkProtocol.model_validate(pack.protocol), answers


def test_answer_matrix_reports_near_duplicate_complete_reviewer_vectors() -> None:
    def answer_for(
        reviewer_id: str,
        incident_id: str,
        question_id: str,
        ground_truth: str,
    ) -> str:
        if reviewer_id in {"reviewer-1", "reviewer-4"}:
            return ground_truth
        return f"{reviewer_id}:{incident_id}:{question_id}"

    protocol, answers = _complete_six_reviewer_answers(answer_for=answer_for)
    changed = next(
        index for index, answer in enumerate(answers) if answer.reviewer_id == "reviewer-4"
    )
    answers[changed] = answers[changed].model_copy(update={"answer": "one-cell-tweak"})

    verdict = validate_answer_matrix(protocol, answers)

    assert verdict.valid is True
    diagnostics = {
        diagnostic.code: diagnostic.message
        for diagnostic in verdict.provenance_diagnostics
    }
    assert "near_duplicate_reviewer_answer_vectors" in diagnostics
    assert "reviewer-1/reviewer-4" in diagnostics[
        "near_duplicate_reviewer_answer_vectors"
    ]
    assert "349/350" in diagnostics["near_duplicate_reviewer_answer_vectors"]


def test_answer_matrix_does_not_flag_independent_noisy_reviewer_vectors() -> None:
    protocol, answers = _complete_six_reviewer_answers(
        answer_for=lambda reviewer_id, incident_id, question_id, _ground_truth: (
            f"{reviewer_id}:{incident_id}:{question_id}"
        )
    )

    verdict = validate_answer_matrix(protocol, answers)

    assert verdict.valid is True
    assert not {
        "identical_reviewer_answer_vectors",
        "near_duplicate_reviewer_answer_vectors",
    }.intersection(
        diagnostic.code for diagnostic in verdict.provenance_diagnostics
    )


def _cycle2_cli(*args: object) -> subprocess.CompletedProcess[str]:
    script = os.environ.get(
        "C15_BENCHMARK_SCRIPT", "scripts/run_governance_benchmark.py"
    )
    return subprocess.run(
        [sys.executable, script, *map(str, args)],
        check=False,
        capture_output=True,
        text=True,
        env=_runner_env(),
    )


def test_cli_kit_manifest_is_not_a_plain_hash_oracle_and_regeneration_detects_edit(
    tmp_path,
) -> None:
    kit = tmp_path / "kit"
    generated = _cycle2_cli(
        "--write-replication-kit", kit, "--pack-nonce", NONCE
    )
    assert generated.returncode == 0, generated.stderr
    manifest = json.loads((kit / "kit_manifest.json").read_text())
    files = artifact_pack_to_files(generate_artifact_pack(pack_nonce=NONCE))
    assert (
        _manifest_incident_hash_inversion_count(
            files,
            manifest,
            reviewer_id=DEFAULT_REVIEWER_IDS[0],
        )
        == 0
    )
    assert not any(
        path.startswith("coordinator_pack/artifacts/")
        for path in manifest["files"]
    )

    artifact = next((kit / "coordinator_pack" / "artifacts").glob("*/*.json"))
    artifact.write_text(artifact.read_text() + " ")
    verified = _cycle2_cli("--verify-replication-kit", kit)
    assert verified.returncode == 1
    assert "noncanonical_coordinator_pack_file" in {
        issue["code"] for issue in json.loads(verified.stdout)["issues"]
    }


def test_cli_reviewer_packet_requires_exactly_one_retained_nonce_source(
    tmp_path,
) -> None:
    output = tmp_path / "packet"
    absent = _cycle2_cli(
        "--generate-reviewer-packet",
        output,
        "--reviewer-id",
        DEFAULT_REVIEWER_IDS[0],
    )
    assert absent.returncode == 2
    assert "requires one retained nonce source" in absent.stdout

    nonce_file = tmp_path / "pack-nonce.txt"
    nonce_file.write_text(f"{NONCE}\n")
    conflict = _cycle2_cli(
        "--generate-reviewer-packet",
        output,
        "--reviewer-id",
        DEFAULT_REVIEWER_IDS[0],
        "--pack-nonce-file",
        nonce_file,
        "--pack-nonce",
        NONCE,
    )
    assert conflict.returncode == 2
    assert "accepts exactly one nonce source" in conflict.stdout

    nonce_file.write_text(f"{NONCE}\nextra\n")
    malformed = _cycle2_cli(
        "--generate-reviewer-packet",
        output,
        "--reviewer-id",
        DEFAULT_REVIEWER_IDS[0],
        "--pack-nonce-file",
        nonce_file,
    )
    assert malformed.returncode == 2
    assert "must contain exactly one" in malformed.stdout

    inline = _cycle2_cli(
        "--generate-reviewer-packet",
        tmp_path / "inline",
        "--reviewer-id",
        DEFAULT_REVIEWER_IDS[0],
        "--pack-nonce",
        NONCE,
    )
    assert inline.returncode == 0
    assert "shell history or process metadata" in inline.stderr


def test_cli_reviewer_packet_sources_produce_identical_canonical_bytes(tmp_path) -> None:
    kit = tmp_path / "kit"
    assert (
        _cycle2_cli("--write-replication-kit", kit, "--pack-nonce", NONCE).returncode
        == 0
    )
    nonce_file = tmp_path / "pack-nonce.txt"
    nonce_file.write_text(NONCE)
    from_file = tmp_path / "from-file"
    from_coordinator = tmp_path / "from-coordinator"
    assert (
        _cycle2_cli(
            "--generate-reviewer-packet",
            from_file,
            "--reviewer-id",
            DEFAULT_REVIEWER_IDS[0],
            "--pack-nonce-file",
            nonce_file,
        ).returncode
        == 0
    )
    assert (
        _cycle2_cli(
            "--generate-reviewer-packet",
            from_coordinator,
            "--reviewer-id",
            DEFAULT_REVIEWER_IDS[0],
            "--coordinator-pack",
            kit / "coordinator_pack",
        ).returncode
        == 0
    )
    file_bytes = {
        path.relative_to(from_file).as_posix(): path.read_bytes()
        for path in from_file.rglob("*")
        if path.is_file()
    }
    coordinator_bytes = {
        path.relative_to(from_coordinator).as_posix(): path.read_bytes()
        for path in from_coordinator.rglob("*")
        if path.is_file()
    }
    assert coordinator_bytes == file_bytes

    source_artifact = next((kit / "coordinator_pack" / "artifacts").glob("*/*.json"))
    source_artifact.write_text(source_artifact.read_text() + " ")
    corrupted = _cycle2_cli(
        "--generate-reviewer-packet",
        tmp_path / "from-corrupted-coordinator",
        "--reviewer-id",
        DEFAULT_REVIEWER_IDS[0],
        "--coordinator-pack",
        kit / "coordinator_pack",
    )
    assert corrupted.returncode == 1
    assert "noncanonical_coordinator_pack_file" in {
        issue["code"] for issue in json.loads(corrupted.stdout)["issues"]
    }


def test_cli_audit_reports_specific_top_level_leak_codes(tmp_path) -> None:
    kit = tmp_path / "kit"
    assert (
        _cycle2_cli("--write-replication-kit", kit, "--pack-nonce", NONCE).returncode
        == 0
    )
    coordinator = kit / "coordinator_pack"
    full_audit = _cycle2_cli("--audit-reviewer-packet", coordinator)
    assert full_audit.returncode == 1
    assert "unblinded_artifact_present" in {
        issue["code"] for issue in json.loads(full_audit.stdout)["issues"]
    }

    for dirname, source_manifest, manifest_name in (
        (
            "renamed",
            coordinator / "reviewer_manifest.json",
            "coordinator_reviewer_manifest.json",
        ),
        (
            "substituted",
            coordinator / "reviewer_manifest.json",
            "reviewer_manifest.json",
        ),
        ("kit-manifest", kit / "kit_manifest.json", "renamed_manifest.json"),
    ):
        packet = tmp_path / dirname
        shutil.copytree(kit / "reviewer_packets" / DEFAULT_REVIEWER_IDS[0], packet)
        shutil.copy(source_manifest, packet / manifest_name)
        audit = _cycle2_cli("--audit-reviewer-packet", packet)
        assert audit.returncode == 1
        assert "coordinator_manifest_present" in {
            issue["code"] for issue in json.loads(audit.stdout)["issues"]
        }


def test_cli_coordinator_pack_remains_valid_for_seal_and_verify(tmp_path) -> None:
    kit = tmp_path / "kit"
    generated = _cycle2_cli(
        "--write-replication-kit", kit, "--pack-nonce", NONCE
    )
    assert generated.returncode == 0
    commitment = json.loads(generated.stdout)["precollection_commitment"]
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    _write_result_evidence(evidence_root, nonce=NONCE)
    coordinator = kit / "coordinator_pack"
    seal = tmp_path / "coordinator-seal.json"
    canonical_args = (
        "--protocol-json",
        coordinator / "protocol.json",
        "--answer-key-json",
        coordinator / "answer_key.json",
        "--condition-key-json",
        coordinator / "condition_key.json",
    )
    sealed = _cycle2_cli(
        "--seal-collected-answers",
        seal,
        "--answers-csv",
        evidence_root / "answers.csv",
        "--reviewer-packet",
        coordinator,
        "--precollection-commitment",
        commitment,
        *canonical_args,
    )
    assert sealed.returncode == 0, sealed.stdout
    verified = _cycle2_cli(
        "--verify-collected-answers-seal",
        seal,
        "--answers-csv",
        evidence_root / "answers.csv",
        "--reviewer-packet",
        coordinator,
        "--expected-precollection-commitment",
        commitment,
        *canonical_args,
    )
    assert verified.returncode == 0, verified.stdout
