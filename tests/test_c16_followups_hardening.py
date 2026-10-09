"""Regression coverage for C16 follow-up hardening."""

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import replace
from typing import Any

import pytest
from acgs_lite import Constitution
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.bittensor.cascade import (
    STAGE_ORDER,
    CascadeStage,
    PrecedentCandidate,
    PrecedentCascade,
)
from constitutional_swarm.governance_fixtures import (
    fixture_trusted_signers,
    valid_provenance_bundle,
)
from constitutional_swarm.governance_receipts import (
    bundle_from_json,
    bundle_to_json,
    verify_bundle,
)
from constitutional_swarm.mesh import ConstitutionalMesh, MeshProof, MeshResult, RemoteVoteRequest
from constitutional_swarm.mesh.vote_envelope import (
    VoteSignerRegistry,
    compute_vote_envelope_root,
    sign_assignment,
    sign_vote_envelope,
    signed_assignment_digest,
    vote_envelope_hash,
)
from constitutional_swarm.remote_vote_transport import LocalRemotePeer, RemoteVoteResponse
from constitutional_swarm.settlement_store import JSONLSettlementStore

def test_c16_registry_frozen_snapshot_has_no_mutation_capability() -> None:
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    registry = VoteSignerRegistry()
    registry.register(
        "registry-voter",
        Ed25519PrivateKey.generate().public_key(),
        roles={"voter", "validator"},
    )
    frozen = registry.frozen_copy()

    with pytest.raises(AttributeError):
        frozen._frozen = False

    assert type(frozen).__name__ == "FrozenVoteSignerRegistry"
    assert frozen.frozen is True
    assert frozen.frozen_copy() is frozen
    assert not hasattr(frozen, "_frozen")
    for mutator in ("register", "replace", "unregister"):
        assert not hasattr(frozen, mutator)

    existing_grant = next(iter(frozen._identities.values()))
    with pytest.raises(TypeError):
        frozen._identities["attacker"] = existing_grant
    with pytest.raises(TypeError):
        frozen._keys[existing_grant.key_id] = "attacker"


def test_c16_registry_frozen_snapshot_is_detached_from_source_and_exports() -> None:
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    original_key = Ed25519PrivateKey.generate().public_key()
    replacement_key = Ed25519PrivateKey.generate().public_key()
    registry = VoteSignerRegistry()
    original_key_id = registry.register(
        "registry-voter", original_key, roles={"voter", "validator"}
    )
    frozen = registry.frozen_copy()
    exported = frozen.trust_grants(role="validator")
    exported[original_key_id]["roles"].append("attacker")
    exported.clear()

    replacement_key_id = registry.replace(
        "registry-voter", replacement_key, roles={"voter", "validator"}
    )
    registry.unregister("registry-voter")

    assert frozen.authorize("registry-voter", original_key_id) is original_key
    assert frozen.trust_grants(role="validator") == {
        original_key_id: {
            "identity_id": "registry-voter",
            "public_key_hex": original_key.public_bytes_raw().hex(),
            "roles": ["validator"],
        }
    }
    with pytest.raises(ValueError, match="not authorized"):
        frozen.authorize("registry-voter", replacement_key_id)


def test_c16_registry_verifiers_accept_mutable_and_frozen_read_only_registries() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        sign_vote_envelope,
        verify_vote_envelope,
        verify_vote_envelopes,
    )

    private_key = Ed25519PrivateKey.generate()
    registry = VoteSignerRegistry()
    registry.register("registry-voter", private_key.public_key())
    frozen = registry.frozen_copy()
    bindings = {
        "task_id": "registry-task",
        "assignment_id": "registry-assignment",
        "producer_id": "registry-producer",
        "artifact_id": "registry-artifact",
        "content_hash": "a" * 64,
        "constitutional_hash": "b" * 64,
    }
    envelope = sign_vote_envelope(
        private_key,
        voter_id="registry-voter",
        decision="approved",
        reason="immutable trust snapshot",
        nonce="registry-nonce",
        issued_at=1.0,
        assigned_peers=("registry-voter",),
        quorum=1,
        evidence_mode="independent",
        protocol_version=2,
        **bindings,
    )

    assert verify_vote_envelope(envelope, registry, **bindings) == envelope
    assert verify_vote_envelope(envelope, frozen, **bindings) == envelope
    assert verify_vote_envelopes(
        (envelope,), registry, require_independent=True, **bindings
    ) == (envelope,)
    assert verify_vote_envelopes(
        (envelope,), frozen, require_independent=True, **bindings
    ) == (envelope,)


def test_c16_precedent_consumers_accept_frozen_registry_snapshot() -> None:
    from constitutional_swarm.bittensor.precedent_store import PrecedentStore

    registry = VoteSignerRegistry().frozen_copy()
    store = PrecedentStore("constitutional-hash", vote_registry=registry)
    cascade = PrecedentCascade(Constitution.default(), vote_registry=registry)

    assert store.vote_registry is registry
    assert cascade._vote_registry is registry


"""Unique C16 forensic, packet-audit, and dotenv regression fragments.

Imports deliberately live inside helpers/tests so this file can be assembled into
the shared C16 regression module without creating import-order coupling.
"""


def c16_forensic_load_benchmark_runner():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parents[1] / "scripts" / "run_governance_benchmark.py"
    spec = importlib.util.spec_from_file_location("c16_forensic_benchmark_runner", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def c16_forensic_write_packet(packet_dir):
    import hashlib
    import json

    from constitutional_swarm.forensic_benchmark import (
        artifact_pack_to_files,
        generate_artifact_pack,
        reviewer_packet_files,
    )

    full_files = artifact_pack_to_files(generate_artifact_pack(pack_nonce="a" * 64))
    packet_files = reviewer_packet_files(full_files, reviewer_id="reviewer-1")
    for relative_path, content in packet_files.items():
        output = packet_dir / relative_path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")

    manifest_entries = {
        relative_path: {
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "bytes": len(content.encode()),
        }
        for relative_path, content in packet_files.items()
    }
    manifest = {
        "schema": "acgs-v0.1-reviewer-artifact-manifest",
        "file_count": len(manifest_entries),
        "files": manifest_entries,
    }
    (packet_dir / "reviewer_manifest.json").write_text(
        json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return full_files


def c16_forensic_protocol(incident_count=15):
    from constitutional_swarm.forensic_benchmark import ForensicBenchmarkProtocol

    return ForensicBenchmarkProtocol(
        incident_count=incident_count,
        artifact_sets={
            "ungoverned_raw_logs": "artifacts/ungoverned_raw_logs/",
            "centralized_structured_logs": "artifacts/centralized_structured_logs/",
            "acgs_receipts_and_audit_artifacts": (
                "artifacts/acgs_receipts_and_audit_artifacts/"
            ),
        },
        external_replication_instructions="C16 deterministic regression fixture",
    )


def c16_forensic_answer_matrix(*, error_cells_by_reviewer, incident_count=15):
    from constitutional_swarm.forensic_benchmark import (
        BASELINES,
        DEFAULT_REVIEWER_IDS,
        FORENSIC_QUESTIONNAIRE,
        ReviewerAnswer,
    )

    cells = [
        (incident_index, question_id)
        for incident_index in range(1, incident_count + 1)
        for question_id in FORENSIC_QUESTIONNAIRE
    ]
    condition_by_reviewer = {
        reviewer_id: BASELINES[index // 2]
        for index, reviewer_id in enumerate(DEFAULT_REVIEWER_IDS)
    }
    answers = []
    for reviewer_id in DEFAULT_REVIEWER_IDS:
        wrong_cells = error_cells_by_reviewer.get(reviewer_id, {})
        for cell_index, (incident_index, question_id) in enumerate(cells):
            ground_truth = f"truth-{incident_index:03d}-{question_id}"
            answers.append(
                ReviewerAnswer(
                    incident_id=f"incident-{incident_index:03d}",
                    artifact_condition=condition_by_reviewer[reviewer_id],
                    reviewer_id=reviewer_id,
                    question_id=question_id,
                    answer=wrong_cells.get(cell_index, ground_truth),
                    ground_truth=ground_truth,
                    confidence=0.8,
                    elapsed_seconds=10.0,
                )
            )
    return answers


def test_c16_forensic_normal_reviewer_packet_is_accepted(tmp_path) -> None:
    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is True
    assert verdict["issues"] == []


def test_c16_forensic_unlisted_renamed_answer_key_is_rejected(tmp_path) -> None:
    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    full_files = c16_forensic_write_packet(packet_dir)
    (packet_dir / "reviewer_notes.json").write_text(
        full_files["answer_key.json"], encoding="utf-8"
    )

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_file" in {issue["code"] for issue in verdict["issues"]}


def test_c16_forensic_unlisted_renamed_condition_key_is_rejected(tmp_path) -> None:
    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    full_files = c16_forensic_write_packet(packet_dir)
    (packet_dir / "reviewer_labels.json").write_text(
        full_files["condition_key.json"], encoding="utf-8"
    )

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_file" in {issue["code"] for issue in verdict["issues"]}


def test_c16_forensic_manifest_symlink_is_rejected_without_dereference(
    tmp_path, monkeypatch
) -> None:
    from pathlib import Path

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    manifest_path = packet_dir / "reviewer_manifest.json"
    external_manifest = tmp_path / "external-manifest.json"
    external_manifest.write_bytes(manifest_path.read_bytes())
    manifest_path.unlink()
    manifest_path.symlink_to(external_manifest)
    original_read_text = Path.read_text

    def guarded_read_text(self, *args, **kwargs):
        if self == manifest_path:
            raise AssertionError("manifest symlink was dereferenced")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "symlink_packet_file" in {issue["code"] for issue in verdict["issues"]}


def test_c16_forensic_nonregular_manifest_is_rejected_without_read(
    tmp_path, monkeypatch
) -> None:
    from pathlib import Path

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    manifest_path = packet_dir / "reviewer_manifest.json"
    manifest_path.unlink()
    manifest_path.mkdir()
    original_read_text = Path.read_text

    def guarded_read_text(self, *args, **kwargs):
        if self == manifest_path:
            raise AssertionError("nonregular manifest was read")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "invalid_reviewer_manifest" in {
        issue["code"] for issue in verdict["issues"]
    }


def test_c16_forensic_member_symlink_is_rejected_without_dereference(
    tmp_path, monkeypatch
) -> None:
    from pathlib import Path

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    member_path = packet_dir / "reviewer_instructions.md"
    external_member = tmp_path / "external-reviewer-instructions.md"
    external_member.write_text("condition_key.json", encoding="utf-8")
    member_path.unlink()
    member_path.symlink_to(external_member)
    original_read_text = Path.read_text

    def guarded_read_text(self, *args, **kwargs):
        if self == member_path:
            raise AssertionError("packet-member symlink was dereferenced")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "symlink_packet_file" in {issue["code"] for issue in verdict["issues"]}


def test_c16_forensic_symlinked_parent_is_rejected_without_leaf_dereference(
    tmp_path, monkeypatch
) -> None:
    from pathlib import Path

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    source_member = packet_dir / "reviewer_instructions.md"
    external_dir = tmp_path / "external-packet-content"
    external_dir.mkdir()
    external_member = external_dir / "reviewer_instructions.md"
    external_member.write_bytes(source_member.read_bytes())
    source_member.unlink()
    (packet_dir / "nested").symlink_to(external_dir, target_is_directory=True)
    manifest_path = packet_dir / "reviewer_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["nested/reviewer_instructions.md"] = manifest["files"].pop(
        "reviewer_instructions.md"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    escaped_leaf = packet_dir / "nested" / "reviewer_instructions.md"
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(self, *args, **kwargs):
        if self == escaped_leaf:
            raise AssertionError("leaf below symlinked parent was dereferenced")
        return original_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "symlink_packet_file" in {issue["code"] for issue in verdict["issues"]}


def test_c16_forensic_unreadable_regular_member_is_explicit_issue(
    tmp_path, monkeypatch
) -> None:
    from pathlib import Path

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    member_path = packet_dir / "reviewer_instructions.md"
    original_read_text = Path.read_text

    def guarded_read_text(self, *args, **kwargs):
        if self == member_path:
            raise OSError("simulated packet read failure")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "packet_file_read_error" in {
        issue["code"] for issue in verdict["issues"]
    }


def test_c16_forensic_seeded_honest_noise_with_correlated_difficulty_is_not_flagged(
) -> None:
    import random

    from constitutional_swarm.forensic_benchmark import (
        DEFAULT_REVIEWER_IDS,
        FORENSIC_QUESTIONNAIRE,
        validate_answer_matrix,
    )

    incident_count = 50
    cell_count = incident_count * len(FORENSIC_QUESTIONNAIRE)
    rng = random.Random(20261009)
    shared_hard_cells = rng.sample(
        range(cell_count), len(DEFAULT_REVIEWER_IDS) // 2
    )
    ordinary_cells = [
        cell for cell in range(cell_count) if cell not in shared_hard_cells
    ]
    errors_by_reviewer = {}
    for reviewer_index, reviewer_id in enumerate(DEFAULT_REVIEWER_IDS):
        hard_cell = shared_hard_cells[reviewer_index // 2]
        errors_by_reviewer[reviewer_id] = {
            hard_cell: f"common-distractor-{hard_cell}",
            **{
                cell: f"{reviewer_id}-honest-error-{cell}"
                for cell in rng.sample(ordinary_cells, 6)
            },
        }

    comparable_overlaps = []
    for pair_index in range(0, len(DEFAULT_REVIEWER_IDS), 2):
        left, right = DEFAULT_REVIEWER_IDS[pair_index : pair_index + 2]
        overlap = set(errors_by_reviewer[left]) & set(errors_by_reviewer[right])
        comparable_overlaps.append(overlap)
        assert len(overlap) == 1
        shared_cell = next(iter(overlap))
        assert (
            errors_by_reviewer[left][shared_cell]
            == errors_by_reviewer[right][shared_cell]
        )

    assert all(len(errors) == 7 for errors in errors_by_reviewer.values())
    assert all(comparable_overlaps)
    answers = c16_forensic_answer_matrix(
        error_cells_by_reviewer=errors_by_reviewer,
        incident_count=incident_count,
    )

    verdict = validate_answer_matrix(c16_forensic_protocol(incident_count), answers)

    assert verdict.valid is True
    assert verdict.provenance_diagnostics == []


def test_c16_forensic_all_correct_reviewers_are_not_flagged() -> None:
    from constitutional_swarm.forensic_benchmark import validate_answer_matrix

    answers = c16_forensic_answer_matrix(error_cells_by_reviewer={})

    verdict = validate_answer_matrix(c16_forensic_protocol(), answers)

    assert verdict.valid is True
    assert verdict.provenance_diagnostics == []


def test_c16_forensic_copied_wrong_answers_with_edits_are_flagged() -> None:
    from constitutional_swarm.forensic_benchmark import validate_answer_matrix

    copied_wrong = {index: f"copied-wrong-{index}" for index in range(7)}
    changed_copy = {
        **copied_wrong,
        **{index: f"changed-copy-{index}" for index in range(7, 25)},
    }
    answers = c16_forensic_answer_matrix(
        error_cells_by_reviewer={
            "reviewer-1": copied_wrong,
            "reviewer-2": changed_copy,
        },
        incident_count=50,
    )

    verdict = validate_answer_matrix(c16_forensic_protocol(50), answers)

    assert verdict.valid is True
    assert "implausible_shared_wrong_answers" in {
        diagnostic.code for diagnostic in verdict.provenance_diagnostics
    }


def test_c16_forensic_dotenv_variants_require_review(tmp_path) -> None:
    from constitutional_swarm.governed_handoff import PolicyEngine

    engine = PolicyEngine(
        {"policy": {"protected_paths": []}},
        {"roles": {}},
        tmp_path,
    )

    for raw_path in (".env.local", "config/.env", "Config/.ENV.Production"):
        decision = engine.decide("file_write", raw_path)
        assert decision.outcome == "human_review_required"
        assert "protected path" in decision.reason


def test_c16_forensic_similarly_named_dotenv_file_remains_allowed(tmp_path) -> None:
    from constitutional_swarm.governed_handoff import PolicyEngine

    engine = PolicyEngine(
        {"policy": {"protected_paths": []}},
        {"roles": {}},
        tmp_path,
    )

    decision = engine.decide("file_write", "config/service.env.local")

    assert decision.outcome == "allow"


def _c16_consumer_dev_bundle(tmp_path):
    store = JSONLSettlementStore(tmp_path / "dev-settlements.jsonl")
    mesh = ConstitutionalMesh(
        Constitution.default(),
        seed=42,
        peers_per_validation=3,
        quorum=3,
        settlement_store=store,
        evidence_mode="single_operator_dev",
    )
    for index in range(4):
        mesh.register_local_signer(f"dev-agent-{index}")
    assignment = mesh.request_validation(
        "dev-agent-0", "safe governed action", "dev-artifact"
    )
    for voter in assignment.peers:
        mesh.validate_and_vote(assignment.assignment_id, voter)
    bundle = bundle_from_json(
        mesh._receipt_bundle_path(assignment.assignment_id).read_text(encoding="utf-8")
    )
    return bundle, mesh.receipt_trust_registry()


def test_c16_receipt_verification_requires_independent_votes_by_default(tmp_path):
    bundle, trust = _c16_consumer_dev_bundle(tmp_path)

    strict = verify_bundle(bundle, trusted_signers=trust)
    assert strict.valid is False
    development = verify_bundle(
        bundle,
        trusted_signers=trust,
        require_independent_votes=False,
    )

    assert "vote_electorate_invalid" in {issue.code for issue in strict.issues}
    assert strict.evidence_policy == "proof_grade"
    assert development.valid is True
    assert development.evidence_policy == "development"


def test_c16_receipt_verification_accepts_independent_votes_by_default():
    verdict = verify_bundle(
        valid_provenance_bundle(),
        trusted_signers=fixture_trusted_signers(),
    )

    assert verdict.valid is True
    assert verdict.evidence_policy == "proof_grade"


def test_c16_cli_dev_evidence_requires_explicit_labelled_optout(tmp_path):
    bundle, trust = _c16_consumer_dev_bundle(tmp_path)
    bundle_path = tmp_path / "dev-bundle.json"
    trust_path = tmp_path / "dev-trust.json"
    bundle_path.write_text(bundle_to_json(bundle), encoding="utf-8")
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    command = [
        sys.executable,
        "scripts/verify_governance_receipts.py",
        str(bundle_path),
        "--trusted-signers",
        str(trust_path),
    ]

    strict = subprocess.run(command, check=False, capture_output=True, text=True)
    development = subprocess.run(
        [*command, "--allow-dev-evidence"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert strict.returncode == 1
    assert json.loads(strict.stdout)["evidence_policy"] == "proof_grade"
    assert development.returncode == 0
    assert json.loads(development.stdout)["evidence_policy"] == "development"


def test_c16_cli_rejects_dev_optout_for_committed_store(tmp_path):
    store_path = tmp_path / "settlements.jsonl"
    store_path.write_text("", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            "--settlement-store",
            str(store_path),
            "--assignment-id",
            "assignment",
            "--allow-dev-evidence",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    output = json.loads(result.stdout)
    assert output["evidence_policy"] == "proof_grade"
    assert "cannot be used with --settlement-store" in output["issues"][0]["message"]


@pytest.mark.parametrize("failure", ["malformed_bundle", "missing_bundle", "malformed_trust"])
def test_c16_cli_dev_parse_errors_keep_development_policy_label(tmp_path, failure):
    bundle_path = tmp_path / "bundle.json"
    trust_path = tmp_path / "trust.json"
    bundle_path.write_text(bundle_to_json(valid_provenance_bundle()), encoding="utf-8")
    trust_path.write_text(json.dumps(fixture_trusted_signers()), encoding="utf-8")
    if failure == "malformed_bundle":
        bundle_path.write_text("{", encoding="utf-8")
    elif failure == "missing_bundle":
        bundle_path = tmp_path / "missing.json"
    else:
        trust_path.write_text("{", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            str(bundle_path),
            "--trusted-signers",
            str(trust_path),
            "--allow-dev-evidence",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    output = json.loads(result.stdout)
    assert output["evidence_policy"] == "development"
    assert output["issues"][0]["code"] == "bundle_parse_error"


def test_c16_cli_nondecision_tamper_reaches_digest_verifier(tmp_path):
    payload = json.loads(bundle_to_json(valid_provenance_bundle()))
    payload["receipts"][0]["payload"]["action"] = "tampered but schema-valid action"
    bundle_path = tmp_path / "tampered.json"
    trust_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    trust_path.write_text(json.dumps(fixture_trusted_signers()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_governance_receipts.py",
            str(bundle_path),
            "--trusted-signers",
            str(trust_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    output = json.loads(result.stdout)
    assert "payload_digest_mismatch" in {
        issue["code"] for issue in output["issues"]
    }


def _c16_consumer_cascade_result(
    *,
    electorate_size: int,
    quorum: int,
    consensus_threshold: float,
    min_consensus_miners: int,
):
    constitution = Constitution.default()
    candidate = PrecedentCandidate(
        candidate_id=f"candidate-{electorate_size}-{quorum}",
        judgment_text="Publish governance reasons with privacy safeguards",
        reasoning_text="Accountability and privacy are jointly protected",
        domain="governance",
        miner_uid="cascade-producer",
        constitutional_hash=constitution.hash,
        stage_results=(),
        current_stage=CascadeStage.MESH_VALIDATION,
        alive=True,
    )
    peers = tuple(f"cascade-voter-{index}" for index in range(electorate_size))
    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.generate()
    registry.register(
        "cascade-assigner",
        assigner_key.public_key(),
        roles={"assigner"},
    )
    keys = {peer: Ed25519PrivateKey.generate() for peer in peers}
    for peer, private_key in keys.items():
        registry.register(
            peer,
            private_key.public_key(),
            roles={"voter", "validator"},
        )
    content_hash = hashlib.sha256(candidate.judgment_text.encode()).hexdigest()[:32]
    assignment_id = f"assignment-{electorate_size}-{quorum}"
    signed_assignment = sign_assignment(
        assigner_key,
        task_id=candidate.candidate_id,
        assignment_id=assignment_id,
        assigner_id="cascade-assigner",
        producer_id=candidate.miner_uid,
        artifact_id=candidate.candidate_id,
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        assigned_peers=peers,
        quorum=quorum,
        selection_seed="cascade-test-selection",
        issued_at=1_800_000_000.0,
    )
    assignment_digest = signed_assignment_digest(signed_assignment)
    envelopes = tuple(
        sign_vote_envelope(
            keys[peer],
            voter_id=peer,
            task_id=candidate.candidate_id,
            assignment_id=assignment_id,
            producer_id=candidate.miner_uid,
            artifact_id=candidate.candidate_id,
            content_hash=content_hash,
            constitutional_hash=constitution.hash,
            decision="approved",
            reason="independent approval",
            nonce=f"nonce-{peer}",
            issued_at=1_800_000_000.0,
            assigned_peers=peers,
            quorum=quorum,
            evidence_mode="independent",
            assignment_digest=assignment_digest,
        )
        for peer in peers
    )
    ordered = tuple(sorted(envelopes, key=lambda item: (item.voter_id, item.key_id)))
    proof = MeshProof(
        assignment_id=assignment_id,
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        vote_hashes=tuple(vote_envelope_hash(item) for item in ordered),
        root_hash=compute_vote_envelope_root(
            task_id=candidate.candidate_id,
            assignment_id=assignment_id,
            producer_id=candidate.miner_uid,
            artifact_id=candidate.candidate_id,
            content_hash=content_hash,
            constitutional_hash=constitution.hash,
            accepted=True,
            envelopes=ordered,
        ),
        accepted=True,
        timestamp=time.time(),
        task_id=candidate.candidate_id,
        producer_id=candidate.miner_uid,
        artifact_id=candidate.candidate_id,
        protocol_version=2,
    )
    result = MeshResult(
        assignment_id=assignment_id,
        accepted=True,
        votes_for=electorate_size,
        votes_against=0,
        quorum_met=True,
        pending_votes=0,
        constitutional_hash=constitution.hash,
        proof=proof,
        settled=True,
        settled_at=time.time(),
        vote_envelopes=ordered,
        signed_assignment=signed_assignment,
    )
    cascade = PrecedentCascade(
        constitution,
        consensus_threshold=consensus_threshold,
        min_consensus_miners=min_consensus_miners,
        vote_registry=registry,
    )
    return cascade, candidate, result


def test_c16_cascade_rejects_one_of_one_electorate():
    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=1,
        quorum=1,
        consensus_threshold=1.0,
        min_consensus_miners=3,
    )

    assert cascade._valid_mesh_result(candidate, result) is False


def test_c16_cascade_rejects_quorum_below_configured_floor():
    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=5,
        quorum=3,
        consensus_threshold=0.8,
        min_consensus_miners=3,
    )

    assert cascade._valid_mesh_result(candidate, result) is False


@pytest.mark.asyncio
async def test_c16_remote_independent_cascade_accepts_delta():
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=3,
        quorum=3,
        seed=42,
        evidence_mode="independent",
    )
    mesh.register_remote_agent(
        "cascade-producer", vote_public_key=Ed25519PrivateKey.generate().public_key()
    )
    routes = {}
    peers = {}
    for index in range(3):
        voter_id = f"cascade-remote-{index}"
        peer = LocalRemotePeer(
            agent_id=voter_id,
            constitution=constitution,
            trusted_request_signers={mesh.get_request_signing_public_key()},
            trusted_assigners=mesh.vote_registry.frozen_copy(),
        )
        peers[voter_id] = peer
        mesh.register_remote_agent(voter_id, vote_public_key=peer.public_key_hex)
        routes[voter_id] = (voter_id, 9000 + index)

    class InMemoryRemoteVoteClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            del port, timeout, ssl_context
            return peers[host].handle_vote_request(request)

    cascade = PrecedentCascade(
        constitution,
        mesh,
        min_consensus_miners=3,
        consensus_threshold=1.0,
        vote_registry=mesh.vote_registry,
    )
    candidate = await cascade.run_full_cascade_remote(
        judgment="Publish governance reasons with privacy safeguards",
        reasoning="Accountability and privacy are jointly protected",
        domain="governance",
        miner_uid="cascade-producer",
        peer_routes=routes,
        client=InMemoryRemoteVoteClient(),
    )

    assert candidate.alive is True
    delta = cascade.accept(candidate)
    assert delta is not None
    assert delta.candidate_id == candidate.candidate_id


"""Additional copy-ready C16 consumer regressions requested after initial red."""


def test_c16_cascade_accepts_exact_configured_quorum_floor():
    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=5,
        quorum=4,
        consensus_threshold=0.8,
        min_consensus_miners=3,
    )

    assert cascade._valid_mesh_result(candidate, result) is True


def _c16_signed_assignment_fixture(*, assigner_roles=("assigner",)):
    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        sign_assignment,
    )

    assigner_key = Ed25519PrivateKey.generate()
    voter_key = Ed25519PrivateKey.generate()
    registry = VoteSignerRegistry()
    registry.register("trusted-assigner", assigner_key.public_key(), roles=assigner_roles)
    registry.register("assigned-voter", voter_key.public_key(), roles={"voter", "validator"})
    bindings = {
        "task_id": "c16-task",
        "assignment_id": "c16-assignment",
        "producer_id": "c16-producer",
        "artifact_id": "c16-artifact",
        "content_hash": "a" * 64,
        "constitutional_hash": "b" * 64,
    }
    assignment = sign_assignment(
        assigner_key,
        assigner_id="trusted-assigner",
        assigned_peers=("assigned-voter",),
        quorum=1,
        selection_seed="c16-selection-seed",
        issued_at=1_800_000_000.0,
        **bindings,
    )
    return assignment, registry, voter_key, bindings


def test_c16_signed_assignment_requires_assigner_role() -> None:
    from constitutional_swarm.mesh.vote_envelope import verify_signed_assignment

    assignment, registry, _, bindings = _c16_signed_assignment_fixture(
        assigner_roles=("voter",)
    )

    with pytest.raises(ValueError, match="assigner"):
        verify_signed_assignment(assignment, registry, **bindings)


def test_c16_assignment_digest_mismatch_rejects_vote_evidence() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        sign_vote_envelope,
        signed_assignment_digest,
        verify_assignment_vote_envelopes,
    )

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    envelope = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="independent approval",
        nonce="c16-vote-nonce",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest="0" * 64,
        **bindings,
    )

    assert signed_assignment_digest(assignment) != envelope.assignment_digest
    with pytest.raises(ValueError, match="assignment digest"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            registry,
            **bindings,
        )


def test_c16_proof_grade_verifier_rejects_legacy_vote_envelope() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        sign_vote_envelope,
        verify_assignment_vote_envelopes,
    )

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    legacy = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="legacy evidence",
        nonce="c16-legacy-nonce",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        protocol_version=2,
        **bindings,
    )

    with pytest.raises(ValueError, match="protocol version 3"):
        verify_assignment_vote_envelopes(
            assignment,
            (legacy,),
            registry,
            **bindings,
        )


def test_c16_mesh_issues_assignment_bound_vote_envelopes() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        signed_assignment_digest,
        verify_assignment_vote_envelopes,
    )

    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=1,
        quorum=1,
        evidence_mode="single_operator_dev",
    )
    mesh.register_local_signer("producer")
    mesh.register_local_signer("assigned-voter")

    assignment = mesh.request_validation("producer", "safe content", "artifact")
    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id,
        assignment.peers[0],
        approved=True,
    )

    assert assignment.signed_assignment is not None
    assert envelope.protocol_version == 3
    assert envelope.assignment_digest == signed_assignment_digest(
        assignment.signed_assignment
    )
    assert verify_assignment_vote_envelopes(
        assignment.signed_assignment,
        (envelope,),
        mesh.vote_registry,
        task_id=assignment.task_id,
        assignment_id=assignment.assignment_id,
        producer_id=assignment.producer_id,
        artifact_id=assignment.artifact_id,
        content_hash=assignment.content_hash,
        constitutional_hash=assignment.constitutional_hash,
        require_independent=False,
    ) == (envelope,)


def test_c16_signed_assignment_rejects_field_tamper_and_untrusted_key() -> None:
    from dataclasses import replace

    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        sign_assignment,
        verify_signed_assignment,
    )

    assignment, registry, _, bindings = _c16_signed_assignment_fixture()
    with pytest.raises(ValueError, match="binding"):
        verify_signed_assignment(
            replace(assignment, artifact_id="tampered-artifact"),
            registry,
            **bindings,
        )

    attacker_key = Ed25519PrivateKey.generate()
    forged = sign_assignment(
        attacker_key,
        assigner_id="attacker",
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        selection_seed=assignment.selection_seed,
        issued_at=assignment.issued_at,
        **bindings,
    )
    attacker_registry = VoteSignerRegistry()
    attacker_registry.register(
        "trusted-assigner",
        Ed25519PrivateKey.generate().public_key(),
        roles={"assigner"},
    )
    with pytest.raises(ValueError, match="not authorized"):
        verify_signed_assignment(forged, attacker_registry, **bindings)


def test_c16_signed_assignment_roster_is_canonical_and_immutable() -> None:
    assignment, _, _, _ = _c16_signed_assignment_fixture()

    assert assignment.assigned_peers == ("assigned-voter",)
    with pytest.raises((AttributeError, TypeError)):
        assignment.assigned_peers += ("attacker",)

    from constitutional_swarm.mesh.vote_envelope import sign_assignment

    with pytest.raises(ValueError, match="distinct"):
        sign_assignment(
            Ed25519PrivateKey.generate(),
            task_id="task",
            assignment_id="assignment",
            assigner_id="assigner",
            producer_id="producer",
            artifact_id="artifact",
            content_hash="a" * 64,
            constitutional_hash="b" * 64,
            assigned_peers=("VOTER", "voter"),
            quorum=2,
            selection_seed="selection",
            issued_at=1.0,
        )


def test_c16_external_registry_requires_authorized_assigner_key() -> None:
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    assigner_key = Ed25519PrivateKey.generate()
    wrong_role = VoteSignerRegistry()
    wrong_role.register("external-assigner", assigner_key.public_key(), roles={"voter"})

    with pytest.raises(ValueError, match="assigner"):
        ConstitutionalMesh(
            Constitution.default(),
            vote_registry=wrong_role,
            assigner_private_key=assigner_key,
            assigner_id="external-assigner",
        )

    with pytest.raises(ValueError, match="requires explicit"):
        ConstitutionalMesh(
            Constitution.default(),
            vote_registry=VoteSignerRegistry(),
        )


def test_c16_recovery_rejects_tampered_signed_assignment() -> None:
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    assigner_key = Ed25519PrivateKey.generate()
    registry = VoteSignerRegistry()
    registry.register("recovery-assigner", assigner_key.public_key(), roles={"assigner"})
    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=1,
        quorum=1,
        vote_registry=registry,
        assigner_private_key=assigner_key,
        assigner_id="recovery-assigner",
        evidence_mode="single_operator_dev",
    )
    mesh.register_local_signer("recovery-producer")
    mesh.register_local_signer("recovery-voter")
    assignment = mesh.request_validation(
        "recovery-producer", "safe recovery content", "recovery-artifact"
    )
    mesh.validate_and_vote(assignment.assignment_id, assignment.peers[0])
    result = mesh.get_result(assignment.assignment_id)
    record = mesh._record_with_serialized_votes(
        mesh._build_settlement_record(assignment, result),
        list(result.vote_envelopes),
    )
    serialized = mesh._serialize_assignment(assignment)
    serialized["signed_assignment"]["signature"] = "0" * 128
    tampered_assignment = mesh._deserialize_assignment(serialized)

    with pytest.raises(ValueError, match="signed assignment signature"):
        mesh._verified_settlement_evidence(record, tampered_assignment, result)


def test_c16_cascade_accepts_exact_ratio_without_float_ceil_overshoot():
    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=50,
        quorum=28,
        consensus_threshold=0.56,
        min_consensus_miners=3,
    )

    assert cascade._valid_mesh_result(candidate, result) is True


def test_c16_default_recovery_quarantines_dev_evidence(tmp_path):
    constitution = Constitution.default()
    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.generate()
    assigner_id = "dev-recovery-assigner"
    registry.register(assigner_id, assigner_key.public_key(), roles={"assigner"})
    store = JSONLSettlementStore(tmp_path / "dev-recovery.jsonl")
    writer = ConstitutionalMesh(
        constitution,
        settlement_store=store,
        vote_registry=registry,
        peers_per_validation=3,
        quorum=3,
        seed=51,
        evidence_mode="single_operator_dev",
        assigner_private_key=assigner_key,
        assigner_id=assigner_id,
    )
    writer.register_local_signer("dev-producer")
    for index in range(3):
        writer.register_local_signer(f"dev-voter-{index}")
    result = writer.full_validation(
        "dev-producer", "safe content", "dev-artifact", task_id="dev-task"
    )
    assert result.settled is True

    strict_reader = ConstitutionalMesh(
        constitution,
        settlement_store=store,
        vote_registry=registry,
        quorum=3,
        seed=52,
        assigner_private_key=assigner_key,
        assigner_id=assigner_id,
    )
    with pytest.raises(KeyError, match="not found"):
        strict_reader.get_result(result.assignment_id)

    dev_reader = ConstitutionalMesh(
        constitution,
        settlement_store=store,
        vote_registry=registry,
        quorum=3,
        seed=53,
        evidence_mode="single_operator_dev",
        assigner_private_key=assigner_key,
        assigner_id=assigner_id,
    )
    recovered = dev_reader.get_result(result.assignment_id)
    assert recovered.settled is True
    assert recovered.vote_envelopes == result.vote_envelopes


@pytest.mark.asyncio
async def test_c16_remote_cascade_rejects_invalid_vote_without_advancing():
    from dataclasses import replace

    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=3,
        quorum=3,
        seed=43,
        evidence_mode="independent",
    )
    mesh.register_remote_agent(
        "cascade-producer-invalid",
        vote_public_key=Ed25519PrivateKey.generate().public_key(),
    )
    peers = {}
    routes = {}
    tampered_hosts = []
    for index in range(3):
        voter_id = f"cascade-invalid-remote-{index}"
        peer = LocalRemotePeer(
            agent_id=voter_id,
            constitution=constitution,
            trusted_request_signers={mesh.get_request_signing_public_key()},
            trusted_assigners=mesh.vote_registry.frozen_copy(),
        )
        peers[voter_id] = peer
        mesh.register_remote_agent(voter_id, vote_public_key=peer.public_key_hex)
        routes[voter_id] = (voter_id, 9100 + index)

    class InvalidSignatureRemoteVoteClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            del port, timeout, ssl_context
            response = peers[host].handle_vote_request(request)
            if host == "cascade-invalid-remote-0":
                tampered_hosts.append(host)
                return RemoteVoteResponse(
                    replace(response.envelope, signature="00" * 64)
                )
            return response

    cascade = PrecedentCascade(
        constitution,
        mesh,
        min_consensus_miners=3,
        consensus_threshold=1.0,
        vote_registry=mesh.vote_registry,
    )
    candidate = await cascade.run_full_cascade_remote(
        judgment="Publish governance reasons with privacy safeguards",
        reasoning="Accountability and privacy are jointly protected",
        domain="governance",
        miner_uid="cascade-producer-invalid",
        peer_routes=routes,
        client=InvalidSignatureRemoteVoteClient(),
    )

    assert candidate.alive is False
    assert [result.stage for result in candidate.stage_results] == STAGE_ORDER[:2]
    assert candidate.stage_results[-1].passed is False
    assert tampered_hosts == ["cascade-invalid-remote-0"]
    assert candidate.stage_results[-1].detail == "mesh error: ValueError"
    assert cascade.accept(candidate) is None
def test_c16_proof_consumers_require_authenticated_assignment(tmp_path):
    """Proof consumers reject otherwise-valid votes when assignment authority is absent."""
    from dataclasses import replace

    from constitutional_swarm.bittensor.precedent_store import PrecedentStore
    from tests.test_c14_protocol_hardening import (
        _c14_precedent_pipeline,
        c14_precedent_signed_record,
        c14_precedent_test_registry,
    )

    record = c14_precedent_signed_record()
    positive_store = PrecedentStore(
        record.constitutional_hash,
        vote_registry=c14_precedent_test_registry(),
    )
    assert positive_store.admit(record).precedent_id == record.precedent_id
    with pytest.raises(ValueError, match="signed assignment"):
        PrecedentStore(
            record.constitutional_hash,
            vote_registry=c14_precedent_test_registry(),
        ).admit(replace(record, signed_assignment=None))

    owner, validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    mesh_result = validator.mesh.get_result(validation.assignment_id)
    assert validator._result_to_synapse(judgment, mesh_result).signed_assignment is not None
    with pytest.raises(ValueError, match="signed assignment"):
        validator._result_to_synapse(
            judgment,
            replace(mesh_result, signed_assignment=None),
        )

    assert owner.record_result(case, judgment, validation) is not None
    missing_owner, _, missing_case, missing_judgment, missing_validation = (
        _c14_precedent_pipeline(tmp_path)
    )
    with pytest.raises(ValueError, match="signed assignment"):
        missing_owner.record_result(
            missing_case,
            missing_judgment,
            replace(missing_validation, signed_assignment=None),
        )

    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=5,
        quorum=3,
        consensus_threshold=0.6,
        min_consensus_miners=3,
    )
    assert cascade._valid_mesh_result(candidate, result) is True
    assert cascade._valid_mesh_result(
        candidate,
        replace(result, signed_assignment=None),
    ) is False


def test_c16_receipt_verifier_requires_authenticated_assignment():
    from constitutional_swarm.governance_receipts import (
        GovernanceReceiptBundle,
        build_receipt,
    )

    bundle = valid_provenance_bundle()
    assert verify_bundle(
        bundle,
        trusted_signers=fixture_trusted_signers(),
    ).valid is True
    original = bundle.receipts[0]
    payload = original.payload.model_copy(update={"signed_assignment": None})
    stripped = build_receipt(payload=payload, signatures=original.signatures)
    verdict = verify_bundle(
        GovernanceReceiptBundle(receipts=[stripped]),
        trusted_signers=fixture_trusted_signers(),
    )

    assert verdict.valid is False
    assert "vote_assignment_missing" in {issue.code for issue in verdict.issues}
def test_c16_remote_peer_rejects_request_without_authoritative_assignment() -> None:
    """A trusted request signer cannot self-attest the voter electorate."""
    constitution = Constitution.default()
    requester = ConstitutionalMesh(
        constitution,
        peers_per_validation=3,
        quorum=2,
        seed=161,
        evidence_mode="single_operator_dev",
    )
    peer = LocalRemotePeer(
        agent_id="coalition-voter",
        constitution=constitution,
        trusted_request_signers={requester.get_request_signing_public_key()},
        trusted_assigners=requester.vote_registry.frozen_copy(),
    )
    requester.register_local_signer("producer")
    requester.register_remote_agent(
        "coalition-voter", vote_public_key=peer.public_key_hex
    )
    requester.register_local_signer("coalition-two")
    requester.register_local_signer("coalition-three")
    assignment = requester.request_validation("producer", "safe content", "artifact")
    request = requester.prepare_remote_vote(assignment.assignment_id, "coalition-voter")

    with pytest.raises(ValueError, match="signed assignment"):
        peer.handle_vote_request(replace(request, signed_assignment=None))


def test_c16_remote_peer_refuses_to_sign_outside_authoritative_roster() -> None:
    constitution = Constitution.default()
    assigner_key = Ed25519PrivateKey.generate()
    requester_key = Ed25519PrivateKey.generate()
    requester_public_key = requester_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    registry = VoteSignerRegistry()
    registry.register("assignment-authority", assigner_key.public_key(), roles={"assigner"})
    peer = LocalRemotePeer(
        agent_id="excluded-peer",
        constitution=constitution,
        trusted_request_signers={requester_public_key},
        trusted_assigners=registry.frozen_copy(),
    )
    content = "safe content"
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
    assignment = sign_assignment(
        assigner_key,
        task_id="task-membership",
        assignment_id="assignment-membership",
        assigner_id="assignment-authority",
        producer_id="producer",
        artifact_id="artifact",
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        assigned_peers=("authorized-peer",),
        quorum=1,
        selection_seed="membership-test",
        issued_at=1_000.0,
    )
    request = RemoteVoteRequest(
        assignment_id=assignment.assignment_id,
        voter_id="excluded-peer",
        producer_id=assignment.producer_id,
        artifact_id=assignment.artifact_id,
        content=content,
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        voter_public_key=peer.public_key_hex,
        nonce="membership-nonce",
        timestamp=1_000.0,
        request_signer_public_key=requester_public_key,
        request_signature=requester_key.sign(b"inconsistent roster request").hex(),
        task_id=assignment.task_id,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        protocol_version=3,
        signed_assignment=assignment,
    )

    with pytest.raises(ValueError, match="not a member"):
        peer.handle_vote_request(request)


def test_c16_vnext_protocol_fixture_corpus_is_opt_in_and_deterministic() -> None:
    from scripts.generate_rust_protocol_fixtures import build_vnext_fixture_corpus

    first = build_vnext_fixture_corpus()
    second = build_vnext_fixture_corpus()

    assert first == second
    assert set(first) == {
        "remote_vote_request_v3.json",
        "signed_assignment_v1.json",
    }
    assert '"protocol_version":3' in first["remote_vote_request_v3.json"]["wire_json"]


def test_c16_mesh_reserves_assigner_identity_from_agent_lifecycle(tmp_path) -> None:
    """Voter enrollment cannot replace or remove the pinned assignment authority."""
    from constitutional_swarm.governance_receipts import bundle_from_json, verify_bundle

    reserved_alias = "  MESH-\u200bASSIGNER  "
    remote_key = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=3,
        quorum=3,
        settlement_store=JSONLSettlementStore(tmp_path / "reserved-assigner.jsonl"),
        evidence_mode="single_operator_dev",
        seed=162,
    )

    for mutation in (
        lambda: mesh.register_local_signer(reserved_alias),
        lambda: mesh.register_remote_agent(
            reserved_alias,
            vote_public_key=remote_key.public_key(),
        ),
        lambda: mesh.unregister_agent(reserved_alias),
    ):
        with pytest.raises(ValueError, match="assignment authority"):
            mutation()

    mesh.register_local_signer("reserved-test-producer")
    for index in range(3):
        mesh.register_local_signer(f"reserved-test-voter-{index}")
    result = mesh.full_validation(
        "reserved-test-producer",
        "safe content after rejected identity mutations",
        "reserved-test-artifact",
        task_id="reserved-test-task",
    )

    assert result.proof is not None and result.proof.verify()
    assert result.signed_assignment is not None
    trust = mesh.receipt_trust_registry()
    assigner_grants = [
        grant
        for grant in trust.values()
        if grant["identity_id"] == mesh.assigner_id
    ]
    assert len(assigner_grants) == 1
    assert assigner_grants[0]["roles"] == ["assigner"]
    receipt = bundle_from_json(
        mesh._receipt_bundle_path(result.assignment_id).read_text(encoding="utf-8")
    )
    verdict = verify_bundle(
        receipt,
        trusted_signers=trust,
        require_independent_votes=False,
    )
    assert verdict.valid, verdict.issues


def test_c16_forensic_nonregular_packet_entry_is_rejected(tmp_path) -> None:
    import os

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    os.mkfifo(packet_dir / "unlisted.fifo")

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["issues"]
    }
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["inventory"]["issues"]
    }


def test_c16_forensic_unlisted_empty_directory_is_rejected(tmp_path) -> None:
    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    (packet_dir / "unlisted-empty-directory").mkdir()

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["issues"]
    }
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["inventory"]["issues"]
    }


@pytest.mark.parametrize(
    "raw_path",
    [".envrc", "config/.envrc", "CONFIG/.ENVRC", "nested/../config/.ENVRC",
     ".env~", "config/.env~", ".ENV~", ".env.bak", "config/.env.bak",
     "CONFIG/.ENV.BAK"],
)
def test_c16_forensic_dotenv_execution_and_backup_variants_require_review(
    tmp_path, raw_path
) -> None:
    from constitutional_swarm.governed_handoff import PolicyEngine

    engine = PolicyEngine({"policy": {"protected_paths": []}}, {"roles": {}}, tmp_path)
    decision = engine.decide("file_write", raw_path)
    assert decision.outcome == "human_review_required"
    assert "protected path" in decision.reason


@pytest.mark.parametrize(
    "raw_path", ["config/service.env~", "config/service.env.bak", ".environment"],
)
def test_c16_forensic_similarly_named_dotenv_backups_remain_allowed(
    tmp_path, raw_path
) -> None:
    from constitutional_swarm.governed_handoff import PolicyEngine

    engine = PolicyEngine({"policy": {"protected_paths": []}}, {"roles": {}}, tmp_path)
    assert engine.decide("file_write", raw_path).outcome == "allow"


def _c16_corrupt_registry_with_dual_role(registry):
    """Bypass registry mutators to model a deserialized/corrupted trust root."""
    assigner = next(
        grant for grant in registry._identities.values() if "assigner" in grant.roles
    )
    corrupted = replace(assigner, roles=assigner.roles | {"voter"})
    if registry.frozen:
        from types import MappingProxyType

        grants = tuple(
            corrupted if grant.identity == assigner.identity else grant
            for grant in registry._grants
        )
        identities = dict(registry._identities)
        identities[assigner.identity] = corrupted
        object.__setattr__(registry, "_grants", grants)
        object.__setattr__(registry, "_identities", MappingProxyType(identities))
    else:
        registry._identities[assigner.identity] = corrupted
    return registry


def test_c16_register_rejects_assigner_and_voter_roles() -> None:
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    key = Ed25519PrivateKey.generate().public_key()
    registry = VoteSignerRegistry()
    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        registry.register("dual-role", key, roles={"assigner", "voter"})


def test_c16_replace_rejects_assigner_and_validator_roles_atomically() -> None:
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    key = Ed25519PrivateKey.generate().public_key()
    registry = VoteSignerRegistry()
    original_key_id = registry.register("voter", key, roles={"voter", "validator"})
    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        registry.replace("voter", key, roles={"assigner", "validator"})
    assert registry.authorize("voter", original_key_id, role="voter") is key


def test_c16_frozen_registry_rejects_assigner_and_voter_roles() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    key = Ed25519PrivateKey.generate().public_key()
    key_id = key_id_for_public_key(key)
    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        FrozenVoteSignerRegistry(
            (_Grant("dual-role", key_id, key, frozenset({"assigner", "voter"})),)
        )


def test_c16_assigner_key_cannot_alias_a_voter_identity() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    key = Ed25519PrivateKey.generate().public_key()
    key_id = key_id_for_public_key(key)
    with pytest.raises(ValueError, match="assigner.*key|key.*assigner"):
        FrozenVoteSignerRegistry(
            (
                _Grant("assigner", key_id, key, frozenset({"assigner"})),
                _Grant("voter", key_id, key, frozenset({"voter", "validator"})),
            )
        )


def test_c16_frozen_registry_rejects_forged_key_fingerprint() -> None:
    from constitutional_swarm.mesh.vote_envelope import FrozenVoteSignerRegistry, _Grant

    key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ValueError, match="fingerprint"):
        FrozenVoteSignerRegistry(
            (_Grant("assigner", "0" * 64, key, frozenset({"assigner"})),)
        )


def test_c16_frozen_registry_rejects_mutable_grant_roles() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(TypeError, match="immutable frozenset"):
        FrozenVoteSignerRegistry(
            (_Grant("assigner", key_id_for_public_key(key), key, {"assigner"}),)
        )


def test_c16_proof_verifier_rejects_assigner_key_aliased_to_voter() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        _Grant,
        verify_assignment_vote_envelopes,
    )

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    envelope = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="approval",
        nonce="aliased-key-proof",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest=signed_assignment_digest(assignment),
        **bindings,
    )
    assigner = registry._identities[assignment.assigner_id]
    registry._identities["aliased-voter"] = _Grant(
        "aliased-voter",
        assigner.key_id,
        assigner.key,
        frozenset({"voter", "validator"}),
    )

    with pytest.raises(ValueError, match="assigner key"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            registry,
            **bindings,
        )


def test_c16_proof_verifier_compares_actual_assigner_and_voter_keys() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        key_id_for_public_key,
        verify_assignment_vote_envelopes,
    )

    shared_key = Ed25519PrivateKey.generate()
    key_id = key_id_for_public_key(shared_key.public_key())
    bindings = {
        "task_id": "shared-key-task",
        "assignment_id": "shared-key-assignment",
        "producer_id": "shared-key-producer",
        "artifact_id": "shared-key-artifact",
        "content_hash": "a" * 64,
        "constitutional_hash": "b" * 64,
    }
    assignment = sign_assignment(
        shared_key,
        assigner_id="shared-key-assigner",
        assigned_peers=("shared-key-voter",),
        quorum=1,
        selection_seed="shared-key-seed",
        issued_at=1_800_000_000.0,
        **bindings,
    )
    envelope = sign_vote_envelope(
        shared_key,
        voter_id="shared-key-voter",
        decision="approved",
        reason="same physical key",
        nonce="shared-key-nonce",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest=signed_assignment_digest(assignment),
        **bindings,
    )

    class HandBuiltRegistry:
        def validate_trust_root(self):
            return None

        def authorize(self, identity, requested_key_id, *, role="voter"):
            assert identity in {"shared-key-assigner", "shared-key-voter"}
            assert requested_key_id == key_id
            assert role in {"assigner", "voter"}
            return shared_key.public_key()

        def trust_grants(self, *, role="validator"):
            return {}

    with pytest.raises(ValueError, match="assigner key"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            HandBuiltRegistry(),
            **bindings,
        )


def test_c16_proof_verifier_rejects_desynchronized_frozen_registry_indexes() -> None:
    from types import MappingProxyType

    from constitutional_swarm.mesh.vote_envelope import verify_assignment_vote_envelopes

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    envelope = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="approval",
        nonce="desynchronized-index-proof",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest=signed_assignment_digest(assignment),
        **bindings,
    )
    frozen = registry.frozen_copy()
    identities = dict(frozen._identities)
    assigner = identities[assignment.assigner_id]
    identities[assignment.assigner_id] = replace(
        assigner, roles=assigner.roles | {"voter"}
    )
    object.__setattr__(frozen, "_identities", MappingProxyType(identities))

    with pytest.raises(ValueError, match="identity index"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            frozen,
            **bindings,
        )


def test_c16_proof_verifier_rejects_desynchronized_mutable_key_index() -> None:
    from constitutional_swarm.mesh.vote_envelope import verify_assignment_vote_envelopes

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    envelope = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="approval",
        nonce="desynchronized-key-proof",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest=signed_assignment_digest(assignment),
        **bindings,
    )
    registry._keys[assignment.key_id] = "assigned-voter"

    with pytest.raises(ValueError, match="key index"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            registry,
            **bindings,
        )


def test_c16_receipt_grant_loading_rejects_dual_role_authority() -> None:
    trust = fixture_trusted_signers()
    assigner_key_id = next(
        key_id for key_id, grant in trust.items() if "assigner" in grant["roles"]
    )
    trust[assigner_key_id] = {
        **trust[assigner_key_id],
        "roles": ["assigner", "validator"],
    }

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trust)

    assert verdict.valid is False
    assert "trust_registry_invalid" in {issue.code for issue in verdict.issues}


def test_c16_signed_assignment_rejects_assigner_in_electorate() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="assigner_id.*assigned_peers"):
        sign_assignment(
            key,
            task_id="task",
            assignment_id="assignment",
            assigner_id="authority",
            producer_id="producer",
            artifact_id="artifact",
            content_hash="a" * 64,
            constitutional_hash="b" * 64,
            assigned_peers=("authority",),
            quorum=1,
            selection_seed="seed",
            issued_at=1.0,
        )


def test_c16_proof_verifier_rejects_hand_built_dual_role_registry() -> None:
    from constitutional_swarm.mesh.vote_envelope import verify_assignment_vote_envelopes

    assignment, registry, voter_key, bindings = _c16_signed_assignment_fixture()
    envelope = sign_vote_envelope(
        voter_key,
        voter_id="assigned-voter",
        decision="approved",
        reason="approval",
        nonce="dual-role-proof",
        issued_at=1_800_000_001.0,
        assigned_peers=assignment.assigned_peers,
        quorum=assignment.quorum,
        assignment_digest=signed_assignment_digest(assignment),
        **bindings,
    )
    _c16_corrupt_registry_with_dual_role(registry)

    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        verify_assignment_vote_envelopes(
            assignment,
            (envelope,),
            registry,
            **bindings,
        )


def test_c16_precedent_store_rejects_hand_built_dual_role_registry() -> None:
    from constitutional_swarm.bittensor.precedent_store import PrecedentStore
    from tests.test_c14_protocol_hardening import (
        c14_precedent_signed_record,
        c14_precedent_test_registry,
    )

    record = c14_precedent_signed_record()
    registry = _c16_corrupt_registry_with_dual_role(c14_precedent_test_registry())

    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        PrecedentStore(
            record.constitutional_hash,
            vote_registry=registry,
        ).admit(record)


def test_c16_validator_rejects_hand_built_dual_role_registry(tmp_path) -> None:
    from tests.test_c14_protocol_hardening import _c14_precedent_pipeline

    _, validator, _, judgment, validation = _c14_precedent_pipeline(tmp_path)
    result = validator.mesh.get_result(validation.assignment_id)
    _c16_corrupt_registry_with_dual_role(validator.mesh.vote_registry)

    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        validator._result_to_synapse(judgment, result)


def test_c16_cascade_rejects_hand_built_dual_role_registry() -> None:
    cascade, candidate, result = _c16_consumer_cascade_result(
        electorate_size=5,
        quorum=3,
        consensus_threshold=0.6,
        min_consensus_miners=3,
    )
    _c16_corrupt_registry_with_dual_role(cascade._vote_registry)

    assert cascade._valid_mesh_result(candidate, result) is False


def test_c16_receipt_rejects_hand_built_dual_role_registry() -> None:
    trust = fixture_trusted_signers()
    assigner_key_id = next(
        key_id for key_id, grant in trust.items() if "assigner" in grant["roles"]
    )
    trust[assigner_key_id] = {
        **trust[assigner_key_id],
        "roles": ["assigner", "validator"],
    }

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trust)

    assert verdict.valid is False
    assert "trust_registry_invalid" in {issue.code for issue in verdict.issues}


def _c16_recovery_evidence_for_assigner(tmp_path, *, assigner_id, assigner_key, registry):
    del tmp_path
    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=1,
        quorum=1,
        vote_registry=registry,
        assigner_private_key=assigner_key,
        assigner_id=assigner_id,
        evidence_mode="single_operator_dev",
    )
    producer_id = f"{assigner_id}-producer"
    voter_id = f"{assigner_id}-voter"
    mesh.register_local_signer(producer_id)
    mesh.register_local_signer(voter_id)
    assignment = mesh.request_validation(
        producer_id, "safe recovery content", f"{assigner_id}-artifact"
    )
    mesh.validate_and_vote(assignment.assignment_id, assignment.peers[0])
    result = mesh.get_result(assignment.assignment_id)
    record = mesh._record_with_serialized_votes(
        mesh._build_settlement_record(assignment, result),
        list(result.vote_envelopes),
    )
    return mesh, record, assignment, result


def test_c16_recovery_pins_mesh_assigner_identity_and_key(tmp_path) -> None:
    registry = VoteSignerRegistry()
    local_key = Ed25519PrivateKey.generate()
    foreign_key = Ed25519PrivateKey.generate()
    registry.register("local-assigner", local_key.public_key(), roles={"assigner"})
    registry.register("foreign-assigner", foreign_key.public_key(), roles={"assigner"})
    local_mesh, _, _, _ = _c16_recovery_evidence_for_assigner(
        tmp_path,
        assigner_id="local-assigner",
        assigner_key=local_key,
        registry=registry,
    )
    _, foreign_record, foreign_assignment, foreign_result = (
        _c16_recovery_evidence_for_assigner(
            tmp_path,
            assigner_id="foreign-assigner",
            assigner_key=foreign_key,
            registry=registry,
        )
    )

    with pytest.raises(ValueError, match="mesh assignment authority"):
        local_mesh._verified_settlement_evidence(
            foreign_record,
            foreign_assignment,
            foreign_result,
        )


def test_c16_recovery_accepts_pinned_mesh_assigner(tmp_path) -> None:
    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.generate()
    registry.register("local-assigner", assigner_key.public_key(), roles={"assigner"})
    mesh, record, assignment, result = _c16_recovery_evidence_for_assigner(
        tmp_path,
        assigner_id="local-assigner",
        assigner_key=assigner_key,
        registry=registry,
    )

    envelopes, recovered = mesh._verified_settlement_evidence(
        record,
        assignment,
        result,
    )

    assert envelopes == result.vote_envelopes
    assert recovered.accepted is True


def test_c16_recovery_rejects_corrupted_dual_role_trust_root(tmp_path) -> None:
    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.generate()
    registry.register("local-assigner", assigner_key.public_key(), roles={"assigner"})
    mesh, record, assignment, result = _c16_recovery_evidence_for_assigner(
        tmp_path,
        assigner_id="local-assigner",
        assigner_key=assigner_key,
        registry=registry,
    )
    _c16_corrupt_registry_with_dual_role(mesh._assigner_trust_root)

    with pytest.raises(ValueError, match="assigner.*voter|voter.*assigner"):
        mesh._verified_settlement_evidence(record, assignment, result)


def test_c16_forensic_socket_entry_is_rejected(tmp_path, monkeypatch) -> None:
    import stat
    from pathlib import Path
    from types import SimpleNamespace

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    socket_path = packet_dir / "unlisted.socket"
    socket_path.write_bytes(b"")
    original_lstat = Path.lstat

    def socket_lstat(self):
        if self == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK)
        return original_lstat(self)

    monkeypatch.setattr(Path, "lstat", socket_lstat)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["inventory"]["issues"]
    }


def test_c16_forensic_fifo_manifest_is_inventory_issue(tmp_path) -> None:
    import os

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    manifest_path = packet_dir / "reviewer_manifest.json"
    manifest_path.unlink()
    os.mkfifo(manifest_path)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "invalid_reviewer_manifest" in {
        issue["code"] for issue in verdict["manifest"]["issues"]
    }
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["inventory"]["issues"]
    }


def test_c16_forensic_device_entry_is_rejected(tmp_path, monkeypatch) -> None:
    import stat
    from pathlib import Path
    from types import SimpleNamespace

    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)
    device_path = packet_dir / "unlisted.device"
    device_path.write_bytes(b"")
    original_lstat = Path.lstat

    def device_lstat(self):
        if self == device_path:
            return SimpleNamespace(st_mode=stat.S_IFCHR)
        return original_lstat(self)

    monkeypatch.setattr(Path, "lstat", device_lstat)

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is False
    assert "unlisted_packet_entry" in {
        issue["code"] for issue in verdict["inventory"]["issues"]
    }


def test_c16_forensic_manifest_parent_directories_are_accepted(tmp_path) -> None:
    runner = c16_forensic_load_benchmark_runner()
    packet_dir = tmp_path / "reviewer-packet"
    packet_dir.mkdir()
    c16_forensic_write_packet(packet_dir)

    assert any(path.is_dir() for path in packet_dir.rglob("*"))

    verdict = runner._audit_reviewer_packet(packet_dir)

    assert verdict["valid"] is True
    assert verdict["inventory"] == {"valid": True, "issues": []}
