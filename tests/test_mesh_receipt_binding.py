"""Mesh settlement must bind the existing v0.1 receipt profile."""

from __future__ import annotations

import json
import subprocess
import sys

from acgs_lite import Constitution
from cryptography.hazmat.primitives import serialization
from constitutional_swarm import (
    ConstitutionalMesh,
    JSONLSettlementStore,
    PROFILE_VERSION,
    bundle_from_json,
    settlement_canonical_digest,
    verify_bundle,
)
from constitutional_swarm.governance_receipts_dsse import to_dsse_envelope


def _trusted_signers(mesh: ConstitutionalMesh) -> dict[str, str]:
    return {
        "settlement-receipt": mesh._receipt_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    }


def _settled_mesh(tmp_path):
    store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
    mesh = ConstitutionalMesh(Constitution.default(), seed=42, settlement_store=store)
    for index in range(4):
        mesh.register_local_signer(f"agent-{index:02d}")
    assignment = mesh.request_validation("agent-00", "summarize notes", "artifact-1")
    for voter in assignment.peers[:2]:
        mesh.validate_and_vote(assignment.assignment_id, voter)
    result = mesh.get_result(assignment.assignment_id)
    assert result is not None
    assert result.settled
    return mesh, assignment, store


def test_settlement_emits_verifiable_v0_1_receipt(tmp_path) -> None:
    mesh, assignment, store = _settled_mesh(tmp_path)
    records = store.load_all()
    assert len(records) == 1
    record = records[0]
    assert record.receipt_digest
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    bundle = bundle_from_json(receipt_path.read_text(encoding="utf-8"))
    assert bundle.profile_version == PROFILE_VERSION
    assert bundle.receipts[0].payload_digest == record.receipt_digest
    assert bundle.receipts[0].payload.evidence_hashes["settlement"] == settlement_canonical_digest(
        record
    )
    verdict = verify_bundle(bundle, trusted_signers=_trusted_signers(mesh))
    assert verdict.valid, verdict.issues
    assert "local" in bundle.receipts[0].payload.metadata["claim"]


def test_payload_tamper_fails_verify(tmp_path) -> None:
    mesh, assignment, _store = _settled_mesh(tmp_path)
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    bundle = json.loads(receipt_path.read_text(encoding="utf-8"))
    bundle["receipts"][0]["payload"]["action"] = "tampered"
    tampered = bundle_from_json(json.dumps(bundle))
    assert verify_bundle(tampered).valid is False


def test_assignment_id_mismatch_is_detectable(tmp_path) -> None:
    mesh, assignment, store = _settled_mesh(tmp_path)
    record = store.load_all()[0]
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    bundle = bundle_from_json(receipt_path.read_text(encoding="utf-8"))
    assert bundle.receipts[0].payload.metadata["assignment_id"] == assignment.assignment_id
    assert record.assignment["assignment_id"] == assignment.assignment_id


def test_standalone_verifier_process(tmp_path) -> None:
    mesh, assignment, _store = _settled_mesh(tmp_path)
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "from constitutional_swarm import bundle_from_json, verify_bundle;"
                f"bundle=bundle_from_json(Path({str(receipt_path)!r}).read_text());"
                f"trusted={_trusted_signers(mesh)!r};"
                "verdict=verify_bundle(bundle, trusted_signers=trusted);"
                "raise SystemExit(0 if verdict.valid else 1)"
            ),
        ],
        check=False,
    )
    assert completed.returncode == 0


def test_dsse_projection_is_not_a_compliance_claim(tmp_path) -> None:
    mesh, assignment, _store = _settled_mesh(tmp_path)
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    bundle = bundle_from_json(receipt_path.read_text(encoding="utf-8"))
    envelope = to_dsse_envelope(bundle.receipts[0])
    assert envelope["signatures"] == []
    text = json.dumps(envelope)
    assert "certified" not in text.lower()
    assert "scitt" not in text.lower()


def test_unknown_critical_field_rejected(tmp_path) -> None:
    mesh, assignment, _store = _settled_mesh(tmp_path)
    receipt_path = mesh._receipt_bundle_path(assignment.assignment_id)
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["receipts"][0]["unexpected"] = "nope"
    try:
        bundle_from_json(json.dumps(payload))
    except Exception:
        return
    raise AssertionError("unknown critical fields must fail closed")
