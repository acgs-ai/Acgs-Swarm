"""Adversarial binding tests for settlement-receipt identity."""

from __future__ import annotations

import json
from copy import deepcopy

from acgs_lite import Constitution
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from constitutional_swarm import ConstitutionalMesh, JSONLSettlementStore, SQLiteSettlementStore
from constitutional_swarm.governance_receipts import (
    SignatureRecord,
    bundle_from_json,
    build_receipt,
    payload_canonical_bytes,
)
from constitutional_swarm.settlement_evidence import (
    RECEIPT_SIGNER_KEY_ID,
    bind_and_verify,
    receipt_path_for,
    verify_committed_settlement_receipt,
)


def _trusted(mesh: ConstitutionalMesh) -> dict[str, str]:
    return {
        RECEIPT_SIGNER_KEY_ID: mesh._receipt_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    }


def _settle(tmp_path, *, name: str = "a", backend: str = "jsonl"):
    path = tmp_path / (f"{name}.db" if backend == "sqlite" else f"{name}.jsonl")
    store = SQLiteSettlementStore(path) if backend == "sqlite" else JSONLSettlementStore(path)
    mesh = ConstitutionalMesh(Constitution.default(), seed=7, settlement_store=store)
    for index in range(4):
        mesh.register_local_signer(f"agent-{index:02d}")
    assignment = mesh.request_validation("agent-00", "summarize notes", f"art-{name}")
    for voter in assignment.peers[:2]:
        mesh.validate_and_vote(assignment.assignment_id, voter)
    return mesh, store, assignment


def test_cross_settlement_receipt_replay_fails(tmp_path) -> None:
    mesh_a, store_a, assign_a = _settle(tmp_path, name="one")
    _mesh_b, store_b, assign_b = _settle(tmp_path, name="two")
    bundle_a = bundle_from_json(receipt_path_for(store_a, assign_a.assignment_id).read_text())
    record_b = store_b.get(assign_b.assignment_id)
    assert record_b is not None
    verdict = bind_and_verify(record_b, bundle_a, trusted_signers=_trusted(mesh_a))
    assert verdict.valid is False
    assert any(
        issue.code in {"assignment_mismatch", "settlement_digest_mismatch", "receipt_pointer_mismatch"}
        for issue in verdict.issues
    )


def test_pointer_substitution_fails(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    record = store.get(assignment.assignment_id)
    assert record is not None
    from dataclasses import replace

    swapped = replace(record, receipt_digest="ab" * 32)
    bundle = bundle_from_json(receipt_path_for(store, assignment.assignment_id).read_text())
    verdict = bind_and_verify(swapped, bundle, trusted_signers=_trusted(mesh))
    assert verdict.valid is False
    assert any(issue.code == "receipt_pointer_mismatch" for issue in verdict.issues)


def test_settlement_field_tamper_breaks_digest(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    record = store.get(assignment.assignment_id)
    assert record is not None
    tampered = deepcopy(record)
    tampered.assignment["artifact_id"] = "mutated"
    # frozen dataclass — rebuild
    from constitutional_swarm.settlement_store import SettlementRecord

    mutated = SettlementRecord(
        assignment={**record.assignment, "artifact_id": "mutated"},
        result=record.result,
        constitutional_hash=record.constitutional_hash,
        schema_version=record.schema_version,
        is_recovered=record.is_recovered,
        receipt_digest=record.receipt_digest,
    )
    bundle = bundle_from_json(receipt_path_for(store, assignment.assignment_id).read_text())
    verdict = bind_and_verify(mutated, bundle, trusted_signers=_trusted(mesh))
    assert verdict.valid is False
    assert any(issue.code == "settlement_digest_mismatch" for issue in verdict.issues)


def test_signature_substitution_over_same_payload_fails(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    bundle = bundle_from_json(receipt_path_for(store, assignment.assignment_id).read_text())
    receipt = bundle.receipts[0]
    rogue = Ed25519PrivateKey.generate()
    sig = rogue.sign(payload_canonical_bytes(receipt.payload))
    forged = build_receipt(
        payload=receipt.payload,
        signatures=[
            SignatureRecord(
                key_id=RECEIPT_SIGNER_KEY_ID,
                algorithm="ed25519",
                public_key_hex=rogue.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                .hex(),
                signature_hex=sig.hex(),
            )
        ],
    )
    from constitutional_swarm.governance_receipts import GovernanceReceiptBundle

    verdict = bind_and_verify(
        store.get(assignment.assignment_id),
        GovernanceReceiptBundle(receipts=[forged]),
        trusted_signers=_trusted(mesh),
    )
    assert verdict.valid is False


def test_untrusted_and_key_id_substitution_fail(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    bundle = bundle_from_json(receipt_path_for(store, assignment.assignment_id).read_text())
    record = store.get(assignment.assignment_id)
    assert bind_and_verify(record, bundle, trusted_signers={}).valid is False
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    assert bind_and_verify(record, bundle, trusted_signers={RECEIPT_SIGNER_KEY_ID: other}).valid is False
    assert bind_and_verify(record, bundle, trusted_signers={"wrong-id": _trusted(mesh)[RECEIPT_SIGNER_KEY_ID]}).valid is False


def test_wrong_payload_type_fails(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    path = receipt_path_for(store, assignment.assignment_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["receipts"][0]["payload_type"] = "application/json"
    try:
        bundle = bundle_from_json(json.dumps(payload))
    except Exception:
        return
    verdict = bind_and_verify(store.get(assignment.assignment_id), bundle, trusted_signers=_trusted(mesh))
    assert verdict.valid is False


def test_receipt_copied_beside_other_store_fails(tmp_path) -> None:
    mesh_a, store_a, assign_a = _settle(tmp_path, name="src")
    _mesh_b, store_b, assign_b = _settle(tmp_path, name="dst", backend="sqlite")
    src = receipt_path_for(store_a, assign_a.assignment_id)
    dst = receipt_path_for(store_b, assign_b.assignment_id)
    dst.write_text(src.read_text(encoding="utf-8"))
    verdict = verify_committed_settlement_receipt(
        store_b, assign_b.assignment_id, trusted_signers=_trusted(mesh_a)
    )
    assert verdict.valid is False


def test_orphan_without_committed_settlement_fails(tmp_path) -> None:
    store = JSONLSettlementStore(tmp_path / "only.jsonl")
    verdict = verify_committed_settlement_receipt(store, "ghost")
    assert verdict.valid is False
    assert any(issue.code == "settlement_missing" for issue in verdict.issues)


def test_vote_signature_is_not_a_receipt_signature(tmp_path) -> None:
    mesh, store, assignment = _settle(tmp_path)
    vote = mesh._votes[assignment.assignment_id][0]
    bundle = bundle_from_json(receipt_path_for(store, assignment.assignment_id).read_text())
    receipt = bundle.receipts[0]
    stolen = build_receipt(
        payload=receipt.payload,
        signatures=[
            SignatureRecord(
                key_id=RECEIPT_SIGNER_KEY_ID,
                algorithm="ed25519",
                public_key_hex=_trusted(mesh)[RECEIPT_SIGNER_KEY_ID],
                signature_hex=vote.signature,
            )
        ],
    )
    from constitutional_swarm.governance_receipts import GovernanceReceiptBundle

    verdict = bind_and_verify(
        store.get(assignment.assignment_id),
        GovernanceReceiptBundle(receipts=[stolen]),
        trusted_signers=_trusted(mesh),
    )
    assert verdict.valid is False
    receipt_pub = mesh._receipt_signing_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    request_pub = mesh._request_signing_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert receipt_pub != request_pub
