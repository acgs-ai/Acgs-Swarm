"""C35b regression tests: caller-pinned anchor roots and strict audit-log decoding."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from typing import Any

import pytest

from constitutional_swarm.bittensor.arweave_audit_log import (
    ArweaveAuditLogger,
    AuditBatch,
    AuditDecisionType,
    AuditLogEntry,
    InMemoryArweaveClient,
)
from constitutional_swarm.bittensor.chain_anchor import (
    AnchorRecord,
    ChainAnchor,
    ProofEvidence,
    _compute_merkle_root as _compute_anchor_root,
)

CONST_HASH = "608508a9bd224290"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _proof(proof_id: str) -> ProofEvidence:
    return ProofEvidence(
        proof_id=proof_id,
        root_hash=_digest(f"root:{proof_id}"),
        content_hash=_digest(f"content:{proof_id}"),
        vote_hashes=(_digest(f"vote:{proof_id}"),),
        constitutional_hash=CONST_HASH,
        captured_at=1_700_000_000.25,
    )


def _record(proofs: list[ProofEvidence]) -> AnchorRecord:
    leaves = [p.membership_leaf() for p in proofs]
    return AnchorRecord(
        anchor_id="anchor-1",
        batch_root=_compute_anchor_root(leaves),
        constitutional_hash=CONST_HASH,
        proof_count=len(proofs),
        block_height=1,
        submitted_at=1_700_000_001.0,
        proof_ids=tuple(p.proof_id for p in proofs),
        leaf_hashes=tuple(leaves),
    )


def _entry(entry_id: str = "entry-1") -> AuditLogEntry:
    return AuditLogEntry(
        entry_id=entry_id,
        case_id="case-1",
        constitutional_hash=CONST_HASH,
        decision_type=AuditDecisionType.ESCALATED,
        compliance_passed=True,
        impact_score=0.5,
        escalation_type="privacy",
        resolution="allow",
        miner_uid="miner-1",
        validator_grade=float("nan"),
        decision_at=1_700_000_000.125,
        tags=(("client", "sdk"),),
    )


# ---------------------------------------------------------------------------
# F1: verify_membership must check a caller-pinned root
# ---------------------------------------------------------------------------


def test_rejects_self_consistent_forged_record_against_pinned_root() -> None:
    genuine = _record([_proof("honest-1"), _proof("honest-2")])
    attacker = _proof("attacker")
    # Forged record is internally consistent: its stored root matches its leaves.
    forged = _record([attacker])

    assert forged.verify_membership(attacker, expected_root=forged.batch_root)
    assert not forged.verify_membership(attacker, expected_root=genuine.batch_root)


def test_rejects_membership_with_wrong_pin_with_matching_pin_control() -> None:
    proof = _proof("p")
    record = _record([proof, _proof("q")])

    assert record.verify_membership(proof, expected_root=record.batch_root)
    assert not record.verify_membership(proof, expected_root=_digest("other-root"))


def test_rejects_uppercase_wrong_pin_with_uppercase_honest_pin_control() -> None:
    proof = _proof("p")
    record = _record([proof, _proof("q")])

    assert record.verify_membership(proof, expected_root=record.batch_root.upper())
    assert not record.verify_membership(proof, expected_root=_digest("other-root").upper())


@pytest.mark.parametrize("bad_pin", ["", "é" * 64, "zz" * 32, None, 1, b"\x00" * 32])
def test_rejects_malformed_pinned_root(bad_pin: object) -> None:
    proof = _proof("p")
    record = _record([proof])

    assert not record.verify_membership(proof, expected_root=bad_pin)  # type: ignore[arg-type]


def test_rejects_membership_call_without_pinned_root() -> None:
    proof = _proof("p")
    record = _record([proof])

    with pytest.raises(TypeError):
        record.verify_membership(proof)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        record.verify_membership(proof, record.batch_root)  # type: ignore[misc]


def test_rejects_stored_root_drift_even_when_pin_matches_recomputation() -> None:
    proof = _proof("p")
    record = _record([proof])
    drifted = replace(record, batch_root=_digest("drift"))

    assert not drifted.verify_membership(proof, expected_root=record.batch_root)


def test_history_lookup_still_finds_anchored_proof_with_outsider_control() -> None:
    anchor = ChainAnchor(CONST_HASH, batch_size=2)
    member = _proof("member")
    anchor.add_proof(member)
    record = anchor.add_proof(_proof("other"))
    assert record is not None

    assert anchor.verify_proof_in_history(member) == record
    assert anchor.verify_proof_in_history(_proof("outsider")) is None


# ---------------------------------------------------------------------------
# F2: strict key sets in AuditLogEntry.from_dict / AuditBatch.from_dict
# ---------------------------------------------------------------------------


def test_rejects_unknown_entry_key_with_roundtrip_control() -> None:
    entry = _entry()
    encoded = entry.to_dict()
    restored = AuditLogEntry.from_dict(encoded)
    assert restored.leaf_hash() == entry.leaf_hash()
    assert math.isnan(restored.validator_grade)

    with pytest.raises(ValueError, match="unknown.*smuggled"):
        AuditLogEntry.from_dict({**encoded, "smuggled": "x"})


@pytest.mark.parametrize(
    "field",
    [
        "entry_id",
        "case_id",
        "constitutional_hash",
        "decision_type",
        "compliance_passed",
        "impact_score",
        "escalation_type",
        "resolution",
        "miner_uid",
        "validator_grade",
        "decision_at",
        "tags",
    ],
)
def test_rejects_missing_entry_key(field: str) -> None:
    encoded = _entry().to_dict()
    encoded.pop(field)

    with pytest.raises(ValueError, match=f"missing.*{field}"):
        AuditLogEntry.from_dict(encoded)


def test_rejects_unknown_batch_key_with_roundtrip_control() -> None:
    batch = AuditBatch("batch-1", CONST_HASH, [_entry("e1"), _entry("e2")])
    encoded = batch.to_dict()
    restored = AuditBatch.from_dict(json.loads(json.dumps(encoded)))
    assert restored.batch_root == batch.batch_root
    assert restored.to_dict() == encoded

    with pytest.raises(ValueError, match="unknown.*smuggled"):
        AuditBatch.from_dict({**encoded, "smuggled": "x"})


@pytest.mark.parametrize(
    "field",
    [
        "batch_id",
        "batch_root",
        "constitutional_hash",
        "entry_count",
        "created_at",
        "entries",
        "leaf_hashes",
    ],
)
def test_rejects_missing_batch_key(field: str) -> None:
    encoded = AuditBatch("batch-1", CONST_HASH, [_entry()]).to_dict()
    encoded.pop(field)

    with pytest.raises(ValueError, match=f"missing.*{field}"):
        AuditBatch.from_dict(encoded)


def test_rejects_unknown_key_in_nested_batch_entry() -> None:
    encoded = AuditBatch("batch-1", CONST_HASH, [_entry()]).to_dict()
    entries: list[dict[str, Any]] = encoded["entries"]
    entries[0] = {**entries[0], "smuggled": "x"}

    with pytest.raises(ValueError, match="unknown.*smuggled"):
        AuditBatch.from_dict(encoded)


def test_fetch_batch_rejects_unknown_keys_with_clean_fetch_control() -> None:
    client = InMemoryArweaveClient()
    logger = ArweaveAuditLogger(CONST_HASH, client)
    logger.add_entry(_entry("e1"))
    receipt = logger.flush()
    assert receipt is not None
    assert logger.fetch_batch(receipt).batch_root == receipt.batch_root

    payload = json.loads(client.fetch(receipt.arweave_tx_id))
    payload["smuggled"] = "x"
    tx_id = client.upload(json.dumps(payload).encode())
    with pytest.raises(ValueError, match="batch"):
        logger.fetch_batch(replace(receipt, arweave_tx_id=tx_id))


def test_rejects_many_newline_keys_with_bounded_error_message() -> None:
    encoded = _entry().to_dict()
    hostile = {f"evil\n{i}\r" + "x" * 500: i for i in range(5000)}

    with pytest.raises(ValueError, match="unknown keys: 5000") as excinfo:
        AuditLogEntry.from_dict({**encoded, **hostile})
    message = str(excinfo.value)
    assert "\n" not in message
    assert "\r" not in message
    assert len(message) < 400


def test_rejects_mixed_type_unknown_keys_without_sort_type_error() -> None:
    encoded: dict[Any, Any] = _entry().to_dict()
    encoded[1] = "int-key"
    encoded[(2, 3)] = "tuple-key"

    with pytest.raises(ValueError, match="unknown keys: 2"):
        AuditLogEntry.from_dict(encoded)
