"""Regression coverage for C35 audit-log and chain-anchor hardening."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from types import MappingProxyType
from typing import Any

import pytest

from constitutional_swarm.bittensor.arweave_audit_log import (
    ArweaveAuditLogger,
    AuditBatch,
    AuditChainSubmitter,
    AuditDecisionType,
    AuditLogEntry,
    AuditLogReceipt,
    InMemoryArweaveClient,
    _compute_merkle_root,
    _merkle_path_for_index,
    verify_merkle_path,
)
from constitutional_swarm.bittensor.chain_anchor import (
    AnchorRecord,
    ChainAnchor,
    ChainSubmitter,
    ProofEvidence,
    _compute_merkle_root as _compute_anchor_root,
)


CONST_HASH = "608508a9bd224290"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _entry(entry_id: str, **changes: Any) -> AuditLogEntry:
    values: dict[str, Any] = {
        "entry_id": entry_id,
        "case_id": "case-1",
        "constitutional_hash": CONST_HASH,
        "decision_type": AuditDecisionType.ESCALATED,
        "compliance_passed": True,
        "impact_score": 0.812345678901,
        "escalation_type": "privacy",
        "resolution": "allow",
        "miner_uid": "miner-1",
        "validator_grade": 0.92004,
        "decision_at": 1_700_000_000.125,
        "tags": (("client", "sdk"), ("region", "ca")),
    }
    values.update(changes)
    return AuditLogEntry(**values)


def _proof(proof_id: str = "proof-1") -> ProofEvidence:
    return ProofEvidence(
        proof_id=proof_id,
        root_hash=_digest(f"root:{proof_id}"),
        content_hash=_digest(f"content:{proof_id}"),
        vote_hashes=(_digest(f"vote:{proof_id}"),),
        constitutional_hash=CONST_HASH,
        captured_at=1_700_000_000.25,
    )


def _flushed_batch() -> tuple[
    ArweaveAuditLogger, InMemoryArweaveClient, Any, dict[str, Any]
]:
    client = InMemoryArweaveClient()
    logger = ArweaveAuditLogger(CONST_HASH, client)
    logger.add_entry(_entry("entry-1"))
    logger.add_entry(_entry("entry-2"))
    receipt = logger.flush()
    assert receipt is not None
    payload = json.loads(client.fetch(receipt.arweave_tx_id))
    return logger, client, receipt, payload


def test_leaf_digest_distinguishes_ambiguous_and_omitted_fields() -> None:
    base = _entry("entry-1", escalation_type="privacy:allow", resolution="deny")
    delimiter_variant = replace(base, escalation_type="privacy", resolution="allow:deny")
    float_variant = replace(base, validator_grade=0.9200001)
    tags_variant = replace(base, tags=(("client", "other"),))

    assert base.leaf_hash() != delimiter_variant.leaf_hash()
    assert base.leaf_hash() != float_variant.leaf_hash()
    assert base.leaf_hash() != tags_variant.leaf_hash()


def test_rejects_noncanonical_nan_with_null_roundtrip_control() -> None:
    left = _entry(
        "entry-1",
        tags=(("z", "last"), ("a", "first")),
        validator_grade=float("nan"),
    )
    right = replace(left, tags=(("a", "first"), ("z", "last")))

    assert left.leaf_hash() == right.leaf_hash()
    encoded = left.to_dict()
    assert encoded["validator_grade"] is None
    restored = AuditLogEntry.from_dict(encoded)
    assert math.isnan(restored.validator_grade)
    assert restored.leaf_hash() == left.leaf_hash()

    logger, client, receipt, payload = _flushed_batch()
    raw = json.dumps(payload).replace('"validator_grade": 0.92004', '"validator_grade": NaN')
    tx_id = client.upload(raw.encode())
    with pytest.raises(ValueError, match="batch"):
        logger.fetch_batch(replace(receipt, arweave_tx_id=tx_id))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("impact_score", float("nan")),
        ("impact_score", float("inf")),
        ("validator_grade", float("inf")),
        ("decision_at", float("-inf")),
    ],
)
def test_rejects_non_finite_authenticated_values(field: str, value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        _entry("entry-1", **{field: value})


def test_rejects_duplicate_tag_keys() -> None:
    with pytest.raises(ValueError, match="duplicate tag"):
        _entry("entry-1", tags=(("client", "one"), ("client", "two")))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("entry_id", 1),
        ("case_id", object()),
        ("constitutional_hash", b"hash"),
        ("decision_type", "escalated"),
        ("compliance_passed", 1),
        ("tags", [["client", "sdk"]]),
    ],
)
def test_rejects_non_plain_audit_entry_fields(field: str, value: object) -> None:
    with pytest.raises(TypeError):
        _entry("entry-1", **{field: value})


def test_rejects_spoofed_audit_entries() -> None:
    class SpoofedEntry(AuditLogEntry):
        def leaf_hash(self) -> str:
            return _digest("spoofed")

    entry = _entry("entry-1")
    spoofed = SpoofedEntry(
        entry_id=entry.entry_id,
        case_id=entry.case_id,
        constitutional_hash=entry.constitutional_hash,
        decision_type=entry.decision_type,
        compliance_passed=entry.compliance_passed,
        impact_score=entry.impact_score,
        escalation_type=entry.escalation_type,
        resolution=entry.resolution,
        miner_uid=entry.miner_uid,
        validator_grade=entry.validator_grade,
        decision_at=entry.decision_at,
        tags=entry.tags,
    )

    with pytest.raises(TypeError, match="AuditLogEntry"):
        AuditBatch("batch-1", CONST_HASH, [spoofed])

    logger = ArweaveAuditLogger(CONST_HASH, InMemoryArweaveClient())
    with pytest.raises(TypeError, match="AuditLogEntry"):
        logger.add_entry(spoofed)


def test_merkle_root_commits_leaf_count_and_node_domains() -> None:
    leaves = [_digest("a"), _digest("b"), _digest("c")]
    assert _compute_merkle_root(leaves) != _compute_merkle_root([*leaves, leaves[-1]])

    leaf = leaves[0]
    leaf_node = hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).digest()
    expected_single = hashlib.sha256(b"\x02" + (1).to_bytes(8, "big") + leaf_node).hexdigest()
    assert _compute_merkle_root([leaf]) == expected_single

    right_node = hashlib.sha256(b"\x00" + bytes.fromhex(leaves[1])).digest()
    tree_root = hashlib.sha256(b"\x01" + leaf_node + right_node).digest()
    expected_pair = hashlib.sha256(b"\x02" + (2).to_bytes(8, "big") + tree_root).hexdigest()
    assert _compute_merkle_root(leaves[:2]) == expected_pair


@pytest.mark.parametrize("leaf_count", [3, 4, 5])
def test_rejects_truncated_merkle_paths_with_valid_control(leaf_count: int) -> None:
    leaves = [_digest(f"leaf-{index}") for index in range(leaf_count)]
    root = _compute_merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        path = _merkle_path_for_index(leaves, index)
        assert verify_merkle_path(
            leaf,
            path,
            root,
            leaf_count=leaf_count,
            leaf_index=index,
        )
        if path:
            assert not verify_merkle_path(
                leaf,
                path[:-1],
                root,
                leaf_count=leaf_count,
                leaf_index=index,
            )


@pytest.mark.parametrize(
    ("path", "leaf_count", "leaf_index"),
    [
        ([(_digest("b"), "sideways")], 2, 0),
        ([], 2, 0),
        ([(_digest("b"), "right"), (_digest("extra"), "left")], 2, 0),
        ([("", "promote")], 2, 0),
        ([(_digest("not-empty"), "promote")], 1, 0),
        ([(_digest("b")[:-1], "right")], 2, 0),
        ([(_digest("b"), "right")], True, 0),
        ([(_digest("b"), "right")], 2, True),
        ([(_digest("b"), "right")], 2, 2),
    ],
)
def test_rejects_malformed_merkle_paths(
    path: list[tuple[str, str]], leaf_count: object, leaf_index: object
) -> None:
    assert not verify_merkle_path(
        _digest("a"),
        path,
        _compute_merkle_root([_digest("a"), _digest("b")]),
        leaf_count=leaf_count,  # type: ignore[arg-type]
        leaf_index=leaf_index,  # type: ignore[arg-type]
    )


def test_rejects_spoofed_merkle_path_containers_and_steps() -> None:
    class SpoofedPath(list[tuple[str, str]]):
        pass

    class SpoofedDirection:
        def __eq__(self, other: object) -> bool:
            return other == "right"

    leaves = [_digest("a"), _digest("b")]
    root = _compute_merkle_root(leaves)
    valid_path = _merkle_path_for_index(leaves, 0)
    assert verify_merkle_path(
        leaves[0], valid_path, root, leaf_count=2, leaf_index=0
    )
    assert not verify_merkle_path(
        leaves[0], SpoofedPath(valid_path), root, leaf_count=2, leaf_index=0
    )
    assert not verify_merkle_path(
        leaves[0],
        [(valid_path[0][0], SpoofedDirection())],  # type: ignore[list-item]
        root,
        leaf_count=2,
        leaf_index=0,
    )


def test_rejects_unpaired_batch_identifiers() -> None:
    leaf = _digest("leaf")
    root = _compute_merkle_root([leaf])
    assert not verify_merkle_path(
        leaf,
        [],
        root,
        leaf_count=1,
        leaf_index=0,
        batch_id="batch-1",
    )


def test_rejects_spoofed_batch_identifier_comparisons() -> None:
    class AlwaysEqual:
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

    leaf = _digest("leaf")
    root = _compute_merkle_root([leaf])
    assert not verify_merkle_path(
        leaf,
        [],
        root,
        leaf_count=1,
        leaf_index=0,
        batch_id=AlwaysEqual(),  # type: ignore[arg-type]
        expected_batch_id="different",
    )


def test_audit_batch_rejects_duplicate_ids_and_detaches_cached_state(monkeypatch: Any) -> None:
    first = _entry("entry-1")
    with pytest.raises(ValueError, match="duplicate entry_id"):
        AuditBatch("batch-1", CONST_HASH, [first, replace(first)])

    calls = 0
    original = AuditLogEntry.leaf_hash

    def counted(entry: AuditLogEntry) -> str:
        nonlocal calls
        calls += 1
        return original(entry)

    monkeypatch.setattr(AuditLogEntry, "leaf_hash", counted)
    source = [_entry("entry-1"), _entry("entry-2"), _entry("entry-3")]
    batch = AuditBatch("batch-1", CONST_HASH, source)
    original_root = batch.batch_root
    assert calls == 3

    source.append(_entry("entry-4"))
    exposed_entries = batch.entries
    exposed_leaves = batch.leaf_hashes
    exposed_entries.clear()
    exposed_leaves.clear()
    batch.merkle_path_for("entry-1")
    batch.merkle_path_for("entry-3")

    assert calls == 3
    assert batch.entry_count == 3
    assert batch.batch_root == original_root
    assert len(batch.entries) == len(batch.leaf_hashes) == 3


def test_rejects_mutation_of_batch_metadata_and_cached_indexes() -> None:
    batch = AuditBatch("batch-1", CONST_HASH, [_entry("entry-1")])

    with pytest.raises(AttributeError):
        batch.batch_id = "other"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        batch.batch_root = _digest("other")  # type: ignore[misc]
    with pytest.raises(TypeError):
        batch._entry_index["other"] = 0  # type: ignore[index]
    with pytest.raises(TypeError):
        batch._entry_by_id["other"] = _entry("other")  # type: ignore[index]
    replacements = {
        "_batch_root": _digest("other"),
        "_entry_count": 0,
        "_entries": (),
        "_leaf_hashes": (),
        "_entry_index": MappingProxyType({}),
        "_entry_by_id": MappingProxyType({}),
        "_merkle_layers": ((),),
    }
    for attribute, replacement in replacements.items():
        with pytest.raises(AttributeError):
            setattr(batch, attribute, replacement)


def test_verify_entry_requires_pinned_receipt_values() -> None:
    entry = _entry("entry-1")
    batch = AuditBatch("batch-1", CONST_HASH, [entry])

    assert batch.verify_entry(
        entry,
        expected_root=batch.batch_root,
        expected_batch_id=batch.batch_id,
    )
    assert not batch.verify_entry(
        entry,
        expected_root=_digest("wrong-root"),
        expected_batch_id=batch.batch_id,
    )
    assert not batch.verify_entry(
        entry,
        expected_root=batch.batch_root,
        expected_batch_id="wrong-batch",
    )


def test_verify_entry_rejects_spoofed_entry() -> None:
    class SpoofedEntry(AuditLogEntry):
        def leaf_hash(self) -> str:
            return _entry("entry-1").leaf_hash()

    genuine = _entry("entry-1")
    batch = AuditBatch("batch-1", CONST_HASH, [genuine])
    spoofed = SpoofedEntry(
        entry_id=genuine.entry_id,
        case_id=genuine.case_id,
        constitutional_hash=genuine.constitutional_hash,
        decision_type=genuine.decision_type,
        compliance_passed=genuine.compliance_passed,
        impact_score=genuine.impact_score,
        escalation_type=genuine.escalation_type,
        resolution=genuine.resolution,
        miner_uid=genuine.miner_uid,
        validator_grade=genuine.validator_grade,
        decision_at=genuine.decision_at,
        tags=genuine.tags,
    )

    assert not batch.verify_entry(
        spoofed,
        expected_root=batch.batch_root,
        expected_batch_id=batch.batch_id,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("batch_root", _digest("wrong-root")),
        ("batch_id", "wrong-batch"),
        ("entry_count", 99),
        ("constitutional_hash", "wrong-constitution"),
    ],
)
def test_fetch_batch_rejects_mismatched_receipt(field: str, replacement: object) -> None:
    logger, _client, receipt, _payload = _flushed_batch()
    mismatched = replace(receipt, **{field: replacement})
    with pytest.raises(ValueError, match="receipt"):
        logger.fetch_batch(mismatched)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_id", object()),
        ("batch_id", object()),
        ("batch_root", "é" * 64),
        ("arweave_tx_id", object()),
        ("constitutional_hash", object()),
        ("created_at", float("nan")),
        ("block_height", True),
    ],
)
def test_fetch_batch_rejects_malformed_receipt_scalars(
    field: str, replacement: object
) -> None:
    logger, _client, receipt, _payload = _flushed_batch()
    malformed = replace(receipt, **{field: replacement})
    with pytest.raises((TypeError, ValueError), match="receipt"):
        logger.fetch_batch(malformed)


def test_fetch_batch_rejects_boolean_receipt_count_for_one_entry() -> None:
    client = InMemoryArweaveClient()
    logger = ArweaveAuditLogger(CONST_HASH, client)
    logger.add_entry(_entry("entry-1"))
    receipt = logger.flush()
    assert receipt is not None and receipt.entry_count == 1

    with pytest.raises(TypeError, match="receipt"):
        logger.fetch_batch(replace(receipt, entry_count=True))


def test_fetch_batch_rejects_spoofed_receipt_comparisons() -> None:
    class AlwaysEqual:
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

    logger, _client, receipt, _payload = _flushed_batch()
    for field in ("batch_id", "batch_root", "constitutional_hash"):
        malformed = replace(receipt, **{field: AlwaysEqual()})
        with pytest.raises(TypeError, match="receipt"):
            logger.fetch_batch(malformed)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("batch_root", _digest("wrong-root")),
        ("batch_id", "wrong-batch"),
        ("entry_count", 99),
        ("constitutional_hash", "wrong-constitution"),
        ("leaf_hashes", [_digest("wrong-leaf")]),
        ("leaf_version", 1),
        ("merkle_version", 1),
    ],
)
def test_fetch_batch_rejects_mismatched_serialized_metadata(
    field: str, replacement: object
) -> None:
    logger, client, receipt, payload = _flushed_batch()
    payload[field] = replacement
    tx_id = client.upload(json.dumps(payload).encode())
    with pytest.raises(ValueError, match="batch"):
        logger.fetch_batch(replace(receipt, arweave_tx_id=tx_id))


def test_fetch_batch_rejects_duplicate_serialized_metadata() -> None:
    logger, client, receipt, payload = _flushed_batch()
    raw = json.dumps(payload)
    duplicate = raw.replace(
        '"batch_id": "' + payload["batch_id"] + '"',
        '"batch_id": "' + payload["batch_id"] + '", "batch_id": "other"',
        1,
    )
    tx_id = client.upload(duplicate.encode())
    with pytest.raises(ValueError, match="batch"):
        logger.fetch_batch(replace(receipt, arweave_tx_id=tx_id))


def test_rejects_missing_serialized_versions_with_current_version_control() -> None:
    payload = AuditBatch("batch-1", CONST_HASH, [_entry("entry-1")]).to_dict()
    assert payload["leaf_version"] == 2
    assert payload["merkle_version"] == 2
    for field in ("leaf_version", "merkle_version"):
        malformed = dict(payload)
        malformed.pop(field)
        with pytest.raises(ValueError, match="version"):
            AuditBatch.from_dict(malformed)


@pytest.mark.parametrize("field", ["leaf_version", "merkle_version"])
@pytest.mark.parametrize("replacement", [2.0, True, "2", object()])
def test_rejects_malformed_serialized_versions(
    field: str, replacement: object
) -> None:
    payload = AuditBatch("batch-1", CONST_HASH, [_entry("entry-1")]).to_dict()
    payload[field] = replacement
    with pytest.raises(ValueError, match="version"):
        AuditBatch.from_dict(payload)


def test_anchor_record_rejects_inconsistent_or_malformed_metadata() -> None:
    proof = _proof()
    leaf = proof.membership_leaf()
    valid = AnchorRecord(
        anchor_id="anchor-1",
        batch_root=_compute_anchor_root([leaf]),
        constitutional_hash=CONST_HASH,
        proof_count=1,
        block_height=1,
        submitted_at=1_700_000_001.0,
        proof_ids=(proof.proof_id,),
        leaf_hashes=(leaf,),
    )
    pin = valid.batch_root
    assert valid.verify_membership(proof, expected_root=pin)
    assert not replace(valid, batch_root=_digest("wrong-root")).verify_membership(proof, expected_root=pin)
    assert not replace(valid, proof_count=2).verify_membership(proof, expected_root=pin)
    assert not replace(valid, leaf_hashes=("not-a-digest",)).verify_membership(proof, expected_root=pin)
    assert not replace(valid, proof_ids=None).verify_membership(proof, expected_root=pin)  # type: ignore[arg-type]
    assert not replace(valid, leaf_hashes=None).verify_membership(proof, expected_root=pin)  # type: ignore[arg-type]
    assert not replace(valid, constitutional_hash="wrong").verify_membership(proof, expected_root=pin)
    assert not replace(valid, proof_ids=("other-proof",)).verify_membership(proof, expected_root=pin)
    assert not replace(valid, batch_root="é" * 64).verify_membership(proof, expected_root=pin)
    assert not valid.verify_membership(replace(proof, proof_id=1), expected_root=pin)  # type: ignore[arg-type]
    assert not valid.verify_membership(replace(proof, vote_hashes=None), expected_root=pin)  # type: ignore[arg-type]


def test_anchor_rejects_spoofed_proof_objects() -> None:
    class SpoofedProof(ProofEvidence):
        def membership_leaf(self) -> str:
            return _proof().membership_leaf()

    genuine = _proof()
    spoofed = SpoofedProof(
        proof_id=genuine.proof_id,
        root_hash=genuine.root_hash,
        content_hash=genuine.content_hash,
        vote_hashes=genuine.vote_hashes,
        constitutional_hash=genuine.constitutional_hash,
        captured_at=genuine.captured_at,
    )
    record = AnchorRecord(
        anchor_id="anchor-1",
        batch_root=_compute_anchor_root([genuine.membership_leaf()]),
        constitutional_hash=CONST_HASH,
        proof_count=1,
        block_height=1,
        submitted_at=1_700_000_001.0,
        proof_ids=(genuine.proof_id,),
        leaf_hashes=(genuine.membership_leaf(),),
    )

    assert not record.verify_membership(spoofed, expected_root=record.batch_root)
    with pytest.raises(TypeError, match="ProofEvidence"):
        ChainAnchor(CONST_HASH).add_proof(spoofed)


def test_rejects_spoofed_receipt_objects_with_shared_protocol_control() -> None:
    class SpoofedReceipt(AuditLogReceipt):
        pass

    logger, _client, receipt, _payload = _flushed_batch()
    spoofed = SpoofedReceipt(
        receipt_id=receipt.receipt_id,
        batch_id=receipt.batch_id,
        batch_root=receipt.batch_root,
        arweave_tx_id=receipt.arweave_tx_id,
        entry_count=receipt.entry_count,
        constitutional_hash=receipt.constitutional_hash,
        created_at=receipt.created_at,
        block_height=receipt.block_height,
    )

    with pytest.raises(TypeError, match="AuditLogReceipt"):
        logger.fetch_batch(spoofed)
    assert AuditChainSubmitter is ChainSubmitter
