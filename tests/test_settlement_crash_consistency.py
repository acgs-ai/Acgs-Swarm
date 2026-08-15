"""Process-boundary crash tests for receipt/settlement lifecycle."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from constitutional_swarm.governance_receipts import (
    GovernanceReceiptBundle,
    ReceiptPayload,
    RoleIdentity,
    ValidatorVote,
    build_receipt,
)
from constitutional_swarm.settlement_evidence import (
    list_orphan_receipts,
    reconcile_orphan_receipts,
    verify_committed_settlement_receipt,
    write_receipt_atomic,
)
from constitutional_swarm.settlement_store import JSONLSettlementStore, SettlementRecord, SQLiteSettlementStore

_DIGEST_A = "11" * 32


def _roles() -> dict[str, RoleIdentity]:
    return {
        "constitution_author": RoleIdentity(
            role="constitution_author", identity_id="c", display_name="c"
        ),
        "executor": RoleIdentity(role="executor", identity_id="e", display_name="e"),
        "validator": RoleIdentity(role="validator", identity_id="v", display_name="v"),
        "auditor": RoleIdentity(role="auditor", identity_id="a", display_name="a"),
    }


def _bundle(assignment_id: str) -> GovernanceReceiptBundle:
    payload = ReceiptPayload(
        receipt_id=f"mesh-{assignment_id}",
        action=assignment_id,
        policy_version="local-constitution",
        policy_hash="abc123",
        roles=_roles(),
        evidence_hashes={"settlement": "00" * 32, "content": "ff" * 32},
        decision="approved",
        validator_votes=[
            ValidatorVote(validator_id="v", decision="approve", rationale="ok")
        ],
        rejected_alternative="skip",
        metadata={"assignment_id": assignment_id, "claim": "local-dsse-shaped-receipt"},
    )
    return GovernanceReceiptBundle(receipts=[build_receipt(payload=payload)])


def _worker() -> None:
    mode = os.environ["ACGS_CRASH_MODE"]
    store_path = Path(os.environ["ACGS_STORE_PATH"])
    assignment_id = os.environ["ACGS_ASSIGNMENT_ID"]
    backend = os.environ.get("ACGS_STORE_BACKEND", "jsonl")
    store = (
        SQLiteSettlementStore(store_path)
        if backend == "sqlite"
        else JSONLSettlementStore(store_path)
    )
    from constitutional_swarm.settlement_evidence import receipt_path_for

    path = receipt_path_for(store, assignment_id)
    write_receipt_atomic(path, _bundle(assignment_id))
    if mode == "after-receipt":
        os._exit(17)
    store.append(
        SettlementRecord(
            assignment={"assignment_id": assignment_id, "producer_id": "e"},
            result={"accepted": True},
            constitutional_hash="abc123",
            receipt_digest=_bundle(assignment_id).receipts[0].payload_digest,
        )
    )
    if mode == "after-settlement":
        os._exit(0)
    os._exit(0)


if __name__ == "__main__":
    _worker()


def _run_worker(tmp_path: Path, *, mode: str, backend: str, assignment_id: str) -> int:
    store_path = tmp_path / ("s.db" if backend == "sqlite" else "s.jsonl")
    env = os.environ.copy()
    env.update(
        {
            "ACGS_CRASH_MODE": mode,
            "ACGS_STORE_PATH": str(store_path),
            "ACGS_STORE_BACKEND": backend,
            "ACGS_ASSIGNMENT_ID": assignment_id,
            "PYTHONPATH": "src:.",
        }
    )
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        env=env,
        check=False,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    return completed.returncode


def test_orphan_receipt_after_crash_is_not_completed_evidence(tmp_path) -> None:
    assignment_id = "crash-1"
    code = _run_worker(tmp_path, mode="after-receipt", backend="jsonl", assignment_id=assignment_id)
    assert code == 17
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    verdict = verify_committed_settlement_receipt(store, assignment_id)
    assert verdict.valid is False
    assert any(issue.code in {"settlement_missing", "receipt_unbound"} for issue in verdict.issues)
    orphans = list_orphan_receipts(store)
    assert orphans
    removed = reconcile_orphan_receipts(store)
    assert removed
    assert list_orphan_receipts(store) == []


def test_committed_receipt_survives_reconcile_after_clean_exit(tmp_path) -> None:
    assignment_id = "ok-1"
    code = _run_worker(tmp_path, mode="after-settlement", backend="sqlite", assignment_id=assignment_id)
    assert code == 0
    store = SQLiteSettlementStore(tmp_path / "s.db")
    loaded = store.get(assignment_id)
    assert loaded is not None
    assert loaded.receipt_digest
    assert list_orphan_receipts(store) == []
    assert reconcile_orphan_receipts(store) == []
    from constitutional_swarm.settlement_evidence import receipt_path_for

    assert receipt_path_for(store, assignment_id).exists()


def test_reconcile_does_not_delete_referenced_receipt(tmp_path) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    bundle = _bundle("keep")
    digest = bundle.receipts[0].payload_digest
    from constitutional_swarm.settlement_evidence import receipt_path_for, write_receipt_atomic

    write_receipt_atomic(receipt_path_for(store, "keep"), bundle)
    store.append(
        SettlementRecord(
            assignment={"assignment_id": "keep", "producer_id": "e"},
            result={"accepted": True},
            constitutional_hash="abc123",
            receipt_digest=digest,
        )
    )
    write_receipt_atomic(receipt_path_for(store, "orphan"), _bundle("orphan"))
    removed = reconcile_orphan_receipts(store)
    assert any("orphan" in item for item in removed)
    assert receipt_path_for(store, "keep").exists()
    assert not receipt_path_for(store, "orphan").exists()
