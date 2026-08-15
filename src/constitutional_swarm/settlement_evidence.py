"""Lifecycle helpers for mesh settlements bound to v0.1 receipts.

Receipt identity
----------------
``SettlementRecord.receipt_digest`` is the receipt **payload digest**
(canonical statement identity). It is not the signed-envelope hash
(``receipt_hash``). The canonical settlement digest is computed by
``protocol.encode_settlement_record_v1`` and **excludes** ``receipt_digest``,
so the pointer cannot appear inside its own pre-image.

A receipt file is **authoritative completed evidence** only when a committed
settlement row references its payload digest. An on-disk receipt without that
pointer is an orphan and must not be reported as completed evidence.

This module does not introduce a fourth evidence format. It composes the
existing ``acgs.local.intoto-dsse-shaped.v0.1`` profile.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

from constitutional_swarm.governance_receipts import (
    PROFILE_VERSION,
    GovernanceReceiptBundle,
    ReceiptIssue,
    VerificationVerdict,
    bundle_from_json,
    bundle_to_json,
    settlement_canonical_digest,
    verify_bundle,
)
from constitutional_swarm.settlement_store import SettlementRecord, normalize_receipt_digest

_fcntl: ModuleType | None
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None

RECEIPT_SIGNER_KEY_ID = "settlement-receipt"
RECEIPT_PAYLOAD_TYPE = "application/vnd.acgs.governance-receipt.v0.1+json"
RECEIPT_IDENTITY_KIND = "payload_digest"
_RECEIPT_SUFFIX = ".receipt.json"
_RECEIPT_NAME = re.compile(r"^(?P<stem>.+)\.(?P<assignment_id>.+)\.receipt\.json$")


def store_filesystem_path(store: Any) -> Path | None:
    """Return the store's durable path, or None for in-memory adapters."""
    describe = getattr(store, "describe", None)
    if describe is None:
        return None
    raw = describe().get("path")
    if not raw:
        return None
    return Path(str(raw))


def store_path(store: Any) -> Path:
    path = store_filesystem_path(store)
    if path is None:
        raise ValueError("settlement store has no filesystem path")
    return path


def receipt_path_for(store: Any, assignment_id: str) -> Path:
    path = store_path(store)
    return path.with_name(f"{path.name}.{assignment_id}.receipt.json")


def parse_receipt_assignment_id(
    path: Path,
    *,
    store_name: str | None = None,
) -> str | None:
    """Extract the assignment id using the store filename as the prefix.

    Receipts are ``{store_name}.{assignment_id}.receipt.json``. Using the
    store prefix (not ``[^.]+``) keeps dotted assignment ids intact.
    """
    name = path.name
    if not name.endswith(_RECEIPT_SUFFIX):
        return None
    body = name[: -len(_RECEIPT_SUFFIX)]
    if store_name:
        prefix = f"{store_name}."
        if not body.startswith(prefix):
            return None
        assignment_id = body[len(prefix) :]
        return assignment_id or None
    match = _RECEIPT_NAME.match(name)
    if match is None:
        return None
    return match.group("assignment_id") or None


@contextmanager
def evidence_lock(store: Any):
    """Exclusive lock shared by settlement writers and orphan reconciliation.

    Uses a dedicated lock file so it never nests with JSONLSettlementStore's
    per-append advisory lock (non-recursive flock would deadlock).
    """
    path = store_filesystem_path(store)
    if path is None:
        yield
        return
    lock_path = path.with_name(path.name + ".evidence.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX)
        yield
    finally:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
        os.close(fd)


def write_receipt_atomic(path: Path, bundle: GovernanceReceiptBundle) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    payload = bundle_to_json(bundle)
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def committed_receipt_index(store: Any) -> dict[str, str]:
    """assignment_id -> payload digest for committed settlements with a pointer."""
    index: dict[str, str] = {}
    for record in store.load_all():
        assignment_id = str(record.assignment.get("assignment_id", ""))
        digest = normalize_receipt_digest(record.receipt_digest)
        if assignment_id and digest:
            index[assignment_id] = digest
    return index


def list_orphan_receipts(store: Any) -> list[Path]:
    referenced = committed_receipt_index(store)
    orphans: list[Path] = []
    store_file = store_path(store)
    root = store_file.parent
    store_name = store_file.name
    prefix = store_name + "."
    if not root.exists():
        return orphans
    for path in root.glob(f"{prefix}*.receipt.json"):
        assignment_id = parse_receipt_assignment_id(path, store_name=store_name)
        if assignment_id is None:
            orphans.append(path)
            continue
        if assignment_id not in referenced:
            orphans.append(path)
    return orphans


def reconcile_orphan_receipts(store: Any) -> list[str]:
    """Delete unreferenced receipt files. Never unlink a referenced assignment."""
    removed: list[str] = []
    with evidence_lock(store):
        referenced = committed_receipt_index(store)
        store_name = store_path(store).name
        for path in list_orphan_receipts(store):
            assignment_id = parse_receipt_assignment_id(path, store_name=store_name)
            if assignment_id is not None and assignment_id in referenced:
                continue
            path.unlink(missing_ok=True)
            removed.append(str(path))
    return removed


def _fail(
    code: str,
    message: str,
    receipt_id: str | None = None,
) -> VerificationVerdict:
    return VerificationVerdict(
        valid=False,
        mode="fail_closed",
        profile_version=PROFILE_VERSION,
        receipt_count=0,
        signature_status="unverifiable",
        issues=[ReceiptIssue(code=code, message=message, receipt_id=receipt_id)],
        receipt_hashes=[],
    )


def verify_committed_settlement_receipt(
    store: Any,
    assignment_id: str,
    *,
    trusted_signers: Mapping[str, str] | None = None,
) -> VerificationVerdict:
    """Verify evidence starting from a committed settlement pointer.

    An orphan receipt (file present, no settlement pointer) is not completed
    evidence and fails closed.
    """
    getter = getattr(store, "get", None)
    record = getter(assignment_id) if getter is not None else None
    if record is None:
        for item in store.load_all():
            if str(item.assignment.get("assignment_id", "")) == assignment_id:
                record = item
                break
    if record is None:
        return _fail("settlement_missing", f"no committed settlement {assignment_id}")
    digest = normalize_receipt_digest(record.receipt_digest)
    if digest is None:
        return _fail(
            "receipt_unbound",
            "settlement has no receipt_digest; file-only receipts are orphans",
        )
    path = receipt_path_for(store, assignment_id)
    if not path.exists():
        return _fail("receipt_missing", f"referenced receipt file absent: {path}")
    try:
        bundle = bundle_from_json(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — fail closed on any malformed artifact
        return _fail("receipt_malformed", f"receipt could not be parsed: {exc}")
    return bind_and_verify(record, bundle, trusted_signers=trusted_signers)


def bind_and_verify(
    record: SettlementRecord,
    bundle: GovernanceReceiptBundle,
    *,
    trusted_signers: Mapping[str, str] | None = None,
) -> VerificationVerdict:
    """Check settlement pointer + existing v0.1 bundle verification together."""
    issues: list[ReceiptIssue] = []
    digest = normalize_receipt_digest(record.receipt_digest)
    if len(bundle.receipts) != 1:
        return VerificationVerdict(
            valid=False,
            mode="fail_closed",
            profile_version=PROFILE_VERSION,
            receipt_count=len(bundle.receipts),
            signature_status="unverifiable",
            issues=[
                ReceiptIssue(
                    code="receipt_count_mismatch",
                    message="settlement evidence must bind exactly one receipt",
                )
            ],
            receipt_hashes=[],
        )
    receipt = bundle.receipts[0]
    receipt_id = receipt.payload.receipt_id
    assignment_id = str(record.assignment.get("assignment_id", ""))
    if digest is None:
        issues.append(
            ReceiptIssue(
                code="receipt_unbound",
                message="settlement pointer is empty",
                receipt_id=receipt_id,
            )
        )
    elif receipt.payload_digest != digest:
        issues.append(
            ReceiptIssue(
                code="receipt_pointer_mismatch",
                message="settlement.receipt_digest is not the receipt payload digest",
                receipt_id=receipt_id,
            )
        )
    if receipt.payload.metadata.get("assignment_id") != assignment_id:
        issues.append(
            ReceiptIssue(
                code="assignment_mismatch",
                message="receipt assignment_id does not match settlement",
                receipt_id=receipt_id,
            )
        )
    expected_action = str(record.assignment.get("artifact_id", assignment_id))
    if receipt.payload.action != expected_action:
        issues.append(
            ReceiptIssue(
                code="action_mismatch",
                message="receipt action does not match settlement artifact_id",
                receipt_id=receipt_id,
            )
        )
    expected_decision = "approved" if bool(record.result.get("accepted", False)) else "denied"
    if receipt.payload.decision != expected_decision:
        issues.append(
            ReceiptIssue(
                code="decision_mismatch",
                message="receipt decision does not match settlement accepted",
                receipt_id=receipt_id,
            )
        )
    expected_policy = str(record.constitutional_hash)
    if receipt.payload.policy_hash != expected_policy:
        issues.append(
            ReceiptIssue(
                code="policy_hash_mismatch",
                message="receipt policy_hash does not match settlement constitutional_hash",
                receipt_id=receipt_id,
            )
        )
    expected_content = str(record.assignment.get("content_hash", "none"))
    if receipt.payload.evidence_hashes.get("content") != expected_content:
        issues.append(
            ReceiptIssue(
                code="content_hash_mismatch",
                message="receipt content hash does not match settlement content_hash",
                receipt_id=receipt_id,
            )
        )
    expected_settlement = settlement_canonical_digest(record)
    actual_settlement = receipt.payload.evidence_hashes.get("settlement")
    if actual_settlement != expected_settlement:
        issues.append(
            ReceiptIssue(
                code="settlement_digest_mismatch",
                message="receipt settlement digest does not match the loaded record",
                receipt_id=receipt_id,
            )
        )
    verifying_ids = {signature.key_id for signature in receipt.signatures}
    if RECEIPT_SIGNER_KEY_ID not in verifying_ids:
        issues.append(
            ReceiptIssue(
                code="receipt_signer_role",
                message="mesh evidence must be signed with key_id settlement-receipt",
                receipt_id=receipt_id,
            )
        )
    if receipt.payload_type != RECEIPT_PAYLOAD_TYPE:
        issues.append(
            ReceiptIssue(
                code="payload_type_mismatch",
                message=f"unexpected payload type {receipt.payload_type}",
                receipt_id=receipt_id,
            )
        )
    if receipt.profile_version != PROFILE_VERSION:
        issues.append(
            ReceiptIssue(
                code="profile_mismatch",
                message=f"unexpected profile {receipt.profile_version}",
                receipt_id=receipt_id,
            )
        )
    verdict = verify_bundle(bundle, trusted_signers=trusted_signers)
    combined = list(issues) + list(verdict.issues)
    valid = not issues and verdict.valid
    return VerificationVerdict(
        valid=valid,
        mode="fail_closed",
        profile_version=PROFILE_VERSION,
        receipt_count=verdict.receipt_count,
        signature_status=verdict.signature_status,
        issues=combined,
        receipt_hashes=verdict.receipt_hashes,
    )
