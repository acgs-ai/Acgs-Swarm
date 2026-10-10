"""Arweave Audit Log — Phase 2.3: permanent off-chain governance audit trail.

On-chain storage is too expensive for full audit logs. Arweave provides
permanent, per-byte storage. The architecture from Q&A §3C:

    Batch audit log entries
         ↓  compute Merkle root
    Upload batch JSON → Arweave (permanent, content-addressed)
         ↓  anchor batch_root
    Submit batch_root → Bittensor chain (tamper-evident, cheap)
         ↓
    Auditors verify: merkle_root matches chain anchor AND
                     entry content matches the Merkle path

This produces the "Selective On-Chain / Off-Chain Split" from roadmap §2.4:
  On-chain (small, immutable):   batch Merkle root + constitutional hash
  Off-chain (large, permanent):  full audit log entries + reasoning text

Privacy: Entries store decision outcomes (pass/fail, escalation type), not
decision content. Individual judgment text lives in Arweave only, not chain.

Design:
  • Pluggable ArweaveClient Protocol — InMemoryArweaveClient for tests
  • AuditLogEntry is frozen=True, slots=True (audit immutability guarantee)
  • AuditBatch computes Merkle paths on demand — auditors can verify single
    entries without fetching the entire batch
  • ChainSubmitter is the same Protocol as chain_anchor.py — no new interface

Roadmap:  08-subnet-implementation-roadmap.md § Phase 2 On-Chain + Privacy
Q&A §3C: docs/strategy/07-subnet-concept-qa-responses.md
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from collections.abc import Set as AbstractSet
from typing import Any, Protocol

from constitutional_swarm.strict_json import StrictJSONError, canonical_dumps, loads

from ._merkle import (
    MERKLE_VERSION,
    build_merkle_layers,
    compute_merkle_root,
    is_digest,
    merkle_path_for_index,
    merkle_root_from_layers,
    verify_merkle_path as _verify_merkle_path,
)
from ._staging import _StagedBatch
from .chain_anchor import ChainSubmitter


logger = logging.getLogger(__name__)

_AUDIT_LEAF_VERSION = 2
_AUDIT_LEAF_DOMAIN = "constitutional_swarm.audit_log_entry"
_MAX_BATCH_JSON_BYTES = 64 * 1024 * 1024

# Exact key sets emitted by to_dict(); from_dict() accepts nothing else.
_ENTRY_KEYS = frozenset(
    {
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
    }
)
_BATCH_KEYS = frozenset(
    {
        "batch_id",
        "leaf_version",
        "merkle_version",
        "batch_root",
        "constitutional_hash",
        "entry_count",
        "created_at",
        "entries",
        "leaf_hashes",
    }
)


def _key_preview(keys: AbstractSet[Any]) -> str:
    # Key names may be attacker-controlled: repr() escapes control characters,
    # and both the number of keys and each key's length are capped.
    shown = sorted(repr(key)[:32] for key in keys)[:5]
    return f"{len(keys)} ({', '.join(shown)}{', ...' if len(keys) > 5 else ''})"


def _require_exact_keys(d: dict[str, Any], keys: frozenset[str], kind: str) -> None:
    unknown = d.keys() - keys
    if unknown:
        raise ValueError(f"{kind} has unknown keys: {_key_preview(unknown)}")
    missing = keys - d.keys()
    if missing:
        raise ValueError(f"{kind} is missing keys: {_key_preview(missing)}")

# ---------------------------------------------------------------------------
# Decision type enum (from Q&A §2)
# ---------------------------------------------------------------------------


class AuditDecisionType(Enum):
    AUTO_PASS = "auto_pass"
    AUTO_REJECT = "auto_reject"  # constitutional violation, hard reject
    ESCALATED = "escalated"  # sent to human miners
    INFRA_ERROR = "infra_error"  # timeout, missing data, service failure
    PRECEDENT = "precedent"  # auto-resolved via PrecedentStore


# ---------------------------------------------------------------------------
# Audit log entry — immutable audit record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """Immutable record of one governance decision.

    Stores outcome metadata only — not judgment content (too large for
    on-chain storage, stored separately in Arweave under the batch).

    Fields:
      entry_id:          unique identifier for this log entry
      case_id:           governance case / escalation ID
      constitutional_hash: which constitution governed this decision
      decision_type:     outcome category (AUTO_PASS, ESCALATED, etc.)
      compliance_passed: True if the decision passed constitutional rules
      impact_score:      aggregate 7-vector score (0.0-1.0)
      escalation_type:   which dimension caused escalation (if any)
      resolution:        final disposition (e.g. "allow", "deny", "allow_with_conditions")
      miner_uid:         miner who handled escalation (empty if auto-resolved)
      validator_grade:   quality score from validators (0.0-1.0, NaN if auto)
      decision_at:       Unix timestamp of the decision
      tags:              extensible metadata (client, framework, domain…)
    """

    entry_id: str
    case_id: str
    constitutional_hash: str
    decision_type: AuditDecisionType
    compliance_passed: bool
    impact_score: float = 0.0
    escalation_type: str = ""
    resolution: str = ""
    miner_uid: str = ""
    validator_grade: float = float("nan")
    decision_at: float = field(default_factory=time.time)
    tags: tuple[tuple[str, str], ...] = ()  # frozen-compatible key-value pairs

    def __post_init__(self) -> None:
        for name in (
            "entry_id",
            "case_id",
            "constitutional_hash",
            "escalation_type",
            "resolution",
            "miner_uid",
        ):
            if type(getattr(self, name)) is not str:
                raise TypeError(f"{name} must be an exact string")
        if type(self.decision_type) is not AuditDecisionType:
            raise TypeError("decision_type must be an exact AuditDecisionType")
        if type(self.compliance_passed) is not bool:
            raise TypeError("compliance_passed must be an exact boolean")
        for name in ("impact_score", "decision_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a finite number")
            if not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
        if isinstance(self.validator_grade, bool) or not isinstance(
            self.validator_grade, (int, float)
        ):
            raise TypeError("validator_grade must be a finite number or NaN")
        if math.isinf(self.validator_grade):
            raise ValueError("validator_grade must be finite or NaN")

        seen_tags: set[str] = set()
        if type(self.tags) is not tuple:
            raise TypeError("tags must be a tuple of string pairs")
        for pair in self.tags:
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError("tags must contain exact two-item tuples")
            key, value = pair
            if type(key) is not str or type(value) is not str:
                raise TypeError("tag keys and values must be exact strings")
            if key in seen_tags:
                raise ValueError(f"duplicate tag key: {key!r}")
            seen_tags.add(key)

    def leaf_hash(self) -> str:
        """SHA-256 hash of the canonical entry representation.

        Used as the Merkle leaf for batch inclusion proofs.
        Deterministic: same entry always produces the same leaf hash.
        """
        payload = {
            "domain": _AUDIT_LEAF_DOMAIN,
            "version": _AUDIT_LEAF_VERSION,
            "entry": self.to_dict(),
        }
        return hashlib.sha256(canonical_dumps(payload).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "case_id": self.case_id,
            "constitutional_hash": self.constitutional_hash,
            "decision_type": self.decision_type.value,
            "compliance_passed": self.compliance_passed,
            "impact_score": self.impact_score,
            "escalation_type": self.escalation_type,
            "resolution": self.resolution,
            "miner_uid": self.miner_uid,
            "validator_grade": (None if math.isnan(self.validator_grade) else self.validator_grade),
            "decision_at": self.decision_at,
            "tags": dict(self.tags),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditLogEntry:
        if type(d) is not dict:
            raise TypeError("audit entry must be an exact dictionary")
        _require_exact_keys(d, _ENTRY_KEYS, "audit entry")
        tags = d["tags"]
        if type(tags) is not dict:
            raise TypeError("entry tags must be an exact dictionary")
        validator_grade = d["validator_grade"]
        if validator_grade is None:
            validator_grade = float("nan")
        return cls(
            entry_id=d["entry_id"],
            case_id=d["case_id"],
            constitutional_hash=d["constitutional_hash"],
            decision_type=AuditDecisionType(d["decision_type"]),
            compliance_passed=d["compliance_passed"],
            impact_score=d["impact_score"],
            escalation_type=d["escalation_type"],
            resolution=d["resolution"],
            miner_uid=d["miner_uid"],
            validator_grade=validator_grade,
            decision_at=d["decision_at"],
            tags=tuple(tags.items()),
        )


# ---------------------------------------------------------------------------
# Arweave client interface (pluggable)
# ---------------------------------------------------------------------------


class ArweaveClient(Protocol):
    """Protocol for uploading to and fetching from Arweave.

    Implement for a real Arweave node/gateway:

        import arweave  # pip install arweave-python-client
        class RealArweaveClient:
            def upload(self, data: bytes, tags: dict[str, str]) -> str:
                tx = arweave.Transaction(wallet, data=data)
                for k, v in tags.items():
                    tx.add_tag(k, v)
                tx.sign()
                tx.send()
                return tx.id
            def fetch(self, tx_id: str) -> bytes:
                return arweave.Transaction.fetch(tx_id).data
    """

    def upload(self, data: bytes, tags: dict[str, str]) -> str:
        """Upload data. Returns the Arweave transaction ID."""
        ...

    def fetch(self, tx_id: str) -> bytes:
        """Fetch data by transaction ID."""
        ...


class InMemoryArweaveClient:
    """In-memory stub — no network I/O, for tests.

    Stores uploads in a dict keyed by deterministic SHA-256 of the data.
    """

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._tags: dict[str, dict[str, str]] = {}

    def upload(self, data: bytes, tags: dict[str, str] | None = None) -> str:
        tx_id = "ar_" + hashlib.sha256(data).hexdigest()[:16]
        self._store[tx_id] = data
        self._tags[tx_id] = tags or {}
        return tx_id

    def fetch(self, tx_id: str) -> bytes:
        if tx_id not in self._store:
            raise KeyError(f"Arweave tx not found: {tx_id}")
        return self._store[tx_id]

    def get_tags(self, tx_id: str) -> dict[str, str]:
        return dict(self._tags.get(tx_id, {}))

    @property
    def transaction_count(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# ChainSubmitter interface (same protocol as chain_anchor.py — no new dep)
# ---------------------------------------------------------------------------


AuditChainSubmitter = ChainSubmitter


# ---------------------------------------------------------------------------
# Audit batch (produced by the logger at flush time)
# ---------------------------------------------------------------------------


class AuditBatch:
    """Finalized audit log batch, ready for Arweave upload + chain anchoring.

    Metadata and cached tree state are immutable after construction. Paths are
    derived from the cached layers for auditor verification.

    The batch_root is anchored on-chain via ChainSubmitter.
    The full batch JSON is stored on Arweave.
    """

    __slots__ = (
        "_batch_id",
        "_batch_root",
        "_constitutional_hash",
        "_created_at",
        "_entries",
        "_entry_by_id",
        "_entry_count",
        "_entry_index",
        "_frozen",
        "_leaf_hashes",
        "_merkle_layers",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("AuditBatch is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("AuditBatch is immutable")
        object.__delattr__(self, name)

    def __init__(
        self,
        batch_id: str,
        constitutional_hash: str,
        entries: list[AuditLogEntry],
        created_at: float | None = None,
    ) -> None:
        if type(batch_id) is not str:
            raise TypeError("batch_id must be an exact string")
        if type(constitutional_hash) is not str:
            raise TypeError("constitutional_hash must be an exact string")
        if type(entries) is not list:
            raise TypeError("entries must be an exact list")
        if created_at is not None:
            if isinstance(created_at, bool) or not isinstance(created_at, (int, float)):
                raise TypeError("created_at must be a finite number")
            if not math.isfinite(created_at):
                raise ValueError("created_at must be finite")
        if any(type(entry) is not AuditLogEntry for entry in entries):
            raise TypeError("entries must contain exact AuditLogEntry instances")
        detached_entries = tuple(entries)
        entry_ids = [entry.entry_id for entry in detached_entries]
        if len(set(entry_ids)) != len(entry_ids):
            raise ValueError("duplicate entry_id in audit batch")

        self._batch_id = batch_id
        self._constitutional_hash = constitutional_hash
        self._entries: tuple[AuditLogEntry, ...] = detached_entries
        self._entry_by_id = MappingProxyType(dict(zip(entry_ids, detached_entries, strict=True)))
        self._entry_index = MappingProxyType(
            {entry_id: index for index, entry_id in enumerate(entry_ids)}
        )
        self._leaf_hashes: tuple[str, ...] = tuple(entry.leaf_hash() for entry in detached_entries)
        self._merkle_layers = build_merkle_layers(self._leaf_hashes)
        self._batch_root = merkle_root_from_layers(self._merkle_layers, len(self._leaf_hashes))
        self._entry_count = len(self._entries)
        self._created_at = time.time() if created_at is None else created_at
        self._frozen = True

    @property
    def batch_id(self) -> str:
        return self._batch_id

    @property
    def constitutional_hash(self) -> str:
        return self._constitutional_hash

    @property
    def batch_root(self) -> str:
        return self._batch_root

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def created_at(self) -> float:
        return self._created_at

    @property
    def entries(self) -> list[AuditLogEntry]:
        return list(self._entries)

    @property
    def leaf_hashes(self) -> list[str]:
        return list(self._leaf_hashes)

    def find_entry(self, entry_id: str) -> AuditLogEntry | None:
        return self._entry_by_id.get(entry_id)

    def merkle_path_for(self, entry_id: str) -> list[tuple[str, str]]:
        """Return the Merkle path proving entry_id is in this batch.

        Each step is (sibling_hash, "left"|"right"|"promote").
        Raises KeyError if entry_id not found.

        Verification::

            entry = batch.find_entry(entry_id)
            path  = batch.merkle_path_for(entry_id)
            assert verify_merkle_path(
                entry.leaf_hash(),
                path,
                receipt.batch_root,
                leaf_count=receipt.entry_count,
                leaf_index=batch.entries.index(entry),
                batch_id=batch.batch_id,
                expected_batch_id=receipt.batch_id,
            )
        """
        try:
            index = self._entry_index[entry_id]
        except KeyError:
            raise KeyError(f"Entry not found in batch: {entry_id}") from None
        return list(merkle_path_for_index(self._merkle_layers, index))

    def verify_entry(
        self,
        entry: AuditLogEntry,
        *,
        expected_root: str,
        expected_batch_id: str,
    ) -> bool:
        """Verify an exact entry against caller-pinned receipt values."""
        if type(entry) is not AuditLogEntry:
            return False
        if type(expected_root) is not str or type(expected_batch_id) is not str:
            return False
        if expected_root != self.batch_root or expected_batch_id != self.batch_id:
            return False
        try:
            index = self._entry_index[entry.entry_id]
            path = self.merkle_path_for(entry.entry_id)
        except KeyError:
            return False
        return verify_merkle_path(
            entry.leaf_hash(),
            path,
            expected_root,
            leaf_count=self.entry_count,
            leaf_index=index,
            batch_id=self.batch_id,
            expected_batch_id=expected_batch_id,
        )

    def compliance_rate(self) -> float:
        if not self._entries:
            raise ValueError("compliance rate requires at least one entry")
        passed = sum(1 for e in self._entries if e.compliance_passed)
        return passed / len(self._entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "leaf_version": _AUDIT_LEAF_VERSION,
            "merkle_version": MERKLE_VERSION,
            "batch_root": self.batch_root,
            "constitutional_hash": self.constitutional_hash,
            "entry_count": self.entry_count,
            "created_at": self.created_at,
            "entries": [e.to_dict() for e in self._entries],
            "leaf_hashes": list(self._leaf_hashes),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditBatch:
        if type(d) is not dict:
            raise TypeError("audit batch must be an exact dictionary")
        if type(d.get("leaf_version")) is not int or d["leaf_version"] != _AUDIT_LEAF_VERSION:
            raise ValueError("audit batch has unsupported leaf version")
        if type(d.get("merkle_version")) is not int or d["merkle_version"] != MERKLE_VERSION:
            raise ValueError("audit batch has unsupported Merkle version")
        _require_exact_keys(d, _BATCH_KEYS, "audit batch")
        raw_entries = d["entries"]
        if type(raw_entries) is not list:
            raise ValueError("audit batch entries must be a list")
        entries = [AuditLogEntry.from_dict(e) for e in raw_entries]
        batch = cls(
            batch_id=d["batch_id"],
            constitutional_hash=d["constitutional_hash"],
            entries=entries,
            created_at=d["created_at"],
        )
        serialized_leaves = d["leaf_hashes"]
        if type(serialized_leaves) is not list or serialized_leaves != batch.leaf_hashes:
            raise ValueError("audit batch leaf hashes do not match entries")
        if type(d["entry_count"]) is not int or d["entry_count"] != batch.entry_count:
            raise ValueError("audit batch entry count does not match entries")
        if type(d["batch_root"]) is not str or d["batch_root"] != batch.batch_root:
            raise ValueError("audit batch root does not match entries")
        return batch


# ---------------------------------------------------------------------------
# Audit log receipt (immutable — returned to the caller after flush)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditLogReceipt:
    """Immutable receipt from a successful audit log flush.

    Contains everything an auditor needs to verify a specific entry:
      1. Fetch batch from Arweave using arweave_tx_id
      2. Verify batch_root matches on-chain anchor at block_height
      3. Retrieve entry from batch → compute leaf_hash
      4. Compute Merkle path → verify against batch_root

    block_height is None when no chain_submitter is configured.
    """

    receipt_id: str
    batch_id: str
    batch_root: str
    arweave_tx_id: str
    entry_count: int
    constitutional_hash: str
    created_at: float
    block_height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "batch_root": self.batch_root,
            "arweave_tx_id": self.arweave_tx_id,
            "entry_count": self.entry_count,
            "constitutional_hash": self.constitutional_hash,
            "block_height": self.block_height,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Arweave audit logger
# ---------------------------------------------------------------------------


class ArweaveAuditLogger:
    """Batches governance decisions, uploads to Arweave, anchors roots on-chain.

    Usage::

        arweave = InMemoryArweaveClient()
        submitter = InMemorySubmitter()   # from chain_anchor.py or any stub
        logger = ArweaveAuditLogger(
            constitutional_hash="608508a9bd224290",
            arweave_client=arweave,
            chain_submitter=submitter,
            batch_size=50,
        )

        entry = AuditLogEntry(
            entry_id=uuid.uuid4().hex[:8],
            case_id="ESC-001",
            constitutional_hash="608508a9bd224290",
            decision_type=AuditDecisionType.ESCALATED,
            compliance_passed=True,
            impact_score=0.85,
            resolution="allow_with_conditions",
            miner_uid="miner-01",
            validator_grade=0.92,
        )
        logger.add_entry(entry)
        receipt = logger.flush()   # → AuditLogReceipt

        # Auditor verification:
        batch = logger.fetch_batch(receipt)
        assert batch.verify_entry(
            entry,
            expected_root=receipt.batch_root,
            expected_batch_id=receipt.batch_id,
        )
    """

    def __init__(
        self,
        constitutional_hash: str,
        arweave_client: ArweaveClient,
        chain_submitter: AuditChainSubmitter | None = None,
        batch_size: int = 100,
    ) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        self._constitutional_hash = constitutional_hash
        self._arweave = arweave_client
        self._chain_submitter = chain_submitter
        self._batch_size = batch_size
        self._pending: _StagedBatch[AuditLogEntry] = _StagedBatch()
        self._receipts: list[AuditLogReceipt] = []
        self._state_lock = threading.RLock()
        self._flush_guard = threading.Lock()
        # Retry state: if Phase 1 (Arweave upload) succeeded but Phase 2
        # (chain submit) failed, we cache the batch + tx_id to reuse on
        # retry instead of creating a ghost orphaned upload on Arweave.
        self._retry_state: tuple[AuditBatch, str] | None = None
        self._staged_batch: AuditBatch | None = None
        self._last_flush_error: Exception | None = None

    @property
    def pending_count(self) -> int:
        with self._state_lock:
            return self._pending.pending_count

    @property
    def receipts(self) -> list[AuditLogReceipt]:
        with self._state_lock:
            return list(self._receipts)

    @property
    def last_flush_error(self) -> Exception | None:
        """Most recent external auto/explicit flush error, cleared on success."""
        with self._state_lock:
            return self._last_flush_error

    def add_entry(self, entry: AuditLogEntry) -> AuditLogReceipt | None:
        """Add an audit log entry. Auto-flushes when batch is full.

        Raises ValueError if entry's constitutional_hash doesn't match.
        Returns AuditLogReceipt if a flush occurred, else None.

        The entry is accepted once appended. If an automatic external upload
        or submit fails, this method logs the failure, leaves the stable batch
        pending, records it in ``last_flush_error``, and returns None. A later
        explicit ``flush()`` retries and propagates any external failure.
        """
        if type(entry) is not AuditLogEntry:
            raise TypeError("entry must be an exact AuditLogEntry instance")
        if entry.constitutional_hash != self._constitutional_hash:
            raise ValueError(
                f"Entry constitutional hash mismatch: "
                f"expected={self._constitutional_hash} got={entry.constitutional_hash}"
            )
        with self._state_lock:
            self._pending.append(entry)
            should_flush = self._pending.pending_count >= self._batch_size
        if should_flush:
            return self._flush(auto=True)
        return None

    def flush(self) -> AuditLogReceipt | None:
        """Flush pending entries → Arweave upload + optional chain anchor.

        Two-phase commit: pending entries are preserved until BOTH the
        Arweave upload AND chain submission succeed.  If either fails,
        entries remain in ``_pending`` so the caller can retry.

        One call processes exactly the stable prefix staged at its start.
        Entries appended during external I/O remain queued, even if that suffix
        reaches ``batch_size``; call ``flush()`` again (or add another entry)
        to process the suffix.

        Returns AuditLogReceipt, or None if no pending entries.
        """
        return self._flush(auto=False)

    def _flush(self, *, auto: bool) -> AuditLogReceipt | None:
        if not self._flush_guard.acquire(blocking=False):
            if auto:
                return None
            raise RuntimeError("flush already in progress")
        try:
            with self._state_lock:
                entries = self._pending.stage()
                if not entries:
                    return None
                if self._staged_batch is None:
                    self._staged_batch = AuditBatch(
                        batch_id=uuid.uuid4().hex[:12],
                        constitutional_hash=self._constitutional_hash,
                        entries=list(entries),
                    )
                batch = self._staged_batch
                retry_state = self._retry_state

            if retry_state is not None:
                batch, tx_id = retry_state
            else:
                batch_json = json.dumps(batch.to_dict()).encode()
                try:
                    tx_id = self._arweave.upload(
                        batch_json,
                        tags={
                            "constitutional_hash": self._constitutional_hash,
                            "batch_id": batch.batch_id,
                            "batch_root": batch.batch_root,
                            "App-Name": "ACGS-constitutional-swarm",
                        },
                    )
                except Exception as exc:
                    with self._state_lock:
                        self._last_flush_error = exc
                    if auto:
                        logger.exception(
                            "automatic audit-log upload failed; entry remains pending"
                        )
                        return None
                    raise
                with self._state_lock:
                    self._retry_state = (batch, tx_id)

            block_height: int | None = None
            if self._chain_submitter is not None:
                try:
                    block_height = self._chain_submitter.submit(
                        batch_root=batch.batch_root,
                        constitutional_hash=self._constitutional_hash,
                        proof_count=batch.entry_count,
                    )
                except Exception as exc:
                    with self._state_lock:
                        self._last_flush_error = exc
                    if auto:
                        logger.exception(
                            "automatic audit-log chain submit failed; entry remains pending"
                        )
                        return None
                    raise

            receipt = AuditLogReceipt(
                receipt_id=uuid.uuid4().hex[:8],
                batch_id=batch.batch_id,
                batch_root=batch.batch_root,
                arweave_tx_id=tx_id,
                entry_count=batch.entry_count,
                constitutional_hash=self._constitutional_hash,
                created_at=time.time(),
                block_height=block_height,
            )
            with self._state_lock:
                self._receipts.append(receipt)
                self._pending.commit()
                self._retry_state = None
                self._staged_batch = None
                self._last_flush_error = None
            return receipt
        finally:
            self._flush_guard.release()

    def fetch_batch(self, receipt: AuditLogReceipt) -> AuditBatch:
        """Reconstruct and authenticate an Arweave batch against its receipt."""
        if type(receipt) is not AuditLogReceipt:
            raise TypeError("receipt must be an exact AuditLogReceipt instance")
        string_fields = (
            receipt.receipt_id,
            receipt.batch_id,
            receipt.arweave_tx_id,
            receipt.constitutional_hash,
        )
        if any(type(value) is not str or not value for value in string_fields):
            raise TypeError("receipt identifiers must be non-empty plain strings")
        if type(receipt.batch_root) is not str:
            raise TypeError("receipt batch root must be a plain string")
        if not is_digest(receipt.batch_root):
            raise ValueError("receipt batch root must be a hexadecimal digest")
        if type(receipt.entry_count) is not int or receipt.entry_count < 0:
            raise TypeError("receipt entry count must be a non-negative integer")
        if type(receipt.created_at) not in (int, float) or not math.isfinite(receipt.created_at):
            raise ValueError("receipt creation time must be finite")
        if receipt.block_height is not None and (
            type(receipt.block_height) is not int or receipt.block_height < 0
        ):
            raise TypeError("receipt block height must be a non-negative integer or None")
        if receipt.constitutional_hash != self._constitutional_hash:
            raise ValueError("receipt constitutional hash does not match logger")
        raw = self._arweave.fetch(receipt.arweave_tx_id)
        try:
            decoded = loads(raw, max_bytes=_MAX_BATCH_JSON_BYTES)
            batch = AuditBatch.from_dict(decoded)
        except (KeyError, StrictJSONError, TypeError, ValueError) as exc:
            raise ValueError("invalid audit batch payload") from exc

        if (
            batch.batch_root != receipt.batch_root
            or batch.batch_id != receipt.batch_id
            or batch.entry_count != receipt.entry_count
            or batch.constitutional_hash != receipt.constitutional_hash
        ):
            raise ValueError("audit batch does not match receipt")
        return batch

    def summary(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "constitutional_hash": self._constitutional_hash,
                "batch_size": self._batch_size,
                "pending": self._pending.pending_count,
                "total_flushed": sum(r.entry_count for r in self._receipts),
                "batches_stored": len(self._receipts),
                "latest_block": (self._receipts[-1].block_height if self._receipts else None),
            }


# ---------------------------------------------------------------------------
# Merkle utilities
# ---------------------------------------------------------------------------


def _compute_merkle_root(leaves: list[str]) -> str:
    """Return the shared count-committed Merkle root in insertion order."""
    return compute_merkle_root(leaves)


def _merkle_path_for_index(
    leaves: list[str],
    target_idx: int,
) -> list[tuple[str, str]]:
    """Return the shared exact-shape path for one leaf index."""
    layers = build_merkle_layers(leaves)
    return list(merkle_path_for_index(layers, target_idx))


def verify_merkle_path(
    leaf_hash: str,
    path: list[tuple[str, str]],
    expected_root: str,
    *,
    leaf_count: int,
    leaf_index: int,
    batch_id: str | None = None,
    expected_batch_id: str | None = None,
) -> bool:
    """Verify an exact-shape path and optional paired batch identifier."""
    if (batch_id is None) != (expected_batch_id is None):
        return False
    if batch_id is not None:
        if type(batch_id) is not str or type(expected_batch_id) is not str:
            return False
        if batch_id != expected_batch_id:
            return False
    return _verify_merkle_path(
        leaf_hash,
        path,
        expected_root,
        leaf_count=leaf_count,
        leaf_index=leaf_index,
    )
