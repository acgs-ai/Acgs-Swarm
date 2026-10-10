"""C27 regression tests: settlement persistence locking, pending reads, lookups.

Each test is phrased as an invalid-state / hostile-interleaving regression:
missing lock primitives must fail closed, pending reads must not race a
concurrent clear, and lookups must not degrade into full-store scans.
"""

from __future__ import annotations

import os
import pathlib
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from constitutional_swarm import settlement_evidence, settlement_store
from constitutional_swarm.settlement_store import (
    JSONLSettlementStore,
    SettlementRecord,
    SQLiteSettlementStore,
)

SRC = Path(__file__).resolve().parents[1] / "src"


def _record(assignment_id: str) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "artifact_id": f"art-{assignment_id}"},
        result={"accepted": True, "assignment_id": assignment_id},
        constitutional_hash="608508a9bd224290",
    )


# --- governance-10 / governance-16: one lock helper, never silently skipped ---


def _disable_lock_primitives(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settlement_store, "_fcntl", None)
    monkeypatch.setattr(settlement_store, "_msvcrt", None)
    # Base code kept a private copy in settlement_evidence; neutralise it too so
    # the test exercises "no primitive available" on both old and new code.
    if hasattr(settlement_evidence, "_fcntl"):
        monkeypatch.setattr(settlement_evidence, "_fcntl", None)


def test_store_lock_without_primitive_raises_instead_of_running_unlocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    _disable_lock_primitives(monkeypatch)
    entered = False
    with pytest.raises(RuntimeError, match="lock"):
        with store._file_lock():
            entered = True
    assert entered is False
    with pytest.raises(RuntimeError):
        store.append(_record("a1"))
    assert not store.path.exists()


def test_evidence_lock_without_primitive_raises_instead_of_running_unlocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    _disable_lock_primitives(monkeypatch)
    entered = False
    with pytest.raises(RuntimeError, match="lock"):
        with settlement_evidence.evidence_lock(store):
            entered = True
    assert entered is False
    # reconcile must refuse to unlink anything without the lock.
    orphan = store.path.with_name(f"{store.path.name}.x1.receipt.json")
    orphan.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError):
        settlement_evidence.reconcile_orphan_receipts(store)
    assert orphan.exists()


def test_evidence_lock_uses_msvcrt_when_fcntl_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, int]] = []

    class _FakeMSVCRT:
        LK_LOCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(fd: int, mode: int, length: int) -> None:
            calls.append((mode, length))

    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    monkeypatch.setattr(settlement_store, "_fcntl", None)
    monkeypatch.setattr(settlement_store, "_msvcrt", _FakeMSVCRT)
    if hasattr(settlement_evidence, "_fcntl"):
        monkeypatch.setattr(settlement_evidence, "_fcntl", None)
    with settlement_evidence.evidence_lock(store):
        pass
    assert calls == [(_FakeMSVCRT.LK_LOCK, 1), (_FakeMSVCRT.LK_UNLCK, 1)]


def test_failed_lock_acquire_does_not_attempt_unlock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    class _DenyingMSVCRT:
        LK_LOCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(fd: int, mode: int, length: int) -> None:
            calls.append(mode)
            if mode == 1:
                raise OSError("deadlock avoided")

    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    monkeypatch.setattr(settlement_store, "_fcntl", None)
    monkeypatch.setattr(settlement_store, "_msvcrt", _DenyingMSVCRT)
    with pytest.raises(OSError, match="deadlock avoided"):
        with store._file_lock():
            pass
    assert calls == [_DenyingMSVCRT.LK_LOCK]


def test_in_memory_store_evidence_lock_is_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    class _MemoryStore:
        def describe(self) -> dict[str, str]:
            return {"backend": "memory"}

    _disable_lock_primitives(monkeypatch)
    with settlement_evidence.evidence_lock(_MemoryStore()):
        pass


# --- governance-11: pending reads take the lock and tolerate concurrent clear ---


def test_load_pending_waits_for_writer_lock(tmp_path: Path) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    store.mark_pending(_record("p1"))
    results: dict[str, object] = {}

    def reader() -> None:
        results["pending"] = [r.assignment["assignment_id"] for r in store.load_pending()]
        results["count"] = store.pending_count()

    with store._file_lock():
        worker = threading.Thread(target=reader)
        worker.start()
        worker.join(0.3)
        assert worker.is_alive(), "load_pending read the pending file without the lock"
    worker.join(5)
    assert not worker.is_alive()
    assert results == {"pending": ["p1"], "count": 1}


def test_pending_file_vanishing_between_check_and_open_reads_as_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    store.mark_pending(_record("p1"))
    real_open = pathlib.Path.open

    def racing_open(self: pathlib.Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self == store.pending_path:
            # Simulate a concurrent clear_pending unlinking the file.
            os.unlink(self)
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pathlib.Path, "open", racing_open)
    assert store.load_pending() == []
    assert store.pending_count() == 0


def test_pending_marker_is_fsynced_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    synced: list[int] = []
    real_fsync = os.fsync

    def tracking_fsync(fd: int) -> None:
        synced.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(settlement_store.os, "fsync", tracking_fsync)
    store.mark_pending(_record("p1"))
    assert synced, "pending marker was published without fsync"
    assert [r.assignment["assignment_id"] for r in store.load_pending()] == ["p1"]


# --- governance-19 (store side): indexed get, closed connections, cached columns ---


def test_sqlite_get_does_not_scan_whole_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    for idx in range(5):
        store.append(_record(f"a{idx}"))

    def no_scan() -> list[SettlementRecord]:
        raise AssertionError("get() must not call load_all()")

    monkeypatch.setattr(store, "load_all", no_scan)
    found = store.get("a3")
    assert found is not None
    assert found.assignment["assignment_id"] == "a3"
    assert store.get("missing") is None


def test_sqlite_connections_are_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[sqlite3.Connection] = []
    closed: list[int] = []
    real_connect = sqlite3.connect

    class _Tracking(sqlite3.Connection):
        def close(self) -> None:
            closed.append(id(self))
            super().close()

    def tracking_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = _Tracking
        conn = real_connect(*args, **kwargs)  # type: ignore[call-overload]
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)
    store = SQLiteSettlementStore(tmp_path / "s.db")
    store.append(_record("a1"))
    store.mark_pending(_record("a2"))
    store.load_all()
    store.load_pending()
    store.pending_count()
    store.get("a1")
    store.clear_pending("a2")
    store.describe()
    assert opened
    assert len(closed) == len(opened)


def test_sqlite_column_metadata_is_cached_after_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteSettlementStore(tmp_path / "s.db")
    store.append(_record("a1"))
    pragma_calls: list[str] = []
    real_connect = sqlite3.connect

    class _Tracking(sqlite3.Connection):
        def execute(self, sql: str, *args: object) -> sqlite3.Cursor:  # type: ignore[override]
            if "PRAGMA table_info" in sql:
                pragma_calls.append(sql)
            return super().execute(sql, *args)  # type: ignore[arg-type]

    def tracking_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = _Tracking
        return real_connect(*args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)
    store.load_all()
    store.load_all()
    store.load_pending()
    assert store.has_receipt_digest_column() is True
    assert pragma_calls == []


def test_reconcile_builds_committed_index_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    store.append(_record("a1"))
    orphan = store.path.with_name(f"{store.path.name}.zz.receipt.json")
    orphan.write_text("{}", encoding="utf-8")
    calls: list[int] = []
    real_index = settlement_evidence.committed_receipt_index

    def counting_index(s: object) -> dict[str, str]:
        calls.append(1)
        return real_index(s)

    monkeypatch.setattr(settlement_evidence, "committed_receipt_index", counting_index)
    removed = settlement_evidence.reconcile_orphan_receipts(store)
    assert removed == [str(orphan)]
    assert len(calls) == 1


def test_lookup_settlement_uses_get_and_falls_back_to_scan(tmp_path: Path) -> None:
    lookup = settlement_store.lookup_settlement
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    store.append(_record("a1"))
    found = lookup(store, "a1")
    assert found is not None and found.assignment["assignment_id"] == "a1"
    assert lookup(store, "nope") is None

    class _NoGet:
        def load_all(self) -> list[SettlementRecord]:
            return [_record("b1"), _record("b2")]

    found_b = lookup(_NoGet(), "b2")
    assert found_b is not None and found_b.assignment["assignment_id"] == "b2"
    assert lookup(_NoGet(), "zz") is None


def test_verify_committed_receipt_for_store_without_get_fails_closed_on_missing() -> None:
    class _NoGet:
        def load_all(self) -> list[SettlementRecord]:
            return [_record("b1")]

    verdict = settlement_evidence.verify_committed_settlement_receipt(_NoGet(), "zz")
    assert verdict.valid is False
    assert verdict.issues[0].code == "settlement_missing"


# --- concurrency: append + pending lifecycle under the shared lock ---


def test_threaded_append_and_pending_lifecycle_is_consistent(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    writers = 8
    per_writer = 15
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(wid: int) -> None:
        store = JSONLSettlementStore(path)
        try:
            for idx in range(per_writer):
                record = _record(f"w{wid}-{idx}")
                store.mark_pending(record)
                store.append(record)
                store.clear_pending(f"w{wid}-{idx}")
        except BaseException as exc:  # noqa: BLE001 - surfaced via assertion below
            errors.append(exc)

    def reader() -> None:
        store = JSONLSettlementStore(path)
        try:
            while not stop.is_set():
                pending = store.load_pending()
                count = store.pending_count()
                assert all(r.assignment["assignment_id"].startswith("w") for r in pending)
                assert 0 <= count <= writers
        except BaseException as exc:  # noqa: BLE001 - surfaced via assertion below
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    threads = [threading.Thread(target=writer, args=(w,)) for w in range(writers)]
    for t in readers + threads:
        t.start()
    for t in threads:
        t.join(60)
    stop.set()
    for t in readers:
        t.join(10)
    assert errors == []
    final = JSONLSettlementStore(path)
    ids = sorted(r.assignment["assignment_id"] for r in final.load_all())
    assert len(ids) == writers * per_writer
    assert len(set(ids)) == len(ids)
    assert final.pending_count() == 0
    assert final.load_pending() == []
    assert not final.pending_path.exists()


_PROCESS_WORKER = """
import sys
from constitutional_swarm.settlement_store import JSONLSettlementStore, SettlementRecord
path, wid, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
store = JSONLSettlementStore(path)
for idx in range(n):
    aid = f"p{wid}-{idx}"
    rec = SettlementRecord(assignment={"assignment_id": aid}, result={"accepted": True})
    store.mark_pending(rec)
    assert aid in {r.assignment["assignment_id"] for r in store.load_pending()}
    store.append(rec)
    store.clear_pending(aid)
    store.pending_count()
print("ok")
"""


def test_multiprocess_append_and_pending_lifecycle_is_consistent(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    procs_n = 4
    per_proc = 15
    env = dict(os.environ, PYTHONPATH=str(SRC))
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _PROCESS_WORKER, str(path), str(w), str(per_proc)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for w in range(procs_n)
    ]
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
        assert out.strip() == "ok"
    final = JSONLSettlementStore(path)
    ids = [r.assignment["assignment_id"] for r in final.load_all()]
    assert len(ids) == procs_n * per_proc
    assert len(set(ids)) == len(ids)
    assert final.pending_count() == 0


# --- review r1: evidence_policy must survive the committed-settlement re-wrap ---


def test_committed_settlement_verdict_preserves_development_evidence_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A development-grade bundle verdict must not be relabelled proof_grade."""
    from types import SimpleNamespace

    from constitutional_swarm.governance_receipts import VerificationVerdict

    digest = "a" * 64
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    record = SettlementRecord(
        assignment={"assignment_id": "d1", "artifact_id": "art-d1"},
        result={"accepted": True},
        constitutional_hash="608508a9bd224290",
        receipt_digest=digest,
    )
    store.append(record)
    settlement_evidence.receipt_path_for(store, "d1").write_text("{}", encoding="utf-8")
    fake_receipt = SimpleNamespace(
        payload_digest=digest,
        payload=SimpleNamespace(
            receipt_id="r1",
            metadata={"assignment_id": "d1"},
            action="art-d1",
            decision="approved",
            policy_hash="608508a9bd224290",
            evidence_hashes={
                "content": "none",
                "settlement": settlement_evidence.settlement_canonical_digest(record),
            },
        ),
        signatures=[SimpleNamespace(key_id=settlement_evidence.RECEIPT_SIGNER_KEY_ID)],
        payload_type=settlement_evidence.RECEIPT_PAYLOAD_TYPE,
        profile_version=settlement_evidence.PROFILE_VERSION,
    )
    monkeypatch.setattr(
        settlement_evidence,
        "bundle_from_json",
        lambda _raw: SimpleNamespace(receipts=[fake_receipt]),
    )
    monkeypatch.setattr(
        settlement_evidence,
        "verify_bundle",
        lambda _bundle, **_kw: VerificationVerdict(
            valid=True,
            mode="fail_closed",
            profile_version=settlement_evidence.PROFILE_VERSION,
            receipt_count=1,
            signature_status="valid",
            evidence_policy="development",
        ),
    )
    verdict = settlement_evidence.verify_committed_settlement_receipt(store, "d1")
    assert verdict.issues == []
    assert verdict.evidence_policy == "development"


# --- review r1: lock file must not follow symlinks and must be private ---


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX O_NOFOLLOW only")
def test_symlinked_lock_path_is_refused(tmp_path: Path) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    store._lock_path.symlink_to(victim)
    with pytest.raises(OSError):
        store.append(_record("a1"))
    assert victim.read_text(encoding="utf-8") == "keep"
    evidence_lock_path = store.path.with_name(store.path.name + ".evidence.lock")
    evidence_lock_path.symlink_to(victim)
    with pytest.raises(OSError):
        with settlement_evidence.evidence_lock(store):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_new_lock_file_is_owner_only(tmp_path: Path) -> None:
    store = JSONLSettlementStore(tmp_path / "s.jsonl")
    store.append(_record("a1"))
    assert store._lock_path.stat().st_mode & 0o777 == 0o600
