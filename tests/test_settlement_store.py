import json
import threading
import warnings
from pathlib import Path

import constitutional_swarm.settlement_store as settlement_store
from constitutional_swarm import JSONLSettlementStore, SettlementRecord


def _make_record(assignment_id: str, *, schema_version: int = 1) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "agent": f"agent-{assignment_id}"},
        result={"ok": True, "assignment_id": assignment_id},
        constitutional_hash="abc123",
        schema_version=schema_version,
    )


class TestJSONLSettlementStoreLocking:
    """P2: JSONLSettlementStore must be safe under concurrent writes."""

    def test_concurrent_appends_no_duplicates(self, tmp_path):
        """Concurrent appends with different IDs should all succeed."""
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        errors = []

        def _append(i):
            try:
                store.append(_make_record(str(i)))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_append, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, f"Concurrent appends produced errors: {errors}"
        records = store.load_all()
        ids = [record.assignment["assignment_id"] for record in records]
        assert len(ids) == len(set(ids)), "No duplicate assignment IDs should be in the log"
        assert len(ids) == 20

    def test_truncated_terminal_line_repaired_on_load(self, tmp_path):
        """A truncated last line must be skipped with a warning, not a crash."""
        path = tmp_path / "settlements.jsonl"
        good = {
            "assignment": {"assignment_id": "1"},
            "result": {},
            "constitutional_hash": "",
            "schema_version": 1,
        }
        path.write_text(
            json.dumps(good) + "\n" + '{"assignment":{"assignment_id":"2","age',
            encoding="utf-8",
        )

        store = JSONLSettlementStore(path)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            records = store.load_all()

        assert len(records) == 1
        assert records[0].assignment["assignment_id"] == "1"
        assert any("truncated" in str(warning.message).lower() for warning in caught)
        assert path.read_text(encoding="utf-8").endswith("\n")

    def test_msvcrt_file_lock_used_when_fcntl_disabled(self, tmp_path, monkeypatch):
        """Module import must remain usable on Windows-style runtimes."""
        calls: list[tuple[int, int]] = []

        class _FakeMSVCRT:
            LK_LOCK = 1
            LK_UNLCK = 2

            @staticmethod
            def locking(fd: int, mode: int, length: int) -> None:
                calls.append((mode, length))

        store = settlement_store.JSONLSettlementStore(tmp_path / "settlements.jsonl")
        monkeypatch.setattr(settlement_store, "_fcntl", None)
        monkeypatch.setattr(settlement_store, "_msvcrt", _FakeMSVCRT)

        with store._file_lock():
            pass

        assert calls == [(_FakeMSVCRT.LK_LOCK, 1), (_FakeMSVCRT.LK_UNLCK, 1)]


class TestJSONLSettlementStoreIndex:
    """Duplicate detection must not rescan the whole log on every append."""

    def test_first_append_on_empty_file(self, tmp_path):
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        store.append(_make_record("a"))
        assert [record.assignment["assignment_id"] for record in store.load_all()] == ["a"]

    def test_sequential_appends_do_not_rescan_each_time(self, tmp_path):
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        for index in range(200):
            store.append(_make_record(f"id-{index}"))
        # Empty-start appends should never walk the log; only an explicit load
        # (or an invalidated index) increments scan_passes.
        assert store.scan_passes == 0
        assert store.json_decode_count == 0
        assert len(store.load_all()) == 200
        assert store.scan_passes == 1
        assert store.json_decode_count == 200

    def test_same_process_duplicate_fails_closed(self, tmp_path):
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        store.append(_make_record("dup"))
        try:
            store.append(_make_record("dup"))
        except settlement_store.DuplicateSettlementError as exc:
            assert "dup" in str(exc)
        else:
            raise AssertionError("expected DuplicateSettlementError")
        assert store.scan_passes == 0

    def test_restart_detects_duplicate(self, tmp_path):
        path = tmp_path / "settlements.jsonl"
        JSONLSettlementStore(path).append(_make_record("persist"))
        restarted = JSONLSettlementStore(path)
        try:
            restarted.append(_make_record("persist"))
        except settlement_store.DuplicateSettlementError:
            pass
        else:
            raise AssertionError("expected DuplicateSettlementError after restart")
        assert restarted.scan_passes == 1
        restarted.append(_make_record("next"))
        assert restarted.scan_passes == 1

    def test_external_append_invalidates_index(self, tmp_path):
        path = tmp_path / "settlements.jsonl"
        store = JSONLSettlementStore(path)
        store.append(_make_record("local"))
        payload = {
            "assignment": {"assignment_id": "external"},
            "result": {"ok": True},
            "constitutional_hash": "abc123",
            "schema_version": 1,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
        store.append(_make_record("after-external"))
        try:
            store.append(_make_record("external"))
        except settlement_store.DuplicateSettlementError:
            pass
        else:
            raise AssertionError("external assignment must be visible after invalidation")
        ids = {record.assignment["assignment_id"] for record in store.load_all()}
        assert ids == {"local", "external", "after-external"}

    def test_mid_file_corruption_fails_closed(self, tmp_path):
        path = tmp_path / "settlements.jsonl"
        good = {
            "assignment": {"assignment_id": "1"},
            "result": {},
            "constitutional_hash": "",
            "schema_version": 1,
        }
        path.write_text(
            json.dumps(good) + "\nnot-json\n" + json.dumps(good | {"assignment": {"assignment_id": "3"}}) + "\n",
            encoding="utf-8",
        )
        store = JSONLSettlementStore(path)
        try:
            store.append(_make_record("4"))
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("mid-file corruption must fail closed")

    def test_injected_write_failure_does_not_commit_index(self, tmp_path, monkeypatch):
        path = tmp_path / "settlements.jsonl"
        store = JSONLSettlementStore(path)
        store.append(_make_record("ok"))
        original_open = Path.open

        def _boom(self, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            handle = original_open(self, *args, **kwargs)
            if mode == "a":
                handle.write('{"assignment":{"assignment_id":"torn"')
                handle.flush()
                raise OSError("injected crash during append")
            return handle

        monkeypatch.setattr(Path, "open", _boom)
        try:
            store.append(_make_record("torn"))
        except OSError:
            pass
        else:
            raise AssertionError("injected crash did not fire")
        monkeypatch.undo()

        recovered = JSONLSettlementStore(path)
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            recovered.append(_make_record("after-crash"))
        ids = [record.assignment["assignment_id"] for record in recovered.load_all()]
        assert ids == ["ok", "after-crash"]

    def test_append_survives_torn_write_then_continues(self, tmp_path):
        path = tmp_path / "settlements.jsonl"
        store = JSONLSettlementStore(path)
        store.append(_make_record("ok"))
        # Durable effect of a crash mid-append: a terminal line with no newline.
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"assignment":{"assignment_id":"torn"')

        recovered = JSONLSettlementStore(path)
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            recovered.append(_make_record("after-crash"))
        ids = [record.assignment["assignment_id"] for record in recovered.load_all()]
        assert ids == ["ok", "after-crash"]

    def test_scale_scan_passes_are_linear(self, tmp_path):
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        for index in range(1000):
            store.append(_make_record(f"n-{index}"))
        assert store.scan_passes == 0
        store.load_all()
        assert store.scan_passes == 1
        assert store.json_decode_count == 1000
