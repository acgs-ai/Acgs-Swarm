"""Subprocess worker for JSONL multi-process settlement tests.

Invoked as ``python tests/jsonl_mp_worker.py <action> <path> <assignment_id>``.
Not imported by the published package.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from constitutional_swarm.settlement_store import (  # noqa: E402
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
)


def _record(assignment_id: str) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "agent": f"agent-{assignment_id}"},
        result={"ok": True, "assignment_id": assignment_id},
        constitutional_hash="abc123",
        schema_version=1,
    )


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.005)
    raise TimeoutError(f"timed out waiting for {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("append", "warm-append", "crash-partial"))
    parser.add_argument("path")
    parser.add_argument("assignment_id")
    parser.add_argument("--next-id", default="")
    parser.add_argument("--ready-file", default="")
    parser.add_argument("--go-file", default="")
    args = parser.parse_args(argv)

    store = JSONLSettlementStore(Path(args.path))

    if args.action == "append":
        if args.ready_file:
            Path(args.ready_file).write_text("ready", encoding="utf-8")
        if args.go_file:
            _wait_for(Path(args.go_file))
        try:
            store.append(_record(args.assignment_id))
        except DuplicateSettlementError:
            print("duplicate")
            return 2
        print("committed")
        return 0

    if args.action == "warm-append":
        store.append(_record(args.assignment_id))
        print("warmed")
        if args.ready_file:
            Path(args.ready_file).write_text("ready", encoding="utf-8")
        if args.go_file:
            _wait_for(Path(args.go_file))
        if not args.next_id:
            raise SystemExit("warm-append requires --next-id")
        try:
            store.append(_record(args.next_id))
        except DuplicateSettlementError:
            print("duplicate")
            return 2
        print("committed")
        return 0

    if args.action == "crash-partial":
        store.path.parent.mkdir(parents=True, exist_ok=True)
        with store._file_lock():
            with store.path.open("a", encoding="utf-8") as handle:
                handle.write(f'{{"assignment":{{"assignment_id":"{args.assignment_id}"')
                handle.flush()
                os.fsync(handle.fileno())
            os._exit(17)

    raise AssertionError(f"unknown action {args.action}")


if __name__ == "__main__":
    raise SystemExit(main())
