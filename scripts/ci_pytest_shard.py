#!/usr/bin/env python3
"""Deterministic pytest sharding for CI, with a coverage proof.

``select`` collects the given test paths, assigns every node id to exactly one
of N shards by hashing the id, and writes the ids for one shard to an args file
that pytest reads as ``pytest @file``.  It also writes a manifest recording the
whole collection, so the shards can later be checked against each other.

``verify`` reads every shard's manifest and JUnit report and fails unless the
shards together ran each collected test exactly once, with nothing skipped.
Nothing here hardcodes a test count: totals come from the collection itself.

The assignment depends only on the node id and the shard count, so adding or
removing a test never moves other tests between shards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

MANIFEST_VERSION = 1
_NODE_ID = re.compile(r"^[^\s:]+\.py::\S")


def shard_of(node_id: str, shards: int) -> int:
    """Return the shard index in ``range(shards)`` that owns ``node_id``."""
    if shards < 1:
        raise ValueError("shards must be at least 1")
    digest = hashlib.sha256(node_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % shards


def collection_digest(node_ids: Sequence[str]) -> str:
    """Digest of the full collection, independent of collection order."""
    joined = "\n".join(sorted(node_ids)).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def collect(paths: Sequence[str], pytest_args: Sequence[str]) -> list[str]:
    """Collect node ids for ``paths`` without running any test."""
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q", *pytest_args, *paths]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(f"pytest collection failed with exit code {completed.returncode}")
    # A node id starts with its test file path; a collection-time warning that
    # merely mentions "::" does not.
    node_ids = [
        line.strip() for line in completed.stdout.splitlines() if _NODE_ID.match(line)
    ]
    if not node_ids:
        raise SystemExit("pytest collected no tests")
    if len(set(node_ids)) != len(node_ids):
        raise SystemExit("pytest collected duplicate node ids")
    return node_ids


def select(arguments: argparse.Namespace) -> int:
    if not 0 <= arguments.index < arguments.shards:
        raise SystemExit("--index must be in range(--shards)")
    node_ids = collect(arguments.paths, arguments.pytest_arg)
    selected = [node for node in node_ids if shard_of(node, arguments.shards) == arguments.index]
    if not selected:
        raise SystemExit(f"shard {arguments.index} of {arguments.shards} selected no tests")
    Path(arguments.out).write_text("".join(f"{node}\n" for node in selected), encoding="utf-8")
    manifest = {
        "version": MANIFEST_VERSION,
        "shards": arguments.shards,
        "index": arguments.index,
        "collected": len(node_ids),
        "collection_sha256": collection_digest(node_ids),
        "selected": len(selected),
    }
    Path(arguments.manifest).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


def _junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts = {"tests": 0, "skipped": 0, "failures": 0, "errors": 0}
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.attrib.get(key, "0"))
    return counts


def verify(arguments: argparse.Namespace) -> int:
    directory = Path(arguments.directory)
    manifests = sorted(directory.rglob("shard-manifest-*.json"))
    problems: list[str] = []
    if not manifests:
        raise SystemExit(f"no shard manifests under {directory}")
    loaded = [json.loads(path.read_text(encoding="utf-8")) for path in manifests]
    shards = {int(manifest["shards"]) for manifest in loaded}
    collected = {int(manifest["collected"]) for manifest in loaded}
    digests = {str(manifest["collection_sha256"]) for manifest in loaded}
    if len(shards) != 1 or len(collected) != 1 or len(digests) != 1:
        raise SystemExit(
            "shards disagree about the collection: "
            f"shards={sorted(shards)} collected={sorted(collected)} digests={sorted(digests)}"
        )
    shard_count, total = shards.pop(), collected.pop()
    if arguments.shards is not None and arguments.shards != shard_count:
        problems.append(f"expected {arguments.shards} shards, manifests say {shard_count}")
    indices = sorted(int(manifest["index"]) for manifest in loaded)
    if indices != list(range(shard_count)):
        problems.append(f"shard indices {indices} are not exactly 0..{shard_count - 1}")
    executed = 0
    for manifest in loaded:
        index = int(manifest["index"])
        report = next(iter(sorted(directory.rglob(f"shard-results-{index}.xml"))), None)
        if report is None:
            problems.append(f"shard {index}: JUnit report missing")
            continue
        counts = _junit_counts(report)
        executed += counts["tests"]
        if counts["tests"] != int(manifest["selected"]):
            problems.append(
                f"shard {index}: ran {counts['tests']} tests, selected {manifest['selected']}"
            )
        for key in ("skipped", "failures", "errors"):
            if counts[key]:
                problems.append(f"shard {index}: {counts[key]} {key}")
    if sum(int(manifest["selected"]) for manifest in loaded) != total:
        problems.append("selected counts do not sum to the collection")
    if executed != total:
        problems.append(f"shards ran {executed} tests, collection has {total}")
    summary = {
        "shards": shard_count,
        "collected": total,
        "executed": executed,
        "collection_sha256": digests.pop(),
        "ok": not problems,
    }
    print(json.dumps(summary, sort_keys=True))
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    selector = commands.add_parser("select", help="write one shard's node ids")
    selector.add_argument("--shards", type=int, required=True)
    selector.add_argument("--index", type=int, required=True)
    selector.add_argument("--out", required=True, help="pytest args file to write")
    selector.add_argument("--manifest", required=True, help="manifest JSON to write")
    selector.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        help="extra argument for the collection run (repeatable)",
    )
    selector.add_argument("paths", nargs="+")
    selector.set_defaults(handler=select)

    verifier = commands.add_parser("verify", help="prove the shards cover the collection")
    verifier.add_argument("--shards", type=int, default=None)
    verifier.add_argument("directory")
    verifier.set_defaults(handler=verify)

    arguments = parser.parse_args(argv)
    handler = arguments.handler
    return int(handler(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
