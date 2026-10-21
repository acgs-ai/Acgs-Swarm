#!/usr/bin/env python3
"""Run or replay a bounded APCC-1 B6/SQLite/W1 qualification shard.

Exit codes: 0 success (smoke remains non-evidence), 1 failure, 2 verified but
incomplete qualification, 130 interrupted. Qualification uses the exact matrix
schedule; only smoke accepts an operation count.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import sqlite3
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "experiments/apcc-1/matrix.v2.json"
SCHEMA = ROOT / "experiments/apcc-1/raw-result.v2.schema.json"


def _emit(value: dict[str, Any], *, error: bool = False) -> None:
    print(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        file=sys.stderr if error else sys.stdout,
        flush=True,
    )


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _provenance(environment_path: Path) -> tuple[dict[str, str], str, dict[str, str]]:
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    if (
        not isinstance(environment, dict)
        or not environment
        or not all(
            isinstance(key, str) and key and isinstance(value, str) and value
            for key, value in environment.items()
        )
    ):
        raise ValueError("environment JSON must be a nonempty map of nonempty strings")
    measured_keys = {
        "qualification_source_manifest",
        "qualification_source_sha256",
        "qualification_git_dirty",
        "qualification_platform",
    }
    if measured_keys.intersection(environment):
        raise ValueError("environment JSON must not replace measured provenance")
    git_sha = _git("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", git_sha) is None:
        raise ValueError("Git HEAD is not a full SHA-1 commit identity")
    paths = sorted(
        {
            *ROOT.joinpath("src").rglob("*.py"),
            Path(__file__).resolve(),
            ROOT / "pyproject.toml",
            ROOT / "uv.lock",
        }
    )
    manifest = json.dumps(
        {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    environment.update(
        qualification_source_manifest=manifest,
        qualification_source_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
        qualification_git_dirty=str(bool(_git("status", "--porcelain"))).lower(),
        qualification_platform=platform.platform(),
    )
    versions = {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "git": _git("--version"),
    }
    for distribution in ("cryptography", "pydantic", "acgs-lite"):
        versions[distribution] = importlib.metadata.version(distribution)
    versions["constitutional-swarm-source"] = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    return environment, git_sha, versions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    smoke = commands.add_parser("smoke", help="Run diagnostics; never matrix evidence")
    smoke.add_argument("--output", type=Path, required=True)
    smoke.add_argument("--operations", type=int, default=3, help="1–1000; default 3")
    run = commands.add_parser(
        "run", help="Execute one exact supported matrix repetition"
    )
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--trial-id", required=True)
    run.add_argument("--environment-json", type=Path, required=True)
    run.add_argument("--environment-id", required=True)
    verify = commands.add_parser(
        "verify", help="Replay proofs and validate retained evidence"
    )
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument(
        "--smoke", action="store_true", help="Verify a smoke ledger as non-evidence"
    )
    verify.add_argument(
        "--expected-ledger-sha256", help="Optional external digest pin for smoke only"
    )
    for command in (run, verify):
        command.add_argument("--matrix", type=Path, default=MATRIX)
        command.add_argument("--schema", type=Path, default=SCHEMA)
    return parser


def main() -> int:
    args = _parser().parse_args()
    # The help path needs only the standard library. Direct script invocation
    # resolves the checked-out package, not an unrelated installed checkout.
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from constitutional_swarm.apcc_empirical.qualification_v3 import (
            run_qualification,
            run_smoke,
            select_run,
            verify_ledger,
            verify_shard,
        )

        if args.command in {"run", "smoke"} and (
            args.output.exists() or args.output.is_symlink()
        ):
            raise ValueError(
                "output must be a new path; existing evidence is never overwritten"
            )
        if args.command == "smoke":
            result = run_smoke(args.output, operations=args.operations, progress=_emit)
            evidence = False
        elif args.command == "run":
            if not args.environment_id.strip():
                raise ValueError("environment ID must be nonempty")
            selected = select_run(args.matrix, args.trial_id)
            environment, git_sha, versions = _provenance(args.environment_json)
            _emit(
                {
                    "event": "starting",
                    "trial_id": selected.trial_id,
                    "duration_seconds": selected.duration_seconds,
                    "target_rate_per_second": selected.target_rate_per_second,
                    "git_sha": git_sha,
                    "source_sha256": environment["qualification_source_sha256"],
                }
            )
            result = run_qualification(
                args.output,
                matrix_path=args.matrix,
                schema_path=args.schema,
                trial_id=args.trial_id,
                environment=environment,
                environment_id=args.environment_id,
                git_sha=git_sha,
                tool_versions=versions,
                progress=_emit,
            )
            evidence = True
        elif args.smoke:
            result = verify_ledger(
                args.output / "ledger.jsonl",
                expected_sha256=args.expected_ledger_sha256,
            )
            if result["header"]["mode"] != "smoke":
                raise ValueError(
                    "qualification evidence requires full shard verification"
                )
            evidence = False
        else:
            if args.expected_ledger_sha256 is not None:
                raise ValueError(
                    "qualification ledger digest is bound by the raw shard"
                )
            result = verify_shard(
                args.output, matrix_path=args.matrix, schema_path=args.schema
            )
            evidence = True
        incomplete = evidence and result["incomplete_run"]
        # The retained ledger contains the full header; avoid repeating its
        # source manifest and public trust material on the terminal.
        result = {key: value for key, value in result.items() if key != "header"}
        _emit(
            {
                "event": "result",
                "command": args.command,
                "qualification_evidence": evidence,
                "status": "incomplete" if incomplete else "verified",
                **result,
            }
        )
        return 2 if incomplete else 0
    except KeyboardInterrupt:
        _emit(
            {"event": "error", "status": "interrupted", "output": str(args.output)},
            error=True,
        )
        return 130
    except Exception as error:  # noqa: BLE001 -- CLI boundary reports typed runtime failures.
        _emit(
            {
                "event": "error",
                "status": "failed",
                "error_type": type(error).__name__,
                "error": str(error),
            },
            error=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
