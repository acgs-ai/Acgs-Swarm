#!/usr/bin/env python3
"""Run or replay a W2 diagnostic; outputs are never campaign qualification rows."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def _emit(value: dict, *, error: bool = False) -> None:
    print(
        json.dumps(value, sort_keys=True),
        file=sys.stderr if error else sys.stdout,
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    smoke = commands.add_parser(
        "smoke", help="Execute one or two complete diagnostic chains"
    )
    smoke.add_argument(
        "--output", type=Path, required=True, help="New evidence directory"
    )
    smoke.add_argument("--chains", type=int, choices=(1, 2), default=1)
    verify = commands.add_parser(
        "verify", help="Independently replay a sealed W2 ledger"
    )
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--expected-sha256", help="External ledger digest pin")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from constitutional_swarm.apcc_empirical.w2_driver import (
            run_smoke,
            verify_ledger,
        )

        if args.command == "smoke":
            result = run_smoke(args.output, chains=args.chains, progress=_emit)
            with (args.output / "result.json").open("x", encoding="utf-8") as output:
                json.dump(result, output, sort_keys=True, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
        else:
            result = verify_ledger(args.ledger, expected_sha256=args.expected_sha256)
        _emit({"status": "verified", "campaign_eligible": False, "result": result})
        return 0
    except KeyboardInterrupt:
        _emit({"status": "interrupted", "campaign_eligible": False}, error=True)
        return 130
    except Exception as error:
        _emit(
            {"status": "failed", "error": str(error), "campaign_eligible": False},
            error=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
