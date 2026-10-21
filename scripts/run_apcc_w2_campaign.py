#!/usr/bin/env python3
"""Execute or independently audit an explicitly parameterized W2 window."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--duration-ns", type=int, required=True)
    run.add_argument("--scheduled-operations", type=int, required=True)
    run.add_argument("--admission-grace-ns", type=int, required=True)
    run.add_argument("--operation-sla-ns", type=int, required=True)
    run.add_argument("--drain-ns", type=int, required=True)
    run.add_argument("--operation-floor", type=int, required=True)
    run.add_argument(
        "--windows",
        type=int,
        choices=(1, 2, 3, 4),
        default=1,
        help="Cold window followed by bounded warm continuation windows",
    )
    audit = commands.add_parser("verify")
    audit.add_argument("--ledger", type=Path, required=True)
    audit.add_argument("--expected-sha256", required=True)
    repetition = commands.add_parser("verify-repetition")
    repetition.add_argument("--manifest", type=Path, required=True)
    repetition.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from constitutional_swarm.apcc_empirical.w2_campaign import (
            run_repetition,
            verify_ledger,
            verify_repetition,
        )
        from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan

        if args.command == "run":
            plan = WindowPlan(
                args.duration_ns,
                args.scheduled_operations,
                args.admission_grace_ns,
                args.operation_sla_ns,
                args.drain_ns,
                args.operation_floor,
            )
            result = run_repetition(args.output, plans=(plan,) * args.windows)
            (args.output / "result.json").write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n"
            )
        elif args.command == "verify":
            result = verify_ledger(args.ledger, expected_sha256=args.expected_sha256)
        else:
            result = verify_repetition(
                args.manifest, expected_sha256=args.expected_sha256
            )
        print(
            json.dumps({"status": "verified", "result": result}, sort_keys=True),
            flush=True,
        )
        return 0
    except KeyboardInterrupt:
        print(
            json.dumps({"status": "interrupted", "campaign_eligible": False}),
            file=sys.stderr,
        )
        return 130
    except Exception as error:
        print(
            json.dumps(
                {"status": "failed", "error": str(error), "campaign_eligible": False}
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
