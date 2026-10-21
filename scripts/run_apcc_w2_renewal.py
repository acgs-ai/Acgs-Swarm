#!/usr/bin/env python3
"""Run or independently replay functional W2 observer renewal evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import sys
import threading

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
    run.add_argument("--handover-timeout-ms", type=int, required=True)
    run.add_argument("--windows", type=int, choices=(2, 3, 4, 5), required=True)
    run.add_argument("--conditioning-duration-ns", type=int)
    ledger = commands.add_parser("verify")
    ledger.add_argument("--ledger", type=Path, required=True)
    repetition = commands.add_parser("verify-repetition")
    repetition.add_argument("--manifest", type=Path, required=True)
    for audit in (ledger, repetition):
        audit.add_argument("--expected-sha256", required=True)
        audit.add_argument("--expected-plan-sha256", required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from constitutional_swarm.apcc_empirical.w2_renewal_replay import (
            verify_ledger,
            verify_repetition,
        )

        if args.command == "run":
            from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan
            from constitutional_swarm.apcc_empirical.w2_renewal_campaign import (
                run_repetition,
            )

            cancel = threading.Event()
            signal.signal(signal.SIGTERM, lambda *_: cancel.set())
            plan = WindowPlan(
                args.duration_ns,
                args.scheduled_operations,
                args.admission_grace_ns,
                args.operation_sla_ns,
                args.drain_ns,
                args.operation_floor,
            )
            plans = (plan,) * args.windows
            if args.conditioning_duration_ns is not None:
                from dataclasses import replace

                plans = (
                    replace(plan, duration_ns=args.conditioning_duration_ns),
                ) + plans[1:]
            execution = run_repetition(
                args.output,
                plans=plans,
                handover_timeout_ms=args.handover_timeout_ms,
                cancel=cancel,
            )
            result = verify_repetition(
                Path(execution["manifest_path"]),
                expected_sha256=execution["manifest_sha256"],
                expected_plan_sha256=execution["plan_sha256"],
            )
            (args.output / "result.json").write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n"
            )
        elif args.command == "verify":
            result = verify_ledger(
                args.ledger,
                expected_sha256=args.expected_sha256,
                expected_plan_sha256=args.expected_plan_sha256,
            )
        else:
            result = verify_repetition(
                args.manifest,
                expected_sha256=args.expected_sha256,
                expected_plan_sha256=args.expected_plan_sha256,
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
