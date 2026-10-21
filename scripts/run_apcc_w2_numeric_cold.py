"""Isolated candidate CLI: external pins required before any authority launch."""

import argparse
import json
from pathlib import Path
import sys
import signal
import threading
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from constitutional_swarm.apcc_empirical.w2_numeric_cold import (  # noqa: E402
    Context,
    run_cold,
    audit_result,
    qualify_capsule,
)


@contextmanager
def cancellation_scope():
    cancel = threading.Event()
    previous = {}

    def request_cancel(signum, frame):
        cancel.set()

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, request_cancel)
        yield cancel
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "validate-inputs",
            "run-cold",
            "verify",
            "audit-failure",
            "qualify-capsule",
        ),
    )
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--numeric-sha256", required=True)
    parser.add_argument("--coverage-sha256", required=True)
    parser.add_argument("--acceptance-sha256", required=True)
    parser.add_argument("--path", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--runtime-plan-sha256")
    args = parser.parse_args()
    context = Context(
        args.inputs,
        numeric_sha=args.numeric_sha256,
        coverage_sha=args.coverage_sha256,
        acceptance_sha=args.acceptance_sha256,
    )
    if args.action == "validate-inputs":
        result = {
            "validated": True,
            "binding": context.binding,
            "campaign_eligible": False,
        }
    elif args.action == "run-cold":
        if args.path is None:
            parser.error("run-cold requires --path")
        with cancellation_scope() as cancel:
            result = run_cold(args.path, context, cancel=cancel)
    elif args.action == "qualify-capsule":
        if args.path is None or args.sha256 is None:
            parser.error("capsule requires --path and --sha256")
        result = qualify_capsule(
            args.path, expected_sha256=args.sha256, context=context
        )
    else:
        if args.path is None or args.sha256 is None or args.runtime_plan_sha256 is None:
            parser.error("audit requires --path, --sha256 and --runtime-plan-sha256")
        result = audit_result(
            args.path,
            expected_sha256=args.sha256,
            expected_plan_sha256=args.runtime_plan_sha256,
            context=context,
            failure_audit=args.action == "audit-failure",
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
