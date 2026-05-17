"""CLI entrypoint for ACGS v0.1 governance receipt verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from constitutional_swarm.governance_receipts import (
    ReceiptIssue,
    VerificationVerdict,
    bundle_from_json,
    verdict_to_json,
    verify_bundle,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Path to receipt bundle JSON")
    parser.add_argument(
        "--report-mode",
        action="store_true",
        help="Report unverifiable signatures without failing solely for that status.",
    )
    parser.add_argument(
        "--trusted-signers",
        type=Path,
        help="JSON object mapping trusted key_id values to public key hex strings.",
    )
    args = parser.parse_args(argv)

    try:
        bundle = bundle_from_json(args.bundle.read_text())
        trusted_signers = None
        if args.trusted_signers is not None:
            trusted_signers = json.loads(args.trusted_signers.read_text())
        verdict = verify_bundle(
            bundle,
            report_mode=args.report_mode,
            trusted_signers=trusted_signers,
        )
    except Exception as exc:
        print(
            verdict_to_json(
                VerificationVerdict(
                    valid=False,
                    mode="report" if args.report_mode else "fail_closed",
                    signature_status="not_checked",
                    issues=[
                        ReceiptIssue(
                            code="bundle_parse_error",
                            message=str(exc),
                        )
                    ],
                )
            )
        )
        print(f"receipt verification failed before verdict construction: {exc}", file=sys.stderr)
        return 2

    print(verdict_to_json(verdict))
    return 0 if verdict.valid else 1
