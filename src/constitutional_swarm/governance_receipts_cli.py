"""CLI entrypoint for fail-closed governance receipt verification."""

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
    parser.add_argument(
        "bundle",
        type=Path,
        nargs="?",
        help="Path to receipt bundle JSON. Optional when --settlement-store is set.",
    )
    parser.add_argument(
        "--report-mode",
        action="store_true",
        help="Emit report-mode diagnostics; verification remains fail-closed.",
    )
    parser.add_argument(
        "--trusted-signers",
        type=Path,
        help=(
            "JSON object mapping key IDs to objects containing identity_id, "
            "public_key_hex, and authorized roles"
        ),
    )
    parser.add_argument(
        "--settlement-store",
        type=Path,
        help="JSONL or SQLite settlement path. When set, verification starts from the committed pointer.",
    )
    parser.add_argument(
        "--assignment-id",
        help="Assignment to verify against --settlement-store.",
    )
    parser.add_argument(
        "--expected-signer-role",
        choices=("validator", "coordinator", "settlement"),
        help="Verifier-selected required signer role for non-settlement receipts.",
    )
    parser.add_argument(
        "--allow-dev-evidence",
        action="store_true",
        help=(
            "Allow single-operator development vote evidence for direct bundle "
            "verification; output is labelled evidence_policy=development."
        ),
    )
    parser.add_argument(
        "--require-proof-grade",
        action="store_true",
        help=(
            "Fail closed unless the verdict is evidence_policy=proof_grade (rejects dev "
            "vote evidence and deterministic fixture trust roots)."
        ),
    )
    args = parser.parse_args(argv)

    try:
        trusted_signers = None
        if args.trusted_signers is not None:
            trusted_signers = json.loads(args.trusted_signers.read_text())
        if args.require_proof_grade and args.allow_dev_evidence:
            raise ValueError(
                "--require-proof-grade cannot be combined with --allow-dev-evidence"
            )
        if args.settlement_store is not None:
            if args.allow_dev_evidence:
                raise ValueError(
                    "--allow-dev-evidence cannot be used with --settlement-store"
                )
            if not args.assignment_id:
                raise ValueError("--assignment-id is required with --settlement-store")
            if args.bundle is None:
                pass
            from constitutional_swarm.settlement_evidence import (
                verify_committed_settlement_receipt,
            )
            from constitutional_swarm.settlement_store import (
                JSONLSettlementStore,
                SQLiteSettlementStore,
            )

            path = args.settlement_store
            store = (
                SQLiteSettlementStore(path)
                if path.suffix == ".db"
                else JSONLSettlementStore(path)
            )
            if args.expected_signer_role not in (None, "settlement"):
                raise ValueError(
                    "committed settlement receipts require --expected-signer-role settlement"
                )
            verdict = verify_committed_settlement_receipt(
                store,
                args.assignment_id,
                trusted_signers=trusted_signers,
            )
        else:
            if args.bundle is None:
                raise ValueError("bundle path is required unless --settlement-store is set")
            bundle = bundle_from_json(args.bundle.read_text())
            verdict = verify_bundle(
                bundle,
                report_mode=args.report_mode,
                trusted_signers=trusted_signers,
                expected_signer_role=args.expected_signer_role,
                require_independent_votes=not args.allow_dev_evidence,
                require_proof_grade=args.require_proof_grade,
            )
    except Exception as exc:
        print(
            verdict_to_json(
                VerificationVerdict(
                    valid=False,
                    mode="report" if args.report_mode else "fail_closed",
                    signature_status="not_checked",
                    evidence_policy=(
                        "development"
                        if args.allow_dev_evidence and args.settlement_store is None
                        else "proof_grade"
                    ),
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

    if args.require_proof_grade and verdict.valid and verdict.evidence_policy != "proof_grade":
        # Defence in depth for verifiers that do not take require_proof_grade.
        verdict = verdict.model_copy(
            update={
                "valid": False,
                "issues": [
                    *verdict.issues,
                    ReceiptIssue(
                        code="evidence_policy_not_proof_grade",
                        message="proof-grade evidence was required, but the policy is development",
                    ),
                ],
            }
        )
    print(verdict_to_json(verdict))
    return 0 if verdict.valid else 1
