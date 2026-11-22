"""Run every bounded APCC model with the pinned TLC distribution."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from _tlc_common import (  # noqa: E402
    TLC_JAR_SHA256,
    TLC_VERSION_LINE,
    resolve_java,
    stage_jar,
)
from _tlc_common import sha256_file as _sha256  # noqa: E402

DEFAULT_CONFIGS = (
    "apcc_safety.cfg",
    "apcc_liveness.cfg",
    "apcc_witness_valid_chain.cfg",
    "apcc_witness_exact_replay.cfg",
    "apcc_witness_stale_rejection.cfg",
    "apcc_witness_revocation.cfg",
    "apcc_witness_recovery.cfg",
    "apcc_ablation_guard_reread.cfg",
    "apcc_ablation_supersession.cfg",
    "apcc_ablation_status_window.cfg",
    "apcc_ablation_attempt_guard.cfg",
    "apcc_ablation_revocation_closure.cfg",
    "apcc_ablation_propagation_fence.cfg",
    "apcc_ablation_recovery_authority.cfg",
    "apcc_ablation_supersession_nonretroactivity.cfg",
    "apcc_witness_invalid_authorization.cfg",
    "apcc_witness_invalid_receipt.cfg",
    "apcc_witness_status_binding.cfg",
    "apcc_ablation_authorization_evidence.cfg",
    "apcc_ablation_receipt_evidence.cfg",
    "apcc_ablation_status_binding.cfg",
    "apcc_witness_legacy_status.cfg",
    "apcc_ablation_legacy_status.cfg",
    "apcc_causal_safety.cfg",
    "apcc_causal_witness.cfg",
    "apcc_causal_ablation.cfg",
    "apcc_multitenant_safety.cfg",
    "apcc_multitenant_witness.cfg",
    "apcc_multitenant_nonce_ablation.cfg",
    "apcc_multitenant_actor_ablation.cfg",
    "apcc_multitenant_target_witness.cfg",
    "apcc_multitenant_target_ablation.cfg",
)
_VIOLATION = re.compile(r"Error: Invariant ([A-Za-z]+) is violated\.")
EXPECTED_WITNESS = {
    "apcc_witness_valid_chain.cfg": "WitnessValidChainNotReached",
    "apcc_witness_exact_replay.cfg": "WitnessExactReplayNotReached",
    "apcc_witness_stale_rejection.cfg": "WitnessStaleRejectionNotReached",
    "apcc_witness_revocation.cfg": "WitnessRevocationBlockedNotReached",
    "apcc_witness_recovery.cfg": "WitnessRecoveryNotReached",
    "apcc_ablation_guard_reread.cfg": "NoRevokedActorCommit",
    "apcc_ablation_supersession.cfg": "AtomicSupersession",
    "apcc_ablation_status_window.cfg": "IssuedStatusHasBoundedResidualValidity",
    "apcc_ablation_attempt_guard.cfg": "NoCrossAttemptReplay",
    "apcc_ablation_revocation_closure.cfg": "EffectiveRevocationClosure",
    "apcc_ablation_propagation_fence.cfg": "RevocationPropagationIsRecoverable",
    "apcc_ablation_recovery_authority.cfg": "NoAuthorityFromRecovery",
    "apcc_ablation_supersession_nonretroactivity.cfg": "SupersessionNonretroactivity",
    "apcc_witness_invalid_authorization.cfg": "WitnessInvalidAuthorizationRejectedNotReached",
    "apcc_witness_invalid_receipt.cfg": "WitnessInvalidReceiptRejectedNotReached",
    "apcc_witness_status_binding.cfg": "WitnessStatusBindingNotReached",
    "apcc_ablation_authorization_evidence.cfg": "NoUnauthorizedCommit",
    "apcc_ablation_receipt_evidence.cfg": "NoInvalidReceiptCommit",
    "apcc_ablation_status_binding.cfg": "DownstreamAuthorityConsistency",
    "apcc_witness_legacy_status.cfg": "WitnessLegacyStatusBlockedNotReached",
    "apcc_ablation_legacy_status.cfg": "NoAuthorityFromLegacyStatus",
    "apcc_causal_witness.cfg": "WitnessCausalCoverageNotReached",
    "apcc_causal_ablation.cfg": "BoundedIndependentCausalVerification",
    "apcc_multitenant_witness.cfg": "WitnessMultitenantIsolationNotReached",
    "apcc_multitenant_nonce_ablation.cfg": "NonceUniqueness",
    "apcc_multitenant_actor_ablation.cfg": "ActorRevocationWorkflowScope",
    "apcc_multitenant_target_witness.cfg": "WitnessRevocationTargetsNotReached",
    "apcc_multitenant_target_ablation.cfg": "RevocationTargetSeparation",
}
CONFIG_MODULE = {
    config: (
        "apcc_causal"
        if config.startswith("apcc_causal_")
        else "apcc_multitenant"
        if config.startswith("apcc_multitenant_")
        else "apcc"
    )
    for config in DEFAULT_CONFIGS
}


def classify_result(exit_code: int, output: str, expected_witness: str | None) -> bool:
    """Accept only normal success or one intentional named witness violation."""
    violations = _VIOLATION.findall(output)
    errors = [
        line.strip()
        for line in output.splitlines()
        if line.lstrip().startswith("Error:")
    ]
    if expected_witness is not None:
        allowed_errors = {
            f"Error: Invariant {expected_witness} is violated.",
            "Error: The behavior up to this point is:",
        }
        return (
            exit_code == 12
            and violations == [expected_witness]
            and bool(errors)
            and all(error in allowed_errors for error in errors)
            and "behavior up to this point" in output
        )
    return (
        exit_code == 0
        and not violations
        and not errors
        and "No error has been found" in output
    )


def _stats(output: str) -> str:
    lines = [
        line.strip()
        for line in output.splitlines()
        if "states generated" in line or "depth of the complete state graph" in line
    ]
    return " | ".join(lines) if lines else "state statistics unavailable"


def _run_config_detailed(
    jar: Path,
    specs: Path,
    config: str,
    timeout: int,
    java: str = "java",
    *,
    work_dir: Path | None = None,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    module = CONFIG_MODULE[config]
    stem = Path(config).stem
    spec_path = specs / f"{module}.tla"
    cfg_path = specs / config

    def _execute(scratch_root: Path) -> tuple[bool, int, str, float]:
        java_tmp = scratch_root / "java" / stem
        metadir = scratch_root / "states" / stem
        java_tmp.mkdir(parents=True, exist_ok=True)
        metadir.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        completed = subprocess.run(
            [
                java,
                f"-Djava.io.tmpdir={java_tmp}",
                "-cp",
                str(jar),
                "tlc2.TLC",
                "-cleanup",
                "-metadir",
                str(metadir),
                "-config",
                config,
                module,
            ],
            cwd=specs,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed_s = round(time.monotonic() - started, 3)
        output = completed.stdout + completed.stderr
        expected_witness = EXPECTED_WITNESS.get(config)
        ok = TLC_VERSION_LINE in output and classify_result(
            completed.returncode, output, expected_witness
        )
        return ok, completed.returncode, output, elapsed_s

    if work_dir is not None:
        ok, returncode, output, elapsed_s = _execute(work_dir)
    else:
        with tempfile.TemporaryDirectory(prefix=f"apcc-tlc-{stem}-") as scratch:
            ok, returncode, output, elapsed_s = _execute(Path(scratch))

    stats_text = _stats(output)
    print(f"{'PASS' if ok else 'FAIL'} {config}: exit={returncode}; {stats_text}")
    if not ok:
        print(output, file=sys.stderr)

    log_file: str | None = None
    log_sha256: str | None = None
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{stem}.log"
        log_path.write_text(output, encoding="utf-8")
        log_file = log_path.name
        log_sha256 = _sha256(log_path)

    expected_witness = EXPECTED_WITNESS.get(config)
    return {
        "config": config,
        "module": f"{module}.tla",
        "expected_witness": expected_witness,
        "expected_exit": 12 if expected_witness is not None else 0,
        "actual_exit": returncode,
        "ok": ok,
        "elapsed_s": elapsed_s,
        "stats": stats_text,
        "spec_sha256": _sha256(spec_path) if spec_path.is_file() else None,
        "cfg_sha256": _sha256(cfg_path) if cfg_path.is_file() else None,
        "jar_sha256": TLC_JAR_SHA256,
        "log_file": log_file,
        "log_sha256": log_sha256,
    }


def run_config(
    jar: Path,
    specs: Path,
    config: str,
    timeout: int,
    java: str = "java",
    *,
    work_dir: Path | None = None,
    log_dir: Path | None = None,
) -> bool:
    entry = _run_config_detailed(
        jar,
        specs,
        config,
        timeout,
        java,
        work_dir=work_dir,
        log_dir=log_dir,
    )
    return bool(entry["ok"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tlc-jar", required=True, type=Path)
    parser.add_argument(
        "--specs", type=Path, default=Path(__file__).resolve().parents[1] / "specs"
    )
    parser.add_argument("--config", action="append", choices=DEFAULT_CONFIGS)
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--log-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    selected_configs = tuple(args.config or DEFAULT_CONFIGS)
    if args.log_dir is not None:
        args.log_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apcc-tlc-") as private_dir:
        private_root = Path(private_dir)
        # Hash and execute one private copy so the checked bytes are the run bytes.
        try:
            jar = stage_jar(args.tlc_jar, private_root)
            jar_valid = _sha256(jar) == TLC_JAR_SHA256
        except OSError:
            jar_valid = False
        if not jar_valid:
            print(
                "FAIL: TLC jar is missing or does not match pinned v1.7.4 SHA-256",
                file=sys.stderr,
            )
            return 2
        java = resolve_java("java")
        try:
            records = [
                _run_config_detailed(
                    jar,
                    args.specs,
                    config,
                    args.timeout,
                    java,
                    work_dir=private_root,
                    log_dir=args.log_dir,
                )
                for config in selected_configs
            ]
        except subprocess.TimeoutExpired as exc:
            print(f"FAIL: TLC timeout after {exc.timeout}s", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"FAIL: could not start Java ({java}): {exc}", file=sys.stderr)
            return 2
    if args.log_dir is not None:
        summary = {
            "tlc_version_line": TLC_VERSION_LINE,
            "jar_sha256": TLC_JAR_SHA256,
            "total": len(records),
            "passed": sum(1 for item in records if item["ok"]),
            "failed": sum(1 for item in records if not item["ok"]),
            "runs": records,
        }
        (args.log_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if all(item["ok"] for item in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
