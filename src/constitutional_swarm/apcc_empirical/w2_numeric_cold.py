"""Candidate numeric cold slice. External receipts authorize one row, never a campaign.

This module performs no work at import. Fixtures cannot pass the execution gate.
Controller plans and seals are accounting evidence, never APCC authority facts.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import threading
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical import w2_renewal_campaign as runner
from constitutional_swarm.apcc_empirical import w2_renewal_replay as replay
from constitutional_swarm.apcc_empirical.contract import (
    load_matrix,
    planned_performance_runs,
)
from constitutional_swarm.apcc_empirical.w2_campaign_plan import (
    diagnostic_window_plan,
    validate_plan,
)

REVISION = "w2-numeric-cold-v1"
REPORTS = {
    "long_run_replays",
    "long_run_completion",
    "final_gate",
    "final_gate_input_comparison",
    "final_pin_isolation",
    "final_security_review",
    "saturation_repair_validation",
    "final_source_replay",
}


def numeric_provenance() -> dict[str, Any]:
    value = runner.provenance()
    root = Path(__file__).resolve().parents[3]
    name = "scripts/run_apcc_w2_numeric_cold.py"
    value["files"][name] = d._sha((root / name).read_bytes())
    return value


def pinned(path: Path, digest: str) -> bytes:
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid external SHA256")
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlink evidence")
    raw = path.read_bytes()
    if d._sha(raw) != digest:
        raise ValueError("external SHA256 mismatch")
    return raw


def canonical(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw)
    if type(value) is not dict or raw != d._json(value):
        raise ValueError("noncanonical object")
    return value


def child(root: Path, name: str) -> Path:
    if (
        type(name) is not str
        or not name
        or Path(name).is_absolute()
        or any(p in ("", ".", "..") for p in name.split("/"))
    ):
        raise ValueError("unsafe evidence path")
    path = root / name
    if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
        raise ValueError("symlink evidence path")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("evidence escapes root")
    return path


def seeded_payloads(sub_seed: str, chain: int, node_index: int) -> Any:
    seed = b64u_decode(sub_seed, expected_length=32)
    if (
        type(chain) is not int
        or type(node_index) is not int
        or not 0 <= chain < 100
        or not 0 <= node_index < 100
    ):
        raise ValueError("numeric payload index")
    node, artifact = d.build_payloads(chain, node_index)

    def fill(purpose: bytes, length: int) -> str:
        raw = (
            b"APCC-W2-CAMPAIGN-PAYLOAD-V1\0"
            + seed
            + chain.to_bytes(8, "big")
            + node_index.to_bytes(2, "big")
            + purpose
            + b"\0"
        )
        return hashlib.shake_256(raw).hexdigest((length + 1) // 2)[:length]

    node = replace(node, description=fill(b"input", len(node.description)))
    artifact = replace(artifact, content=fill(b"output", len(artifact.content)))
    if (
        len(d._node_input(node)) != 1024
        or len(d._json(artifact.canonical_dict())) != 4096
    ):
        raise ValueError("numeric payload byte contract")
    return node, artifact


def validate_coverage(
    value: dict[str, Any], matrix_path: Path, numeric_sha: str
) -> dict[str, Any]:
    """Reconstruct all 345 identities; prospective coverage grants no warm execution."""
    if (
        value.get("revision") != "w2-campaign-coverage-v1-prospective"
        or value.get("campaign_eligible") is not False
        or value.get("execution_authorized") is not False
    ):
        raise ValueError("invalid prospective coverage")
    pinned(matrix_path, value["source_matrix"]["sha256"])
    if value["numeric_timing_plan"]["sha256"] != numeric_sha:
        raise ValueError("coverage numeric pin mismatch")
    runs = [
        r
        for r in planned_performance_runs(load_matrix(matrix_path))
        if (r.baseline_id, r.store, r.workload_id) == ("B6", "sqlite", "W2")
    ]
    rows = value["windows"]
    if len(runs) != 345 or type(rows) is not list or len(rows) != len(runs):
        raise ValueError("coverage must contain all 345 rows")
    ids, ledgers, denominators = set(), set(), set()
    for i, (row, run) in enumerate(zip(rows, runs, strict=True)):
        position = (
            0
            if run.cache_state == "cold"
            else run.repetition + (3 if run.phase == "measured" else 0)
        )
        series = (
            f"{run.cache_state}-seed-{run.seed}-rate-{run.target_rate_per_second}"
            + (f"-repetition-{run.repetition:02d}" if run.cache_state == "cold" else "")
        )
        expected = {
            "coverage_index": i,
            "trial_id": run.trial_id,
            "sub_seed_b64u": run.sub_seed_b64u,
            "seed": run.seed,
            "baseline_id": "B6",
            "store": "sqlite",
            "workload_id": "W2",
            "cache_state": run.cache_state,
            "phase": run.phase,
            "repetition": run.repetition,
            "trial_index": run.trial_index,
            "target_rate_per_second": run.target_rate_per_second,
            "payload_bytes": list(run.payload_pair),
            "legacy_duration_seconds": run.duration_seconds,
            "mapped_window_ms": 10_000_000 // run.target_rate_per_second,
            "scheduled_operations": 10000,
            "minimum_on_time_commits": 10000,
            "maximum_late_completions": 0,
            "series_id": series,
            "series_window_index": position,
            "ledger_filename": f"{series}/window-{position:03d}.jsonl",
            "denominator_id": f"w2-campaign-coverage-v1/{run.trial_id}",
            "campaign_eligible": False,
            "warmup_runs_completed_before_window": 0
            if run.cache_state == "cold"
            else (run.repetition if run.phase == "warmup" else 3),
            "pre_run_queries": {
                "requirement": "exactly-zero"
                if run.cache_state == "cold"
                else "at-least-one",
                "observed": None,
            },
        }
        if set(row) != set(expected) | {"stimulus_sample"}:
            raise ValueError("coverage row exact fields")
        if any(
            type(row.get(k)) is not type(v) or row.get(k) != v
            for k, v in expected.items()
        ):
            raise ValueError("coverage planner identity, duration or floor mismatch")
        node, artifact = seeded_payloads(run.sub_seed_b64u, 0, 0)
        sample = {
            "local_chain": 0,
            "node_index": 0,
            "input_bytes": 1024,
            "output_bytes": 4096,
            "input_sha256": d._sha(d._node_input(node)),
            "output_sha256": d._sha(d._json(artifact.canonical_dict())),
        }
        if row["stimulus_sample"] != sample:
            raise ValueError("coverage seeded stimulus mismatch")
        ids.add(row["trial_id"])
        ledgers.add(row["ledger_filename"])
        denominators.add(row["denominator_id"])
    if len(ids) != 345 or len(ledgers) != 345 or len(denominators) != 345:
        raise ValueError("coverage bijection failed")
    groups = {row["series_id"] for row in rows}
    if (
        len(groups) != 165
        or len(value["series"]) != 165
        or {s["series_id"] for s in value["series"]} != groups
    ):
        raise ValueError("coverage series mismatch")
    for series in value["series"]:
        grouped = [r for r in rows if r["series_id"] == series["series_id"]]
        count = 1 if grouped[0]["cache_state"] == "cold" else 13
        if (
            series["window_count"] != count
            or series["ordered_trial_ids"] != [r["trial_id"] for r in grouped]
            or [r["series_window_index"] for r in grouped] != list(range(count))
        ):
            raise ValueError("coverage series ordering or repeated warmup")
        window_ms = grouped[0]["mapped_window_ms"]
        warm = count == 13
        total = (
            count * (window_ms + 1000 + 100000 + (2000 if warm else 0))
            + (count - 1) * 2000
        )
        # These remain prospective values, never the runtime cold setup authority.
        expected_limits = {
            "maximum_renewals": count - 1,
            "maximum_single_launch_ms": window_ms + 101000 + (4000 if warm else 0),
            "maximum_total_lifetime_ms": total,
            "handover_timeout_ms": 2000,
            "setup_margin_per_window_ms": 100000,
            "renewal_full_proof_drain_ms": 2000 if warm else 0,
            "window_drain_ms": 1000,
            "campaign_eligible": False,
            "fresh_authority_store": True,
            "same_store_all_windows": warm,
            "renew_before_window_indices": list(range(1, 13)) if warm else [],
        }
        if any(
            type(series.get(k)) is not type(v) or series[k] != v
            for k, v in expected_limits.items()
        ):
            raise ValueError("prospective coverage series budget altered")
    if value["counts"] != {
        "cold_measured": 150,
        "warmup": 45,
        "warm_measured": 150,
        "total_windows": 345,
        "cold_stores": 150,
        "warm_stores": 15,
        "total_stores": 165,
        "qualifying_candidate_windows": 300,
        "total_scheduled_operations": 3450000,
    }:
        raise ValueError("forged coverage counts")
    if value["planner"]["source_sha256"] != d._sha(
        (Path(__file__).parent / "contract.py").read_bytes()
    ):
        raise ValueError("coverage planner source mismatch")
    first = rows[0]
    if (
        first["seed"],
        first["target_rate_per_second"],
        first["cache_state"],
        first["phase"],
        first["repetition"],
    ) != (104729, 10, "cold", "measured", 0):
        raise ValueError("wrong first numeric row")
    return first


def validate_acceptance(value: dict[str, Any], root: Path) -> None:
    """Strict proposed receipt, external to the sealed Phase 1 capsule."""
    if (
        set(value)
        != {
            "revision",
            "fixture",
            "capsule_sha256sums",
            "phase1_source_manifest_sha256",
            "reports",
            "failure_audit",
            "numeric_delta",
        }
        or value["revision"] != "w2-phase1-acceptance-receipt-v1"
        or value["fixture"] is not False
    ):
        raise ValueError("Phase 1 acceptance receipt required; fixtures cannot execute")
    sums = value["capsule_sha256sums"]
    raw = pinned(child(root, sums["filename"]), sums["sha256"])
    members = {}
    for line in raw.decode().splitlines():
        sha, name = line.split("  ", 1)
        if name in members:
            raise ValueError("duplicate capsule member")
        pinned(child(root, name), sha)
        members[name] = sha
    if value["phase1_source_manifest_sha256"] not in members.values():
        raise ValueError("Phase 1 source manifest not sealed")
    reports = value["reports"]
    if set(reports) != REPORTS:
        raise ValueError("all eight Phase 1 reports required")
    for name, link in reports.items():
        if members.get(link["filename"]) != link["sha256"]:
            raise ValueError("report is not sealed in capsule")
        report = json.loads(pinned(child(root, link["filename"]), link["sha256"]))
        if (
            report.get("source_manifest_sha256")
            != value["phase1_source_manifest_sha256"]
        ):
            raise ValueError("Phase 1 report source mismatch")
        evidence = report.get("evidence")
        if (
            type(evidence) is not list
            or not evidence
            or any(
                type(e) is not dict
                or set(e) != {"source", "sha256", "destination"}
                or members.get(e["destination"]) != e["sha256"]
                for e in evidence
            )
        ):
            raise ValueError("readiness report missing sealed supporting evidence")
        if name == "final_gate_input_comparison":
            maps = []
            for side in ("before", "after"):
                link = report[side]
                matches = [
                    e
                    for e in evidence
                    if e["source"] == link["source"] and e["sha256"] == link["sha256"]
                ]
                if len(matches) != 1:
                    raise ValueError("gate input map evidence mismatch")
                maps.append(
                    json.loads(
                        pinned(child(root, matches[0]["destination"]), link["sha256"])
                    )
                )
            if maps[0] != maps[1]:
                raise ValueError("gate inputs changed")
        checks: Any = {
            "long_run_replays": {
                "all_passed": True,
                "fresh_process": True,
                "window_count": 4,
            },
            "long_run_completion": {
                "completed": True,
                "window_durations_seconds": [1000] * 4,
                "campaign_eligible": False,
                "owned_cleanup_proven": True,
            },
            "final_gate": {"exit_code": 0, "make_verify_passed": True},
            "final_gate_input_comparison": {"changed": []},
            "final_pin_isolation": {
                "protected_delta_count": 0,
                "historical_manifests": 13,
                "historical_entries": 648,
                "explicit_opt_in_deltas": [
                    "src/constitutional_swarm/apcc_empirical/w2_campaign.py",
                    "src/constitutional_swarm/authority_child.py",
                    "src/constitutional_swarm/authority_service.py",
                ],
            },
            "final_security_review": {
                "complete": True,
                "unresolved_material_findings": [],
            },
            "saturation_repair_validation": {"passed": True},
            "final_source_replay": {"all_passed": True, "fresh_process": True},
        }[name]
        if any(
            type(report.get(k)) is not type(v) or report[k] != v
            for k, v in checks.items()
        ):
            raise ValueError(f"Phase 1 report failed: {name}")
    for name in ("failure_audit", "numeric_delta"):
        link = value[name]
        report = canonical(pinned(child(root, link["filename"]), link["sha256"]))
        if report.get("fixture") is not False or report.get("passed") is not True:
            raise ValueError(f"missing real {name} acceptance")
        if name == "failure_audit" and (
            report.get("fresh_process") is not True
            or report.get("all_expected_rejections") is not True
        ):
            raise ValueError("failure audit incomplete")
        if name == "numeric_delta":
            if (
                report.get("make_verify_exit_code") != 0
                or report.get("independent_review_unresolved") != []
            ):
                raise ValueError("numeric source delta not reviewed and gated")
            source = numeric_provenance()
            if report.get("provenance") != source:
                raise ValueError("numeric source provenance not accepted")


DRAIN_DOMAIN = b"APCC-W2-NUMERIC-DRAIN-WITNESS-V1\0"


def drain_body(
    header: dict[str, Any], ledger_sha: str, fsync_ns: int, terminal_ns: int | None
) -> dict[str, Any]:
    epoch = header["numeric_setup"]["epoch_monotonic_ns"]
    deadline = header["plan"]["duration_ns"] + header["plan"]["drain_ns"]
    elapsed = fsync_ns - epoch
    if (
        type(fsync_ns) is not int
        or elapsed < 0
        or (
            terminal_ns is not None
            and (type(terminal_ns) is not int or not 0 <= terminal_ns <= elapsed)
        )
    ):
        raise ValueError("invalid durable drain clock")
    return {
        "revision": "w2-numeric-drain-witness-v1",
        "ledger_sha256": ledger_sha,
        "pacing_epoch_monotonic_ns": epoch,
        "ledger_fsync_monotonic_ns": fsync_ns,
        "ledger_fsync_elapsed_ns": elapsed,
        "drain_deadline_ns": deadline,
        "terminal_proof_completed_ns": terminal_ns,
        "window_drain_violation": elapsed > deadline,
    }


def verify_drain_witness(
    raw: bytes, header: dict[str, Any], footer: dict[str, Any], ledger_sha: str
) -> dict[str, Any]:
    value = canonical(raw)
    if (
        set(value) != {"body", "key_id", "signature"}
        or value["key_id"] != "controller-accounting-v1"
    ):
        raise ValueError("invalid drain witness envelope")
    body = value["body"]
    expected = drain_body(
        header,
        ledger_sha,
        body["ledger_fsync_monotonic_ns"],
        footer.get("terminal_proof_completed_ns"),
    )
    if (
        d._json(body) != d._json(expected)
        or body["ledger_fsync_elapsed_ns"] < footer["elapsed_ns"]
    ):
        raise ValueError("drain witness clock or ledger substitution")
    Ed25519PublicKey.from_public_bytes(
        b64u_decode(header["controller_public_key"], expected_length=32)
    ).verify(
        b64u_decode(value["signature"], expected_length=64),
        DRAIN_DOMAIN + d._json(body),
    )
    return body


def failure_artifact(
    output: Path, context: Any, error: BaseException
) -> dict[str, Any]:
    """Controller diagnostics only; never call an unverified prefix authoritative."""
    primary = getattr(context, "primary_error", None) or error

    def describe(exc: BaseException) -> dict[str, str]:
        return {"type": type(exc).__name__, "message": str(exc)}

    chain, seen = [], set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(describe(current))
        current = current.__cause__ or current.__context__
    links = {}
    for name in (
        "window-000.jsonl",
        "cleanup.json",
        "renewal-plan.json",
        "renewal-journal.jsonl",
        "drain-witness.json",
        "repetition.json",
    ):
        path = output / name
        if path.is_file() and not path.is_symlink():
            links[name] = {
                "sha256": d._sha(path.read_bytes()),
                "bytes": path.stat().st_size,
            }
    progress = dict(getattr(context, "progress", {}))
    admitted, overloads = progress.get("admitted", 0), progress.get("overloads", 0)
    cleanup_errors = list(getattr(context, "cleanup_errors", []))
    if (primary is not error or progress.get("phase") == "cleanup") and not any(
        e is error for e in cleanup_errors
    ):
        cleanup_errors.append(error)
    cleanup = None
    if "cleanup.json" in links:
        try:
            cleanup = json.loads((output / "cleanup.json").read_bytes())
        except ValueError:
            pass
    return {
        "revision": "w2-numeric-failed-attempt-v1",
        "numeric": getattr(context, "binding", None),
        "primary_error": describe(primary),
        "exception_chain": chain,
        "cleanup_errors": [describe(e) for e in cleanup_errors],
        "cleanup_status": "proven"
        if isinstance(cleanup, dict)
        and cleanup.get("owned_cleanup_proven") is True
        and not cleanup_errors
        else "failed-or-unproven",
        "phase": getattr(context, "failure_phase", progress.get("phase", "preflight")),
        "setup_progress": progress,
        "scheduled": 10000,
        "admitted": admitted,
        "overloads": overloads,
        "unexecuted": 10000 - admitted - overloads,
        "proofs_completed": progress.get("proofs_completed", 0),
        "observed_artifacts": links,
        "prefix_proofs_audited": False,
        "campaign_eligible": False,
        "cell_qualified": False,
    }


class SetupLimitError(ValueError):
    """No window was admitted; only authority provisioning may have occurred."""


class Context:
    def __init__(
        self,
        input_dir: Path,
        *,
        numeric_sha: str,
        coverage_sha: str,
        acceptance_sha: str,
    ):
        self.input_dir = input_dir
        self.pins = {
            "numeric-plan.json": numeric_sha,
            "coverage-plan.json": coverage_sha,
            "phase1-acceptance.json": acceptance_sha,
        }
        self.raw = {
            name: pinned(child(input_dir, name), sha) for name, sha in self.pins.items()
        }
        validate_plan(self.raw["numeric-plan.json"], expected_sha256=numeric_sha)
        coverage = canonical(self.raw["coverage-plan.json"])
        matrix = (
            Path(__file__).resolve().parents[3] / "experiments/apcc-1/matrix.v2.json"
        )
        self.row = validate_coverage(coverage, matrix, numeric_sha)
        validate_acceptance(canonical(self.raw["phase1-acceptance.json"]), input_dir)
        self.accepted_provenance = numeric_provenance()
        self.binding = {
            "revision": REVISION,
            "external_inputs": self.pins,
            "trial_id": self.row["trial_id"],
            "sub_seed_b64u": self.row["sub_seed_b64u"],
            "setup_limit_ms": 198000,
            "launch_lifetime_ms": 1200000,
            "renewals_executed": 0,
            "completion_margin_ms": 1000,
            "fixture": False,
        }

    def begin_setup(self) -> None:
        self.controller_origin_monotonic_ns = time.monotonic_ns()
        self.primary_error: BaseException | None = None
        self.cleanup_errors: list[BaseException] = []
        self.progress = {
            "phase": "bootstrap",
            "workflows_created": 0,
            "agents_registered": 0,
            "admitted": 0,
            "overloads": 0,
            "proofs_completed": 0,
        }

    @property
    def runtime_binding(self) -> dict[str, Any]:
        return {
            **self.binding,
            "controller_origin_monotonic_ns": self.controller_origin_monotonic_ns,
        }

    def provenance(self) -> dict[str, Any]:
        actual = numeric_provenance()
        if actual != self.accepted_provenance:
            raise ValueError("numeric source changed after acceptance")
        return actual

    def payload_builder(self, chain: int, node: int) -> Any:
        return seeded_payloads(self.row["sub_seed_b64u"], chain, node)

    def limits(self, plans: Any) -> dict[str, str]:
        if plans != (diagnostic_window_plan("cell_10_pps"),):
            raise ValueError("numeric cold must use exact first full window")
        return {
            "maximum_renewals": "1",
            "maximum_total_lifetime_ms": "1200000",
            "maximum_single_launch_ms": "1200000",
            "handover_timeout_ms": "2000",
        }

    def check_setup(
        self, launch: Any, now: int, plan: Any, *, now_ns: int | None = None
    ) -> None:
        elapsed_ns = (
            time.monotonic_ns() if now_ns is None else now_ns
        ) - self.controller_origin_monotonic_ns
        self.progress.update(
            setup_elapsed_ns=elapsed_ns,
            signed_launch_remaining_ms=int(launch.not_after_ms) - now,
        )
        if (
            not 0 <= elapsed_ns < 198_000_000_000
            or int(launch.not_after_ms) - int(launch.not_before_ms) != 1_200_000
            or now < int(launch.not_before_ms)
            or now - int(launch.not_before_ms) >= 198000
            or int(launch.not_after_ms) - now
            < (plan.duration_ns + plan.drain_ns) // 1_000_000 + 1000
        ):
            raise SetupLimitError(
                "numeric setup exceeded frozen allowance or remaining launch cap"
            )

    def seal_drain(
        self,
        directory: Path,
        header: Any,
        ledger_path: Path,
        controller: Any,
        fsync_ns: int,
        terminal_ns: int | None,
    ) -> bool:
        body = drain_body(
            header, d._sha(ledger_path.read_bytes()), fsync_ns, terminal_ns
        )
        record = {
            "body": body,
            "key_id": "controller-accounting-v1",
            "signature": b64u_encode(controller.sign(DRAIN_DOMAIN + d._json(body))),
        }
        runner._write(directory / "drain-witness.json", d._json(record))
        return body["window_drain_violation"]

    @staticmethod
    def is_late(pace: dict[str, Any], plan: Any) -> bool:
        return pace["end_ns"] > min(
            pace["admitted_ns"] + 200_000_000,
            pace["scheduled_ns"] + 225_000_000,
            plan.duration_ns + 1_000_000_000,
        )

    def install(self, directory: Path) -> None:
        receipt = canonical(self.raw["phase1-acceptance.json"])
        sums = receipt["capsule_sha256sums"]
        names = set(self.pins) | {sums["filename"]}
        for line in (
            pinned(child(self.input_dir, sums["filename"]), sums["sha256"])
            .decode()
            .splitlines()
        ):
            names.add(line.split("  ", 1)[1])
        names.update(receipt[k]["filename"] for k in ("failure_audit", "numeric_delta"))
        for relative in sorted(names):
            source = child(self.input_dir, relative)
            destination = directory / "inputs" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())


def _run_cold_attempt(
    output: Path, context: Context, *, cancel: threading.Event | None = None
) -> dict[str, Any]:
    owned_output = not output.exists()
    try:
        result = runner.run_repetition(
            output,
            plans=(diagnostic_window_plan("cell_10_pps"),),
            handover_timeout_ms=2000,
            numeric_context=context,
            cancel=cancel,
        )
    except BaseException as error:
        record = failure_artifact(output, context, error)
        try:
            if owned_output and output.is_dir():
                raw = d._json(record)
                runner._write(output / "failed-attempt.json", raw)
                error.add_note(f"Durable failed-attempt SHA256: {d._sha(raw)}")
            else:
                error.add_note(
                    "Output directory is absent or not owned by this attempt; failed-attempt evidence was not persisted"
                )
        except BaseException as evidence_error:
            error.add_note(
                f"Failed-attempt evidence could not be persisted: {evidence_error!r}"
            )
        primary = getattr(context, "primary_error", None)
        if primary is not None and primary is not error:
            raise primary from None
        raise
    context.progress["phase"] = "result-sealing"
    cleanup = canonical((output / "cleanup.json").read_bytes().removesuffix(b"\n"))
    if cleanup.get("owned_cleanup_proven") is not True:
        raise ValueError("numeric cleanup not proven")
    footer = json.loads((output / "window-000.jsonl").read_bytes().splitlines()[-1])
    manifest = {
        "revision": "w2-numeric-cold-audit-v1",
        "numeric": context.binding,
        "status": "fatal"
        if footer["numeric_outcome"]["status"] != "complete"
        or json.loads((output / "drain-witness.json").read_bytes())["body"][
            "window_drain_violation"
        ]
        else "complete",
        "campaign_eligible": False,
        "files": {
            name: d._sha((output / name).read_bytes())
            for name in (
                "repetition.json",
                "cleanup.json",
                "renewal-plan.json",
                "renewal-journal.jsonl",
                "drain-witness.json",
                "window-000.jsonl",
            )
        },
    }
    raw = d._json(manifest)
    runner._write(output / "numeric-result.json", raw)
    return {
        **result,
        "numeric_result_path": str(output / "numeric-result.json"),
        "numeric_result_sha256": d._sha(raw),
    }


def run_cold(
    output: Path, context: Context, *, cancel: threading.Event | None = None
) -> dict[str, Any]:
    """Persist failures from execution, teardown and result construction alike."""
    owned_output = not output.exists()
    try:
        return _run_cold_attempt(output, context, cancel=cancel)
    except BaseException as error:
        if (
            owned_output
            and output.is_dir()
            and not (output / "failed-attempt.json").exists()
        ):
            try:
                raw = d._json(failure_artifact(output, context, error))
                runner._write(output / "failed-attempt.json", raw)
                error.add_note(f"Durable failed-attempt SHA256: {d._sha(raw)}")
            except BaseException as evidence_error:
                error.add_note(
                    f"Failed-attempt evidence could not be persisted: {evidence_error!r}"
                )
        raise


class NumericPolicy(replay._Policy):
    def __init__(
        self,
        directory: Path,
        expected_plan_sha256: str,
        context: Context,
        failure_audit: bool,
    ):
        super().__init__(directory, expected_plan_sha256, _numeric_opt_in=True)
        if (
            self.plan["revision"] != REVISION
            or {
                k: v
                for k, v in self.plan["numeric"].items()
                if k != "controller_origin_monotonic_ns"
            }
            != context.binding
            or type(self.plan["numeric"].get("controller_origin_monotonic_ns"))
            is not int
            or self.plan["numeric"]["controller_origin_monotonic_ns"] <= 0
            or self.plan["limits"]
            != context.limits((diagnostic_window_plan("cell_10_pps"),))
            or self.plan["windows"] != [asdict(diagnostic_window_plan("cell_10_pps"))]
        ):
            raise ValueError("numeric runtime plan substitution")
        self.payload_builder = context.payload_builder
        self.failure_audit = failure_audit
        self.ledger_sha = ""
        self.context = context

    def check_header(self, header: dict[str, Any]) -> Any:
        launch = super().check_header(header)
        setup = header.get("numeric_setup")
        origin = self.plan["numeric"]["controller_origin_monotonic_ns"]
        if (
            type(setup) is not dict
            or set(setup) != {"controller_origin_monotonic_ns", "epoch_monotonic_ns"}
            or setup["controller_origin_monotonic_ns"] != origin
            or type(setup["epoch_monotonic_ns"]) is not int
        ):
            raise ValueError("numeric setup clock binding")
        self.context.controller_origin_monotonic_ns = origin
        self.context.check_setup(
            launch,
            header["started_wall_ms"],
            diagnostic_window_plan("cell_10_pps"),
            now_ns=setup["epoch_monotonic_ns"],
        )
        renewal = header["renewal"]
        if (
            header["window_index"] != 0
            or header["previous_ledger"] is not None
            or renewal["epoch"] != 0
            or renewal["continuity"] is not None
            or len(renewal["records"]) != 1
        ):
            raise ValueError("numeric cold forbids renewal or predecessor rescue")
        return launch

    def check_footer(
        self, header: Any, footer: Any, stream: Any, trust: Any, certificates: Any
    ) -> None:
        outcome = footer.get("numeric_outcome")
        counts = footer["accounting"]
        if (
            type(outcome) is not dict
            or set(outcome) != {"status", "unexecuted", "admitted"}
            or any(type(outcome[k]) is not int for k in ("unexecuted", "admitted"))
        ):
            raise ValueError("numeric footer exact fields")
        if (
            outcome["unexecuted"] != 10000 - counts["committed"] - counts["overloads"]
            or outcome["admitted"] != counts["committed"]
        ):
            raise ValueError("numeric denominator mismatch")
        if not self.failure_audit and outcome["status"] != "complete":
            raise ValueError("numeric success rejects failed prefix")
        witness = verify_drain_witness(
            (self.directory / "drain-witness.json").read_bytes(),
            header,
            footer,
            self.ledger_sha,
        )
        if self.failure_audit:
            if witness["window_drain_violation"]:
                # Complete operation proofs stay valid; the window itself failed.
                if outcome["status"] not in ("complete", "fatal", "fatal_drain"):
                    raise ValueError("unknown failed-window outcome")
                if outcome["status"] in ("complete", "fatal_drain") and (
                    counts["committed"] != 10000
                    or counts["overloads"]
                    or outcome["unexecuted"]
                    or type(footer.get("terminal_proof")) is not dict
                    or footer["terminal_proof"].get("node_index") != 99
                ):
                    raise ValueError(
                        "drain-only failure lost complete operation evidence"
                    )
                if outcome["status"] == "fatal" and not (
                    counts["overloads"] or counts["late_completions"]
                ):
                    raise ValueError("fatal prefix lacks an operation failure")
                if "terminal_proof" in footer:
                    row = footer["terminal_proof"]
                    if (
                        type(row.get("verification_time_ms")) is not int
                        or not header["started_wall_ms"] + 1_000_000
                        <= row["verification_time_ms"]
                        <= header["started_wall_ms"]
                        + footer["terminal_proof_completed_ns"] // 1_000_000
                        + 1000
                    ):
                        raise ValueError("failed terminal proof clock mismatch")
                    d._verify_operation(
                        footer["terminal_proof"],
                        header,
                        stream,
                        trust,
                        certificates,
                        expected_payload_builder=self.payload_builder,
                    )
                return
            if (
                outcome["status"] != "fatal"
                or counts["overloads"] + counts["late_completions"] == 0
                or "terminal_proof" in footer
            ):
                raise ValueError("not an authenticated fatal prefix")
        else:
            if witness["window_drain_violation"]:
                raise ValueError("numeric durable ledger drain exceeded deadline")
            if (
                outcome != {"status": "complete", "unexecuted": 0, "admitted": 10000}
                or counts["on_time_commits"] != 10000
                or counts["late_completions"]
                or counts["overloads"]
            ):
                raise ValueError("numeric floor/SLA failed")
            row = footer.get("terminal_proof")
            if type(row) is not dict or row.get("node_index") != 99:
                raise ValueError("missing complete terminal proof")
            d._verify_operation(
                row,
                header,
                stream,
                trust,
                certificates,
                expected_payload_builder=self.payload_builder,
            )
            if (
                not header["started_wall_ms"] + 1_000_000
                <= row["verification_time_ms"]
                <= header["started_wall_ms"] + 1_001_000
                or type(footer.get("terminal_proof_completed_ns")) is not int
                or not 1_000_000_000_000
                <= footer["terminal_proof_completed_ns"]
                <= 1_001_000_000_000
            ):
                raise ValueError("terminal proof clock mismatch")


def verify(
    path: Path,
    *,
    expected_sha256: str,
    expected_plan_sha256: str,
    context: Context,
    failure_audit: bool = False,
) -> dict[str, Any]:
    policy = NumericPolicy(path.parent, expected_plan_sha256, context, failure_audit)
    policy.ledger_sha = expected_sha256
    result = c.verify_ledger(
        path,
        expected_sha256=expected_sha256,
        expected_provenance=context.provenance(),
        _renewal_policy=policy,
        _numeric_policy=policy,
    )
    result.update(
        numeric_status="fatal-audited"
        if failure_audit
        else "complete-audited-unsealed",
        campaign_eligible=False,
        fixture=False,
        trial_id=context.row["trial_id"],
    )
    return result


def audit_result(
    path: Path,
    *,
    expected_sha256: str,
    expected_plan_sha256: str,
    context: Context,
    failure_audit: bool = False,
) -> dict[str, Any]:
    value = canonical(pinned(path, expected_sha256))
    names = {
        "repetition.json",
        "cleanup.json",
        "renewal-plan.json",
        "renewal-journal.jsonl",
        "drain-witness.json",
        "window-000.jsonl",
    }
    if (
        set(value) != {"revision", "numeric", "status", "campaign_eligible", "files"}
        or value["revision"] != "w2-numeric-cold-audit-v1"
        or value["numeric"] != context.binding
        or value["campaign_eligible"] is not False
        or set(value["files"]) != names
        or value["status"] != ("fatal" if failure_audit else "complete")
    ):
        raise ValueError(
            "numeric audit manifest substitution or failed success request"
        )
    files = {
        name: pinned(child(path.parent, name), sha)
        for name, sha in value["files"].items()
    }
    if value["files"]["renewal-plan.json"] != expected_plan_sha256:
        raise ValueError("runtime plan pin substitution")
    cleanup = canonical(files["cleanup.json"].removesuffix(b"\n"))
    if (
        cleanup.get("owned_cleanup_proven") is not True
        or cleanup.get("owned_pids_absent") is not True
        or cleanup.get("controller_run_descriptors") != []
        or cleanup.get("unavailable_owned_pids") != []
    ):
        raise ValueError("numeric cleanup evidence failed")
    repetition = canonical(files["repetition.json"].removesuffix(b"\n"))
    header = json.loads(files["window-000.jsonl"].splitlines()[0])
    if (
        repetition.get("revision") != "w2-numeric-cold-result-v1"
        or repetition.get("numeric") != context.binding
        or repetition.get("status") != value["status"]
        or repetition.get("campaign_eligible") is not False
        or repetition.get("windows")
        != [
            {
                "filename": "window-000.jsonl",
                "sha256": value["files"]["window-000.jsonl"],
            }
        ]
        or repetition.get("plan")
        != {"filename": "renewal-plan.json", "sha256": expected_plan_sha256}
    ):
        raise ValueError("numeric repetition binding failed")
    records = header["renewal"]["records"]
    if files["renewal-journal.jsonl"] != b"".join(d._json(r) + b"\n" for r in records):
        raise ValueError("numeric final journal prefix substitution")
    result = verify(
        path.parent / "window-000.jsonl",
        expected_sha256=value["files"]["window-000.jsonl"],
        expected_plan_sha256=expected_plan_sha256,
        context=context,
        failure_audit=failure_audit,
    )
    if repetition.get("drain_witness") != {
        "filename": "drain-witness.json",
        "sha256": value["files"]["drain-witness.json"],
    }:
        raise ValueError("repetition drain witness binding")
    if failure_audit:
        entries = [json.loads(line) for line in files["window-000.jsonl"].splitlines()][
            1:-1
        ]
        fatal_times = [
            e["pacing"]["decision_ns"] for e in entries if e["type"] == "overload"
        ]
        fatal_times += [
            e["pacing"]["end_ns"]
            for e in entries
            if e["type"] == "operation"
            and Context.is_late(e["pacing"], diagnostic_window_plan("cell_10_pps"))
        ]
        if (
            (
                not fatal_times
                and not json.loads(files["drain-witness.json"])["body"][
                    "window_drain_violation"
                ]
            )
            or sum(e["type"] == "overload" for e in entries) > 1
            or any(
                fatal_times and e["pacing"]["admitted_ns"] > min(fatal_times)
                for e in entries
                if e["type"] == "operation"
            )
        ):
            raise ValueError("admission continued after fatal numeric outcome")
    result["cleanup_proven"] = True
    result["manifest_sha256"] = expected_sha256
    return result


def fresh_cli_command(
    cli: Path, arguments: list[str]
) -> tuple[list[str], dict[str, str]]:
    """Exclude site startup, .pth execution, ambient paths and instrumentation."""
    import os
    import sys
    import sysconfig

    packages = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    bootstrap = (
        f"import sys,runpy; sys.dont_write_bytecode=True; sys.path.extend({packages!r}); "
        "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR"}
    }
    return [
        sys.executable,
        "-I",
        "-S",
        "-c",
        bootstrap,
        str(cli.resolve()),
        *arguments,
    ], environment


def qualify_capsule(
    path: Path, *, expected_sha256: str, context: Context
) -> dict[str, Any]:
    """Derive one cold-cell success only after pinned sealing and a fresh CLI replay.

    This does not assert complete 345-row coverage or warm qualification.
    """
    import subprocess

    capsule = canonical(pinned(path, expected_sha256))
    if (
        set(capsule)
        != {"revision", "numeric", "result", "runtime_plan_sha256", "campaign_eligible"}
        or capsule["revision"] != "w2-numeric-cold-capsule-v1"
        or capsule["numeric"] != context.binding
        or capsule["campaign_eligible"] is not False
        or set(capsule["result"]) != {"filename", "sha256"}
    ):
        raise ValueError("invalid sealed numeric capsule")
    result_path = child(path.parent, capsule["result"]["filename"])
    pinned(result_path, capsule["result"]["sha256"])
    root = Path(__file__).resolve().parents[3]
    arguments = [
        "verify",
        "--inputs",
        str(context.input_dir.resolve()),
        "--numeric-sha256",
        context.pins["numeric-plan.json"],
        "--coverage-sha256",
        context.pins["coverage-plan.json"],
        "--acceptance-sha256",
        context.pins["phase1-acceptance.json"],
        "--path",
        str(result_path.resolve()),
        "--sha256",
        capsule["result"]["sha256"],
        "--runtime-plan-sha256",
        capsule["runtime_plan_sha256"],
    ]
    command, env = fresh_cli_command(
        root / "scripts/run_apcc_w2_numeric_cold.py", arguments
    )
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=3600,
        check=True,
    )
    audited = json.loads(completed.stdout)
    if (
        audited.get("numeric_status") != "complete-audited-unsealed"
        or audited.get("campaign_eligible") is not False
        or audited.get("cleanup_proven") is not True
        or audited.get("trial_id") != context.row["trial_id"]
    ):
        raise ValueError("fresh process numeric replay did not pass")
    # Revalidate pins after the subprocess to prevent a changed capsule/result.
    pinned(path, expected_sha256)
    pinned(result_path, capsule["result"]["sha256"])
    return {
        "revision": "w2-numeric-cold-qualified-v1",
        "trial_id": context.row["trial_id"],
        "cell_qualified": True,
        "campaign_eligible": False,
        "campaign_complete": False,
        "covered_rows": 1,
        "required_rows": 345,
        "capsule_sha256": expected_sha256,
        "fresh_cli_stdout_sha256": d._sha(completed.stdout.encode()),
        "fixture": False,
    }
