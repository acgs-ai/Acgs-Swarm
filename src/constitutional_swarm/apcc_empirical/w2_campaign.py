"""Controller-only fixed-window W2 execution and independent campaign replay.

Authority proofs use the unchanged W2 diagnostic proof checker and its signed
experiment identity. The separately domain-separated campaign seal never grants
authority. Explicit timing parameters are required; local runs do not approve them.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from contextlib import ExitStack, nullcontext
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    decode_observer_launch_attestation,
    encode_observer_launch_attestation,
    encode_signed_authority_observation,
)
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.sqlite_store import _config_from_object, _config_object
from constitutional_swarm.apcc.verifier import ScopedTrust, TrustBinding, TrustRole
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan, verify_accounting
from constitutional_swarm.authority_service import (
    _decode_commit_request,
    _encode_commit_request,
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governed_commit import (
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG

DOMAIN = b"APCC-1.w2-campaign-v1.ledger\0"


class CampaignWorkerPool(d.WorkerPool):
    """Reserve a real permit before timestamping deadline-bound admission."""

    def submit_before(
        self,
        function: Callable[[int], Any],
        *,
        deadline_ns: int,
        clock: Callable[[], int],
    ) -> Future[Any] | None:
        with self._state_lock:
            if self._closed or not self._permits.acquire(blocking=False):
                return None
            try:
                admitted_ns = clock()
                if admitted_ns >= deadline_ns:
                    self._permits.release()
                    return None
                future: Future[Any] = Future()
                self._queue.put((lambda: function(admitted_ns), future))
                return future
            except BaseException:
                self._permits.release()
                raise


def provenance() -> dict[str, Any]:
    value = d._source_provenance()
    root = Path(__file__).resolve().parents[3]
    for name in (
        "scripts/run_apcc_w2_campaign.py",
        "docs/internal/APCC-1-W2-Campaign-Protocol.md",
    ):
        value["files"][name] = d._sha((root / name).read_bytes())
    return value


def _header_check(header: dict[str, Any]) -> Any:
    if (
        header["revision"] != "w2-campaign-v1"
        or type(header["capacity"]) is not int
        or header["capacity"] != 16
    ):
        raise ValueError("invalid campaign revision/capacity")
    config = _config_from_object(header["expected_public_config"])
    if (
        config.causal_profile is not AuthorityCausalProfile.W2_LINEAR_100
        or _config_object(config) != header["expected_public_config"]
        or header["config_sha256"] != d._sha(d._json(_config_object(config)))
        or _config_object(config)["bindings"] != header["trust"]
    ):
        raise ValueError("campaign profile/configuration substitution")
    producers = [item for item in header["trust"] if item["role"] == "producer"]
    other_keys = {
        item["public_key"] for item in header["trust"] if item["role"] != "producer"
    } | {header["controller_public_key"]}
    if len(producers) != 100 or len({p["public_key"] for p in producers}) != 100:
        raise ValueError("campaign producer identity count")
    for i, binding in enumerate(producers):
        if (
            binding["scope"][0] != f"agent-{i:03d}"
            or binding["key_id"] != f"producer-key-{i:03d}"
            or binding["scope"][1] != "authority:w2:producer"
            or binding["public_key"] in other_keys
        ):
            raise ValueError("campaign scoped producer substitution")
    pids = [
        header[field]
        for field in ("authority_pid", "executor_pid", "observer_pid", "controller_pid")
    ]
    if any(type(pid) is not int or pid <= 0 for pid in pids) or len(set(pids)) != 4:
        raise ValueError("campaign process identities")
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    if (
        launch.observer_pid != str(header["observer_pid"])
        or config.authority_store_id
        != header["launch_expectations"]["authority_store_id"]
        or header["observer_experiment"] != d._EXPERIMENT
    ):
        raise ValueError("campaign launch substitution")
    if type(header["started_wall_ms"]) is not int or header["started_wall_ms"] <= 0:
        raise ValueError("campaign wall clock")
    for name in ("window_index", "chain_offset"):
        if type(header[name]) is not int or header[name] < 0:
            raise ValueError("invalid campaign lifecycle index")
    if (
        header["phase"] != ("cold" if header["window_index"] == 0 else "warm")
        or header["repetition_id"] != header["run_id"]
        or header["warm_mode"] != "same-handles-continuation"
    ):
        raise ValueError("campaign lifecycle substitution")
    from constitutional_swarm.apcc.observation import ObserverLaunchExpectationsV1

    launch.verify(
        pinned_controller_public_key=b64u_decode(
            header["controller_public_key"], expected_length=32
        ),
        expected=ObserverLaunchExpectationsV1(**header["launch_expectations"]),
        now_ms=header["started_wall_ms"],
    )
    if type(header["window_plans"]) is not list:
        raise ValueError("invalid repetition window plans")
    plans = tuple(WindowPlan(**p) for p in header["window_plans"])
    _repetition_lifetime(plans)
    index = header["window_index"]
    if index >= len(plans) or header["plan"] != asdict(plans[index]):
        raise ValueError("window plan substitution")
    if (
        launch.backend_kind != "sqlite"
        or launch.experiment_id != d._EXPERIMENT
        or launch.run_id != header["run_id"]
        or launch.authority_store_id != config.authority_store_id
        or int(launch.not_after_ms) - int(launch.not_before_ms) > 1_200_000
        or int(launch.not_after_ms)
        < header["started_wall_ms"]
        + (plans[index].duration_ns + plans[index].drain_ns + 999_999) // 1_000_000
    ):
        raise ValueError("campaign observer lifetime or identity mismatch")
    return launch


def verify_ledger(
    path: Path,
    *,
    expected_sha256: str,
    expected_provenance: dict[str, Any] | None = None,
    _state: dict[str, Any] | None = None,
    _depth: int = 0,
    _renewal_policy: Any = None,
    _numeric_policy: Any = None,
) -> dict[str, Any]:
    """Replay signed observations and every causal closure, with no result cache."""
    if _depth >= 4:
        raise ValueError("campaign predecessor chain exceeds repetition bound")
    raw = path.read_bytes()
    if d._sha(raw) != expected_sha256:
        raise ValueError("campaign external digest mismatch")
    lines = raw.splitlines(keepends=True)
    if len(lines) < 3 or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("truncated campaign ledger")
    values = [json.loads(line) for line in lines]
    if any(
        d._json(row) + b"\n" != line for row, line in zip(values, lines, strict=True)
    ):
        raise ValueError("noncanonical campaign ledger")
    header, footer = values[0], values[-1]
    if header["type"] != "header" or footer["type"] != "footer":
        raise ValueError("campaign envelope")
    body = {key: value for key, value in footer.items() if key != "signature"}
    if body["prefix_sha256"] != d._sha(b"".join(lines[:-1])):
        raise ValueError("campaign prefix seal mismatch")
    Ed25519PublicKey.from_public_bytes(
        b64u_decode(header["controller_public_key"], expected_length=32)
    ).verify(
        b64u_decode(footer["signature"], expected_length=64), DOMAIN + d._json(body)
    )
    if header["provenance"] != footer["provenance_after"] or (
        expected_provenance is not None and header["provenance"] != expected_provenance
    ):
        raise ValueError("campaign provenance mismatch")
    launch = (
        _header_check(header)
        if _renewal_policy is None
        else _renewal_policy.check_header(header)
    )
    plan = WindowPlan(**header["plan"])
    state = {} if _state is None else _state
    previous = header["previous_ledger"]
    if _renewal_policy is not None:
        state["stream"] = _renewal_policy.check_transition(path, header, launch)
    elif header["window_index"] == 0:
        if previous is not None or header["chain_offset"] != 0:
            raise ValueError("invalid cold window predecessor")
        state["stream"] = AuthorityObservationVerificationStream(launch.session_id)
    else:
        if (
            type(previous) is not dict
            or set(previous) != {"filename", "sha256"}
            or previous["filename"] != f"window-{header['window_index'] - 1:03d}.jsonl"
        ):
            raise ValueError("invalid warm predecessor link")
        previous_path = path.parent / previous["filename"]
        if previous_path.is_symlink():
            raise ValueError("campaign predecessor symlink rejected")
        verify_ledger(
            previous_path,
            expected_sha256=previous["sha256"],
            expected_provenance=expected_provenance,
            _state=state,
            _depth=_depth + 1,
        )
        prior = state["header"]
        if any(
            header[name] != prior[name]
            for name in (
                "run_id",
                "repetition_id",
                "expected_public_config",
                "controller_public_key",
                "launch",
                "worker_ids",
                "authority_pid",
                "executor_pid",
                "observer_pid",
                "controller_pid",
                "provenance",
                "window_plans",
            )
        ):
            raise ValueError("warm handle/profile/repetition substitution")
        if (
            header["window_index"] != prior["window_index"] + 1
            or header["chain_offset"]
            != prior["chain_offset"] + prior["plan"]["scheduled_operations"] // 100
            or state["accounting"].committed != prior["plan"]["scheduled_operations"]
            or header["started_wall_ms"]
            < prior["started_wall_ms"] + state["elapsed_ns"] // 1_000_000
        ):
            raise ValueError("incomplete or overlapping warm transition")
    stream = state["stream"]
    trust = d._trust(header)
    certificates: dict[str, bytes] = {}
    accounting_rows = []
    seen_commits: set[str] = set()
    seen_nonces: set[str] = set()
    operations: dict[int, dict[str, Any]] = {}
    last_end = 0
    for entry in values[1:-1]:
        if entry["type"] == "operation":
            if (
                set(entry) != {"type", "proof", "pacing"}
                or entry["pacing"].get("outcome") != "committed"
            ):
                raise ValueError("campaign operation envelope mismatch")
            row, pace = entry["proof"], entry["pacing"]
            request = _decode_commit_request(row["request"])
            chain, node = (
                header["chain_offset"] + pace["chain_index"],
                pace["node_index"],
            )
            payload = request.receipt.payload
            if (
                row["chain"] != chain
                or row["node_index"] != node
                or payload.workflow_id != f"workflow-{header['run_id']}-{chain:03d}"
                or payload.node_id != f"node-{node:03d}"
                or payload.agent_id != f"agent-{node:03d}"
                or payload.key_id != f"producer-key-{node:03d}"
            ):
                raise ValueError("campaign cross-chain identity splice")
            if request.commit_id in seen_commits or row["nonce"] in seen_nonces:
                raise ValueError("campaign replayed operation")
            seen_commits.add(request.commit_id)
            seen_nonces.add(row["nonce"])
            if any(
                type(row[key]) is not int
                for key in (
                    "admit_ns",
                    "start_ns",
                    "commit_start_ns",
                    "commit_end_ns",
                    "observe_end_ns",
                    "end_ns",
                    "verification_time_ms",
                    "worker_id",
                )
            ):
                raise ValueError("campaign proof timing type")
            if (
                not (
                    0
                    <= row["admit_ns"]
                    <= row["start_ns"]
                    <= row["commit_start_ns"]
                    <= row["commit_end_ns"]
                    <= row["observe_end_ns"]
                    <= row["end_ns"]
                )
                or row["end_ns"] < last_end
            ):
                raise ValueError("campaign observation order/timing")
            if (
                abs(
                    row["verification_time_ms"]
                    - header["started_wall_ms"]
                    - row["observe_end_ns"] // 1_000_000
                )
                > 1000
            ):
                raise ValueError("campaign wall/monotonic clock skew")
            for pacing_key, proof_key in (
                ("admitted_ns", "admit_ns"),
                ("started_ns", "start_ns"),
                ("commit_end_ns", "commit_end_ns"),
                ("end_ns", "end_ns"),
                ("worker_id", "worker_id"),
            ):
                if pace[pacing_key] != row[proof_key]:
                    raise ValueError("campaign timing proof substitution")
            d._verify_operation(
                row,
                header,
                stream,
                trust,
                certificates,
                expected_payload_builder=None
                if _numeric_policy is None
                else _numeric_policy.payload_builder,
            )
            last_end = row["end_ns"]
            operations[pace["slot_index"]] = entry
            accounting_rows.append(pace)
        elif entry["type"] == "overload":
            if (
                set(entry) != {"type", "pacing"}
                or entry["pacing"].get("outcome") != "overload"
            ):
                raise ValueError("campaign overload envelope mismatch")
            accounting_rows.append(entry["pacing"])
        else:
            raise ValueError("unknown campaign row")
    accounting = verify_accounting(
        plan,
        sorted(accounting_rows, key=lambda row: cast(int, row["slot_index"])),
        worker_ids=header["worker_ids"],
        claimed_counts=footer["accounting"],
        failure_prefix=_numeric_policy is not None and _numeric_policy.failure_audit,
        slot_hard_ceiling_ns=None if _numeric_policy is None else 225_000_000,
    )
    if len(operations) != accounting.committed:
        raise ValueError("campaign committed proof count mismatch")
    # Reusing a lane for a later workflow requires all 100 previous proofs.
    by_chain: dict[int, list[dict[str, Any]]] = {}
    for entry in operations.values():
        by_chain.setdefault(entry["pacing"]["chain_index"], []).append(entry["pacing"])
    for chain, rows in by_chain.items():
        if chain >= 16:
            previous = by_chain.get(chain - 16, [])
            if len(previous) != 100 or min(r["admitted_ns"] for r in rows) < max(
                r["end_ns"] for r in previous
            ):
                raise ValueError("campaign incomplete lane rotation")
    last_decision = max(
        (row.get("decision_ns", 0) for row in accounting_rows), default=0
    )
    if type(footer["elapsed_ns"]) is not int or footer["elapsed_ns"] < max(
        (
            0
            if _numeric_policy is not None and _numeric_policy.failure_audit
            else plan.duration_ns
        ),
        last_end,
        last_decision,
    ):
        raise ValueError("campaign elapsed time/window truncation")
    if footer["campaign_eligible"] is not False:
        raise ValueError("campaign qualification substitution")
    if _renewal_policy is not None:
        _renewal_policy.check_footer(header, footer, stream, trust, certificates)
    state.update(header=header, accounting=accounting, elapsed_ns=footer["elapsed_ns"])
    return {
        "ledger_path": str(path),
        "ledger_sha256": expected_sha256,
        "accounting": asdict(accounting),
        "operation_floor_passed": accounting.on_time_commits >= plan.operation_floor
        and accounting.late_completions == 0,
        "campaign_eligible": False,
    }


def verify_repetition(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if d._sha(raw) != expected_sha256:
        raise ValueError("repetition external digest mismatch")
    manifest = json.loads(raw)
    if (
        d._json(manifest) + b"\n" != raw
        or set(manifest)
        != {"revision", "repetition_id", "windows", "campaign_eligible"}
        or manifest["revision"] != "w2-repetition-v1"
        or manifest["campaign_eligible"] is not False
        or type(manifest["windows"]) is not list
        or not 1 <= len(manifest["windows"]) <= 4
    ):
        raise ValueError("invalid repetition manifest")
    results = []
    prior = None
    for index, link in enumerate(manifest["windows"]):
        if (
            type(link) is not dict
            or set(link) != {"filename", "sha256"}
            or link["filename"] != f"window-{index:03d}.jsonl"
        ):
            raise ValueError("invalid repetition ledger order")
        ledger = path.parent / link["filename"]
        if ledger.is_symlink():
            raise ValueError("repetition ledger symlink rejected")
        header = json.loads(ledger.read_bytes().splitlines()[0])
        if (
            header["repetition_id"] != manifest["repetition_id"]
            or header["window_index"] != index
            or header["previous_ledger"] != prior
            or len(header["window_plans"]) != len(manifest["windows"])
        ):
            raise ValueError("repetition identity/link substitution")
        results.append(verify_ledger(ledger, expected_sha256=link["sha256"]))
        prior = link
    return {
        "manifest_path": str(path),
        "manifest_sha256": expected_sha256,
        "windows": results,
        "campaign_eligible": False,
    }


def _repetition_lifetime(plans: tuple[WindowPlan, ...]) -> int:
    if (
        type(plans) is not tuple
        or not 1 <= len(plans) <= 4
        or any(type(plan) is not WindowPlan for plan in plans)
    ):
        raise ValueError("repetition requires one to four explicit window plans")
    lifetime = max(
        300_000,
        (sum(p.duration_ns + p.drain_ns for p in plans) + 999_999) // 1_000_000
        + 100_000,
    )
    if lifetime > 1_200_000:
        raise ValueError("campaign repetition exceeds existing observer lifetime bound")
    return lifetime


def run_window(
    output_dir: Path, *, plan: WindowPlan, cancel: threading.Event | None = None
) -> dict[str, Any]:
    return run_repetition(output_dir, plans=(plan,), cancel=cancel)["windows"][0]


def run_repetition(
    output_dir: Path,
    *,
    plans: tuple[WindowPlan, ...],
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Execute a fresh isolated repetition. Failed/cancelled prefixes are unsealed."""
    lifetime = _repetition_lifetime(plans)
    directory = output_dir.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = provenance()
    run_id = secrets.token_hex(12)
    child, observer_config, _, controller, private_paths = d.q._configuration(
        directory, run_id, launch_lifetime_ms=lifetime
    )
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]
    root = child.authority.producer_trust[0].scope[2]
    bindings = tuple(
        TrustBinding(
            TrustRole.PRODUCER,
            (f"agent-{i:03d}", "authority:w2:producer", root),
            f"producer-key-{i:03d}",
            d._public(key),
        )
        for i, key in enumerate(producers)
    )
    child = replace(
        child,
        authority=replace(
            child.authority,
            producer_trust=bindings,
            causal_profile=AuthorityCausalProfile.W2_LINEAR_100,
        ),
    )
    observer_config = replace(observer_config, experiment_id=d._EXPERIMENT)
    authority = observer = pool = None
    stop = cancel if cancel is not None else threading.Event()
    ordered = threading.Condition()
    snapshot_lock = threading.Lock()
    failed: list[BaseException] = []
    payloads: dict[int, Any] = {}
    dags: dict[int, TaskDAG] = {}
    try:
        authority = start_authority(child)
        # Workflow registration precedes the measured clock; it is recorded as
        # setup, never counted as admitted workload or hidden in operation latency.
        for chain in range(sum(plan.scheduled_operations for plan in plans) // 100):
            if stop.is_set():
                raise InterruptedError("campaign cancelled during provisioning")
            values = [d.build_payloads(chain, node) for node in range(100)]
            workflow = f"workflow-{run_id}-{chain:03d}"
            dag = TaskDAG(dag_id=workflow)
            for node, _ in values:
                dag = dag.add_node(node)
            authority.admin_client.create_workflow(
                workflow_id=workflow,
                nodes={node.node_id: tuple(node.depends_on) for node, _ in values},
                policy_version="1",
                required_capabilities={node.node_id: () for node, _ in values},
                input_digests={
                    node.node_id: d._sha(d._node_input(node)) for node, _ in values
                },
            )
            for i, producer in enumerate(producers):
                authority.admin_client.register_agent(
                    workflow_id=workflow,
                    agent_id=f"agent-{i:03d}",
                    public_key=producer.public_key(),
                )
            payloads[chain], dags[chain] = values, dag
        observer = start_authority_observer(authority, observer_config)
        for path in private_paths:
            path.unlink(missing_ok=True)
        execution = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        pool = CampaignWorkerPool()
        stream = AuthorityObservationVerificationStream(
            observer.launch_attestation.session_id
        )
        certificates: dict[str, bytes] = {}
        results = []
        chain_offset = 0
        previous_ledger = None
        for window_index, plan in enumerate(plans):
            result = _execute_window(
                directory,
                plan=plan,
                child=child,
                controller=controller,
                source=source,
                run_id=run_id,
                authority=authority,
                observer=observer,
                execution=execution,
                pool=pool,
                stop=stop,
                ordered=ordered,
                snapshot_lock=snapshot_lock,
                failed=failed,
                payloads=payloads,
                dags=dags,
                producers=producers,
                stream=stream,
                certificates=certificates,
                window_index=window_index,
                chain_offset=chain_offset,
                previous_ledger=previous_ledger,
                plans=plans,
            )
            results.append(result)
            if (
                window_index + 1 < len(plans)
                and result["accounting"]["committed"] != plan.scheduled_operations
            ):
                raise ValueError("incomplete window cannot transition to warm")
            previous_ledger = {
                "filename": Path(result["ledger_path"]).name,
                "sha256": result["ledger_sha256"],
            }
            chain_offset += plan.scheduled_operations // 100
        manifest = {
            "revision": "w2-repetition-v1",
            "repetition_id": run_id,
            "windows": [
                {"filename": Path(r["ledger_path"]).name, "sha256": r["ledger_sha256"]}
                for r in results
            ],
            "campaign_eligible": False,
        }
        manifest_path = directory / "repetition.json"
        with manifest_path.open("xb") as file:
            file.write(d._json(manifest) + b"\n")
            file.flush()
            os.fsync(file.fileno())
        return verify_repetition(
            manifest_path, expected_sha256=d._sha(manifest_path.read_bytes())
        )
    finally:
        stop.set()
        with ordered:
            ordered.notify_all()
        with ExitStack() as cleanup:
            for path in private_paths:
                cleanup.callback(path.unlink, missing_ok=True)
            if authority is not None:
                cleanup.callback(authority.close)
            if observer is not None:
                cleanup.callback(observer.close)
            if pool is not None:
                cleanup.callback(pool.close)


def _execute_window(
    directory: Path,
    *,
    plan: WindowPlan,
    child: Any,
    controller: Any,
    source: dict[str, Any],
    run_id: str,
    authority: Any,
    observer: Any,
    execution: Any,
    pool: Any,
    stop: threading.Event,
    ordered: Any,
    snapshot_lock: Any,
    failed: list[BaseException],
    payloads: Any,
    dags: Any,
    producers: Any,
    stream: Any,
    certificates: dict[str, bytes],
    window_index: int,
    chain_offset: int,
    previous_ledger: Any,
    plans: tuple[WindowPlan, ...],
    epoch_context: Callable[[], Any] | None = None,
    header_extension: dict[str, Any] | None = None,
    source_check: Callable[[], dict[str, Any]] | None = None,
    terminal_proof: Callable[[list[dict[str, Any]], dict[str, Any]], Any] | None = None,
    completion_after_release: bool = False,
    numeric_context: Any = None,
) -> dict[str, Any]:
    fatal = threading.Event()
    if numeric_context is not None:
        if not completion_after_release:
            raise ValueError("numeric completion requires actual permit release")
        pool._numeric_fatal = fatal
        numeric_context.check_setup(
            observer.launch_attestation, int(time.time() * 1000), plan
        )
    terminal_completed_ns = None
    pending: list[Future[Any]] = []
    acknowledgments: dict[tuple[int, int], Future[None]] = {}
    completed: dict[int, int] = {}
    lane_owners: dict[int, int] = {}
    entries: list[dict[str, Any]] = []
    next_verified = 0
    ticket_count = 0
    ledger_path = directory / f"window-{window_index:03d}.jsonl"
    public_config = _config_object(child.authority)
    launch = observer.launch_attestation
    header = {
        "type": "header",
        "revision": "w2-campaign-v1",
        "run_id": run_id,
        "repetition_id": run_id,
        "window_index": window_index,
        "window_plans": [asdict(p) for p in plans],
        "phase": "cold" if window_index == 0 else "warm",
        "chain_offset": chain_offset,
        "previous_ledger": previous_ledger,
        "warm_mode": "same-handles-continuation",
        "plan": asdict(plan),
        "capacity": 16,
        "worker_ids": pool.worker_ids,
        "authority_pid": authority.pid,
        "executor_pid": execution.pid,
        "observer_pid": int(launch.observer_pid),
        "controller_pid": os.getpid(),
        "launch": b64u_encode(encode_observer_launch_attestation(launch)),
        "launch_expectations": asdict(d._expectations(launch)),
        "controller_public_key": b64u_encode(d._public(controller)),
        "trust": public_config["bindings"],
        "expected_public_config": public_config,
        "config_sha256": d._sha(d._json(public_config)),
        "observer_experiment": d._EXPERIMENT,
        "config_provenance": "controller expectation; authority checks remain signed APCC proofs",
        "provenance": source,
        "started_wall_ms": int(time.time() * 1000),
    }
    if header_extension is not None:
        if set(header_extension) != {"renewal", "warm_mode"}:
            raise ValueError("invalid opt-in renewal header extension")
        header.update(header_extension)
    trust = ScopedTrust(child.authority.trust_bindings)
    started = time.monotonic_ns()
    if numeric_context is not None:
        wall = int(time.time() * 1000)
        numeric_context.check_setup(launch, wall, plan, now_ns=started)
        header["started_wall_ms"] = wall
        numeric_context.progress["phase"] = "pacing"
        header["numeric_setup"] = {
            "epoch_monotonic_ns": started,
            "controller_origin_monotonic_ns": numeric_context.controller_origin_monotonic_ns,
        }

    def clock() -> int:
        return time.monotonic_ns() - started

    prefix = hashlib.sha256()
    with ledger_path.open("xb") as ledger:

        def append(value: dict[str, Any]) -> None:
            encoded = d._json(value) + b"\n"
            ledger.write(encoded)
            ledger.flush()
            prefix.update(encoded)

        append(header)
        for index in range(plan.scheduled_operations):
            if fatal.is_set():
                break
            slot = plan.slot(index)
            while (
                clock() < slot.scheduled_ns
                and not stop.is_set()
                and not failed
                and not fatal.is_set()
            ):
                stop.wait(min(0.01, (slot.scheduled_ns - clock()) / 1e9))
            if stop.is_set() or failed:
                raise InterruptedError("campaign cancelled or worker failed")
            if fatal.is_set():
                break
            chain, node_index = chain_offset + slot.chain_index, slot.node_index
            reason = "admission_deadline"
            future = None
            while clock() < slot.deadline_ns:
                if fatal.is_set():
                    break
                if stop.is_set() or failed:
                    raise InterruptedError("campaign admission aborted")
                predecessor = acknowledgments.get((chain, node_index - 1))
                if node_index and (predecessor is None or not predecessor.done()):
                    reason = "predecessor_uncommitted"
                    stop.wait(0.001)
                    continue
                if predecessor is not None:
                    predecessor.result()
                lane = chain % 16
                if (
                    lane_owners.get(lane, chain) != chain
                    and completed.get(lane_owners[lane], 0) != 100
                ):
                    reason = "chain_unavailable"
                    stop.wait(0.001)
                    continue
                admit = clock()
                ack: Future[None] = Future()
                ticket = ticket_count

                def operation(
                    chain: int = chain,
                    node_index: int = node_index,
                    lane: int = lane,
                    admit: int = admit,
                    ack: Future[None] = ack,
                    ticket: int = ticket,
                    slot: Any = slot,
                ) -> dict[str, Any]:
                    nonlocal next_verified
                    try:
                        node, artifact = payloads[chain][node_index]
                        begin = clock()
                        with (
                            execution.w2_lane(lane),
                            nullcontext() if epoch_context is None else epoch_context(),
                        ):
                            with snapshot_lock:
                                if stop.is_set() or failed:
                                    raise InterruptedError(
                                        "campaign stopped before mutation"
                                    )
                                if node_index == 0:
                                    execution.load_dag(dags[chain])
                                producer = producers[node_index]
                                authorization = sign_attempt_authorization(
                                    execution.prepare_claim(
                                        node.node_id, artifact.agent_id
                                    ),
                                    producer,
                                )
                                execution.claim(
                                    node.node_id, artifact.agent_id, authorization
                                )
                                payload = execution.produce_result(
                                    node.node_id, artifact, authorization=authorization
                                )
                                request = execution.build_request(
                                    sign_governed_receipt(payload, producer)
                                )
                                commit_start = clock()
                                outcome = d.B6AuthorityAdapter().execute_trusted(
                                    d.TrialStimulus(
                                        payload=request.canonical_hash().encode(
                                            "ascii"
                                        ),
                                        commit_request=request,
                                    ),
                                    execution=execution,
                                )
                                commit_end = clock()
                                if outcome.authoritative_outcome != "committed":
                                    raise ValueError("campaign commit rejected")
                            ack.set_result(None)
                            with ordered:
                                ordered.wait_for(
                                    lambda: (
                                        next_verified == ticket
                                        or bool(failed)
                                        or stop.is_set()
                                    ),
                                    timeout=30,
                                )
                                if next_verified != ticket or failed or stop.is_set():
                                    raise InterruptedError(
                                        "campaign ordered observation aborted"
                                    )
                                nonce = b64u_encode(secrets.token_bytes(16))
                                with snapshot_lock:
                                    target = execution.observation_target(
                                        request, request_nonce=nonce
                                    )
                                    response = observer.client.observe(target)
                                observe_end = clock()
                                row = {
                                    "type": "operation",
                                    "index": ticket,
                                    "chain": chain,
                                    "node_index": node_index,
                                    "worker_id": threading.get_ident(),
                                    "admit_ns": admit,
                                    "start_ns": begin,
                                    "commit_start_ns": commit_start,
                                    "commit_end_ns": commit_end,
                                    "observe_end_ns": observe_end,
                                    "decision": outcome.authoritative_outcome,
                                    "request": _encode_commit_request(request),
                                    "request_hash": request.canonical_hash(),
                                    "nonce": nonce,
                                    "target": target.to_object(),
                                    "observation": b64u_encode(
                                        encode_signed_authority_observation(response)
                                    ),
                                    "verification_time_ms": int(time.time() * 1000),
                                }
                                d._verify_operation(
                                    row,
                                    header,
                                    stream,
                                    trust,
                                    certificates,
                                    expected_payload_builder=None
                                    if numeric_context is None
                                    else numeric_context.payload_builder,
                                )
                                row["end_ns"] = clock()
                                pace = {
                                    **asdict(slot),
                                    "outcome": "committed",
                                    "admitted_ns": admit,
                                    "started_ns": begin,
                                    "commit_end_ns": commit_end,
                                    "end_ns": row["end_ns"],
                                    "worker_id": row["worker_id"],
                                }
                                entry: dict[str, Any] = {
                                    "type": "operation",
                                    "proof": row,
                                    "pacing": pace,
                                }

                                def publish(entry: dict[str, Any]) -> None:
                                    nonlocal next_verified
                                    with ordered:
                                        if completion_after_release:
                                            end = clock()
                                            entry["proof"]["end_ns"] = end
                                            entry["pacing"]["end_ns"] = end
                                        append(entry)
                                        entries.append(entry)
                                        if numeric_context is not None:
                                            numeric_context.progress[
                                                "proofs_completed"
                                            ] += 1
                                        if (
                                            numeric_context is not None
                                            and numeric_context.is_late(
                                                entry["pacing"], plan
                                            )
                                        ):
                                            fatal.set()
                                        completed[chain] = completed.get(chain, 0) + 1
                                        next_verified += 1
                                        ordered.notify_all()

                                if completion_after_release:

                                    def after_release(entry: dict[str, Any]) -> None:
                                        try:
                                            publish(entry)
                                        except BaseException as error:
                                            stop.set()
                                            with ordered:
                                                failed.append(error)
                                                ordered.notify_all()
                                            raise

                                    entry["_after_release"] = after_release
                                else:
                                    publish(entry)
                                return entry
                    except BaseException as error:
                        stop.set()
                        with ordered:
                            failed.append(error)
                            ordered.notify_all()
                        if not ack.done():
                            ack.set_exception(error)
                        raise

                future = pool.submit_before(
                    lambda admitted_ns, operation=operation: operation(
                        admit=admitted_ns
                    ),
                    deadline_ns=slot.deadline_ns,
                    clock=clock,
                )
                if future is not None:
                    lane_owners[lane] = chain
                    acknowledgments[chain, node_index] = ack
                    ticket_count += 1
                    pending.append(future)
                    if numeric_context is not None:
                        numeric_context.progress["admitted"] += 1
                    break
                reason = "permit_exhausted"
                stop.wait(0.001)
            if future is None:
                if fatal.is_set():
                    break
                predecessor = acknowledgments.get((chain, node_index - 1))
                if reason == "predecessor_uncommitted" and predecessor is not None:
                    # The acknowledgement may arrive between the final poll and
                    # deadline expiry, or publication may follow the RPC return.
                    # Only a missing predecessor slot proves no admitted commit.
                    reason = "admission_deadline"
                decision_ns = clock()
                pace = {
                    **asdict(slot),
                    "outcome": "overload",
                    "decision_ns": decision_ns,
                    "reason": reason
                    if decision_ns < plan.duration_ns
                    else "window_closed",
                }
                with (
                    nullcontext() if numeric_context is None else pool._state_lock,
                    ordered,
                ):
                    if fatal.is_set():
                        break
                    entry = {"type": "overload", "pacing": pace}
                    append(entry)
                    entries.append(entry)
                    if numeric_context is not None:
                        numeric_context.progress["overloads"] += 1
                        fatal.set()
        while (
            clock() < plan.duration_ns
            and not stop.is_set()
            and not failed
            and not fatal.is_set()
        ):
            stop.wait(min(0.01, (plan.duration_ns - clock()) / 1e9))
        if stop.is_set() or failed:
            raise InterruptedError("campaign interrupted before drain")
        if numeric_context is not None:
            numeric_context.progress["phase"] = "drain"
        for future in pending:
            future.result()
        account = verify_accounting(
            plan,
            sorted(
                [entry["pacing"] for entry in entries],
                key=lambda row: cast(int, row["slot_index"]),
            ),
            worker_ids=pool.worker_ids,
            failure_prefix=numeric_context is not None and fatal.is_set(),
            slot_hard_ceiling_ns=None if numeric_context is None else 225_000_000,
        )
        footer: dict[str, Any] = {
            "type": "footer",
            "provenance_after": provenance()
            if source_check is None
            else source_check(),
            "prefix_sha256": prefix.hexdigest(),
            "accounting": asdict(account),
            "campaign_eligible": False,
            "elapsed_ns": clock(),
        }
        if numeric_context is not None:
            footer["numeric_outcome"] = {
                "status": "fatal" if fatal.is_set() else "complete",
                "unexecuted": plan.scheduled_operations - len(entries),
                "admitted": len(pending),
            }
        if terminal_proof is not None and not fatal.is_set():
            footer["terminal_proof"] = terminal_proof(entries, header)
            footer["elapsed_ns"] = clock()
            if numeric_context is not None:
                terminal_completed_ns = footer["elapsed_ns"]
                footer["terminal_proof_completed_ns"] = terminal_completed_ns
                if terminal_completed_ns > plan.duration_ns + plan.drain_ns:
                    footer["numeric_outcome"]["status"] = "fatal_drain"
        footer["signature"] = b64u_encode(controller.sign(DOMAIN + d._json(footer)))
        append(footer)
        os.fsync(ledger.fileno())
        ledger_fsync_monotonic_ns = time.monotonic_ns()
    drain_violation = False
    if numeric_context is not None:
        drain_violation = numeric_context.seal_drain(
            directory,
            header,
            ledger_path,
            controller,
            ledger_fsync_monotonic_ns,
            terminal_completed_ns,
        )
    return {
        "ledger_path": str(ledger_path),
        "ledger_sha256": d._sha(ledger_path.read_bytes()),
        "accounting": asdict(account),
        "operation_floor_passed": account.on_time_commits >= plan.operation_floor
        and account.late_completions == 0
        and not drain_violation,
        "campaign_eligible": False,
    }
