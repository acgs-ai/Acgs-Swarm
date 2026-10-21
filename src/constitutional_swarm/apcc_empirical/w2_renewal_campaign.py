"""Functional W2 windows across explicitly fenced observer epochs.

This runner cannot grant numeric qualification. Its external plan binds the
authority-generated renewal key before any workload or observer is admitted.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from concurrent.futures import Future
from contextlib import ExitStack, nullcontext
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    encode_signed_authority_observation,
)
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.verifier import ScopedTrust, TrustBinding, TrustRole
from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan
from constitutional_swarm.apcc_empirical.w2_renewal_codec import w2_config_digest
from constitutional_swarm.apcc_empirical.w2_renewal_evidence import scan_owned_resources
from constitutional_swarm.apcc_empirical.w2_renewal_runtime import (
    W2RenewalConfig,
    start_w2_renewal_authority,
)
from constitutional_swarm.authority_service import _decode_commit_request
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.swarm import TaskDAG


def provenance() -> dict[str, Any]:
    value = c.provenance()
    root = Path(__file__).resolve().parents[3]
    value["files"]["scripts/run_apcc_w2_renewal.py"] = d._sha(
        (root / "scripts/run_apcc_w2_renewal.py").read_bytes()
    )
    return value


class EpochWorkerPool(c.CampaignWorkerPool):
    """Hold a real permit across the authority epoch check and full proof work."""

    def __init__(
        self,
        execution: Any,
        epoch: Any,
        *,
        admission_scope: Any = nullcontext,
        begin_admission: Any = lambda: None,
        end_admission: Any = lambda: None,
    ) -> None:
        self._numeric_fatal: threading.Event | None = None
        self._admission_scope = admission_scope
        self._begin_admission = begin_admission
        self._end_admission = end_admission
        super().__init__()
        self._execution, self._epoch = execution, epoch

    def _worker(self) -> None:
        self.worker_ids.append(threading.get_ident())
        try:
            self._barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            return
        while (job := self._queue.get()) is not None:
            function, future = job
            running = future.set_running_or_notify_cancel()
            result, error = None, None
            try:
                if running:
                    result = function()
            except BaseException as failure:
                error = failure
            finally:
                # Close the recorded interval before another admission can reserve
                # the released permit. Operation proof work has already returned.
                with self._state_lock:
                    self._permits.release()
                    try:
                        if running and error is None and type(result) is dict:
                            callback = result.pop("_after_release", None)
                            if callback is not None:
                                callback(result)
                    except BaseException as failure:
                        error = failure
                    try:
                        self._end_admission()
                    except BaseException as failure:
                        error = failure
            if running:
                if error is not None:
                    future.set_exception(error)
                else:
                    future.set_result(result)

    def submit_before(
        self, function: Any, *, deadline_ns: int, clock: Any
    ) -> Future[Any] | None:
        with self._state_lock, self._admission_scope():
            if (
                self._closed
                or (self._numeric_fatal is not None and self._numeric_fatal.is_set())
                or not self._permits.acquire(blocking=False)
            ):
                return None
            registered = queued = False
            try:
                self._begin_admission()
                registered = True
                with self._epoch():
                    self._execution.check_w2_admission_epoch()
                admitted = clock()
                if admitted >= deadline_ns:
                    return None
                future: Future[Any] = Future()
                self._queue.put((lambda: function(admitted), future))
                queued = True
                return future
            finally:
                if not queued:
                    self._permits.release()
                    if registered:
                        self._end_admission()

    def submit(self, function: Any) -> Any:
        raise ValueError("renewal workers require epoch-bound paced admission")


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _functional_limits(
    plans: tuple[WindowPlan, ...], handover_timeout_ms: int
) -> dict[str, str]:
    if (
        type(plans) is not tuple
        or not 2 <= len(plans) <= 5
        or any(type(p) is not WindowPlan or p.qualification for p in plans)
        or type(handover_timeout_ms) is not int
        or not 1 <= handover_timeout_ms <= 10_000
    ):
        raise ValueError(
            "functional renewal requires two to five explicit nonqualifying windows"
        )
    if any(p.duration_ns + p.drain_ns >= 1_100_000_000_000 for p in plans):
        raise ValueError("functional window does not fit the unchanged observer cap")
    total = sum((p.duration_ns + p.drain_ns + 999_999) // 1_000_000 for p in plans)
    total += len(plans) * 100_000 + (len(plans) - 1) * handover_timeout_ms
    if total > len(plans) * 1_200_000:
        raise ValueError("functional repetition exceeds finite epoch budget")
    return {
        "maximum_renewals": str(len(plans) - 1),
        "maximum_total_lifetime_ms": str(total),
        "maximum_single_launch_ms": str(min(1_200_000, total)),
        "handover_timeout_ms": str(handover_timeout_ms),
    }


def run_repetition(
    output_dir: Path,
    *,
    plans: tuple[WindowPlan, ...],
    handover_timeout_ms: int = 10_000,
    cancel: threading.Event | None = None,
    numeric_context: Any = None,
) -> dict[str, Any]:
    """Run real clocks; seal only complete repetitions, always ineligible."""
    limits = (
        _functional_limits(plans, handover_timeout_ms)
        if numeric_context is None
        else numeric_context.limits(plans)
    )
    directory = output_dir.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = provenance() if numeric_context is None else numeric_context.provenance()
    if numeric_context is not None:
        numeric_context.begin_setup()
    run_id = secrets.token_hex(12)
    lifetime = min(
        1_200_000, (plans[0].duration_ns + plans[0].drain_ns) // 1_000_000 + 100_000
    )
    if numeric_context is not None:
        lifetime = 1_200_000
    child, launch, _, controller, private_paths = d.q._configuration(
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
    launch = replace(launch, experiment_id=d._EXPERIMENT)
    config = W2RenewalConfig(
        plan_digest=sha256_digest(b"unbound-w2-bootstrap"),
        journal_path=str(directory / "private-journal" / "journal.jsonl"),
        repetition_id=run_id,
        controller_public_key=d._public(controller),
        experiment_id=d._EXPERIMENT,
        run_id=run_id,
        **{key: int(value) for key, value in limits.items()},
    )
    plan_path = directory / "renewal-plan.json"

    def bind_plan(key_info: dict[str, Any]) -> str:
        if set(key_info) != {
            "renewal_key_id",
            "renewal_public_key",
            "authority_session_id",
        }:
            raise ValueError("renewal bootstrap key proof fields mismatch")
        public = {
            "revision": "w2-renewal-functional-v1",
            "repetition_id": run_id,
            "authority_store_id": child.authority.authority_store_id,
            **key_info,
            "controller_public_key": b64u_encode(d._public(controller)),
            "config_digest": w2_config_digest(child.authority),
            "profile": "W2_LINEAR_100",
            "limits": limits,
            "windows": [asdict(p) for p in plans],
            "campaign_eligible": False,
        }
        if numeric_context is not None:
            numeric_context.install(directory)
            public["revision"] = "w2-numeric-cold-v1"
            public["numeric"] = numeric_context.runtime_binding
        raw = d._json(public) + b"\n"
        _write(plan_path, raw)
        return sha256_digest(raw)

    stop = cancel if cancel is not None else threading.Event()
    ordered, snapshot_lock = threading.Condition(), threading.Lock()
    failed: list[BaseException] = []
    service = pool = None
    owned: list[int] = []
    payloads: dict[int, Any] = {}
    dags: dict[int, TaskDAG] = {}
    try:

        def on_spawn(role: str, pid: int) -> None:
            owned.append(pid)
            with (directory / "owned-processes.jsonl").open("ab") as file:
                file.write(d._json({"role": role, "pid": pid}) + b"\n")
                file.flush()
                os.fsync(file.fileno())

        service = start_w2_renewal_authority(
            child, config, launch, plan_builder=bind_plan, on_spawn=on_spawn
        )
        if numeric_context is not None:
            numeric_context.check_setup(
                service.observer.launch_attestation, int(time.time() * 1000), plans[0]
            )
        for path in private_paths:
            path.unlink(missing_ok=True)
        if numeric_context is not None:
            numeric_context.progress["phase"] = "setup"
        for chain in range(sum(p.scheduled_operations for p in plans) // 100):
            if stop.is_set():
                raise InterruptedError("renewal cancelled during setup")
            values = [
                (
                    d.build_payloads
                    if numeric_context is None
                    else numeric_context.payload_builder
                )(chain, node)
                for node in range(100)
            ]
            workflow = f"workflow-{run_id}-{chain:03d}"
            dag = TaskDAG(dag_id=workflow)
            for node, _ in values:
                dag = dag.add_node(node)
            if numeric_context is not None:
                numeric_context.check_setup(
                    service.observer.launch_attestation,
                    int(time.time() * 1000),
                    plans[0],
                )
            service.admin_client.create_workflow(
                workflow_id=workflow,
                nodes={node.node_id: tuple(node.depends_on) for node, _ in values},
                policy_version="1",
                required_capabilities={node.node_id: () for node, _ in values},
                input_digests={
                    node.node_id: d._sha(d._node_input(node)) for node, _ in values
                },
            )
            if numeric_context is not None:
                numeric_context.check_setup(
                    service.observer.launch_attestation,
                    int(time.time() * 1000),
                    plans[0],
                )
            if numeric_context is not None:
                numeric_context.progress["workflows_created"] += 1
            for i, producer in enumerate(producers):
                if numeric_context is not None:
                    numeric_context.check_setup(
                        service.observer.launch_attestation,
                        int(time.time() * 1000),
                        plans[0],
                    )
                service.admin_client.register_agent(
                    workflow_id=workflow,
                    agent_id=f"agent-{i:03d}",
                    public_key=producer.public_key(),
                )
                if numeric_context is not None:
                    numeric_context.progress["agents_registered"] += 1
                if numeric_context is not None:
                    numeric_context.check_setup(
                        service.observer.launch_attestation,
                        int(time.time() * 1000),
                        plans[0],
                    )
            payloads[chain], dags[chain] = values, dag
        if numeric_context is not None:
            numeric_context.check_setup(
                service.observer.launch_attestation, int(time.time() * 1000), plans[0]
            )
        execution = service.spawn_executor(CapabilityRegistry(), policy_version="1")

        def epoch_context() -> Any:
            return execution.w2_epoch(service.epoch, service.config.plan_digest)

        pool = EpochWorkerPool(
            execution,
            epoch_context,
            admission_scope=service.admission_scope,
            begin_admission=service.begin_admission,
            end_admission=service.end_admission,
        )
        results, offset, previous, continuity = [], 0, None, None
        certificates: dict[str, bytes] = {}
        for index, plan in enumerate(plans):
            if numeric_context is not None:
                numeric_context.check_setup(
                    service.observer.launch_attestation, int(time.time() * 1000), plan
                )
            evidence = service.evidence()
            if numeric_context is not None:
                numeric_context.check_setup(
                    service.observer.launch_attestation, int(time.time() * 1000), plan
                )
            observer = service.observer
            stream = AuthorityObservationVerificationStream(
                observer.launch_attestation.session_id
            )

            def terminal(entries: list[dict[str, Any]], header: dict[str, Any]) -> Any:
                operations = [
                    entry["proof"] for entry in entries if entry["type"] == "operation"
                ]
                if not operations:
                    raise ValueError("renewal cannot seal an empty authority stream")
                row = dict(operations[-1])
                nonce = b64u_encode(secrets.token_bytes(16))
                with (
                    epoch_context(),
                    execution.w2_lane(row["chain"] % 16),
                    snapshot_lock,
                ):
                    target = execution.observation_target(
                        _decode_commit_request(row["request"]), request_nonce=nonce
                    )
                    response = observer.client.observe(target)
                row.update(
                    nonce=nonce,
                    target=target.to_object(),
                    observation=b64u_encode(
                        encode_signed_authority_observation(response)
                    ),
                    verification_time_ms=int(time.time() * 1000),
                )
                d._verify_operation(
                    row,
                    header,
                    stream,
                    ScopedTrust(child.authority.trust_bindings),
                    certificates,
                    expected_payload_builder=None
                    if numeric_context is None
                    else numeric_context.payload_builder,
                )
                return row

            result = c._execute_window(
                directory,
                plan=plan,
                child=child,
                controller=controller,
                source=source,
                run_id=run_id,
                authority=service.authority,
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
                window_index=index,
                chain_offset=offset,
                previous_ledger=previous,
                plans=plans,
                epoch_context=epoch_context,
                header_extension={
                    "warm_mode": "renewed-observer-epochs-v1",
                    "renewal": {
                        "plan_sha256": d._sha(plan_path.read_bytes()),
                        "epoch": service.epoch,
                        "authority_session_id": evidence["authority_session_id"],
                        "delegation": evidence["delegation"],
                        "records": evidence["records"],
                        "continuity": continuity,
                        "checkpoint": evidence["checkpoint_proof"],
                        "initial_checkpoint_proof": evidence[
                            "initial_checkpoint_proof"
                        ],
                    },
                },
                source_check=provenance
                if numeric_context is None
                else numeric_context.provenance,
                terminal_proof=terminal,
                completion_after_release=True,
                numeric_context=numeric_context,
            )
            results.append(result)
            footer = json.loads(
                Path(result["ledger_path"]).read_bytes().splitlines()[-1]
            )
            previous = {
                "filename": Path(result["ledger_path"]).name,
                "sha256": result["ledger_sha256"],
            }
            offset += plan.scheduled_operations // 100
            if index + 1 < len(plans):
                if (
                    result["accounting"]["committed"] != plan.scheduled_operations
                    or result["accounting"]["late_completions"]
                ):
                    raise ValueError("incomplete or late window cannot renew")
                if snapshot_lock.locked():
                    raise ValueError("renewal snapshot lock not drained")
                renewed = service.renew(
                    final_observation=b64u_decode(
                        footer["terminal_proof"]["observation"]
                    ),
                    ledger_digest=sha256_digest(
                        Path(result["ledger_path"]).read_bytes()
                    ),
                    ledger_seal_digest=sha256_digest(d._json(footer)),
                    launch_lifetime_ms=min(
                        1_200_000,
                        (plans[index + 1].duration_ns + plans[index + 1].drain_ns)
                        // 1_000_000
                        + 100_000,
                    ),
                )
                continuity = renewed["continuity"]
        final = service.evidence()
        journal = b"".join(d._json(record) + b"\n" for record in final["records"])
        _write(directory / "renewal-journal.jsonl", journal)
        manifest = {
            "revision": "w2-renewal-repetition-v1",
            "repetition_id": run_id,
            "plan": {
                "filename": plan_path.name,
                "sha256": d._sha(plan_path.read_bytes()),
            },
            "windows": [
                {"filename": Path(r["ledger_path"]).name, "sha256": r["ledger_sha256"]}
                for r in results
            ],
            "journal": {
                "filename": "renewal-journal.jsonl",
                "sha256": d._sha(journal),
                "tip_digest": sha256_digest(d._json(final["records"][-1])),
            },
            "campaign_eligible": False,
        }
        if numeric_context is not None:
            manifest["revision"] = "w2-numeric-cold-result-v1"
            manifest["numeric"] = numeric_context.binding
            manifest["drain_witness"] = {
                "filename": "drain-witness.json",
                "sha256": d._sha((directory / "drain-witness.json").read_bytes()),
            }
            manifest["status"] = (
                "complete" if results[0]["operation_floor_passed"] else "fatal"
            )
        _write(directory / "repetition.json", d._json(manifest) + b"\n")
        return {
            "manifest_path": str(directory / "repetition.json"),
            "manifest_sha256": d._sha((directory / "repetition.json").read_bytes()),
            "plan_sha256": d._sha(plan_path.read_bytes()),
            "windows": results,
            "campaign_eligible": False,
        }
    except BaseException as error:
        if numeric_context is not None:
            numeric_context.primary_error = error
            numeric_context.failure_phase = numeric_context.progress["phase"]
        raise
    finally:
        if numeric_context is not None:
            numeric_context.progress["phase"] = "cleanup"
        stop.set()
        with ordered:
            ordered.notify_all()
        if service is not None:
            owned = sorted(set(owned) | set(service.owned_pids))

        def cleanup_action(function: Any, *args: Any, **kwargs: Any) -> None:
            try:
                function(*args, **kwargs)
            except BaseException as error:
                if numeric_context is not None:
                    numeric_context.cleanup_errors.append(error)
                raise

        try:
            with ExitStack() as cleanup:
                for path in private_paths:
                    cleanup.callback(cleanup_action, path.unlink, missing_ok=True)
                if service is not None:
                    cleanup.callback(cleanup_action, service.close)
                if pool is not None:
                    cleanup.callback(cleanup_action, pool.close)
        finally:
            resource = scan_owned_resources(directory, owned_pids=owned)
            resource["owned_pids"] = sorted(set(owned))
            self_descriptors = []
            for descriptor in Path("/proc/self/fd").iterdir():
                try:
                    target = Path(os.readlink(descriptor))
                except FileNotFoundError:
                    continue
                if target.is_absolute() and target.is_relative_to(directory):
                    self_descriptors.append(
                        {
                            "fd": int(descriptor.name),
                            "path": str(target.relative_to(directory)),
                        }
                    )
            resource["controller_run_descriptors"] = self_descriptors
            resource["owned_cleanup_proven"] = (
                bool(owned)
                and resource["owned_pids_absent"]
                and not self_descriptors
                and not resource["unavailable_owned_pids"]
            )
            resource["owned_scope"] = (
                "Exact spawned authority, scheduler, signer and observer processes plus controller descriptors; SQLite handles are not exported. Unrelated host FD visibility remains separate."
            )
            _write(directory / "cleanup.json", d._json(resource) + b"\n")
            if not resource["owned_cleanup_proven"]:
                raise RuntimeError("owned renewal cleanup could not be proven")
