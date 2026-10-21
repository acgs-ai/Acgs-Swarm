"""Noncampaign W2 chain diagnostics with controller-sealed, replayable proofs."""

from __future__ import annotations
import base64
import hashlib
import json
import os
import platform
import sqlite3
import sys
import secrets
import threading
import time
from collections.abc import Mapping, Callable
from concurrent.futures import Future
from dataclasses import asdict, replace
from pathlib import Path
from queue import Queue
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from constitutional_swarm.apcc.codec import canonical_statement, decode_envelope
from constitutional_swarm.apcc.crypto import (
    PROPOSAL_DOMAIN,
    b64u_decode,
    b64u_encode,
    domain_preimage,
    sha256_digest,
)
from constitutional_swarm.apcc.model import CertificateSubject, Signature
from constitutional_swarm.apcc.observation import (
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
    ObserverLaunchExpectationsV1,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    encode_observer_launch_attestation,
    encode_signed_authority_observation,
)
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.sqlite_store import (
    _operation_from_json,
    _operation_identity,
    _config_object,
    _config_from_object,
)
from constitutional_swarm.apcc.verifier import (
    ScopedTrust,
    TrustBinding,
    TrustRole,
    CausalClosureLimits,
    verify_causal_closure,
)
from constitutional_swarm.apcc_empirical import qualification_v3 as q
from constitutional_swarm.apcc_empirical.qualification_v3 import (
    _json,
    _sha,
    _public,
    _node_input,
    _expectations,
    _trust,
    _verify_governed_verdict,
)
from constitutional_swarm.apcc_empirical.adapters import (
    B6AuthorityAdapter,
    TrialStimulus,
)
from constitutional_swarm.artifact import Artifact
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
from constitutional_swarm.swarm import TaskDAG, TaskNode

_DOMAIN = b"APCC-1.w2-driver-v1.ledger\x00"
_EXPERIMENT = "apcc-1-w2-diagnostic"


class WorkerPool:
    """Sixteen live workers; admission never queues beyond sixteen permits."""

    def __init__(self) -> None:
        self._permits = threading.BoundedSemaphore(16)
        self._queue: Queue[Any] = Queue()
        self._barrier = threading.Barrier(17)
        self.worker_ids: list[int] = []
        self._closed = False
        self._state_lock = threading.Lock()
        self._threads = [
            threading.Thread(target=self._worker, name=f"w2-worker-{i}")
            for i in range(16)
        ]
        started: list[threading.Thread] = []
        try:
            for thread in self._threads:
                thread.start()
                started.append(thread)
            self._barrier.wait(timeout=30)
        except BaseException:
            self._closed = True
            self._barrier.abort()
            for _ in started:
                self._queue.put(None)
            for thread in started:
                thread.join()
            raise
        self.worker_ids.sort()

    def _worker(self) -> None:
        self.worker_ids.append(threading.get_ident())
        try:
            self._barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            return
        while (job := self._queue.get()) is not None:
            function, future = job
            if not future.set_running_or_notify_cancel():
                self._permits.release()
                continue
            try:
                result = function()
            except BaseException as error:
                self._permits.release()
                future.set_exception(error)
            else:
                self._permits.release()
                future.set_result(result)

    def submit(self, function: Callable[[], Any]) -> Future[Any] | None:
        with self._state_lock:
            if self._closed or not self._permits.acquire(blocking=False):
                return None
            future: Future[Any] = Future()
            self._queue.put((function, future))
            return future

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            for _ in self._threads:
                self._queue.put(None)
        for thread in self._threads:
            thread.join()


class _Resolver:
    def __init__(self, certificates: dict[str, bytes]) -> None:
        self.certificates = certificates

    def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
        return self.certificates.get(certificate_digest)


def build_payloads(chain: int, index: int) -> tuple[TaskNode, Artifact]:
    node = TaskNode(
        node_id=f"node-{index:03d}",
        title="W2",
        depends_on=(f"node-{index - 1:03d}",) if index else (),
    )
    node = replace(node, description="x" * (1024 - len(_node_input(node))))
    artifact = Artifact(
        f"artifact-{chain:03d}-{index:03d}",
        node.node_id,
        f"agent-{index:03d}",
        "text/plain",
        "",
        timestamp=0.0,
    )
    artifact = replace(
        artifact, content="x" * (4096 - len(_json(artifact.canonical_dict())))
    )
    if len(_node_input(node)) != 1024 or len(_json(artifact.canonical_dict())) != 4096:
        raise ValueError("W2 payload size mismatch")
    return node, artifact


def _expected_payload_bytes(
    chain: int, index: int, builder: Any = None
) -> tuple[bytes, bytes]:
    node, artifact = (build_payloads if builder is None else builder)(chain, index)
    input_bytes, output_bytes = _node_input(node), _json(artifact.canonical_dict())
    if len(input_bytes) != 1024 or len(output_bytes) != 4096:
        raise ValueError("expected payload builder violates fixed canonical byte sizes")
    return input_bytes, output_bytes


def _verify_operation(
    row: Mapping[str, Any],
    header: Mapping[str, Any],
    stream: AuthorityObservationVerificationStream,
    trust: ScopedTrust,
    certificates: dict[str, bytes],
    *,
    expected_payload_builder: Any = None,
) -> None:
    request = _decode_commit_request(row["request"])
    response = decode_signed_authority_observation(b64u_decode(row["observation"]))
    target, payload = response.snapshot.request, request.receipt.payload
    if (
        request.canonical_hash() != row["request_hash"]
        or row["decision"] != "committed"
    ):
        raise ValueError("commit identity or decision mismatch")
    if (
        target.workflow_id,
        target.node_id,
        target.attempt_id,
        target.expected_commit_id,
        target.request_nonce,
    ) != (
        payload.workflow_id,
        payload.node_id,
        payload.attempt_id,
        request.commit_id,
        row["nonce"],
    ):
        raise ValueError("observation target identity mismatch")
    if target.to_object() != row["target"]:
        raise ValueError("observation target substitution")
    _verify_governed_verdict(request, header, row["verification_time_ms"])
    persisted = response.snapshot.persisted_operation_bytes
    if persisted is None:
        raise ValueError("missing persisted operation binding")
    atomic, superseded = _operation_from_json(persisted.decode("utf-8"))
    producer_bytes = canonical_statement(atomic.evidence.producer_statement)
    expected_subject = CertificateSubject(
        payload.workflow_id,
        payload.node_id,
        payload.attempt_id,
        payload.agent_id,
        payload.authority_snapshot_digest,
        payload.input_digest,
        payload.output_digest,
    )
    expected_signature = Signature(
        "Ed25519",
        payload.key_id,
        b64u_encode(base64.b64decode(request.receipt.signature, validate=True)),
    )
    if (
        superseded is not None
        or atomic.commit_id != request.commit_id
        or atomic.nonce != payload.nonce
        or atomic.subject != expected_subject
        or atomic.signatures.producer != expected_signature
        or domain_preimage(PROPOSAL_DOMAIN, producer_bytes) != payload.canonical_bytes()
        or _operation_identity(atomic, superseded) != target.expected_operation_digest
        or sha256_digest(persisted) != target.expected_operation_digest
        or sha256_digest(producer_bytes) != target.public_request_digest
    ):
        raise ValueError("persisted operation does not bind exact governed request")
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    result = stream.consume(
        response,
        launch=launch,
        pinned_controller_public_key=b64u_decode(
            header["controller_public_key"], expected_length=32
        ),
        expected_experiment_id=_EXPERIMENT,
        expected_run_id=header["run_id"],
        expected_launch=ObserverLaunchExpectationsV1(**header["launch_expectations"]),
        trust=trust,
        now_ms=row["verification_time_ms"],
        maximum_staleness_ms=5000,
    )
    output = response.snapshot.output_bytes
    if (
        response.snapshot.state is not AuthorityObservationState.COMMITTED
        or not result.consumable
        or result.authority_proof
        is not ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
        or output is None
        or len(output) != 4096
        or sha256_digest(output) != payload.output_digest
    ):
        raise ValueError("operation lacks consumable authoritative output proof")
    input_bytes, expected_output = _expected_payload_bytes(
        row["chain"], row["node_index"], expected_payload_builder
    )
    if output != expected_output or payload.input_digest != sha256_digest(input_bytes):
        raise ValueError("operation violates fixed payload contract")

    envelope = response.snapshot.certificate_envelope_bytes
    assert envelope is not None
    closure = verify_causal_closure(
        envelope,
        trust=trust,
        resolver=_Resolver(certificates),
        limits=CausalClosureLimits(max_depth=99),
    )
    if not closure.ok or closure.certificate is None:
        raise ValueError("invalid W2 causal closure")
    certificate = closure.certificate
    previous = row["node_index"] - 1
    references = certificate.bindings.predecessors
    if previous < 0:
        if references:
            raise ValueError("root has predecessor")
    else:
        if (
            len(references) != 1
            or references[0].workflow_id != payload.workflow_id
            or references[0].node_id != f"node-{previous:03d}"
        ):
            raise ValueError("W2 predecessor topology mismatch")
    certificates[decode_envelope(envelope).payload_sha256] = envelope


def _source_provenance() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[3]
    paths = sorted((root / "src" / "constitutional_swarm").rglob("*.py"))
    paths += [
        root / name
        for name in (
            "pyproject.toml",
            "uv.lock",
            "docs/internal/APCC-1-Protocol-Spec.md",
            "docs/internal/APCC-1-Qualification-Live-Protocol-v3.md",
            "experiments/apcc-1/matrix.v2.json",
            "experiments/apcc-1/raw-result.v2.schema.json",
            "experiments/apcc-1/qualification-live.v3.json",
            "scripts/run_apcc_w2_diagnostic.py",
        )
    ]
    return {
        "files": {
            str(path.relative_to(root)): _sha(path.read_bytes()) for path in paths
        },
        "python": sys.version,
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
    }


def verify_ledger(
    path: Path,
    *,
    expected_sha256: str | None = None,
    expected_provenance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Independently replay every proof and full closure without a verification cache."""
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    if expected_sha256 is not None and _sha(raw) != expected_sha256:
        raise ValueError("ledger digest mismatch")
    if len(lines) < 102 or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("unsealed or truncated W2 ledger")
    values = [json.loads(line) for line in lines]
    if any(
        _json(value) + b"\n" != line for value, line in zip(values, lines, strict=True)
    ):
        raise ValueError("noncanonical W2 ledger")
    header, footer = values[0], values[-1]
    if header["provenance"] != footer["provenance_after"] or (
        expected_provenance is not None and header["provenance"] != expected_provenance
    ):
        raise ValueError("W2 source provenance changed")
    for field in (
        "chains",
        "capacity",
        "authority_pid",
        "observer_pid",
        "executor_pid",
        "controller_pid",
        "started_wall_ms",
    ):
        if type(header[field]) is not int or header[field] <= 0:
            raise ValueError("invalid W2 header integer")
    for field in ("verified_operations", "maximum_occupancy", "elapsed_ns"):
        if type(footer[field]) is not int or footer[field] < 0:
            raise ValueError("invalid W2 footer integer")
    if any(type(item) is not int or item <= 0 for item in header["worker_ids"]):
        raise ValueError("invalid W2 worker identity")
    body = {key: value for key, value in footer.items() if key != "signature"}
    if (
        header["revision"] != "w2-driver-v1"
        or header["mode"] != "diagnostic"
        or header["chains"] not in (1, 2)
        or header["capacity"] != 16
        or len(header["worker_ids"]) != 16
        or len(set(header["worker_ids"])) != 16
    ):
        raise ValueError("invalid W2 envelope")
    if footer["type"] != "footer" or body["prefix_sha256"] != _sha(
        b"".join(lines[:-1])
    ):
        raise ValueError("W2 seal prefix mismatch")
    Ed25519PublicKey.from_public_bytes(
        b64u_decode(header["controller_public_key"], expected_length=32)
    ).verify(
        b64u_decode(footer["signature"], expected_length=64), _DOMAIN + _json(body)
    )
    config = header["expected_public_config"]
    parsed_config = _config_from_object(config)
    if (
        _config_object(parsed_config) != config
        or parsed_config.authority_store_id
        != header["launch_expectations"]["authority_store_id"]
    ):
        raise ValueError("W2 configuration mismatch")
    if config["causal_profile"] != AuthorityCausalProfile.W2_LINEAR_100.value or header[
        "config_sha256"
    ] != _sha(_json(config)):
        raise ValueError("W2 profile mismatch")
    producers = [item for item in header["trust"] if item["role"] == "producer"]
    if (
        len(producers) != 100
        or len({item["public_key"] for item in producers}) != 100
        or [item["scope"][0] for item in producers]
        != [f"agent-{i:03d}" for i in range(100)]
    ):
        raise ValueError("W2 producer bindings mismatch")
    authority_keys = {
        item["public_key"] for item in header["trust"] if item["role"] != "producer"
    } | {header["controller_public_key"]}
    for index, binding in enumerate(producers):
        if (
            binding["key_id"] != f"producer-key-{index:03d}"
            or binding["scope"][1] != "authority:w2:producer"
            or binding["public_key"] in authority_keys
        ):
            raise ValueError("W2 key role separation mismatch")
    if config["bindings"] != header["trust"]:
        raise ValueError("public configuration trust mismatch")
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    if (
        str(header["observer_pid"]) != launch.observer_pid
        or len(
            {
                header[name]
                for name in (
                    "authority_pid",
                    "observer_pid",
                    "executor_pid",
                    "controller_pid",
                )
            }
        )
        != 4
    ):
        raise ValueError("W2 process identity mismatch")
    stream = AuthorityObservationVerificationStream(launch.session_id)
    trust = _trust(header)
    certificates: dict[str, bytes] = {}
    rows = values[1:-1]
    if len(rows) != header["chains"] * 100 or footer["verified_operations"] != len(
        rows
    ):
        raise ValueError("incomplete W2 chains")
    if type(rows[-1]["end_ns"]) is not int or footer["elapsed_ns"] < rows[-1]["end_ns"]:
        raise ValueError("W2 elapsed time precedes completion")
    previous_commit = previous_end = 0
    commits: set[str] = set()
    nonces: set[str] = set()
    events: list[tuple[int, int]] = []
    worker_end: dict[int, int] = {}
    for index, row in enumerate(rows):
        for field in (
            "index",
            "chain",
            "node_index",
            "worker_id",
            "admit_ns",
            "start_ns",
            "commit_start_ns",
            "commit_end_ns",
            "observe_end_ns",
            "end_ns",
            "verification_time_ms",
        ):
            if type(row[field]) is not int or row[field] < 0:
                raise ValueError("invalid W2 integer field")
        if row["start_ns"] < worker_end.get(row["worker_id"], 0):
            raise ValueError("overlapping W2 worker intervals")
        worker_end[row["worker_id"]] = row["end_ns"]
        chain, node_index = divmod(index, 100)
        request = _decode_commit_request(row["request"])
        payload = request.receipt.payload
        workflow = f"workflow-{header['run_id']}-{chain:03d}"
        if (
            row["type"],
            row["index"],
            row["chain"],
            row["node_index"],
            payload.workflow_id,
            payload.node_id,
            payload.agent_id,
            payload.key_id,
        ) != (
            "operation",
            index,
            chain,
            node_index,
            workflow,
            f"node-{node_index:03d}",
            f"agent-{node_index:03d}",
            f"producer-key-{node_index:03d}",
        ):
            raise ValueError("W2 identity/order mismatch")
        if row["worker_id"] not in header["worker_ids"] or not (
            row["admit_ns"]
            <= row["start_ns"]
            <= row["commit_start_ns"]
            <= row["commit_end_ns"]
            <= row["observe_end_ns"]
            <= row["end_ns"]
        ):
            raise ValueError("invalid W2 worker interval")
        if (
            row["admit_ns"] < previous_commit
            or row["end_ns"] < previous_end
            or (node_index == 0 and row["start_ns"] < previous_end)
        ):
            raise ValueError("W2 commit or rotation overlap")
        if request.commit_id in commits or row["nonce"] in nonces:
            raise ValueError("duplicate W2 identity")
        if (
            abs(
                row["verification_time_ms"]
                - header["started_wall_ms"]
                - row["observe_end_ns"] // 1_000_000
            )
            > 1000
        ):
            raise ValueError("W2 observation clock mismatch")
        commits.add(request.commit_id)
        nonces.add(row["nonce"])
        _verify_operation(row, header, stream, trust, certificates)
        previous_commit, previous_end = row["commit_end_ns"], row["end_ns"]
        events.extend(((row["admit_ns"], 1), (row["end_ns"], -1)))
    occupancy = maximum = 0
    for _, change in sorted(events):
        occupancy += change
        maximum = max(maximum, occupancy)
        if not 0 <= occupancy <= 16:
            raise ValueError("W2 capacity exceeded")
    if (
        not 1 <= footer["maximum_occupancy"] <= 16
        or footer["maximum_occupancy"] != maximum
        or footer["campaign_eligible"] is not False
    ):
        raise ValueError("W2 diagnostic classification mismatch")
    return {**body, "ledger_path": str(path), "ledger_sha256": _sha(raw)}


def run_smoke(
    output_dir: Path,
    *,
    chains: int = 1,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Complete one or two chains on persistent child handles, without campaign rows."""
    if type(chains) is not int or chains not in (1, 2):
        raise ValueError("W2 diagnostics require one or two complete chains")
    provenance = _source_provenance()
    directory = Path(output_dir).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = secrets.token_hex(12)
    child, observer_config, _, controller, private_paths = q._configuration(
        directory, run_id
    )
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]
    root = child.authority.producer_trust[0].scope[2]
    bindings = tuple(
        TrustBinding(
            TrustRole.PRODUCER,
            (f"agent-{i:03d}", "authority:w2:producer", root),
            f"producer-key-{i:03d}",
            _public(key),
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
    observer_config = replace(observer_config, experiment_id=_EXPERIMENT)
    authority = observer = pool = None
    ledger_path = directory / "ledger.jsonl"
    rows: list[dict[str, Any]] = []
    try:
        authority = start_authority(child)
        observer = start_authority_observer(authority, observer_config)
        for path in private_paths:
            path.unlink(missing_ok=True)
        execution = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        pool = WorkerPool()
        launch = observer.launch_attestation
        public_config = _config_object(child.authority)
        header = {
            "type": "header",
            "provenance": provenance,
            "revision": "w2-driver-v1",
            "mode": "diagnostic",
            "run_id": run_id,
            "chains": chains,
            "capacity": 16,
            "worker_ids": pool.worker_ids,
            "authority_pid": authority.pid,
            "executor_pid": execution.pid,
            "observer_pid": int(launch.observer_pid),
            "controller_pid": os.getpid(),
            "launch": b64u_encode(encode_observer_launch_attestation(launch)),
            "launch_expectations": asdict(_expectations(launch)),
            "controller_public_key": b64u_encode(_public(controller)),
            "trust": public_config["bindings"],
            "expected_public_config": public_config,
            "config_sha256": _sha(_json(public_config)),
            "config_provenance": "controller-sealed expectation; not an authority-signed configuration proof",
            "started_wall_ms": int(time.time() * 1000),
        }
        stream = AuthorityObservationVerificationStream(launch.session_id)
        trust = ScopedTrust(child.authority.trust_bindings)
        certificates: dict[str, bytes] = {}
        adapter = B6AuthorityAdapter()
        started = time.monotonic_ns()

        def clock() -> int:
            return time.monotonic_ns() - started

        prefix = hashlib.sha256()
        with ledger_path.open("xb") as ledger:

            def append(value: Mapping[str, Any]) -> None:
                encoded = _json(dict(value)) + b"\n"
                ledger.write(encoded)
                ledger.flush()
                prefix.update(encoded)

            append(header)
            # Commit acknowledgments permit the next dependent node; observation
            # and proof publication remain in one globally ordered critical section.
            ordered = threading.Condition()
            snapshot_lock = threading.Lock()
            next_verified = 0
            failed: list[BaseException] = []
            for chain in range(chains):
                payloads = [build_payloads(chain, i) for i in range(100)]
                workflow = f"workflow-{run_id}-{chain:03d}"
                dag = TaskDAG(dag_id=workflow)
                for node, _ in payloads:
                    dag = dag.add_node(node)
                authority.admin_client.create_workflow(
                    workflow_id=workflow,
                    nodes={
                        node.node_id: tuple(node.depends_on) for node, _ in payloads
                    },
                    policy_version="1",
                    required_capabilities={node.node_id: () for node, _ in payloads},
                    input_digests={
                        node.node_id: _sha(_node_input(node)) for node, _ in payloads
                    },
                )
                for i, producer in enumerate(producers):
                    authority.admin_client.register_agent(
                        workflow_id=workflow,
                        agent_id=f"agent-{i:03d}",
                        public_key=producer.public_key(),
                    )
                execution.load_dag(dag)
                pending: list[Future[Any]] = []
                for node_index, (node, artifact) in enumerate(payloads):
                    acknowledgment: Future[None] = Future()
                    admit = clock()

                    def operation(
                        node_index: int = node_index,
                        node: TaskNode = node,
                        artifact: Artifact = artifact,
                        admit: int = admit,
                        acknowledgment: Future[None] = acknowledgment,
                    ) -> dict[str, Any]:
                        nonlocal next_verified
                        start = clock()
                        with snapshot_lock:
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
                            outcome = adapter.execute_trusted(
                                TrialStimulus(
                                    payload=request.canonical_hash().encode("ascii"),
                                    commit_request=request,
                                ),
                                execution=execution,
                            )
                            commit_end = clock()
                            if outcome.authoritative_outcome != "committed":
                                raise ValueError("W2 governed commit failed")
                        acknowledgment.set_result(None)
                        with ordered:
                            ordered.wait_for(
                                lambda: (
                                    next_verified == chain * 100 + node_index
                                    or bool(failed)
                                )
                            )
                            if failed:
                                raise RuntimeError(
                                    "W2 ordered verification aborted"
                                ) from failed[0]
                            nonce = b64u_encode(secrets.token_bytes(16))
                            with snapshot_lock:
                                target = execution.observation_target(
                                    request, request_nonce=nonce
                                )
                                response = observer.client.observe(target)
                            observe_end = clock()
                            row = {
                                "type": "operation",
                                "index": chain * 100 + node_index,
                                "chain": chain,
                                "node_index": node_index,
                                "worker_id": threading.get_ident(),
                                "admit_ns": admit,
                                "start_ns": start,
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
                            _verify_operation(row, header, stream, trust, certificates)
                            row["end_ns"] = clock()
                            append(row)
                            next_verified += 1
                            ordered.notify_all()
                            return row

                    def guarded(
                        operation: Callable[[], dict[str, Any]] = operation,
                        acknowledgment: Future[None] = acknowledgment,
                    ) -> dict[str, Any]:
                        try:
                            return operation()
                        except BaseException as error:
                            with ordered:
                                failed.append(error)
                                ordered.notify_all()
                            if not acknowledgment.done():
                                acknowledgment.set_exception(error)
                            raise

                    future = pool.submit(guarded)
                    if future is None:
                        raise ValueError("W2 smoke capacity exhausted")
                    pending.append(future)
                    acknowledgment.result()
                    # No catch-up queue: this diagnostic waits for one permit
                    # before its next slot if all sixteen are still verifying.
                    if len(pending) >= 16:
                        pending[-16].result()
                rows.extend(future.result() for future in pending)
                if progress is not None:
                    progress(
                        {
                            "verified_operations": len(rows),
                            "elapsed_seconds": clock() / 1e9,
                        }
                    )
                if not execution.is_complete:
                    raise ValueError("W2 chain incomplete before rotation")
            events = sorted(
                event
                for row in rows
                for event in ((row["admit_ns"], 1), (row["end_ns"], -1))
            )
            occupancy = maximum = 0
            for _, change in events:
                occupancy += change
                maximum = max(maximum, occupancy)
            footer = {
                "type": "footer",
                "provenance_after": _source_provenance(),
                "prefix_sha256": prefix.hexdigest(),
                "verified_operations": len(rows),
                "maximum_occupancy": maximum,
                "campaign_eligible": False,
                "elapsed_ns": clock(),
            }
            footer["signature"] = b64u_encode(controller.sign(_DOMAIN + _json(footer)))
            append(footer)
            os.fsync(ledger.fileno())
        return verify_ledger(ledger_path, expected_provenance=provenance)
    finally:
        if pool is not None:
            pool.close()
        if observer is not None:
            observer.close()
        if authority is not None:
            authority.close()
        for path in private_paths:
            path.unlink(missing_ok=True)
