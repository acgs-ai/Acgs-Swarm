"""Trusted SQLite/W1 supervisor with replayable public-only evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.codec import canonical_statement
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
from constitutional_swarm.apcc.ports import APCCAuthorityConfig, StatusFreshnessPolicy
from constitutional_swarm.apcc.sqlite_store import (
    _operation_from_json,
    _operation_identity,
)
from constitutional_swarm.apcc.verifier import ScopedTrust, TrustBinding, TrustRole
from constitutional_swarm.apcc_empirical.adapters import (
    B6AuthorityAdapter,
    TrialStimulus,
)
from constitutional_swarm.apcc_empirical.artifacts import (
    RawArtifactWriter,
    read_artifact_run,
)
from constitutional_swarm.apcc_empirical.contract import (
    MATRIX_REVISION_V2,
    PerformanceRun,
    canonical_json_bytes,
    load_matrix,
    planned_performance_runs,
)
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.authority_child import AuthorityChildConfig, KeySourceRef
from constitutional_swarm.authority_observer import (
    AuthorityObserverLaunchConfig,
    ControllerKeySourceRef,
)
from constitutional_swarm.authority_service import (
    _decode_commit_request,
    _encode_commit_request,
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governed_commit import (
    CommitRequest,
    VerdictDecision,
    _signed_receipt_digest,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode

_DOMAIN = b"APCC-1.qualification-v3.ledger\x00"
_EXPERIMENT = "apcc-1-qualification-v3"
_AGENT = "producer-1"
_NODE = "node-1"


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def select_run(matrix_path: Path, trial_id: str) -> PerformanceRun:
    """Reject unsupported or non-planner identities before any child launch."""
    matrix = load_matrix(matrix_path)
    if matrix.revision != MATRIX_REVISION_V2:
        raise ValueError("qualification v3 requires matrix v2")
    for run in planned_performance_runs(matrix):
        if run.trial_id == trial_id:
            identity = (
                run.baseline_id,
                run.store,
                run.workload_id,
                run.cache_state,
                run.phase,
                run.payload_pair,
                run.ablation_id,
            )
            if identity != (
                "B6",
                "sqlite",
                "W1",
                "cold",
                "measured",
                (1024, 4096),
                None,
            ):
                raise ValueError("unsupported qualification cell")
            return run
    raise ValueError("unknown planner trial identity")


def next_slot(
    previous_slot: int, elapsed_ns: int, rate: int, duration_seconds: int
) -> int | None:
    """Fixed-window admission: slot zero starts now; missed arrivals drop."""
    if (
        any(
            type(value) is not int
            for value in (previous_slot, elapsed_ns, rate, duration_seconds)
        )
        or min(previous_slot, elapsed_ns) < 0
        or min(rate, duration_seconds) <= 0
    ):
        raise ValueError("invalid pacing arguments")
    if elapsed_ns >= duration_seconds * 1_000_000_000:
        return None
    slot = (
        max(previous_slot, (elapsed_ns * rate + 999_999_999) // 1_000_000_000)
        if previous_slot
        else 0
    )
    return slot if slot < duration_seconds * rate else None


def _node_input(node: TaskNode) -> bytes:
    return _json(
        {
            "title": node.title,
            "description": node.description,
            "domain": node.domain,
            "required_capabilities": node.required_capabilities,
            "depends_on": node.depends_on,
        }
    )


def build_payloads(index: int) -> tuple[TaskNode, Artifact]:
    """Return exactly 1024 canonical input bytes and 4096 artifact bytes."""
    node = TaskNode(node_id=_NODE, title="W1")
    node = replace(node, description="x" * (1024 - len(_node_input(node))))
    artifact = Artifact(
        f"artifact-{index:08d}", _NODE, _AGENT, "text/plain", "", timestamp=0.0
    )
    artifact = replace(
        artifact, content="x" * (4096 - len(_json(artifact.canonical_dict())))
    )
    if len(_node_input(node)) != 1024 or len(_json(artifact.canonical_dict())) != 4096:
        raise ValueError("payload sizing failed")
    return node, artifact


def _configuration(
    directory: Path, run_id: str, *, launch_lifetime_ms: int = 300_000
) -> tuple[
    AuthorityChildConfig,
    AuthorityObserverLaunchConfig,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    tuple[Path, Path],
]:
    keys = {
        name: Ed25519PrivateKey.generate()
        for name in (
            "policy",
            "registry",
            "control",
            "commit",
            "status",
            "identity",
            "producer",
            "controller",
        )
    }
    root = sha256_digest(secrets.token_bytes(32))
    store_id = f"store-{run_id}"
    bindings = (
        TrustBinding(
            TrustRole.PRODUCER,
            (_AGENT, "authority:qualification:producer", root),
            "producer-key",
            _public(keys["producer"]),
        ),
        TrustBinding(
            TrustRole.POLICY,
            ("qualification-policy", "1", "1"),
            "policy-key",
            _public(keys["policy"]),
        ),
        TrustBinding(
            TrustRole.REGISTRY, (root, "1"), "registry-key", _public(keys["registry"])
        ),
        TrustBinding(
            TrustRole.COMMIT, (store_id,), "commit-key", _public(keys["commit"])
        ),
        TrustBinding(
            TrustRole.STATUS, (store_id,), "status-key", _public(keys["status"])
        ),
    )
    config = APCCAuthorityConfig(
        store_id,
        (bindings[0],),
        (bindings[1],),
        (bindings[2],),
        bindings[3],
        bindings[4],
        StatusFreshnessPolicy("5000", "1000"),
    )
    bundle: dict[str, Any] = {
        name: b64u_encode(_private(keys[name]))
        for name in ("registry", "control", "commit", "status", "identity")
    }
    bundle["policy"] = {"1": b64u_encode(_private(keys["policy"]))}
    key_path, controller_path = (
        directory / ".authority.keys",
        directory / ".controller.key",
    )
    _write_new(key_path, _json(bundle))
    try:
        _write_new(
            controller_path, b64u_encode(_private(keys["controller"])).encode("ascii")
        )
    except BaseException:
        key_path.unlink(missing_ok=True)
        raise
    child = AuthorityChildConfig(
        str(directory / "authority.db"),
        config,
        KeySourceRef("file", str(key_path), _public(keys["identity"])),
        provision=True,
    )
    controller_public = _public(keys["controller"])
    observer = AuthorityObserverLaunchConfig(
        _EXPERIMENT,
        run_id,
        store_id,
        "sqlite",
        run_id,
        None,
        sha256_digest(controller_public),
        ControllerKeySourceRef(str(controller_path), controller_public),
        launch_lifetime_ms=launch_lifetime_ms,
    )
    return (
        child,
        observer,
        keys["producer"],
        keys["controller"],
        (key_path, controller_path),
    )


def _expectations(launch: Any) -> ObserverLaunchExpectationsV1:
    return ObserverLaunchExpectationsV1(
        **{
            name: getattr(launch, name)
            for name in ObserverLaunchExpectationsV1.__dataclass_fields__
        }
    )


def _trust(header: Mapping[str, Any]) -> ScopedTrust:
    return ScopedTrust(
        tuple(
            TrustBinding(
                TrustRole(item["role"]),
                tuple(item["scope"]),
                item["key_id"],
                b64u_decode(item["public_key"], expected_length=32),
            )
            for item in header["trust"]
        )
    )


def _verify_governed_verdict(
    request: CommitRequest, header: Mapping[str, Any], now_ms: int
) -> None:
    """Verify the ledger's legacy verdict against its scoped policy trust pin.

    This proves a valid receipt-bound verdict, not byte identity with the legacy
    decision row: that row is not part of the signed APCC observation schema.
    """
    payload, verdict = request.receipt.payload, request.verdict
    scope = [
        payload.verifier_policy_id,
        payload.policy_version,
        str(payload.policy_epoch),
    ]
    policies = [
        binding
        for binding in header["trust"]
        if binding["role"] == "policy" and binding["scope"] == scope
    ]
    if len(policies) != 1:
        raise ValueError("governed verdict policy binding mismatch")
    policy = policies[0]
    expected = {
        "decision": VerdictDecision.ALLOW,
        "store_id": header["launch_expectations"]["authority_store_id"],
        "verifier_policy_id": payload.verifier_policy_id,
        "policy_id": payload.verifier_policy_id,
        "policy_version": payload.policy_version,
        "verifier_key_id": policy["key_id"],
        "receipt_digest": _signed_receipt_digest(request.receipt),
        **{
            name: getattr(payload, name)
            for name in (
                "workflow_id",
                "node_id",
                "attempt_id",
                "agent_id",
                "expected_node_state_version",
                "policy_epoch",
                "authority_epoch",
                "agent_revocation_epoch",
                "workflow_revocation_generation",
                "workflow_generation",
            )
        },
    }
    if any(getattr(verdict, name) != value for name, value in expected.items()):
        raise ValueError("governed verdict binding mismatch")
    now = now_ms // 1000
    if (
        verdict.issued_at > now + 30
        or verdict.expires_at < now
        or verdict.expires_at <= verdict.issued_at
    ):
        raise ValueError("governed verdict expired or not yet valid")
    try:
        Ed25519PublicKey.from_public_bytes(
            b64u_decode(policy["public_key"], expected_length=32)
        ).verify(
            base64.b64decode(verdict.signature, validate=True),
            verdict.canonical_bytes(),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise ValueError("invalid governed verdict signature") from error


def _verify_operation(
    row: Mapping[str, Any],
    header: Mapping[str, Any],
    stream: AuthorityObservationVerificationStream,
    trust: ScopedTrust,
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
    node, artifact = build_payloads(row["index"])
    if output != _json(
        artifact.canonical_dict()
    ) or payload.input_digest != sha256_digest(_node_input(node)):
        raise ValueError("operation violates fixed payload contract")


def verify_ledger(path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    """Replay proofs at recorded verification times; require a complete signed seal."""
    raw = Path(path).read_bytes()
    digest = _sha(raw)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("ledger digest mismatch")
    lines = raw.splitlines(keepends=True)
    if len(lines) < 2 or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("truncated ledger")
    values = [json.loads(line) for line in lines]
    if any(
        _json(value) + b"\n" != line for value, line in zip(values, lines, strict=True)
    ):
        raise ValueError("noncanonical ledger")
    header, footer = values[0], values[-1]
    if (
        header["type"] != "header"
        or footer["type"] != "footer"
        or header["revision"] != "qualification-v3"
        or header["mode"] not in {"smoke", "qualification"}
    ):
        raise ValueError("invalid ledger envelope")
    body = {key: value for key, value in footer.items() if key != "signature"}
    if body["prefix_sha256"] != _sha(b"".join(lines[:-1])):
        raise ValueError("ledger prefix changed")
    Ed25519PublicKey.from_public_bytes(
        b64u_decode(header["controller_public_key"], expected_length=32)
    ).verify(
        b64u_decode(footer["signature"], expected_length=64), _DOMAIN + _json(body)
    )
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    stream = AuthorityObservationVerificationStream(launch.session_id)
    expected_lifetime = (
        max(300_000, header["duration_seconds"] * 1000 + 100_000)
        if header["mode"] == "qualification"
        else 300_000
    )
    if int(launch.not_after_ms) - int(launch.not_before_ms) != expected_lifetime:
        raise ValueError("observer launch lifetime does not match selected run")
    if header["mode"] == "qualification" and header["started_wall_ms"] + header[
        "duration_seconds"
    ] * 1000 > int(launch.not_after_ms):
        raise ValueError("observer launch expires before run deadline")
    trust = _trust(header)
    identities: set[str] = set()
    commits: set[str] = set()
    nonces: set[str] = set()
    verified = previous_end = 0
    previous_slot = -1
    previous_time = header["started_wall_ms"]
    for index, row in enumerate(values[1:-1]):
        if (
            row["type"] != "operation"
            or row["index"] != index
            or type(row["slot"]) is not int
            or row["slot"] <= previous_slot
            or row["start_ns"] < previous_end
            or not (
                row["start_ns"]
                <= row["commit_start_ns"]
                <= row["commit_end_ns"]
                <= row["observe_end_ns"]
                <= row["end_ns"]
            )
        ):
            raise ValueError("invalid operation order or timing")
        if (
            row["verification_time_ms"] < previous_time
            or abs(
                row["verification_time_ms"]
                - header["started_wall_ms"]
                - row["observe_end_ns"] // 1_000_000
            )
            > 1000
        ):
            raise ValueError("verification time not bound to operation clock")
        previous_end, previous_slot, previous_time = (
            row["end_ns"],
            row["slot"],
            row["verification_time_ms"],
        )
        request = _decode_commit_request(row["request"])
        workflow = request.receipt.payload.workflow_id
        if (
            workflow != f"workflow-{header['run_id']}-{index:08d}"
            or workflow in identities
            or request.commit_id in commits
            or row["nonce"] in nonces
        ):
            raise ValueError("duplicate or substituted operation identity")
        identities.add(workflow)
        commits.add(request.commit_id)
        nonces.add(row["nonce"])
        if header["mode"] == "qualification":
            scheduled_ns = (
                row["slot"] * 1_000_000_000 // header["target_rate_per_second"]
            )
            if (
                row["start_ns"] < scheduled_ns
                or row["start_ns"] >= header["duration_seconds"] * 1_000_000_000
            ):
                raise ValueError("operation violated pacing or admission deadline")
        _verify_operation(row, header, stream, trust)
        on_time = (
            header["mode"] == "smoke"
            or row["end_ns"] < header["duration_seconds"] * 1_000_000_000
        )
        if row["counted"] is not on_time:
            raise ValueError("post-deadline completion counted")
        verified += int(on_time)
    count = len(values) - 2
    if (
        body["admitted_operations"] != count
        or body["committed_operations"] != count
        or body["verified_operations"] != verified
        or body["overload_operations"] != body["scheduled_operations"] - count
        or body["elapsed_ns"] < previous_end
    ):
        raise ValueError("ledger completion counts disagree")
    if header["mode"] == "qualification" and (
        body["scheduled_operations"]
        != header["duration_seconds"] * header["target_rate_per_second"]
        or body["elapsed_ns"] < header["duration_seconds"] * 1_000_000_000
    ):
        raise ValueError("fixed schedule changed")
    incomplete = header["mode"] != "qualification" or verified < 10000
    if body["incomplete_run"] is not incomplete:
        raise ValueError("completion floor changed")
    return {**body, "ledger_path": str(path), "ledger_sha256": digest, "header": header}


def _execute(
    directory: Path,
    *,
    operations: int | None,
    run: PerformanceRun | None,
    provenance: Mapping[str, Any],
    progress: Callable[[dict[str, Any]], None] | None,
) -> dict[str, Any]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = secrets.token_hex(12)
    config, observer_config, producer, controller, private_paths = _configuration(
        directory,
        run_id,
        launch_lifetime_ms=max(300_000, int(run.duration_seconds or 0) * 1000 + 100_000)
        if run is not None
        else 300_000,
    )
    authority = observer = None
    ledger_path = directory / "ledger.jsonl"
    attempt: dict[str, Any] | None = None
    admitted = committed = verified = 0
    try:
        authority = start_authority(config)
        observer = start_authority_observer(authority, observer_config)
        for path in private_paths:
            path.unlink(missing_ok=True)
        execution = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        launch = observer.launch_attestation
        if run is not None and int(time.time() * 1000) + int(
            run.duration_seconds or 0
        ) * 1000 > int(launch.not_after_ms):
            raise ValueError("observer launch expires before run deadline")
        header = {
            "type": "header",
            "revision": "qualification-v3",
            "mode": "smoke" if run is None else "qualification",
            "run_id": run_id,
            "trial_id": None if run is None else run.trial_id,
            "target_rate_per_second": None
            if run is None
            else run.target_rate_per_second,
            "duration_seconds": None if run is None else run.duration_seconds,
            "launch": b64u_encode(encode_observer_launch_attestation(launch)),
            "launch_expectations": asdict(_expectations(launch)),
            "controller_public_key": b64u_encode(_public(controller)),
            "trust": [
                {
                    "role": binding.role.value,
                    "scope": list(binding.scope),
                    "key_id": binding.key_id,
                    "public_key": b64u_encode(binding.public_key),
                }
                for binding in config.authority.trust_bindings
            ],
            "provenance": dict(provenance),
            "pre_run_queries": 0,
            "warmup_runs_completed": 0,
            "bootstrap_reads": "required schema, secure authority and observer bootstrap only",
            "started_wall_ms": int(time.time() * 1000),
        }
        stream = AuthorityObservationVerificationStream(launch.session_id)
        trust = ScopedTrust(config.authority.trust_bindings)
        adapter = B6AuthorityAdapter()
        scheduled = (
            operations
            if run is None
            else int(run.duration_seconds or 0) * run.target_rate_per_second
        )
        assert scheduled is not None
        slot = 0
        prefix = hashlib.sha256()
        with ledger_path.open("xb") as ledger:

            def append(value: Mapping[str, Any]) -> None:
                encoded = _json(dict(value)) + b"\n"
                ledger.write(encoded)
                ledger.flush()
                prefix.update(encoded)

            started = time.monotonic_ns()
            append(header)
            duration_ns = (
                None if run is None else int(run.duration_seconds or 0) * 1_000_000_000
            )
            while slot < scheduled:
                elapsed = time.monotonic_ns() - started
                if run is not None:
                    assert duration_ns is not None
                    if elapsed >= duration_ns:
                        break
                    # Drop missed arrivals instead of accumulating a catch-up burst.
                    next_arrival = next_slot(
                        slot,
                        elapsed,
                        run.target_rate_per_second,
                        int(run.duration_seconds or 0),
                    )
                    if next_arrival is None:
                        break
                    slot = next_arrival
                    target_ns = slot * 1_000_000_000 // run.target_rate_per_second
                    delay = target_ns - (time.monotonic_ns() - started)
                    if delay > 0:
                        time.sleep(delay / 1_000_000_000)
                op_start = time.monotonic_ns() - started
                if duration_ns is not None and op_start >= duration_ns:
                    break
                node, artifact = build_payloads(admitted)
                workflow = f"workflow-{run_id}-{admitted:08d}"
                attempt = {
                    "index": admitted,
                    "workflow_id": workflow,
                    "slot": slot,
                    "start_ns": op_start,
                    "stage": "provisioning",
                }
                dag = TaskDAG(dag_id=workflow).add_node(node)
                authority.admin_client.create_workflow(
                    workflow_id=workflow,
                    nodes={_NODE: ()},
                    policy_version="1",
                    required_capabilities={_NODE: ()},
                    input_digests={_NODE: _sha(_node_input(node))},
                )
                authority.admin_client.register_agent(
                    workflow_id=workflow,
                    agent_id=_AGENT,
                    public_key=producer.public_key(),
                )
                execution.load_dag(dag)
                authorization = sign_attempt_authorization(
                    execution.prepare_claim(_NODE, _AGENT), producer
                )
                execution.claim(_NODE, _AGENT, authorization)
                payload = execution.produce_result(
                    _NODE, artifact, authorization=authorization
                )
                request = execution.build_request(
                    sign_governed_receipt(payload, producer)
                )
                attempt.update(
                    stage="committing",
                    request=_encode_commit_request(request),
                    request_hash=request.canonical_hash(),
                )
                commit_start = time.monotonic_ns() - started
                outcome = adapter.execute_trusted(
                    TrialStimulus(
                        payload=request.canonical_hash().encode("ascii"),
                        commit_request=request,
                    ),
                    execution=execution,
                )
                commit_end = time.monotonic_ns() - started
                attempt.update(
                    stage="observation_target",
                    authoritative_outcome=outcome.authoritative_outcome,
                    commit_start_ns=commit_start,
                    commit_end_ns=commit_end,
                )
                if outcome.authoritative_outcome != "committed":
                    raise ValueError("trusted B6 commit was not COMMITTED")
                committed += 1
                nonce = b64u_encode(secrets.token_bytes(16))
                target = execution.observation_target(request, request_nonce=nonce)
                attempt.update(stage="observe", target=target.to_object())
                response = observer.client.observe(target)
                observe_end = time.monotonic_ns() - started
                row: dict[str, Any] = {
                    "type": "operation",
                    "index": admitted,
                    "slot": slot,
                    "start_ns": op_start,
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
                attempt.update(stage="verification")
                _verify_operation(row, header, stream, trust)
                row["end_ns"] = time.monotonic_ns() - started
                row["counted"] = duration_ns is None or row["end_ns"] < duration_ns
                append(row)
                admitted += 1
                verified += int(row["counted"])
                attempt = None
                slot += 1
                if progress is not None and (admitted == 1 or admitted % 100 == 0):
                    progress(
                        {
                            "admitted_operations": admitted,
                            "verified_operations": verified,
                            "elapsed_seconds": row["end_ns"] / 1e9,
                        }
                    )
            if duration_ns is not None:
                remaining = duration_ns - (time.monotonic_ns() - started)
                if remaining > 0:
                    time.sleep(remaining / 1e9)
            footer = {
                "type": "footer",
                "prefix_sha256": prefix.hexdigest(),
                "scheduled_operations": scheduled,
                "admitted_operations": admitted,
                "committed_operations": committed,
                "verified_operations": verified,
                "overload_operations": scheduled - admitted,
                "elapsed_ns": time.monotonic_ns() - started,
                "incomplete_run": run is None or verified < 10000,
            }
            footer["signature"] = b64u_encode(controller.sign(_DOMAIN + _json(footer)))
            append(footer)
            os.fsync(ledger.fileno())
        return verify_ledger(ledger_path)
    except BaseException as error:
        causes: list[dict[str, str]] = []
        cause: BaseException | None = error
        seen: set[int] = set()
        while cause is not None and id(cause) not in seen and len(causes) < 8:
            seen.add(id(cause))
            causes.append(
                {"error_type": type(cause).__name__, "error": str(cause)[:1000]}
            )
            cause = cause.__cause__ or (
                None if cause.__suppress_context__ else cause.__context__
            )
        _write_new(
            directory / "failure.json",
            _json(
                {
                    "status": "failed",
                    "incomplete_run": True,
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "causes": causes,
                    "ledger_path": str(ledger_path),
                    "attempt": attempt,
                    "admitted_operations": admitted + int(attempt is not None),
                    "committed_operations": committed,
                    "verified_operations": verified,
                }
            ),
        )
        raise
    finally:
        if observer is not None:
            observer.close()
        if authority is not None:
            authority.close()
        for path in private_paths:
            path.unlink(missing_ok=True)


def run_smoke(
    output_dir: Path,
    *,
    operations: int = 3,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run fresh-database diagnostics without producing matrix evidence."""
    if type(operations) is not int or not 1 <= operations <= 1000:
        raise ValueError("smoke operations must be between 1 and 1000")
    return _execute(
        Path(output_dir),
        operations=operations,
        run=None,
        provenance={},
        progress=progress,
    )


def _record(
    run: PerformanceRun,
    result: Mapping[str, Any],
    matrix_path: Path,
    *,
    environment_id: str,
    git_sha: str,
    tool_versions: Mapping[str, str],
) -> dict[str, Any]:
    matrix = load_matrix(matrix_path)
    record: dict[str, Any] = dict.fromkeys(
        (
            "ablation_classification",
            "ablation_id",
            "attack_id",
            "case_index",
            "condition_id",
            "cost_saved_ns",
            "database_index",
            "distinct_states",
            "failed_invariant",
            "fault_target",
            "formal_evidence",
            "generated_states",
            "search_depth",
            "successful_commits",
            "witness_marker",
        )
    )
    incomplete = result["incomplete_run"]
    record.update(
        artifact_sha256=result["ledger_sha256"],
        authoritative_compromise=False,
        authoritative_outcome="committed" if result["committed_operations"] else "none",
        baseline_id="B6",
        byte_counts={"ledger": Path(result["ledger_path"]).stat().st_size},
        cache_state="cold",
        concurrency=1,
        dag="single-node",
        detected=incomplete,
        environment_id=environment_id,
        fail_closed=True,
        failure_code="INCOMPLETE_RUN" if incomplete else None,
        git_sha=git_sha,
        incorrect_current_consumption=False,
        input_bytes=1024,
        matrix_sha256=matrix.matrix_sha256,
        matrix_revision=matrix.revision,
        outcome="failed" if incomplete else "accepted",
        output_bytes=4096,
        phase="measured",
        record_type="performance",
        recovered=False,
        repetition=run.repetition,
        schema_version="apcc-1.raw-result.v2",
        seed=run.seed,
        store="sqlite",
        sub_seed_b64u=run.sub_seed_b64u,
        target_rate_per_second=run.target_rate_per_second,
        timings_ns={"total": result["elapsed_ns"]},
        tool_versions=dict(tool_versions),
        trial_id=run.trial_id,
        trial_index=run.trial_index,
        workload_id="W1",
        workload_evidence={
            "agents": 1,
            "completed_operations": result["verified_operations"],
            "duration_seconds": run.duration_seconds,
            "incomplete_run": incomplete,
            "lifecycle_mode": run.lifecycle_mode,
            "nodes": 1,
            "operation_limit": run.operation_limit,
            "parameters": {},
            "payload_pair": [1024, 4096],
            "pre_run_queries": 0,
            "schedule": "none",
            "warmup_runs_completed": 0,
        },
    )
    return record


def run_qualification(
    output_dir: Path,
    *,
    matrix_path: Path,
    schema_path: Path,
    trial_id: str,
    environment: Mapping[str, str],
    environment_id: str,
    git_sha: str,
    tool_versions: Mapping[str, str],
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute one supported planner repetition at its fixed deadline."""
    if Path(output_dir).exists() or Path(output_dir).is_symlink():
        raise ValueError("qualification output already exists")
    run = select_run(matrix_path, trial_id)
    matrix = load_matrix(matrix_path)
    provenance = {
        "environment": dict(environment),
        "environment_id": environment_id,
        "git_sha": git_sha,
        "tool_versions": dict(tool_versions),
        "matrix_sha256": matrix.matrix_sha256,
        "schema_sha256": _sha(Path(schema_path).read_bytes()),
        "trial_id": trial_id,
    }
    # This validates reviewed matrix/schema pins before any subprocess launch.
    writer = RawArtifactWriter(
        Path(output_dir),
        "shard",
        matrix=matrix,
        matrix_path=Path(matrix_path),
        schema_path=Path(schema_path),
        planned_trial_ids=[trial_id],
        environment=environment,
        environment_id=environment_id,
        git_sha=git_sha,
        tool_versions=tool_versions,
    )
    try:
        result = _execute(
            Path(output_dir) / "execution",
            operations=None,
            run=run,
            provenance=provenance,
            progress=progress,
        )
        writer.append(
            _record(
                run,
                result,
                matrix_path,
                environment_id=environment_id,
                git_sha=git_sha,
                tool_versions=tool_versions,
            )
        )
        writer.finalize()
    except BaseException:
        writer.abort()
        raise
    verified = verify_shard(
        Path(output_dir), matrix_path=matrix_path, schema_path=schema_path
    )
    return {
        **result,
        "raw_artifact_path": str(Path(output_dir) / "shard"),
        "shard_verified": verified["shard_verified"],
    }


def verify_shard(
    output_dir: Path, *, matrix_path: Path, schema_path: Path
) -> dict[str, Any]:
    """Replay the pinned ledger and reconstruct the exact schema-validated row."""
    artifact = read_artifact_run(Path(output_dir) / "shard")
    raw = (artifact.path / "raw.jsonl").read_bytes()
    if _sha(raw) != artifact.raw_sha256:
        raise ValueError("raw artifact changed after validated read")
    record = json.loads(raw)
    run = select_run(matrix_path, record["trial_id"])
    result = verify_ledger(
        Path(output_dir) / "execution" / "ledger.jsonl",
        expected_sha256=record["artifact_sha256"],
    )
    header = result["header"]
    if (
        header["mode"] != "qualification"
        or header["trial_id"] != run.trial_id
        or header["duration_seconds"] != run.duration_seconds
        or header["target_rate_per_second"] != run.target_rate_per_second
    ):
        raise ValueError("ledger is not this planner repetition")
    provenance = header["provenance"]
    if provenance["schema_sha256"] != _sha(Path(schema_path).read_bytes()) or any(
        provenance[key] != artifact.manifest[key]
        for key in (
            "environment",
            "environment_id",
            "git_sha",
            "tool_versions",
            "matrix_sha256",
        )
    ):
        raise ValueError("ledger provenance differs from shard")
    expected = _record(
        run,
        result,
        matrix_path,
        environment_id=provenance["environment_id"],
        git_sha=provenance["git_sha"],
        tool_versions=provenance["tool_versions"],
    )
    if canonical_json_bytes(record) != canonical_json_bytes(expected):
        raise ValueError("raw row disagrees with independently replayed ledger")
    return {
        "shard_verified": True,
        "verified_operations": result["verified_operations"],
        "incomplete_run": result["incomplete_run"],
        "ledger_sha256": result["ledger_sha256"],
    }
