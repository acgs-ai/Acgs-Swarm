"""Real spawned B6 supervision and independent public-proof replay contracts."""

from __future__ import annotations

import base64
import copy
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    encode_signed_authority_observation,
    ObservationAuthorityProof,
)
from constitutional_swarm.apcc.verifier import ScopedTrust
from constitutional_swarm.apcc_empirical import qualification_v3 as qualification
from constitutional_swarm.apcc_empirical.adapters import (
    AuthorityObservation,
    B6AuthorityAdapter,
    ScenarioExecutionError,
    TrialStimulus,
)
from constitutional_swarm.apcc_empirical.contract import (
    load_matrix,
    planned_performance_runs,
)
from constitutional_swarm.authority_service import (
    AuthorityServiceHandle,
    _SwarmExecutionHandle,
    _decode_commit_request,
    _encode_commit_request,
)
from constitutional_swarm.authority_observer import (
    AuthorityObserverLaunchConfig,
    ControllerKeySourceRef,
)
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import CommitOutcome, VerdictDecision
from tests import test_apcc_observation_target as observation_target_tests

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "experiments" / "apcc-1"
MATRIX = DATA / "matrix.v2.json"
SCHEMA = DATA / "raw-result.v2.schema.json"
spawned_request = observation_target_tests.spawned_request


def _values(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _stream(header):
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    return AuthorityObservationVerificationStream(launch.session_id)


@pytest.fixture(scope="module")
def smoke(tmp_path_factory):
    directory = tmp_path_factory.mktemp("qualification-v3") / "smoke"
    result = qualification.run_smoke(directory, operations=3)
    return directory, result, _values(directory / "ledger.jsonl")


def test_real_smoke_rotates_distinct_workflows_and_replays_public_proofs(smoke):
    directory, result, values = smoke
    assert result["verified_operations"] == result["committed_operations"] == 3
    assert result["incomplete_run"] is True
    assert result["header"]["mode"] == "smoke"
    assert result["header"]["trial_id"] is None
    assert not (directory / "shard").exists()
    assert not list(directory.rglob("*.keys"))
    assert not list(directory.rglob("*.key"))
    assert not (directory / "failure.json").exists()
    assert qualification.verify_ledger(directory / "ledger.jsonl") == result
    workflows = [row["target"]["workflow_id"] for row in values[1:-1]]
    assert len(set(workflows)) == 3
    with sqlite3.connect(directory / "authority.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM workflows").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM commit_index").fetchone() == (
            3,
        )
    header = values[0]
    stream = _stream(header)
    for row in values[1:-1]:
        qualification._verify_operation(
            row, header, stream, qualification._trust(header)
        )
        request = _decode_commit_request(row["request"])
        response = decode_signed_authority_observation(b64u_decode(row["observation"]))
        assert len(response.snapshot.output_bytes) == 4096
        assert (
            sha256_digest(response.snapshot.output_bytes)
            == request.receipt.payload.output_digest
        )
        node, artifact = qualification.build_payloads(row["index"])
        assert len(qualification._node_input(node)) == 1024
        assert request.receipt.payload.input_digest == sha256_digest(
            qualification._node_input(node)
        )
        assert response.snapshot.output_bytes == qualification._json(
            artifact.canonical_dict()
        )
    assert stream.next_sequence == 4


@pytest.mark.parametrize(
    "mutation",
    [
        "decision",
        "request-hash",
        "nonce",
        "target",
        "controller",
        "run",
        "trust",
        "signature",
        "output",
        "certificate",
        "status",
    ],
)
def test_operation_verifier_rejects_tampering_beyond_ledger_checksum(smoke, mutation):
    _, _, values = smoke
    header, row = copy.deepcopy(values[0]), copy.deepcopy(values[1])
    if mutation == "decision":
        row["decision"] = "DENIED"
    elif mutation == "request-hash":
        row["request_hash"] = "0" * 64
    elif mutation == "nonce":
        row["nonce"] = b64u_encode(b"x" * 16)
    elif mutation == "target":
        row["target"]["workflow_id"] = "substituted"
    elif mutation == "controller":
        header["controller_public_key"] = b64u_encode(b"x" * 32)
    elif mutation == "run":
        header["run_id"] = "substituted"
    elif mutation == "trust":
        header["trust"] = []
    else:
        response = decode_signed_authority_observation(b64u_decode(row["observation"]))
        if mutation == "signature":
            response = replace(
                response,
                signature=replace(
                    response.signature, signature_b64u=b64u_encode(b"x" * 64)
                ),
            )
        else:
            field = {
                "output": "output_bytes",
                "certificate": "certificate_envelope_bytes",
                "status": "current_status_evidence",
            }[mutation]
            response = replace(
                response,
                snapshot=replace(
                    response.snapshot,
                    **{field: b"x" * 4096 if mutation == "output" else b"{}"},
                ),
            )
        row["observation"] = b64u_encode(encode_signed_authority_observation(response))
    with pytest.raises((ValueError, TypeError)):
        qualification._verify_operation(
            row, header, _stream(header), qualification._trust(header)
        )


def test_operation_sequence_rejects_reorder_and_replay(smoke):
    _, _, values = smoke
    header, first, second = values[:3]
    trust = qualification._trust(header)
    with pytest.raises(ValueError):
        qualification._verify_operation(second, header, _stream(header), trust)
    stream = _stream(header)
    qualification._verify_operation(first, header, stream, trust)
    with pytest.raises(ValueError):
        qualification._verify_operation(first, header, stream, trust)


@pytest.mark.parametrize("mutation", ["signature", "agent_id", "nonce"])
def test_operation_binds_entire_producer_receipt_despite_recomputed_hash(
    smoke, mutation
):
    _, _, values = smoke
    header, row = copy.deepcopy(values[0]), copy.deepcopy(values[1])
    request = _decode_commit_request(row["request"])
    if mutation == "signature":
        receipt = replace(
            request.receipt, signature=base64.b64encode(bytes(64)).decode("ascii")
        )
    else:
        replacement = (
            "different-producer" if mutation == "agent_id" else b64u_encode(b"z" * 16)
        )
        receipt = replace(
            request.receipt,
            payload=replace(request.receipt.payload, **{mutation: replacement}),
        )
    substituted = replace(request, receipt=receipt)
    row["request"] = _encode_commit_request(substituted)
    row["request_hash"] = substituted.canonical_hash()
    assert row["request_hash"] != request.canonical_hash()
    with pytest.raises(ValueError):
        qualification._verify_operation(
            row, header, _stream(header), qualification._trust(header)
        )


def test_operation_rejects_invalid_verdict_signature_despite_recomputed_hash(smoke):
    _, _, values = smoke
    header, row = copy.deepcopy(values[0]), copy.deepcopy(values[1])
    request = _decode_commit_request(row["request"])
    substituted = replace(
        request,
        verdict=replace(
            request.verdict, signature=base64.b64encode(bytes(64)).decode("ascii")
        ),
    )
    row["request"] = _encode_commit_request(substituted)
    row["request_hash"] = substituted.canonical_hash()
    with pytest.raises(ValueError):
        qualification._verify_operation(
            row, header, _stream(header), qualification._trust(header)
        )


@pytest.fixture(scope="module")
def verdict_smoke(tmp_path_factory):
    """Retain a test-owned ephemeral signer in memory, never in the proof ledger."""
    directory = tmp_path_factory.mktemp("verdict-binding") / "smoke"
    configuration = qualification._configuration
    captured = []

    def configure(*args, **kwargs):
        result = configuration(*args, **kwargs)
        child = result[0]
        bundle = json.loads(Path(child.key_source.location).read_bytes())
        captured.append(
            Ed25519PrivateKey.from_private_bytes(b64u_decode(bundle["policy"]["1"]))
        )
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(qualification, "_configuration", configure)
        qualification.run_smoke(directory, operations=1)
    assert not list(directory.glob("*.keys"))
    return _values(directory / "ledger.jsonl"), captured[0]


@pytest.mark.parametrize(
    "mutation",
    [
        "store_id",
        "receipt_digest",
        "workflow_id",
        "node_id",
        "attempt_id",
        "agent_id",
        "workflow_generation",
        "expected_node_state_version",
        "decision",
        "expires_at",
        "issued_at",
    ],
)
def test_validly_signed_verdict_still_requires_exact_bindings(verdict_smoke, mutation):
    values, signer = verdict_smoke
    header, row = copy.deepcopy(values[0]), copy.deepcopy(values[1])
    request = _decode_commit_request(row["request"])
    verdict = request.verdict
    if mutation == "decision":
        changed = VerdictDecision.DENY
    elif mutation == "expires_at":
        changed = verdict.issued_at - 1
    elif mutation == "issued_at":
        changed = row["verification_time_ms"] // 1000 + 60
    elif mutation in {"workflow_generation", "expected_node_state_version"}:
        changed = getattr(verdict, mutation) + 1
    else:
        changed = "other-value"
    verdict = replace(verdict, **{mutation: changed})
    verdict = replace(
        verdict,
        signature=base64.b64encode(signer.sign(verdict.canonical_bytes())).decode(
            "ascii"
        ),
    )
    signer.public_key().verify(
        base64.b64decode(verdict.signature), verdict.canonical_bytes()
    )
    substituted = replace(request, verdict=verdict)
    row["request"] = _encode_commit_request(substituted)
    row["request_hash"] = substituted.canonical_hash()
    with pytest.raises(ValueError):
        qualification._verify_operation(
            row, header, _stream(header), qualification._trust(header)
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "truncated",
        "missing-footer",
        "reorder",
        "duplicate",
        "count",
        "mode",
        "identity",
    ],
)
def test_ledger_seal_rejects_mutation(smoke, tmp_path, mutation):
    directory, _, original = smoke
    values = copy.deepcopy(original)
    if mutation == "missing-footer":
        values.pop()
    elif mutation == "reorder":
        values[1], values[2] = values[2], values[1]
    elif mutation == "duplicate":
        values.insert(2, values[1])
    elif mutation == "count":
        values[-1]["verified_operations"] = 10000
    elif mutation == "mode":
        values[0]["mode"] = "qualification"
    elif mutation == "identity":
        values[1]["target"]["node_id"] = "other"
    raw = b"".join(qualification._json(value) + b"\n" for value in values)
    if mutation == "truncated":
        raw = (directory / "ledger.jsonl").read_bytes()[:-1]
    path = tmp_path / "tampered.jsonl"
    path.write_bytes(raw)
    with pytest.raises((ValueError, KeyError, InvalidSignature)):
        qualification.verify_ledger(path)


def test_ledger_digest_is_bound(smoke):
    directory, result, _ = smoke
    qualification.verify_ledger(
        directory / "ledger.jsonl", expected_sha256=result["ledger_sha256"]
    )
    with pytest.raises(ValueError, match="digest"):
        qualification.verify_ledger(
            directory / "ledger.jsonl", expected_sha256="0" * 64
        )


def test_observer_launch_precedes_scheduler_and_production(tmp_path, monkeypatch):
    events = []
    start_observer = qualification.start_authority_observer
    spawn_executor = AuthorityServiceHandle.spawn_executor
    build_payloads = qualification.build_payloads

    def observe(*args, **kwargs):
        result = start_observer(*args, **kwargs)
        events.append("observer")
        return result

    def spawn(*args, **kwargs):
        assert events == ["observer"]
        result = spawn_executor(*args, **kwargs)
        events.append("scheduler")
        return result

    def payload(*args, **kwargs):
        assert events[:2] == ["observer", "scheduler"]
        events.append("payload")
        return build_payloads(*args, **kwargs)

    monkeypatch.setattr(qualification, "start_authority_observer", observe)
    monkeypatch.setattr(AuthorityServiceHandle, "spawn_executor", spawn)
    monkeypatch.setattr(qualification, "build_payloads", payload)
    assert (
        qualification.run_smoke(tmp_path / "ordered", operations=1)[
            "verified_operations"
        ]
        == 1
    )


@pytest.mark.parametrize(
    "failure", ["commit-denied", "missing-target", "proof-rejected"]
)
def test_failed_operation_retains_diagnostics_and_never_counts(
    tmp_path, monkeypatch, failure
):
    directory = tmp_path / failure
    if failure == "commit-denied":
        monkeypatch.setattr(
            B6AuthorityAdapter,
            "execute_trusted",
            lambda *a, **k: AuthorityObservation(
                "DENIED", None, None, None, None, None
            ),
        )
    else:

        def reject(*args, **kwargs):
            raise ValueError(failure)

        if failure == "missing-target":
            monkeypatch.setattr(_SwarmExecutionHandle, "observation_target", reject)
        else:
            monkeypatch.setattr(qualification, "_verify_operation", reject)
    with pytest.raises(ValueError):
        qualification.run_smoke(directory, operations=1)
    diagnostic = json.loads((directory / "failure.json").read_text())
    assert diagnostic["incomplete_run"] is True
    assert diagnostic["admitted_operations"] == 1
    assert diagnostic["committed_operations"] == int(failure != "commit-denied")
    assert diagnostic["verified_operations"] == 0
    assert diagnostic["attempt"]["index"] == 0
    assert diagnostic["attempt"]["request_hash"]
    assert [row["type"] for row in _values(directory / "ledger.jsonl")] == ["header"]
    with pytest.raises(ValueError, match="truncated"):
        qualification.verify_ledger(directory / "ledger.jsonl")
    assert not (directory / "shard").exists()
    assert not list(directory.glob("*.keys"))
    assert not list(directory.glob("*.key"))


def test_public_adapter_is_inert_and_fake_execution_handle_is_rejected():
    adapter = B6AuthorityAdapter()
    stimulus = TrialStimulus(payload=b"not-an-authority-request")
    with pytest.raises(ScenarioExecutionError):
        adapter.execute(stimulus)
    with pytest.raises(TypeError, match="spawned"):
        adapter.execute_trusted(stimulus, execution=object())


@pytest.fixture(scope="module")
def planner_runs():
    return tuple(planned_performance_runs(load_matrix(MATRIX)))


def _supported(run):
    return (
        run.baseline_id,
        run.store,
        run.workload_id,
        run.cache_state,
        run.phase,
        run.payload_pair,
        run.ablation_id,
    ) == ("B6", "sqlite", "W1", "cold", "measured", (1024, 4096), None)


def _qualification_args(run):
    return dict(
        matrix_path=MATRIX,
        schema_path=SCHEMA,
        trial_id=run.trial_id,
        environment={"os": "test"},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("baseline_id", "B1"),
        ("store", "postgresql"),
        ("workload_id", "W6"),
        ("cache_state", "warm"),
        ("phase", "warmup"),
    ],
)
def test_unsupported_cells_reject_before_children(
    tmp_path, monkeypatch, planner_runs, field, value
):
    run = next(run for run in planner_runs if getattr(run, field) == value)

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported cell launched authority")

    monkeypatch.setattr(qualification, "start_authority", unexpected)
    directory = tmp_path / "unsupported"
    with pytest.raises(ValueError, match="unsupported"):
        qualification.run_qualification(directory, **_qualification_args(run))
    assert not directory.exists()


def test_unknown_trial_and_frozen_v1_reject_before_launch():
    with pytest.raises(ValueError, match="unknown"):
        qualification.select_run(MATRIX, "invented-trial")
    with pytest.raises(ValueError, match="matrix v2"):
        qualification.select_run(DATA / "matrix.v1.json", "invented-trial")


def test_existing_smoke_directory_is_preserved(tmp_path):
    directory = tmp_path / "occupied"
    directory.mkdir()
    sentinel = directory / "existing-evidence"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        qualification.run_smoke(directory, operations=1)
    assert list(directory.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"preserve"


@pytest.mark.parametrize("operations", [0, -1, 1001, True, 1.0])
def test_invalid_smoke_count_rejects_without_output(tmp_path, operations):
    directory = tmp_path / "invalid"
    with pytest.raises(ValueError):
        qualification.run_smoke(directory, operations=operations)
    assert not directory.exists()


@pytest.mark.parametrize(
    "next_slot,elapsed_ns,expected",
    [
        (0, 0, 0),
        (0, 5_000_000, 0),
        (1, 50_000_000, 1),
        (1, 100_000_000, 1),
        (1, 100_000_001, 2),
        (1, 450_000_000, 5),
        (8, 450_000_000, 8),
        (9999, 999_900_000_001, None),
        (1, 1_000_000_000_000, None),
        (0, 1_000_000_000_001, None),
    ],
)
def test_fixed_deadline_pacer_drops_missed_slots_without_extension(
    next_slot, elapsed_ns, expected
):
    assert qualification.next_slot(next_slot, elapsed_ns, 10, 1000) == expected


@pytest.mark.parametrize(
    "arguments",
    [
        (-1, 0, 10, 1000),
        (0, -1, 10, 1000),
        (0, 0, 0, 1000),
        (0, 0, 10, 0),
        (True, 0, 10, 1000),
    ],
)
def test_pacer_rejects_invalid_numeric_contract(arguments):
    with pytest.raises(ValueError):
        qualification.next_slot(*arguments)


def test_qualification_existing_output_is_untouched_before_launch(
    tmp_path, monkeypatch, planner_runs
):
    directory = tmp_path / "occupied"
    directory.mkdir()
    sentinel = directory / "previous-evidence"
    sentinel.write_bytes(b"preserve")
    run = next(run for run in planner_runs if _supported(run))

    def unexpected(*args, **kwargs):
        pytest.fail("existing output launched authority")

    monkeypatch.setattr(qualification, "start_authority", unexpected)
    with pytest.raises(ValueError, match="already exists"):
        qualification.run_qualification(directory, **_qualification_args(run))
    assert list(directory.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"preserve"


def test_bad_schema_is_rejected_before_children(tmp_path, monkeypatch, planner_runs):
    run = next(run for run in planner_runs if _supported(run))
    arguments = _qualification_args(run)
    schema = tmp_path / "substituted-schema.json"
    schema.write_text("{}")
    arguments["schema_path"] = schema

    def unexpected(*args, **kwargs):
        pytest.fail("unreviewed schema launched authority")

    monkeypatch.setattr(qualification, "start_authority", unexpected)
    with pytest.raises(ValueError):
        qualification.run_qualification(tmp_path / "invalid-schema", **arguments)


@pytest.fixture
def incomplete_shard(tmp_path, monkeypatch, planner_runs):
    """One real operation, then simulated elapsed time; never successful evidence."""
    run = next(run for run in planner_runs if _supported(run))
    offset = 0

    def monotonic_ns():
        return time.monotonic_ns() + offset

    def deadline_after_first(progress):
        nonlocal offset
        assert progress["admitted_operations"] == 1
        offset = run.duration_seconds * 1_000_000_000

    monkeypatch.setattr(
        qualification,
        "time",
        SimpleNamespace(monotonic_ns=monotonic_ns, time=time.time, sleep=time.sleep),
    )
    arguments = _qualification_args(run)
    arguments["environment"] = {
        "os": "test",
        "clock": "simulated deadline after one real proof",
    }
    directory = tmp_path / "incomplete"
    result = qualification.run_qualification(
        directory, progress=deadline_after_first, **arguments
    )
    return directory, result, run


def test_real_underfilled_shard_keeps_fixed_deadline_and_replays(incomplete_shard):
    directory, result, run = incomplete_shard
    assert result["verified_operations"] == result["committed_operations"] == 1
    assert (
        result["scheduled_operations"]
        == run.duration_seconds * run.target_rate_per_second
    )
    assert result["overload_operations"] == result["scheduled_operations"] - 1
    assert result["elapsed_ns"] >= run.duration_seconds * 1_000_000_000
    assert result["incomplete_run"] is True
    verified = qualification.verify_shard(
        directory, matrix_path=MATRIX, schema_path=SCHEMA
    )
    assert verified["shard_verified"] is True
    assert verified["incomplete_run"] is True
    assert verified["verified_operations"] == 1
    row = json.loads((directory / "shard" / "raw.jsonl").read_bytes())
    assert row["failure_code"] == "INCOMPLETE_RUN"
    assert row["workload_evidence"]["completed_operations"] == 1
    assert row["workload_evidence"]["duration_seconds"] == run.duration_seconds
    assert row["trial_id"] == run.trial_id


@pytest.mark.parametrize("file", ["execution/ledger.jsonl", "shard/raw.jsonl"])
def test_shard_verifier_rejects_bound_file_tamper(incomplete_shard, file):
    directory, _, _ = incomplete_shard
    path = directory / file
    path.write_bytes(
        path.read_bytes().replace(
            b'"incomplete_run":true', b'"incomplete_run":false', 1
        )
    )
    with pytest.raises(ValueError):
        qualification.verify_shard(directory, matrix_path=MATRIX, schema_path=SCHEMA)


def test_commit_finishing_at_deadline_is_retained_but_not_counted(
    tmp_path, monkeypatch, planner_runs
):
    run = next(run for run in planner_runs if _supported(run))
    offset = 0
    verify_operation = qualification._verify_operation

    def monotonic_ns():
        return time.monotonic_ns() + offset

    def verify_then_deadline(*args, **kwargs):
        nonlocal offset
        verify_operation(*args, **kwargs)
        offset = run.duration_seconds * 1_000_000_000

    monkeypatch.setattr(
        qualification,
        "time",
        SimpleNamespace(monotonic_ns=monotonic_ns, time=time.time, sleep=time.sleep),
    )
    monkeypatch.setattr(qualification, "_verify_operation", verify_then_deadline)
    arguments = _qualification_args(run)
    arguments["environment"] = {
        "clock": "simulated deadline after real proof verification"
    }
    directory = tmp_path / "late"
    result = qualification.run_qualification(directory, **arguments)
    assert result["committed_operations"] == 1
    assert result["verified_operations"] == 0
    assert result["incomplete_run"] is True
    row = _values(directory / "execution" / "ledger.jsonl")[1]
    assert row["counted"] is False
    assert row["end_ns"] >= run.duration_seconds * 1_000_000_000
    assert (
        qualification.verify_shard(directory, matrix_path=MATRIX, schema_path=SCHEMA)[
            "verified_operations"
        ]
        == 0
    )


def test_cli_smoke_and_verify_use_real_spawned_path(tmp_path):
    directory = tmp_path / "cli"
    script = ROOT / "scripts" / "run_apcc_qualification_v3.py"
    command = [sys.executable, str(script)]
    smoke_process = subprocess.run(
        command + ["smoke", "--output", str(directory), "--operations", "2"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert smoke_process.returncode == 0, smoke_process.stderr
    result = json.loads(smoke_process.stdout.splitlines()[-1])
    assert result["verified_operations"] == 2
    assert result["qualification_evidence"] is False
    verify = subprocess.run(
        command
        + [
            "verify",
            "--smoke",
            "--output",
            str(directory),
            "--expected-ledger-sha256",
            result["ledger_sha256"],
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert verify.returncode == 0, verify.stderr
    assert json.loads(verify.stdout)["verified_operations"] == 2
    before = (directory / "ledger.jsonl").read_bytes()
    duplicate = subprocess.run(
        command + ["smoke", "--output", str(directory)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert duplicate.returncode == 1
    assert (directory / "ledger.jsonl").read_bytes() == before


def _launch_config():
    public = b"x" * 32
    return AuthorityObserverLaunchConfig(
        experiment_id="test-experiment",
        run_id="test-run",
        authority_store_id="test-store",
        backend_kind="sqlite",
        backend_instance="test-instance",
        backend_schema=None,
        controller_key_id=sha256_digest(public),
        controller_key_source=ControllerKeySourceRef("unused-controller-key", public),
    )


def test_observer_launch_default_lifetime_remains_five_minutes(smoke):
    assert _launch_config().launch_lifetime_ms == 300_000
    _, _, values = smoke
    header = values[0]
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    issued = int(launch.not_before_ms)
    assert int(launch.not_after_ms) - issued == 300_000
    arguments = dict(
        pinned_controller_public_key=b64u_decode(header["controller_public_key"]),
        expected=qualification._expectations(launch),
    )
    launch.verify(now_ms=issued + 299_999, **arguments)
    with pytest.raises(ValueError, match="trust binding"):
        launch.verify(now_ms=issued + 300_001, **arguments)


@pytest.mark.parametrize("lifetime", [1, 300_000, 1_100_000, 1_200_000])
def test_observer_launch_accepts_explicit_bounded_lifetime(lifetime):
    assert (
        replace(_launch_config(), launch_lifetime_ms=lifetime).launch_lifetime_ms
        == lifetime
    )


@pytest.mark.parametrize(
    "lifetime", [0, -1, True, False, 300_000.0, "300000", None, 1_200_001]
)
def test_observer_launch_rejects_invalid_lifetime_before_launch(lifetime):
    with pytest.raises((TypeError, ValueError)):
        replace(_launch_config(), launch_lifetime_ms=lifetime)


def test_thousand_second_qualification_has_valid_extended_signed_launch(
    incomplete_shard,
):
    directory, result, run = incomplete_shard
    assert run.duration_seconds == 1000
    header = result["header"]
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    issued, expires = int(launch.not_before_ms), int(launch.not_after_ms)
    assert expires - issued == 1_100_000
    arguments = dict(
        pinned_controller_public_key=b64u_decode(header["controller_public_key"]),
        expected=qualification._expectations(launch),
    )
    launch.verify(now_ms=issued + 300_001, **arguments)
    launch.verify(now_ms=issued + 1_000_000, **arguments)
    launch.verify(now_ms=expires, **arguments)
    with pytest.raises(ValueError, match="trust binding"):
        launch.verify(now_ms=expires + 1, **arguments)
    with pytest.raises(ValueError, match="signature"):
        replace(launch, not_after_ms=str(expires + 1)).verify(
            now_ms=expires, **arguments
        )
    assert (
        qualification.verify_shard(directory, matrix_path=MATRIX, schema_path=SCHEMA)[
            "incomplete_run"
        ]
        is True
    )


def test_longer_launch_does_not_relax_signed_status_freshness(smoke):
    _, _, values = smoke
    header, row = copy.deepcopy(values[0]), copy.deepcopy(values[1])
    row["verification_time_ms"] += 6001
    launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
    assert row["verification_time_ms"] < int(launch.not_after_ms)
    with pytest.raises(ValueError):
        qualification._verify_operation(
            row, header, _stream(header), qualification._trust(header)
        )


def test_shard_rejects_raw_replacement_after_artifact_validation(
    incomplete_shard, tmp_path, monkeypatch
):
    original, _, _ = incomplete_shard
    directory = tmp_path / "raced-copy"
    shutil.copytree(original, directory)
    read_artifact = qualification.read_artifact_run

    def read_then_replace(path):
        artifact = read_artifact(path)
        raw = artifact.path / "raw.jsonl"
        raw.write_bytes(raw.read_bytes() + b" ")
        return artifact

    monkeypatch.setattr(qualification, "read_artifact_run", read_then_replace)
    with pytest.raises(ValueError):
        qualification.verify_shard(directory, matrix_path=MATRIX, schema_path=SCHEMA)
    assert (original / "shard" / "raw.jsonl").read_bytes() != (
        directory / "shard" / "raw.jsonl"
    ).read_bytes()


def test_spawned_scheduler_and_observer_survive_idle_then_verify(spawned_request):
    config, _, execution, observer, request, launch_config = spawned_request
    assert execution.commit(request).outcome is CommitOutcome.COMMITTED
    time.sleep(3)
    target = execution.observation_target(request, request_nonce=b64u_encode(b"i" * 16))
    response = observer.client.observe(target)
    launch = observer.launch_attestation
    verified = AuthorityObservationVerificationStream(launch.session_id).consume(
        response,
        launch=launch,
        pinned_controller_public_key=launch_config.controller_key_source.expected_public_key,
        expected_experiment_id=launch_config.experiment_id,
        expected_run_id=launch_config.run_id,
        expected_launch=qualification._expectations(launch),
        trust=ScopedTrust(config.authority.trust_bindings),
        now_ms=int(time.time() * 1000),
        maximum_staleness_ms=5000,
    )
    assert verified.consumable is True
    assert (
        verified.authority_proof
        is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
    )
    assert (
        sha256_digest(response.snapshot.output_bytes)
        == request.receipt.payload.output_digest
    )


def test_stalled_partial_observer_frame_still_expires_and_cannot_resume(
    spawned_request,
):
    _, _, execution, observer, request, _ = spawned_request
    assert execution.commit(request).outcome is CommitOutcome.COMMITTED
    target = execution.observation_target(request, request_nonce=b64u_encode(b"p" * 16))
    channel = observer.client._channel_socket
    assert channel is not None
    started = time.monotonic()
    channel.sendall(b"\x00")
    time.sleep(2.5)
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        observer.client.observe(target)
    assert time.monotonic() - started < 4.5
    with pytest.raises(GovernanceBypassDenied):
        observer.client.observe(target)
