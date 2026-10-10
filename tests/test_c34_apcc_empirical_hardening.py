"""C34 regression tests for the APCC empirical harness.

Every test here is unit-level: no network, no ``uv sync``, no historical worker
process.  B5 supervisor methods are exercised on adapters built with
``__new__`` and explicitly injected state.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import inspect
import io
import json
import os
import stat
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import strict_json
from constitutional_swarm.apcc_empirical import adapters as adapters_module
from constitutional_swarm.apcc_empirical import artifacts as artifacts_module
from constitutional_swarm.apcc_empirical import contract as contract_module
from constitutional_swarm.apcc_empirical import historical_gcb
from constitutional_swarm.apcc_empirical.adapters import (
    BaselineEvidence,
    Capability,
    ExperimentalSQLiteAdapter,
    TrialStimulus,
    TrustedKey,
    create_baseline_adapter,
    native_evidence_for_variant,
)
from constitutional_swarm.apcc_empirical.contract import (
    ContractViolation,
    canonical_json_bytes,
    derive_attack_trial,
    load_matrix,
)
from constitutional_swarm.apcc_empirical.historical_gcb import (
    HistoricalGCBAdapter,
    HistoricalSnapshotError,
)

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "experiments" / "apcc-1" / "matrix.v1.json"
SCHEMA_PATH = ROOT / "experiments" / "apcc-1" / "raw-result.schema.json"


def _bare_b5(**attributes: Any) -> HistoricalGCBAdapter:
    adapter = HistoricalGCBAdapter.__new__(HistoricalGCBAdapter)
    for name, value in attributes.items():
        setattr(adapter, name, value)
    return adapter


def _write_tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir()
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root


# --------------------------------------------------------------------------- apcc-core-4


def test_snapshot_hash_rejects_merged_or_split_file_trees(tmp_path: Path) -> None:
    split = _write_tree(tmp_path / "split", {"a": b"x", "b": b"y"})
    merged = _write_tree(tmp_path / "merged", {"a": b"xb\0y"})
    split_digest = _bare_b5(_snapshot=split)._hash_snapshot()
    merged_digest = _bare_b5(_snapshot=merged)._hash_snapshot()
    assert split_digest != merged_digest


def test_one_tree_hash_is_shared_by_supervisor_and_both_subprocess_scripts(
    tmp_path: Path,
) -> None:
    source = historical_gcb._HASH_TREE_SOURCE
    assert historical_gcb._WORKER.count(source) == 1
    assert historical_gcb._ENVIRONMENT_IDENTITY_SCRIPT.count(source) == 1
    compile(historical_gcb._WORKER, "<worker>", "exec")
    compile(historical_gcb._ENVIRONMENT_IDENTITY_SCRIPT, "<environment>", "exec")
    for script in (historical_gcb._WORKER, historical_gcb._ENVIRONMENT_IDENTITY_SCRIPT):
        names = [
            node.name for node in ast.walk(ast.parse(script)) if isinstance(node, ast.FunctionDef)
        ]
        assert names.count("hash_tree") == 1

    tree = _write_tree(
        tmp_path / "tree",
        {"pkg/mod.py": b"print(1)\n", "pkg/__pycache__/mod.cpython-313.pyc": b"pyc"},
    )
    # The snapshot includes planted bytecode; environment hashes skip it.
    assert _bare_b5(_snapshot=tree)._hash_snapshot() == historical_gcb._hash_tree(
        tree, exclude_bytecode=False
    )
    assert historical_gcb._hash_tree(tree, exclude_bytecode=False) != historical_gcb._hash_tree(
        tree, exclude_bytecode=True
    )


# --------------------------------------------------------------------------- apcc-core-6


def _key_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        name: base64.b64encode(bytes([index]) * 32).decode("ascii")
        for index, name in enumerate(("verifier", "admin", "agent", "journal"), 1)
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


def _keyed_adapter(tmp_path: Path, raw: bytes | None, mode: int = 0o600) -> HistoricalGCBAdapter:
    database = tmp_path / "authority.sqlite3"
    if raw is not None:
        key_path = database.with_suffix(database.suffix + ".b5-keys.json")
        key_path.write_bytes(raw)
        key_path.chmod(mode)
    return _bare_b5(path=database, _created_paths={})


@pytest.mark.parametrize("journal", [True, False], ids=["current", "legacy-3-key"])
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_b5_key_file_with_group_or_other_permissions_is_rejected(
    tmp_path: Path, mode: int, journal: bool
) -> None:
    values = _key_values() if journal else _key_values(journal=None)
    adapter = _keyed_adapter(tmp_path, json.dumps(values).encode(), mode=mode)
    with pytest.raises(HistoricalSnapshotError, match="key file is unsafe"):
        adapter._load_or_create_keys()


@pytest.mark.parametrize("journal", [True, False], ids=["current", "legacy-3-key"])
def test_b5_hard_linked_key_file_is_rejected(tmp_path: Path, journal: bool) -> None:
    values = _key_values() if journal else _key_values(journal=None)
    adapter = _keyed_adapter(tmp_path, json.dumps(values).encode())
    key_path = adapter.path.with_suffix(adapter.path.suffix + ".b5-keys.json")
    os.link(key_path, tmp_path / "second-link")
    with pytest.raises(HistoricalSnapshotError, match="key file is unsafe"):
        adapter._load_or_create_keys()


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(_key_values(agent=base64.b64encode(b"\x01" * 31).decode())).encode(),
        json.dumps(
            _key_values(journal=None, agent=base64.b64encode(b"\x01" * 31).decode())
        ).encode(),
        json.dumps(_key_values(verifier=base64.b64encode(b"\x01" * 33).decode())).encode(),
        json.dumps(_key_values(journal=None)).encode(),
        json.dumps(_key_values(admin="not base64!")).encode(),
        json.dumps(_key_values(admin=7)).encode(),
        b'{"verifier":"AA==","verifier":"AA==","admin":"","agent":"","journal":""}',
    ],
    ids=[
        "short-seed",
        "legacy-short-seed",
        "long-seed",
        "no-journal-secret",
        "bad-b64",
        "non-string",
        "dup-key",
    ],
)
def test_b5_malformed_key_file_is_rejected(tmp_path: Path, raw: bytes) -> None:
    adapter = _keyed_adapter(tmp_path, raw)
    with pytest.raises(HistoricalSnapshotError, match="key file is malformed"):
        adapter._load_or_create_keys()


def test_b5_key_file_symlink_message_is_preserved(tmp_path: Path) -> None:
    adapter = _keyed_adapter(tmp_path, None)
    target = tmp_path / "target"
    target.write_text("{}")
    adapter.path.with_suffix(adapter.path.suffix + ".b5-keys.json").symlink_to(target)
    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        adapter._load_or_create_keys()


def test_b5_created_key_file_is_private_and_round_trips(tmp_path: Path) -> None:
    adapter = _keyed_adapter(tmp_path, None)
    seeds, journal_secret = adapter._load_or_create_keys()
    key_path = adapter.path.with_suffix(adapter.path.suffix + ".b5-keys.json")
    assert stat.S_IMODE(key_path.stat().st_mode) & 0o077 == 0
    assert len(seeds) == 3
    assert all(len(seed) == 32 for seed in (*seeds, journal_secret))
    assert journal_secret not in seeds
    reloaded = _bare_b5(path=adapter.path, _created_paths={})._load_or_create_keys()
    assert reloaded == (seeds, journal_secret)


def test_b5_journal_mac_keys_do_not_derive_from_the_verifier_signing_seed() -> None:
    seeds = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
    base = _bare_b5(_seeds=seeds, _journal_secret=b"\x04" * 32)
    rotated_seed = _bare_b5(_seeds=(b"\x09" * 32, *seeds[1:]), _journal_secret=b"\x04" * 32)
    rotated_secret = _bare_b5(_seeds=seeds, _journal_secret=b"\x05" * 32)
    assert base._journal_mac_key() == rotated_seed._journal_mac_key()
    assert base._journal_head_mac_key() == rotated_seed._journal_head_mac_key()
    assert base._journal_mac_key() != rotated_secret._journal_mac_key()
    assert base._journal_mac_key() != base._journal_head_mac_key()
    legacy = hmac.new(
        seeds[0],
        b"constitutional-swarm/APCC-B5/journal-mac-kdf/v1\0"
        + historical_gcb.GCB1_COMMIT_SHA.encode()
        + b"\0"
        + historical_gcb.GCB1_LOCK_SHA256.encode(),
        hashlib.sha256,
    ).digest()
    assert base._journal_mac_key() != legacy


def test_b5_journal_secret_is_not_sent_to_the_worker() -> None:
    source = inspect.getsource(HistoricalGCBAdapter._start_worker)
    assert "_journal_secret" not in source
    assert '("verifier", "admin", "agent")' in source


# --------------------------------------------------------------------------- apcc-core-5


class _PipeProcess:
    """Minimal stand-in for the worker Popen: stdin captured, stdout a real pipe."""

    def __init__(self) -> None:
        read_end, self.write_end = os.pipe()
        self.stdin = io.StringIO()
        self.stdout = os.fdopen(read_end, "r")
        self.stderr = None

    def reply(self, frame: dict[str, object]) -> None:
        os.write(self.write_end, json.dumps(frame).encode() + b"\n")

    def close(self) -> None:
        self.stdout.close()
        os.close(self.write_end)


def _rpc_adapter(process: _PipeProcess) -> HistoricalGCBAdapter:
    return _bare_b5(
        _secret=b"\x07" * 32,
        _sequence=0,
        _stdout_buffer=bytearray(),
        _process=process,
        _rpc_timeout_seconds=5.0,
    )


def test_b5_reflected_supervisor_frame_is_not_accepted_as_a_worker_response() -> None:
    process = _PipeProcess()
    try:
        adapter = _rpc_adapter(process)
        envelope = adapter._envelope({"command": "identity", "ok": True})
        process.reply(dict(envelope))
        with pytest.raises(HistoricalSnapshotError, match="not authenticated"):
            adapter._send_envelope(envelope)
    finally:
        process.close()


def test_b5_worker_tagged_response_is_accepted() -> None:
    process = _PipeProcess()
    try:
        adapter = _rpc_adapter(process)
        envelope = adapter._envelope({"command": "identity"})
        body = {"ok": True, "value": 1}
        sequence = envelope["sequence"]
        process.reply(
            {
                "sequence": sequence,
                "body": body,
                "mac": historical_gcb._frame_mac(b"\x07" * 32, "w2s", sequence, body),
            }
        )
        assert adapter._send_envelope(envelope) == body
    finally:
        process.close()


def test_b5_worker_script_uses_the_same_direction_bound_frame_mac() -> None:
    tree = ast.parse(historical_gcb._WORKER)
    wanted = {"canonical", "mac_for"}
    functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {node.name for node in functions} == wanted
    secret = b"\x08" * 32
    namespace: dict[str, Any] = {
        "json": json,
        "hmac": hmac,
        "hashlib": hashlib,
        "secret": secret,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<worker-mac>", "exec"), namespace)
    body = {"ok": True}
    for direction in ("s2w", "w2s"):
        assert namespace["mac_for"](direction, 3, body) == historical_gcb._frame_mac(
            secret, direction, 3, body
        )
    assert namespace["mac_for"]("s2w", 3, body) != namespace["mac_for"]("w2s", 3, body)
    assert 'mac_for("s2w", sequence, body)' in historical_gcb._WORKER
    assert 'mac_for("w2s", sequence, body)' in historical_gcb._WORKER


# --------------------------------------------------------------------------- apcc-core-8


def _attacker_injected_evidence() -> BaselineEvidence:
    attacker = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
    attacker_public = attacker.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    valid = BaselineEvidence.valid()
    injected = replace(
        valid,
        signer_key_id="attacker-key",
        trusted_keys=(*valid.trusted_keys, TrustedKey("attacker-key", attacker_public)),
    )
    encoded = injected.canonical_statement_bytes()
    return replace(injected, encoded_statement=encoded, signature=attacker.sign(encoded))


def test_b4_ignores_trust_roots_carried_by_the_verified_evidence(tmp_path: Path) -> None:
    adapter = create_baseline_adapter("B4", tmp_path / "b4.db")
    stimulus = TrialStimulus.attack(
        b"payload",
        attack_id="unknown-key",
        capabilities=frozenset({Capability.PROOF_VALIDATION}),
        evidence=_attacker_injected_evidence(),
    )
    observation = adapter.execute(stimulus)
    assert observation.authoritative_outcome == "denied"
    assert observation.artifact_visible is False


def test_b4_trusted_key_injection_variant_fails_closed(tmp_path: Path) -> None:
    evidence = native_evidence_for_variant("unknown-key:trusted-key-injection")
    assert any(key.key_id == evidence.signer_key_id for key in evidence.trusted_keys)
    assert (
        adapters_module.variant_id_for_native_evidence("unknown-key", evidence)
        == "unknown-key:trusted-key-injection"
    )
    adapter = create_baseline_adapter("B4", tmp_path / "b4-variant.db")
    observation = adapter.execute(
        TrialStimulus.attack(
            b"payload",
            attack_id="unknown-key",
            capabilities=frozenset({Capability.PROOF_VALIDATION}),
            evidence=evidence,
        )
    )
    assert observation.authoritative_outcome == "denied"


def test_b4_accepts_valid_evidence_under_the_pinned_root(tmp_path: Path) -> None:
    adapter = create_baseline_adapter("B4", tmp_path / "b4-control.db")
    observation = adapter.execute(TrialStimulus.control(b"payload"))
    assert observation.authoritative_outcome == "committed"


def test_b4_caller_pinned_trust_root_is_authoritative(tmp_path: Path) -> None:
    adapter = ExperimentalSQLiteAdapter(
        "B4", tmp_path / "b4-pinned.db", trusted_keys={"some-other-key": b"\x00" * 32}
    )
    observation = adapter.execute(TrialStimulus.control(b"payload"))
    assert observation.authoritative_outcome == "denied"


def test_b5_blocks_the_trusted_key_injection_variant_before_any_rpc() -> None:
    adapter = _bare_b5(_public_runtime_methods=frozenset())
    reason = adapter.blocked_reason("unknown-key:trusted-key-injection")
    assert reason is not None and "TrustedGovernanceBootstrap" in reason

    def no_rpc(_body: object) -> object:
        raise AssertionError("blocked variant must not reach the worker")

    adapter._rpc = no_rpc  # type: ignore[method-assign]
    stimulus = TrialStimulus.attack(
        b"payload",
        attack_id="unknown-key",
        capabilities=frozenset({Capability.PROOF_VALIDATION}),
        evidence=native_evidence_for_variant("unknown-key:trusted-key-injection"),
    )
    with pytest.raises(adapters_module.BaselineBlocked):
        adapter._execute_locked(stimulus)


# --------------------------------------------------------------------------- apcc-opt-8


def test_b5_database_path_validation_has_no_inert_bind_parameter() -> None:
    signature = inspect.signature(HistoricalGCBAdapter._validate_worker_database_path)
    assert list(signature.parameters) == ["self"]


# --------------------------------------------------------------------------- apcc-opt-4


def _raw_record(matrix: Any) -> dict[str, object]:
    trial = derive_attack_trial(
        matrix, baseline_id="B6", store="sqlite", attack_id="missing-proof", trial_index=0
    )
    return {
        "ablation_id": None,
        "ablation_classification": None,
        "artifact_sha256": "1" * 64,
        "attack_id": "missing-proof",
        "authoritative_compromise": False,
        "authoritative_outcome": "none",
        "baseline_id": "B6",
        "byte_counts": {"certificate": 0},
        "cache_state": "cold",
        "case_index": None,
        "condition_id": None,
        "concurrency": 1,
        "cost_saved_ns": None,
        "dag": "single-node",
        "database_index": None,
        "detected": True,
        "distinct_states": None,
        "environment_id": "test",
        "fail_closed": True,
        "failed_invariant": None,
        "failure_code": "EXPECTED_REJECTION",
        "fault_target": None,
        "formal_evidence": None,
        "generated_states": None,
        "git_sha": "0" * 40,
        "incorrect_current_consumption": False,
        "input_bytes": 1024,
        "matrix_revision": matrix.revision,
        "matrix_sha256": matrix.matrix_sha256,
        "outcome": "rejected",
        "output_bytes": 4096,
        "phase": None,
        "record_type": "functional-attack",
        "recovered": False,
        "repetition": trial.seed_repetition,
        "schema_version": "apcc-1.raw-result.v1",
        "search_depth": None,
        "seed": trial.seed,
        "store": "sqlite",
        "sub_seed_b64u": trial.sub_seed_b64u,
        "successful_commits": None,
        "target_rate_per_second": 10,
        "timings_ns": {"total": 1},
        "tool_versions": {"python": "test"},
        "trial_id": trial.trial_id,
        "trial_index": trial.trial_index,
        "witness_marker": None,
        "workload_id": "W1",
        "workload_evidence": {
            "agents": 1,
            "completed_operations": 1,
            "duration_seconds": None,
            "incomplete_run": False,
            "lifecycle_mode": "single-trial",
            "nodes": 1,
            "operation_limit": None,
            "parameters": {},
            "payload_pair": [1024, 4096],
            "pre_run_queries": 0,
            "schedule": "none",
            "warmup_runs_completed": 0,
        },
    }


def test_bytes_loaders_match_path_loaders_and_reject_noncanonical_bytes() -> None:
    raw = MATRIX_PATH.read_bytes()
    matrix = contract_module.load_matrix_bytes(raw)
    assert matrix == load_matrix(MATRIX_PATH)
    record = _raw_record(matrix)
    encoded = canonical_json_bytes(record)
    assert contract_module.load_raw_result_bytes(encoded, matrix=matrix) == record
    with pytest.raises(ContractViolation, match="canonical JSON"):
        contract_module.load_raw_result_bytes(encoded.rstrip(b"\n"), matrix=matrix)
    with pytest.raises(ContractViolation, match="size"):
        contract_module.load_matrix_bytes(b" " * (1_048_576 + 1))
    with pytest.raises(TypeError):
        contract_module.load_matrix_bytes(str(MATRIX_PATH))  # type: ignore[arg-type]


def test_artifact_write_and_read_do_not_round_trip_through_temp_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record(matrix)
    writer = artifacts_module.RawArtifactWriter(
        tmp_path,
        "run-c34",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"])],
        environment={"os": "test"},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("artifact validation must not use temporary files")

    monkeypatch.setattr(tempfile, "TemporaryDirectory", forbidden)
    monkeypatch.setattr(tempfile, "mkdtemp", forbidden)
    writer.append(record)
    run = writer.finalize()
    assert artifacts_module.read_artifact_run(run).record_count == 1


# --------------------------------------------------------------------------- opt-1 / apcc-opt-5


def test_contract_duplicate_key_policy_is_the_shared_strict_json_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    original = strict_json.reject_duplicate_keys

    def spy(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        calls.append(len(pairs))
        return original(pairs)

    monkeypatch.setattr(strict_json, "reject_duplicate_keys", spy)
    contract_module.load_matrix_bytes(MATRIX_PATH.read_bytes())
    assert calls
    with pytest.raises(ContractViolation, match="duplicate key"):
        contract_module.load_matrix_bytes(b'{"a":1,"a":1}\n')
