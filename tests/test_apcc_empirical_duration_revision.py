from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from constitutional_swarm.apcc_empirical.artifacts import (
    ArtifactViolation,
    RawArtifactWriter,
    read_artifact_run,
)
from constitutional_swarm.apcc_empirical.contract import (
    ContractViolation,
    canonical_json_bytes,
    load_matrix,
    load_raw_result,
    planned_ablation_performance_runs,
    planned_performance_runs,
    planning_cardinalities,
    validate_matrix,
)
from tests.test_apcc_empirical_contract import _raw_record_for_family


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "experiments" / "apcc-1"


def _performance_record():
    matrix = load_matrix(DATA / "matrix.v2.json")
    record = _raw_record_for_family(matrix, "performance")
    record["schema_version"] = matrix.raw_result_schema_version
    return matrix, record


def test_generator_preserves_frozen_inputs_and_reproduces_v2(tmp_path: Path) -> None:
    names = ("matrix.v1.json", "raw-result.schema.json", "qualification-live.v2.json")
    before = {
        name: hashlib.sha256((DATA / name).read_bytes()).hexdigest() for name in names
    }
    command = [
        sys.executable,
        str(ROOT / "scripts" / "generate_apcc_matrix_v2.py"),
        "--output",
        str(tmp_path),
    ]
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(command + ["--check"], check=True, capture_output=True)
    for name in ("matrix.v2.json", "raw-result.v2.schema.json"):
        assert (tmp_path / name).read_bytes() == (DATA / name).read_bytes()
    assert before == {
        name: hashlib.sha256((DATA / name).read_bytes()).hexdigest() for name in names
    }


def test_v2_changes_only_revision_and_duration_policy() -> None:
    original = json.loads((DATA / "matrix.v1.json").read_bytes())
    revised = json.loads((DATA / "matrix.v2.json").read_bytes())
    assert (
        revised.pop("performance_duration_policy")
        == "max-base-duration-ceil-minimum-operations-over-target-rate"
    )
    revised["revision"] = original["revision"]
    assert revised == original


@pytest.mark.parametrize(("rate", "duration"), [(10, 1000), (100, 100), (500, 30)])
def test_version_qualified_duration_preserves_minimum_operations(
    rate: int, duration: int
) -> None:
    old = load_matrix(DATA / "matrix.v1.json")
    new = load_matrix(DATA / "matrix.v2.json")
    assert old.performance_duration_seconds(rate) == 30
    assert new.performance_duration_seconds(rate) == duration
    assert duration * rate >= 10_000
    assert new.repetitions.minimum_completed_operations == 10_000


@pytest.mark.parametrize("rate", [True, 0, -1, 20, 10.0])
def test_duration_rejects_unplanned_or_noninteger_rates(rate: object) -> None:
    matrix = load_matrix(DATA / "matrix.v2.json")
    with pytest.raises(ContractViolation, match="target rate"):
        matrix.performance_duration_seconds(rate)  # type: ignore[arg-type]


def test_planners_preserve_cells_and_w6_while_extending_low_rates() -> None:
    old = load_matrix(DATA / "matrix.v1.json")
    new = load_matrix(DATA / "matrix.v2.json")
    assert planning_cardinalities(new) == planning_cardinalities(old)
    old_runs = tuple(planned_performance_runs(old))
    new_runs = tuple(planned_performance_runs(new))
    assert [(run.trial_id, run.sub_seed) for run in old_runs] == [
        (run.trial_id, run.sub_seed) for run in new_runs
    ]
    duration_total = 0
    fixed = 0
    for run in new_runs:
        if run.workload_id == "W6":
            assert run.duration_seconds is None and run.operation_limit == 10_000
            fixed += 1
        else:
            assert (
                run.duration_seconds
                == {10: 1000, 100: 100, 500: 30}[run.target_rate_per_second]
            )
            assert run.operation_limit is None
            duration_total += run.duration_seconds
    ablations = tuple(planned_ablation_performance_runs(new))
    assert len(ablations) == 780
    assert {run.duration_seconds for run in ablations} == {100}
    assert fixed == 2760
    assert duration_total + sum(run.duration_seconds for run in ablations) == 11_513_600


@pytest.mark.parametrize(
    "mutation",
    ["missing-policy", "wrong-policy", "v1-extra-policy", "unknown-revision"],
)
def test_revision_policy_is_exact_and_cannot_reinterpret_v1(mutation: str) -> None:
    value = json.loads((DATA / "matrix.v2.json").read_bytes())
    if mutation == "missing-policy":
        value.pop("performance_duration_policy")
    elif mutation == "wrong-policy":
        value["performance_duration_policy"] = "fixed-30"
    elif mutation == "v1-extra-policy":
        value["revision"] = "apcc-1.matrix.v1"
    else:
        value["revision"] = "apcc-1.matrix.v3"
    with pytest.raises(ContractViolation):
        validate_matrix(value)


def test_raw_v2_duration_and_completed_count_are_independently_bound(
    tmp_path: Path,
) -> None:
    matrix, record = _performance_record()
    path = tmp_path / "record.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record
    for field, value in (("duration_seconds", 30), ("completed_operations", 9999)):
        bad = copy.deepcopy(record)
        bad["workload_evidence"][field] = value
        path.write_bytes(canonical_json_bytes(bad))
        with pytest.raises(ContractViolation):
            load_raw_result(path, matrix=matrix)
    record["workload_evidence"]["completed_operations"] = 9999
    record["workload_evidence"]["incomplete_run"] = True
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record
    record["schema_version"] = "apcc-1.raw-result.v1"
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation, match="schema version"):
        load_raw_result(path, matrix=matrix)


def test_v2_artifact_roundtrip_and_cross_version_schema_rejection(
    tmp_path: Path,
) -> None:
    matrix, record = _performance_record()
    args = dict(
        matrix=matrix,
        matrix_path=DATA / "matrix.v2.json",
        planned_trial_ids=[record["trial_id"]],
        environment={"os": "test"},
        environment_id=record["environment_id"],
        git_sha=record["git_sha"],
        tool_versions=record["tool_versions"],
    )
    with pytest.raises(ArtifactViolation, match="reviewed schema"):
        RawArtifactWriter(
            tmp_path, "mixed", schema_path=DATA / "raw-result.schema.json", **args
        )
    writer = RawArtifactWriter(
        tmp_path, "v2", schema_path=DATA / "raw-result.v2.schema.json", **args
    )
    writer.append(record)
    run = writer.finalize()
    assert (run / "matrix.v2.json").is_file()
    assert not (run / "matrix.v1.json").exists()
    loaded = read_artifact_run(run)
    assert loaded.record_count == 1
    assert loaded.manifest["schema_version"] == "apcc-1.raw-result.v2"
    assert loaded.manifest["matrix_sha256"] == matrix.matrix_sha256


@pytest.mark.parametrize(("rate", "duration"), [(10, 1000), (100, 100), (500, 30)])
def test_v2_schema_binds_rate_duration_and_completion(rate: int, duration: int) -> None:
    _, record = _performance_record()
    schema = Draft202012Validator(
        json.loads((DATA / "raw-result.v2.schema.json").read_bytes())
    )
    record["target_rate_per_second"] = rate
    record["workload_evidence"]["duration_seconds"] = duration
    assert not list(schema.iter_errors(record))
    record["workload_evidence"]["duration_seconds"] = duration + 1
    assert list(schema.iter_errors(record))
    record["workload_evidence"]["duration_seconds"] = duration
    record["workload_evidence"]["completed_operations"] = 9999
    assert list(schema.iter_errors(record))
    record["workload_evidence"]["incomplete_run"] = True
    assert not list(schema.iter_errors(record))


@pytest.mark.parametrize("substitution", ["manifest", "matrix", "schema"])
def test_artifact_reader_rejects_cross_version_substitution_with_rehashed_manifest(
    tmp_path: Path, substitution: str
) -> None:
    matrix, record = _performance_record()
    writer = RawArtifactWriter(
        tmp_path,
        "run",
        matrix=matrix,
        matrix_path=DATA / "matrix.v2.json",
        schema_path=DATA / "raw-result.v2.schema.json",
        planned_trial_ids=[record["trial_id"]],
        environment={"os": "test"},
        environment_id=record["environment_id"],
        git_sha=record["git_sha"],
        tool_versions=record["tool_versions"],
    )
    writer.append(record)
    run = writer.finalize()
    assert read_artifact_run(run).record_count == 1
    if substitution == "manifest":
        path = run / "manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["matrix_revision"] = "apcc-1.matrix.v1"
        manifest["schema_version"] = "apcc-1.raw-result.v1"
        path.write_bytes(canonical_json_bytes(manifest))
    elif substitution == "matrix":
        (run / "matrix.v2.json").write_bytes((DATA / "matrix.v1.json").read_bytes())
    else:
        (run / "raw-result.schema.json").write_bytes(
            (DATA / "raw-result.schema.json").read_bytes()
        )
    (run / "SHA256SUMS").write_bytes(
        b"".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n".encode()
            for path in sorted(run.iterdir())
            if path.name != "SHA256SUMS"
        )
    )
    with pytest.raises(ArtifactViolation):
        read_artifact_run(run)


def test_generator_rejects_modified_frozen_input(tmp_path: Path) -> None:
    for name in ("matrix.v1.json", "raw-result.schema.json"):
        (tmp_path / name).write_bytes((DATA / name).read_bytes())
    with (tmp_path / "matrix.v1.json").open("ab") as stream:
        stream.write(b" ")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_apcc_matrix_v2.py"),
            "--source",
            str(tmp_path),
            "--output",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "frozen input hash mismatch" in result.stderr
    assert not (tmp_path / "matrix.v2.json").exists()
