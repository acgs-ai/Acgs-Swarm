"""Host admission for W2 runs: the probe decides alone and before the campaign."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from scripts import w2_host_probe

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "w2-cell" / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "w2-qualification.yml"


def test_no_limit_records_without_deciding() -> None:
    assert w2_host_probe.parse_limit("") is None
    assert w2_host_probe.parse_limit("  ") is None
    assert w2_host_probe.decide(10_000.0, None) is None


def test_limit_admits_at_or_below_and_voids_above() -> None:
    assert w2_host_probe.decide(99.9, 100.0) is True
    assert w2_host_probe.decide(100.0, 100.0) is True
    assert w2_host_probe.decide(100.1, 100.0) is False


@pytest.mark.parametrize("raw", ("0", "-5", "nan", "inf", "fast"))
def test_unusable_limit_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        w2_host_probe.parse_limit(raw)


def test_every_round_does_the_same_work() -> None:
    first = w2_host_probe.run_round()
    second = w2_host_probe.run_round()
    assert first["checksum"] == second["checksum"]
    assert first["cpu_ns"] > 0
    assert set(first["parts_cpu_ns"]) == {"json", "sha256", "sqlite", "loop"}


def test_decision_uses_the_fastest_round() -> None:
    result = w2_host_probe.probe(3, 1e9, "before")
    rounds_ms = [entry["cpu_ns"] / 1e6 for entry in result["rounds"]]
    assert result["best_cpu_ms"] == round(min(rounds_ms), 3)
    assert result["admitted"] is True
    assert w2_host_probe.probe(3, 1e-6, "before")["admitted"] is False


def test_cli_writes_a_new_file_and_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "probe.json"
    command = [
        sys.executable,
        str(ROOT / "scripts" / "w2_host_probe.py"),
        "--output",
        str(output),
        "--rounds",
        "3",
        "--max-cpu-ms",
        "0.000001",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    recorded = json.loads(output.read_text(encoding="utf-8"))
    assert recorded["admitted"] is False
    assert recorded["revision"] == w2_host_probe.PROBE_REVISION
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode != 0


def _load_action_steps() -> list[dict[str, object]]:
    yaml = pytest.importorskip("yaml")
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    return list(action["runs"]["steps"])


def _run_probe_step(
    tmp_path: Path,
    *,
    max_cpu_ms: str,
    attempt: int,
    final_attempt: bool,
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    steps = _load_action_steps()
    probe_step = next(step for step in steps if step.get("id") == "probe")
    run_script = str(probe_step["run"])

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    python_shim = bin_dir / "python"
    python_shim.write_text(
        f'#!/usr/bin/env bash\nexec {shlex.quote(sys.executable)} "$@"\n',
        encoding="utf-8",
    )
    python_shim.chmod(0o755)

    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    github_output = tmp_path / "github-output.txt"
    github_summary = tmp_path / "github-summary.md"

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
            "W2_BUNDLE_DIR": str(bundle_dir),
            "GITHUB_OUTPUT": str(github_output),
            "GITHUB_STEP_SUMMARY": str(github_summary),
            "HOST_PROBE_MAX_CPU_MS": max_cpu_ms,
            "W2_ATTEMPT": str(attempt),
            "W2_FINAL_ATTEMPT": "true" if final_attempt else "false",
        }
    )
    completed = subprocess.run(
        ["bash", "-c", run_script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed, bundle_dir, github_output, github_summary


def test_workflow_decides_before_any_w2_step_and_gates_them() -> None:
    steps = _load_action_steps()
    names = [str(step["name"]) for step in steps]
    probe = next(index for index, step in enumerate(steps) if step.get("id") == "probe")
    smoke = names.index("W2 smoke pre-flight")
    campaign = names.index("Run W2 cold qualification campaign")
    assert probe < smoke < campaign
    for index in (smoke, campaign):
        assert steps[index]["if"] == "steps.probe.outputs.void == 'false'"
    # The decision step may read nothing produced by the smoke run or campaign.
    assert "w2-campaign" not in str(steps[probe]["run"])
    assert "w2-smoke" not in str(steps[probe]["run"])
    after = next(step for step in steps if str(step["name"]).startswith("Host CPU probe after"))
    assert "--max-cpu-ms" not in str(after["run"])
    assert "steps.probe.outputs.void == 'false'" in str(after["if"])
    audit = next(step for step in steps if str(step["name"]).startswith("Independent audit"))
    upload = next(
        step for step in steps if str(step["name"]).startswith("Upload sealed W2 qualification")
    )
    assert audit["if"] == "always()"
    assert upload["if"] == "always()"


def test_committed_limit_is_200_ms_and_usable() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["w2-cold-cell"]
    expression = job["with"]["host_probe_max_cpu_ms"]
    assert expression == "${{ inputs.host_probe_max_cpu_ms || '200' }}"
    assert w2_host_probe.parse_limit("200") == 200.0
    assert job["strategy"]["fail-fast"] is False


def test_action_probe_step_admitted(tmp_path: Path) -> None:
    completed, bundle_dir, github_output, _ = _run_probe_step(
        tmp_path,
        max_cpu_ms="1000000",
        attempt=1,
        final_attempt=False,
    )
    assert completed.returncode == 0, completed.stderr
    outputs = github_output.read_text(encoding="utf-8").splitlines()
    assert "void=false" in outputs
    assert not (bundle_dir / "host-void.json").exists()
    recorded = json.loads((bundle_dir / "host-probe-before.json").read_text(encoding="utf-8"))
    assert recorded["admitted"] is True


def test_action_probe_step_void_non_final_exits_zero(tmp_path: Path) -> None:
    completed, bundle_dir, github_output, github_summary = _run_probe_step(
        tmp_path,
        max_cpu_ms="0.000001",
        attempt=1,
        final_attempt=False,
    )
    assert completed.returncode == 0, completed.stderr
    outputs = github_output.read_text(encoding="utf-8").splitlines()
    assert "void=true" in outputs
    void_record = json.loads((bundle_dir / "host-void.json").read_text(encoding="utf-8"))
    assert void_record["void"] is True
    assert void_record["attempt"] == 1
    assert void_record["reason"] == "host_cpu_probe_over_limit"
    assert void_record["max_cpu_ms"] == 0.000001
    assert "NO ADMISSIBLE HOST" not in github_summary.read_text(encoding="utf-8")


def test_action_probe_step_void_final_attempt_fails_red(tmp_path: Path) -> None:
    completed, bundle_dir, github_output, github_summary = _run_probe_step(
        tmp_path,
        max_cpu_ms="0.000001",
        attempt=3,
        final_attempt=True,
    )
    assert completed.returncode != 0
    outputs = github_output.read_text(encoding="utf-8").splitlines()
    assert "void=true" in outputs
    void_record = json.loads((bundle_dir / "host-void.json").read_text(encoding="utf-8"))
    assert void_record["void"] is True
    assert void_record["attempt"] == 3
    assert void_record["reason"] == "host_cpu_probe_over_limit"
    assert void_record["max_cpu_ms"] == 0.000001
    assert "NO ADMISSIBLE HOST" in github_summary.read_text(encoding="utf-8")
    assert "::error::" in completed.stdout
