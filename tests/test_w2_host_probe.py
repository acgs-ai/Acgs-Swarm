"""Host admission for W2 runs: the probe decides alone and before the campaign."""

from __future__ import annotations

import json
from pathlib import Path
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


def test_workflow_decides_before_any_w2_step_and_gates_them() -> None:
    yaml = pytest.importorskip("yaml")
    steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    names = [step["name"] for step in steps]
    probe = next(index for index, step in enumerate(steps) if step.get("id") == "probe")
    smoke = names.index("W2 smoke pre-flight")
    campaign = names.index("Run W2 cold qualification campaign")
    assert probe < smoke < campaign
    for index in (smoke, campaign):
        assert steps[index]["if"] == "steps.probe.outputs.void == 'false'"
    # The decision step may read nothing produced by the smoke run or campaign.
    assert "w2-campaign" not in steps[probe]["run"]
    assert "w2-smoke" not in steps[probe]["run"]
    after = next(step for step in steps if step["name"].startswith("Host CPU probe after"))
    assert "--max-cpu-ms" not in after["run"]


def test_committed_limit_is_240_ms_and_usable() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    expression = workflow["jobs"]["w2-cold-cell"]["with"]["host_probe_max_cpu_ms"]
    assert expression == "${{ inputs.host_probe_max_cpu_ms || '240' }}"
    assert w2_host_probe.parse_limit("240") == 240.0
