"""In-window host monitor: record-only, and never in the way of the campaign."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import threading
import time

import pytest

from scripts import w2_host_monitor, w2_host_probe

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "w2-cell" / "action.yml"
CAMPAIGN_STEP = "Run W2 cold qualification campaign"


def _records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _campaign_step() -> dict[str, object]:
    yaml = pytest.importorskip("yaml")
    steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    return next(step for step in steps if step["name"] == CAMPAIGN_STEP)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_sample_runs_the_probe_work_and_records_host_counters() -> None:
    record = w2_host_monitor.sample(4)
    assert record["type"] == "sample"
    assert record["sequence"] == 4
    assert record["cpu_ns"] > 0
    assert record["checksum"] == w2_host_probe.run_round()["checksum"]
    assert set(record["parts_cpu_ns"]) == {"json", "sha256", "sqlite", "loop"}
    ticks = record["host_cpu_ticks"]
    assert ticks is None or len(ticks) == 8


def test_monitor_writes_header_samples_and_footer_until_stopped(tmp_path: Path) -> None:
    output = tmp_path / "window.jsonl"
    stop = threading.Event()
    timer = threading.Timer(1.0, stop.set)
    timer.start()
    try:
        count = w2_host_monitor.monitor(output, 0.05, 60.0, stop.wait)
    finally:
        timer.cancel()
    records = _records(output)
    assert records[0]["type"] == "header"
    assert records[0]["record_only"] is True
    assert records[0]["probe_revision"] == w2_host_probe.PROBE_REVISION
    samples = [record for record in records if record["type"] == "sample"]
    assert count == len(samples) >= 1
    assert [record["sequence"] for record in samples] == list(range(count))
    assert records[-1] == {"type": "footer", "samples": count, "stopped": True}
    with pytest.raises(FileExistsError):
        w2_host_monitor.monitor(output, 0.05, 60.0, stop.wait)


def test_monitor_stops_at_its_maximum_lifetime(tmp_path: Path) -> None:
    output = tmp_path / "window.jsonl"
    started = time.monotonic()
    w2_host_monitor.monitor(output, 30.0, 0.01, threading.Event().wait)
    assert time.monotonic() - started < 20.0
    assert _records(output)[-1]["stopped"] is False


def test_cli_stops_on_sigterm_and_leaves_a_readable_file(tmp_path: Path) -> None:
    output = tmp_path / "window.jsonl"
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts" / "w2_host_monitor.py"),
            "--output",
            str(output),
            "--interval-seconds",
            "0.05",
        ],
        cwd=tmp_path,
    )
    try:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if output.exists() and len(output.read_text(encoding="utf-8").splitlines()) >= 2:
                break
            time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=30.0) == 0
    finally:
        if process.poll() is None:
            process.kill()
    records = _records(output)
    assert records[0]["type"] == "header"
    assert records[-1]["type"] == "footer"


def test_campaign_step_starts_the_monitor_without_any_limit() -> None:
    step = _campaign_step()
    run = str(step["run"])
    assert step["if"] == "steps.probe.outputs.void == 'false'"
    assert run.index("scripts/w2_host_monitor.py") < run.index("scripts/run_apcc_w2_campaign.py")
    assert "--max-cpu-ms" not in run
    assert "GITHUB_OUTPUT" not in run
    assert "host-probe-window.jsonl" in run


def _run_campaign_step(tmp_path: Path, shim: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the action's campaign step with ``python`` replaced by ``shim``."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_shim = bin_dir / "python"
    python_shim.write_text("#!/usr/bin/env bash\n" + shim, encoding="utf-8")
    python_shim.chmod(0o755)
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
            "W2_OUT_ROOT": str(tmp_path / "out"),
            "W2_BUNDLE_DIR": str(bundle_dir),
            "DURATION_NS": "1",
            "SCHEDULED_OPERATIONS": "1",
            "ADMISSION_GRACE_NS": "1",
            "OPERATION_SLA_NS": "1",
            "DRAIN_NS": "1",
            "OPERATION_FLOOR": "1",
            "WINDOWS": "1",
        }
    )
    completed = subprocess.run(
        ["bash", "-c", str(_campaign_step()["run"])],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return completed, bundle_dir


@pytest.mark.parametrize("campaign_rc", (0, 7))
def test_campaign_step_keeps_the_campaign_exit_code_and_stops_the_monitor(
    tmp_path: Path, campaign_rc: int
) -> None:
    # The campaign is a stub that ends once the real monitor has written its
    # header; everything else runs for real.
    completed, bundle_dir = _run_campaign_step(
        tmp_path,
        'if [ "$1" = "scripts/run_apcc_w2_campaign.py" ]; then\n'
        "  for _ in $(seq 1 300); do\n"
        '    [ -s "${W2_BUNDLE_DIR}/host-probe-window.jsonl" ] && break\n'
        "    sleep 0.1\n"
        "  done\n"
        f"  exit {campaign_rc}\n"
        "fi\n"
        f'exec {shlex.quote(sys.executable)} "$@"\n',
    )
    assert completed.returncode == campaign_rc, completed.stderr
    assert "::warning::" not in completed.stdout
    records = _records(bundle_dir / "host-probe-window.jsonl")
    assert records[0]["type"] == "header"
    assert records[-1]["type"] == "footer"
    assert records[-1]["stopped"] is True
    assert not _pid_alive(int(records[0]["pid"]))  # type: ignore[call-overload]


def test_campaign_step_survives_a_monitor_that_cannot_start(tmp_path: Path) -> None:
    completed, _ = _run_campaign_step(
        tmp_path,
        'if [ "$1" = "scripts/run_apcc_w2_campaign.py" ]; then exit 0; fi\nexit 3\n',
    )
    assert completed.returncode == 0, completed.stderr
    assert "::warning::" in completed.stdout


def test_campaign_step_kills_a_monitor_that_ignores_sigterm(tmp_path: Path) -> None:
    pid_file = tmp_path / "monitor.pid"
    started = time.monotonic()
    completed, _ = _run_campaign_step(
        tmp_path,
        'if [ "$1" = "scripts/run_apcc_w2_campaign.py" ]; then\n'
        f"  for _ in $(seq 1 300); do [ -s {shlex.quote(str(pid_file))} ] && break; sleep 0.1; done\n"
        "  exit 5\n"
        "fi\n"
        "trap '' TERM\n"
        f"echo $$ > {shlex.quote(str(pid_file))}\n"
        "exec sleep 600\n",
    )
    assert completed.returncode == 5, completed.stderr
    assert time.monotonic() - started < 60.0
    assert "::warning::" in completed.stdout
    assert not _pid_alive(int(pid_file.read_text(encoding="utf-8")))
