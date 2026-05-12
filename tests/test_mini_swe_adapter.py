"""Tests for the optional mini-swe-agent external baseline adapter."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from constitutional_swarm.swe_bench.agent import SWEPatch
from constitutional_swarm.swe_bench.mini_swe_agent import (
    BACKEND_MINI_EXTERNAL_BASELINE,
    SCORE_SOURCE_NOT_EVALUATED,
    MiniSWEBenchAgent,
    MiniSweBenchRunner,
    _run_command,
    build_mini_swe_prompt,
    to_prediction_row,
)

MODULE = "constitutional_swarm.swe_bench.mini_swe_agent"


def _task() -> dict[str, object]:
    return {
        "instance_id": "django__django-11099",
        "repo": "django/django",
        "base_commit": "abc123",
        "FAIL_TO_PASS": "tests/test_bug.py::test_fix",
        "problem_statement": "Fix a bug.",
        "hints_text": "Look near parser.py",
    }


def _diff() -> str:
    return "diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"


def test_build_prompt_includes_swe_bench_fields() -> None:
    prompt = build_mini_swe_prompt(_task())

    assert "django__django-11099" in prompt
    assert "django/django" in prompt
    assert "abc123" in prompt
    assert "- tests/test_bug.py::test_fix" in prompt
    assert "Look near parser.py" in prompt


def test_runner_success_extracts_patch_from_trajectory(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("--output") + 1])
        output_path.write_text(
            json.dumps({"info": {"submission": _diff()}, "messages": []}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="ignored", stderr="")

    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    runner = MiniSweBenchRunner(model="test-model", timeout_s=12.0)
    result = runner.run(_task())

    assert result.status == "submitted"
    assert result.patch == _diff()
    assert result.metadata["backend"] == BACKEND_MINI_EXTERNAL_BASELINE
    assert result.metadata["score_source"] == SCORE_SOURCE_NOT_EVALUATED
    assert result.metadata["model"] == "test-model"
    assert result.metadata["timeout_s"] == 12.0
    assert result.metadata["trajectory_present"] is True


def test_runner_builds_cli_command_contract(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["timeout"] = kwargs["timeout_s"]
        seen["cwd"] = kwargs["cwd"]
        seen["env"] = kwargs["env"]
        return subprocess.CompletedProcess(cmd, 0, stdout=_diff(), stderr="")

    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    runner = MiniSweBenchRunner(
        model="m",
        timeout_s=7.0,
        extra_args=["--config", "mini.yaml"],
        work_dir="/tmp/mini-work",
        env={"OPENAI_API_KEY": "secret"},
    )
    result = runner.run(_task())

    cmd = seen["cmd"]
    assert result.status == "submitted"
    assert cmd[:1] == ["/bin/mini"]
    assert "--task" in cmd
    assert "--yolo" not in cmd
    assert "--exit-immediately" in cmd
    assert "--output" in cmd
    assert "--model" in cmd
    assert cmd[-2:] == ["--config", "mini.yaml"]
    assert seen["timeout"] == 7.0
    assert str(seen["cwd"]) == "/tmp/mini-work"
    assert seen["env"] == {"OPENAI_API_KEY": "secret"}
    assert result.metadata["env_keys"] == ["OPENAI_API_KEY"]


def test_runner_missing_cli_returns_safe_failure(monkeypatch) -> None:
    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: None)

    result = MiniSweBenchRunner().run(_task())

    assert result.patch == ""
    assert result.status == "missing_cli"
    assert result.metadata["error"] == "missing_cli"
    assert result.metadata["backend"] == BACKEND_MINI_EXTERNAL_BASELINE


def test_runner_timeout_returns_safe_failure(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout_s"])

    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    result = MiniSweBenchRunner(timeout_s=1.5).run(_task())

    assert result.patch == ""
    assert result.status == "timeout"
    assert result.metadata["error"] == "timeout"
    assert result.metadata["timeout_s"] == 1.5


def test_runner_malformed_output_returns_safe_failure(monkeypatch) -> None:
    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(
        f"{MODULE}._run_command",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout="not a diff", stderr=""),
    )

    result = MiniSweBenchRunner().run(_task())

    assert result.patch == ""
    assert result.status == "malformed_output"
    assert result.metadata["error"] == "malformed_output"
    assert result.metadata["patch_length"] == 0


def test_runner_nonzero_exit_redacts_secret_tail(monkeypatch) -> None:
    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(
        f"{MODULE}._run_command",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd,
            2,
            stdout="",
            stderr=(
                "OPENAI_API_KEY=sk-live-secret token:abcd password=hunter2 "
                "Authorization: Bearer sk-another-secret GH_TOKEN=ghp_secret"
            ),
        ),
    )

    result = MiniSweBenchRunner().run(_task())

    assert result.patch == ""
    assert result.status == "nonzero_exit"
    assert result.metadata["error"] == "nonzero_exit"
    tail = result.metadata["stderr_tail"]
    assert "sk-live-secret" not in tail
    assert "abcd" not in tail
    assert "hunter2" not in tail
    assert "sk-another-secret" not in tail
    assert "ghp_secret" not in tail
    assert "<redacted>" in tail


def test_agent_solve_wraps_runner_result_as_swepatch() -> None:
    class FakeRunner:
        def run(self, task):
            return type(
                "Result",
                (),
                {
                    "patch": _diff(),
                    "status": "submitted",
                    "metadata": {
                        "backend": BACKEND_MINI_EXTERNAL_BASELINE,
                        "score_source": SCORE_SOURCE_NOT_EVALUATED,
                        "intervention_rate": 0.0,
                    },
                },
            )()

    patch = MiniSWEBenchAgent(runner=FakeRunner()).solve(_task())

    assert isinstance(patch, SWEPatch)
    assert patch.success is True
    assert patch.patch == _diff()
    assert patch.metadata["mini_status"] == "submitted"
    assert patch.metadata["backend"] == BACKEND_MINI_EXTERNAL_BASELINE
    assert patch.metadata["score_source"] == SCORE_SOURCE_NOT_EVALUATED


def test_runner_extracts_submission_from_message_extra(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("--output") + 1])
        output_path.write_text(
            json.dumps({"messages": [{"extra": {"submission": _diff()}}]}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    result = MiniSweBenchRunner().run(_task())

    assert result.status == "submitted"
    assert result.patch == _diff()


def test_runner_yolo_is_explicit_opt_in(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=_diff(), stderr="")

    monkeypatch.setattr(f"{MODULE}.shutil.which", lambda _name: "/bin/mini")
    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    result = MiniSweBenchRunner(yolo=True).run(_task())

    assert result.status == "submitted"
    assert "--yolo" in seen["cmd"]
    assert result.metadata["yolo"] is True


def test_runner_resolves_path_like_binary_to_absolute_executable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "mini"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=_diff(), stderr="")

    monkeypatch.setattr(f"{MODULE}._run_command", fake_run)

    result = MiniSweBenchRunner(mini_binary=str(binary)).run(_task())

    assert result.status == "submitted"
    assert seen["cmd"][0] == str(binary.resolve())


def test_run_command_uses_explicit_minimal_env(monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    class FakeProc:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return "out", "err"

    def fake_popen(cmd, **kwargs):
        seen.update(kwargs)
        return FakeProc()

    monkeypatch.setenv("AMBIENT_SECRET", "do-not-inherit")
    monkeypatch.setattr(f"{MODULE}.subprocess.Popen", fake_popen)

    completed = _run_command(
        ["/bin/mini"],
        timeout_s=1.0,
        cwd=tmp_path,
        env={"OPENAI_API_KEY": "explicit"},
    )

    assert completed.stdout == "out"
    child_env = seen["env"]
    assert child_env["OPENAI_API_KEY"] == "explicit"
    assert "PATH" in child_env
    assert "AMBIENT_SECRET" not in child_env
    assert seen["cwd"] == tmp_path
    assert seen["start_new_session"] is True


def test_to_prediction_row_preserves_score_source_labels() -> None:
    row = to_prediction_row(_task(), _diff(), model_name="mini/m", score_source="local_harness")

    assert row == {
        "model_name_or_path": "mini/m",
        "instance_id": "django__django-11099",
        "model_patch": _diff(),
        "backend": BACKEND_MINI_EXTERNAL_BASELINE,
        "score_source": "local_harness",
    }
