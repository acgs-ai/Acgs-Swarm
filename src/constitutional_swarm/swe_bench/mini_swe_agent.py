"""mini-swe-agent external baseline adapter for SWE-bench scaffolds.

This module treats ``SWE-agent/mini-swe-agent`` as an optional black-box
baseline.  It does not import or vendor mini-swe-agent; callers must install
and configure the ``mini`` / ``mini-swe-agent`` CLI separately if they want live
runs.  Live runs default to a temporary isolated working directory and only
use no-confirmation mode when explicitly requested.  Unit tests mock the
subprocess boundary so default CI needs no provider, Docker, or mini
installation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench.agent import SWEBenchAgent

BACKEND_MINI_EXTERNAL_BASELINE = "mini_external_baseline"
SCORE_SOURCE_NOT_EVALUATED = "not_evaluated"
SCORE_SOURCE_LOCAL_HARNESS = "local_harness"
SCORE_SOURCE_OFFICIAL_SWEBENCH = "official_swebench"

_DIFF_MARKER = re.compile(r"(?m)^(?:diff --git |--- [ab]?/|\+\+\+ [ab]?/|@@ )")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|AUTHORIZATION|PASSWORD|SECRET)[A-Z0-9_]*)"
    r"\b\s*[:=]\s*(?:(?:Bearer|Basic|Token)\s+)?([^\s,;]+)"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(Authorization\s*[:=]\s*(?:Bearer|Basic|Token))\s+([^\s,;]+)"
)
_KNOWN_SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9][A-Za-z0-9._-]*|gh[pousr]_[A-Za-z0-9_]+)\b")

_PROMPT_TEMPLATE = """\
You are solving a SWE-bench task. Produce a unified diff that fixes the bug.

Output rules:
- Reply with ONLY the unified diff, no prose, no code fences, no explanation.
- Use standard `--- a/<path>` and `+++ b/<path>` headers.
- Paths must be relative to the repository root.
- Do not modify tests unless the task explicitly requires it.

Instance: {instance_id}
Repository: {repo}
Base commit: {base_commit}

Tests that should flip from FAIL to PASS:
{fail_to_pass}

Problem statement:
{problem_statement}

{hints_section}Produce the patch now."""


@dataclass(frozen=True)
class MiniSweRunResult:
    """Structured result from a black-box mini-swe-agent invocation."""

    patch: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)


class MiniSweBenchRunner:
    """Invoke an installed mini-swe-agent CLI and normalize its patch output.

    The runner is intentionally a subprocess adapter instead of a Python API
    integration.  That keeps mini-swe-agent optional, preserves baseline
    fidelity, and prevents its runtime/config dependencies from entering the
    Acgs-Swarm core import path.
    """

    def __init__(
        self,
        *,
        mini_binary: str | None = None,
        model: str | None = None,
        timeout_s: float = 180.0,
        extra_args: list[str] | None = None,
        work_dir: Path | str | None = None,
        env: dict[str, str] | None = None,
        yolo: bool = False,
    ) -> None:
        self.mini_binary = mini_binary
        self.model = model
        self.timeout_s = timeout_s
        self.extra_args = list(extra_args or [])
        self.work_dir = Path(work_dir).expanduser().resolve() if work_dir is not None else None
        self.env = dict(env or {})
        self.yolo = yolo

    def run(self, task: dict[str, Any]) -> MiniSweRunResult:
        """Run mini-swe-agent for one SWE-bench-shaped task.

        Returns a safe failure result instead of raising for expected runtime
        conditions (missing CLI, timeout, non-zero exit, no diff).  Unexpected
        Python errors are summarized by type only.
        """
        resolved_binary = self._resolve_binary()
        base_metadata = self._base_metadata(resolved_binary=resolved_binary)
        if resolved_binary is None:
            return MiniSweRunResult(
                patch="",
                status="missing_cli",
                metadata={**base_metadata, "error": "missing_cli"},
            )

        prompt = build_mini_swe_prompt(task)
        try:
            with tempfile.TemporaryDirectory(prefix="acgs-mini-swe-") as tmp_dir:
                tmp_path = Path(tmp_dir)
                trajectory_path = tmp_path / "mini.traj.json"
                run_cwd = self._prepare_work_dir(tmp_path)
                cmd = self._build_command(
                    resolved_binary=resolved_binary,
                    task_prompt=prompt,
                    output_path=trajectory_path,
                )
                try:
                    proc = _run_command(
                        cmd,
                        timeout_s=self.timeout_s,
                        cwd=run_cwd,
                        env=self.env,
                    )
                except subprocess.TimeoutExpired:
                    return MiniSweRunResult(
                        patch="",
                        status="timeout",
                        metadata={**base_metadata, "error": "timeout"},
                    )

                trajectory_text = _read_text_if_exists(trajectory_path)
                candidate_text = _trajectory_submission(trajectory_text)
                if not candidate_text:
                    candidate_text = "\n".join([proc.stdout or "", trajectory_text or ""])
                patch = _extract_diff(candidate_text)
                metadata = {
                    **base_metadata,
                    "exit_code": proc.returncode,
                    "stdout_tail": _redacted_tail(proc.stdout),
                    "stderr_tail": _redacted_tail(proc.stderr),
                    "trajectory_present": bool(trajectory_text),
                    "patch_length": len(patch),
                    "cwd": str(run_cwd),
                    "env_keys": sorted(self.env),
                }
                if proc.returncode != 0:
                    return MiniSweRunResult(
                        patch="",
                        status="nonzero_exit",
                        metadata={**metadata, "error": "nonzero_exit"},
                    )
                if not patch:
                    return MiniSweRunResult(
                        patch="",
                        status="malformed_output",
                        metadata={**metadata, "error": "malformed_output"},
                    )
                return MiniSweRunResult(patch=patch, status="submitted", metadata=metadata)
        except Exception as exc:  # defensive: keep public metadata opaque
            return MiniSweRunResult(
                patch="",
                status="runner_error",
                metadata={**base_metadata, "error": type(exc).__name__},
            )

    def _resolve_binary(self) -> str | None:
        if self.mini_binary:
            return _resolve_executable(self.mini_binary)
        return shutil.which("mini") or shutil.which("mini-swe-agent")

    def _prepare_work_dir(self, tmp_path: Path) -> Path:
        if self.work_dir is not None:
            self.work_dir.mkdir(parents=True, exist_ok=True)
            return self.work_dir
        isolated = tmp_path / "workspace"
        isolated.mkdir()
        return isolated

    def _build_command(
        self,
        *,
        resolved_binary: str,
        task_prompt: str,
        output_path: Path,
    ) -> list[str]:
        cmd = [
            resolved_binary,
            "--task",
            task_prompt,
            "--exit-immediately",
            "--output",
            str(output_path),
        ]
        if self.yolo:
            cmd.append("--yolo")
        if self.model is not None:
            cmd.extend(["--model", self.model])
        cmd.extend(self.extra_args)
        return cmd

    def _base_metadata(self, *, resolved_binary: str | None) -> dict[str, Any]:
        return {
            "backend": BACKEND_MINI_EXTERNAL_BASELINE,
            "score_source": SCORE_SOURCE_NOT_EVALUATED,
            "mini_binary": resolved_binary or self.mini_binary or "mini",
            "model": self.model or "mini-default",
            "timeout_s": self.timeout_s,
            "intervention_rate": 0.0,
            "yolo": self.yolo,
            "env_keys": sorted(self.env),
        }


class MiniSWEBenchAgent(SWEBenchAgent):
    """``SWEBenchAgent`` adapter backed by an external mini-swe-agent CLI."""

    def __init__(
        self,
        *,
        runner: MiniSweBenchRunner | None = None,
        mini_binary: str | None = None,
        model: str | None = None,
        timeout_s: float = 180.0,
        extra_args: list[str] | None = None,
        work_dir: Path | str | None = None,
        env: dict[str, str] | None = None,
        yolo: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            model_name=model or kwargs.pop("model_name", "mini-swe-agent"),
            timeout_s=timeout_s,
            **kwargs,
        )
        self.runner = runner or MiniSweBenchRunner(
            mini_binary=mini_binary,
            model=model,
            timeout_s=timeout_s,
            extra_args=extra_args,
            work_dir=work_dir,
            env=env,
            yolo=yolo,
        )

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        result = self.runner.run(task)
        return result.patch, {"mini_status": result.status, **result.metadata}


def build_mini_swe_prompt(task: dict[str, Any]) -> str:
    """Build the black-box mini-swe-agent task prompt."""
    fail_to_pass = _as_list(task.get("FAIL_TO_PASS"))
    hints = str(task.get("hints_text") or "").strip()
    hints_section = f"Hints:\n{hints}\n\n" if hints else ""
    return _PROMPT_TEMPLATE.format(
        instance_id=task.get("instance_id", "unknown"),
        repo=task.get("repo", "unknown"),
        base_commit=task.get("base_commit", "unknown"),
        fail_to_pass="\n".join(f"- {item}" for item in fail_to_pass) or "(none listed)",
        problem_statement=str(task.get("problem_statement") or "").strip(),
        hints_section=hints_section,
    )


def to_prediction_row(
    task: dict[str, Any],
    patch: str,
    *,
    model_name: str = "mini-swe-agent",
    score_source: str = SCORE_SOURCE_NOT_EVALUATED,
    backend: str = BACKEND_MINI_EXTERNAL_BASELINE,
) -> dict[str, Any]:
    """Convert a mini-generated patch to a SWE-bench prediction row."""
    return {
        "model_name_or_path": model_name,
        "instance_id": str(task.get("instance_id", "unknown")),
        "model_patch": patch,
        "backend": backend,
        "score_source": score_source,
    }


def _extract_diff(text: str) -> str:
    """Extract unified diff text from raw mini output or trajectory content."""
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    match = _DIFF_MARKER.search(stripped)
    if not match:
        return ""
    diff = stripped[match.start() :].strip()
    return diff + ("\n" if not diff.endswith("\n") else "")


def _trajectory_submission(raw_json: str) -> str:
    if not raw_json:
        return ""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ""
    info = data.get("info", {}) if isinstance(data, dict) else {}
    submission = info.get("submission")
    if isinstance(submission, str) and submission.strip():
        return submission
    messages = data.get("messages", []) if isinstance(data, dict) else []
    if isinstance(messages, list):
        for message in reversed(messages):
            if not isinstance(message, dict):
                continue
            extra = message.get("extra")
            if isinstance(extra, dict):
                submission = extra.get("submission")
                if isinstance(submission, str) and _DIFF_MARKER.search(submission):
                    return submission
            content = message.get("content")
            if isinstance(content, str) and _DIFF_MARKER.search(content):
                return content
    return ""


def _read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError:
        return ""


def _redacted_tail(text: str, *, limit: int = 500) -> str:
    if not text:
        return ""
    redacted = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    redacted = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)} <redacted>", redacted)
    redacted = _KNOWN_SECRET_RE.sub("<redacted>", redacted)
    return redacted[-limit:]


def _resolve_executable(binary: str) -> str | None:
    path_like = os.sep in binary or (os.altsep is not None and os.altsep in binary)
    if not path_like:
        return shutil.which(binary)
    path = Path(binary).expanduser().resolve()
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return None


def _run_command(
    cmd: list[str],
    *,
    timeout_s: float,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_subprocess_env(env),
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout=stdout, stderr=stderr)


def _subprocess_env(env: dict[str, str]) -> dict[str, str]:
    safe_env = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        safe_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    safe_env.update(env)
    return safe_env


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        proc.kill()
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value]
    return [str(value)]


__all__ = [
    "BACKEND_MINI_EXTERNAL_BASELINE",
    "SCORE_SOURCE_LOCAL_HARNESS",
    "SCORE_SOURCE_NOT_EVALUATED",
    "SCORE_SOURCE_OFFICIAL_SWEBENCH",
    "MiniSWEBenchAgent",
    "MiniSweBenchRunner",
    "MiniSweRunResult",
    "build_mini_swe_prompt",
    "to_prediction_row",
]
