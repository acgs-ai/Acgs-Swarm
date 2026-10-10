"""CodexSWEBenchAgent — SWEBenchAgent backed by the Codex CLI (GPT).

Wires :class:`SWEBenchAgent._generate_patch()` to ``codex exec`` so a real
LM produces unified diffs for SWE-bench-shaped tasks. Patch shape is
validated (a ``diff --git``/``--- a/``/``+++ b/`` file header is required;
prose before it is cut) but **not** applied
or tested — full benchmark scoring still requires a Docker harness with the
instance repo checked out.

Usage
-----
>>> agent = CodexSWEBenchAgent(model="gpt-5.4", timeout_s=180)
>>> result = agent.solve(task)  # task from SWEBenchHarness

Requires the ``codex`` binary on ``$PATH`` (npm i -g @openai/codex) and a
logged-in ChatGPT/OpenAI account (``codex login``).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench._diff import extract_unified_diff
from constitutional_swarm.swe_bench._messages_agent import build_swe_bench_prompt
from constitutional_swarm.swe_bench._subprocess import _run_process
from constitutional_swarm.swe_bench.agent import SWEBenchAgent

_log = logging.getLogger(__name__)

# Backward-compatible private name; the single implementation lives in _diff.
_extract_diff = extract_unified_diff


class CodexSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates patch generation to ``codex exec``.

    Parameters
    ----------
    model:
        Codex model identifier passed via ``-m``. ``None`` uses the Codex
        default (typically ``gpt-5.4``).
    codex_binary:
        Override path to the ``codex`` CLI. Defaults to ``shutil.which("codex")``.
    timeout_s:
        Hard timeout for the subprocess (also returned in ``SWEPatch``).
    sandbox:
        Codex sandbox mode. ``read-only`` is safest; generation does not need
        to edit files.
    extra_args:
        Additional CLI args appended after the prompt (e.g. ``["--json"]``).
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        codex_binary: str | None = None,
        timeout_s: float = 180.0,
        sandbox: str = "read-only",
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            model_name=model or kwargs.pop("model_name", "codex-default"),
            timeout_s=timeout_s,
            **kwargs,
        )
        resolved = codex_binary or shutil.which("codex")
        if resolved is None:
            raise RuntimeError(
                "codex CLI not found on PATH. Install with `npm i -g @openai/codex` "
                "and authenticate with `codex login`."
            )
        self.codex_binary = resolved
        self.model = model
        self.sandbox = sandbox
        self.extra_args: list[str] = list(extra_args or [])

    # ------------------------------------------------------------------
    # Overrides
    # ------------------------------------------------------------------

    def _build_prompt(self, task: dict[str, Any]) -> str:
        return build_swe_bench_prompt(task)

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        prompt = self._build_prompt(task)
        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            last_path = Path(tmp.name)
        try:
            cmd = [
                self.codex_binary,
                "exec",
                "--sandbox",
                self.sandbox,
                "--skip-git-repo-check",
                "--output-last-message",
                str(last_path),
            ]
            if self.model:
                cmd.extend(["-m", self.model])
            cmd.extend(self.extra_args)

            try:
                proc = _run_process(
                    cmd,
                    input_text=prompt,
                    timeout_s=self.timeout_s,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"codex exec timed out after {self.timeout_s}s") from exc

            stats: dict[str, Any] = {
                "model": self.model or "codex-default",
                "sandbox": self.sandbox,
                "exit_code": proc.returncode,
                "intervention_rate": 0.0,
            }
            if proc.returncode != 0:
                _log.warning("codex exec failed (%s): %s", proc.returncode, proc.stderr[-500:])
                stats["error"] = "codex_exit_nonzero"
                stats["stderr_tail"] = proc.stderr[-500:]
                return "", stats

            try:
                last_message = last_path.read_text(encoding="utf-8")
            except OSError:
                last_message = ""
            patch = extract_unified_diff(last_message) or extract_unified_diff(proc.stdout)
            stats["raw_length"] = len(last_message)
            stats["patch_length"] = len(patch)
            return patch, stats
        finally:
            try:
                last_path.unlink()
            except OSError:
                pass


__all__ = ["CodexSWEBenchAgent"]
