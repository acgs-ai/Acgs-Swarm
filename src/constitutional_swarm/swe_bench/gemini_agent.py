"""GeminiSWEBenchAgent — SWEBenchAgent backed by Gemini on Vertex AI.

Uses the ``google-genai`` SDK (NOT ``google-cloud-aiplatform``) — Google's
unified Gemini client that supports both the public Generative Language API
and Vertex AI via the ``vertexai=True`` flag. Auth uses ADC, same as
VertexClaudeSWEBenchAgent.

Model
-----
The constructor's ``model`` defaults to ``gemini-2.5-pro``. Probed
2026-05-09 against project ``acgs-493208-493513``: 3.x not yet available
on Vertex; 2.5-pro is the current Pro tier. Override via ``--model`` if a
newer family becomes available.

Requirements
------------
- ``pip install "constitutional-swarm[vertex]"`` (installs google-genai
  + google-cloud-aiplatform).
- ADC: ``gcloud auth application-default login`` OR
  ``GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json``.
- Vertex AI Gemini quota provisioned in the target GCP project (default
  for new projects with billing enabled).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from constitutional_swarm.swe_bench.agent import SWEBenchAgent
from constitutional_swarm.swe_bench.claude_agent import (
    _PROMPT_TEMPLATE,
    _extract_diff,
)

_log = logging.getLogger(__name__)


class GeminiSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates patch generation to Gemini on Vertex AI."""

    _DEFAULT_MODEL = "gemini-2.5-pro"
    _DEFAULT_REGION = "global"
    _DEFAULT_SYSTEM = (
        "You are an expert software engineer. "
        "When asked to fix a bug, output only the unified diff — "
        "no explanation, no code fences, no markdown."
    )

    def __init__(
        self,
        *,
        project_id: str | None = None,
        region: str | None = None,
        model: str | None = None,
        timeout_s: float = 180.0,
        max_new_tokens: int = 16384,
        system_prompt: str | None = None,
        extra_config: dict[str, Any] | None = None,
        thinking_budget: int | None = 0,
        **kwargs: Any,
    ) -> None:
        self._model = model or self._DEFAULT_MODEL
        self._region = region or self._DEFAULT_REGION
        self._project_id = (
            project_id
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
        )
        if not self._project_id:
            raise ValueError(
                "project_id is required. Pass it explicitly or set "
                "GOOGLE_CLOUD_PROJECT."
            )

        super().__init__(
            model_name=self._model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            **kwargs,
        )
        try:
            from google import genai
        except ImportError as exc:
            raise ImportError(
                "google-genai is required. Install with "
                "`pip install \"constitutional-swarm[vertex]\"`."
            ) from exc
        self._client = genai.Client(
            vertexai=True,
            project=self._project_id,
            location=self._region,
        )
        self._system = system_prompt or self._DEFAULT_SYSTEM
        self._extra_config: dict[str, Any] = dict(extra_config or {})
        # Gemini 2.5+/3.x emit "thinking" tokens that consume the output budget
        # before any visible text is produced. For SWE-bench diff generation we
        # don't need extended thinking, so default to thinking_budget=0
        # (disabled). Set None to leave the model's default in place; pass an
        # int to cap. None of the canonical SWE-bench prompts justify the
        # spend of letting Gemini reason for thousands of tokens before
        # emitting a diff.
        self._thinking_budget = thinking_budget

    def _build_prompt(self, task: dict[str, Any]) -> str:
        fail_to_pass = task.get("FAIL_TO_PASS") or []
        if isinstance(fail_to_pass, str):
            fail_to_pass = [fail_to_pass]
        hints = task.get("hints_text") or ""
        hints_section = f"Hints:\n{hints.strip()}\n\n" if hints.strip() else ""
        return _PROMPT_TEMPLATE.format(
            instance_id=task.get("instance_id", "unknown"),
            repo=task.get("repo", "unknown"),
            base_commit=task.get("base_commit", "unknown"),
            fail_to_pass="\n".join(f"- {t}" for t in fail_to_pass) or "(none listed)",
            problem_statement=(task.get("problem_statement") or "").strip(),
            hints_section=hints_section,
        )

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        prompt = self._build_prompt(task)
        stats: dict[str, Any] = {
            "model": self._model,
            "region": self._region,
            "project_id": self._project_id,
            "provider": "gemini",
            "intervention_rate": 0.0,
        }

        config: dict[str, Any] = {
            "system_instruction": self._system,
            "max_output_tokens": self.max_new_tokens,
        }
        if self._thinking_budget is not None:
            # google-genai accepts nested dict; SDK builds ThinkingConfig.
            config["thinking_config"] = {"thinking_budget": int(self._thinking_budget)}
        config.update(self._extra_config)

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=[prompt],
                config=config,
            )
        except Exception as exc:  # noqa: BLE001 — google-genai exceptions are varied
            kind = type(exc).__name__
            msg = str(exc)
            _log.warning("Gemini error %s: %s", kind, msg[:200])
            stats["error"] = f"genai_{kind}"
            stats["stderr_tail"] = msg[:500]
            return "", stats

        raw = response.text or ""
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            stats["input_tokens"] = int(getattr(usage, "prompt_token_count", 0) or 0)
            stats["output_tokens"] = int(getattr(usage, "candidates_token_count", 0) or 0)
            stats["thoughts_tokens"] = int(getattr(usage, "thoughts_token_count", 0) or 0)
            stats["total_tokens"] = int(getattr(usage, "total_token_count", 0) or 0)
        else:
            stats["input_tokens"] = 0
            stats["output_tokens"] = 0

        # Gemini's stop reason equivalent is finish_reason on the first candidate.
        finish_reason = None
        candidates = getattr(response, "candidates", None) or []
        if candidates:
            fr = getattr(candidates[0], "finish_reason", None)
            finish_reason = getattr(fr, "name", None) or (str(fr) if fr is not None else None)
        stats["stop_reason"] = finish_reason

        patch = _extract_diff(raw)
        stats["raw_length"] = len(raw)
        stats["patch_length"] = len(patch)
        return patch, stats


__all__ = ["GeminiSWEBenchAgent"]
