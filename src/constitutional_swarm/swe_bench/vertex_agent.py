"""VertexClaudeSWEBenchAgent — SWEBenchAgent backed by Claude on Vertex AI.

Wires :class:`SWEBenchAgent._generate_patch()` to ``anthropic.AnthropicVertex``
so Claude (e.g. ``claude-sonnet-4-6``) routes through Google Cloud Vertex AI
instead of the direct Anthropic Messages API. The wire format is the same
(Messages API); the only differences vs the direct path are:

- Constructor takes ``project_id`` + ``region`` (no API key).
- Auth uses Application Default Credentials (``gcloud auth
  application-default login``), Workload Identity, or
  ``GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json``.
- ``model`` is part of the URL on Vertex; the SDK still accepts it as a
  kwarg and forwards it correctly.

Requirements
------------
- ``pip install "anthropic[vertex]" google-cloud-aiplatform``
- A GCP project with Anthropic models enabled (Vertex AI Model Garden →
  search "Claude" → request access if needed).
- ADC configured: ``gcloud auth application-default login`` (interactive
  user creds) OR ``GOOGLE_APPLICATION_CREDENTIALS`` pointing at a service
  account JSON.

Usage
-----
>>> agent = VertexClaudeSWEBenchAgent(
...     project_id="my-gcp-project",
...     region="global",
...     model="claude-sonnet-4-6",
... )
>>> result = agent.solve(task)
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


class VertexClaudeSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates patch generation to Claude on Vertex AI.

    Parameters
    ----------
    project_id:
        GCP project ID. Falls back to ``GOOGLE_CLOUD_PROJECT`` then
        ``ANTHROPIC_VERTEX_PROJECT_ID`` env vars.
    region:
        Vertex region. ``"global"`` (default) is recommended — dynamic
        routing, max availability, no pricing premium. Use a specific
        region (``"us-east5"``, ``"europe-west1"``) for data-residency
        requirements.
    model:
        Vertex model ID. Defaults to ``claude-sonnet-4-6``. Must be a
        model available in your project's enabled regions.
    timeout_s:
        Hard timeout passed to the HTTP client; recorded in ``SWEPatch``.
    max_new_tokens:
        Maximum tokens for the completion (``max_tokens`` in the API).
    system_prompt:
        Optional system-turn content. Defaults to a concise coding persona.
    extra_kwargs:
        Additional kwargs forwarded to ``client.messages.create()``.
    """

    _DEFAULT_MODEL = "claude-sonnet-4-6"
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
        max_new_tokens: int = 2048,
        system_prompt: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
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
                "GOOGLE_CLOUD_PROJECT / ANTHROPIC_VERTEX_PROJECT_ID."
            )

        super().__init__(
            model_name=self._model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            **kwargs,
        )
        try:
            from anthropic import AnthropicVertex
        except ImportError as exc:
            raise ImportError(
                "anthropic[vertex] is required. Install with "
                "`pip install \"anthropic[vertex]\" google-cloud-aiplatform`."
            ) from exc
        self._client = AnthropicVertex(
            project_id=self._project_id,
            region=self._region,
        )
        self._system = system_prompt or self._DEFAULT_SYSTEM
        self._extra_kwargs: dict[str, Any] = dict(extra_kwargs or {})

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
        import anthropic

        prompt = self._build_prompt(task)
        stats: dict[str, Any] = {
            "model": self._model,
            "region": self._region,
            "project_id": self._project_id,
            "intervention_rate": 0.0,
        }
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self.max_new_tokens,
                system=self._system,
                messages=[{"role": "user", "content": prompt}],
                **self._extra_kwargs,
            )
        except anthropic.APIStatusError as exc:
            _log.warning("Vertex API error %s: %s", exc.status_code, exc.message)
            stats["error"] = f"api_status_{exc.status_code}"
            stats["stderr_tail"] = str(exc.message)[:500]
            return "", stats
        except anthropic.APIConnectionError as exc:
            _log.warning("Vertex connection error: %s", exc)
            stats["error"] = "connection_error"
            stats["stderr_tail"] = str(exc)[:500]
            return "", stats
        except anthropic.APITimeoutError:
            _log.warning("Vertex request timed out after %.0fs", self.timeout_s)
            stats["error"] = "timeout"
            return "", stats

        raw = ""
        if response.content:
            raw = response.content[0].text if hasattr(response.content[0], "text") else ""

        usage = response.usage
        stats["input_tokens"] = usage.input_tokens if usage else 0
        stats["output_tokens"] = usage.output_tokens if usage else 0
        stats["stop_reason"] = response.stop_reason

        patch = _extract_diff(raw)
        stats["raw_length"] = len(raw)
        stats["patch_length"] = len(patch)
        return patch, stats


__all__ = ["VertexClaudeSWEBenchAgent"]
