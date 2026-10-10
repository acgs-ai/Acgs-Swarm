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

import os
from typing import Any

from constitutional_swarm.swe_bench._messages_agent import _MessagesAPIAgent


class VertexClaudeSWEBenchAgent(_MessagesAPIAgent):
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
    _LOG_LABEL = "Vertex"

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
            model=model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            system_prompt=system_prompt,
            extra_kwargs=extra_kwargs,
            **kwargs,
        )
        try:
            import anthropic
            from anthropic import AnthropicVertex
        except ImportError as exc:
            raise ImportError(
                "anthropic[vertex] is required. Install with "
                "`pip install \"anthropic[vertex]\" google-cloud-aiplatform`."
            ) from exc
        self._anthropic = anthropic
        self._client = AnthropicVertex(
            project_id=self._project_id,
            region=self._region,
            timeout=self.timeout_s,
            max_retries=0,
        )

    def _provider_stats(self) -> dict[str, Any]:
        return {"region": self._region, "project_id": self._project_id}


__all__ = ["VertexClaudeSWEBenchAgent"]
