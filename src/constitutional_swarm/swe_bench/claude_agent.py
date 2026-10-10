"""ClaudeSWEBenchAgent — SWEBenchAgent backed by the Anthropic Messages API.

Wires :class:`SWEBenchAgent._generate_patch()` to ``anthropic.Anthropic``
so Claude (e.g. ``claude-sonnet-4-5``) produces unified diffs for
SWE-bench-shaped tasks.

Requirements
------------
- ``anthropic>=0.84`` installed (``pip install anthropic``)
- ``ANTHROPIC_API_KEY`` set in the environment (or pass ``api_key`` kwarg)

Usage
-----
>>> agent = ClaudeSWEBenchAgent(model="claude-sonnet-4-5", timeout_s=180)
>>> result = agent.solve(task)   # task dict from load_instances()
"""

from __future__ import annotations

from typing import Any

from constitutional_swarm.swe_bench._diff import extract_unified_diff
from constitutional_swarm.swe_bench._messages_agent import _MessagesAPIAgent

# Backward-compatible private name; the single implementation lives in _diff.
_extract_diff = extract_unified_diff


class ClaudeSWEBenchAgent(_MessagesAPIAgent):
    """SWEBenchAgent that delegates patch generation to the Anthropic Messages API.

    Parameters
    ----------
    model:
        Anthropic model identifier. Defaults to ``claude-sonnet-4-5``.
    api_key:
        Anthropic API key. Falls back to ``ANTHROPIC_API_KEY`` env var.
    timeout_s:
        Hard timeout passed to the HTTP client; also recorded in ``SWEPatch``.
    max_new_tokens:
        Maximum tokens for the completion (``max_tokens`` in the API).
    system_prompt:
        Optional system-turn content. Defaults to a concise coding persona.
    extra_kwargs:
        Additional kwargs forwarded to ``client.messages.create()``.
    """

    _DEFAULT_MODEL = "claude-sonnet-4-5"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        timeout_s: float = 180.0,
        max_new_tokens: int = 2048,
        system_prompt: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
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
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required. Install with `pip install anthropic`."
            ) from exc
        client_kwargs: dict[str, Any] = {
            "timeout": self.timeout_s,
            "max_retries": 0,
        }
        if api_key:
            client_kwargs["api_key"] = api_key
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(**client_kwargs)


__all__ = ["ClaudeSWEBenchAgent"]
