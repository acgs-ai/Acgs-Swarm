"""Shared prompt and Anthropic Messages-API plumbing for SWE-bench adapters.

``ClaudeSWEBenchAgent``, ``ClaudeOAuthSWEBenchAgent`` and
``VertexClaudeSWEBenchAgent`` differ only in how they authenticate and build
their SDK client. Everything else -- the task prompt, the system prompt, the
``messages.create`` call, the SDK error mapping and the usage/patch stats -- lives
here so a fix lands once instead of drifting across copies.

Subclasses must set ``self._anthropic`` (the SDK module whose exception classes
are caught) and ``self._client`` after calling ``super().__init__``. The base
never constructs the client itself: credential checks and project validation
must keep running before the SDK is imported.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from constitutional_swarm.swe_bench._diff import extract_unified_diff
from constitutional_swarm.swe_bench.agent import SWEBenchAgent

_log = logging.getLogger(__name__)

PROMPT_TEMPLATE = """\
You are solving a SWE-bench task. Produce a unified diff that fixes the bug.

Output rules:
- Reply with ONLY the unified diff, no prose, no code fences, no explanation.
- Use standard ``--- a/<path>`` and ``+++ b/<path>`` headers.
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

DEFAULT_SYSTEM_PROMPT = (
    "You are an expert software engineer. "
    "When asked to fix a bug, output only the unified diff — "
    "no explanation, no code fences, no markdown."
)


def build_swe_bench_prompt(task: dict[str, Any]) -> str:
    """Render the canonical SWE-bench patch prompt for one task dict."""
    fail_to_pass = task.get("FAIL_TO_PASS") or []
    if isinstance(fail_to_pass, str):
        fail_to_pass = [fail_to_pass]
    hints = task.get("hints_text") or ""
    hints_section = f"Hints:\n{hints.strip()}\n\n" if hints.strip() else ""
    return PROMPT_TEMPLATE.format(
        instance_id=task.get("instance_id", "unknown"),
        repo=task.get("repo", "unknown"),
        base_commit=task.get("base_commit", "unknown"),
        fail_to_pass="\n".join(f"- {t}" for t in fail_to_pass) or "(none listed)",
        problem_statement=(task.get("problem_statement") or "").strip(),
        hints_section=hints_section,
    )


class _MessagesAPIAgent(SWEBenchAgent):
    """Base for SWE-bench agents that call an Anthropic Messages-API client.

    The SDK error mapping catches ``APITimeoutError`` before
    ``APIConnectionError`` (the former subclasses the latter), so timeouts are
    reported as ``"timeout"`` and routed by the recovery plane accordingly.
    """

    _DEFAULT_MODEL: ClassVar[str]
    _DEFAULT_SYSTEM: ClassVar[str] = DEFAULT_SYSTEM_PROMPT
    _LOG_LABEL: ClassVar[str] = "Anthropic"

    _anthropic: Any
    _client: Any

    def __init__(
        self,
        *,
        model: str | None,
        timeout_s: float,
        max_new_tokens: int,
        system_prompt: str | None,
        extra_kwargs: dict[str, Any] | None,
        **kwargs: Any,
    ) -> None:
        self._model = model or self._DEFAULT_MODEL
        super().__init__(
            model_name=self._model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            **kwargs,
        )
        if extra_kwargs and "timeout" in extra_kwargs:
            raise ValueError("extra_kwargs cannot override the configured timeout")
        self._system = system_prompt or self._DEFAULT_SYSTEM
        self._extra_kwargs: dict[str, Any] = dict(extra_kwargs or {})

    def _provider_stats(self) -> dict[str, Any]:
        """Provider-specific fields recorded in every stats dict."""
        return {}

    def _build_prompt(self, task: dict[str, Any]) -> str:
        return build_swe_bench_prompt(task)

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        sdk = self._anthropic
        label = self._LOG_LABEL
        prompt = self._build_prompt(task)
        stats: dict[str, Any] = {
            "model": self._model,
            **self._provider_stats(),
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
        except sdk.APIStatusError as exc:
            _log.warning("%s API error %s: %s", label, exc.status_code, exc.message)
            stats["error"] = f"api_status_{exc.status_code}"
            stats["stderr_tail"] = str(exc.message)[:500]
            return "", stats
        except sdk.APITimeoutError:
            _log.warning("%s request timed out after %.0fs", label, self.timeout_s)
            stats["error"] = "timeout"
            return "", stats
        except sdk.APIConnectionError as exc:
            _log.warning("%s connection error: %s", label, exc)
            stats["error"] = "connection_error"
            stats["stderr_tail"] = str(exc)[:500]
            return "", stats

        raw = ""
        if response.content:
            raw = response.content[0].text if hasattr(response.content[0], "text") else ""

        usage = response.usage
        stats["input_tokens"] = usage.input_tokens if usage else 0
        stats["output_tokens"] = usage.output_tokens if usage else 0
        stats["stop_reason"] = response.stop_reason

        patch = extract_unified_diff(raw)
        stats["raw_length"] = len(raw)
        stats["patch_length"] = len(patch)
        return patch, stats


__all__ = [
    "DEFAULT_SYSTEM_PROMPT",
    "PROMPT_TEMPLATE",
    "_MessagesAPIAgent",
    "build_swe_bench_prompt",
]
