"""ClaudeOAuthSWEBenchAgent — uses Claude Code's OAuth login session.

Reads the OAuth access token Claude Code stores at
``~/.claude/.credentials.json`` (key path: ``claudeAiOauth.accessToken``)
and passes it as ``auth_token`` to ``anthropic.Anthropic``. This lets a
SWE-bench batch run on the same billing seat as the user's interactive
Claude Code session, without minting a new API key.

Why not auto-refresh
--------------------
Claude Code refreshes OAuth tokens itself when it starts and on its own
schedule. Replicating that flow here would mean knowing Anthropic's OAuth
client_id, refresh endpoint, and scope set, and bearing the security risk
of those secrets living in this codebase. Instead, we trust Claude Code:
if our token is expired at agent construction time, raise a clear error
asking the user to re-run ``claude`` (or any command that opens Claude
Code), which refreshes the credentials file in place.

Requirements
------------
- ``anthropic>=0.84``
- A current Claude Code login: ``~/.claude/.credentials.json`` exists with
  a non-expired ``claudeAiOauth.accessToken``.

Usage
-----
>>> agent = ClaudeOAuthSWEBenchAgent(model="claude-sonnet-4-6")
>>> result = agent.solve(task)
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench.agent import SWEBenchAgent
from constitutional_swarm.swe_bench.claude_agent import (
    _PROMPT_TEMPLATE,
    _extract_diff,
)

_log = logging.getLogger(__name__)

_DEFAULT_CRED_PATH = Path.home() / ".claude" / ".credentials.json"
_CRED_KEY = "claudeAiOauth"


class CredentialError(RuntimeError):
    """Raised when the Claude Code OAuth credential cannot be used."""


def _read_oauth_token(
    cred_path: Path | None = None,
    *,
    now: float | None = None,
    skew_s: float = 30.0,
) -> str:
    """Read and validate the Claude Code OAuth access token.

    Parameters
    ----------
    cred_path:
        Override credentials.json path (defaults to ``~/.claude/.credentials.json``;
        also honors ``CLAUDE_CONFIG_DIR``).
    now:
        Current epoch seconds (injectable for tests). Defaults to ``time.time()``.
    skew_s:
        Treat the token as expired if it expires within this many seconds.
        Default 30s — leaves headroom for in-flight requests.

    Returns
    -------
    str
        The access token.

    Raises
    ------
    CredentialError
        If the file is missing, malformed, or the token is expired.
    """
    if cred_path is None:
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
        cred_path = (
            Path(config_dir) / ".credentials.json" if config_dir else _DEFAULT_CRED_PATH
        )

    if not cred_path.exists():
        raise CredentialError(
            f"Claude Code credentials not found at {cred_path}. "
            "Run `claude` once to log in (this writes the credential file)."
        )

    try:
        data = json.loads(cred_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialError(
            f"Could not read credentials at {cred_path}: {exc}"
        ) from exc

    section = data.get(_CRED_KEY)
    if not isinstance(section, dict):
        raise CredentialError(
            f"Credentials file at {cred_path} is missing the {_CRED_KEY!r} section. "
            "Re-run `claude login` (or any `claude` command) to refresh."
        )

    token = section.get("accessToken")
    if not isinstance(token, str) or not token:
        raise CredentialError(
            f"No accessToken in {cred_path}::{_CRED_KEY}. Re-run `claude login`."
        )

    expires_at = section.get("expiresAt")
    if isinstance(expires_at, (int, float)):
        # Anthropic stores expiresAt in MILLISECONDS since epoch (consistent with
        # other Claude Code tooling). Treat any value > 1e11 as ms, else seconds.
        cur = now if now is not None else time.time()
        exp_s = expires_at / 1000.0 if expires_at > 1e11 else float(expires_at)
        if exp_s - skew_s <= cur:
            raise CredentialError(
                f"Claude OAuth access token expired at "
                f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(exp_s))}. "
                f"Run `claude` to refresh."
            )

    return token


class ClaudeOAuthSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that uses Claude Code's OAuth session for auth.

    Parameters
    ----------
    model:
        Anthropic model identifier. Defaults to ``claude-sonnet-4-6``.
    cred_path:
        Override the credentials file path (for tests / non-default homes).
    timeout_s:
        Hard timeout passed to the HTTP client.
    max_new_tokens:
        Maximum tokens for the completion.
    system_prompt:
        Optional system-turn content. Defaults to a concise coding persona.
    extra_kwargs:
        Additional kwargs forwarded to ``client.messages.create()``.
    """

    _DEFAULT_MODEL = "claude-sonnet-4-6"
    _DEFAULT_SYSTEM = (
        "You are an expert software engineer. "
        "When asked to fix a bug, output only the unified diff — "
        "no explanation, no code fences, no markdown."
    )

    def __init__(
        self,
        *,
        model: str | None = None,
        cred_path: Path | str | None = None,
        timeout_s: float = 180.0,
        max_new_tokens: int = 2048,
        system_prompt: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._model = model or self._DEFAULT_MODEL
        super().__init__(
            model_name=self._model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            **kwargs,
        )
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required. Install with `pip install anthropic`."
            ) from exc

        path = Path(cred_path) if cred_path else None
        token = _read_oauth_token(path)
        self._client = anthropic.Anthropic(auth_token=token)
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
            "auth": "oauth",
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
            _log.warning("Anthropic API error %s: %s", exc.status_code, exc.message)
            stats["error"] = f"api_status_{exc.status_code}"
            stats["stderr_tail"] = str(exc.message)[:500]
            return "", stats
        except anthropic.APIConnectionError as exc:
            _log.warning("Anthropic connection error: %s", exc)
            stats["error"] = "connection_error"
            stats["stderr_tail"] = str(exc)[:500]
            return "", stats
        except anthropic.APITimeoutError:
            _log.warning("Anthropic request timed out after %.0fs", self.timeout_s)
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


__all__ = ["ClaudeOAuthSWEBenchAgent", "CredentialError", "_read_oauth_token"]
