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

import importlib
import json
import os
import time
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench._messages_agent import _MessagesAPIAgent

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


def _load_anthropic_module() -> Any:
    try:
        return importlib.import_module("anthropic")
    except ImportError as exc:
        raise ImportError(
            "anthropic package is required. Install with `pip install anthropic`."
        ) from exc


class ClaudeOAuthSWEBenchAgent(_MessagesAPIAgent):
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
        super().__init__(
            model=model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            system_prompt=system_prompt,
            extra_kwargs=extra_kwargs,
            **kwargs,
        )
        path = Path(cred_path) if cred_path else None
        token = _read_oauth_token(path)
        anthropic = _load_anthropic_module()
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(
            auth_token=token,
            timeout=self.timeout_s,
            max_retries=0,
        )

    def _provider_stats(self) -> dict[str, Any]:
        return {"auth": "oauth"}


__all__ = ["ClaudeOAuthSWEBenchAgent", "CredentialError", "_read_oauth_token"]
