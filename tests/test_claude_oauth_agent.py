"""Unit tests for ClaudeOAuthSWEBenchAgent.

These tests do NOT make live Anthropic API calls. They mock the client
and synthesize credential files in tmp dirs to verify token loading,
expiry handling, and patch dispatch.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from constitutional_swarm.swe_bench.claude_oauth_agent import (
    ClaudeOAuthSWEBenchAgent,
    CredentialError,
    _read_oauth_token,
)


class _FakeAPIStatusError(Exception):
    def __init__(self, *, message: str, response: object, body: object) -> None:
        super().__init__(message)
        self.message = message
        self.response = response
        self.body = body
        self.status_code = getattr(response, "status_code", None)


class _FakeAPIConnectionError(Exception):
    pass


class _FakeAPITimeoutError(Exception):
    pass


def _fake_anthropic_module(*, client: MagicMock | None = None) -> SimpleNamespace:
    mock_client = client or MagicMock()
    return SimpleNamespace(
        Anthropic=MagicMock(return_value=mock_client),
        APIStatusError=_FakeAPIStatusError,
        APIConnectionError=_FakeAPIConnectionError,
        APITimeoutError=_FakeAPITimeoutError,
    )


def _write_creds(
    tmp_path: Path,
    *,
    access_token: str = "sk-ant-oat01-fake",
    expires_at_ms: int | None = None,
    section_key: str = "claudeAiOauth",
    extra: dict | None = None,
) -> Path:
    """Write a minimal credentials.json under tmp_path/.claude/.credentials.json."""
    cred_dir = tmp_path / ".claude"
    cred_dir.mkdir(parents=True, exist_ok=True)
    cred_path = cred_dir / ".credentials.json"
    section = {
        "accessToken": access_token,
        "refreshToken": "rt-fake",
        "expiresAt": expires_at_ms if expires_at_ms is not None else int((time.time() + 3600) * 1000),
        "scopes": ["user:inference"],
        "subscriptionType": "max",
        "rateLimitTier": "standard",
    }
    if extra:
        section.update(extra)
    cred_path.write_text(json.dumps({section_key: section}))
    return cred_path


# ── _read_oauth_token: file IO + expiry ────────────────────────────────────────


def test_read_oauth_token_happy_path(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path, access_token="my-fake-token")
    assert _read_oauth_token(cred) == "my-fake-token"


def test_read_oauth_token_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(CredentialError, match="not found"):
        _read_oauth_token(missing)


def test_read_oauth_token_malformed_json_raises(tmp_path: Path) -> None:
    bad = tmp_path / "creds.json"
    bad.write_text("{not valid json")
    with pytest.raises(CredentialError, match="Could not read"):
        _read_oauth_token(bad)


def test_read_oauth_token_missing_section_raises(tmp_path: Path) -> None:
    bad = tmp_path / "creds.json"
    bad.write_text(json.dumps({"otherSection": {}}))
    with pytest.raises(CredentialError, match="missing the 'claudeAiOauth'"):
        _read_oauth_token(bad)


def test_read_oauth_token_expired_raises(tmp_path: Path) -> None:
    """Token whose expiresAt is in the past must raise."""
    past_ms = int((time.time() - 60) * 1000)
    cred = _write_creds(tmp_path, expires_at_ms=past_ms)
    with pytest.raises(CredentialError, match="expired"):
        _read_oauth_token(cred)


def test_read_oauth_token_within_skew_raises(tmp_path: Path) -> None:
    """Token expiring within the skew window is treated as expired."""
    soon_ms = int((time.time() + 5) * 1000)
    cred = _write_creds(tmp_path, expires_at_ms=soon_ms)
    with pytest.raises(CredentialError, match="expired"):
        _read_oauth_token(cred, skew_s=30.0)


def test_read_oauth_token_seconds_fallback(tmp_path: Path) -> None:
    """If expiresAt is in seconds (small int), don't mis-interpret as ms."""
    future_s = int(time.time() + 3600)  # plain seconds
    cred = _write_creds(tmp_path, expires_at_ms=future_s)
    # Should not raise.
    assert _read_oauth_token(cred) == "sk-ant-oat01-fake"


def test_read_oauth_token_no_expiry_field(tmp_path: Path) -> None:
    """If expiresAt is absent, we accept the token (Claude Code's job to refresh)."""
    cred_dir = tmp_path / ".claude"
    cred_dir.mkdir()
    cred_path = cred_dir / ".credentials.json"
    cred_path.write_text(json.dumps({
        "claudeAiOauth": {"accessToken": "no-expiry-token"}
    }))
    assert _read_oauth_token(cred_path) == "no-expiry-token"


# ── ClaudeOAuthSWEBenchAgent: construction + dispatch ──────────────────────────


def test_agent_constructs_with_valid_creds(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    fake_module = _fake_anthropic_module()
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred)
        assert agent._model == "claude-sonnet-4-6"
        fake_module.Anthropic.assert_called_once_with(auth_token="sk-ant-oat01-fake")


def test_agent_constructs_with_custom_model(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    fake_module = _fake_anthropic_module()
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred, model="claude-opus-4-7")
        assert agent._model == "claude-opus-4-7"


def test_agent_propagates_credential_error(tmp_path: Path) -> None:
    """If the cred file is bad, agent constructor must raise CredentialError."""
    missing = tmp_path / "missing.json"
    with pytest.raises(CredentialError):
        ClaudeOAuthSWEBenchAgent(cred_path=missing)


def test_agent_requires_anthropic_after_creds_validate(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        side_effect=ImportError("anthropic package is required"),
    ):
        with pytest.raises(ImportError, match="anthropic package is required"):
            ClaudeOAuthSWEBenchAgent(cred_path=cred)


def test_agent_generate_patch_dispatches_via_oauth_client(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path, access_token="real-oauth-tok")
    diff_body = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"
    fake_response = SimpleNamespace(
        content=[SimpleNamespace(text=diff_body)],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        stop_reason="end_turn",
    )
    mock_client = MagicMock()
    mock_client.messages.create.return_value = fake_response
    fake_module = _fake_anthropic_module(client=mock_client)
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred)
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })

    assert patch_text.startswith("--- a/x.py")
    assert stats["model"] == "claude-sonnet-4-6"
    assert stats["auth"] == "oauth"
    assert stats["input_tokens"] == 10
    fake_module.Anthropic.assert_called_once_with(auth_token="real-oauth-tok")
    call_kwargs = mock_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "claude-sonnet-4-6"


def test_agent_generate_patch_handles_api_status_error(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    mock_client = MagicMock()
    fake_response = MagicMock(status_code=401, headers={})
    err = _FakeAPIStatusError(
        message="invalid token",
        response=fake_response,
        body=None,
    )
    mock_client.messages.create.side_effect = err
    fake_module = _fake_anthropic_module(client=mock_client)
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred)
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })
    assert patch_text == ""
    assert stats["error"] == "api_status_401"
    assert "invalid token" in stats["stderr_tail"]


def test_agent_generate_patch_handles_connection_error(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    mock_client = MagicMock()
    mock_client.messages.create.side_effect = _FakeAPIConnectionError("network down")
    fake_module = _fake_anthropic_module(client=mock_client)
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred)
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })
    assert patch_text == ""
    assert stats["error"] == "connection_error"
    assert "network down" in stats["stderr_tail"]


def test_agent_generate_patch_handles_timeout(tmp_path: Path) -> None:
    cred = _write_creds(tmp_path)
    mock_client = MagicMock()
    mock_client.messages.create.side_effect = _FakeAPITimeoutError()
    fake_module = _fake_anthropic_module(client=mock_client)
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_module,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=cred, timeout_s=12.0)
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })
    assert patch_text == ""
    assert stats["error"] == "timeout"


# ── _extract_diff: prose prefix handling (shared with claude_agent) ────────────


def test_extract_diff_strips_prose_prefix() -> None:
    """Models often prepend prose before the diff. The extractor must cut it."""
    from constitutional_swarm.swe_bench.claude_agent import _extract_diff
    response = (
        "Looking at this issue, I need to fix the off-by-one bug.\n"
        "Here's the patch:\n\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    out = _extract_diff(response)
    assert out.startswith("--- a/foo.py")
    assert "Looking at this issue" not in out
    assert out.endswith("\n")


def test_extract_diff_strips_prose_inside_code_fence() -> None:
    """Prose that lives INSIDE a code fence should also be stripped."""
    from constitutional_swarm.swe_bench.claude_agent import _extract_diff
    response = (
        "```diff\n"
        "Some prose inside the fence\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "```\n"
    )
    out = _extract_diff(response)
    assert out.startswith("--- a/foo.py")
    assert "Some prose" not in out


def test_extract_diff_returns_empty_when_no_marker() -> None:
    """Pure prose (no diff anywhere) returns empty so harness records non-success."""
    from constitutional_swarm.swe_bench.claude_agent import _extract_diff
    assert _extract_diff("I cannot solve this bug.") == ""
    assert _extract_diff("") == ""


def test_extract_diff_rejects_hunk_only_patch() -> None:
    """Hunks without file headers are NOT applyable — must return empty.

    Real failure observed in best-of-K run 2026-05-09: agent#2 emitted
    `@@ -242,7 +242,7 @@\n     elif isinstance(...)\n-    return ...\n
    +    return ...\n` with no preceding `--- a/path` header. git apply
    would fail since it has no file to patch. Picker `longest` still chose
    it because it had more chars; picker `vote` got confused. The fix is
    extractor-level: a patch needs file headers to be valid.
    """
    from constitutional_swarm.swe_bench.claude_agent import _extract_diff
    hunk_only = (
        "@@ -242,7 +242,7 @@\n"
        "     if isinstance(transform, CompoundModel):\n"
        "         return _separable(transform)\n"
        "-    elif isinstance(transform, Model):\n"
        "+    elif isinstance(transform, BaseModel):\n"
    )
    # Pre-fix: would return the same string (passes _DIFF_MARKER on @@).
    # Post-fix: returns "" since no file header.
    assert _extract_diff(hunk_only) == ""

    # But add a file header and it should be accepted.
    with_header = "--- a/foo.py\n+++ b/foo.py\n" + hunk_only
    assert _extract_diff(with_header).startswith("--- a/foo.py")
