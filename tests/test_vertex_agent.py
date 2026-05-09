"""Unit tests for VertexClaudeSWEBenchAgent.

These tests do NOT make live Vertex API calls. They mock the AnthropicVertex
client to verify constructor behavior, prompt building, and patch extraction
parity with ClaudeSWEBenchAgent.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _has_anthropic_vertex() -> bool:
    try:
        from anthropic import AnthropicVertex  # noqa: F401
    except ImportError:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _has_anthropic_vertex(),
    reason="anthropic[vertex] extra not installed",
)


def _import_agent():
    from constitutional_swarm.swe_bench.vertex_agent import (
        VertexClaudeSWEBenchAgent,
    )
    return VertexClaudeSWEBenchAgent


def test_project_id_required_when_no_env() -> None:
    """Constructor must reject empty project_id when no env vars set."""
    Agent = _import_agent()
    env_clear = {k: "" for k in ("GOOGLE_CLOUD_PROJECT", "ANTHROPIC_VERTEX_PROJECT_ID")}
    with patch.dict(os.environ, env_clear, clear=False):
        # Drop the keys so they're really absent, not empty.
        for k in env_clear:
            os.environ.pop(k, None)
        with pytest.raises(ValueError, match="project_id is required"):
            Agent()


def test_project_id_falls_back_to_google_cloud_project_env() -> None:
    """GOOGLE_CLOUD_PROJECT env var should be picked up."""
    Agent = _import_agent()
    with patch.dict(
        os.environ,
        {"GOOGLE_CLOUD_PROJECT": "fallback-project-123"},
    ), patch("anthropic.AnthropicVertex") as mock_vertex:
        agent = Agent()
        assert agent._project_id == "fallback-project-123"
        mock_vertex.assert_called_once_with(
            project_id="fallback-project-123",
            region="global",
        )


def test_explicit_project_overrides_env() -> None:
    Agent = _import_agent()
    with patch.dict(
        os.environ,
        {"GOOGLE_CLOUD_PROJECT": "env-project"},
    ), patch("anthropic.AnthropicVertex") as mock_vertex:
        agent = Agent(project_id="explicit-project", region="us-east5")
        assert agent._project_id == "explicit-project"
        assert agent._region == "us-east5"
        mock_vertex.assert_called_once_with(
            project_id="explicit-project",
            region="us-east5",
        )


def test_default_model_is_sonnet_4_6() -> None:
    Agent = _import_agent()
    with patch("anthropic.AnthropicVertex"):
        agent = Agent(project_id="p")
        assert agent._model == "claude-sonnet-4-6"
        assert agent.model_name == "claude-sonnet-4-6"


def test_build_prompt_contains_task_fields() -> None:
    Agent = _import_agent()
    with patch("anthropic.AnthropicVertex"):
        agent = Agent(project_id="p")
        prompt = agent._build_prompt({
            "instance_id": "django__django-12345",
            "repo": "django/django",
            "base_commit": "abcdef0",
            "FAIL_TO_PASS": ["tests.test_foo::test_bar"],
            "problem_statement": "Fix the off-by-one in pagination.",
            "hints_text": "  Look at Paginator.page().  ",
        })
        assert "django__django-12345" in prompt
        assert "django/django" in prompt
        assert "abcdef0" in prompt
        assert "tests.test_foo::test_bar" in prompt
        assert "off-by-one in pagination" in prompt
        assert "Look at Paginator.page()." in prompt


def test_generate_patch_extracts_diff_and_records_usage() -> None:
    """Mock the client's messages.create to return a fake response and
    verify _generate_patch produces a clean diff + usage stats."""
    Agent = _import_agent()
    diff_body = (
        "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    fake_content = [SimpleNamespace(text=diff_body)]
    fake_response = SimpleNamespace(
        content=fake_content,
        usage=SimpleNamespace(input_tokens=42, output_tokens=17),
        stop_reason="end_turn",
    )
    with patch("anthropic.AnthropicVertex") as mock_vertex:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = fake_response
        mock_vertex.return_value = mock_client

        agent = Agent(project_id="p")
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })

    assert patch_text.startswith("--- a/foo.py")
    assert patch_text.endswith("\n")
    assert stats["model"] == "claude-sonnet-4-6"
    assert stats["region"] == "global"
    assert stats["project_id"] == "p"
    assert stats["input_tokens"] == 42
    assert stats["output_tokens"] == 17
    assert stats["stop_reason"] == "end_turn"
    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "claude-sonnet-4-6"
    assert call_kwargs["messages"][0]["role"] == "user"


def test_generate_patch_handles_api_status_error() -> None:
    """API errors must be caught and surfaced as stats[error] with empty patch."""
    Agent = _import_agent()
    import anthropic
    with patch("anthropic.AnthropicVertex") as mock_vertex:
        mock_client = MagicMock()
        # APIStatusError requires a real-shaped httpx.Response (with .request);
        # MagicMock auto-provides any attribute access.
        fake_response = MagicMock(status_code=429, headers={})
        err = anthropic.APIStatusError(
            message="quota exceeded",
            response=fake_response,
            body=None,
        )
        mock_client.messages.create.side_effect = err
        mock_vertex.return_value = mock_client

        agent = Agent(project_id="p")
        patch_text, stats = agent._generate_patch({
            "instance_id": "x",
            "repo": "x/x",
            "base_commit": "0",
            "FAIL_TO_PASS": [],
            "problem_statement": "p",
        })

    assert patch_text == ""
    assert stats["error"].startswith("api_status_")
    assert "quota exceeded" in stats["stderr_tail"]


def test_import_error_gracefully_reported(monkeypatch) -> None:
    """If anthropic[vertex] is missing, constructor raises a clear ImportError."""
    Agent = _import_agent()

    # Simulate ImportError by removing AnthropicVertex from the anthropic module.
    import anthropic
    original = getattr(anthropic, "AnthropicVertex", None)
    monkeypatch.delattr(anthropic, "AnthropicVertex", raising=False)
    # Force re-import path inside __init__: the agent does a local
    # `from anthropic import AnthropicVertex`, which will raise ImportError.

    try:
        with pytest.raises(ImportError, match="anthropic\\[vertex\\] is required"):
            Agent(project_id="p")
    finally:
        if original is not None:
            anthropic.AnthropicVertex = original
