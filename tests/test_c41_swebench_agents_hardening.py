"""C41 regression tests: SWE-bench agent adapters share one diff extractor,
one prompt builder and one Messages-API error mapping, and the multi-candidate
runner labels its oracle selection as pass@k.

All tests are phrased as invalid-input regressions: hunk-only or prose-prefixed
model output must not survive extraction in any adapter, and an oracle-selected
best-of-k score must never be reported as a plain single-sample resolve rate.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MC_SCRIPT = _REPO_ROOT / "scripts" / "run_mc_swarm.py"


@functools.cache
def _load_mc_module() -> types.ModuleType:
    name = "c41_run_mc_swarm"
    spec = importlib.util.spec_from_file_location(name, _MC_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[cls.__module__].
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_D = "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"
_G = "diff --git a/foo.py b/foo.py\n" + _D
_HUNK_ONLY = "@@ -1 +1 @@\n-old\n+new\n"
_PROSE_PREFIXED = "Here is the fix:\n\n" + _G

# Golden outputs captured from the pre-refactor
# ``constitutional_swarm.swe_bench.claude_agent._extract_diff`` (base c1d97bf).
# The shared extractor must reproduce them byte-for-byte.
_GOLDEN: list[tuple[str, str]] = [
    ("", ""),
    ("   \n\t", ""),
    ("I cannot solve this bug.", ""),
    (_D, _D),
    (_D.rstrip("\n"), _D),
    (_G, _G),
    (_PROSE_PREFIXED, _G),
    ("```diff\n" + _D + "```\n", _D),
    ("```\n" + _G + "```", _G),
    ("```diff\nSure, here you go:\n" + _D + "```", _D),
    (_HUNK_ONLY, ""),
    (
        "prose\n@@ -1 +1 @@\n-a\n+b\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-c\n+d\n",
        "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-c\n+d\n",
    ),
    ("+++ b/only.py\n@@ -0,0 +1 @@\n+x\n", "+++ b/only.py\n@@ -0,0 +1 @@\n+x\n"),
    (
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n",
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n",
    ),
    ("---a/nospace.py\n", ""),
    ("  --- a/indented.py\n+++ b/indented.py\n", "--- a/indented.py\n+++ b/indented.py\n"),
    ("text --- a/inline.py\n", ""),
    ("--- foo.py\n+++ foo.py\n@@ -1 +1 @@\n-a\n+b\n", ""),
    ("```\n```", ""),
    ("```", ""),
    ("x\r\n--- a/crlf.py\r\n+++ b/crlf.py\r\n", "--- a/crlf.py\r\n+++ b/crlf.py\n"),
    ("\n\n" + _D + "\n\n\n", _D),
    ("```python\nprint(1)\n```", ""),
    (
        "Trailing prose after diff\n" + _D + "\nHope this helps!",
        _D + "\nHope this helps!\n",
    ),
]


# ---------------------------------------------------------------------------
# bench-eval-opt-1: one extractor with the claude_agent semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("raw", "expected"), _GOLDEN)
def test_c41_shared_extractor_matches_claude_agent_golden_outputs(raw: str, expected: str) -> None:
    from constitutional_swarm.swe_bench._diff import extract_unified_diff

    assert extract_unified_diff(raw) == expected


def _adapter_extractors() -> list[tuple[str, Any]]:
    from constitutional_swarm.swe_bench import claude_agent, codex_agent, mini_swe_agent

    return [
        ("claude_agent", claude_agent._extract_diff),
        ("codex_agent", codex_agent._extract_diff),
        ("mini_swe_agent", mini_swe_agent._extract_diff),
        ("run_mc_swarm", _load_mc_module()._extract_diff),
    ]


@pytest.mark.parametrize("index", range(4))
def test_c41_adapters_reject_hunk_only_output(index: int) -> None:
    name, extract = _adapter_extractors()[index]
    assert extract(_HUNK_ONLY) == "", f"{name} accepted an unapplyable hunk-only patch"


@pytest.mark.parametrize("index", range(4))
def test_c41_adapters_cut_prose_prefix(index: int) -> None:
    name, extract = _adapter_extractors()[index]
    assert extract(_PROSE_PREFIXED) == _G, f"{name} kept the prose prefix"


@pytest.mark.parametrize("index", range(4))
def test_c41_adapters_use_the_single_shared_extractor(index: int) -> None:
    from constitutional_swarm.swe_bench._diff import extract_unified_diff

    name, extract = _adapter_extractors()[index]
    assert extract is extract_unified_diff, f"{name} carries its own diff extractor copy"


def test_c41_mini_trajectory_ignores_hunk_only_message_content() -> None:
    from constitutional_swarm.swe_bench.mini_swe_agent import _trajectory_submission

    raw = json.dumps({"messages": [{"content": _HUNK_ONLY}, {"extra": {"submission": _HUNK_ONLY}}]})
    assert _trajectory_submission(raw) == ""


def test_c41_codex_agent_returns_empty_patch_for_hunk_only_output() -> None:
    import subprocess

    from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

    def _run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        idx = cmd.index("--output-last-message")
        Path(cmd[idx + 1]).write_text(_HUNK_ONLY, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=_HUNK_ONLY, stderr="")

    agent = CodexSWEBenchAgent(codex_binary="/bin/true")
    with patch("constitutional_swarm.swe_bench.codex_agent._run_process", side_effect=_run):
        patch_text, stats = agent._generate_patch(_TASK)
    assert patch_text == ""
    assert stats["patch_length"] == 0


# ---------------------------------------------------------------------------
# bench-eval-opt-2: shared prompt builder + Messages-API base
# ---------------------------------------------------------------------------

_TASK: dict[str, Any] = {
    "instance_id": "astropy__astropy-12907",
    "repo": "astropy/astropy",
    "base_commit": "deadbeef",
    "problem_statement": "  separability_matrix is wrong for nested models  ",
    "FAIL_TO_PASS": "tests/test_separable.py::test_nested",
    "hints_text": "  look at _cstack  ",
}


class _StatusError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class _ConnectionError(Exception):
    pass


class _TimeoutError(_ConnectionError):
    """Mirrors the real SDK: APITimeoutError subclasses APIConnectionError."""


def _fake_sdk(client: MagicMock) -> SimpleNamespace:
    return SimpleNamespace(
        Anthropic=MagicMock(return_value=client),
        AnthropicVertex=MagicMock(return_value=client),
        APIStatusError=_StatusError,
        APIConnectionError=_ConnectionError,
        APITimeoutError=_TimeoutError,
    )


def _write_oauth_creds(tmp_path: Path) -> Path:
    path = tmp_path / ".credentials.json"
    path.write_text(
        json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat01-c41", "expiresAt": None}}),
        encoding="utf-8",
    )
    return path


def _build_messages_agent(kind: str, sdk: SimpleNamespace, tmp_path: Path) -> Any:
    if kind == "claude":
        from constitutional_swarm.swe_bench.claude_agent import ClaudeSWEBenchAgent

        with patch.dict("sys.modules", {"anthropic": sdk}):
            return ClaudeSWEBenchAgent(api_key="k")
    if kind == "vertex":
        from constitutional_swarm.swe_bench.vertex_agent import VertexClaudeSWEBenchAgent

        with patch.dict("sys.modules", {"anthropic": sdk}):
            return VertexClaudeSWEBenchAgent(project_id="p")
    from constitutional_swarm.swe_bench.claude_oauth_agent import ClaudeOAuthSWEBenchAgent

    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=sdk,
    ):
        return ClaudeOAuthSWEBenchAgent(cred_path=_write_oauth_creds(tmp_path))


_KINDS = ["claude", "vertex", "oauth"]


@pytest.mark.parametrize("kind", _KINDS)
def test_c41_messages_agents_share_one_base(kind: str, tmp_path: Path) -> None:
    from constitutional_swarm.swe_bench._messages_agent import _MessagesAPIAgent

    agent = _build_messages_agent(kind, _fake_sdk(MagicMock()), tmp_path)
    assert isinstance(agent, _MessagesAPIAgent)
    assert "_generate_patch" not in type(agent).__dict__, "subclass re-implements the error mapping"
    assert "_build_prompt" not in type(agent).__dict__, "subclass re-implements the prompt builder"


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize(
    ("exc", "expected_error"),
    [
        (_TimeoutError("slow"), "timeout"),
        (_ConnectionError("reset"), "connection_error"),
        (_StatusError(529, "overloaded"), "api_status_529"),
    ],
)
def test_c41_messages_agents_map_sdk_errors_with_timeout_first(
    kind: str, exc: Exception, expected_error: str, tmp_path: Path
) -> None:
    client = MagicMock()
    client.messages.create.side_effect = exc
    agent = _build_messages_agent(kind, _fake_sdk(client), tmp_path)

    patch_text, stats = agent._generate_patch(_TASK)

    assert patch_text == ""
    assert stats["error"] == expected_error


@pytest.mark.parametrize("kind", _KINDS)
def test_c41_messages_agents_reject_hunk_only_completion(kind: str, tmp_path: Path) -> None:
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        content=[SimpleNamespace(text=_HUNK_ONLY)],
        usage=SimpleNamespace(input_tokens=3, output_tokens=4),
        stop_reason="end_turn",
    )
    agent = _build_messages_agent(kind, _fake_sdk(client), tmp_path)

    patch_text, stats = agent._generate_patch(_TASK)

    assert patch_text == ""
    assert stats["patch_length"] == 0
    assert stats["input_tokens"] == 3
    assert client.messages.create.call_args.kwargs["system"] == agent._system


def test_c41_all_api_adapters_send_the_same_prompt(tmp_path: Path) -> None:
    from constitutional_swarm.swe_bench._messages_agent import build_swe_bench_prompt
    from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

    expected = build_swe_bench_prompt(_TASK)
    assert "- tests/test_separable.py::test_nested" in expected
    assert "Hints:\nlook at _cstack\n\n" in expected

    for kind in _KINDS:
        agent = _build_messages_agent(kind, _fake_sdk(MagicMock()), tmp_path)
        assert agent._build_prompt(_TASK) == expected, kind
    assert CodexSWEBenchAgent(codex_binary="/bin/true")._build_prompt(_TASK) == expected


# ---------------------------------------------------------------------------
# bench-eval-3 (MC part): oracle best-of-k is labelled pass@k
# ---------------------------------------------------------------------------


def _mc_row(resolved: bool) -> dict[str, Any]:
    return {
        "instance_id": "x",
        "patch_generated": True,
        "applied": True,
        "resolved": resolved,
    }


def test_c41_mc_summary_labels_oracle_selection_as_pass_at_k() -> None:
    mc = _load_mc_module()
    rows = [_mc_row(True), _mc_row(False)]

    summary = mc._build_summary(
        rows,
        k=4,
        total_cands=8,
        total_valid=6,
        total_applied_cands=5,
        total_resolved_cands=2,
        total_timeouts=1,
    )

    assert summary["resolve_metric"] == "pass@k"
    assert summary["selection"] == "oracle"
    assert summary["k"] == 4
    assert summary["resolve_rate"] == 0.5
    for row in summary["rows"]:
        assert row["resolve_metric"] == "pass@k"
        assert row["selection"] == "oracle"
        assert row["k"] == 4
