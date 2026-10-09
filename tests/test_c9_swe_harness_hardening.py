"""Regression coverage for the C9 SWE harness audit findings."""

import json
import math
import os
import signal
import subprocess
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import httpx
import pytest

from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.langgraph_runtime.coordinator_adapter import run_langgraph
from constitutional_swarm.langgraph_runtime.nodes import (
    append_crdt_node,
    generate_node,
    validate_node,
)
from constitutional_swarm.langgraph_runtime.runtime import build_swarm_graph
from constitutional_swarm.langgraph_runtime.streaming import stream_to_crdt
from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch
from constitutional_swarm.swe_bench.harness import SWEBenchHarness
from constitutional_swarm.swe_bench.local_harness import (
    HarnessResult,
    LocalSWEBenchHarness,
    _django_test_status,
    _parse_pytest_summary,
    _pytest_test_status,
    _run,
)
from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator


class _C9RuntimeCleanDNA:
    hash = CONSTITUTIONAL_HASH

    def validate(self, _patch: str) -> SimpleNamespace:
        return SimpleNamespace(valid=True, violations=(), risk_score=0.0)


class _C9RuntimeCRDT:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def append(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "cid"


def _c9_runtime_make_tasks(count: int) -> list[dict[str, object]]:
    return [
        {
            "instance_id": f"c9-runtime-{index}",
            "problem_statement": "repair the runtime",
        }
        for index in range(count)
    ]


class _C9RuntimeSuccessAgent(SWEBenchAgent):
    def _generate_patch(self, _task: dict[str, object]) -> tuple[str, dict[str, object]]:
        return "--- a/file.py\n+++ b/file.py\n", {"intervention_rate": 0.0}


def test_c9_runtime_langgraph_requires_dna_before_graph_construction() -> None:
    with pytest.raises((TypeError, ValueError), match="dna"):
        build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: ("patch", {}),
            dna=None,
        )


@pytest.mark.parametrize("state", [{}, {"patch": ""}, {"patch": "patch"}])
def test_c9_runtime_validate_node_never_governs_without_dna(
    state: dict[str, str],
) -> None:
    with pytest.raises((TypeError, ValueError), match="dna"):
        validate_node(state, dna=None)


def test_c9_runtime_generate_node_does_not_create_or_overwrite_hash() -> None:
    state = {"constitutional_hash": "caller-value"}
    result = generate_node(state, generator=lambda _state: ("patch", {}))
    assert "constitutional_hash" not in result
    assert state["constitutional_hash"] == "caller-value"


@pytest.mark.parametrize("initial", [{}, {"constitutional_hash": "wrong"}])
def test_c9_runtime_graph_rejects_bad_entry_hash_before_generation(
    initial: dict[str, str],
) -> None:
    pytest.importorskip("langgraph")
    generator = MagicMock(return_value=("patch", {}))
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=generator,
        dna=_C9RuntimeCleanDNA(),
        crdt=_C9RuntimeCRDT(),
    )
    result = graph.invoke(
        initial,
        config={"configurable": {"thread_id": f"bad-{len(initial)}"}},
    )
    generator.assert_not_called()
    assert result.get("cid", "") == ""


def test_c9_runtime_graph_preserves_hash_through_generation() -> None:
    pytest.importorskip("langgraph")
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=lambda _state: ("patch", {}),
        dna=_C9RuntimeCleanDNA(),
        crdt=_C9RuntimeCRDT(),
    )
    result = graph.invoke(
        {"constitutional_hash": CONSTITUTIONAL_HASH},
        config={"configurable": {"thread_id": "good-hash"}},
    )
    assert result["constitutional_hash"] == CONSTITUTIONAL_HASH


class _C9RuntimeSettlingGraph:
    async def astream(self, inputs, **_kwargs):
        yield {"settle": {"governed": True, "patch": "patch"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("inputs", [{"task_id": "missing"}, {"constitutional_hash": "wrong"}])
async def test_c9_runtime_streaming_rejects_untrusted_hash(
    inputs: dict[str, str],
) -> None:
    crdt = _C9RuntimeCRDT()
    with pytest.raises((RuntimeError, ValueError), match="hash"):
        async for _chunk in stream_to_crdt(_C9RuntimeSettlingGraph(), inputs, crdt):
            pass
    assert crdt.calls == []


@pytest.mark.parametrize("hook_kind", ["rank1", "subspace"])
def test_c9_runtime_failed_steering_is_warned_and_not_counted(
    monkeypatch,
    hook_kind: str,
) -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )
    if hook_kind == "rank1":
        hook = latent_dna._BODESHook(torch.tensor([1.0, 0.0]))
    else:
        subspace = violation_subspace.ViolationSubspace(
            basis=np.array([[1.0, 0.0]]),
            mean=np.zeros(2),
        )
        hook = latent_dna._BODESSubspaceHook(subspace)
    hidden = torch.tensor([[[1.0, 0.0]]])

    def fail_where(*_args, **_kwargs):
        raise RuntimeError("forced steering failure")

    monkeypatch.setattr(latent_dna.torch, "where", fail_where)
    with pytest.warns(RuntimeWarning, match="steering failed"):
        output = hook(None, (), hidden.clone())
    assert torch.equal(output, hidden)
    assert hook.interventions == 0
    assert hook.steer_failures == 1


def test_c9_runtime_leace_tensors_are_cached_per_device_and_dtype(monkeypatch) -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )
    identity = np.eye(2)
    subspace = violation_subspace.ViolationSubspace(
        basis=np.array([[1.0, 0.0]]),
        mean=np.zeros(2),
        whitener=identity,
        dewhitener=identity,
    )
    hook = latent_dna._BODESSubspaceHook(subspace)
    tracked = {id(hook.whitener), id(hook.dewhitener)}
    original_to = torch.Tensor.to
    conversions = 0

    def counted_to(tensor, *args, **kwargs):
        nonlocal conversions
        if id(tensor) in tracked:
            conversions += 1
        return original_to(tensor, *args, **kwargs)

    monkeypatch.setattr(torch.Tensor, "to", counted_to)
    hidden = torch.tensor([[[1.0, 0.0]]], dtype=torch.float64)
    hook(None, (), hidden.clone())
    hook(None, (), hidden.clone())
    assert conversions == 2


def test_c9_runtime_adapter_metrics_name_patch_generation() -> None:
    result = run_langgraph(
        [_C9RuntimeSuccessAgent()],
        _c9_runtime_make_tasks(3),
    )
    assert result["patch_generated"] == 3
    assert result["patch_rate"] == pytest.approx(1.0)
    assert result["resolved"] == result["patch_generated"]
    assert result["resolve_rate"] == result["patch_rate"]
    assert result["evaluation_mode"] == "patch_generation_only"





_C9_BACKEND_TASK = {
    "instance_id": "project__repo-1",
    "repo": "project/repo",
    "base_commit": "abc123",
    "FAIL_TO_PASS": ["tests/test_example.py::test_fix"],
    "problem_statement": "Fix the example.",
}


def _c9_backend_write_oauth_credentials(tmp_path: Path) -> Path:
    credential_dir = tmp_path / ".claude"
    credential_dir.mkdir()
    credential_path = credential_dir / ".credentials.json"
    credential_path.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-test",
                    "expiresAt": int((time.time() + 3600) * 1000),
                }
            }
        ),
        encoding="utf-8",
    )
    return credential_path


def _c9_backend_anthropic_timeout() -> Exception:
    import anthropic

    return anthropic.APITimeoutError(httpx.Request("POST", "https://example.invalid"))


@pytest.mark.parametrize(
    "value",
    [True, False, "1", None, 0, 0.0, -1, math.nan, math.inf, -math.inf],
)
def test_c9_backend_timeout_validator_rejects_unbounded_values(value: object) -> None:
    from constitutional_swarm.swe_bench.agent import _validate_timeout_seconds

    with pytest.raises(ValueError, match="timeout_s"):
        _validate_timeout_seconds(value)


@pytest.mark.parametrize(("value", "expected"), [(1, 1.0), (0.125, 0.125)])
def test_c9_backend_timeout_validator_normalizes_positive_numbers(
    value: object,
    expected: float,
) -> None:
    from constitutional_swarm.swe_bench.agent import _validate_timeout_seconds

    assert _validate_timeout_seconds(value) == expected


def test_c9_backend_base_agent_enforces_timeout_invariant() -> None:
    from constitutional_swarm.swe_bench.agent import SWEBenchAgent

    with pytest.raises(ValueError, match="timeout_s"):
        SWEBenchAgent(timeout_s=0)


def test_c9_backend_claude_client_has_hard_timeout_and_no_implicit_retries() -> None:
    from constitutional_swarm.swe_bench.claude_agent import ClaudeSWEBenchAgent

    with patch("anthropic.Anthropic") as client_constructor:
        agent = ClaudeSWEBenchAgent(api_key="test", timeout_s=12.5)

    assert agent.timeout_s == 12.5
    client_constructor.assert_called_once_with(
        api_key="test",
        timeout=12.5,
        max_retries=0,
    )


def test_c9_backend_claude_rejects_per_call_timeout_override() -> None:
    from constitutional_swarm.swe_bench.claude_agent import ClaudeSWEBenchAgent

    with patch("anthropic.Anthropic"):
        with pytest.raises(ValueError, match="timeout"):
            ClaudeSWEBenchAgent(extra_kwargs={"timeout": None})


def test_c9_backend_oauth_client_has_hard_timeout_and_no_implicit_retries(
    tmp_path: Path,
) -> None:
    from constitutional_swarm.swe_bench.claude_oauth_agent import (
        ClaudeOAuthSWEBenchAgent,
    )

    credential_path = _c9_backend_write_oauth_credentials(tmp_path)
    with patch("anthropic.Anthropic") as client_constructor:
        agent = ClaudeOAuthSWEBenchAgent(
            cred_path=credential_path,
            timeout_s=8.25,
        )

    assert agent.timeout_s == 8.25
    client_constructor.assert_called_once_with(
        auth_token="sk-ant-oat01-test",
        timeout=8.25,
        max_retries=0,
    )


def test_c9_backend_vertex_client_has_hard_timeout_and_no_implicit_retries() -> None:
    from constitutional_swarm.swe_bench.vertex_agent import VertexClaudeSWEBenchAgent

    with patch("anthropic.AnthropicVertex") as client_constructor:
        agent = VertexClaudeSWEBenchAgent(project_id="test-project", timeout_s=7.5)

    assert agent.timeout_s == 7.5
    client_constructor.assert_called_once_with(
        project_id="test-project",
        region="global",
        timeout=7.5,
        max_retries=0,
    )


def test_c9_backend_gemini_client_has_hard_timeout_and_one_attempt() -> None:
    from constitutional_swarm.swe_bench.gemini_agent import GeminiSWEBenchAgent

    with patch("google.genai.Client") as client_constructor:
        agent = GeminiSWEBenchAgent(project_id="test-project", timeout_s=1.25)

    assert agent.timeout_s == 1.25
    http_options = client_constructor.call_args.kwargs["http_options"]
    assert http_options.timeout == 1250
    assert http_options.retry_options.attempts == 1


def test_c9_backend_gemini_rejects_transport_override() -> None:
    from constitutional_swarm.swe_bench.gemini_agent import GeminiSWEBenchAgent

    with patch("google.genai.Client"):
        with pytest.raises(ValueError, match="http_options"):
            GeminiSWEBenchAgent(
                project_id="test-project",
                extra_config={"http_options": {"timeout": None}},
            )


@pytest.mark.parametrize(
    ("module_name", "class_name", "constructor_target", "constructor_kwargs"),
    [
        (
            "constitutional_swarm.swe_bench.claude_agent",
            "ClaudeSWEBenchAgent",
            "anthropic.Anthropic",
            {"api_key": "test"},
        ),
        (
            "constitutional_swarm.swe_bench.vertex_agent",
            "VertexClaudeSWEBenchAgent",
            "anthropic.AnthropicVertex",
            {"project_id": "test-project"},
        ),
    ],
)
def test_c9_backend_anthropic_timeout_is_not_misclassified_as_connection_error(
    module_name: str,
    class_name: str,
    constructor_target: str,
    constructor_kwargs: dict[str, str],
) -> None:
    module = __import__(module_name, fromlist=[class_name])
    agent_class = getattr(module, class_name)
    client = MagicMock()
    client.messages.create.side_effect = _c9_backend_anthropic_timeout()

    with patch(constructor_target, return_value=client):
        agent = agent_class(**constructor_kwargs)

    patch_text, stats = agent._generate_patch(_C9_BACKEND_TASK)
    assert patch_text == ""
    assert stats["error"] == "timeout"


def test_c9_backend_oauth_timeout_is_not_misclassified_as_connection_error(
    tmp_path: Path,
) -> None:
    import anthropic

    from constitutional_swarm.swe_bench.claude_oauth_agent import (
        ClaudeOAuthSWEBenchAgent,
    )

    credential_path = _c9_backend_write_oauth_credentials(tmp_path)
    client = MagicMock()
    client.messages.create.side_effect = _c9_backend_anthropic_timeout()
    fake_anthropic = SimpleNamespace(
        Anthropic=MagicMock(return_value=client),
        APIStatusError=anthropic.APIStatusError,
        APIConnectionError=anthropic.APIConnectionError,
        APITimeoutError=anthropic.APITimeoutError,
    )
    with patch(
        "constitutional_swarm.swe_bench.claude_oauth_agent._load_anthropic_module",
        return_value=fake_anthropic,
    ):
        agent = ClaudeOAuthSWEBenchAgent(cred_path=credential_path)

    patch_text, stats = agent._generate_patch(_C9_BACKEND_TASK)
    assert patch_text == ""
    assert stats["error"] == "timeout"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups required")
def test_c9_backend_process_tree_kills_group_even_when_parent_exits_after_term() -> None:
    from constitutional_swarm.swe_bench._subprocess import _terminate_process_tree

    process = MagicMock(pid=4312)
    process.wait.return_value = 0
    with patch("os.killpg") as kill_group:
        _terminate_process_tree(process, grace_s=0.01)

    assert kill_group.call_args_list == [
        call(4312, signal.SIGTERM),
        call(4312, signal.SIGKILL),
    ]


def test_c9_backend_shared_process_runner_starts_session_and_reaps_on_timeout() -> None:
    from constitutional_swarm.swe_bench._subprocess import _run_process

    process = MagicMock(pid=4312)
    process.communicate.side_effect = subprocess.TimeoutExpired(["tool"], 0.1)
    with patch(
        "constitutional_swarm.swe_bench._subprocess.subprocess.Popen",
        return_value=process,
    ) as popen_constructor, patch(
        "constitutional_swarm.swe_bench._subprocess._terminate_process_tree"
    ) as terminate:
        with pytest.raises(subprocess.TimeoutExpired):
            _run_process(
                ["tool"],
                input_text="prompt",
                timeout_s=0.1,
                cwd=None,
                env=None,
            )

    assert popen_constructor.call_args.kwargs["start_new_session"] is True
    process.communicate.assert_called_once_with(input="prompt", timeout=0.1)
    terminate.assert_called_once_with(process)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups required")
def test_c9_backend_real_timeout_reaps_grandchild_after_parent_exits(
    tmp_path: Path,
) -> None:
    from constitutional_swarm.swe_bench._subprocess import _run_process

    grandchild_pid_path = tmp_path / "grandchild.pid"
    grandchild_code = (
        "import signal,time;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        "time.sleep(60)"
    )
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        f"p=subprocess.Popen([sys.executable,'-c',{grandchild_code!r}]);"
        f"pathlib.Path({str(grandchild_pid_path)!r}).write_text(str(p.pid));"
        "time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _run_process([sys.executable, "-c", parent_code], timeout_s=0.2)

    grandchild_pid = int(grandchild_pid_path.read_text(encoding="utf-8"))
    for _ in range(50):
        try:
            stat = Path(f"/proc/{grandchild_pid}/stat").read_text(encoding="utf-8")
        except FileNotFoundError:
            break
        if stat.split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        pytest.fail(f"grandchild process {grandchild_pid} survived timeout cleanup")


def test_c9_backend_codex_timeout_uses_shared_tree_safe_runner() -> None:
    from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

    agent = CodexSWEBenchAgent(codex_binary="/usr/bin/codex", timeout_s=1.0)
    with patch(
        "constitutional_swarm.swe_bench.codex_agent._run_process",
        side_effect=subprocess.TimeoutExpired(["codex"], 1.0),
    ) as run_process:
        result = agent.solve(_C9_BACKEND_TASK)

    assert result.success is False
    assert result.metadata["error"] == "timeout"
    assert run_process.call_args.kwargs["timeout_s"] == 1.0


def test_c9_backend_codex_nonzero_exit_has_machine_readable_error() -> None:
    from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

    agent = CodexSWEBenchAgent(codex_binary="/usr/bin/codex", timeout_s=1.0)
    completed = subprocess.CompletedProcess(
        ["codex"],
        returncode=23,
        stdout="",
        stderr="codex failed",
    )
    with patch(
        "constitutional_swarm.swe_bench.codex_agent._run_process",
        return_value=completed,
    ):
        result = agent.solve(_C9_BACKEND_TASK)

    assert result.success is False
    assert result.metadata["error"] == "codex_exit_nonzero"
    assert result.metadata["exit_code"] == 23
    assert result.metadata["stderr_tail"] == "codex failed"






C9_HARNESS_MODEL_PATCH = """\
diff --git a/src/demo.py b/src/demo.py
--- a/src/demo.py
+++ b/src/demo.py
@@ -1 +1 @@
-broken
+fixed
"""
C9_HARNESS_TEST_PATCH = """\
diff --git a/tests/test_demo.py b/tests/test_demo.py
--- a/tests/test_demo.py
+++ b/tests/test_demo.py
@@ -1 +1 @@
-assert broken()
+assert fixed()
"""
C9_HARNESS_INSTANCE = {
    "instance_id": "demo__demo-1",
    "repo": "demo/demo",
    "base_commit": "deadbeef",
    "FAIL_TO_PASS": ["tests/test_demo.py::test_fixed"],
    "PASS_TO_PASS": ["tests/test_demo.py::test_still_works"],
    "test_patch": C9_HARNESS_TEST_PATCH,
}


def c9_harness_stub_stages(monkeypatch, harness, *, test_patch_ok=True):
    events = []

    def clone(repo, worktree, result):
        events.append("clone")

    def checkout(worktree, base_commit, result):
        events.append("checkout")

    def model_patch(worktree, patch, result):
        events.append("model_patch")
        result.applied = True

    def official_patch(worktree, base_commit, patch, result):
        events.append("test_patch")
        assert patch == C9_HARNESS_TEST_PATCH
        result.metadata["test_patch_applied"] = test_patch_ok
        if not test_patch_ok:
            result.stage = "test_patch"
            result.error = "official test patch did not apply"

    def candidate_guard(worktree, base_commit, result):
        events.append("candidate_guard")

    def run_tests(
        worktree, fail_to_pass, pass_to_pass, result, python_bin, *, runner=None
    ):
        events.append("tests")
        assert runner == "pytest"
        result.fail_to_pass_passed = len(fail_to_pass)
        result.pass_to_pass_passed = len(pass_to_pass)
        result.metadata["fail_to_pass_statuses"] = {
            test_id: "passed" for test_id in fail_to_pass
        }
        result.metadata["pass_to_pass_statuses"] = {
            test_id: "passed" for test_id in pass_to_pass
        }

    monkeypatch.setattr(harness, "_clone_to_worktree", clone)
    monkeypatch.setattr(harness, "_checkout", checkout)
    monkeypatch.setattr(harness, "_apply_patch", model_patch)
    monkeypatch.setattr(
        harness,
        "_validate_candidate_test_controls",
        candidate_guard,
        raising=False,
    )
    monkeypatch.setattr(harness, "_apply_test_patch", official_patch, raising=False)
    monkeypatch.setattr(harness, "_run_tests", run_tests)
    return events


def test_c9_harness_official_test_patch_runs_after_model_patch_before_tests(
    tmp_path, monkeypatch
):
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    events = c9_harness_stub_stages(monkeypatch, harness)
    result = harness.evaluate(dict(C9_HARNESS_INSTANCE), C9_HARNESS_MODEL_PATCH)
    assert events == [
        "clone",
        "checkout",
        "model_patch",
        "candidate_guard",
        "test_patch",
        "tests",
    ]
    assert result.resolved is True
    assert result.metadata["test_patch_applied"] is True


def test_c9_harness_official_test_patch_failure_is_fail_closed(tmp_path, monkeypatch):
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    events = c9_harness_stub_stages(monkeypatch, harness, test_patch_ok=False)
    result = harness.evaluate(dict(C9_HARNESS_INSTANCE), C9_HARNESS_MODEL_PATCH)
    assert result.resolved is False
    assert result.stage == "test_patch"
    assert result.error == "official test patch did not apply"
    assert result.metadata["test_patch_applied"] is False
    assert events == ["clone", "checkout", "model_patch", "candidate_guard", "test_patch"]


def test_c9_harness_official_test_patch_restores_model_modified_test_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def c9_harness_git(*args, input_text=None):
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )

    c9_harness_git("init")
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / "src" / "demo.py").write_text("broken\n")
    (repo / "tests" / "test_demo.py").write_text("assert broken()\n")
    c9_harness_git("add", "src/demo.py", "tests/test_demo.py")
    base_tree = c9_harness_git("write-tree").stdout.strip()

    model_patch = C9_HARNESS_MODEL_PATCH + """\
diff --git a/tests/test_demo.py b/tests/test_demo.py
--- a/tests/test_demo.py
+++ b/tests/test_demo.py
@@ -1 +1 @@
-assert broken()
+assert malicious()
"""
    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    result = HarnessResult("demo__demo-1")
    harness._apply_patch(repo, model_patch, result)
    assert result.applied is True
    assert (repo / "tests" / "test_demo.py").read_text() == "assert malicious()\n"

    harness._apply_test_patch(repo, base_tree, C9_HARNESS_TEST_PATCH, result)

    assert result.error is None
    assert result.metadata["test_patch_applied"] is True
    assert (repo / "src" / "demo.py").read_text() == "fixed\n"
    assert (repo / "tests" / "test_demo.py").read_text() == "assert fixed()\n"


def test_c9_harness_missing_test_patch_is_fail_closed(tmp_path, monkeypatch):
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    events = c9_harness_stub_stages(monkeypatch, harness)
    instance = dict(C9_HARNESS_INSTANCE)
    instance.pop("test_patch")
    result = harness.evaluate(instance, C9_HARNESS_MODEL_PATCH)
    assert result.resolved is False
    assert result.stage == "test_patch"
    assert result.metadata["test_patch_applied"] is False
    assert "test_patch" in (result.error or "")
    assert "tests" not in events


@pytest.mark.parametrize(
    ("reported_status", "return_code", "junit_body", "expected_status"),
    [
        ("skipped", 0, "<skipped />", "skipped"),
        ("xfailed", 0, "<skipped type='pytest.xfail' />", "skipped"),
        ("xpassed", 0, "", "xpassed"),
        ("failed", 1, "<failure />", "failed"),
        ("error", 1, "<error />", "error"),
        ("missing", 0, None, "missing"),
    ],
)
def test_c9_harness_required_pytest_status_must_be_passed(
    tmp_path, monkeypatch, reported_status, return_code, junit_body, expected_status
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    required = "tests/test_demo.py::test_fixed"

    def fake_run(cmd, **kwargs):
        junit_path = Path(cmd[cmd.index("--junitxml") + 1])
        if junit_body is None:
            junit_path.write_text(
                '<testsuite><testcase file="tests/test_other.py" name="test_other" />'
                "</testsuite>"
            )
        else:
            junit_path.write_text(
                '<testsuite><testcase file="tests/test_demo.py" name="test_fixed">'
                f"{junit_body}</testcase></testsuite>"
            )
        if reported_status == "missing":
            return return_code, "1 deselected in 0.01s"
        token = "ERROR" if reported_status == "error" else reported_status.upper()
        summary_name = "errors" if reported_status == "error" else reported_status
        return return_code, f"{token} {required}\n1 {summary_name} in 0.01s"

    monkeypatch.setattr(local_harness, "_run", fake_run)
    statuses, _ = harness._pytest(tmp_path, [required], sys.executable)
    assert statuses == {required: expected_status}
    assert sum(status == "passed" for status in statuses.values()) == 0


def test_c9_harness_pytest_selector_with_mixed_outcomes_is_not_passed(
    tmp_path, monkeypatch
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    required = "tests/test_demo.py::test_fixed"
    output = (
        f"PASSED {required}[first]\n"
        f"SKIPPED {required}[second]\n"
        "1 passed, 1 skipped in 0.01s"
    )

    def fake_run(cmd, **_kwargs):
        junit_path = Path(cmd[cmd.index("--junitxml") + 1])
        junit_path.write_text(
            '<testsuite><testcase file="tests/test_demo.py" name="test_fixed[first]" />'
            '<testcase file="tests/test_demo.py" name="test_fixed[second]">'
            "<skipped /></testcase></testsuite>"
        )
        return 0, output

    monkeypatch.setattr(local_harness, "_run", fake_run)
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    statuses, _ = harness._pytest(tmp_path, [required], sys.executable)
    assert statuses == {required: "skipped"}


def test_c9_harness_required_django_skip_is_failure(tmp_path, monkeypatch):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    required = "demo.tests.DemoTests.test_fixed"
    output = (
        "test_fixed (demo.tests.DemoTests.test_fixed) ... skipped 'not available'\n"
        "Ran 1 test in 0.001s\n\nOK (skipped=1)\n"
    )
    monkeypatch.setattr(local_harness, "_run", lambda *args, **kwargs: (0, output))
    statuses, _ = harness._django_runtests(tmp_path, [required], sys.executable)
    assert statuses == {required: "skipped"}


def test_c9_harness_pytest_warning_and_rerun_summary_parser():
    assert _parse_pytest_summary("1 passed, 1 warning in 0.01s") == (1, 0)
    assert _parse_pytest_summary("1 passed, 1 rerun in 0.02s") == (1, 0)


def test_c9_harness_untrusted_subprocesses_use_allowlisted_environment(
    tmp_path, monkeypatch
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "do-not-leak")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((list(cmd), kwargs.get("env")))
        if "pytest" in cmd:
            test_id = cmd[-1]
            return 0, f"PASSED {test_id}\n1 passed in 0.01s"
        if "runtests.py" in cmd:
            test_id = cmd[-1]
            method = test_id.rsplit(".", 1)[-1]
            return 0, f"{method} ({test_id}) ... ok\nRan 1 test in 0.001s\n\nOK\n"
        return 0, ""

    monkeypatch.setattr(local_harness, "_run", fake_run)
    harness = LocalSWEBenchHarness(work_dir=tmp_path, env_isolation=True)
    harness._pytest(tmp_path, ["tests/test_demo.py::test_fixed"], sys.executable)
    harness._django_runtests(tmp_path, ["demo.tests.DemoTests.test_fixed"], sys.executable)
    harness._ensure_env("demo__demo-1", tmp_path, HarnessResult("demo__demo-1"))
    untrusted = [
        (cmd, env)
        for cmd, env in calls
        if "pytest" in cmd or "runtests.py" in cmd or "pip" in cmd
    ]
    assert untrusted
    for _, env in untrusted:
        assert env is not None
        assert env.get("PATH") == os.environ.get("PATH", "")
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "OPENAI_API_KEY" not in env
        assert "GITHUB_TOKEN" not in env
        if os.name == "nt" and "SystemRoot" in os.environ:
            assert env["SystemRoot"] == os.environ["SystemRoot"]


def test_c9_harness_run_defaults_to_minimal_environment(monkeypatch):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-git")
    completed = subprocess.CompletedProcess(["git", "status"], 0, "ok", "")
    with patch.object(local_harness, "_run_process", return_value=completed) as runner:
        assert local_harness._run(["git", "status"], timeout=1.0) == (0, "ok")

    child_env = runner.call_args.kwargs["env"]
    assert child_env is not None
    assert child_env["PATH"] == os.environ.get("PATH", "")
    assert "AWS_SECRET_ACCESS_KEY" not in child_env


@pytest.mark.parametrize(
    "bad_timeout", [0, -1, float("nan"), float("inf"), float("-inf"), True, "60"]
)
@pytest.mark.parametrize("field_name", ["timeout_s", "env_timeout_s"])
def test_c9_harness_rejects_unbounded_timeouts(tmp_path, field_name, bad_timeout):
    with pytest.raises(ValueError, match=field_name):
        LocalSWEBenchHarness(work_dir=tmp_path, **{field_name: bad_timeout})


@pytest.mark.parametrize(
    ("instance", "patch"),
    [
        ({"instance_id": "bad", "repo": "", "base_commit": ""}, C9_HARNESS_MODEL_PATCH),
        (dict(C9_HARNESS_INSTANCE), ""),
    ],
)
def test_c9_harness_evaluation_mode_is_present_on_early_returns(tmp_path, instance, patch):
    result = LocalSWEBenchHarness(work_dir=tmp_path).evaluate(instance, patch)
    assert result.metadata["evaluation_mode"] == "local_dockerless"


def test_c9_harness_generation_metric_schema_uses_patch_names_and_aliases():
    results = [
        SWEPatch(task_id="a", patch="diff", success=True),
        SWEPatch(task_id="b", patch="", success=False),
    ]
    metrics = SWEBenchHarness.summary(results)
    assert metrics["total"] == 2
    assert metrics["patch_generated"] == 1
    assert metrics["patch_rate"] == pytest.approx(0.5)
    assert metrics["resolved"] == metrics["patch_generated"]
    assert metrics["resolve_rate"] == metrics["patch_rate"]
    assert metrics["evaluation_mode"] == "patch_generation_only"


def test_c9_harness_patch_generation_metric_uses_patch_content():
    results = [
        SWEPatch(task_id="has-patch", patch="diff", success=False),
        SWEPatch(task_id="no-patch", patch="", success=True),
    ]
    metrics = SWEBenchHarness.summary(results)
    assert metrics["patch_generated"] == 1
    assert metrics["patch_rate"] == pytest.approx(0.5)


def test_c9_harness_swarm_coordinator_reuses_patch_generation_metrics():
    patches = [
        SWEPatch(task_id="a", patch="diff", success=True),
        SWEPatch(task_id="b", patch="", success=False),
    ]
    metrics = SwarmCoordinator._aggregate(
        patches, MerkleCRDT(agent_id="c9-harness-test")
    )
    assert metrics["patch_generated"] == 1
    assert metrics["patch_rate"] == pytest.approx(0.5)
    assert metrics["resolved"] == metrics["patch_generated"]
    assert metrics["resolve_rate"] == metrics["patch_rate"]
    assert metrics["evaluation_mode"] == "patch_generation_only"


def test_c9_harness_normalize_task_preserves_official_test_patch():
    from constitutional_swarm.swe_bench import run_one_by_one

    raw = {
        **C9_HARNESS_INSTANCE,
        "problem_statement": "fix it",
        "FAIL_TO_PASS": json.dumps(C9_HARNESS_INSTANCE["FAIL_TO_PASS"]),
        "PASS_TO_PASS": json.dumps(C9_HARNESS_INSTANCE["PASS_TO_PASS"]),
    }
    assert run_one_by_one._normalize_task(raw)["test_patch"] == C9_HARNESS_TEST_PATCH


def test_c9_harness_best_of_k_candidate_patch_rejects_traversal(tmp_path, monkeypatch):
    from constitutional_swarm.swe_bench import run_one_by_one

    run_root = tmp_path / "runs"
    monkeypatch.setattr(run_one_by_one, "_run_dir", lambda run_id: run_root / run_id)
    with pytest.raises(ValueError, match="instance_id"):
        run_one_by_one._save_candidate_patch(
            "run-1", "../../owned", 0, C9_HARNESS_MODEL_PATCH
        )
    assert not (tmp_path / "owned.agent0.diff").exists()
    assert not (run_root / "owned.agent0.diff").exists()


def test_c9_harness_best_of_k_persists_each_candidate_before_next_solve(
    tmp_path, monkeypatch
):
    from constitutional_swarm.swe_bench import run_one_by_one

    task = {**C9_HARNESS_INSTANCE, "problem_statement": "fix it"}
    datasets_module = types.ModuleType("datasets")
    datasets_module.load_dataset = lambda *args, **kwargs: [task]
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)
    run_root = tmp_path / "runs"
    monkeypatch.setattr(run_one_by_one, "_run_dir", lambda run_id: run_root / run_id)

    class C9HarnessFirstAgent:
        def solve(self, solve_task):
            return SWEPatch(solve_task["instance_id"], C9_HARNESS_MODEL_PATCH, True)

    class C9HarnessSecondAgent:
        def solve(self, solve_task):
            raise RuntimeError("second candidate failed")

    agents = iter([C9HarnessFirstAgent(), C9HarnessSecondAgent()])
    monkeypatch.setattr(run_one_by_one, "_build_agent", lambda **kwargs: next(agents))
    with pytest.raises(RuntimeError, match="second candidate failed"):
        run_one_by_one.run_best_of_k_batch(
            run_id="run-1",
            model="model-a",
            k=2,
            dataset="dataset",
            split="test",
        )
    results_path = run_root / "run-1" / "results.jsonl"
    rows = [json.loads(line) for line in results_path.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["agent_index"] == 0
    assert rows[0]["is_winner"] is False
    candidate_path = run_root / "run-1" / "patches" / "demo__demo-1.agent0.diff"
    assert candidate_path.read_text() == C9_HARNESS_MODEL_PATCH




def test_c9_runtime_agent_forwards_caller_hash_to_governed_graph() -> None:
    pytest.importorskip("langgraph")
    from constitutional_swarm.langgraph_runtime.agent import LangGraphSWEBenchAgent

    crdt = _C9RuntimeCRDT()

    def c9_runtime_graph_factory():
        return build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: ("--- a/file.py\n+++ b/file.py\n", {}),
            dna=_C9RuntimeCleanDNA(),
            crdt=crdt,
        )

    agent = LangGraphSWEBenchAgent(
        graph_factory=c9_runtime_graph_factory,
        constitutional_hash=CONSTITUTIONAL_HASH,
    )
    result = agent.solve(
        {
            "instance_id": "c9-runtime-agent",
            "problem_statement": "preserve caller hash provenance",
        }
    )

    assert result.success is True
    assert result.metadata["constitutional_hash"] == CONSTITUTIONAL_HASH
    assert len(crdt.calls) == 1






def c9_harness_review_git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )


def c9_harness_review_process_running(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


@pytest.mark.parametrize(
    ("case", "official_patch"),
    [
        (
            "rename",
            """diff --git a/tests/old.py b/tests/new.py
similarity index 100%
rename from tests/old.py
rename to tests/new.py
""",
        ),
        (
            "copy",
            """diff --git a/tests/old.py b/tests/new.py
similarity index 100%
copy from tests/old.py
copy to tests/new.py
""",
        ),
        (
            "delete",
            """diff --git a/tests/old.py b/tests/old.py
deleted file mode 100644
--- a/tests/old.py
+++ /dev/null
@@ -1 +0,0 @@
-assert safe()
""",
        ),
        (
            "new",
            """diff --git a/tests/new.py b/tests/new.py
new file mode 100644
--- /dev/null
+++ b/tests/new.py
@@ -0,0 +1 @@
+assert official()
""",
        ),
        (
            "symlink",
            """diff --git a/tests/link.py b/tests/link.py
new file mode 120000
--- /dev/null
+++ b/tests/link.py
@@ -0,0 +1 @@
+official-target
\\ No newline at end of file
""",
        ),
    ],
)
def test_c9_harness_review_official_patch_restores_all_preimages(
    tmp_path, case, official_patch
):
    repo = tmp_path / case
    repo.mkdir()
    c9_harness_review_git(repo, "init")
    (repo / "tests").mkdir()
    (repo / "tests" / "old.py").write_text("assert safe()\n")
    c9_harness_review_git(repo, "add", "tests/old.py")
    base_tree = c9_harness_review_git(repo, "write-tree").stdout.strip()

    (repo / "tests" / "old.py").write_text("assert malicious_model()\n")
    if case in {"new", "symlink"}:
        target = "link.py" if case == "symlink" else "new.py"
        (repo / "tests" / target).write_text("malicious-model\n")
    c9_harness_review_git(repo, "add", "-A")

    result = HarnessResult("review")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._apply_test_patch(
        repo, base_tree, official_patch, result
    )

    assert result.error is None
    assert result.metadata["test_patch_applied"] is True
    if case == "rename":
        assert not (repo / "tests" / "old.py").exists()
        assert (repo / "tests" / "new.py").read_text() == "assert safe()\n"
    elif case == "copy":
        assert (repo / "tests" / "old.py").read_text() == "assert safe()\n"
        assert (repo / "tests" / "new.py").read_text() == "assert safe()\n"
    elif case == "delete":
        assert not (repo / "tests" / "old.py").exists()
    elif case == "new":
        assert (repo / "tests" / "new.py").read_text() == "assert official()\n"
    else:
        assert (repo / "tests" / "link.py").is_symlink()
        assert os.readlink(repo / "tests" / "link.py") == "official-target"


@pytest.mark.parametrize(
    ("output", "return_code", "expected"),
    [
        ("PASSED tests/test_other.py::test_other\n1 passed in 0.01s", 0, "missing"),
        (
            "PASSED tests/test_demo.py::test_required[first]\n"
            "SKIPPED tests/test_demo.py::test_required[second]\n"
            "1 passed, 1 skipped in 0.01s",
            0,
            "skipped",
        ),
        (
            "PASSED tests/test_demo.py::test_required[first]\n"
            "SKIPPED [1] tests/test_demo.py:10: unavailable\n"
            "1 passed, 1 skipped in 0.01s",
            0,
            "skipped",
        ),
        (
            "PASSED tests/test_demo.py::test_required\n"
            "ERROR teardown of tests/test_demo.py::test_required\n"
            "1 passed, 1 error in 0.01s",
            0,
            "error",
        ),
        ("PASSED tests/test_demo.py::test_required\n1 passed in 0.01s", 1, "error"),
    ],
)
def test_c9_harness_review_pytest_requires_exact_identity(
    output, return_code, expected
):
    assert (
        _pytest_test_status(
            "tests/test_demo.py::test_required", output, return_code
        )
        == expected
    )


@pytest.mark.parametrize(
    ("output", "return_code", "expected"),
    [
        (
            "test_other (pkg.tests.Case.test_other) ... ok\n"
            "Ran 1 test in 0.001s\n\nOK\n",
            0,
            "missing",
        ),
        (
            "test_required (pkg.tests.Case.test_required) ... ok\n"
            "Ran 1 test in 0.001s\n\nOK\n",
            1,
            "error",
        ),
    ],
)
def test_c9_harness_review_django_requires_exact_identity_and_zero_rc(
    output, return_code, expected
):
    assert (
        _django_test_status(
            "pkg.tests.Case.test_required", output, return_code
        )
        == expected
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group regression")
def test_c9_harness_review_timeout_reaps_ignoring_grandchild(tmp_path):
    pid_path = tmp_path / "grandchild.pid"
    grandchild = (
        "import os,signal,time,pathlib;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()));"
        "time.sleep(30)"
    )
    child = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]);"
        "time.sleep(30)"
    )
    grandchild_pid = None
    try:
        rc, _ = _run([sys.executable, "-c", child], timeout=0.2)
        assert rc == 124
        for _ in range(50):
            if pid_path.exists():
                grandchild_pid = int(pid_path.read_text())
                break
            time.sleep(0.01)
        assert grandchild_pid is not None
        for _ in range(50):
            if not c9_harness_review_process_running(grandchild_pid):
                break
            time.sleep(0.02)
        else:
            pytest.fail("grandchild survived local harness stage timeout")
    finally:
        if grandchild_pid is not None:
            try:
                os.kill(grandchild_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass




class _C9RuntimeReviewChunkGraph:
    def __init__(self, chunks):
        self.chunks = chunks

    async def astream(self, _inputs, **_kwargs):
        for chunk in self.chunks:
            yield chunk


class _C9RuntimeReviewResultAgent:
    def __init__(self, *results):
        self.results = iter(results)

    def solve(self, _task):
        return next(self.results)


def test_c9_runtime_agent_does_not_return_governance_rejected_patch() -> None:
    pytest.importorskip("langgraph")
    from constitutional_swarm.langgraph_runtime.agent import LangGraphSWEBenchAgent

    class _C9RuntimeRiskyDNA:
        hash = CONSTITUTIONAL_HASH

        def validate(self, _patch: str) -> SimpleNamespace:
            return SimpleNamespace(
                valid=False,
                violations=("unsafe patch",),
                risk_score=1.0,
            )

    crdt = _C9RuntimeCRDT()

    def c9_runtime_rejecting_graph_factory():
        return build_swarm_graph(
            {"hash": CONSTITUTIONAL_HASH},
            generator=lambda _state: ("--- a/file.py\n+++ b/file.py\n", {}),
            dna=_C9RuntimeRiskyDNA(),
            crdt=crdt,
        )

    agent = LangGraphSWEBenchAgent(
        graph_factory=c9_runtime_rejecting_graph_factory,
        constitutional_hash=CONSTITUTIONAL_HASH,
    )
    result = agent.solve(
        {
            "instance_id": "c9-runtime-rejected-agent",
            "problem_statement": "reject the generated patch",
        }
    )

    assert result.success is False
    assert result.patch == ""
    assert result.metadata["error"] == "governance_rejected"
    assert result.metadata["governance_status"] == "rejected"
    assert result.metadata["violations"] == ["unsafe patch"]
    assert crdt.calls == []


def test_c9_runtime_append_node_binds_exact_constitutional_hash() -> None:
    from constitutional_swarm.langgraph_runtime.nodes import append_crdt_node

    crdt = MerkleCRDT("c9-runtime-review")
    result = append_crdt_node(
        {
            "patch": "patch",
            "governed": True,
            "risk_score": 0.0,
            "violations": [],
            "constitutional_hash": CONSTITUTIONAL_HASH,
        },
        crdt=crdt,
    )

    node = crdt.get(result["cid"])
    assert node is not None
    assert node.constitutional_hash == CONSTITUTIONAL_HASH


@pytest.mark.parametrize(
    "state",
    [
        {"patch": "patch", "governed": True},
        {"patch": "patch", "governed": True, "constitutional_hash": "wrong"},
    ],
)
def test_c9_runtime_append_node_rejects_untrusted_hash(state) -> None:
    from constitutional_swarm.langgraph_runtime.nodes import append_crdt_node

    crdt = _C9RuntimeCRDT()
    with pytest.raises(ValueError, match="hash"):
        append_crdt_node(state, crdt=crdt)
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_c9_runtime_streaming_rejects_intermediate_hash_tampering() -> None:
    graph = _C9RuntimeReviewChunkGraph(
        [
            {"generate": {"patch": "patch", "constitutional_hash": "wrong"}},
            {"validate": {"governance_status": "accepted", "governed": True}},
            {"settle": {"settled": True}},
        ]
    )
    crdt = _C9RuntimeCRDT()

    with pytest.raises(ValueError, match="hash"):
        async for _chunk in stream_to_crdt(
            graph,
            {"task_id": "tampered", "constitutional_hash": CONSTITUTIONAL_HASH},
            crdt,
        ):
            pass
    assert crdt.calls == []


@pytest.mark.asyncio
async def test_c9_runtime_streaming_does_not_append_rejected_or_unsettled_state() -> None:
    graph = _C9RuntimeReviewChunkGraph(
        [
            {"generate": {"patch": "unsafe patch"}},
            {
                "validate": {
                    "governance_status": "rejected",
                    "governed": False,
                    "violations": ["unsafe patch"],
                }
            },
            {"settle": {"settled": False}},
        ]
    )
    crdt = _C9RuntimeCRDT()

    async for _chunk in stream_to_crdt(
        graph,
        {"task_id": "rejected", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert crdt.calls == []


@pytest.mark.asyncio
async def test_c9_runtime_streaming_appends_accumulated_accepted_state() -> None:
    graph = _C9RuntimeReviewChunkGraph(
        [
            {"generate": {"patch": "accepted patch", "intervention_rate": 0.25}},
            {
                "validate": {
                    "governed": True,
                    "risk_score": 0.0,
                    "violations": [],
                }
            },
            {"settle": {"governance_status": "accepted", "settled": True}},
        ]
    )
    crdt = _C9RuntimeCRDT()

    async for _chunk in stream_to_crdt(
        graph,
        {"task_id": "accepted", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert len(crdt.calls) == 1
    call = crdt.calls[0]
    payload = json.loads(call["payload"])
    assert payload["patch"] == "accepted patch"
    assert payload["governance_status"] == "accepted"
    assert payload["settled"] is True
    assert payload["risk_score"] == 0.0
    assert payload["constitutional_hash"] == CONSTITUTIONAL_HASH
    assert call["bodes_passed"] is True
    assert call["constitutional_hash"] == CONSTITUTIONAL_HASH


@pytest.mark.parametrize("hash_source", ["metadata", "configuration"])
def test_c9_runtime_adapter_binds_governed_result_hash(
    monkeypatch,
    hash_source: str,
) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    created = []

    class _C9RuntimeReviewCoordinatorCRDT(_C9RuntimeCRDT):
        def __init__(self, _agent_id):
            super().__init__()
            created.append(self)

        @property
        def size(self):
            return len(self.calls)

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _C9RuntimeReviewCoordinatorCRDT)
    metadata = (
        {"constitutional_hash": CONSTITUTIONAL_HASH}
        if hash_source == "metadata"
        else {}
    )
    result = SWEPatch(
        task_id="c9-runtime-governed",
        patch="patch",
        success=True,
        governed=True,
        metadata=metadata,
    )

    coordinator_adapter.run_langgraph(
        [_C9RuntimeReviewResultAgent(result)],
        _c9_runtime_make_tasks(1),
        constitutional_hash=(
            CONSTITUTIONAL_HASH if hash_source == "configuration" else None
        ),
    )

    assert created[0].calls[0]["bodes_passed"] is True
    expected_artifact_hash = (
        CONSTITUTIONAL_HASH if hash_source == "metadata" else ""
    )
    assert created[0].calls[0]["constitutional_hash"] == expected_artifact_hash


def test_c9_runtime_adapter_stamps_default_hash_on_governed_result(monkeypatch) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    created = []

    class _C9RuntimeReviewCoordinatorCRDT(_C9RuntimeCRDT):
        def __init__(self, _agent_id):
            super().__init__()
            created.append(self)

        @property
        def size(self):
            return len(self.calls)

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _C9RuntimeReviewCoordinatorCRDT)
    result = SWEPatch(
        task_id="c9-runtime-governed-no-hash",
        patch="patch",
        success=True,
        governed=True,
    )

    outcome = coordinator_adapter.run_langgraph(
        [_C9RuntimeReviewResultAgent(result)],
        _c9_runtime_make_tasks(1),
    )

    assert "constitutional_hash" not in outcome["patches"][0].metadata
    assert created[0].calls[0]["bodes_passed"] is True
    assert created[0].calls[0]["constitutional_hash"] == ""


def test_c9_runtime_adapter_marks_generation_only_log_ungoverned(monkeypatch) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    created = []

    class _C9RuntimeReviewCoordinatorCRDT(_C9RuntimeCRDT):
        def __init__(self, _agent_id):
            super().__init__()
            created.append(self)

        @property
        def size(self):
            return len(self.calls)

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _C9RuntimeReviewCoordinatorCRDT)
    result = SWEPatch(
        task_id="c9-runtime-generation-only",
        patch="patch",
        success=True,
        governed=False,
    )

    coordinator_adapter.run_langgraph(
        [_C9RuntimeReviewResultAgent(result)],
        _c9_runtime_make_tasks(1),
        constitutional_hash=CONSTITUTIONAL_HASH,
    )

    assert created[0].calls[0]["bodes_passed"] is False
    assert created[0].calls[0]["constitutional_hash"] == ""


def test_c9_runtime_subspace_dimension_mismatch_is_loud_and_counted() -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )
    subspace = violation_subspace.ViolationSubspace(
        basis=np.array([[1.0, 0.0]]),
        mean=np.zeros(2),
    )
    hook = latent_dna._BODESSubspaceHook(subspace)
    hidden = torch.ones((1, 3, 3))

    with pytest.warns(RuntimeWarning, match="dimension.*expected 2.*got 3"):
        output = hook(None, (), hidden.clone())

    assert torch.equal(output, hidden)
    assert hook.total_tokens == 3
    assert hook.interventions == 0
    assert hook.steer_failures == 3


@pytest.mark.parametrize("hook_kind", ["rank1", "subspace"])
def test_c9_runtime_successful_steering_records_no_failures(hook_kind: str) -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )
    if hook_kind == "rank1":
        hook = latent_dna._BODESHook(torch.tensor([1.0, 0.0]))
    else:
        hook = latent_dna._BODESSubspaceHook(
            violation_subspace.ViolationSubspace(
                basis=np.array([[1.0, 0.0]]),
                mean=np.zeros(2),
            )
        )

    hook(None, (), torch.tensor([[[1.0, 0.0]]]))

    assert hook.interventions == 1
    assert hook.steer_failures == 0


@pytest.mark.parametrize("hook_kind", ["rank1", "subspace"])
def test_c9_runtime_enable_resets_all_latent_counters(hook_kind: str) -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )

    class _C9RuntimeReviewModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.config = SimpleNamespace(model_type="c9-runtime-review")
            self.layers = torch.nn.ModuleList([torch.nn.Identity()])

        def generate(self, *args, **kwargs):
            return None

    model = _C9RuntimeReviewModel()
    kwargs = {"v_viol": torch.tensor([1.0, 0.0])}
    if hook_kind == "subspace":
        kwargs = {
            "subspace": violation_subspace.ViolationSubspace(
                basis=np.array([[1.0, 0.0]]),
                mean=np.zeros(2),
            )
        }
    wrapper = latent_dna.LatentDNAWrapper(
        model,
        layer_idx=0,
        layer_attr_path="layers",
        **kwargs,
    )
    wrapper._hook_impl.total_tokens = 5
    wrapper._hook_impl.interventions = 4
    wrapper._hook_impl.steer_failures = 3

    wrapper.enable()
    try:
        assert wrapper.intervention_stats()["total_tokens"] == 0
        assert wrapper.intervention_stats()["steered_tokens"] == 0
        assert wrapper.intervention_stats()["steer_failures"] == 0
    finally:
        wrapper.disable()


@pytest.mark.parametrize("hook_kind", ["rank1", "leace"])
def test_c9_runtime_latent_cache_reuses_each_dtype(hook_kind: str) -> None:
    np = pytest.importorskip("numpy")
    torch = pytest.importorskip("torch")
    latent_dna = pytest.importorskip("constitutional_swarm.latent_dna")
    violation_subspace = pytest.importorskip(
        "constitutional_swarm.violation_subspace"
    )
    if hook_kind == "rank1":
        hook = latent_dna._BODESHook(torch.tensor([1.0, 0.0]))
    else:
        identity = np.eye(2)
        hook = latent_dna._BODESSubspaceHook(
            violation_subspace.ViolationSubspace(
                basis=np.array([[1.0, 0.0]]),
                mean=np.zeros(2),
                whitener=identity,
                dewhitener=identity,
            )
        )

    input32 = torch.tensor([[[1.0, 0.0]]], dtype=torch.float32)
    input64 = input32.to(dtype=torch.float64)
    output32_first = hook(None, (), input32.clone())
    output32_second = hook(None, (), input32.clone())
    output64_first = hook(None, (), input64.clone())
    output64_second = hook(None, (), input64.clone())

    assert torch.equal(output32_first, output32_second)
    assert torch.equal(output64_first, output64_second)
    assert torch.allclose(output32_first.to(dtype=torch.float64), output64_first)
    assert len(hook._tensor_cache) == 2


@pytest.mark.parametrize("instance_id", ["", ".", "..", "bad\0id"])
def test_c9_harness_rejects_unsafe_instance_id_before_filesystem_mutation(
    tmp_path, monkeypatch, instance_id
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    instance = dict(C9_HARNESS_INSTANCE, instance_id=instance_id)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("filesystem mutation reached for unsafe instance id")

    monkeypatch.setattr(local_harness.shutil, "rmtree", forbidden)
    monkeypatch.setattr(harness, "_clone_to_worktree", forbidden)
    result = harness.evaluate(instance, C9_HARNESS_MODEL_PATCH)

    assert result.resolved is False
    assert result.applied is False
    assert result.stage == "clone"
    assert "invalid instance_id" in (result.error or "")


@pytest.mark.parametrize("instance_id", ["", ".", "..", "bad\0id"])
def test_c9_harness_rejects_unsafe_venv_id_before_creation(
    tmp_path, monkeypatch, instance_id
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness", env_isolation=True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("venv filesystem mutation reached for unsafe instance id")

    monkeypatch.setattr(local_harness.shutil, "rmtree", forbidden)
    monkeypatch.setattr(local_harness, "_run", forbidden)
    with pytest.raises(ValueError, match="invalid instance_id"):
        harness._ensure_env(instance_id, tmp_path, HarnessResult(instance_id))


def test_c9_harness_scoped_paths_are_strict_descendants(tmp_path):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    root = tmp_path / "root"
    root.mkdir()
    child = local_harness._safe_child_path(root, "owner/repo", field_name="repo")
    assert child.parent == root.resolve()
    assert child != root.resolve()
    assert child.is_relative_to(root.resolve())


def test_c9_harness_safe_id_is_readable_stable_and_collision_resistant():
    import constitutional_swarm.swe_bench.local_harness as local_harness

    slash_id = local_harness._safe_id("a/b", field_name="instance_id")
    underscore_id = local_harness._safe_id("a_b", field_name="instance_id")

    assert slash_id.startswith("a_b-")
    assert underscore_id.startswith("a_b-")
    assert slash_id == local_harness._safe_id("a/b", field_name="instance_id")
    assert slash_id != underscore_id


def test_c9_harness_cleanup_refuses_paths_retargeted_outside_roots(
    tmp_path, monkeypatch
):
    harness = LocalSWEBenchHarness(
        work_dir=tmp_path / "harness",
        env_isolation=True,
    )
    outside_worktree = tmp_path / "outside-worktree"
    outside_venv = tmp_path / "outside-venv"
    outside_worktree.mkdir()
    outside_venv.mkdir()
    (outside_worktree / "sentinel").write_text("keep")
    (outside_venv / "sentinel").write_text("keep")

    def clone(_repo, worktree, _result):
        worktree.mkdir()

    def apply_model(_worktree, _patch, result):
        result.applied = True

    def apply_official(_worktree, _base, _patch, result):
        result.metadata["test_patch_applied"] = True

    def ensure_env(instance_id, _worktree, _result, **_kwargs):
        venv = harness.env_cache_dir / instance_id
        venv.mkdir()
        return venv, sys.executable

    def retarget_paths(worktree, _f2p, _p2p, result, _python, **_kwargs):
        venv = harness.env_cache_dir / C9_HARNESS_INSTANCE["instance_id"]
        worktree.rmdir()
        venv.rmdir()
        worktree.symlink_to(outside_worktree, target_is_directory=True)
        venv.symlink_to(outside_venv, target_is_directory=True)
        result.metadata["fail_to_pass_statuses"] = {
            C9_HARNESS_INSTANCE["FAIL_TO_PASS"][0]: "passed"
        }

    monkeypatch.setattr(harness, "_clone_to_worktree", clone)
    monkeypatch.setattr(harness, "_checkout", lambda *_args: None)
    monkeypatch.setattr(harness, "_apply_patch", apply_model)
    monkeypatch.setattr(
        harness, "_validate_candidate_test_controls", lambda *_args: None
    )
    monkeypatch.setattr(harness, "_apply_test_patch", apply_official)
    monkeypatch.setattr(harness, "_ensure_env", ensure_env)
    monkeypatch.setattr(harness, "_run_tests", retarget_paths)

    result = harness.evaluate(C9_HARNESS_INSTANCE, C9_HARNESS_MODEL_PATCH)

    assert result.resolved is False
    assert "cleanup refused" in (result.error or "")
    assert (outside_worktree / "sentinel").read_text() == "keep"
    assert (outside_venv / "sentinel").read_text() == "keep"


@pytest.mark.parametrize(
    "output",
    [
        "test_required (pkg.tests.Case.test_required) ... ok\n",
        "test_required (pkg.tests.Case) ... ok\n",
        "pkg.tests.Case.test_required ... ok\n",
        "test_required (pkg.tests.Case.test_required)\nA useful description ... ok\n",
    ],
)
def test_c9_harness_django_accepts_supported_identity_formats(output):
    output += "Ran 1 test in 0.001s\n\nOK\n"
    assert _django_test_status("pkg.tests.Case.test_required", output, 0) == "passed"


def test_c9_harness_django_pass_requires_ran_summary():
    output = "test_required (pkg.tests.Case.test_required) ... ok\n"
    assert _django_test_status("pkg.tests.Case.test_required", output, 0) == "error"


def _c9_harness_config_repo(tmp_path):
    repo = tmp_path / "config-repo"
    repo.mkdir()
    c9_harness_review_git(repo, "init")
    base_files = {
        "pytest.ini": "[pytest]\naddopts = -q\n",
        "setup.cfg": "[metadata]\nname = demo\n\n[tool:pytest]\naddopts = -q\n",
        "tox.ini": "[tox]\nenvlist = py\n\n[pytest]\naddopts = -q\n",
        "pyproject.toml": (
            "[project]\nname = 'demo'\nversion = '1.0'\n\n"
            "[tool.pytest.ini_options]\naddopts = '-q'\n"
        ),
    }
    for relative, content in base_files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    c9_harness_review_git(repo, "add", "-A")
    base_tree = c9_harness_review_git(repo, "write-tree").stdout.strip()
    return repo, base_tree


@pytest.mark.parametrize(
    ("relative", "candidate"),
    [
        ("nested/conftest.py", "def pytest_runtest_setup(item):\n    item.add_marker('skip')\n"),
        ("pytest.ini", "[pytest]\naddopts = --ignore=tests\n"),
        ("setup.cfg", "[metadata]\nname = demo\n\n[tool:pytest]\naddopts = --ignore=tests\n"),
        ("tox.ini", "[tox]\nenvlist = py\n\n[pytest]\naddopts = --ignore=tests\n"),
        (
            "pyproject.toml",
            "[project]\nname = 'demo'\nversion = '1.0'\n\n"
            "[tool.pytest.ini_options]\naddopts = '--ignore=tests'\n",
        ),
        ("pyproject.toml", "[tool.pytest.ini_options\naddopts = '-q'\n"),
    ],
)
def test_c9_harness_rejects_candidate_pytest_control_changes(
    tmp_path, relative, candidate
):
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(candidate)
    c9_harness_review_git(repo, "add", "-A")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.resolved is False
    assert result.error is not None
    assert "pytest control" in result.error


def test_c9_harness_rejects_candidate_symlinked_conftest(tmp_path):
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    (repo / "payload.py").write_text("print('payload')\n")
    nested = repo / "nested"
    nested.mkdir()
    (nested / "conftest.py").symlink_to("../payload.py")
    c9_harness_review_git(repo, "add", "-A")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.resolved is False
    assert result.error is not None
    assert "pytest control" in result.error


def test_c9_harness_allows_unrelated_multipurpose_config_change(tmp_path):
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    (repo / "setup.cfg").write_text(
        "[metadata]\nname = demo\nversion = 2.0\n\n[tool:pytest]\naddopts = -q\n"
    )
    c9_harness_review_git(repo, "add", "setup.cfg")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.error is None


def test_c9_harness_rejects_native_tool_pytest_config_change(tmp_path):
    repo = tmp_path / "native-pytest-config"
    repo.mkdir()
    c9_harness_review_git(repo, "init")
    pyproject = repo / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'demo'\nversion = '1.0'\n\n"
        "[tool.pytest]\naddopts = ['-q']\n"
    )
    c9_harness_review_git(repo, "add", "pyproject.toml")
    base_tree = c9_harness_review_git(repo, "write-tree").stdout.strip()
    pyproject.write_text(
        "[project]\nname = 'demo'\nversion = '1.0'\n\n"
        "[tool.pytest]\naddopts = ['-p', 'flipper']\n"
    )
    c9_harness_review_git(repo, "add", "pyproject.toml")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.error == "candidate modified pytest control: pyproject.toml"


def test_c9_harness_official_patch_may_change_pytest_control_after_candidate_gate(
    tmp_path,
):
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    result = HarnessResult("config")
    harness._validate_candidate_test_controls(repo, base_tree, result)
    assert result.error is None

    official = """diff --git a/pytest.ini b/pytest.ini
--- a/pytest.ini
+++ b/pytest.ini
@@ -1,2 +1,2 @@
 [pytest]
-addopts = -q
+addopts = -ra
"""
    harness._apply_test_patch(repo, base_tree, official, result)

    assert result.metadata["test_patch_applied"] is True
    assert (repo / "pytest.ini").read_text() == "[pytest]\naddopts = -ra\n"


@pytest.mark.parametrize(
    ("xml", "expected"),
    [
        (
            '<testsuite><testcase file="tests/test_demo.py" name="test_fixed" />'
            "</testsuite>",
            "passed",
        ),
        (
            '<testsuite><testcase file="tests/test_demo.py" name="test_fixed">'
            '<skipped message="no" /></testcase></testsuite>',
            "skipped",
        ),
        (
            '<testsuite><testcase file="tests/test_demo.py" name="test_fixed">'
            '<failure message="bad" /></testcase></testsuite>',
            "failed",
        ),
        (
            '<testsuite><testcase file="tests/test_demo.py" name="test_fixed[first]" />'
            '<testcase file="tests/test_demo.py" name="test_fixed[second]">'
            '<skipped /></testcase></testsuite>',
            "skipped",
        ),
        (
            '<testsuite><testcase file="tests/test_other.py" name="test_other" />'
            "</testsuite>",
            "missing",
        ),
        ("not xml", "error"),
        ("<testsuite />", "missing"),
    ],
)
def test_c9_harness_junit_is_primary_per_test_evidence(
    tmp_path, monkeypatch, xml, expected
):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    required = "tests/test_demo.py::test_fixed"
    junit_paths = []

    def fake_run(cmd, **_kwargs):
        junit_path = Path(cmd[cmd.index("--junitxml") + 1])
        junit_paths.append(junit_path)
        junit_path.write_text(xml)
        return 0, f"PASSED {required}\n1 passed in 0.01s"

    monkeypatch.setattr(local_harness, "_run", fake_run)
    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    statuses, _ = harness._pytest(tmp_path, [required], sys.executable)

    assert statuses == {required: expected}
    assert len(junit_paths) == 1
    assert junit_paths[0].parent.parent == harness.work_dir
    assert not junit_paths[0].parent.exists()


def test_c9_harness_missing_junit_rejects_forged_stdout_pass(tmp_path, monkeypatch):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    required = "tests/test_demo.py::test_fixed"
    monkeypatch.setattr(
        local_harness,
        "_run",
        lambda *_args, **_kwargs: (0, f"PASSED {required}\n1 passed in 0.01s"),
    )
    statuses, _ = LocalSWEBenchHarness(work_dir=tmp_path / "harness")._pytest(
        tmp_path, [required], sys.executable
    )
    assert statuses == {required: "error"}


def test_c9_harness_real_pytest_rejects_forged_pass_without_junit(tmp_path):
    worktree = tmp_path / "repo"
    worktree.mkdir()
    (worktree / "test_a.py").write_text(
        "import os\n\n"
        "def test_x():\n"
        "    os.write(1, b'PASSED test_a.py::test_x\\n')\n"
        "    os._exit(0)\n"
    )

    statuses, _ = LocalSWEBenchHarness(work_dir=tmp_path / "harness")._pytest(
        worktree, ["test_a.py::test_x"], sys.executable
    )

    assert statuses == {"test_a.py::test_x": "error"}


def test_c9_harness_junit_matches_class_method_selector(tmp_path, monkeypatch):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    required = "tests/test_demo.py::TestCase::test_fixed"

    def fake_run(cmd, **_kwargs):
        junit_path = Path(cmd[cmd.index("--junitxml") + 1])
        junit_path.write_text(
            '<testsuite><testcase file="tests/test_demo.py" '
            'classname="tests.test_demo.TestCase" name="test_fixed" />'
            "</testsuite>"
        )
        return 0, f"PASSED {required}\n1 passed in 0.01s"

    monkeypatch.setattr(local_harness, "_run", fake_run)
    statuses, _ = LocalSWEBenchHarness(work_dir=tmp_path / "harness")._pytest(
        tmp_path, [required], sys.executable
    )

    assert statuses == {required: "passed"}


class _C9RuntimeConfiguredWrapperAgent(SWEBenchAgent):
    def __init__(self) -> None:
        super().__init__(wrapper=object())

    def _generate_patch(
        self, _task: dict[str, object]
    ) -> tuple[str, dict[str, object]]:
        return "patch", {"intervention_rate": 0.25}


def test_c9_runtime_coordinator_default_hash_stamps_direct_governed_result() -> None:
    result = run_langgraph(
        [_C9RuntimeConfiguredWrapperAgent()], _c9_runtime_make_tasks(1)
    )

    patch_result = result["patches"][0]
    assert patch_result.success is True
    assert patch_result.governed is True
    assert "constitutional_hash" not in patch_result.metadata


def test_c9_runtime_coordinator_hash_mismatch_rejects_one_result_and_preserves_batch(
    monkeypatch,
) -> None:
    from constitutional_swarm.langgraph_runtime import coordinator_adapter

    class _C9RuntimeCoordinatorCRDT(_C9RuntimeCRDT):
        def __init__(self, _agent_id):
            super().__init__()

        @property
        def size(self):
            return len(self.calls)

    monkeypatch.setattr(coordinator_adapter, "MerkleCRDT", _C9RuntimeCoordinatorCRDT)
    first = SWEPatch(
        task_id="c9-runtime-0",
        patch="first good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )
    bad = SWEPatch(
        task_id="c9-runtime-1",
        patch="bad patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": "wrong"},
    )
    good = SWEPatch(
        task_id="c9-runtime-2",
        patch="last good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )

    result = coordinator_adapter.run_langgraph(
        [_C9RuntimeReviewResultAgent(first, bad, good)],
        _c9_runtime_make_tasks(3),
    )

    accepted_before, rejected, accepted_after = result["patches"]
    assert accepted_before.patch == "first good patch"
    assert rejected.patch == ""
    assert rejected.success is False
    assert rejected.governed is False
    assert rejected.metadata["governance_status"] == "rejected"
    assert rejected.metadata["error"] == "constitutional_hash_mismatch"
    assert rejected.metadata["expected_constitutional_hash"] == CONSTITUTIONAL_HASH
    assert rejected.metadata["actual_constitutional_hash"] == "wrong"
    assert accepted_after.patch == "last good patch"
    assert accepted_after.success is True
    assert result["total"] == 3
    assert result["patch_generated"] == 2
    assert result["crdt_size"] == 3


def test_c9_runtime_coordinator_rejects_bad_configured_hash_before_agent_call() -> None:
    agent = MagicMock()

    with pytest.raises(ValueError, match="configured constitutional hash"):
        run_langgraph(
            [agent],
            _c9_runtime_make_tasks(1),
            constitutional_hash="wrong",
        )

    agent.solve.assert_not_called()


@pytest.mark.parametrize("configured_hash", ["", False])
def test_c9_runtime_coordinator_only_none_selects_default_hash(
    configured_hash,
) -> None:
    agent = MagicMock()

    with pytest.raises(ValueError, match="configured constitutional hash"):
        run_langgraph(
            [agent],
            _c9_runtime_make_tasks(1),
            constitutional_hash=configured_hash,
        )

    agent.solve.assert_not_called()


def test_c9_runtime_explicit_rejection_overrides_governed_flag() -> None:
    contradictory = SWEPatch(
        task_id="c9-runtime-0",
        patch="must not escape",
        success=True,
        governed=True,
        metadata={
            "constitutional_hash": CONSTITUTIONAL_HASH,
            "governance_status": "rejected",
        },
    )

    result = run_langgraph(
        [_C9RuntimeReviewResultAgent(contradictory)],
        _c9_runtime_make_tasks(1),
    )

    rejected = result["patches"][0]
    assert rejected.patch == ""
    assert rejected.success is False
    assert rejected.governed is False
    assert rejected.metadata["governance_status"] == "rejected"
    assert rejected.metadata["error"] == "governance_rejected"
    assert result["patch_generated"] == 0


def test_c9_runtime_graph_accepts_without_optional_crdt() -> None:
    pytest.importorskip("langgraph")
    graph = build_swarm_graph(
        {"hash": CONSTITUTIONAL_HASH},
        generator=lambda _state: ("patch", {}),
        dna=_C9RuntimeCleanDNA(),
        crdt=None,
    )

    result = graph.invoke(
        {
            "constitutional_hash": CONSTITUTIONAL_HASH,
            "quorum_reached": True,
        },
        config={"configurable": {"thread_id": "c9-runtime-no-crdt"}},
    )

    assert result["governance_status"] == "accepted"
    assert result["governed"] is True
    assert result["cid"] == ""
    assert result["settled"] is True


def test_c9_runtime_optional_crdt_still_rejects_invalid_hash() -> None:
    with pytest.raises(ValueError, match="constitutional hash mismatch"):
        append_crdt_node(
            {"constitutional_hash": "wrong", "governed": True},
            crdt=None,
        )


def test_c9_backend_safe_path_component_rejects_nul() -> None:
    from constitutional_swarm.swe_bench.run_one_by_one import _safe_path_component

    with pytest.raises(ValueError, match="instance_id"):
        _safe_path_component("repo__issue\x00suffix", field_name="instance_id")


def test_c9_backend_subprocess_env_inherits_only_safe_connectivity(monkeypatch) -> None:
    from constitutional_swarm.swe_bench._subprocess import _subprocess_env

    allowed = {
        "HTTP_PROXY": "http://proxy.example",
        "HTTPS_PROXY": "https://proxy.example",
        "NO_PROXY": "localhost,127.0.0.1",
        "PIP_INDEX_URL": "https://index.example/simple",
        "PIP_EXTRA_INDEX_URL": "https://extra.example/simple",
        "SSL_CERT_FILE": "/certs/ca.pem",
        "REQUESTS_CA_BUNDLE": "/certs/requests.pem",
    }
    for name, value in allowed.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    monkeypatch.setenv("DATABASE_CREDENTIALS", "must-not-leak")

    child_env = _subprocess_env()

    assert {name: child_env[name] for name in allowed} == allowed
    assert "AWS_SECRET_ACCESS_KEY" not in child_env
    assert "GITHUB_TOKEN" not in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "DATABASE_CREDENTIALS" not in child_env


@pytest.mark.parametrize(
    "name",
    ["HTTP_PROXY", "HTTPS_PROXY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"],
)
def test_c9_backend_subprocess_env_drops_credential_bearing_urls(
    monkeypatch, name
) -> None:
    from constitutional_swarm.swe_bench._subprocess import _subprocess_env

    monkeypatch.setenv(name, "https://agent:secret@example.invalid/simple")

    child_env = _subprocess_env()

    assert name not in child_env
    assert "agent" not in repr(child_env)
    assert "secret" not in repr(child_env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("HTTP_PROXY", "agent:secret@proxy.example:8080"),
        (
            "PIP_EXTRA_INDEX_URL",
            "https://public.example/simple https://agent:secret@private.example/simple",
        ),
    ],
)
def test_c9_backend_subprocess_env_drops_credentials_in_any_url_token(
    monkeypatch, name, value
) -> None:
    from constitutional_swarm.swe_bench._subprocess import _subprocess_env

    monkeypatch.setenv(name, value)

    child_env = _subprocess_env()

    assert name not in child_env
    assert "agent" not in repr(child_env)
    assert "secret" not in repr(child_env)


def test_c9_backend_whitespace_patch_is_not_generated() -> None:
    from constitutional_swarm.swe_bench.harness import _patch_generation_metrics

    metrics = _patch_generation_metrics(
        [SWEPatch(task_id="whitespace", patch="  \n\t", success=False)]
    )

    assert metrics["patch_generated"] == 0
    assert metrics["patch_rate"] == 0.0
    assert metrics["resolved"] == 0
    assert metrics["resolve_rate"] == 0.0


def test_c9_backend_nul_instance_fails_before_agent_construction(monkeypatch) -> None:
    from constitutional_swarm.swe_bench import run_one_by_one

    task = {
        "instance_id": "repo__issue\x00suffix",
        "repo": "owner/repo",
        "base_commit": "deadbeef",
        "problem_statement": "fix",
        "FAIL_TO_PASS": [],
        "PASS_TO_PASS": [],
        "test_patch": "",
    }
    datasets_module = types.ModuleType("datasets")
    datasets_module.load_dataset = lambda *args, **kwargs: [task]
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)
    monkeypatch.setattr(run_one_by_one, "_attempted_winner_ids", lambda run_id: set())
    build_agent = MagicMock(side_effect=AssertionError("paid provider construction reached"))
    monkeypatch.setattr(run_one_by_one, "_build_agent", build_agent)

    with pytest.raises(ValueError, match="instance_id"):
        run_one_by_one.run_best_of_k_batch(
            run_id="run-1",
            model="model-a",
            k=1,
            dataset="dataset",
            split="test",
        )

    build_agent.assert_not_called()


def test_c9_backend_run_one_validates_instance_before_agent_construction(
    tmp_path, monkeypatch
) -> None:
    from constitutional_swarm.swe_bench import run_one_by_one

    task = {
        "instance_id": "repo__issue\x00suffix",
        "repo": "owner/repo",
        "base_commit": "deadbeef",
        "problem_statement": "fix",
        "FAIL_TO_PASS": [],
        "PASS_TO_PASS": [],
        "test_patch": "",
    }
    datasets_module = types.ModuleType("datasets")
    datasets_module.load_dataset = lambda *args, **kwargs: [task]
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)
    monkeypatch.setattr(run_one_by_one, "_DEFAULT_RUN_ROOT", tmp_path)
    build_agent = MagicMock(side_effect=AssertionError("paid provider construction reached"))
    monkeypatch.setattr(run_one_by_one, "_build_agent", build_agent)

    with pytest.raises(ValueError, match="instance_id"):
        run_one_by_one.run_one(
            run_id="run-one",
            model="model-a",
            dataset="dataset",
            split="test",
        )

    build_agent.assert_not_called()


def test_c9_backend_swarm_validates_instances_before_agent_construction(
    tmp_path, monkeypatch
) -> None:
    from constitutional_swarm.swe_bench import run_one_by_one

    task = {
        "instance_id": "repo__issue\x00suffix",
        "repo": "owner/repo",
        "base_commit": "deadbeef",
        "problem_statement": "fix",
        "FAIL_TO_PASS": [],
        "PASS_TO_PASS": [],
        "test_patch": "",
    }
    datasets_module = types.ModuleType("datasets")
    datasets_module.load_dataset = lambda *args, **kwargs: [task]
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)
    monkeypatch.setattr(run_one_by_one, "_DEFAULT_RUN_ROOT", tmp_path)
    build_agent = MagicMock(side_effect=AssertionError("paid provider construction reached"))
    monkeypatch.setattr(run_one_by_one, "_build_agent", build_agent)

    with pytest.raises(ValueError, match="instance_id"):
        run_one_by_one.run_swarm_batch(
            run_id="run-swarm",
            model="model-a",
            k=1,
            dataset="dataset",
            split="test",
        )

    build_agent.assert_not_called()


def test_c9_backend_codex_read_error_falls_back_to_stdout_stderr_is_diagnostic() -> None:
    from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

    agent = CodexSWEBenchAgent.__new__(CodexSWEBenchAgent)
    agent.model = "test-model"
    agent.sandbox = "none"
    agent.extra_args = []
    agent.codex_binary = "/usr/bin/codex"
    agent.timeout_s = 60.0
    task = {
        "instance_id": "test-3",
        "repo": "a/b",
        "base_commit": "abc",
        "FAIL_TO_PASS": [],
        "PASS_TO_PASS": [],
        "problem_statement": "Fix it",
    }
    stdout_diff = (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    proc = subprocess.CompletedProcess(
        ["codex"], 0, stdout=stdout_diff, stderr="non-fatal runner diagnostic"
    )
    last_path = MagicMock(spec=Path)
    last_path.read_text.side_effect = OSError("file gone")
    last_path.unlink.return_value = None
    temp_file = MagicMock()
    temp_file.__enter__.return_value = temp_file
    temp_file.__exit__.return_value = False
    temp_file.name = "/tmp/c9-last-message.txt"

    with (
        patch(
            "constitutional_swarm.swe_bench.codex_agent._run_process",
            return_value=proc,
        ),
        patch("constitutional_swarm.swe_bench.codex_agent.Path", return_value=last_path),
        patch(
            "constitutional_swarm.swe_bench.codex_agent.tempfile.NamedTemporaryFile",
            return_value=temp_file,
        ),
    ):
        patch_text, stats = agent._generate_patch(task)

    assert patch_text == stdout_diff
    assert stats["raw_length"] == 0
    assert stats["patch_length"] == len(stdout_diff)
    last_path.unlink.assert_called_once_with()


@pytest.mark.parametrize(
    ("bad_metadata", "expected_error"),
    [
        (None, "invalid_metadata"),
        ({"governance_status": []}, "invalid_governance_status"),
        ({"constitutional_hash": object()}, "constitutional_hash_mismatch"),
        (float("nan"), "invalid_metadata"),
        ({"governance_status": float("inf")}, "invalid_governance_status"),
        ({"constitutional_hash": float("-inf")}, "constitutional_hash_mismatch"),
    ],
)
def test_c9_runtime_coordinator_rejects_malformed_metadata_without_aborting_batch(
    bad_metadata,
    expected_error,
) -> None:
    good_first = SWEPatch(
        task_id="c9-malformed-0",
        patch="first good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )
    malformed = SWEPatch(
        task_id="c9-malformed-1",
        patch="must not escape",
        success=True,
        governed=True,
        metadata=bad_metadata,
    )
    good_last = SWEPatch(
        task_id="c9-malformed-2",
        patch="last good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )

    result = run_langgraph(
        [_C9RuntimeReviewResultAgent(good_first, malformed, good_last)],
        _c9_runtime_make_tasks(3),
    )

    accepted_before, rejected, accepted_after = result["patches"]
    assert accepted_before.patch == "first good patch"
    assert rejected.patch == ""
    assert rejected.success is False
    assert rejected.governed is False
    assert rejected.metadata["governance_status"] == "rejected"
    assert rejected.metadata["error"] == expected_error
    assert rejected.metadata["constitutional_hash"] == CONSTITUTIONAL_HASH
    json.dumps(rejected.metadata, allow_nan=False)
    assert accepted_after.patch == "last good patch"
    assert result["patch_generated"] == 2
    assert result["crdt_size"] == 3


@pytest.mark.parametrize(
    "bad_metadata",
    [
        {"constitutional_hash": "wrong", "other": object()},
        {"constitutional_hash": "wrong", "other": float("nan")},
        {"constitutional_hash": "wrong", "other": {"nested": object()}},
    ],
)
def test_c9_runtime_wrong_hash_rejection_discards_unsafe_metadata_without_aborting_batch(
    bad_metadata,
) -> None:
    good_first = SWEPatch(
        task_id="c9-wrong-hash-0",
        patch="first good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )
    malformed = SWEPatch(
        task_id="c9-wrong-hash-1",
        patch="must not escape",
        success=True,
        governed=True,
        metadata=bad_metadata,
    )
    good_last = SWEPatch(
        task_id="c9-wrong-hash-2",
        patch="last good patch",
        success=True,
        governed=True,
        metadata={"constitutional_hash": CONSTITUTIONAL_HASH},
    )

    result = run_langgraph(
        [_C9RuntimeReviewResultAgent(good_first, malformed, good_last)],
        _c9_runtime_make_tasks(3),
    )

    accepted_before, rejected, accepted_after = result["patches"]
    assert accepted_before.patch == "first good patch"
    assert rejected.patch == ""
    assert rejected.metadata == {
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "governance_status": "rejected",
        "error": "constitutional_hash_mismatch",
        "actual_constitutional_hash": "wrong",
        "expected_constitutional_hash": CONSTITUTIONAL_HASH,
    }
    json.dumps(rejected.metadata, allow_nan=False)
    assert accepted_after.patch == "last good patch"
    assert result["patch_generated"] == 2
    assert result["crdt_size"] == 3


@pytest.mark.asyncio
async def test_c9_runtime_streaming_excludes_private_accumulated_state() -> None:
    graph = _C9RuntimeReviewChunkGraph(
        [
            {
                "generate": {
                    "patch": "accepted patch",
                    "_secret": "credential-material",
                    "_h_next": [[1.0]],
                }
            },
            {
                "validate": {
                    "governed": True,
                    "risk_score": 0.0,
                    "violations": [],
                }
            },
            {"settle": {"governance_status": "accepted", "settled": True}},
        ]
    )
    crdt = _C9RuntimeCRDT()

    async for _chunk in stream_to_crdt(
        graph,
        {"task_id": "private-state", "constitutional_hash": CONSTITUTIONAL_HASH},
        crdt,
    ):
        pass

    assert len(crdt.calls) == 1
    payload = json.loads(crdt.calls[0]["payload"])
    assert "_secret" not in payload
    assert "_h_next" not in payload
    assert payload["patch"] == "accepted patch"
    assert payload["governance_status"] == "accepted"
    assert payload["settled"] is True
    assert payload["constitutional_hash"] == CONSTITUTIONAL_HASH


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        (".pytest.ini", "[pytest]\naddopts = -p attacker\n"),
        ("pytest.toml", "[pytest]\naddopts = ['-p', 'attacker']\n"),
        (".pytest.toml", "[pytest]\naddopts = ['-p', 'attacker']\n"),
        ("tests/runtests.py", "print('forged django runner')\n"),
        ("pytest.py", "print('shadowed pytest')\n"),
        ("pytest/__init__.py", "print('shadowed pytest package')\n"),
    ],
)
def test_c9_harness_rejects_candidate_runner_and_discovery_controls(
    tmp_path, relative, content
) -> None:
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    c9_harness_review_git(repo, "add", "-A")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.resolved is False
    assert result.error is not None
    assert "pytest control" in result.error or "test runner" in result.error


@pytest.mark.parametrize(
    "relative",
    [
        "_pytest.py",
        "_pytest/__init__.py",
        "pluggy.py",
        "pluggy/__init__.py",
        "iniconfig.py",
        "iniconfig/__init__.py",
        "py.py",
        "py/__init__.py",
        "pytest_flipper.py",
        "pytest_flipper/__init__.py",
    ],
)
def test_c9_harness_rejects_repo_root_pytest_dependency_shadows(
    tmp_path, relative
) -> None:
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("raise RuntimeError('shadowed pytest dependency')\n")
    c9_harness_review_git(repo, "add", "-A")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.error == f"candidate modified pytest control: {relative}"


def test_c9_harness_uses_base_runner_when_official_patch_adds_django_entry(
    tmp_path, monkeypatch
) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    selected_runners = []

    def clone(_repo, worktree, _result):
        worktree.mkdir()

    def apply_model(_worktree, _patch, result):
        result.applied = True

    def apply_official(worktree, _base, _patch, result):
        tests_dir = worktree / "tests"
        tests_dir.mkdir()
        (tests_dir / "runtests.py").write_text("# official test runner entry\n")
        result.metadata["test_patch_applied"] = True

    def run_suite(_worktree, test_ids, _python, runner):
        selected_runners.append(runner)
        return {test_id: "passed" for test_id in test_ids}, ""

    monkeypatch.setattr(harness, "_clone_to_worktree", clone)
    monkeypatch.setattr(harness, "_checkout", lambda *_args: None)
    monkeypatch.setattr(harness, "_apply_patch", apply_model)
    monkeypatch.setattr(
        harness, "_validate_candidate_test_controls", lambda *_args: None
    )
    monkeypatch.setattr(harness, "_apply_test_patch", apply_official)
    monkeypatch.setattr(harness, "_run_suite", run_suite)

    result = harness.evaluate(C9_HARNESS_INSTANCE, C9_HARNESS_MODEL_PATCH)

    assert result.resolved is True
    assert selected_runners == ["pytest", "pytest"]


@pytest.mark.parametrize(
    "output",
    [
        (
            "pkg.tests.Case.test_required ... ok\n"
            "test_required (pkg.tests.Case.test_required) ... skipped 'real skip'\n"
            "Ran 1 test in 0.01s\nOK (skipped=1)\n"
        ),
        (
            "pkg.tests.Case.test_required ... ok\n"
            "Ran 1 test in 0.01s\nOK (skipped=1)\n"
        ),
        (
            "pkg.tests.Case.test_required ... ok\n"
            "Ran 1 test in 0.01s\nFAILED (failures=0)\n"
            "Ran 1 test in 0.01s\nOK (skipped=1)\n"
        ),
    ],
)
def test_c9_harness_django_conflicting_pass_fails_closed(output) -> None:
    assert _django_test_status("pkg.tests.Case.test_required", output, 0) == "skipped"


def test_c9_harness_real_pytest_junit_denies_fake_stdout_pass_for_skip(tmp_path) -> None:
    worktree = tmp_path / "repo"
    worktree.mkdir()
    (worktree / "test_smoke.py").write_text(
        "import pytest\n\n"
        "def test_passed():\n"
        "    assert True\n\n"
        "def test_skipped():\n"
        "    print('test_smoke.py::test_skipped PASSED')\n"
        "    pytest.skip('required skip')\n"
    )
    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")

    statuses, _log = harness._pytest(
        worktree,
        ["test_smoke.py::test_passed", "test_smoke.py::test_skipped"],
        sys.executable,
    )

    assert statuses == {
        "test_smoke.py::test_passed": "passed",
        "test_smoke.py::test_skipped": "skipped",
    }


def test_c9_harness_rejects_existing_worktree_alias_before_deletion(
    tmp_path, monkeypatch
) -> None:
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness")
    victim = harness.work_dir / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel"
    sentinel.write_text("keep")
    alias = harness.work_dir / local_harness._safe_id(
        C9_HARNESS_INSTANCE["instance_id"], field_name="instance_id"
    )
    alias.symlink_to(victim, target_is_directory=True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("clone reached after unsafe worktree alias")

    monkeypatch.setattr(harness, "_clone_to_worktree", forbidden)
    result = harness.evaluate(C9_HARNESS_INSTANCE, C9_HARNESS_MODEL_PATCH)

    assert result.resolved is False
    assert "invalid instance_id" in (result.error or "")
    assert sentinel.read_text() == "keep"


def test_c9_harness_rejects_existing_venv_alias_before_deletion(
    tmp_path, monkeypatch
) -> None:
    import constitutional_swarm.swe_bench.local_harness as local_harness

    harness = LocalSWEBenchHarness(work_dir=tmp_path / "harness", env_isolation=True)
    victim = harness.env_cache_dir / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel"
    sentinel.write_text("keep")
    alias = harness.env_cache_dir / local_harness._safe_id(
        C9_HARNESS_INSTANCE["instance_id"], field_name="instance_id"
    )
    alias.symlink_to(victim, target_is_directory=True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("environment creation reached after unsafe venv alias")

    monkeypatch.setattr(local_harness, "_run", forbidden)
    with pytest.raises(ValueError, match="invalid instance_id"):
        harness._ensure_env(
            C9_HARNESS_INSTANCE["instance_id"],
            tmp_path,
            HarnessResult(C9_HARNESS_INSTANCE["instance_id"]),
        )

    assert sentinel.read_text() == "keep"


def test_c9_harness_rejects_gitignored_conftest_hidden_from_diff(tmp_path):
    """A patch(1)-applied conftest.py hidden via .gitignore must not pass the gate."""
    repo, base_tree = _c9_harness_config_repo(tmp_path)
    (repo / ".gitignore").write_text("conftest.py\n")
    (repo / "conftest.py").write_text(
        "def pytest_runtest_makereport(item, call):\n    pass\n"
    )
    # The harness stages with `git add -A`, which skips ignored files, so the
    # conftest never appears in `git diff --name-only`.
    c9_harness_review_git(repo, "add", "-A")
    staged = c9_harness_review_git(repo, "diff", "--cached", "--name-only").stdout
    assert "conftest.py\n" not in staged.replace(".gitignore", "")

    result = HarnessResult("config")
    LocalSWEBenchHarness(work_dir=tmp_path / "harness")._validate_candidate_test_controls(
        repo, base_tree, result
    )

    assert result.error is not None
    assert "git-ignored" in result.error
    assert "conftest.py" in result.error


def test_c9_apply_patch_has_no_patch1_fallback(tmp_path, monkeypatch):
    """When every git-apply strategy fails, the harness must not fall back to
    patch(1) (whose header parsing can write .git metadata); it fails closed."""
    import constitutional_swarm.swe_bench.local_harness as local_harness

    commands = []

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        return 1, "error: patch does not apply"

    monkeypatch.setattr(local_harness, "_run", fake_run)
    monkeypatch.setattr(local_harness.shutil, "which", lambda name: f"/usr/bin/{name}")
    result = HarnessResult("demo")
    LocalSWEBenchHarness(work_dir=tmp_path)._apply_patch(
        tmp_path, '--- "a/\\056git/config"\n+++ "b/\\056git/config"\n', result
    )

    assert result.applied is False
    assert result.error == "patch did not apply"
    assert commands, "git apply strategies should still be attempted"
    assert all(cmd[0] == "git" for cmd in commands)
    assert not any(cmd[0] == "patch" for cmd in commands)


def test_c9_pytest_runs_disable_plugin_autoload(tmp_path, monkeypatch):
    import constitutional_swarm.swe_bench.local_harness as local_harness

    seen_envs = []

    def fake_run(cmd, **kwargs):
        if "pytest" in cmd:
            seen_envs.append(kwargs.get("env"))
        return 1, ""

    monkeypatch.setattr(local_harness, "_run", fake_run)
    LocalSWEBenchHarness(work_dir=tmp_path)._pytest(
        tmp_path, ["tests/test_demo.py::test_x"], sys.executable
    )

    assert seen_envs
    assert all(env and env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1" for env in seen_envs)
