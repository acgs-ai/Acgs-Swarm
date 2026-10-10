from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import constitutional_swarm.governed_handoff as governed_handoff
from constitutional_swarm.governed_handoff import (
    ALLOW,
    DENY,
    AuditLogger,
    ExternalAgentAdapter,
    PolicyEngine,
    TaskSpec,
    _load_bundle_signer,
    main,
    pack_task,
    run_local_command,
    run_task,
    verify_bundle,
)


@pytest.fixture(autouse=True)
def _isolate_signer_state(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Keep signer-cache and process-hardening assertions local to each test."""

    monkeypatch.setattr(governed_handoff, "_SIGNER_CACHE_IDENTITY", None, raising=False)
    monkeypatch.setattr(governed_handoff, "_SIGNER_CACHE_VALUE", None, raising=False)
    if not request.node.name.startswith("test_process_hardening_syscall"):
        monkeypatch.setattr(
            governed_handoff, "_mark_process_non_dumpable", lambda: None, raising=False
        )


def _write_configs(root: Path, *, policy: str = "") -> None:
    acgs = root / ".acgs"
    acgs.mkdir()
    (acgs / "constitution.yaml").write_text(
        "schema_version: 1\n" + ("policy:\n" + policy if policy else "policy: {}\n"),
        encoding="utf-8",
    )
    (acgs / "swarm.yaml").write_text(
        """schema_version: 1
roles:
  proposer: {adapter: mock}
  executor: {adapter: mock}
  validator: {adapter: mock}
  observer: {adapter: mock}
adapters:
  mock: {}
""",
        encoding="utf-8",
    )


def _task(root: Path, task_id: str, *directives: str) -> Path:
    path = root / f"{task_id}.md"
    path.write_text(
        "\n".join((f"task_id: {task_id}", *directives)),
        encoding="utf-8",
    )
    return path


def _policy(root: Path, configured: dict[str, Any] | None = None) -> PolicyEngine:
    return PolicyEngine(
        {"policy": configured or {}},
        {"roles": {"executor": {}, "observer": {}, "proposer": {}, "validator": {}}},
        root,
    )


def test_external_adapter_receives_minimal_environment_without_signing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured.update({"argv": argv, **kwargs})
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setenv("ACGS_SIGNING_KEY_ID", "private-id")
    monkeypatch.setenv("UNRELATED_CREDENTIAL", "private-value")
    monkeypatch.setenv("PATH", "/untrusted/bin")
    task = TaskSpec("env", tmp_path / "task.md", "", {})

    ExternalAgentAdapter(name="codex", command="echo").propose_actions(task)

    child_env = captured["env"]
    assert child_env["PATH"] == governed_handoff.FIXED_SUBPROCESS_PATH
    assert not any(name.startswith("ACGS_SIGNING_") for name in child_env)
    assert "UNRELATED_CREDENTIAL" not in child_env


def test_direct_external_adapter_hardens_before_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sequence: list[str] = []
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: sequence.append("prctl"),
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        sequence.append("child")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)

    ExternalAgentAdapter(name="codex", command="echo").propose_actions(
        TaskSpec("direct-adapter", tmp_path / "task.md", "", {})
    )

    assert sequence == ["prctl", "child"]


def test_local_command_uses_the_same_fixed_path_resolver_and_scrubbed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_which(name: str, *, path: str) -> str | None:
        assert path == governed_handoff.FIXED_SUBPROCESS_PATH
        return "/trusted/bin/echo" if name == "echo" else None

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured.update({"argv": argv, **kwargs})
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(governed_handoff.shutil, "which", fake_which)
    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setenv("PATH", "/untrusted/bin")

    result = run_local_command(
        "echo ok", cwd=tmp_path, command_allowlist={"echo"}
    )

    assert captured["argv"] == ["/trusted/bin/echo", "ok"]
    assert captured["env"]["PATH"] == governed_handoff.FIXED_SUBPROCESS_PATH
    assert "ACGS_SIGNING_KEY" not in captured["env"]
    assert result["argv"] == ["/trusted/bin/echo", "ok"]


def test_direct_local_command_hardens_before_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sequence: list[str] = []
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: sequence.append("prctl"),
    )
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        sequence.append("child")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)

    run_local_command("true", cwd=tmp_path)

    assert sequence == ["prctl", "child"]


@pytest.mark.parametrize("boundary", ["adapter", "local"])
def test_direct_subprocess_boundaries_fail_closed_before_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: (_ for _ in ()).throw(OSError("prctl denied")),
    )
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("child launched after hardening failure"),
    )

    with pytest.raises(RuntimeError, match="cannot secure supervisor process"):
        if boundary == "adapter":
            ExternalAgentAdapter(name="codex", command="echo").propose_actions(
                TaskSpec("direct-adapter", tmp_path / "task.md", "", {})
            )
        else:
            run_local_command("true", cwd=tmp_path)


def test_cached_signer_memory_remains_protected_after_configuration_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    _load_bundle_signer()
    monkeypatch.delenv("ACGS_SIGNING_KEY")
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: (_ for _ in ()).throw(OSError("prctl denied")),
    )
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("child launched with unprotected cached signer"),
    )

    with pytest.raises(RuntimeError, match="cannot secure supervisor process"):
        run_local_command("true", cwd=tmp_path)


@pytest.mark.parametrize("command", ["./echo ok", "make target", "missing-command"])
def test_local_command_revalidates_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("invalid command reached subprocess"),
    )
    monkeypatch.setattr(governed_handoff.shutil, "which", lambda *args, **kwargs: None)

    with pytest.raises(ValueError):
        run_local_command(
            command,
            cwd=tmp_path,
            command_allowlist={command.split()[0]},
        )


def test_run_task_dispatches_tool_and_test_through_resolved_scrubbed_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    task = _task(
        tmp_path,
        "dispatch-boundary",
        "ACGS_TOOL echo tool",
        "ACGS_TEST echo test",
    )
    launched: list[tuple[list[str], dict[str, str]]] = []

    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: "/trusted/bin/echo" if name == "echo" else None,
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        launched.append((argv, kwargs["env"]))
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setenv("ACGS_SIGNING_KEY_ID", "private-id")
    monkeypatch.setenv("UNRELATED_CREDENTIAL", "private-value")

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "handoff_ready"
    assert [argv for argv, _ in launched] == [
        ["/trusted/bin/echo", "tool"],
        ["/trusted/bin/echo", "test"],
    ]
    assert all(
        environment["PATH"] == governed_handoff.FIXED_SUBPROCESS_PATH
        and not any(name.startswith("ACGS_SIGNING_") for name in environment)
        and "UNRELATED_CREDENTIAL" not in environment
        for _, environment in launched
    )


@pytest.mark.parametrize(
    "command",
    [
        "./echo ok",
        "/bin/echo ok",
        r"tools\echo ok",
        "make target",
        "gmake target",
        "xargs echo",
        "timeout 1 true",
        "nice true",
        "nohup true",
        "find .",
        "git status",
        "awk 1 file",
        "gawk 1 file",
        "mawk 1 file",
        "sed -n 1p file",
        "pip install thing",
        "pip3 install thing",
        "pip3.12 install thing",
        "sudo true",
        "doas true",
        "busybox true",
        "java Main",
        "javac Main.java",
        "stdbuf -o0 true",
        "setsid true",
        "flock lockfile true",
        "chrt 1 true",
        "taskset 1 true",
        "ionice true",
        "nsenter true",
        "unshare true",
        "chroot / true",
        "strace true",
        "ltrace true",
        "gdb true",
        "tar --checkpoint-action=exec=sh archive.tar",
        "ssh host true",
        "scp source destination",
        "rsync source destination",
        "zip archive.zip file",
        "unzip archive.zip",
        "vim file",
        "vi file",
        "nvim file",
        "ed file",
        "ex file",
        "less file",
        "more file",
        "man true",
        "watch true",
        "systemd-run true",
        "su user",
        "pkexec true",
        "runuser user",
        "npm run task",
        "pnpm run task",
        "yarn run task",
        "go run file.go",
        "gcc file.c",
        "cc file.c",
        "clang file.c",
        "cmake .",
        "ninja target",
        "meson setup build",
        "ctest",
        "docker run image",
        "podman run image",
        "nix run package",
        "toolbox run true",
        "tclsh script.tcl",
        "sqlite3 database",
    ],
)
def test_rejects_path_qualified_and_launcher_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    executable = command.split()[0]
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )
    engine = _policy(tmp_path, {"command_allowlist": [executable]})

    decision = engine.decide("tool_call", command)

    assert decision.outcome == DENY


@pytest.mark.parametrize(
    "command",
    [
        "echo /usr/bin/PYTHON3",
        r'echo "tools\StDbUf"',
        "echo --command=/usr/bin/timeout",
    ],
)
def test_rejects_denied_command_names_in_later_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )

    decision = _policy(tmp_path).decide("tool_call", command)

    assert decision.outcome == DENY


@pytest.mark.parametrize("command", ["echo ok", "true"])
def test_allows_inert_default_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )

    assert _policy(tmp_path).decide("tool_call", command).outcome == ALLOW


def test_configured_allowlist_selects_safe_commands_but_cannot_add_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # C25b: command_allowlist narrows the closed SAFE_COMMANDS table; unknown
    # names (custom or denied) are never added.
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )
    engine = _policy(
        tmp_path,
        {"command_allowlist": ["true", "custom-check", "make"]},
    )

    assert engine.command_allowlist == {"true"}
    assert engine.decide("tool_call", "true").outcome == ALLOW
    assert engine.decide("tool_call", "echo ok").outcome == DENY
    assert engine.decide("tool_call", "custom-check").outcome == DENY
    assert engine.decide("tool_call", "make").outcome == DENY


@pytest.mark.parametrize(
    ("configured", "command"),
    [
        ([], "cat .env"),
        ([r"private-marker"], "cat .env"),
        ([r"private-marker"], "echo private-marker"),
    ],
)
def test_secret_command_patterns_are_extend_only(
    tmp_path: Path, configured: list[str], command: str
) -> None:
    engine = _policy(
        tmp_path,
        {
            "command_allowlist": ["cat"],
            "secret_command_patterns": configured,
        },
    )

    decision = engine.decide("tool_call", command)

    assert decision.outcome == DENY
    assert decision.reason == "secret-reading command denied"


def test_inline_signing_key_is_reusable_and_malformed_values_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)

    first = _load_bundle_signer()
    second = _load_bundle_signer()

    assert first is not None
    assert second is first
    assert os.environ["ACGS_SIGNING_KEY"] == "ab" * 32

    for malformed in (
        "",
        "00",
        "not-hex",
        " " + "ab" * 32,
        "ab" * 16 + " " + "ab" * 16,
    ):
        monkeypatch.setenv("ACGS_SIGNING_KEY", malformed)
        with pytest.raises(ValueError, match="ACGS_SIGNING_KEY"):
            _load_bundle_signer()


def test_signer_hardens_process_on_cache_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    hardening_calls: list[str] = []
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: hardening_calls.append("prctl"),
    )
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)

    first = _load_bundle_signer()
    second = _load_bundle_signer()

    assert second is first
    assert hardening_calls == ["prctl", "prctl"]


def test_process_hardening_syscall_uses_prctl_abi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int, int, int]] = []

    class FakePrctl:
        argtypes: list[object] = []
        restype: object = None

        def __call__(self, *args: int) -> int:
            calls.append(args)
            return 0

    fake_prctl = FakePrctl()
    monkeypatch.setattr(governed_handoff.sys, "platform", "linux")
    monkeypatch.setattr(
        governed_handoff.ctypes,
        "CDLL",
        lambda name, *, use_errno: SimpleNamespace(prctl=fake_prctl),
    )

    governed_handoff._mark_process_non_dumpable()

    # C25b (L3): PR_SET_DUMPABLE is followed by a PR_GET_DUMPABLE read-back.
    assert calls == [(4, 0, 0, 0, 0), (3, 0, 0, 0, 0)]
    assert fake_prctl.argtypes == [
        governed_handoff.ctypes.c_int,
        governed_handoff.ctypes.c_ulong,
        governed_handoff.ctypes.c_ulong,
        governed_handoff.ctypes.c_ulong,
        governed_handoff.ctypes.c_ulong,
    ]
    assert fake_prctl.restype is governed_handoff.ctypes.c_int


def test_process_hardening_syscall_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPrctl:
        argtypes: list[object] = []
        restype: object = None

        def __call__(self, *args: int) -> int:
            return -1

    monkeypatch.setattr(governed_handoff.sys, "platform", "linux")
    monkeypatch.setattr(
        governed_handoff.ctypes,
        "CDLL",
        lambda name, *, use_errno: SimpleNamespace(prctl=FailingPrctl()),
    )
    monkeypatch.setattr(governed_handoff.ctypes, "get_errno", lambda: 1)

    with pytest.raises(OSError, match="Operation not permitted"):
        governed_handoff._mark_process_non_dumpable()


def test_process_hardening_syscall_is_noop_off_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(governed_handoff.sys, "platform", "darwin")
    monkeypatch.setattr(
        governed_handoff.ctypes,
        "CDLL",
        lambda *args, **kwargs: pytest.fail("prctl loaded off Linux"),
    )

    governed_handoff._mark_process_non_dumpable()


def test_signer_cache_identity_tracks_key_id_and_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    first = _load_bundle_signer()
    assert _load_bundle_signer() is first

    monkeypatch.setenv("ACGS_SIGNING_KEY_ID", "rotated-id")
    changed_id = _load_bundle_signer()
    assert changed_id is not first
    assert changed_id is not None and changed_id.key_id == "rotated-id"

    monkeypatch.setenv("ACGS_SIGNING_KEY", "cd" * 32)
    assert _load_bundle_signer() is not changed_id


def test_process_hardening_failure_prevents_child_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    task = _task(tmp_path, "hardening-failure", "ACGS_TEST true")
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: (_ for _ in ()).throw(OSError("prctl denied")),
    )
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("child launched after hardening failure"),
    )

    with pytest.raises(RuntimeError, match="cannot secure supervisor process"):
        run_task(task, repo_root=tmp_path)

    evidence = tmp_path / ".acgs" / "evidence"
    assert not evidence.exists() or list(evidence.iterdir()) == []


def test_process_hardening_precedes_child_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    task = _task(tmp_path, "hardening-order", "ACGS_TEST true")
    sequence: list[str] = []
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: sequence.append("prctl"),
    )
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        sequence.append("child")
        assert not any(name.startswith("ACGS_SIGNING_") for name in kwargs["env"])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)

    run_task(task, repo_root=tmp_path)

    assert sequence == ["prctl", "prctl", "child"]


def test_process_hardening_precedes_external_adapter_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    (tmp_path / ".acgs/swarm.yaml").write_text(
        """schema_version: 1
roles:
  proposer: {adapter: mock}
  executor: {adapter: codex}
  validator: {adapter: mock}
  observer: {adapter: mock}
adapters:
  codex: {command: echo}
""",
        encoding="utf-8",
    )
    task = _task(tmp_path, "external-order")
    sequence: list[str] = []
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.setattr(
        governed_handoff,
        "_mark_process_non_dumpable",
        lambda: sequence.append("prctl"),
    )
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        sequence.append("adapter" if str(task) in argv else "test")
        assert not any(name.startswith("ACGS_SIGNING_") for name in kwargs["env"])
        stdout = "ACGS_TEST true\n" if sequence[-1] == "adapter" else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)

    run_task(task, repo_root=tmp_path)

    assert sequence == ["prctl", "prctl", "adapter", "prctl", "test"]


def test_signing_key_file_is_preferred_and_accepts_one_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "signing-key"
    key_file.write_bytes(("ab" * 32 + "\n").encode())
    key_file.chmod(0o600)
    monkeypatch.setenv("ACGS_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("ACGS_SIGNING_KEY", "malformed-inline-value")

    assert _load_bundle_signer() is not None


@pytest.mark.parametrize("payload", [b"", b"ab", b"ab" * 32 + b"\n\n", b"gg" * 32])
def test_signing_key_file_rejects_malformed_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    key_file = tmp_path / "signing-key"
    key_file.write_bytes(payload)
    key_file.chmod(0o600)
    monkeypatch.setenv("ACGS_SIGNING_KEY_FILE", str(key_file))

    with pytest.raises(ValueError, match="ACGS_SIGNING_KEY_FILE"):
        _load_bundle_signer()


@pytest.mark.parametrize(
    "unsafe_kind", ["public", "symlink", "hardlink", "directory", "missing"]
)
def test_signing_key_file_rejects_unsafe_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_kind: str
) -> None:
    target = tmp_path / "target"
    target.write_text("ab" * 32, encoding="ascii")
    target.chmod(0o600)
    key_file = target
    if unsafe_kind == "public":
        target.chmod(0o644)
    elif unsafe_kind == "symlink":
        key_file = tmp_path / "link"
        key_file.symlink_to(target)
    elif unsafe_kind == "hardlink":
        key_file = tmp_path / "hardlink"
        os.link(target, key_file)
    elif unsafe_kind == "directory":
        key_file = tmp_path / "key-directory"
        key_file.mkdir()
    elif unsafe_kind == "missing":
        key_file = tmp_path / "missing"
    monkeypatch.setenv("ACGS_SIGNING_KEY_FILE", str(key_file))

    with pytest.raises(ValueError, match="ACGS_SIGNING_KEY_FILE"):
        _load_bundle_signer()


def test_signing_key_file_rejects_other_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    key_file = tmp_path / "signing-key"
    key_file.write_text("ab" * 32, encoding="ascii")
    key_file.chmod(0o600)
    monkeypatch.setenv("ACGS_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setattr(secure_files.os, "geteuid", lambda: os.stat(key_file).st_uid + 1)

    with pytest.raises(ValueError, match="ACGS_SIGNING_KEY_FILE"):
        _load_bundle_signer()


def test_second_run_in_same_process_remains_signed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)

    first = run_task(
        _task(tmp_path, "signed-first", "ACGS_TEST true"), repo_root=tmp_path
    )
    second = run_task(
        _task(tmp_path, "signed-second", "ACGS_TEST true"), repo_root=tmp_path
    )

    assert first.signed is True
    assert second.signed is True


def test_malformed_signing_key_is_rejected_before_evidence_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    task = _task(tmp_path, "bad-signer", "ACGS_TEST true")
    monkeypatch.setenv("ACGS_SIGNING_KEY", " ")

    with pytest.raises(ValueError, match="ACGS_SIGNING_KEY"):
        run_task(task, repo_root=tmp_path)

    evidence = tmp_path / ".acgs" / "evidence"
    assert not evidence.exists() or list(evidence.iterdir()) == []


def test_cli_run_reports_the_signer_used_for_the_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_configs(tmp_path)
    task = _task(tmp_path, "signed-cli", "ACGS_TEST true")
    monkeypatch.setenv("ACGS_SIGNING_KEY", "ab" * 32)
    monkeypatch.chdir(tmp_path)

    assert main(["run", "--task", str(task)]) == 0

    output = json.loads(capsys.readouterr().out)
    bundle = json.loads(Path(output["bundle_path"]).read_text(encoding="utf-8"))
    assert output["signed"] is True
    assert bundle["signature"]["alg"] == "ed25519"


@pytest.mark.parametrize("collision", ["audit", "bundle"])
def test_run_rejects_existing_evidence_before_actions_and_preserves_it(
    tmp_path: Path, collision: str
) -> None:
    _write_configs(tmp_path)
    task = _task(
        tmp_path,
        f"existing-{collision}",
        "ACGS_WRITE output.txt :: changed",
        "ACGS_TEST true",
    )
    evidence = tmp_path / ".acgs" / "evidence"
    evidence.mkdir()
    existing = evidence / f"existing-{collision}.{collision}.jsonl"
    if collision == "bundle":
        existing = evidence / "existing-bundle.bundle.json"
    original = b"preserve-existing-evidence\n"
    existing.write_bytes(original)

    with pytest.raises(FileExistsError):
        run_task(task, repo_root=tmp_path)

    assert existing.read_bytes() == original
    assert not (tmp_path / "output.txt").exists()


def test_run_fails_closed_when_bundle_collision_is_injected_at_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    task = _task(
        tmp_path,
        "claim-race",
        "ACGS_WRITE output.txt :: changed",
        "ACGS_TEST true",
    )
    real_open = governed_handoff.os.open

    def collide_on_bundle(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if str(path).endswith("claim-race.bundle.json") and flags & os.O_EXCL:
            raise FileExistsError(path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(governed_handoff.os, "open", collide_on_bundle)

    with pytest.raises(FileExistsError):
        run_task(task, repo_root=tmp_path)

    assert not (tmp_path / "output.txt").exists()


def test_audit_logger_keeps_writing_to_the_exclusively_claimed_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, "stable-audit")
    logger.emit("observer", "first", {})
    claimed = tmp_path / "claimed.jsonl"
    path.rename(claimed)
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text("replacement\n", encoding="utf-8")
    path.symlink_to(replacement)

    logger.emit("observer", "second", {})
    assert [event["event_type"] for event in logger.read_events()] == [
        "first",
        "second",
    ]
    logger.close()

    assert replacement.read_text(encoding="utf-8") == "replacement\n"
    assert [event["event_type"] for event in governed_handoff.read_audit(claimed)] == [
        "first",
        "second",
    ]


def test_audit_logger_refuses_an_existing_path(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        AuditLogger(path, "collision")

    assert path.read_bytes() == b"preserve\n"


def test_pack_signs_when_configured_and_refuses_to_replace_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_configs(tmp_path)
    result = run_task(
        _task(tmp_path, "pack-signed", "ACGS_TEST true"), repo_root=tmp_path
    )
    result.bundle_path.unlink()
    seed = bytes.fromhex("ab" * 32)
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    monkeypatch.setenv("ACGS_SIGNING_KEY", seed.hex())

    bundle = pack_task("pack-signed", acgs_dir=tmp_path / ".acgs")

    assert bundle["signature"]["alg"] == "ed25519"
    assert verify_bundle(
        result.bundle_path,
        trusted_public_keys={
            "acgs-supervisor": public_key.public_bytes_raw().hex(),
        },
    )["ok"] is True
    assert os.environ["ACGS_SIGNING_KEY"] == seed.hex()
    preserved = result.bundle_path.read_bytes()
    with pytest.raises(FileExistsError):
        pack_task("pack-signed", acgs_dir=tmp_path / ".acgs")
    assert result.bundle_path.read_bytes() == preserved
    result.bundle_path.unlink()
    monkeypatch.chdir(tmp_path)
    assert main(["pack", "--task", "pack-signed"]) == 0
    assert json.loads(capsys.readouterr().out)["signed"] is True
    assert verify_bundle(
        Path(".acgs/evidence/pack-signed.bundle.json"),
        trusted_public_keys={
            "acgs-supervisor": public_key.public_bytes_raw().hex(),
        },
    )["ok"] is True


def test_pack_rejects_audit_copied_from_a_different_task(tmp_path: Path) -> None:
    _write_configs(tmp_path)
    result = run_task(
        _task(tmp_path, "original-task", "ACGS_TEST true"), repo_root=tmp_path
    )
    copied_audit = tmp_path / ".acgs/evidence/copied-task.audit.jsonl"
    copied_audit.write_bytes(result.audit_path.read_bytes())

    with pytest.raises(ValueError, match="task id"):
        pack_task("copied-task", acgs_dir=tmp_path / ".acgs")

    assert not (tmp_path / ".acgs/evidence/copied-task.bundle.json").exists()


def test_pack_uses_one_frozen_audit_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_configs(tmp_path)
    result = run_task(
        _task(tmp_path, "single-read", "ACGS_TEST true"), repo_root=tmp_path
    )
    result.bundle_path.unlink()
    real_read_audit = governed_handoff.read_audit
    read_count = 0

    def counted_read(path: Path) -> list[dict[str, Any]]:
        nonlocal read_count
        read_count += 1
        return real_read_audit(path)

    monkeypatch.setattr(governed_handoff, "read_audit", counted_read)

    pack_task("single-read", acgs_dir=tmp_path / ".acgs")

    assert read_count == 1


@pytest.mark.parametrize("task_id", ["", ".", "..", "../escape", "nested/task", "/abs"])
def test_pack_rejects_invalid_task_ids_before_path_construction(
    tmp_path: Path, task_id: str
) -> None:
    acgs_dir = tmp_path / ".acgs"
    acgs_dir.mkdir()

    with pytest.raises(ValueError, match="task id"):
        pack_task(task_id, acgs_dir=acgs_dir)
