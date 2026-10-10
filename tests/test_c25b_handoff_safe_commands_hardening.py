"""C25b regression tests: closed safe-command set and unconditional signer hardening.

Each test is phrased as an invalid input (or unsafe state) that must be rejected.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import constitutional_swarm.governed_handoff as governed_handoff
from constitutional_swarm.governed_handoff import (
    ALLOW,
    DENY,
    PolicyEngine,
    run_local_command,
)


@pytest.fixture(autouse=True)
def _isolate_signer_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governed_handoff, "_SIGNER_CACHE_IDENTITY", None)
    monkeypatch.setattr(governed_handoff, "_SIGNER_CACHE_VALUE", None)
    monkeypatch.delenv("ACGS_SIGNING_KEY", raising=False)
    monkeypatch.delenv("ACGS_SIGNING_KEY_FILE", raising=False)


@pytest.fixture
def trusted_which(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        governed_handoff.shutil,
        "which",
        lambda name, *, path: f"/trusted/bin/{name}",
    )


def _policy(root: Path, configured: dict[str, Any] | None = None) -> PolicyEngine:
    return PolicyEngine(
        {"policy": configured or {}},
        {"roles": {"executor": {}, "observer": {}, "proposer": {}, "validator": {}}},
        root,
    )


# --- M1: closed, code-owned safe-command set -------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "split --filter=sh input",
        "split -b 1 --filter=sh input",
        "capsh --",
        "prlimit --nofile=1 true",
        "setpriv --reuid=0 true",
        "bwrap --bind / / true",
        "timeout 1 true",
        "nice true",
        "stdbuf -o0 true",
        "cat file",
        "custom-check",
    ],
)
def test_configured_executable_outside_safe_set_is_denied(
    tmp_path: Path, trusted_which: None, command: str
) -> None:
    executable = command.split()[0]
    engine = _policy(tmp_path, {"command_allowlist": [executable, "true", "echo"]})

    decision = engine.decide("tool_call", command)

    assert decision.outcome == DENY
    assert "safe-command" in decision.reason


@pytest.mark.parametrize(
    "command",
    [
        "true --version",
        "true extra",
        "echo --version",
        "echo --help",
        "echo -e x",
        "echo -n x",
        "echo --opt=value",
        "echo /etc/passwd",
        r'echo "tools\x"',
        "echo ''",
        "echo " + "a" * 257,
        "echo " + " ".join(["a"] * 65),
    ],
)
def test_safe_command_with_unlisted_argument_shape_is_denied(
    tmp_path: Path, trusted_which: None, command: str
) -> None:
    decision = _policy(tmp_path).decide("tool_call", command)

    assert decision.outcome == DENY
    assert "argument" in decision.reason


@pytest.mark.parametrize("command", ["true", "echo ok", "echo hello-world v1.2 a=b"])
def test_safe_set_still_allows_existing_workflows(
    tmp_path: Path, trusted_which: None, command: str
) -> None:
    assert _policy(tmp_path).decide("tool_call", command).outcome == ALLOW


def test_configuration_can_narrow_but_never_add(
    tmp_path: Path, trusted_which: None
) -> None:
    engine = _policy(tmp_path, {"command_allowlist": ["true", "split", "custom-check"]})

    assert engine.command_allowlist == {"true"}
    assert engine.decide("tool_call", "true").outcome == ALLOW
    assert engine.decide("tool_call", "echo ok").outcome == DENY
    assert engine.decide("tool_call", "split --filter=sh x").outcome == DENY


def test_empty_configured_selection_denies_every_command(
    tmp_path: Path, trusted_which: None
) -> None:
    engine = _policy(tmp_path, {"command_allowlist": []})

    assert engine.command_allowlist == set()
    assert engine.decide("tool_call", "true").outcome == DENY


@pytest.mark.parametrize("configured", ["true echo", {"true": 1}, 1])
def test_malformed_configured_selection_fails_closed(
    tmp_path: Path, trusted_which: None, configured: object
) -> None:
    engine = _policy(tmp_path, {"command_allowlist": configured})

    assert engine.command_allowlist == set()
    assert engine.decide("tool_call", "true").outcome == DENY


def test_safe_command_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        governed_handoff.SAFE_COMMANDS["split"] = governed_handoff.SAFE_COMMANDS[  # type: ignore[index]
            "true"
        ]


def test_direct_local_command_cannot_add_executables(
    tmp_path: Path, trusted_which: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        governed_handoff.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("unsafe command reached subprocess"),
    )

    for command in ("split --filter=sh x", "echo --version", "env true"):
        with pytest.raises(ValueError):
            run_local_command(
                command, cwd=tmp_path, command_allowlist={command.split()[0], "echo"}
            )


# --- L1: exact-name matching, no version-suffix pattern gaps ----------------------


@pytest.mark.parametrize(
    "command",
    ["ruby3.3 -e x", "node22 -e x", "perl5.38 -e x", "python3.13 -c x", "pip3.13 x"],
)
def test_version_suffixed_executable_is_denied(
    tmp_path: Path, trusted_which: None, command: str
) -> None:
    engine = _policy(tmp_path, {"command_allowlist": [command.split()[0]]})

    assert engine.decide("tool_call", command).outcome == DENY


# --- L2: hardening before every governed launch, signer or not ------------------


def test_unsigned_local_launch_hardens_supervisor_first(
    tmp_path: Path, trusted_which: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    sequence: list[str] = []
    monkeypatch.setattr(
        governed_handoff, "_mark_process_non_dumpable", lambda: sequence.append("prctl")
    )

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        sequence.append("child")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(governed_handoff.subprocess, "run", fake_run)

    run_local_command("true", cwd=tmp_path)

    assert sequence == ["prctl", "child"]


def test_unsigned_launch_fails_closed_when_hardening_fails(
    tmp_path: Path, trusted_which: None, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        run_local_command("true", cwd=tmp_path)


# --- L3: PR_GET_DUMPABLE read-back ----------------------------------------------


def test_dumpable_state_not_cleared_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, ...]] = []

    class SilentlyIgnoredPrctl:
        argtypes: list[object] = []
        restype: object = None

        def __call__(self, *args: int) -> int:
            calls.append(args)
            return 0 if args[0] == 4 else 1  # SET "succeeds", GET still reports 1

    monkeypatch.setattr(governed_handoff.sys, "platform", "linux")
    monkeypatch.setattr(
        governed_handoff.ctypes,
        "CDLL",
        lambda name, *, use_errno: SimpleNamespace(prctl=SilentlyIgnoredPrctl()),
    )

    with pytest.raises(OSError, match="PR_GET_DUMPABLE"):
        governed_handoff._mark_process_non_dumpable()
    assert calls == [(4, 0, 0, 0, 0), (3, 0, 0, 0, 0)]


# --- Real kernel: child cannot read the hardened supervisor's environ -------------

_SUPERVISOR = textwrap.dedent(
    """
    import os, subprocess, sys
    import constitutional_swarm.governed_handoff as gh

    probe = [
        sys.executable,
        "-c",
        "import os\\n"
        "try:\\n"
        "    data = open(f'/proc/{os.getppid()}/environ', 'rb').read()\\n"
        "    print('READ' if b'canary-value' in data else 'MISSING')\\n"
        "except OSError as exc:\\n"
        "    print('DENIED', exc.errno)\\n",
    ]

    def run_probe():
        return subprocess.run(probe, capture_output=True, text=True, check=True).stdout.strip()

    print("before", run_probe())
    gh._secure_signer_process()
    print("after", run_probe())
    """
)


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not os.path.isdir("/proc/self"),
    reason="Linux procfs and prctl required",
)
def test_real_kernel_child_cannot_read_hardened_supervisor_environ(
    tmp_path: Path,
) -> None:
    # Runs the real (unstubbed) hardening in a fresh interpreter so the pytest
    # worker itself is never made non-dumpable.
    source_root = Path(governed_handoff.__file__).resolve().parents[1]
    environment = {
        "PATH": os.environ.get("PATH", governed_handoff.FIXED_SUBPROCESS_PATH),
        "PYTHONPATH": str(source_root),
        # /proc/<pid>/environ exposes the exec-time environment, so the canary
        # must be present when the supervisor starts.
        "C25B_CANARY": "canary-value",
    }
    completed = subprocess.run(
        [sys.executable, "-c", _SUPERVISOR],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=environment,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()

    assert lines[0] == "before READ"  # negative control: unhardened supervisor is readable
    assert lines[1] == "after DENIED 13"
