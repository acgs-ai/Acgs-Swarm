"""Behavioral regressions for deterministic infrastructure and hermetic test gates."""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from tests import test_core_import_isolation


REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = REPO_ROOT / "Makefile"
ENV_ERROR = "ERROR: project environment is missing or stale; run make setup"


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _fake_path_tools(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    marker = tmp_path / "path-tool-ran.log"
    fake_bin = tmp_path / "fake-path-bin"
    for tool in ("uv", "ruff", "pytest", "mypy", "python"):
        _write_executable(
            fake_bin / tool,
            f'printf "%s\\n" "{tool} $*" >> "{marker}"\nexit 0\n',
        )
    env = os.environ.copy()
    for name in ("EXTRAS", "MAKEFLAGS", "MAKELEVEL", "MFLAGS", "PYTHONPATH", "SYNC_FLAGS", "UV"):
        env.pop(name, None)
    env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
    return fake_bin, marker, env


def _run_make(
    tmp_path: Path,
    target: str,
    env: dict[str, str],
    *assignments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "-f", str(MAKEFILE), target, *assignments],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _create_fake_project_venv(
    tmp_path: Path,
    marker: Path,
    *,
    symlinks: bool = False,
) -> Path:
    venv.EnvBuilder(with_pip=False, symlinks=symlinks).create(tmp_path / ".venv")
    venv_bin = tmp_path / ".venv" / "bin"
    for tool in ("pytest", "mypy", "ruff"):
        _write_executable(
            venv_bin / tool,
            f'printf "%s\\n" "{tool} $*" >> "{marker}"\nexit 0\n',
        )
    for tool in ("acgs-swarm", "acgs-verify-receipts", "acgs-agent-self-evolve"):
        env_name = f"{tool.upper().replace('-', '_')}_EXIT"
        _write_executable(
            venv_bin / tool,
            f'printf "%s\\n" "{tool} $*" >> "{marker}"\nexit "${{{env_name}:-0}}"\n',
        )

    purelib_result = subprocess.run(
        [
            str(venv_bin / "python"),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    package = Path(purelib_result.stdout.strip()) / "constitutional_swarm"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    pytest_package = Path(purelib_result.stdout.strip()) / "pytest"
    pytest_package.mkdir()
    (pytest_package / "__init__.py").write_text("", encoding="utf-8")
    (pytest_package / "__main__.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).open('a', encoding='utf-8').write("
        "'pytest ' + ' '.join(__import__('sys').argv[1:]) + '\\n')\n",
        encoding="utf-8",
    )
    return venv_bin


def _record_installed_extras(tmp_path: Path, extras: str = "dev transport") -> None:
    (tmp_path / ".venv" / ".make-extras").write_text(
        " ".join(sorted(extras.split())) + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("venv_state", ["missing", "empty"])
def test_make_gate_rejects_missing_or_empty_project_environment(
    tmp_path: Path,
    venv_state: str,
) -> None:
    if venv_state == "empty":
        (tmp_path / ".venv" / "bin").mkdir(parents=True)
    _, marker, env = _fake_path_tools(tmp_path)

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode != 0
    assert ENV_ERROR in result.stdout + result.stderr
    assert not marker.exists(), "Make fell through to a PATH-resolved tool"


def test_make_gate_rejects_stale_environment_and_displays_uv_diagnostics(tmp_path: Path) -> None:
    fake_bin, path_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)
    _write_executable(
        fake_bin / "uv",
        f'printf "%s\\n" "uv $*" >> "{path_marker}"\n'
        'echo "cache directory permission denied" >&2\nexit 7\n',
    )

    result = _run_make(tmp_path, "lint", env)

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "cache directory permission denied" in output
    assert ENV_ERROR in output
    assert "uv sync --check --locked" in path_marker.read_text(encoding="utf-8")
    assert not local_marker.exists(), "lint ran even though the environment was stale"


def test_make_gate_accepts_locked_project_environment_and_runs_local_lint(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "uv sync --check --locked" in uv_marker.read_text(encoding="utf-8")
    assert local_marker.read_text(encoding="utf-8").startswith("ruff check ")


def test_make_gate_rejects_project_tool_resolving_outside_venv(tmp_path: Path) -> None:
    fake_bin, path_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    venv_bin = _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)
    tool_path = venv_bin / "ruff"
    tool_path.unlink()
    tool_path.symlink_to(fake_bin / "ruff")

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode != 0
    assert ENV_ERROR in result.stdout + result.stderr
    if path_marker.exists():
        assert not any(
            line.startswith("uv ") for line in path_marker.read_text(encoding="utf-8").splitlines()
        )
    assert not local_marker.exists(), "lint ran with an external project tool"


def test_make_gate_rejects_non_venv_python_wrapper(tmp_path: Path) -> None:
    _, path_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    venv_bin = _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)
    _write_executable(venv_bin / "python", f'exec "{sys.executable}" "$@"\n')

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode != 0
    assert ENV_ERROR in result.stdout + result.stderr
    if path_marker.exists():
        assert not any(
            line.startswith("uv ") for line in path_marker.read_text(encoding="utf-8").splitlines()
        )
    assert not local_marker.exists(), "lint ran with a non-venv interpreter"


def test_make_gate_accepts_standard_venv_python_symlink(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker, symlinks=True)
    _record_installed_extras(tmp_path)

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "uv sync --check --locked" in uv_marker.read_text(encoding="utf-8")
    assert local_marker.read_text(encoding="utf-8").startswith("ruff check ")


def test_make_gate_does_not_depend_on_gnu_realpath(tmp_path: Path) -> None:
    fake_bin, _, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)
    _write_executable(fake_bin / "realpath", 'echo "GNU realpath unavailable" >&2\nexit 91\n')

    result = _run_make(tmp_path, "lint", env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert local_marker.read_text(encoding="utf-8").startswith("ruff check ")


def test_make_setup_persists_sorted_extras_after_success(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)

    result = _run_make(tmp_path, "setup", env, "EXTRAS=dev transport research")

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / ".venv" / ".make-extras").read_text(encoding="utf-8") == (
        "dev research transport\n"
    )
    uv_call = uv_marker.read_text(encoding="utf-8")
    assert "uv sync --locked" in uv_call
    for extra in ("dev", "transport", "research"):
        assert f"--extra {extra}" in uv_call


def test_make_setup_does_not_persist_extras_when_sync_fails(tmp_path: Path) -> None:
    fake_bin, _, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _write_executable(fake_bin / "uv", 'echo "sync failed" >&2\nexit 23\n')

    result = _run_make(tmp_path, "setup", env, "EXTRAS=dev transport research")

    assert result.returncode != 0
    assert "sync failed" in result.stdout + result.stderr
    assert not (tmp_path / ".venv" / ".make-extras").exists()


def test_make_gate_reuses_setup_extras_when_extras_are_unspecified(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path, "dev transport research")

    result = _run_make(tmp_path, "test-all", env)

    assert result.returncode == 0, result.stdout + result.stderr
    uv_call = uv_marker.read_text(encoding="utf-8")
    for extra in ("dev", "research", "transport"):
        assert f"--extra {extra}" in uv_call
    assert "pytest tests/" in local_marker.read_text(encoding="utf-8")


def test_make_gate_rejects_explicit_extras_mismatch_before_uv(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path, "dev transport research")

    result = _run_make(tmp_path, "test-all", env, "EXTRAS=dev transport")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "EXTRAS" in output
    assert "dev transport" in output
    assert "dev research transport" in output
    assert not uv_marker.exists(), "uv ran despite an explicit extras mismatch"
    assert not local_marker.exists(), "tests ran despite an explicit extras mismatch"


def test_make_gate_accepts_explicit_reordered_matching_extras(tmp_path: Path) -> None:
    _, uv_marker, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path, "dev transport research")

    result = _run_make(tmp_path, "test-all", env, "EXTRAS=transport dev research")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "uv sync --check --locked" in uv_marker.read_text(encoding="utf-8")
    assert "pytest tests/" in local_marker.read_text(encoding="utf-8")


def test_make_smoke_runs_installed_console_scripts(tmp_path: Path) -> None:
    _, _, env = _fake_path_tools(tmp_path)
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)

    result = _run_make(tmp_path, "smoke", env)

    assert result.returncode == 0, result.stdout + result.stderr
    calls = local_marker.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "acgs-swarm --help",
        "acgs-verify-receipts --help",
        "acgs-agent-self-evolve --help",
    ]


@pytest.mark.parametrize(
    ("tool", "env_name"),
    [
        ("acgs-swarm", "ACGS_SWARM_EXIT"),
        ("acgs-verify-receipts", "ACGS_VERIFY_RECEIPTS_EXIT"),
        ("acgs-agent-self-evolve", "ACGS_AGENT_SELF_EVOLVE_EXIT"),
    ],
)
def test_make_smoke_propagates_console_script_failures(
    tmp_path: Path,
    tool: str,
    env_name: str,
) -> None:
    _, _, env = _fake_path_tools(tmp_path)
    env[env_name] = "9"
    local_marker = tmp_path / "venv-tool-ran.log"
    _create_fake_project_venv(tmp_path, local_marker)
    _record_installed_extras(tmp_path)

    result = _run_make(tmp_path, "smoke", env)

    assert result.returncode != 0
    assert f"{tool} --help" in local_marker.read_text(encoding="utf-8").splitlines()


def test_isolated_import_ignores_stale_pythonpath_and_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale_root = tmp_path / "stale-checkout"
    stale_package = stale_root / "constitutional_swarm"
    stale_package.mkdir(parents=True)
    (stale_package / "__init__.py").write_text("STALE_INSTALL = True\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(stale_root))
    monkeypatch.chdir(stale_root)

    result = test_core_import_isolation._run_isolated(
        """
        from pathlib import Path
        import constitutional_swarm

        print(Path(constitutional_swarm.__file__).resolve())
        """
    )

    assert result.returncode == 0, result.stderr
    imported = Path(result.stdout.strip())
    assert imported.is_relative_to(REPO_ROOT / "src"), imported
