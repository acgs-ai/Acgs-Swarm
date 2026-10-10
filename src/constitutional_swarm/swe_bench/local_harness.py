"""Local (Docker-less) SWE-bench validation harness.

Pipeline per instance:

1. Clone ``repo`` into a shared cache (once per repo).
2. Hard-reset a scratch worktree to ``base_commit``.
3. ``git apply`` the candidate patch.
4. Run the instance's ``FAIL_TO_PASS`` and ``PASS_TO_PASS`` tests via
   a per-repo test runner — django's ``tests/runtests.py`` when that
   file is present, else pytest in the *current* Python interpreter.
5. Report a structured :class:`HarnessResult`; ``resolved=True`` iff every
   required test passed.

Scope / honesty
---------------
This is a mechanical scaffold. When ``env_isolation=True``, a per-instance
venv is created and ``pip install <worktree>`` bootstraps the target repo's
dependencies; this handles most pure-Python SWE-bench Lite instances but
does NOT reproduce repo-specific build pinning (no Docker image, no exact
CI environment). When ``env_isolation=False`` (the default), the caller
must ensure the target repo's deps are importable from the active
interpreter. Full Docker-based isolation remains a separate iteration.

Environment filtering is defense in depth, not process isolation. Untrusted
code running inside pytest can tamper with pytest's in-process reporting.
Repository-root ``pytest_*`` modules are blocked, but preinstalled entry-point
plugins and plugins with arbitrary import names remain outside repository shadow
checks. Run adversarial model patches without credentials in the harness
environment and inside a separate uid or container.

Python version selection
------------------------
SWE-bench Lite base commits target 2022-2023 era Python (3.9-3.11); a
modern host interpreter (e.g. 3.14) will fail to resolve era-pinned
wheels. When ``python_version`` is set (or present on the instance dict,
or auto-detected from the repo's ``pyproject.toml``'s ``requires-python``),
and ``uv`` is available on PATH, the harness calls ``uv python install``
+ ``uv venv --python`` to materialise an interpreter of the requested
version before pip-installing the worktree. This is still Docker-less
but lifts the host-Python ceiling.

Inputs
------
An "instance" is a ``dict`` with the SWE-bench Lite schema fields used
here: ``instance_id``, ``repo``, ``base_commit``, ``FAIL_TO_PASS``,
``PASS_TO_PASS``. Test IDs follow pytest's ``path::TestClass::test`` form.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from configparser import ConfigParser, Error as ConfigParserError
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench._subprocess import _run_process, _subprocess_env
from constitutional_swarm.swe_bench.agent import _validate_timeout_seconds

_log = logging.getLogger(__name__)

_DEFAULT_WORK_DIR = Path.home() / ".cache" / "constitutional_swarm" / "swe_bench"
_PYTEST_SUMMARY = re.compile(
    r"(?m)^=*\s*(?P<summary>(?:\d+\s+(?:passed|failed|error|errors|skipped|xfailed|xpassed|"
    r"deselected|warning|warnings|rerun|reruns)"
    r"(?:,\s*)?)+)\s+in\s+[0-9.]+\s*s(?:\s*\([^)]*\))?\s*=*\s*$"
)
_PYTEST_STATUS_RE = re.compile(
    r"(?m)^(?P<status>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+"
    r"(?P<test_id>\S+)"
)
_DJANGO_OUTCOME_RE = re.compile(
    r"(?i)^(?P<label>.+?)\s+\.\.\.\s+"
    r"(?P<status>ok|FAIL|ERROR|skipped(?:\s+.*)?|expected failure|unexpected success)\s*$"
)
_DJANGO_IDENTITY_RE = re.compile(r"^(?P<name>\S+)\s+\((?P<context>[^)]+)\)\s*$")


@dataclass
class HarnessResult:
    """Outcome of a single instance evaluation.

    Fields
    ------
    instance_id:
        SWE-bench instance id.
    applied:
        True iff ``git apply`` accepted the patch cleanly.
    resolved:
        True iff every FAIL_TO_PASS and PASS_TO_PASS test passed after
        applying the patch.

        .. note::
            This harness runs without Docker (``evaluation_mode="local_dockerless"``).
            Results may differ from official SWE-bench leaderboard scores, which
            use per-instance Docker images with pinned build environments. Use
            ``result.metadata["evaluation_mode"]`` to distinguish local from
            official results in downstream consumers.
    fail_to_pass_passed / fail_to_pass_failed:
        Counts from the FAIL_TO_PASS phase.
    pass_to_pass_passed / pass_to_pass_failed:
        Counts from the PASS_TO_PASS phase.
    stage:
        One of ``clone``, ``checkout``, ``apply``, ``tests``, ``done`` —
        identifies where the pipeline exited.
    error:
        Short human-readable diagnostic on failure (``None`` on success).
    log_tail:
        Last ~2000 chars of combined stdout/stderr from the failing stage
        (empty when ``resolved``).
    duration_s:
        Wall-clock seconds for the entire evaluation.
    """

    instance_id: str
    applied: bool = False
    resolved: bool = False
    fail_to_pass_passed: int = 0
    fail_to_pass_failed: int = 0
    pass_to_pass_passed: int = 0
    pass_to_pass_failed: int = 0
    stage: str = "clone"
    error: str | None = None
    log_tail: str = ""
    duration_s: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class LocalSWEBenchHarness:
    """Docker-less SWE-bench evaluation harness.

    Parameters
    ----------
    work_dir:
        Root for scratch worktrees. One subdir per run, cleaned afterwards
        unless ``keep_worktree=True``. This and explicit cache roots are
        trusted local configuration, never instance-provided paths.
    repo_cache_dir:
        Persistent cache for bare-ish clones. Reused across instances so
        we pay clone cost once per repo.
    python_bin:
        Python interpreter used to invoke pytest when env isolation is off.
        Defaults to the current interpreter.
    timeout_s:
        Per-stage timeout (clone, checkout, apply, each pytest phase).
    keep_worktree:
        If True, leave the scratch worktree in place after evaluation —
        useful for debugging a single instance.
    env_isolation:
        If True, create a per-instance venv and ``pip install`` the patched
        worktree into it before running tests. Pytest then runs with the
        venv's interpreter so the target project's dependencies don't
        collide with the host interpreter. If venv creation or install
        fails, the instance is reported as an env error (resolved=False)
        rather than silently falling back.
    env_cache_dir:
        Root for per-instance venvs. Each evaluation creates a fresh
        ``<env_cache_dir>/<instance_id>`` venv and removes it afterwards
        unless ``keep_worktree`` is also set.
    env_timeout_s:
        Timeout for venv creation and ``pip install`` (installing packages
        like astropy / scipy can take several minutes on first run).
    python_version:
        Optional "X.Y" Python version string (e.g. ``"3.10"``). When set
        together with ``env_isolation=True``, the harness materialises a
        venv with that Python via ``uv python install`` + ``uv venv
        --python``. A per-instance ``python_version`` key on the
        instance dict overrides this default; if neither is provided
        the harness attempts to auto-detect from the worktree's
        ``pyproject.toml``'s ``requires-python``. Requires ``uv`` on
        PATH when any version is in effect.
    """

    def __init__(
        self,
        *,
        work_dir: Path | str | None = None,
        repo_cache_dir: Path | str | None = None,
        python_bin: str | None = None,
        timeout_s: float = 600.0,
        keep_worktree: bool = False,
        env_isolation: bool = False,
        env_cache_dir: Path | str | None = None,
        env_timeout_s: float = 900.0,
        python_version: str | None = None,
    ) -> None:
        base = Path(work_dir) if work_dir else _DEFAULT_WORK_DIR
        self.work_dir = base / "worktrees"
        self.repo_cache_dir = Path(repo_cache_dir) if repo_cache_dir else base / "repos"
        self.env_cache_dir = Path(env_cache_dir) if env_cache_dir else base / "venvs"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)
        self.env_cache_dir.mkdir(parents=True, exist_ok=True)
        self.python_bin = python_bin or _current_python()
        self.timeout_s = _validate_timeout_seconds(timeout_s)
        self.keep_worktree = keep_worktree
        self.env_isolation = env_isolation
        self.env_timeout_s = _validate_timeout_seconds(
            env_timeout_s, field_name="env_timeout_s"
        )
        self.python_version = python_version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, instance: dict[str, Any], patch: str) -> HarnessResult:
        """Run clone → checkout → apply → pytest for ``instance`` with ``patch``.

        Always returns a :class:`HarnessResult` — exceptions in subprocesses
        are caught and surfaced via ``error`` / ``log_tail``.

        .. note::
            This harness runs **without Docker** (``evaluation_mode="local_dockerless"``).
            It reproduces the mechanical test-pass/fail signal but does not reproduce
            the exact CI environment used by the official SWE-bench leaderboard.
            The returned :class:`HarnessResult` carries
            ``metadata["evaluation_mode"] = "local_dockerless"`` so downstream
            scripts can distinguish local results from official leaderboard results.
        """
        import time

        t0 = time.monotonic()
        instance_id = str(instance.get("instance_id", "unknown"))
        repo = str(instance.get("repo", "")).strip()
        base_commit = str(instance.get("base_commit", "")).strip()
        fail_to_pass = _as_list(instance.get("FAIL_TO_PASS"))
        pass_to_pass = _as_list(instance.get("PASS_TO_PASS"))
        test_patch = str(instance.get("test_patch", ""))
        result = HarnessResult(
            instance_id=instance_id,
            metadata={
                "evaluation_mode": "local_dockerless",
                "test_patch_applied": False,
            },
        )

        if not repo or not base_commit:
            result.stage = "clone"
            result.error = "missing repo or base_commit"
            result.duration_s = time.monotonic() - t0
            return result
        if not patch.strip():
            result.stage = "apply"
            result.error = "empty patch"
            result.duration_s = time.monotonic() - t0
            return result
        if not test_patch.strip():
            result.stage = "test_patch"
            result.error = "missing or empty test_patch"
            result.duration_s = time.monotonic() - t0
            return result

        try:
            worktree = _safe_child_path(
                self.work_dir, instance_id, field_name="instance_id"
            )
        except ValueError as exc:
            result.stage = "clone"
            result.error = str(exc)
            result.duration_s = time.monotonic() - t0
            return result
        venv_path: Path | None = None
        try:
            if worktree.exists():
                safe_worktree = _scoped_path_for_cleanup(
                    self.work_dir, worktree, label="worktree"
                )
                shutil.rmtree(safe_worktree)
            self._clone_to_worktree(repo, worktree, result)
            if result.error:
                return result
            self._checkout(worktree, base_commit, result)
            if result.error:
                return result
            base_runner = _detect_test_runner(worktree)
            self._apply_patch(worktree, patch, result)
            if not result.applied:
                return result
            self._validate_candidate_test_controls(worktree, base_commit, result)
            if result.error:
                return result
            self._apply_test_patch(worktree, base_commit, test_patch, result)
            if not result.metadata["test_patch_applied"]:
                return result
            test_python = self.python_bin
            if self.env_isolation:
                inst_version = str(instance.get("python_version") or "").strip() or None
                effective_version = inst_version or self.python_version
                if effective_version is None:
                    effective_version = _detect_python_version(worktree)
                venv_path, isolated_python = self._ensure_env(
                    instance_id, worktree, result, python_version=effective_version
                )
                if isolated_python is None:
                    return result
                test_python = isolated_python
            self._run_tests(
                worktree,
                fail_to_pass,
                pass_to_pass,
                result,
                test_python,
                runner=base_runner,
            )
            result.stage = "done"
            statuses = {
                **result.metadata.get("fail_to_pass_statuses", {}),
                **result.metadata.get("pass_to_pass_statuses", {}),
            }
            result.resolved = bool(statuses) and all(
                status == "passed" for status in statuses.values()
            )
            return result
        finally:
            result.duration_s = time.monotonic() - t0
            if not self.keep_worktree:
                _cleanup_scoped_directory(
                    self.work_dir,
                    worktree,
                    result,
                    label="worktree",
                )
                if venv_path is not None:
                    _cleanup_scoped_directory(
                        self.env_cache_dir,
                        venv_path,
                        result,
                        label="venv",
                    )

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _clone_to_worktree(self, repo: str, worktree: Path, result: HarnessResult) -> None:
        result.stage = "clone"
        try:
            cache = _safe_child_path(self.repo_cache_dir, repo, field_name="repo")
        except ValueError as exc:
            result.error = str(exc)
            return
        url = f"https://github.com/{repo}.git"
        if not cache.exists():
            # Full clone (not --filter=blob:none) so the --shared worktree below
            # has all blobs available for `git apply --index` / --3way merges.
            rc, out = _run(
                ["git", "clone", url, str(cache)],
                timeout=self.timeout_s,
            )
            if rc != 0:
                result.error = f"clone failed (rc={rc})"
                result.log_tail = out[-2000:]
                return
        else:
            _run(
                ["git", "-C", str(cache), "fetch", "--tags", "--prune", "origin"],
                timeout=self.timeout_s,
            )

        rc, out = _run(
            ["git", "clone", "--no-hardlinks", "--shared", str(cache), str(worktree)],
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = f"worktree clone failed (rc={rc})"
            result.log_tail = out[-2000:]

    def _checkout(self, worktree: Path, base_commit: str, result: HarnessResult) -> None:
        result.stage = "checkout"
        rc, out = _run(
            ["git", "-C", str(worktree), "checkout", "--detach", base_commit],
            timeout=self.timeout_s,
        )
        if rc != 0:
            # Try fetching the specific commit then retrying — SWE-bench commits
            # are occasionally not reachable without a full fetch.
            _run(
                ["git", "-C", str(worktree), "fetch", "origin", base_commit],
                timeout=self.timeout_s,
            )
            rc, out = _run(
                ["git", "-C", str(worktree), "checkout", "--detach", base_commit],
                timeout=self.timeout_s,
            )
        if rc != 0:
            result.error = f"checkout failed (rc={rc})"
            result.log_tail = out[-2000:]

    def _apply_patch(self, worktree: Path, patch: str, result: HarnessResult) -> None:
        result.stage = "apply"
        # Strict → --recount (fix LLM hunk-count errors) → 3-way. There is
        # deliberately NO patch(1) fuzz fallback (unlike the official SWE-bench
        # harness): patch(1) accepts many header syntaxes (C-quoted names,
        # renames, context diffs, Index: lines) through which a model patch can
        # write .git metadata or git-ignored files and so hide changes from the
        # pytest-control gate. A patch that only applies with fuzz fails closed.
        # Trade-off: fuzz-only patches score unresolved here but may resolve in
        # the official harness, so local resolve rates are a lower bound.
        out = ""
        for flags in (["--index"], ["--index", "--recount"], ["--3way", "--recount"]):
            rc, out = _run(
                ["git", "-C", str(worktree), "apply", *flags, "-"],
                input_text=patch,
                timeout=self.timeout_s,
            )
            if rc == 0:
                result.applied = True
                return
        result.applied = False
        result.error = "patch did not apply"
        result.log_tail = out[-2000:]

    def _validate_candidate_test_controls(
        self,
        worktree: Path,
        base_commit: str,
        result: HarnessResult,
    ) -> None:
        """Reject candidate changes that can alter pytest collection or outcomes.

        The official SWE-bench ``test_patch`` is applied only after this check,
        so official changes to these controls remain authoritative.
        """
        result.stage = "apply"
        rc, out = _run(
            ["git", "-C", str(worktree), "cat-file", "-e", f"{base_commit}^{{tree}}"],
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = "could not verify base tree for pytest controls"
            result.log_tail = out[-2000:]
            return
        # Git-ignored files are invisible to ``git diff`` but pytest still loads
        # them (e.g. a conftest.py hidden via .gitignore). Only checkout and the
        # candidate patch have touched the worktree at this point, so any
        # ignored untracked file came from the candidate: fail closed.
        rc, out = _run(
            [
                "git",
                "-C",
                str(worktree),
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = "could not inspect ignored candidate files"
            result.log_tail = out[-2000:]
            return
        ignored = [path for path in out.split("\0") if path]
        if ignored:
            result.error = "candidate patch created git-ignored files: " + ", ".join(
                sorted(ignored)[:10]
            )
            return
        rc, out = _run(
            [
                "git",
                "-C",
                str(worktree),
                "diff",
                "--name-only",
                "-z",
                base_commit,
                "--",
            ],
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = "could not inspect candidate pytest controls"
            result.log_tail = out[-2000:]
            return

        try:
            changed_paths = [path for path in out.split("\0") if path]
            for path in changed_paths:
                _validate_repo_path(path)
        except ValueError as exc:
            result.error = f"unsafe candidate path while checking pytest controls: {exc}"
            return

        for path in changed_paths:
            name = Path(path).name
            if fnmatchcase(name, "conftest*.py") or name in {
                "pytest.ini",
                ".pytest.ini",
                "pytest.toml",
                ".pytest.toml",
            }:
                result.error = f"candidate modified pytest control: {path}"
                return
            if path == "tests/runtests.py":
                result.error = f"candidate modified test runner: {path}"
                return
            if _is_pytest_shadow_path(path):
                result.error = f"candidate modified pytest control: {path}"
                return
            if name not in {"setup.cfg", "tox.ini", "pyproject.toml"}:
                continue
            base_text, base_error = self._base_file_text(worktree, base_commit, path)
            if base_error:
                result.error = base_error
                return
            candidate_path = worktree / path
            if candidate_path.is_symlink():
                result.error = f"candidate modified pytest control with symlink: {path}"
                return
            try:
                candidate_text = (
                    candidate_path.read_text(encoding="utf-8")
                    if candidate_path.is_file()
                    else None
                )
                base_section = _pytest_config_section(name, base_text)
                candidate_section = _pytest_config_section(name, candidate_text)
            except (OSError, UnicodeError, ValueError) as exc:
                result.error = f"candidate pytest control could not be verified: {path}: {exc}"
                return
            if base_section != candidate_section:
                result.error = f"candidate modified pytest control: {path}"
                return

    def _base_file_text(
        self,
        worktree: Path,
        base_commit: str,
        path: str,
    ) -> tuple[str | None, str | None]:
        rc, _ = _run(
            ["git", "-C", str(worktree), "cat-file", "-e", f"{base_commit}:{path}"],
            timeout=self.timeout_s,
        )
        if rc != 0:
            return None, None
        rc, out = _run(
            ["git", "-C", str(worktree), "show", f"{base_commit}:{path}"],
            timeout=self.timeout_s,
        )
        if rc != 0:
            return None, f"could not verify base pytest control: {path}"
        return out, None

    def _apply_test_patch(
        self,
        worktree: Path,
        base_commit: str,
        test_patch: str,
        result: HarnessResult,
    ) -> None:
        """Restore official test targets from base, then apply the test patch strictly."""
        result.stage = "test_patch"
        result.metadata["test_patch_applied"] = False
        if not test_patch.strip():
            result.error = "missing or empty test_patch"
            return

        rc, out = _run(
            ["git", "-C", str(worktree), "apply", "--numstat", "-z", "-"],
            input_text=test_patch,
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = "could not parse test_patch targets"
            result.log_tail = out[-2000:]
            return
        reverse_rc, reverse_out = _run(
            [
                "git",
                "-C",
                str(worktree),
                "apply",
                "--reverse",
                "--numstat",
                "-z",
                "-",
            ],
            input_text=test_patch,
            timeout=self.timeout_s,
        )
        if reverse_rc != 0:
            result.error = "could not parse reverse test_patch targets"
            result.log_tail = reverse_out[-2000:]
            return
        try:
            targets = _parse_numstat_paths(out)
            for path in _parse_numstat_paths(reverse_out):
                if path not in targets:
                    targets.append(path)
        except ValueError as exc:
            result.error = f"unsafe test_patch target: {exc}"
            return
        if not targets:
            result.error = "test_patch has no target files"
            return

        for path in targets:
            rc, _ = _run(
                ["git", "-C", str(worktree), "cat-file", "-e", f"{base_commit}:{path}"],
                timeout=self.timeout_s,
            )
            if rc == 0:
                rc, restore_out = _run(
                    ["git", "-C", str(worktree), "checkout", base_commit, "--", path],
                    timeout=self.timeout_s,
                )
            else:
                rc, restore_out = _run(
                    ["git", "-C", str(worktree), "rm", "-f", "--ignore-unmatch", "--", path],
                    timeout=self.timeout_s,
                )
                if rc == 0:
                    rc, restore_out = _run(
                        ["git", "-C", str(worktree), "clean", "-f", "--", path],
                        timeout=self.timeout_s,
                    )
            if rc != 0:
                result.error = f"failed to restore test_patch target {path}"
                result.log_tail = restore_out[-2000:]
                return

        rc, out = _run(
            ["git", "-C", str(worktree), "apply", "--index", "-"],
            input_text=test_patch,
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = "official test patch did not apply"
            result.log_tail = out[-2000:]
            return
        result.metadata["test_patch_applied"] = True

    def _run_tests(
        self,
        worktree: Path,
        fail_to_pass: list[str],
        pass_to_pass: list[str],
        result: HarnessResult,
        python_bin: str,
        *,
        runner: str | None = None,
    ) -> None:
        result.stage = "tests"
        runner = runner or _detect_test_runner(worktree)
        result.metadata["test_runner"] = runner
        if fail_to_pass:
            statuses, log = self._run_suite(worktree, fail_to_pass, python_bin, runner)
            result.metadata["fail_to_pass_statuses"] = statuses
            result.fail_to_pass_passed = sum(s == "passed" for s in statuses.values())
            result.fail_to_pass_failed = len(statuses) - result.fail_to_pass_passed
            if result.fail_to_pass_failed > 0:
                result.log_tail = log[-2000:]
        else:
            result.metadata["fail_to_pass_statuses"] = {}
        if pass_to_pass:
            statuses, log = self._run_suite(worktree, pass_to_pass, python_bin, runner)
            result.metadata["pass_to_pass_statuses"] = statuses
            result.pass_to_pass_passed = sum(s == "passed" for s in statuses.values())
            result.pass_to_pass_failed = len(statuses) - result.pass_to_pass_passed
            if result.pass_to_pass_failed > 0 and not result.log_tail:
                result.log_tail = log[-2000:]
        else:
            result.metadata["pass_to_pass_statuses"] = {}

    def _run_suite(
        self, worktree: Path, test_ids: list[str], python_bin: str, runner: str
    ) -> tuple[dict[str, str], str]:
        if runner == "django":
            return self._django_runtests(worktree, test_ids, python_bin)
        return self._pytest(worktree, test_ids, python_bin)

    def _django_runtests(
        self, worktree: Path, test_ids: list[str], python_bin: str
    ) -> tuple[dict[str, str], str]:
        """Run django's tests/runtests.py with dotted SWE-bench test IDs.

        SWE-bench stores django test IDs in django's native dotted form
        (``test_utils.tests.OverrideSettingsTests.test_foo``); those are
        what ``runtests.py`` expects, so we pass them through as-is.
        """
        statuses: dict[str, str] = {}
        logs: list[str] = []
        for test_id in test_ids:
            cmd = [
                python_bin,
                "tests/runtests.py",
                "--verbosity=2",
                "--parallel=1",
                test_id,
            ]
            rc, out = _run(
                cmd,
                cwd=worktree,
                timeout=self.timeout_s,
                env=_subprocess_env(),
            )
            statuses[test_id] = _django_test_status(test_id, out, rc)
            logs.append(out)
        return statuses, "\n".join(logs)

    def _pytest(
        self, worktree: Path, test_ids: list[str], python_bin: str
    ) -> tuple[dict[str, str], str]:
        statuses: dict[str, str] = {}
        logs: list[str] = []
        for test_id in test_ids:
            junit_dir = Path(
                tempfile.mkdtemp(prefix="swe-junit-", dir=self.work_dir)
            ).resolve()
            junit_path = junit_dir / "result.xml"
            try:
                cmd = [
                    python_bin,
                    "-m",
                    "pytest",
                    "--no-header",
                    "-q",
                    "-rA",
                    "--disable-warnings",
                    "--junitxml",
                    str(junit_path),
                    test_id,
                ]
                rc, out = _run(
                    cmd,
                    cwd=worktree,
                    timeout=self.timeout_s,
                    # Candidate packages installed into the venv may register
                    # pytest11 entry-point plugins; never auto-load them.
                    env=_subprocess_env({"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}),
                )
                if junit_path.exists():
                    status = _pytest_junit_status(test_id, junit_path, rc)
                    stdout_status = _pytest_test_status(test_id, out, rc)
                    if status == "passed" and stdout_status in {
                        "error",
                        "failed",
                        "skipped",
                        "xfailed",
                        "xpassed",
                    }:
                        status = stdout_status
                else:
                    status = "error"
                statuses[test_id] = status
                logs.append(out)
            finally:
                try:
                    safe_junit_dir = _scoped_path_for_cleanup(
                        self.work_dir, junit_dir, label="junit directory"
                    )
                except ValueError as exc:
                    statuses[test_id] = "error"
                    logs.append(str(exc))
                else:
                    if safe_junit_dir.exists():
                        shutil.rmtree(safe_junit_dir, ignore_errors=True)
        return statuses, "\n".join(logs)

    def _ensure_env(
        self,
        instance_id: str,
        worktree: Path,
        result: HarnessResult,
        *,
        python_version: str | None = None,
    ) -> tuple[Path | None, str | None]:
        """Create a per-instance venv and ``pip install`` the patched worktree.

        When ``python_version`` is set, the venv is materialised with that
        Python via ``uv python install`` + ``uv venv --python`` (requires
        ``uv`` on PATH). Otherwise falls back to ``<self.python_bin> -m venv``.

        Returns ``(venv_path, python_bin)``. On failure, records an env
        error on ``result`` and returns ``(venv_path_or_None, None)`` so
        the caller can short-circuit without running tests.
        """
        result.stage = "env"
        venv_path = _safe_child_path(
            self.env_cache_dir, instance_id, field_name="instance_id"
        )
        if venv_path.exists():
            safe_venv_path = _scoped_path_for_cleanup(
                self.env_cache_dir, venv_path, label="venv"
            )
            shutil.rmtree(safe_venv_path, ignore_errors=True)
        if python_version:
            if not shutil.which("uv"):
                result.error = f"uv not on PATH but python_version={python_version} requested"
                result.metadata["env_stage"] = "uv-missing"
                return None, None
            rc, out = _run(
                ["uv", "python", "install", python_version],
                timeout=self.env_timeout_s,
            )
            if rc != 0:
                result.error = f"uv python install {python_version} failed (rc={rc})"
                result.log_tail = out[-2000:]
                result.metadata["env_stage"] = "uv-python-install"
                return venv_path, None
            rc, out = _run(
                ["uv", "venv", "--seed", "--python", python_version, str(venv_path)],
                timeout=self.env_timeout_s,
            )
            if rc != 0:
                result.error = f"uv venv --python {python_version} failed (rc={rc})"
                result.log_tail = out[-2000:]
                result.metadata["env_stage"] = "uv-venv"
                return venv_path, None
            result.metadata["env_python_version"] = python_version
        else:
            rc, out = _run(
                [self.python_bin, "-m", "venv", str(venv_path)],
                timeout=self.env_timeout_s,
            )
            if rc != 0:
                result.error = f"venv creation failed (rc={rc})"
                result.log_tail = out[-2000:]
                result.metadata["env_stage"] = "venv"
                return venv_path, None
        venv_py = str(venv_path / "bin" / "python")
        rc, out = _run(
            [venv_py, "-m", "pip", "install", "--quiet", "--upgrade", "pip", "pytest"],
            timeout=self.env_timeout_s,
            env=_subprocess_env(),
        )
        if rc != 0:
            result.error = f"pip bootstrap failed (rc={rc})"
            result.log_tail = out[-2000:]
            result.metadata["env_stage"] = "pip-bootstrap"
            return venv_path, None
        rc, out = _run(
            [venv_py, "-m", "pip", "install", "--quiet", str(worktree)],
            timeout=self.env_timeout_s,
            env=_subprocess_env(),
        )
        if rc != 0:
            result.error = f"pip install target failed (rc={rc})"
            result.log_tail = out[-2000:]
            result.metadata["env_stage"] = "pip-install"
            failure_class = _classify_env_failure(out)
            if failure_class is not None:
                result.metadata["env_failure_class"] = failure_class
            return venv_path, None
        result.metadata["env_python"] = venv_py
        return venv_path, venv_py


# ----------------------------------------------------------------------
# Dataset loading helpers
# ----------------------------------------------------------------------


def load_instances(
    *,
    jsonl_path: Path | str | None = None,
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    split: str = "test",
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Load SWE-bench instances from a local JSONL file or a HuggingFace dataset.

    A local ``jsonl_path`` wins if provided. Otherwise the harness attempts
    to import ``datasets`` and load the named dataset/split.
    """
    if jsonl_path is not None:
        path = Path(jsonl_path)
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return rows[:limit] if limit else rows
    try:
        from datasets import load_dataset  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "datasets library not installed; pass jsonl_path or install `datasets`"
        ) from exc
    ds = load_dataset(dataset, split=split)
    rows = [dict(r) for r in ds]
    return rows[:limit] if limit else rows


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------


def _current_python() -> str:
    import sys

    return sys.executable


_REQUIRES_PYTHON_RE = re.compile(r"(?:>=?|\^|~=?)\s*(\d+\.\d+)")


def _detect_python_version(worktree: Path) -> str | None:
    """Best-effort parse of ``project.requires-python`` from ``pyproject.toml``.

    Returns the lower-bound "X.Y" if parseable, else None. We pick the
    lower bound because SWE-bench Lite base commits are historical and
    generally need the oldest compatible interpreter. ``setup.py`` is
    not consulted — keep this cheap and explicit.
    """
    pyproject = worktree / "pyproject.toml"
    if not pyproject.exists():
        return None
    try:
        import tomllib
    except ImportError:  # pragma: no cover — tomllib is stdlib on 3.11+
        return None
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    req = data.get("project", {}).get("requires-python")
    if not isinstance(req, str) or not req.strip():
        return None
    match = _REQUIRES_PYTHON_RE.search(req)
    if match:
        return match.group(1)
    fallback = re.search(r"(\d+\.\d+)", req)
    return fallback.group(1) if fallback else None


# Build-log signatures of a native extension / toolchain failure while
# installing the target repo. Matched case-insensitively over the FULL pip
# output (not the 2000-char tail). Keep tight: a match relabels an env
# failure as an external native-build blocker; it never marks a run resolved.
_NATIVE_BUILD_FAILURE_RE = re.compile(
    r"failed building wheel for"
    r"|could not build wheels for"
    r"|can't find rust compiler"
    r"|requires rust"
    r"|error: command '[^']*(?:gcc|g\+\+|cc|clang|cl\.exe)' failed"
    r"|microsoft visual c\+\+ [\d.]+ or greater is required"
    r"|fatal error: [\w./-]+\.h: no such file or directory",
    re.IGNORECASE,
)


def _classify_env_failure(output: str) -> str | None:
    """Classify a failed ``pip install <worktree>`` log, or return None."""
    if _NATIVE_BUILD_FAILURE_RE.search(output):
        return "native-build-incompatibility"
    return None


def _safe_id(raw: str, *, field_name: str = "identifier") -> str:
    if "\0" in raw:
        raise ValueError(f"invalid {field_name}: NUL is not allowed")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    if safe in {"", ".", ".."}:
        raise ValueError(f"invalid {field_name}: unsafe path component")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:200]}-{digest}"


def _safe_child_path(root: Path, raw: str, *, field_name: str) -> Path:
    """Return a sanitized strict child of ``root`` or raise before filesystem use."""
    root_resolved = root.resolve()
    lexical_child = root_resolved / _safe_id(raw, field_name=field_name)
    if lexical_child.is_symlink():
        raise ValueError(f"invalid {field_name}: symlink path component")
    child = lexical_child.resolve(strict=False)
    if (
        child != lexical_child
        or child == root_resolved
        or not child.is_relative_to(root_resolved)
    ):
        raise ValueError(f"invalid {field_name}: path escapes configured root")
    return child


def _scoped_path_for_cleanup(root: Path, expected: Path, *, label: str) -> Path:
    """Re-resolve a path immediately before deletion and reject retargeting."""
    root_resolved = root.resolve()
    expected_absolute = expected.absolute()
    current = expected.resolve(strict=False)
    if (
        current != expected_absolute
        or current == root_resolved
        or not current.is_relative_to(root_resolved)
    ):
        raise ValueError(f"cleanup refused for {label}: path was retargeted or escaped")
    return current


def _cleanup_scoped_directory(
    root: Path,
    expected: Path,
    result: HarnessResult,
    *,
    label: str,
) -> None:
    try:
        safe_path = _scoped_path_for_cleanup(root, expected, label=label)
    except ValueError as exc:
        message = str(exc)
        result.metadata.setdefault("cleanup_errors", []).append(message)
        result.resolved = False
        if result.error is None:
            result.error = message
        return
    if safe_path.exists():
        shutil.rmtree(safe_path, ignore_errors=True)


def _detect_test_runner(worktree: Path) -> str:
    """Pick a test runner based on files present in the worktree.

    - ``django``: ``tests/runtests.py`` exists (the django/django repo).
    - ``pytest``: default fallback.

    Keep the set tight — every new runner adds a parser to maintain.
    Extend deliberately (sympy ``bin/test``, scikit-learn ``nosetests``,
    etc.) only when there's evidence of instances needing it.
    """
    if (worktree / "tests" / "runtests.py").is_file():
        return "django"
    return "pytest"


_DJANGO_RAN_RE = re.compile(r"Ran\s+(\d+)\s+tests?\s+in", re.IGNORECASE)
_DJANGO_FAILED_RE = re.compile(r"FAILED\s*\(([^)]*)\)", re.IGNORECASE)
_DJANGO_OK_RE = re.compile(
    r"^\s*OK(?:\s*\(([^)]*)\))?\s*$", re.IGNORECASE | re.MULTILINE
)


def _parse_django_summary(output: str) -> tuple[int, int]:
    """Parse django runtests.py output → ``(passed, failed)``.

    Django prints ``Ran N tests in X.XXXs`` followed by either ``OK``
    (all passed) or ``FAILED (failures=F, errors=E, ...)``. Skips,
    expected failures, and unexpected successes are counted as
    non-passes. When the summary is missing (early crash), returns
    ``(0, 0)`` and the caller decides how to treat collection failures.
    """
    m_ran = _DJANGO_RAN_RE.search(output)
    if not m_ran:
        return 0, 0
    total = int(m_ran.group(1))
    m_outcome = _DJANGO_FAILED_RE.search(output) or _DJANGO_OK_RE.search(output)
    if not m_outcome:
        return 0, total
    not_passed = 0
    details = m_outcome.group(1) or ""
    for part in details.split(","):
        part = part.strip()
        for key in (
            "failures",
            "errors",
            "skipped",
            "expected failures",
            "unexpected successes",
        ):
            prefix = f"{key}="
            if part.startswith(prefix):
                try:
                    not_passed += int(part[len(prefix) :])
                except ValueError:
                    pass
    return max(0, total - not_passed), not_passed


def _pytest_test_status(test_id: str, output: str, return_code: int) -> str:
    """Classify one explicitly requested pytest node; only PASSED is success."""
    reported = [
        {
            "PASSED": "passed",
            "FAILED": "failed",
            "ERROR": "error",
            "SKIPPED": "skipped",
            "XFAIL": "xfailed",
            "XPASS": "xpassed",
        }[match.group("status")]
        for match in _PYTEST_STATUS_RE.finditer(output)
        if _pytest_node_matches(test_id, match.group("test_id"))
    ]
    for non_pass in ("error", "failed", "skipped", "xfailed", "xpassed"):
        if non_pass in reported:
            return non_pass
    counts = _pytest_summary_counts(output)
    for non_pass in ("errors", "error", "failed", "skipped", "xfailed", "xpassed"):
        if counts.get(non_pass, 0):
            return "error" if non_pass in {"error", "errors"} else non_pass
    if counts.get("deselected", 0):
        return "missing"
    if reported and return_code == 0:
        return "passed"
    return "error" if return_code != 0 else "missing"


def _pytest_node_matches(requested: str, reported: str) -> bool:
    """Match an exact pytest node or a parameterized descendant of that node."""
    return reported == requested or (
        "[" not in requested and reported.startswith(f"{requested}[")
    )


def _django_test_status(test_id: str, output: str, return_code: int) -> str:
    """Classify one explicitly requested Django test by its verbosity-2 line."""
    pending_identity: str | None = None
    reported: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        identity = _django_identity(line)
        if identity is not None:
            pending_identity = identity
        match = _DJANGO_OUTCOME_RE.match(line)
        if match is None:
            continue
        inline_identity = _django_identity(match.group("label"))
        reported_id = inline_identity or pending_identity or match.group("label")
        pending_identity = None
        if reported_id != test_id:
            continue
        status = match.group("status").lower()
        if status == "ok":
            reported.append("passed")
        elif status == "fail":
            reported.append("failed")
        elif status == "error":
            reported.append("error")
        elif status.startswith("skipped"):
            reported.append("skipped")
        elif status == "expected failure":
            reported.append("xfailed")
        elif status == "unexpected success":
            reported.append("xpassed")

    summary_status = _django_summary_status(output, return_code)
    if summary_status is not None:
        reported.append(summary_status)
    for non_pass in ("error", "failed", "skipped", "xfailed", "xpassed"):
        if non_pass in reported:
            return non_pass
    if "passed" in reported and return_code == 0:
        return "passed"
    return "error" if return_code != 0 else "missing"


def _django_summary_status(output: str, return_code: int) -> str | None:
    """Return a non-pass encoded by a single-test Django summary."""
    if _DJANGO_RAN_RE.search(output) is None:
        return "error"
    matches = [*_DJANGO_FAILED_RE.finditer(output), *_DJANGO_OK_RE.finditer(output)]
    if not matches:
        return "error"
    reported: list[str] = []
    for match in matches:
        counts: dict[str, int] = {}
        for part in (match.group(1) or "").split(","):
            key, separator, value = part.strip().partition("=")
            if not separator:
                continue
            try:
                counts[key] = int(value)
            except ValueError:
                return "error"
        for key, status in (
            ("errors", "error"),
            ("failures", "failed"),
            ("skipped", "skipped"),
            ("expected failures", "xfailed"),
            ("unexpected successes", "xpassed"),
        ):
            if counts.get(key, 0) > 0:
                reported.append(status)
    for non_pass in ("error", "failed", "skipped", "xfailed", "xpassed"):
        if non_pass in reported:
            return non_pass
    return "error" if return_code != 0 else None


def _django_identity(label: str) -> str | None:
    match = _DJANGO_IDENTITY_RE.match(label)
    if match is None:
        return None
    name = match.group("name")
    context = match.group("context")
    if context.endswith(f".{name}"):
        return context
    return f"{context}.{name}"


def _pytest_junit_status(test_id: str, junit_path: Path, return_code: int) -> str:
    """Classify an explicitly requested pytest node from its JUnit artifact."""
    try:
        root = ET.parse(junit_path).getroot()
    except (ET.ParseError, OSError):
        return "error"
    statuses: list[str] = []
    for case in root.iter("testcase"):
        if not _junit_case_matches(test_id, case.attrib):
            continue
        if case.find("error") is not None:
            statuses.append("error")
        elif case.find("failure") is not None:
            statuses.append("failed")
        elif case.find("skipped") is not None:
            statuses.append("skipped")
        else:
            statuses.append("passed")
    if not statuses:
        return "error" if return_code != 0 else "missing"
    for non_pass in ("error", "failed", "skipped"):
        if non_pass in statuses:
            return non_pass
    return "passed" if return_code == 0 else "error"


def _junit_case_matches(test_id: str, attributes: dict[str, str]) -> bool:
    parts = test_id.split("::")
    requested_file = parts[0].replace("\\", "/")
    requested_name = parts[-1]
    reported_file = attributes.get("file", "").replace("\\", "/")
    reported_name = attributes.get("name", "")
    if reported_file and reported_file != requested_file:
        return False
    if not _pytest_node_matches(requested_name, reported_name):
        return False
    if len(parts) <= 2:
        return True
    requested_classes = ".".join(parts[1:-1])
    classname = attributes.get("classname", "")
    return bool(classname) and (
        classname == requested_classes or classname.endswith(f".{requested_classes}")
    )


def _pytest_config_section(name: str, content: str | None) -> object:
    if content is None:
        return None
    if name == "pyproject.toml":
        try:
            import tomllib

            data = tomllib.loads(content)
        except (ImportError, ValueError) as exc:
            raise ValueError("malformed pyproject.toml") from exc
        return data.get("tool", {}).get("pytest")
    parser = ConfigParser(interpolation=None)
    try:
        parser.read_string(content)
    except ConfigParserError as exc:
        raise ValueError(f"malformed {name}") from exc
    section = "tool:pytest" if name == "setup.cfg" else "pytest"
    return dict(parser.items(section)) if parser.has_section(section) else None


def _parse_numstat_paths(output: str) -> list[str]:
    """Parse ``git apply --numstat -z`` output into validated repository paths."""
    records = output.split("\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        parts = record.split("\t", 2)
        if len(parts) != 3:
            raise ValueError("malformed numstat output")
        path = parts[2]
        candidates: tuple[str, ...]
        if path:
            candidates = (path,)
        else:
            if index + 1 >= len(records):
                raise ValueError("malformed rename numstat output")
            candidates = (records[index], records[index + 1])
            index += 2
        for candidate in candidates:
            _validate_repo_path(candidate)
            if candidate not in paths:
                paths.append(candidate)
    return paths


def _validate_repo_path(path: str) -> None:
    candidate = Path(path)
    if (
        not path
        or "\\" in path
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError(path or "empty path")


def _is_pytest_shadow_path(path: str) -> bool:
    """Return whether a repository-root path can shadow pytest internals."""
    for module in ("pytest", "_pytest", "pluggy", "iniconfig", "py"):
        if path == f"{module}.py" or path.startswith(f"{module}/"):
            return True
    root_name = path.split("/", 1)[0]
    return root_name.startswith("pytest_") and (
        root_name.endswith(".py") or "/" in path
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (json.JSONDecodeError, ValueError):
            pass
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    return [str(value)]


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    timeout: float = 600.0,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    child_env = _subprocess_env() if env is None else env
    try:
        proc = _run_process(
            cmd,
            cwd=cwd,
            input_text=input_text,
            timeout_s=timeout,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout after {timeout}s: {exc}"
    except FileNotFoundError as exc:
        return 127, f"missing binary: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _parse_pytest_summary(output: str) -> tuple[int, int]:
    """Return (passed, failed) counts parsed from pytest's final summary."""
    counts = _pytest_summary_counts(output)
    passed = counts.get("passed", 0)
    failed = sum(
        counts.get(kind, 0)
        for kind in ("failed", "error", "errors", "skipped", "xfailed", "xpassed")
    )
    return passed, failed


def _pytest_summary_counts(output: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for match in _PYTEST_SUMMARY.finditer(output):
        for token in re.finditer(r"(\d+)\s+([a-z]+)", match.group("summary")):
            kind = token.group(2)
            counts[kind] = counts.get(kind, 0) + int(token.group(1))
    return counts


__all__ = [
    "HarnessResult",
    "LocalSWEBenchHarness",
    "load_instances",
]
