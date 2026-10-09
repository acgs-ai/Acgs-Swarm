"""Shared subprocess lifecycle helpers for SWE-bench command adapters.

Environment filtering is defense in depth only. On Linux, an untrusted child
may read ``/proc/$PPID/environ`` and recover the parent process environment.
Run the local harness itself without credentials, preferably under a separate
uid or in a container when evaluating adversarial model-written code.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from constitutional_swarm.swe_bench.agent import _validate_timeout_seconds


_INHERITED_CONNECTIVITY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)
_URL_CONNECTIVITY_ENV = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "http_proxy",
    "https_proxy",
}


def _subprocess_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal child environment without ambient credentials.

    Only connectivity settings required by proxies, package indexes, and TLS
    certificate validation are inherited. URL settings containing userinfo are
    dropped rather than exposing embedded credentials to model-controlled code.
    Explicit ``overrides`` are trusted adapter configuration and are applied
    separately from ambient inheritance.

    This is environment filtering, not OS isolation: without a container or
    separate uid, child code may read host files such as ``~/.aws`` and, on
    Linux, the parent environment via ``/proc/$PPID/environ`` when permissions
    allow it.
    """
    safe_env = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        safe_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    for name in _INHERITED_CONNECTIVITY_ENV:
        value = os.environ.get(name)
        if value is None:
            continue
        if name in _URL_CONNECTIVITY_ENV and _url_contains_credentials(value):
            continue
        safe_env[name] = value
    safe_env.update(overrides or {})
    return safe_env


def _url_contains_credentials(value: str) -> bool:
    for token in value.split():
        candidate = token if "://" in token else f"//{token}"
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return True
        if parsed.username is not None or parsed.password is not None:
            return True
    return False


def _run_process(
    cmd: list[str],
    *,
    timeout_s: float,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a bounded command in a new process group and reap it on timeout."""
    timeout = _validate_timeout_seconds(timeout_s)
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        if input_text is None:
            stdout, stderr = process.communicate(timeout=timeout)
        else:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            _terminate_process_tree(process)
        finally:
            _close_process_pipes(process)
        raise
    return subprocess.CompletedProcess(
        cmd,
        process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _terminate_process_tree(
    process: subprocess.Popen[str],
    *,
    grace_s: float = 2.0,
) -> None:
    """Terminate a process group, then kill surviving descendants and reap."""
    grace = _validate_timeout_seconds(grace_s, field_name="grace_s")
    if os.name == "nt":
        process.terminate()
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=grace)
        return

    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        _reap_process(process, grace_s=grace)
        return
    except OSError:
        process.terminate()
        if not _reap_process(process, grace_s=grace):
            process.kill()
            _reap_process(process, grace_s=grace)
        return

    leader_reaped = _reap_process(process, grace_s=grace)

    # The group may still contain descendants after its original leader exits.
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()

    if not leader_reaped:
        _reap_process(process, grace_s=grace)


def _reap_process(process: subprocess.Popen[str], *, grace_s: float) -> bool:
    try:
        process.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        return False
    return True


def _close_process_pipes(process: subprocess.Popen[str]) -> None:
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()


__all__ = ["_run_process", "_subprocess_env", "_terminate_process_tree"]
