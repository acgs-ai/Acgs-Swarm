"""Governed coding-agent handoff CLI for constitutional_swarm.

This module is intentionally lightweight: it turns a local task file into
governed tool, file-write, test, and handoff events, then writes tamper-evident
JSONL audit evidence plus a bundle under the caller repository's ``.acgs`` dir.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import inspect
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from time import time
from types import MappingProxyType
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.constants import CONSTITUTIONAL_HASH

ALLOW = "allow"
DENY = "deny"
REVIEW = "human_review_required"
ZERO_HASH = "0" * 64

# Domain separator for the bundle attestation pre-image. Versioned so the signed
# pre-image can never be confused with any other Ed25519 message in the system.
BUNDLE_SCHEMA_VERSION = 2
BUNDLE_SIG_DOMAIN = "acgs.governed-handoff.bundle-attestation.v2"

# Repository metadata and tool-configuration roots are security boundaries, not
# caller policy. Local configuration may add protected paths but can never remove
# these roots or the code-owned path patterns below.
IMMUTABLE_PROTECTED_ROOTS: frozenset[str] = frozenset(
    {".git", ".github", ".acgs", ".claude", ".vscode", ".husky"}
)
CODE_OWNED_PROTECTED_PATHS: tuple[str, ...] = (
    ".env",
    ".env.*",
    ".env~",
    "**/.env",
    "**/.env.*",
    "**/.env~",
    ".envrc",
    ".envrc.*",
    ".envrc~",
    "**/.envrc",
    "**/.envrc.*",
    "**/.envrc~",
    ".pre-commit-config.yaml",
    "secrets",
    "secrets/**",
)


def _normalize_protected_pattern(pattern: Any) -> str | None:
    normalized = os.path.normpath(str(pattern).replace("\\", "/"))
    folded = normalized.replace("\\", "/").casefold()
    return None if folded in {"", "."} else folded

# Capture platform support before tests or callers can wrap the ``os`` functions.
# Membership in ``supports_dir_fd`` is by function identity, so checking it at
# write time would incorrectly reject a safe platform whenever ``os.open`` is
# instrumented for auditing or deterministic race testing.
_HAS_SAFE_DIR_FD_OPERATIONS = all(
    function in os.supports_dir_fd for function in (os.open, os.mkdir, os.unlink)
)
try:
    _HAS_SAFE_DIR_FD_REPLACE = {"src_dir_fd", "dst_dir_fd"}.issubset(
        inspect.signature(os.replace).parameters
    )
except (TypeError, ValueError):
    _HAS_SAFE_DIR_FD_REPLACE = False

# Code-owned closed safe-command set for the deterministic ``tool_call`` gate.
# Only executables listed here can ever run, and only with argument shapes their
# spec permits. Configuration (``command_allowlist``) may SELECT a subset of these
# names but can never add an executable, flag, or argument shape. Anything that
# does not match is denied (fail closed). Interpreters, launchers, shells, and
# any other unlisted executable are therefore impossible to enable: there is no
# denylist to bypass, and lookup is by exact name (``python3.12``, ``ruby3.3``
# etc. simply are not keys).
_PLAIN_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.,:+=@%-]*")


@dataclass(frozen=True)
class SafeCommandSpec:
    """Argument policy for one code-owned safe command.

    ``allowed_flags`` lists the exact flag tokens accepted. Every other argument
    must be a positional that fully matches ``positional_pattern`` (``None``
    means no positionals). Path separators and leading ``-`` never match the
    positional patterns used here, so unlisted flags and ``--opt=value`` forms
    are rejected rather than passed through.
    """

    name: str
    allowed_flags: frozenset[str] = frozenset()
    positional_pattern: re.Pattern[str] | None = None
    max_positionals: int = 0
    max_argument_length: int = 256

    def validate(self, arguments: list[str]) -> None:
        positionals = 0
        for argument in arguments:
            if argument in self.allowed_flags:
                continue
            if len(argument) > self.max_argument_length:
                raise ValueError(
                    f"argument for {self.name!r} exceeds {self.max_argument_length} "
                    "characters; fail closed"
                )
            if self.positional_pattern is None or not self.positional_pattern.fullmatch(
                argument
            ):
                raise ValueError(
                    f"argument {argument!r} is not permitted for safe command "
                    f"{self.name!r}; fail closed"
                )
            positionals += 1
            if positionals > self.max_positionals:
                raise ValueError(
                    f"too many arguments for safe command {self.name!r}; fail closed"
                )


SAFE_COMMANDS: Mapping[str, SafeCommandSpec] = MappingProxyType(
    {
        "true": SafeCommandSpec(name="true"),
        "echo": SafeCommandSpec(
            name="echo", positional_pattern=_PLAIN_WORD, max_positionals=64
        ),
    }
)

# Backwards-compatible name for the default selection (every safe command).
DEFAULT_COMMAND_ALLOWLIST: tuple[str, ...] = tuple(SAFE_COMMANDS)
DEFAULT_SECRET_COMMAND_PATTERNS: tuple[str, ...] = (
    r"\b(cat|less|more|head|tail|sed|awk|grep|rg)\b.*"
    r"(\.env|secret|credential|id_rsa|token)",
    r"\b(printenv|env)\b",
    r"\b(git\s+config\s+--get|gh\s+auth\s+token)\b",
)

# Child processes see a code-owned search path and a small set of benign locale
# and home-directory values. In particular, no ACGS signing value or ambient
# credential is inherited across the process boundary. System directories come
# first so an operator-writable /usr/local/bin cannot shadow system tools; it
# stays last because operator-installed agent CLIs commonly live there.
FIXED_SUBPROCESS_PATH = "/usr/bin:/bin:/usr/local/bin"
_SUBPROCESS_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {"HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ"}
)


def _select_safe_commands(configured: Any) -> set[str]:
    """Return the safe commands an operator selection enables.

    A missing (None) selection enables every safe command; any other value that
    is not a list, tuple or set enables nothing. A sequence can only narrow the
    code-owned set:
    unknown names are ignored, never added, and an empty list enables nothing.
    """

    if configured is None:
        return set(SAFE_COMMANDS)
    if not isinstance(configured, (list, tuple, set, frozenset)):
        return set()
    return {name for name in (str(item) for item in configured) if name in SAFE_COMMANDS}


def _scrubbed_env() -> dict[str, str]:
    """Harden the supervisor process, then return a minimal child environment."""

    # Every governed launch hardens first, whether or not a signer is configured,
    # so no child ever starts while the supervisor is inspectable via procfs.
    _secure_signer_process()

    child_env = {
        name: value
        for name, value in os.environ.items()
        if name in _SUBPROCESS_ENV_ALLOWLIST and not name.startswith("ACGS_SIGNING_")
    }
    child_env["PATH"] = FIXED_SUBPROCESS_PATH
    return child_env


def _resolve_command(
    command: str, *, command_allowlist: set[str] | frozenset[str]
) -> list[str]:
    """Parse, authorize against the closed safe set, and resolve on the fixed path."""

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError("unparseable command; fail closed") from exc
    if not argv:
        raise ValueError("empty tool command")
    executable = argv[0]
    name = executable.replace("\\", "/").rsplit("/", 1)[-1]
    spec = SAFE_COMMANDS.get(name)
    if spec is None:
        raise ValueError(
            f"command {name!r} is not in the code-owned safe-command allowlist "
            "(interpreters, launchers, and unlisted executables are never allowed); "
            "fail closed"
        )
    if name not in command_allowlist:
        raise ValueError(
            f"safe command {name!r} is not selected by command_allowlist; fail closed"
        )
    if name != executable:
        raise ValueError("path-qualified executable is not allowed")
    spec.validate(argv[1:])
    resolved = shutil.which(name, path=FIXED_SUBPROCESS_PATH)
    if resolved is None or not Path(resolved).is_absolute():
        raise ValueError(f"command {name!r} cannot be resolved on the fixed path")
    return [resolved, *argv[1:]]


def _claim_exclusive_file(path: Path, *, readable: bool = False) -> int:
    """Create and retain a private, non-following evidence file descriptor."""

    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (os.O_RDWR if readable else os.O_WRONLY) | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise OSError(f"evidence path is not a private regular file: {path}")
    return descriptor


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting evidence")
        view = view[written:]


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while chunk := os.pread(descriptor, 1024 * 1024, offset):
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class Action:
    kind: str
    value: str
    content: str | None = None


@dataclass
class AuditLogger:
    path: Path
    task_id: str
    previous_hash: str = ZERO_HASH
    event_index: int = 0
    _descriptor: int | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self._descriptor is None:
            self._descriptor = _claim_exclusive_file(self.path, readable=True)

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def read_events(self) -> list[dict[str, Any]]:
        if self._descriptor is None:
            raise ValueError("audit logger is closed")
        return _parse_audit_bytes(_read_all(self._descriptor))

    def emit(
        self, role: str, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        base = {
            "event_index": self.event_index,
            "timestamp": time(),
            "task_id": self.task_id,
            "role": role,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": self.previous_hash,
        }
        event_hash = sha256_text(canonical_json(base))
        event = {**base, "event_hash": event_hash}
        if self._descriptor is None:
            raise ValueError("audit logger is closed")
        _write_all(self._descriptor, (canonical_json(event) + "\n").encode("utf-8"))
        os.fsync(self._descriptor)
        self.previous_hash = event_hash
        self.event_index += 1
        return event


class ExecutorAdapter(Protocol):
    name: str

    def propose_actions(self, task: TaskSpec) -> list[Action]:
        """Return requested actions; policy gates decide what can run."""


@dataclass(frozen=True)
class PolicyDecision:
    gate: str
    subject: str
    outcome: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {
            "gate": self.gate,
            "subject": self.subject,
            "outcome": self.outcome,
            "reason": self.reason,
        }


class PolicyEngine:
    """Apply the code-owned governed handoff policy.

    Tool commands are authorized against the closed ``SAFE_COMMANDS`` table,
    whose entries each carry an explicit argument policy. ``command_allowlist``
    only selects a subset of that table; it can never add an executable, so
    interpreters, launchers, and wrappers cannot be enabled by configuration.
    """

    def __init__(
        self, constitution: dict[str, Any], swarm: dict[str, Any], repo_root: Path
    ) -> None:
        self.constitution = constitution
        self.swarm = swarm
        self.repo_root = repo_root.resolve()
        policy = (
            constitution.get("policy", {}) if isinstance(constitution, dict) else {}
        )
        configured_paths = policy.get("protected_paths")
        if not isinstance(configured_paths, list):
            configured_paths = []
        normalized_configured_paths = [
            normalized
            for pattern in configured_paths
            if (normalized := _normalize_protected_pattern(pattern)) is not None
        ]
        self.protected_paths = tuple(
            dict.fromkeys(
                (
                    *CODE_OWNED_PROTECTED_PATHS,
                    *normalized_configured_paths,
                )
            )
        )
        configured_secret_patterns = policy.get("secret_command_patterns")
        if not isinstance(configured_secret_patterns, list):
            configured_secret_patterns = []
        secret_patterns = dict.fromkeys(
            (
                *DEFAULT_SECRET_COMMAND_PATTERNS,
                *(str(pattern) for pattern in configured_secret_patterns),
            )
        )
        self.secret_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in secret_patterns
        ]
        # Closed set: a configured list narrows SAFE_COMMANDS (an empty list
        # enables nothing); a missing or null value enables the whole set and
        # any other non-sequence value enables nothing.
        self.command_allowlist = _select_safe_commands(policy.get("command_allowlist"))

    def decide(self, gate: str, subject: str, **context: Any) -> PolicyDecision:
        if gate == "intake":
            return self._intake(subject, context)
        if gate == "tool_call":
            return self._tool_call(subject)
        if gate == "file_write":
            return self._file_write(subject)
        if gate == "state_transition":
            return self._state_transition(subject)
        if gate == "handoff":
            return self._handoff(subject, context)
        return PolicyDecision(gate, subject, DENY, "unknown policy gate; fail closed")

    def _intake(self, subject: str, context: dict[str, Any]) -> PolicyDecision:
        required_roles = {"executor", "observer", "proposer", "validator"}
        roles = set((self.swarm.get("roles") or {}).keys())
        if not context.get("task_exists"):
            return PolicyDecision("intake", subject, DENY, "task file does not exist")
        if not context.get("task_content"):
            return PolicyDecision("intake", subject, DENY, "task file is empty")
        declared_version = None
        if isinstance(self.constitution, dict):
            declared_version = self.constitution.get(
                "constitutional_version"
            ) or self.constitution.get("constitutional_hash")
        if declared_version is not None and str(declared_version) != CONSTITUTIONAL_HASH:
            return PolicyDecision(
                "intake",
                subject,
                DENY,
                f"constitution version {declared_version!r} does not match pinned "
                f"{CONSTITUTIONAL_HASH!r}; fail closed",
            )
        if not required_roles.issubset(roles):
            missing = ", ".join(sorted(required_roles - roles))
            return PolicyDecision(
                "intake", subject, DENY, f"missing role assignments: {missing}"
            )
        return PolicyDecision("intake", subject, ALLOW, "task intake policy passed")

    def _tool_call(self, command: str) -> PolicyDecision:
        if not command:
            return PolicyDecision("tool_call", command, DENY, "empty tool command")
        if any(pattern.search(command) for pattern in self.secret_patterns):
            return PolicyDecision(
                "tool_call", command, DENY, "secret-reading command denied"
            )
        if re.search(r"[;&|`$<>]", command):
            return PolicyDecision(
                "tool_call", command, DENY, "shell metacharacters are not allowed"
            )
        try:
            _resolve_command(command, command_allowlist=self.command_allowlist)
        except ValueError as exc:
            return PolicyDecision("tool_call", command, DENY, str(exc))
        return PolicyDecision("tool_call", command, ALLOW, "tool command allowed")

    def _file_write(self, raw_path: str) -> PolicyDecision:
        decision, _ = self._evaluate_file_write(raw_path)
        return decision

    def _evaluate_file_write(
        self, raw_path: str
    ) -> tuple[PolicyDecision, Path | None]:
        lexical = Path(os.path.normpath(str(self.repo_root / raw_path)))
        if not lexical.is_absolute():
            lexical = lexical.absolute()
        if not lexical.is_relative_to(self.repo_root):
            return PolicyDecision(
                "file_write", raw_path, DENY, "path escapes repository root"
            ), None
        try:
            resolved = lexical.resolve()
        except (OSError, RuntimeError) as exc:
            return PolicyDecision(
                "file_write",
                raw_path,
                DENY,
                f"path cannot be resolved safely: {exc}",
            ), None
        if not resolved.is_relative_to(self.repo_root):
            return PolicyDecision(
                "file_write", raw_path, DENY, "path escapes repository root"
            ), None
        if lexical == self.repo_root or resolved == self.repo_root:
            return PolicyDecision(
                "file_write",
                raw_path,
                DENY,
                "repository root is not a valid file write target",
            ), None
        lexical_relative = lexical.relative_to(self.repo_root).as_posix()
        resolved_relative = resolved.relative_to(self.repo_root).as_posix()
        if any(
            self._is_protected_path(candidate)
            for candidate in (lexical_relative, resolved_relative)
        ):
            return PolicyDecision(
                "file_write",
                resolved_relative,
                REVIEW,
                "protected path requires human review",
            ), resolved
        return (
            PolicyDecision(
                "file_write", resolved_relative, ALLOW, "file write allowed"
            ),
            resolved,
        )

    def _is_protected_path(self, relative_path: str) -> bool:
        folded = relative_path.casefold()
        if any(
            component in IMMUTABLE_PROTECTED_ROOTS
            for component in folded.split("/")
        ):
            return True
        return any(fnmatch(folded, pattern) for pattern in self.protected_paths)

    def _state_transition(self, transition: str) -> PolicyDecision:
        allowed = {
            "executing->validating",
            "intake_pending->planned",
            "planned->executing",
            "validating->blocked",
            "validating->handoff_ready",
            "validating->human_review_required",
        }
        if transition not in allowed:
            return PolicyDecision(
                "state_transition", transition, DENY, "unknown transition; fail closed"
            )
        return PolicyDecision(
            "state_transition", transition, ALLOW, "state transition allowed"
        )

    def _handoff(self, subject: str, context: dict[str, Any]) -> PolicyDecision:
        tests_run = context.get("tests_run") or []
        if not tests_run:
            return PolicyDecision(
                "handoff", subject, DENY, "test proof is required before handoff"
            )
        if not any(test.get("passed") for test in tests_run):
            return PolicyDecision(
                "handoff", subject, DENY, "at least one passing test proof is required"
            )
        return PolicyDecision(
            "handoff", subject, ALLOW, "handoff gate passed with test proof"
        )


@dataclass(frozen=True)
class RunResult:
    task_id: str
    final_state: str
    audit_path: Path
    bundle_path: Path
    chain_hash: str
    signed: bool = False


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    path: Path
    content: str
    metadata: dict[str, Any]


class MockAdapter:
    """Deterministic local adapter for CLI smoke runs and tests.

    Supported task directives:
    - ``ACGS_WRITE path :: content``
    - ``ACGS_TOOL command``
    - ``ACGS_TEST command``
    """

    name = "mock"

    def propose_actions(self, task: TaskSpec) -> list[Action]:
        actions: list[Action] = []
        for raw_line in task.content.splitlines():
            line = raw_line.strip()
            if line.startswith("ACGS_WRITE "):
                target, sep, content = line.removeprefix("ACGS_WRITE ").partition(
                    " :: "
                )
                if sep:
                    actions.append(
                        Action(kind="write", value=target.strip(), content=content)
                    )
            elif line.startswith("ACGS_TOOL "):
                actions.append(
                    Action(kind="tool", value=line.removeprefix("ACGS_TOOL ").strip())
                )
            elif line.startswith("ACGS_TEST "):
                actions.append(
                    Action(kind="test", value=line.removeprefix("ACGS_TEST ").strip())
                )
        return actions


class LocalShellAdapter(MockAdapter):
    """Alias for local shell-backed mock directives."""

    name = "local-shell"


class ExternalAgentAdapter:
    """Boundary for Codex/Claude-style agents invoked by a local command."""

    def __init__(self, *, name: str, command: str | None) -> None:
        self.name = name
        self._command = command

    def propose_actions(self, task: TaskSpec) -> list[Action]:
        if not self._command:
            raise RuntimeError(f"{self.name} adapter is not configured")
        env = _scrubbed_env()
        argv = [*self._resolve_command(), str(task.path)]
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip() or f"{self.name} adapter failed"
            )
        synthetic = TaskSpec(task.task_id, task.path, completed.stdout, task.metadata)
        return MockAdapter().propose_actions(synthetic)

    def _resolve_command(self) -> list[str]:
        """Resolve the operator command's executable on the fixed path.

        A bare name is looked up on ``FIXED_SUBPROCESS_PATH``; a path must be
        absolute and executable. Relative paths would resolve against the
        supervisor's working directory, so they are refused.
        """

        try:
            argv = shlex.split(self._command or "")
        except ValueError as exc:
            raise RuntimeError(
                f"{self.name} adapter command is unparseable; fail closed"
            ) from exc
        if not argv:
            raise RuntimeError(f"{self.name} adapter command is empty; fail closed")
        executable = argv[0]
        if "/" in executable.replace("\\", "/") and not Path(executable).is_absolute():
            raise RuntimeError(
                f"{self.name} adapter executable must be a bare name or an "
                "absolute path; fail closed"
            )
        resolved = shutil.which(executable, path=FIXED_SUBPROCESS_PATH)
        if resolved is None or not Path(resolved).is_absolute():
            raise RuntimeError(
                f"{self.name} adapter executable {executable!r} cannot be resolved "
                "on the fixed path; fail closed"
            )
        return [resolved, *argv[1:]]


def build_adapter(name: str, config: dict[str, Any] | None = None) -> ExecutorAdapter:
    config = config or {}
    if name == "mock":
        return MockAdapter()
    if name in {"local-shell", "shell"}:
        return LocalShellAdapter()
    if name in {"claude", "codex"}:
        command = config.get("command")
        return ExternalAgentAdapter(
            name=name, command=str(command) if command else None
        )
    raise ValueError(f"unknown executor adapter: {name}")


@dataclass(frozen=True)
class BundleSigner:
    """Ed25519 signer the supervisor uses to make an evidence bundle unforgeable.

    Governed child environments omit all ``ACGS_SIGNING_*`` values. On Linux,
    signer loading also marks the supervisor non-dumpable before any child is
    started, blocking same-user reads of the supervisor environment through
    procfs. A parent shell that exported an inline key still retains it, and a
    same-user agent is not fully contained on any platform. Non-Linux platforms
    additionally lack this procfs/ptrace mitigation. Prefer
    ``ACGS_SIGNING_KEY_FILE`` plus a separate operating-system user.
    """

    key_id: str
    private_key: Ed25519PrivateKey


_SIGNER_CACHE_LOCK = threading.Lock()
_SIGNER_CACHE_IDENTITY: tuple[int, str, str, str] | None = None
_SIGNER_CACHE_VALUE: BundleSigner | None = None


def _mark_process_non_dumpable() -> None:
    """Block Linux ptrace/procfs inspection before a signed child launch."""

    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        error_number = ctypes.get_errno()
        if error_number:
            raise OSError(error_number, os.strerror(error_number))
        raise OSError("prctl(PR_SET_DUMPABLE, 0) failed")
    # Read the state back: a filtered or emulated prctl that reports success
    # without clearing the flag must not be trusted.
    if prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE
        raise OSError("PR_GET_DUMPABLE did not report 0 after PR_SET_DUMPABLE; fail closed")


def _read_signing_key_file(path: str) -> str:
    """Read exactly one hex seed, permitting one trailing newline."""

    if not path:
        raise ValueError("ACGS_SIGNING_KEY_FILE must name a private key file")
    from constitutional_swarm.secure_files import PrivateFileError, private_file

    try:
        with private_file(path) as stream:
            payload = stream.read(66)
    except PrivateFileError as exc:
        raise ValueError(f"ACGS_SIGNING_KEY_FILE is not private: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"ACGS_SIGNING_KEY_FILE cannot be read securely: {exc}") from exc
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    if len(payload) != 64:
        raise ValueError(
            "ACGS_SIGNING_KEY_FILE must contain exactly 64 hexadecimal characters "
            "and may end with one newline"
        )
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "ACGS_SIGNING_KEY_FILE must contain exactly 64 hexadecimal characters"
        ) from exc


def _secure_signer_process() -> None:
    """Fail closed when the platform signer-isolation control cannot be applied."""

    try:
        _mark_process_non_dumpable()
    except (AttributeError, OSError) as exc:
        raise RuntimeError(
            f"cannot secure supervisor process for signed operation: {exc}"
        ) from exc


def _load_bundle_signer() -> BundleSigner | None:
    """Load and cache the configured supervisor Ed25519 signer.

    ``ACGS_SIGNING_KEY_FILE`` is preferred and is revalidated on every load as
    an effective-user-owned, owner-only, regular, single-link file; mode 0600 is
    recommended. It contains exactly 64 hexadecimal seed characters, with one
    optional trailing newline. ``ACGS_SIGNING_KEY`` remains supported for
    compatibility but is deprecated because the exporting parent shell retains
    it. An absent key produces an unsigned bundle; malformed or insecure
    configured material fails closed.

    Child environments omit signing values. Linux additionally requires a
    successful ``PR_SET_DUMPABLE=0`` call on every configured load, including a
    cache hit. A same-user agent is not fully contained on any platform, and
    other platforms additionally lack that procfs/ptrace mitigation. Use a
    private key file and a separate user for stronger isolation.
    """

    global _SIGNER_CACHE_IDENTITY, _SIGNER_CACHE_VALUE

    with _SIGNER_CACHE_LOCK:
        key_file = os.environ.get("ACGS_SIGNING_KEY_FILE")
        if key_file is not None:
            raw = _read_signing_key_file(key_file)
            source = f"file:{key_file}"
            setting_name = "ACGS_SIGNING_KEY_FILE"
        else:
            configured = os.environ.get("ACGS_SIGNING_KEY")
            if configured is None:
                if _SIGNER_CACHE_VALUE is not None:
                    _secure_signer_process()
                return None
            raw = configured
            source = "environment"
            setting_name = "ACGS_SIGNING_KEY"
        key_id = os.environ.get("ACGS_SIGNING_KEY_ID", "").strip() or "acgs-supervisor"
        if len(raw) != 64 or re.fullmatch(r"[0-9a-fA-F]{64}", raw) is None:
            raise ValueError(
                f"{setting_name} must provide exactly 64 hexadecimal characters"
            )
        seed = bytes.fromhex(raw)
        _secure_signer_process()
        identity = (os.getpid(), source, key_id, hashlib.sha256(seed).hexdigest())
        if identity == _SIGNER_CACHE_IDENTITY and _SIGNER_CACHE_VALUE is not None:
            return _SIGNER_CACHE_VALUE
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(seed)
        except ValueError as exc:
            raise ValueError(f"{setting_name} is not a valid Ed25519 seed") from exc
        signer = BundleSigner(key_id=key_id, private_key=private_key)
        _SIGNER_CACHE_IDENTITY = identity
        _SIGNER_CACHE_VALUE = signer
        return signer


def _bundle_attestation_preimage(bundle: dict[str, Any]) -> bytes:
    """Canonical bytes binding every v2 payload field except the signature block."""

    payload = {key: value for key, value in bundle.items() if key != "signature"}
    attestation = {
        "domain": BUNDLE_SIG_DOMAIN,
        "payload": payload,
    }
    return canonical_json(attestation).encode("utf-8")


def _verify_bundle_signature(
    bundle: dict[str, Any], trusted_public_keys: dict[str, str] | None
) -> str:
    """Return a signature status for a bundle's ``signature`` block.

    Statuses: ``unsigned`` (no block); ``no_trust_anchor`` (signed but the caller
    supplied no trusted keys, so authorship cannot be established); ``untrusted_key``;
    ``invalid``; ``valid``. Trust derives ONLY from ``trusted_public_keys`` (an
    out-of-band map of key id -> hex Ed25519 public key); the key embedded in the
    bundle is a hint and is never trusted on its own.
    """

    block = bundle.get("signature")
    if not isinstance(block, dict) or not block.get("sig"):
        return "unsigned"
    if bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        return "unsupported_schema"
    if (
        block.get("alg") != "ed25519"
        or block.get("domain") != BUNDLE_SIG_DOMAIN
        or not isinstance(block.get("key_id"), str)
        or not isinstance(block.get("public_key"), str)
        or not isinstance(block.get("sig"), str)
    ):
        return "invalid"
    if not trusted_public_keys:
        return "no_trust_anchor"
    public_hex = trusted_public_keys.get(str(block.get("key_id", "")))
    if public_hex is None:
        return "untrusted_key"
    try:
        if bytes.fromhex(str(block["public_key"])) != bytes.fromhex(public_hex):
            return "invalid"
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public_key.verify(
            base64.b64decode(str(block["sig"]), validate=True),
            _bundle_attestation_preimage(bundle),
        )
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return "invalid"
    return "valid"


_BUNDLE_SUMMARY_FIELDS: tuple[str, ...] = (
    "constitution_hash",
    "constitutional_version",
    "workflow_hash",
    "task_metadata",
    "role_assignments",
    "policy_decisions",
    "tool_events",
    "file_changes",
    "tests_run",
    "final_state",
)


def _derived_bundle_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive every verifier-facing summary from replayable audit evidence."""

    if not isinstance(events, list):
        raise ValueError("audit_events must be a list")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"audit event {index} must be an object")

    run_metadata = _required_latest_payload(events, "run_metadata")
    return {
        "constitution_hash": run_metadata.get("constitution_hash"),
        "constitutional_version": run_metadata.get("constitutional_version"),
        "workflow_hash": run_metadata.get("workflow_hash"),
        "task_metadata": _required_latest_payload(events, "task_metadata"),
        "role_assignments": _required_latest_payload(events, "role_assignments"),
        "policy_decisions": _mapping_payloads(events, "policy_decision"),
        "tool_events": _mapping_payloads(events, "tool_event"),
        "file_changes": _mapping_payloads(events, "file_change"),
        "tests_run": _mapping_payloads(events, "test_run"),
        "final_state": _required_latest_payload(events, "final_state"),
    }


def _required_latest_payload(
    events: list[dict[str, Any]], event_type: str
) -> dict[str, Any]:
    for event in reversed(events):
        if event.get("event_type") == event_type:
            payload = event.get("payload")
            if not isinstance(payload, dict):
                raise ValueError(f"{event_type} payload must be an object")
            return payload
    raise ValueError(f"missing {event_type} audit event")


def _mapping_payloads(
    events: list[dict[str, Any]], event_type: str
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for event in events:
        if event.get("event_type") != event_type:
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ValueError(f"{event_type} payload must be an object")
        payloads.append(payload)
    return payloads


def build_bundle(
    *,
    audit_path: Path,
    bundle_path: Path,
    constitution_hash: str,
    workflow_hash: str,
    constitutional_version: str = CONSTITUTIONAL_HASH,
    signer: BundleSigner | None = None,
) -> dict[str, Any]:
    return _build_bundle_from_snapshot(
        audit_path=audit_path,
        bundle_path=bundle_path,
        constitution_hash=constitution_hash,
        workflow_hash=workflow_hash,
        constitutional_version=constitutional_version,
        signer=signer,
        events=read_audit(audit_path),
    )


def _build_bundle_from_snapshot(
    *,
    audit_path: Path,
    bundle_path: Path,
    constitution_hash: str,
    workflow_hash: str,
    constitutional_version: str = CONSTITUTIONAL_HASH,
    signer: BundleSigner | None = None,
    events: list[dict[str, Any]],
    bundle_descriptor: int | None = None,
) -> dict[str, Any]:
    chain_hash = replay_hashes(events)
    summary = _derived_bundle_summary(events)
    expected_metadata = {
        "constitution_hash": constitution_hash,
        "constitutional_version": constitutional_version,
        "workflow_hash": workflow_hash,
    }
    for metadata_field, expected in expected_metadata.items():
        if summary[metadata_field] != expected:
            raise ValueError(
                f"{metadata_field} does not match signed run_metadata audit evidence"
            )
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "audit_path": str(audit_path),
        **summary,
        "chain_hash": chain_hash,
        "audit_events": [
            {k: v for k, v in event.items() if k != "_line"} for event in events
        ],
    }
    if signer is not None:
        signature = signer.private_key.sign(_bundle_attestation_preimage(bundle))
        bundle["signature"] = {
            "alg": "ed25519",
            "domain": BUNDLE_SIG_DOMAIN,
            "key_id": signer.key_id,
            "public_key": signer.private_key.public_key().public_bytes_raw().hex(),
            "sig": base64.b64encode(signature).decode("ascii"),
        }
    owns_descriptor = bundle_descriptor is None
    descriptor = (
        _claim_exclusive_file(bundle_path)
        if bundle_descriptor is None
        else bundle_descriptor
    )
    try:
        _write_all(
            descriptor,
            (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        if owns_descriptor:
            os.close(descriptor)
    return bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acgs-swarm")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run a task through governed handoff gates")
    run.add_argument("--task", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="Verify an evidence bundle")
    verify.add_argument("--bundle", required=True, type=Path)
    verify.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        metavar="KEYID=HEXPUBKEY",
        help=(
            "Trusted Ed25519 public key as KEYID=HEX (repeatable). At least one "
            "trusted key and a valid signature are required for ok=true; "
            "omitting trust anchors yields diagnostic-only failure."
        ),
    )

    pack = subparsers.add_parser(
        "pack", help="Rebuild a bundle from an audit JSONL task id"
    )
    pack.add_argument("--task", required=True)

    return parser


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hash_yaml_payload(payload: dict[str, Any]) -> str:
    return sha256_text(canonical_json(payload))


def _parse_trusted_keys(items: list[str] | None) -> dict[str, str]:
    """Parse ``KEYID=HEXPUBKEY`` CLI items into a trusted-key map."""

    trusted: dict[str, str] = {}
    for item in items or []:
        key_id, sep, hex_value = item.partition("=")
        if sep and key_id.strip() and hex_value.strip():
            trusted[key_id.strip()] = hex_value.strip()
    return trusted


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        result = run_task(args.task)
        print(
            json.dumps(
                {
                    "task_id": result.task_id,
                    "final_state": result.final_state,
                    "audit_path": str(result.audit_path),
                    "bundle_path": str(result.bundle_path),
                    "chain_hash": result.chain_hash,
                    "signed": result.signed,
                },
                sort_keys=True,
            )
        )
        return (
            0 if result.final_state in {"handoff_ready", "human_review_required"} else 1
        )
    if args.command == "verify":
        trusted = _parse_trusted_keys(args.trusted_key)
        verify_result = verify_bundle(
            args.bundle, trusted_public_keys=trusted or None
        )
        print(json.dumps(verify_result, sort_keys=True))
        return 0 if verify_result["ok"] else 1
    if args.command == "pack":
        bundle = pack_task(args.task)
        print(
            json.dumps(
                {
                    "bundle_path": f".acgs/evidence/{args.task}.bundle.json",
                    "chain_hash": bundle["chain_hash"],
                    "signed": isinstance(bundle.get("signature"), dict),
                },
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError(args.command)


def pack_task(task_id: str, *, acgs_dir: Path = Path(".acgs")) -> dict[str, Any]:
    task_id = _validate_task_id(task_id)
    evidence_dir = acgs_dir / "evidence"
    audit_path = evidence_dir / f"{task_id}.audit.jsonl"
    if not audit_path.exists():
        raise FileNotFoundError(audit_path)
    events = read_audit(audit_path)
    run_metadata = _validate_pack_snapshot(events, task_id=task_id)
    signer = _load_bundle_signer()
    return _build_bundle_from_snapshot(
        audit_path=audit_path,
        bundle_path=evidence_dir / f"{task_id}.bundle.json",
        constitution_hash=run_metadata["constitution_hash"],
        workflow_hash=run_metadata["workflow_hash"],
        signer=signer,
        events=events,
    )


def _validate_pack_snapshot(
    events: list[dict[str, Any]], *, task_id: str
) -> dict[str, Any]:
    """Validate a frozen audit snapshot against the caller-pinned task identity."""

    replay_hashes(events)
    for index, event in enumerate(events):
        if event.get("task_id") != task_id:
            raise ValueError(f"audit event {index} task id does not match requested task id")
    task_metadata = _required_latest_payload(events, "task_metadata")
    if task_metadata.get("task_id") != task_id:
        raise ValueError("audit task metadata task id does not match requested task id")
    return _required_latest_payload(events, "run_metadata")


def read_audit(path: Path) -> list[dict[str, Any]]:
    return _parse_audit_bytes(path.read_bytes())


def _parse_audit_bytes(payload: bytes) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_no, line in enumerate(payload.decode("utf-8").splitlines(), start=1):
        if line.strip():
            event = json.loads(line)
            event["_line"] = line_no
            events.append(event)
    return events


def replay_hashes(events: list[dict[str, Any]]) -> str:
    previous = ZERO_HASH
    for index, event in enumerate(events):
        if event.get("event_index") != index:
            raise ValueError(
                f"audit event index mismatch at line {event.get('_line', index + 1)}"
            )
        if event.get("prev_hash") != previous:
            raise ValueError(f"audit prev_hash mismatch at event {index}")
        observed_hash = event.get("event_hash")
        payload = {k: v for k, v in event.items() if k not in {"event_hash", "_line"}}
        expected_hash = sha256_text(canonical_json(payload))
        if observed_hash != expected_hash:
            raise ValueError(f"audit event_hash mismatch at event {index}")
        previous = observed_hash
    return previous


def run_local_command(
    command: str,
    *,
    cwd: Path,
    command_allowlist: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    effective_allowlist = _select_safe_commands(command_allowlist)
    argv = _resolve_command(command, command_allowlist=effective_allowlist)
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=_scrubbed_env(),
    )
    return {
        "command": command,
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "passed": completed.returncode == 0,
    }


def run_task(task_path: Path, *, repo_root: Path = Path(".")) -> RunResult:
    repo_root = repo_root.resolve()
    acgs_dir = repo_root / ".acgs"
    constitution_path = acgs_dir / "constitution.yaml"
    swarm_path = acgs_dir / "swarm.yaml"
    constitution = _load_yaml(constitution_path)
    swarm = _load_yaml(swarm_path)
    task = _load_task(task_path.resolve())
    evidence_dir = acgs_dir / "evidence"
    audit_path = evidence_dir / f"{task.task_id}.audit.jsonl"
    bundle_path = evidence_dir / f"{task.task_id}.bundle.json"
    signer = _load_bundle_signer()
    for evidence_path in (audit_path, bundle_path):
        if evidence_path.exists():
            raise FileExistsError(evidence_path)
    audit_descriptor = _claim_exclusive_file(audit_path, readable=True)
    try:
        bundle_descriptor = _claim_exclusive_file(bundle_path)
    except Exception:
        os.close(audit_descriptor)
        raise
    logger = AuditLogger(audit_path, task.task_id, _descriptor=audit_descriptor)
    try:
        return _run_claimed_task(
            repo_root=repo_root,
            constitution_path=constitution_path,
            swarm_path=swarm_path,
            constitution=constitution,
            swarm=swarm,
            task=task,
            logger=logger,
            bundle_path=bundle_path,
            bundle_descriptor=bundle_descriptor,
            signer=signer,
        )
    finally:
        logger.close()
        os.close(bundle_descriptor)


def _run_claimed_task(
    *,
    repo_root: Path,
    constitution_path: Path,
    swarm_path: Path,
    constitution: dict[str, Any],
    swarm: dict[str, Any],
    task: TaskSpec,
    logger: AuditLogger,
    bundle_path: Path,
    bundle_descriptor: int,
    signer: BundleSigner | None,
) -> RunResult:
    constitution_hash = hash_yaml_payload(constitution)
    workflow_hash = hash_yaml_payload(swarm)
    policy = PolicyEngine(constitution, swarm, repo_root)

    logger.emit(
        "observer",
        "run_metadata",
        {
            "constitution_path": str(constitution_path),
            "constitution_hash": constitution_hash,
            "constitutional_version": CONSTITUTIONAL_HASH,
            "workflow_path": str(swarm_path),
            "workflow_hash": workflow_hash,
        },
    )
    logger.emit("observer", "task_metadata", task.metadata)
    logger.emit("observer", "role_assignments", swarm.get("roles", {}))

    intake = policy.decide(
        "intake",
        str(task.path),
        task_exists=task.path.exists(),
        task_content=task.content.strip(),
    )
    _record_decision(logger, intake)
    if intake.outcome != ALLOW:
        return _finish(
            logger,
            bundle_path,
            constitution_hash,
            workflow_hash,
            "blocked",
            signer=signer,
            bundle_descriptor=bundle_descriptor,
        )

    _transition(policy, logger, "intake_pending->planned")
    logger.emit(
        "proposer",
        "plan",
        {
            "summary": "Run task through proposer, executor, validator, observer governance gates.",
            "adapter": _executor_adapter_name(swarm),
            "actions": [
                "intake",
                "tool_call",
                "file_write",
                "state_transition",
                "handoff",
            ],
        },
    )

    _transition(policy, logger, "planned->executing")
    file_changes: list[dict[str, Any]] = []
    tests_run: list[dict[str, Any]] = []
    blocked = False
    human_review_required = False
    for action in _load_actions(swarm, task):
        if action.kind == "tool":
            blocked = _handle_tool_action(policy, logger, action, repo_root) or blocked
        elif action.kind == "test":
            blocked = (
                _handle_test_action(policy, logger, action, repo_root, tests_run)
                or blocked
            )
        elif action.kind == "write":
            result = _handle_write_action(
                policy, logger, action, repo_root, file_changes
            )
            blocked = result["blocked"] or blocked
            human_review_required = (
                result["human_review_required"] or human_review_required
            )

    _transition(policy, logger, "executing->validating")
    handoff = policy.decide("handoff", "human-review", tests_run=tests_run)
    _record_decision(logger, handoff)
    logger.emit(
        "validator",
        "validation",
        {
            "policy_compliant": not blocked and handoff.outcome == ALLOW,
            "human_review_required": human_review_required,
            "file_changes": file_changes,
            "tests_run": tests_run,
        },
    )

    if blocked or handoff.outcome == DENY:
        final_state = "blocked"
    elif human_review_required:
        final_state = "human_review_required"
    else:
        final_state = "handoff_ready"
    _transition(policy, logger, f"validating->{final_state}")
    return _finish(
        logger,
        bundle_path,
        constitution_hash,
        workflow_hash,
        final_state,
        signer=signer,
        bundle_descriptor=bundle_descriptor,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _failed_bundle_verification(
    error: str,
    *,
    expected_chain_hash: Any = None,
    event_count: int = 0,
    signature_status: str = "invalid",
) -> dict[str, Any]:
    return {
        "ok": False,
        "chain_ok": False,
        "summary_ok": False,
        "chain_hash": None,
        "expected_chain_hash": expected_chain_hash,
        "event_count": event_count,
        "signature_status": signature_status,
        "summary_mismatches": [],
        "error": error,
    }


def verify_bundle(
    bundle_path: Path, *, trusted_public_keys: dict[str, str] | None = None
) -> dict[str, Any]:
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _failed_bundle_verification(f"invalid bundle: {exc}")
    if not isinstance(bundle, dict):
        return _failed_bundle_verification("bundle must be an object")

    events = bundle.get("audit_events")
    signature_status = _verify_bundle_signature(bundle, trusted_public_keys)
    if not isinstance(events, list):
        return _failed_bundle_verification(
            "audit_events must be a list",
            expected_chain_hash=bundle.get("chain_hash"),
            signature_status=signature_status,
        )
    try:
        chain_hash = replay_hashes(events)
        derived_summary = _derived_bundle_summary(events)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        return {
            "ok": False,
            "chain_ok": False,
            "summary_ok": False,
            "chain_hash": None,
            "expected_chain_hash": bundle.get("chain_hash"),
            "event_count": len(events),
            "signature_status": signature_status,
            "summary_mismatches": [],
            "error": str(exc),
        }
    chain_ok = chain_hash == bundle.get("chain_hash")
    # Attestation success requires replay, derived summaries, schema v2, and an
    # out-of-band trust anchor. Individual diagnostics remain available on failure.
    summary_mismatches = [
        field
        for field in _BUNDLE_SUMMARY_FIELDS
        if bundle.get(field) != derived_summary[field]
    ]
    summary_ok = not summary_mismatches
    schema_ok = bundle.get("schema_version") == BUNDLE_SCHEMA_VERSION
    ok = schema_ok and chain_ok and summary_ok and signature_status == "valid"
    error = None
    if not schema_ok:
        error = (
            f"unsupported bundle schema {bundle.get('schema_version')!r}; "
            f"expected {BUNDLE_SCHEMA_VERSION}"
        )
    elif not chain_ok:
        error = "bundle chain_hash does not match embedded audit events"
    elif not summary_ok:
        error = "bundle summary mismatch: " + ", ".join(summary_mismatches)
    elif signature_status != "valid":
        error = f"bundle signature is not trusted and valid: {signature_status}"
    return {
        "ok": ok,
        "chain_ok": chain_ok,
        "summary_ok": summary_ok,
        "chain_hash": chain_hash,
        "expected_chain_hash": bundle.get("chain_hash"),
        "event_count": len(events),
        "signature_status": signature_status,
        "summary_mismatches": summary_mismatches,
        **({"error": error} if error else {}),
    }


def _executor_adapter_name(swarm: dict[str, Any]) -> str:
    executor = (swarm.get("roles") or {}).get("executor") or {}
    return str(executor.get("adapter", "mock"))


def _finish(
    logger: AuditLogger,
    bundle_path: Path,
    constitution_hash: str,
    workflow_hash: str,
    final_state: str,
    *,
    signer: BundleSigner | None = None,
    bundle_descriptor: int | None = None,
) -> RunResult:
    logger.emit("observer", "final_state", {"state": final_state})
    bundle = _build_bundle_from_snapshot(
        audit_path=logger.path,
        bundle_path=bundle_path,
        constitution_hash=constitution_hash,
        workflow_hash=workflow_hash,
        signer=signer,
        events=logger.read_events(),
        bundle_descriptor=bundle_descriptor,
    )
    return RunResult(
        task_id=logger.task_id,
        final_state=final_state,
        audit_path=logger.path,
        bundle_path=bundle_path,
        chain_hash=bundle["chain_hash"],
        signed=signer is not None,
    )


def _handle_test_action(
    policy: PolicyEngine,
    logger: AuditLogger,
    action: Action,
    repo_root: Path,
    tests_run: list[dict[str, Any]],
) -> bool:
    decision = policy.decide("tool_call", action.value)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        return True
    event = run_local_command(
        action.value, cwd=repo_root, command_allowlist=policy.command_allowlist
    )
    tests_run.append(event)
    logger.emit("validator", "test_run", event)
    return not event["passed"]


def _handle_tool_action(
    policy: PolicyEngine, logger: AuditLogger, action: Action, repo_root: Path
) -> bool:
    decision = policy.decide("tool_call", action.value)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        return True
    event = run_local_command(
        action.value, cwd=repo_root, command_allowlist=policy.command_allowlist
    )
    logger.emit("executor", "tool_event", event)
    return event["returncode"] != 0


def _handle_write_action(
    policy: PolicyEngine,
    logger: AuditLogger,
    action: Action,
    repo_root: Path,
    file_changes: list[dict[str, Any]],
) -> dict[str, bool]:
    decision, target = policy._evaluate_file_write(action.value)
    _record_decision(logger, decision)
    if decision.outcome == REVIEW:
        return {"blocked": False, "human_review_required": True}
    if decision.outcome != ALLOW:
        return {"blocked": True, "human_review_required": False}
    if target is None:
        raise AssertionError("allowed write must have a canonical target")
    change = _write_file(repo_root, target, action.content)
    file_changes.append(change)
    logger.emit("executor", "file_change", change)
    return {"blocked": False, "human_review_required": False}


def _latest_payload(events: list[dict[str, Any]], event_type: str) -> dict[str, Any]:
    for event in reversed(events):
        if event.get("event_type") == event_type:
            payload = event.get("payload")
            return payload if isinstance(payload, dict) else {"value": payload}
    return {}


def _load_actions(swarm: dict[str, Any], task: TaskSpec) -> list[Action]:
    raw_adapters = swarm.get("adapters")
    adapters = raw_adapters if isinstance(raw_adapters, dict) else {}
    adapter_name = _executor_adapter_name(swarm)
    raw_config = adapters.get(adapter_name)
    adapter_config = raw_config if isinstance(raw_config, dict) else {}
    return build_adapter(adapter_name, adapter_config).propose_actions(task)


def _load_task(path: Path) -> TaskSpec:
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    metadata = {
        "task_id": _task_id(path, content),
        "task_path": str(path),
        "task_hash": sha256_text(content),
    }
    return TaskSpec(
        task_id=metadata["task_id"], path=path, content=content, metadata=metadata
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        payload = _parse_simple_yaml(text)
    else:
        payload = yaml.safe_load(text)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return payload


def _parse_inline_mapping(value: str) -> dict[str, Any]:
    inner = value.strip()[1:-1].strip()
    if not inner:
        return {}
    result: dict[str, Any] = {}
    for part in inner.split(","):
        key, sep, raw_value = part.partition(":")
        if not sep:
            raise ValueError(f"unsupported inline YAML mapping: {value}")
        result[key.strip()] = _parse_scalar(raw_value.strip())
    return result


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return _parse_inline_mapping(value)
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]
    pending: tuple[int, dict[str, Any], str] | None = None
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if pending and indent > pending[0]:
            parent = pending[1]
            key = pending[2]
            container: dict[str, Any] | list[Any] = (
                [] if stripped.startswith("- ") else {}
            )
            parent[key] = container
            stack.append((indent - 1, container))
            pending = None
        container = stack[-1][1]
        if stripped.startswith("- "):
            if not isinstance(container, list):
                raise ValueError("unsupported YAML list placement")
            container.append(_parse_scalar(stripped[2:].strip()))
            continue
        key, sep, value = stripped.partition(":")
        if not sep or not isinstance(container, dict):
            raise ValueError(f"unsupported YAML line: {line}")
        if value.strip():
            container[key.strip()] = _parse_scalar(value.strip())
        else:
            pending = (indent, container, key.strip())
    return root


def _payloads(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [
        event["payload"] for event in events if event.get("event_type") == event_type
    ]


def _record_decision(logger: AuditLogger, decision: PolicyDecision) -> None:
    logger.emit("validator", "policy_decision", decision.as_dict())


def _validate_task_id(task_id: str) -> str:
    if (
        task_id in {"", ".", ".."}
        or re.fullmatch(r"[A-Za-z0-9_.-]+", task_id) is None
    ):
        raise ValueError("task id must be a safe filename component")
    return task_id


def _task_id(path: Path, content: str) -> str:
    match = re.search(r"(?m)^task_id:\s*(.*?)\s*$", content)
    if match:
        return _validate_task_id(match.group(1))
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", path.stem).strip("-") or "task"
    return _validate_task_id(f"{safe_stem}-{sha256_text(content)[:10]}")


def _transition(policy: PolicyEngine, logger: AuditLogger, transition: str) -> None:
    decision = policy.decide("state_transition", transition)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        raise RuntimeError(f"state transition denied: {transition}")
    logger.emit("observer", "state_transition", {"transition": transition})


def _require_safe_write_primitives() -> None:
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    missing = [name for name in required_flags if not hasattr(os, name)]
    if not _HAS_SAFE_DIR_FD_OPERATIONS:
        missing.append("dir_fd file operations")
    if not _HAS_SAFE_DIR_FD_REPLACE:
        missing.append("dir_fd atomic replace")
    if missing:
        raise RuntimeError(
            "safe governed writes are unsupported on this platform: "
            + ", ".join(missing)
        )


def _hash_open_file(file_descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(file_descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _open_directory(name: str | Path, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    return os.open(name, flags, dir_fd=dir_fd)


def _write_file(
    repo_root: Path, target: Path, content: str | None
) -> dict[str, Any]:
    _require_safe_write_primitives()
    repo_root = repo_root.resolve()
    if not target.is_relative_to(repo_root):
        raise ValueError("file write target escapes repository root")
    relative = target.relative_to(repo_root)
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("file write target is not a safe repository-relative path")

    directory_fds: list[int] = []
    temporary_fd: int | None = None
    temporary_name: str | None = None
    before_hash: str | None = None
    data = (content or "").encode("utf-8")
    try:
        current_fd = _open_directory(repo_root)
        directory_fds.append(current_fd)
        for component in relative.parts[:-1]:
            try:
                child_fd = _open_directory(component, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                child_fd = _open_directory(component, dir_fd=current_fd)
            directory_fds.append(child_fd)
            current_fd = child_fd

        filename = relative.parts[-1]
        read_flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        existing_mode: int | None = None
        try:
            existing_fd = os.open(filename, read_flags, dir_fd=current_fd)
        except FileNotFoundError:
            pass
        else:
            try:
                existing_stat = os.fstat(existing_fd)
                if not stat.S_ISREG(existing_stat.st_mode):
                    raise ValueError("file write target must be a regular file")
                existing_mode = stat.S_IMODE(existing_stat.st_mode)
                before_hash = _hash_open_file(existing_fd)
            finally:
                os.close(existing_fd)

        create_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        for _ in range(32):
            candidate = f".{filename}.acgs-{secrets.token_hex(8)}.tmp"
            try:
                temporary_fd = os.open(
                    candidate, create_flags, 0o666, dir_fd=current_fd
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_fd is None or temporary_name is None:
            raise FileExistsError("could not allocate a unique temporary write target")

        if existing_mode is not None:
            os.fchmod(temporary_fd, existing_mode)
        remaining = memoryview(data)
        while remaining:
            written = os.write(temporary_fd, remaining)
            if written <= 0:
                raise OSError("short write while creating governed file")
            remaining = remaining[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=current_fd,
            dst_dir_fd=current_fd,
        )
        temporary_name = None
        os.fsync(current_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_name is not None and directory_fds:
            try:
                os.unlink(temporary_name, dir_fd=directory_fds[-1])
            except FileNotFoundError:
                pass
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)

    return {
        "path": relative.as_posix(),
        "before_hash": before_hash,
        "after_hash": hashlib.sha256(data).hexdigest(),
        "action": "write",
    }


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
