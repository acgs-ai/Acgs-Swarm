"""External digest, fresh-process replay and Linux cleanup evidence helpers.

These checks collect evidence; they do not authorize observer renewal or turn a
functional run into campaign qualification. No private key or database is copied.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import sysconfig
from pathlib import Path, PurePosixPath
from typing import Any


def read_external_digests(manifest: Path) -> dict[str, str]:
    """Check an external SHA256SUMS file and all its contained regular files."""
    if manifest.is_symlink():
        raise ValueError("external manifest symlink rejected")
    root = manifest.resolve().parent
    result = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00-\x20]+)", line)
        if match is None:
            raise ValueError("invalid external digest record")
        digest, name = match.groups()
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or any(p in {".", ".."} for p in relative.parts)
            or relative.as_posix() != name
            or "\\" in name
        ):
            raise ValueError("external digest path escapes or is noncanonical")
        if name in result:
            raise ValueError("duplicate external digest path")
        path = root
        for component in relative.parts:
            path /= component
            if path.is_symlink():
                raise ValueError("external digest file symlink rejected")
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError("external digest requires a contained regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("external file digest mismatch")
        result[name] = digest
    if not result:
        raise ValueError("empty external digest manifest")
    return result


def audit_replays(
    manifest: Path,
    *,
    cli: Path,
    timeout_seconds: int = 1800,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Execute each manifest ledger/manifest in a new uninstrumented Python CLI.

    The supplied CLI itself must be source-pinned by the caller's capsule. A
    successful result here is only functional replay, not a Phase1 gate proof.
    """
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("invalid replay timeout")
    if expected_plan_sha256 is not None and (
        type(expected_plan_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256) is None
    ):
        raise ValueError("invalid external plan SHA256")
    entries = read_external_digests(manifest)
    # -I -S excludes sitecustomize, usercustomize and executable .pth files.
    # Add only this interpreter's explicit package directories, never call site.
    package_paths = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    bootstrap = (
        f"import sys,runpy; sys.path.extend({package_paths!r}); "
        "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR"}
    }
    replays = []
    for name, digest in entries.items():
        path = manifest.resolve().parent / name
        if path.name == "repetition.json":
            arguments = ["verify-repetition", "--manifest", str(path)]
        elif re.fullmatch(r"window-[0-9]{3}\.jsonl", path.name):
            arguments = ["verify", "--ledger", str(path)]
        else:
            raise ValueError("external replay manifest contains a non-ledger artifact")
        command = [sys.executable, "-I", "-S", "-c", bootstrap, str(cli.resolve()), *arguments, "--expected-sha256", digest]
        if expected_plan_sha256 is not None:
            command.extend(("--expected-plan-sha256", expected_plan_sha256))
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=environment,
                check=False,
            )
            try:
                output = json.loads(completed.stdout)
            except (ValueError, TypeError):
                output = None
            verified = (
                completed.returncode == 0
                and type(output) is dict
                and output.get("status") == "verified"
                and type(output.get("result")) is dict
                and output["result"].get("campaign_eligible") is False
            )
            row = {
                "filename": name,
                "sha256": digest,
                "command": command,
                "returncode": completed.returncode,
                "stdout": output,
                "stderr": completed.stderr,
                "verified": verified,
            }
        except subprocess.TimeoutExpired:
            row = {
                "filename": name, "sha256": digest, "command": command,
                "returncode": None, "stdout": None, "stderr": "replay timeout",
                "verified": False,
            }
        replays.append(row)
    # Recheck bytes after the processes finish; verification must not race an
    # ordinary in-place mutation of the externally pinned ledger collection.
    if read_external_digests(manifest) != entries:
        raise ValueError("external digest collection changed during audit")
    return {
        "revision": "w2-renewal-fresh-process-replays-v1",
        "campaign_eligible": False,
        "fresh_process": True,
        "instrumented": False,
        "expected_plan_sha256": expected_plan_sha256,
        "replays": replays,
        "all_verified": all(row["verified"] for row in replays),
    }


def scan_owned_resources(run_directory: Path, *, owned_pids: list[int]) -> dict[str, Any]:
    """Inspect owned PIDs plus all visible Linux FDs pointing into the run tree.

    Inaccessible process descriptor tables are reported, not treated as proof of
    absence. This is observation only: never kill a PID discovered by scanning.
    """
    if any(type(pid) is not int or pid <= 0 for pid in owned_pids):
        raise ValueError("invalid owned PID")
    if not Path("/proc/self/fd").is_dir():
        raise RuntimeError("Linux /proc required for process/descriptor evidence")
    root = run_directory.resolve()
    live = []
    for pid in sorted(set(owned_pids)):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            pass
        live.append(pid)
    descriptors = []
    inaccessible = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        pid = int(process.name)
        try:
            table = list((process / "fd").iterdir())
            for descriptor in table:
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                if target.endswith(" (deleted)"):
                    target = target[:-10]
                resolved = Path(target)
                if resolved.is_absolute() and resolved.is_relative_to(root):
                    descriptors.append({"pid": pid, "fd": int(descriptor.name), "relative_path": str(resolved.relative_to(root))})
        except FileNotFoundError:
            continue
        except PermissionError:
            inaccessible.append(pid)
    unavailable_owned = sorted(set(inaccessible) & set(owned_pids))
    return {
        "live_owned_pids": live,
        "open_run_descriptors": descriptors,
        "inaccessible_pids": inaccessible,
        "unavailable_owned_pids": unavailable_owned,
        "owned_pids_absent": not live,
        "fd_absence_proven": not descriptors and not inaccessible,
        "clean": not live and not descriptors and not inaccessible,
    }
