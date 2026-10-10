"""Shared pinned-TLC helpers for the TLC runner scripts.

The jar is never executed from the caller-supplied path. Each runner copies it
into its private temporary directory, hashes that copy, and executes only the
copy, so a swap of the original after the digest check cannot reach TLC.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

TLC_JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLC_VERSION_LINE = "TLC2 Version 2.19 of 08 August 2024"
STAGED_JAR_NAME = "tla2tools-pinned.jar"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_jar(source: Path, private_dir: Path) -> Path:
    """Copy ``source`` into ``private_dir``; the caller must hash the returned copy."""
    if not source.is_file():
        raise FileNotFoundError(f"TLC jar is not a regular file: {source}")
    staged = private_dir / STAGED_JAR_NAME
    shutil.copyfile(source, staged)
    staged.chmod(0o400)
    return staged


def resolve_java(command: str) -> str:
    """Resolve ``command`` once to an absolute path; unresolved names fail at launch."""
    return shutil.which(command) or command
