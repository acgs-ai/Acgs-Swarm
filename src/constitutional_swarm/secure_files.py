"""Fail-closed validation for existing private files and descriptors.

Validation is a single ``fstat`` snapshot; it does not prevent later mutation.
``open_private_file`` owns and returns a raw descriptor on success, so callers
must close it.  ``O_NOFOLLOW`` protects only the final path component and does
not provide confinement against hostile ancestor-directory replacement.

Policy failures (non-regular files, wrong ownership, unsafe modes, multiple
links, and ``O_PATH`` descriptors) raise ``PrivateFileError``. Wrong argument
types raise ``TypeError``; invalid scalar arguments raise ``ValueError``;
missing safety primitives raise ``RuntimeError``; native syscall failures remain
``OSError``. ``require_private_fd`` accepts readable and read/write descriptors,
but never accepts an ``O_PATH`` descriptor.
"""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from typing import BinaryIO, Iterator, cast

__all__ = ["PrivateFileError", "open_private_file", "private_file", "require_private_fd"]


class PrivateFileError(PermissionError):
    """Raised when a descriptor violates the private-file policy."""


def require_private_fd(fd: int) -> None:
    """Require one borrowed descriptor snapshot to identify a private file.

    The borrowed descriptor is never closed by this function.
    """
    if type(fd) is not int:
        raise TypeError("fd must be an exact integer")
    if fd < 0:
        raise ValueError("fd must be non-negative")
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        raise RuntimeError("os.geteuid is required for private file validation")

    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    path_only = getattr(os, "O_PATH", 0)
    if type(path_only) is int and path_only > 0 and descriptor_flags & path_only:
        raise PrivateFileError("O_PATH descriptors are not readable private files")

    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise PrivateFileError("descriptor must refer to a regular file")
    if metadata.st_uid != geteuid():
        raise PrivateFileError("private file owner must be the effective user")
    if stat.S_IMODE(metadata.st_mode) & 0o7077:
        raise PrivateFileError("private file permissions contain unsafe mode bits")
    if metadata.st_nlink != 1:
        raise PrivateFileError("private file must have exactly one link")


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value <= 0:
        raise RuntimeError(f"{name} is required for private file opening")
    return value


def open_private_file(path: str | os.PathLike[str]) -> int:
    """Open and validate an existing final path component, returning its fd."""
    resolved = os.fspath(path)
    if type(resolved) is not str:
        raise TypeError("path must resolve to an exact string")
    if not resolved:
        raise ValueError("path must not be empty")

    flags = os.O_RDONLY
    flags |= _required_open_flag("O_NOFOLLOW")
    flags |= _required_open_flag("O_NONBLOCK")
    flags |= _required_open_flag("O_NOCTTY")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if type(cloexec) is int and cloexec > 0:
        flags |= cloexec

    fd = os.open(resolved, flags)
    owned = True
    try:
        os.set_inheritable(fd, False)
        require_private_fd(fd)
        status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, status_flags & ~os.O_NONBLOCK)
        owned = False
        return fd
    finally:
        if owned:
            os.close(fd)


@contextmanager
def private_file(path: str | os.PathLike[str]) -> Iterator[BinaryIO]:
    """Yield a readable binary stream and close it when the context exits."""
    fd = open_private_file(path)
    try:
        stream = cast(BinaryIO, os.fdopen(fd, "rb"))
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream
