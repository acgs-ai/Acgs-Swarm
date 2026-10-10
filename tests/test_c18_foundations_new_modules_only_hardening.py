"""Rework regressions for the C18 foundation helpers."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "identifier",
    [
        pytest.param(" leading", id="leading-space"),
        pytest.param("trailing ", id="trailing-space"),
        pytest.param("a\u00a0b", id="nbsp"),
        pytest.param("a\u3000b", id="ideographic-space"),
        pytest.param("a\u2028b", id="line-separator"),
        pytest.param("a\u2029b", id="paragraph-separator"),
        pytest.param("a\u034fb", id="combining-grapheme-joiner"),
        pytest.param("a\ufe0f", id="variation-selector"),
        pytest.param("a\u3164b", id="hangul-filler"),
        pytest.param("a\u115fb", id="leading-hangul-filler"),
        pytest.param("a\u2800b", id="braille-blank"),
        pytest.param("e\u0301", id="nfd"),
        pytest.param("é", id="nfc"),
        pytest.param("аgent", id="cyrillic-lookalike"),
        pytest.param("ａｇｅｎｔ", id="fullwidth-lookalike"),
        pytest.param("a\ue000b", id="private-use"),
        pytest.param("a\u0378b", id="unassigned"),
        pytest.param("../../etc/passwd", id="parent-path"),
        pytest.param("a/b", id="forward-slash"),
        pytest.param("a\\b", id="backslash"),
        pytest.param("\u0301", id="lone-combining-mark"),
        pytest.param("a" * (1024 * 1024), id="one-megabyte"),
    ],
)
def test_require_plain_id_rejects_non_plain_identifiers(identifier: str) -> None:
    from constitutional_swarm.framing import require_plain_id

    with pytest.raises(ValueError):
        require_plain_id(identifier)


@pytest.mark.parametrize(
    "identifier",
    [
        "agent-0001",
        "review-agent",
        "miner-01",
        "550e8400e29b41d4a716446655440000",
        "a" * 64,
        "no-log:" + "b" * 64,
        "log:42:" + "c" * 64,
        "5FP9ECygsPrdLA9hoc1f4fHws1poDSB18E9tEqRRZueTFTuo",
        "A" + "z" * 127,
        "task.name_with:parts-1",
    ],
)
def test_require_plain_id_accepts_repository_identifier_formats(identifier: str) -> None:
    from constitutional_swarm.framing import require_plain_id

    assert require_plain_id(identifier) == identifier


@pytest.mark.parametrize("identifier", ["a" * 129, "agent..child", ".agent", "-agent"])
def test_require_plain_id_rejects_invalid_ascii_shape(identifier: str) -> None:
    from constitutional_swarm.framing import require_plain_id

    with pytest.raises(ValueError):
        require_plain_id(identifier)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(r'"\ud800"', id="root-high"),
        pytest.param(r'"\udfff"', id="root-low"),
        pytest.param(r'["\ud800"]', id="list"),
        pytest.param(r'{"outer":{"value":"\udfff"}}', id="nested-value"),
        pytest.param(r'{"\ud800":1}', id="key"),
    ],
)
def test_strict_json_rejects_decoded_lone_surrogates(raw: str) -> None:
    from constitutional_swarm.strict_json import StrictJSONError, loads

    with pytest.raises(StrictJSONError, match="UTF-8"):
        loads(raw, max_bytes=64)


def test_strict_json_accepts_valid_surrogate_pair() -> None:
    from constitutional_swarm.strict_json import loads

    assert loads(r'"\ud83d\ude00"', max_bytes=32) == "😀"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("\ud800", id="root-value"),
        pytest.param(["\udfff"], id="list-value"),
        pytest.param({"nested": "\ud800"}, id="nested-value"),
        pytest.param({"\udfff": 1}, id="key"),
    ],
)
def test_canonical_dumps_rejects_lone_surrogates(value: object) -> None:
    from constitutional_swarm.strict_json import StrictJSONError, canonical_dumps

    with pytest.raises(StrictJSONError, match="UTF-8"):
        canonical_dumps(value)


def test_canonical_dumps_preserves_documented_number_and_key_distinctions() -> None:
    from constitutional_swarm.strict_json import canonical_dumps

    assert canonical_dumps([-0.0, 0.0, 1.0, 1]) == "[-0.0,0.0,1.0,1]"
    assert canonical_dumps({"é": 1, "z": 2}) == r'{"z":2,"\u00e9":1}'


def test_duplicate_key_hook_rejects_surrogate_key() -> None:
    from constitutional_swarm.strict_json import StrictJSONError, reject_duplicate_keys

    with pytest.raises(StrictJSONError, match="UTF-8"):
        reject_duplicate_keys([("\ud800", 1)])


@pytest.mark.parametrize(
    ("operation", "args", "kwargs"),
    [
        ("loads", ('{"a":1,"a":2}',), {"max_bytes": 32}),
        ("loads", ("NaN",), {"max_bytes": 3}),
        ("loads", ("{",), {"max_bytes": 1}),
        ("loads", ("[]",), {"max_bytes": 2, "max_depth": 0}),
        ("loads", (b'"\xff"',), {"max_bytes": 3}),
        ("loads", ("0",), {"max_bytes": 0}),
        ("loads", ("9" * 5000,), {"max_bytes": 5000}),
        ("canonical_dumps", ([float("inf")],), {}),
    ],
)
def test_strict_json_uses_one_policy_exception(
    operation: str, args: tuple[object, ...], kwargs: dict[str, object]
) -> None:
    from constitutional_swarm import strict_json

    function = getattr(strict_json, operation)
    with pytest.raises(strict_json.StrictJSONError):
        function(*args, **kwargs)


def test_canonical_cycle_uses_policy_exception() -> None:
    from constitutional_swarm.strict_json import StrictJSONError, canonical_dumps

    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(StrictJSONError, match="circular"):
        canonical_dumps(cyclic)


def test_strict_json_normalizes_recursion_to_policy_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from constitutional_swarm import strict_json

    def recurse(*args: object, **kwargs: object) -> object:
        raise RecursionError("decoder recursion")

    monkeypatch.setattr(strict_json.json, "loads", recurse)
    with pytest.raises(strict_json.StrictJSONError, match="recursion"):
        strict_json.loads("null", max_bytes=4)


@pytest.mark.parametrize("mode", [0o4600, 0o2600, 0o1600])
def test_require_private_fd_rejects_special_permission_bits(tmp_path: Path, mode: int) -> None:
    from constitutional_swarm.secure_files import PrivateFileError, require_private_fd

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(mode)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(PrivateFileError, match="permission"):
            require_private_fd(fd)
    finally:
        os.close(fd)


def test_require_private_fd_rejects_path_only_descriptor(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import PrivateFileError, require_private_fd

    if not hasattr(os, "O_PATH"):
        pytest.skip("O_PATH is unavailable")
    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    fd = os.open(path, os.O_PATH)
    try:
        with pytest.raises(PrivateFileError, match="O_PATH"):
            require_private_fd(fd)
    finally:
        os.close(fd)


def test_open_private_file_uses_noctty_and_clears_nonblocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    observed_flags: list[int] = []
    real_open = secure_files.os.open

    def recording_open(candidate: str, flags: int) -> int:
        observed_flags.append(flags)
        return real_open(candidate, flags)

    monkeypatch.setattr(secure_files.os, "open", recording_open)
    fd = secure_files.open_private_file(path)
    try:
        assert observed_flags[0] & os.O_NOCTTY
        assert not (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK)
    finally:
        os.close(fd)


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK", "O_NOCTTY"])
@pytest.mark.parametrize(
    ("case", "value"),
    [
        pytest.param("missing", None, id="missing"),
        pytest.param("value", 0, id="zero"),
        pytest.param("value", False, id="false"),
        pytest.param("value", object(), id="non-integer"),
    ],
)
def test_open_private_file_validates_required_flags_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag: str,
    case: str,
    value: object,
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    if case == "missing":
        monkeypatch.delattr(secure_files.os, flag)
    else:
        monkeypatch.setattr(secure_files.os, flag, value)

    def unexpected_open(candidate: str, flags: int) -> int:
        raise AssertionError("os.open must not run before flag validation")

    monkeypatch.setattr(secure_files.os, "open", unexpected_open)
    with pytest.raises(RuntimeError, match=flag):
        secure_files.open_private_file(path)


def test_open_private_file_closes_fd_when_flag_clearing_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    opened: list[int] = []
    real_open = secure_files.os.open
    real_fcntl = secure_files.fcntl.fcntl

    def recording_open(candidate: str, flags: int) -> int:
        fd = real_open(candidate, flags)
        opened.append(fd)
        return fd

    def failing_fcntl(fd: int, command: int, arg: int = 0) -> int:
        if command == secure_files.fcntl.F_SETFL:
            raise OSError("cannot clear flags")
        return real_fcntl(fd, command, arg)

    monkeypatch.setattr(secure_files.os, "open", recording_open)
    monkeypatch.setattr(secure_files.fcntl, "fcntl", failing_fcntl)
    with pytest.raises(OSError, match="clear flags"):
        secure_files.open_private_file(path)
    with pytest.raises(OSError) as exc_info:
        os.fstat(opened[0])
    assert exc_info.value.errno == errno.EBADF


def test_private_file_yields_binary_stream_and_closes_on_exit(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import private_file

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    with private_file(path) as stream:
        assert stream.read() == b"secret"
        assert stream.closed is False
    assert stream.closed is True


def test_private_file_closes_on_body_exception(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import private_file

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    with pytest.raises(RuntimeError, match="body"):
        with private_file(path) as stream:
            raise RuntimeError("body")
    assert stream.closed is True


def test_private_file_closes_raw_fd_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    opened: list[int] = []
    real_open_private_file = secure_files.open_private_file

    def recording_open_private_file(candidate: str | os.PathLike[str]) -> int:
        fd = real_open_private_file(candidate)
        opened.append(fd)
        return fd

    def failing_fdopen(fd: int, mode: str):
        raise OSError("fdopen failed")

    monkeypatch.setattr(secure_files, "open_private_file", recording_open_private_file)
    monkeypatch.setattr(secure_files.os, "fdopen", failing_fdopen)
    with pytest.raises(OSError, match="fdopen"):
        with secure_files.private_file(path):
            pass
    with pytest.raises(OSError) as exc_info:
        os.fstat(opened[0])
    assert exc_info.value.errno == errno.EBADF


def test_secure_file_policy_rejections_share_exception_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY)
    metadata = os.fstat(fd)
    try:
        for changes in (
            {"st_mode": (metadata.st_mode & ~stat.S_IFMT(metadata.st_mode)) | stat.S_IFDIR},
            {"st_uid": metadata.st_uid + 1},
            {"st_mode": metadata.st_mode | 0o040},
            {"st_nlink": 2},
        ):
            values = {
                "st_mode": metadata.st_mode,
                "st_uid": metadata.st_uid,
                "st_nlink": metadata.st_nlink,
                **changes,
            }
            monkeypatch.setattr(
                secure_files.os,
                "fstat",
                lambda candidate, values=values: type("Stat", (), values)(),
            )
            with pytest.raises(secure_files.PrivateFileError):
                secure_files.require_private_fd(fd)
    finally:
        os.close(fd)
