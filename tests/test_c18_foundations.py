"""Regression tests for the C18 security foundation helpers."""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class _IntSubclass(int):
    pass


class _ListSubclass(list[object]):
    pass


@pytest.mark.parametrize(
    "raw",
    ['{"key":1,"key":2}', '{"outer":{"key":1,"key":2}}'],
)
def test_strict_json_rejects_duplicate_keys(raw: str) -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(ValueError, match="duplicate"):
        loads(raw, max_bytes=128)


def test_duplicate_key_hook_is_available_independently() -> None:
    from constitutional_swarm.strict_json import reject_duplicate_keys

    assert reject_duplicate_keys([("a", 1), ("b", 2)]) == {"a": 1, "b": 2}
    with pytest.raises(ValueError, match="duplicate"):
        reject_duplicate_keys([("a", 1), ("a", 2)])


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_strict_json_rejects_nonfinite_numbers(token: str) -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(ValueError, match="finite"):
        loads(token, max_bytes=32)


@pytest.mark.parametrize("token", ["1.5", "1e2", "-2.0"])
def test_strict_json_can_reject_all_float_lexemes(token: str) -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(ValueError, match="float"):
        loads(token, max_bytes=32, allow_float=False)


def test_strict_json_allows_only_finite_floats_when_enabled() -> None:
    from constitutional_swarm.strict_json import loads

    assert loads("1.25", max_bytes=4) == 1.25


def test_strict_json_enforces_encoded_byte_limit_before_parsing() -> None:
    from constitutional_swarm.strict_json import loads

    assert loads('"é"', max_bytes=4) == "é"
    with pytest.raises(ValueError, match="byte"):
        loads('"é"', max_bytes=3)
    assert loads(bytearray(b"null"), max_bytes=4) is None
    with pytest.raises(ValueError, match="byte"):
        loads(b"null", max_bytes=3)
    with pytest.raises(ValueError, match="byte"):
        loads(bytearray(b"null"), max_bytes=3)


def test_strict_json_rejects_oversized_text_before_utf8_encoding() -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(ValueError, match="byte"):
        loads("\ud800\ud800", max_bytes=1)


def test_strict_json_rejects_malformed_utf8() -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(ValueError, match="UTF-8"):
        loads(b'"\xff"', max_bytes=3)


def test_strict_json_checks_depth_and_ignores_brackets_in_strings() -> None:
    from constitutional_swarm.strict_json import loads

    assert loads("[" * 64 + "0" + "]" * 64, max_bytes=129) is not None
    with pytest.raises(ValueError, match="depth"):
        loads("[" * 65 + "0" + "]" * 65, max_bytes=131)
    assert loads(r'{"text":"[}] \" still text"}', max_bytes=64, max_depth=1) == {
        "text": '[}] " still text'
    }
    assert loads("0", max_bytes=1, max_depth=0) == 0
    with pytest.raises(ValueError, match="depth"):
        loads("[]", max_bytes=2, max_depth=0)


def test_strict_json_default_depth_fails_before_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from constitutional_swarm import strict_json

    called = False

    def decode(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(strict_json.json, "loads", decode)
    with pytest.raises(ValueError, match="depth"):
        strict_json.loads("[" * 65 + "0" + "]" * 65, max_bytes=131)
    assert called is False


@pytest.mark.parametrize(
    ("kwargs", "exception"),
    [
        ({"max_bytes": 0}, ValueError),
        ({"max_bytes": -1}, ValueError),
        ({"max_bytes": True}, TypeError),
        ({"max_bytes": 1.0}, TypeError),
        ({"max_bytes": 1, "max_depth": -1}, ValueError),
        ({"max_bytes": 1, "max_depth": True}, TypeError),
        ({"max_bytes": 1, "allow_float": 1}, TypeError),
    ],
)
def test_strict_json_rejects_invalid_options(
    kwargs: dict[str, object], exception: type[Exception]
) -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(exception):
        loads("0", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("raw", [memoryview(b"0"), _StringSubclass("0"), _BytesSubclass(b"0")])
def test_strict_json_rejects_spoofed_or_unsupported_input(raw: object) -> None:
    from constitutional_swarm.strict_json import loads

    with pytest.raises(TypeError):
        loads(raw, max_bytes=1)  # type: ignore[arg-type]


def test_strict_json_normalizes_decoder_recursion_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from constitutional_swarm import strict_json

    def recurse(*args: object, **kwargs: object) -> object:
        raise RecursionError("decoder recursion")

    monkeypatch.setattr(strict_json.json, "loads", recurse)
    with pytest.raises(ValueError, match="recursion"):
        strict_json.loads("null", max_bytes=4)


def test_canonical_json_is_compact_sorted_and_deterministic() -> None:
    from constitutional_swarm.strict_json import canonical_dumps

    first = {"z": [3, 2, 1], "a": {"é": True}}
    second = {"a": {"é": True}, "z": [3, 2, 1]}
    expected = r'{"a":{"\u00e9":true},"z":[3,2,1]}'
    assert canonical_dumps(first) == expected
    assert canonical_dumps(second) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_nonfinite_values(value: float) -> None:
    from constitutional_swarm.strict_json import canonical_dumps

    with pytest.raises(ValueError, match="finite"):
        canonical_dumps({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        {1: "integer key"},
        {_StringSubclass("key"): "spoofed key"},
        _ListSubclass([1]),
        _IntSubclass(1),
        {"value": _StringSubclass("spoofed value")},
    ],
)
def test_canonical_json_rejects_non_json_or_spoofed_objects(value: object) -> None:
    from constitutional_swarm.strict_json import canonical_dumps

    with pytest.raises(TypeError):
        canonical_dumps(value)


def test_canonical_json_rejects_cycles_but_allows_shared_containers() -> None:
    from constitutional_swarm.strict_json import canonical_dumps

    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="circular"):
        canonical_dumps(cyclic)

    shared = [1, 2]
    assert canonical_dumps([shared, shared]) == "[[1,2],[1,2]]"


def test_canonical_json_dumps_detached_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    from constitutional_swarm import strict_json

    original = {"items": [1, 2]}
    real_dumps = strict_json.json.dumps

    def mutate_then_dump(value: object, **kwargs: object) -> str:
        original["items"].append(3)
        return real_dumps(value, **kwargs)

    monkeypatch.setattr(strict_json.json, "dumps", mutate_then_dump)
    assert strict_json.canonical_dumps(original) == '{"items":[1,2]}'
    assert original == {"items": [1, 2, 3]}


def test_framed_digest_has_frozen_known_answer() -> None:
    from constitutional_swarm.framing import framed_digest

    assert framed_digest(b"test-domain", b"raw", "text", -42).hex() == (
        "404a6a1e9b6976b81946d311666f760b40e0df9868bde166e73b6be64fbcaca0"
    )


def test_framed_digest_separates_domain_order_boundaries_and_types() -> None:
    from constitutional_swarm.framing import framed_digest

    baseline = framed_digest(b"domain-a", b"ab", b"c")
    assert baseline != framed_digest(b"domain-b", b"ab", b"c")
    assert baseline != framed_digest(b"domain-a", b"c", b"ab")
    assert baseline != framed_digest(b"domain-a", b"a", b"bc")
    assert len({framed_digest(b"domain-a", value) for value in (b"1", "1", 1)}) == 3
    assert framed_digest(b"domain-a", b"") != framed_digest(b"domain-a")


@pytest.mark.parametrize(
    ("domain", "parts"),
    [
        (b"", ()),
        ("domain", ()),
        (_BytesSubclass(b"domain"), ()),
        (b"domain", (True,)),
        (b"domain", (_BytesSubclass(b"part"),)),
        (b"domain", (_StringSubclass("part"),)),
        (b"domain", (_IntSubclass(1),)),
        (b"domain", (1.5,)),
    ],
)
def test_framed_digest_rejects_empty_or_spoofed_inputs(
    domain: object, parts: tuple[object, ...]
) -> None:
    from constitutional_swarm.framing import framed_digest

    with pytest.raises((TypeError, ValueError)):
        framed_digest(domain, *parts)  # type: ignore[arg-type]


def test_framed_digest_uses_utf8_for_text() -> None:
    from constitutional_swarm.framing import framed_digest

    prefix = b"constitutional-swarm.framed-digest.v1\x00"
    domain = b"domain"
    payload = b"s" + "é".encode()
    transcript = (
        prefix + len(domain).to_bytes(8, "big") + domain + len(payload).to_bytes(8, "big") + payload
    )
    assert framed_digest(domain, "é") == hashlib.sha256(transcript).digest()
    with pytest.raises(ValueError, match="UTF-8"):
        framed_digest(domain, "\ud800")


@pytest.mark.parametrize("identifier", ["agent-1", "review-agent", "no-log:abc123"])
def test_plain_id_preserves_visible_identifiers(identifier: str) -> None:
    from constitutional_swarm.framing import require_plain_id

    assert require_plain_id(identifier) == identifier


@pytest.mark.parametrize(
    "identifier",
    ["", "nul\x00id", "line\nid", "delete\x7fid", "c1\x85id", "bidi\u202eid", "zero\u200bid"],
)
def test_plain_id_rejects_empty_control_or_format_characters(identifier: str) -> None:
    from constitutional_swarm.framing import require_plain_id

    with pytest.raises(ValueError):
        require_plain_id(identifier)


@pytest.mark.parametrize("identifier", [b"agent", _StringSubclass("agent")])
def test_plain_id_rejects_nonexact_strings(identifier: object) -> None:
    from constitutional_swarm.framing import require_plain_id

    with pytest.raises(TypeError):
        require_plain_id(identifier)  # type: ignore[arg-type]


def test_plain_id_rejects_lone_surrogate() -> None:
    from constitutional_swarm.framing import require_plain_id

    with pytest.raises(ValueError, match="ASCII"):
        require_plain_id("agent-\ud800")


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_open_private_file_accepts_owned_private_regular_file(tmp_path: Path, mode: int) -> None:
    from constitutional_swarm.secure_files import open_private_file

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(mode)
    fd = open_private_file(path)
    try:
        assert os.read(fd, 6) == b"secret"
        assert os.get_inheritable(fd) is False
    finally:
        os.close(fd)


def test_open_private_file_rejects_public_permissions(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import open_private_file

    path = tmp_path / "public"
    path.write_bytes(b"secret")
    path.chmod(0o640)
    with pytest.raises(PermissionError, match="permission"):
        open_private_file(path)


def test_open_private_file_rejects_symlink_and_hard_link(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import PrivateFileError, open_private_file

    target = tmp_path / "target"
    target.write_bytes(b"secret")
    target.chmod(0o600)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target)
    with pytest.raises(OSError):
        open_private_file(symlink)

    hard_link = tmp_path / "hard-link"
    hard_link.hardlink_to(target)
    with pytest.raises(PrivateFileError, match="link"):
        open_private_file(target)


def test_open_private_file_rejects_directory_and_fifo_without_blocking(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import PrivateFileError, open_private_file

    tmp_path.chmod(0o700)
    with pytest.raises(PrivateFileError, match="regular"):
        open_private_file(tmp_path)

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(PrivateFileError, match="regular"):
        open_private_file(fifo)


def test_private_fd_rejects_wrong_owner_from_fstat_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY)
    real_fstat = os.fstat
    info = real_fstat(fd)
    spoofed = SimpleNamespace(
        st_mode=info.st_mode,
        st_uid=os.geteuid() + 1,
        st_nlink=info.st_nlink,
    )
    monkeypatch.setattr(secure_files.os, "fstat", lambda candidate: spoofed)
    try:
        with pytest.raises(PermissionError, match="owner"):
            secure_files.require_private_fd(fd)
        assert real_fstat(fd).st_ino == info.st_ino
    finally:
        os.close(fd)


@pytest.mark.parametrize("fd", [-1, True, 1.5])
def test_private_fd_rejects_invalid_descriptors(fd: object) -> None:
    from constitutional_swarm.secure_files import require_private_fd

    with pytest.raises((TypeError, ValueError)):
        require_private_fd(fd)  # type: ignore[arg-type]


@pytest.mark.parametrize("path", ["", b"path", 1, None])
def test_open_private_file_rejects_invalid_paths(path: object) -> None:
    from constitutional_swarm.secure_files import open_private_file

    with pytest.raises((TypeError, ValueError)):
        open_private_file(path)  # type: ignore[arg-type]


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK", "O_NOCTTY"])
def test_open_private_file_fails_closed_without_required_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    monkeypatch.delattr(secure_files.os, flag)
    with pytest.raises(RuntimeError, match=flag):
        secure_files.open_private_file(path)


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK", "O_NOCTTY"])
def test_open_private_file_fails_closed_with_invalid_required_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    monkeypatch.setattr(secure_files.os, flag, 0)
    with pytest.raises(RuntimeError, match=flag):
        secure_files.open_private_file(path)


def test_private_fd_fails_closed_without_effective_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY)
    monkeypatch.delattr(secure_files.os, "geteuid")
    try:
        with pytest.raises(RuntimeError, match="geteuid"):
            secure_files.require_private_fd(fd)
        os.fstat(fd)
    finally:
        os.close(fd)


def test_open_private_file_closes_owned_fd_when_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    opened: list[int] = []
    real_open = secure_files.os.open

    def recording_open(candidate: str, flags: int) -> int:
        fd = real_open(candidate, flags)
        opened.append(fd)
        return fd

    def reject(fd: int) -> None:
        raise PermissionError("rejected")

    monkeypatch.setattr(secure_files.os, "open", recording_open)
    monkeypatch.setattr(secure_files, "require_private_fd", reject)
    with pytest.raises(PermissionError, match="rejected"):
        secure_files.open_private_file(path)

    assert len(opened) == 1
    with pytest.raises(OSError) as exc_info:
        os.fstat(opened[0])
    assert exc_info.value.errno == errno.EBADF


def test_open_private_file_closes_owned_fd_when_inheritability_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import secure_files

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    opened: list[int] = []
    real_open = secure_files.os.open

    def recording_open(candidate: str, flags: int) -> int:
        fd = real_open(candidate, flags)
        opened.append(fd)
        return fd

    def reject(fd: int, inheritable: bool) -> None:
        raise OSError("cannot set inheritable state")

    monkeypatch.setattr(secure_files.os, "open", recording_open)
    monkeypatch.setattr(secure_files.os, "set_inheritable", reject)
    with pytest.raises(OSError, match="inheritable"):
        secure_files.open_private_file(path)

    assert len(opened) == 1
    with pytest.raises(OSError) as exc_info:
        os.fstat(opened[0])
    assert exc_info.value.errno == errno.EBADF


def test_private_fd_never_closes_borrowed_descriptor(tmp_path: Path) -> None:
    from constitutional_swarm.secure_files import require_private_fd

    path = tmp_path / "private"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY)
    try:
        require_private_fd(fd)
        os.fstat(fd)
        path.chmod(0o640)
        with pytest.raises(PermissionError):
            require_private_fd(fd)
        os.fstat(fd)
    finally:
        os.close(fd)
