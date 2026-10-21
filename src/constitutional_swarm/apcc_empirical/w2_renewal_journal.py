"""Authority-owned renewal journal; independent of SQLite and APCC wire objects.

No recovery/reopen API exists: losing the owning process ends this session. A
signed prefix is evidence of that prefix only, never proof of clean completion.
Callers must independently validate the evidence attached to each transition.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import encode_payload
from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc_empirical.w2_renewal_protocol import SignerBinding

DOMAIN = b"APCC-W2-AUTHORITY-RENEWAL-JOURNAL-V1"
_MAX = 2**53 - 1
_CONTEXT = {"authority_store_id", "authority_session_id", "repetition_id"}
_NUMBERS = {
    "sequence",
    "epoch",
    "not_before_ms",
    "expires_at_ms",
    "now_ms",
    "maximum_total_lifetime_ms",
    "maximum_renewals",
}
_FIELDS = _NUMBERS | {
    "protocol",
    "context",
    "plan_digest",
    "previous_digest",
    "state",
    "nonce",
    "evidence",
}


def _integer(value: int) -> int:
    if type(value) is not int or not 0 <= value <= _MAX:
        raise ValueError("journal integer outside safe range")
    return value


def _strings(value: object, fields: set[str] | None = None) -> dict[str, str]:
    if type(value) is not dict or (fields is not None and set(value) != fields):
        raise ValueError("journal map fields mismatch")
    if any(
        type(k) is not str or type(v) is not str or not k or not v
        for k, v in value.items()
    ):
        raise ValueError("journal map requires nonempty strings")
    return dict(value)


def _validate(body: dict[str, Any], previous: dict[str, Any] | None) -> None:
    if set(body) != _FIELDS or body["protocol"] != DOMAIN.decode():
        raise ValueError("journal body fields mismatch")
    _strings(body["context"], _CONTEXT)
    _strings(body["evidence"])
    for field in _NUMBERS:
        value = body[field]
        if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,15}", value) is None:
            raise ValueError("noncanonical journal counter")
        _integer(int(value))
    for field in ("plan_digest", "previous_digest"):
        b64u_decode(body[field], expected_length=32)
    if type(body["nonce"]) is not str or not body["nonce"]:
        raise ValueError("empty journal nonce")
    if type(body["state"]) is not str:
        raise ValueError("journal state must be a string")
    start, end, now = (
        int(body[k]) for k in ("not_before_ms", "expires_at_ms", "now_ms")
    )
    _integer(start + int(body["maximum_total_lifetime_ms"]))
    if not start <= now < end <= start + int(body["maximum_total_lifetime_ms"]):
        # Failure may be recorded after expiration, but never activate authority.
        if body["state"] != "FAILED" or not start <= now or not start < end:
            raise ValueError("journal lifetime exhausted")
    if previous is None:
        if (body["state"], body["epoch"], body["sequence"]) != ("ACTIVE", "0", "0"):
            raise ValueError("journal initial state mismatch")
        if body["previous_digest"] != sha256_digest(b"") or end - now > 1_200_000:
            raise ValueError("invalid initial journal boundary")
        return
    for field in (
        "context",
        "plan_digest",
        "not_before_ms",
        "maximum_total_lifetime_ms",
        "maximum_renewals",
    ):
        if body[field] != previous[field]:
            raise ValueError("journal scope substitution")
    if int(body["sequence"]) != int(previous["sequence"]) + 1 or now < int(
        previous["now_ms"]
    ):
        raise ValueError("journal sequence or clock regression")
    old, new = previous["state"], body["state"]
    if old == "FAILED" or (
        new != "FAILED"
        and (old, new)
        not in {
            ("ACTIVE", "DRAINED"),
            ("DRAINED", "PREPARED"),
            ("PREPARED", "RETIRED"),
            ("RETIRED", "ACTIVE"),
        }
    ):
        raise ValueError("invalid journal state transition")
    increment = int(new == "ACTIVE")
    if int(body["epoch"]) != int(previous["epoch"]) + increment:
        raise ValueError("journal epoch mismatch")
    if new == "ACTIVE":
        if now >= int(previous["expires_at_ms"]) or end - now > 1_200_000:
            raise ValueError("expired predecessor or oversized successor")
        if int(body["epoch"]) > int(body["maximum_renewals"]):
            raise ValueError("renewal count exhausted")
    elif body["expires_at_ms"] != previous["expires_at_ms"]:
        raise ValueError("nonactivation changed expiration")


def verify_journal(
    data: bytes,
    binding: SignerBinding,
    *,
    expected_context: dict[str, str],
    expected_plan_digest: str,
    expected_final_digest: str | None = None,
    require_active: bool = False,
) -> tuple[dict[str, Any], ...]:
    """Verify a prefix. Complete-run callers must pin its externally sealed tip."""
    if not data or not data.endswith(b"\n"):
        raise ValueError("empty or truncated journal")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    result: list[dict[str, Any]] = []
    previous_digest = sha256_digest(b"")
    nonces: set[str] = set()
    for raw in data.splitlines():
        obj = json.loads(raw)
        if type(obj) is not dict or set(obj) != {"body", "key_id", "signature"}:
            raise ValueError("journal envelope fields mismatch")
        if encode_payload(obj) != raw or obj["key_id"] != binding.key_id:
            raise ValueError("journal encoding or signer mismatch")
        body = obj["body"]
        if type(body) is not dict:
            raise ValueError("invalid journal body")
        _validate(body, result[-1]["body"] if result else None)
        if (
            body["context"] != expected_context
            or body["plan_digest"] != expected_plan_digest
        ):
            raise ValueError("journal external scope mismatch")
        if body["previous_digest"] != previous_digest or body["nonce"] in nonces:
            raise ValueError("journal chain or nonce mismatch")
        try:
            Ed25519PublicKey.from_public_bytes(binding.public_key).verify(
                b64u_decode(obj["signature"], expected_length=64),
                DOMAIN + b"\0" + encode_payload(body),
            )
        except InvalidSignature as exc:
            raise ValueError("invalid journal signature") from exc
        nonces.add(body["nonce"])
        previous_digest = sha256_digest(raw)
        result.append(obj)
    if expected_final_digest is not None and previous_digest != expected_final_digest:
        raise ValueError("journal sealed tip mismatch")
    if require_active and result[-1]["body"]["state"] != "ACTIVE":
        raise ValueError("unfinished or failed journal")
    return tuple(result)


class RenewalJournal:
    """Single-process owner; a failed durable write irreversibly fences this object."""

    _lock: Any
    _path: Path
    _signer: Ed25519PrivateKey
    _binding: SignerBinding
    _bytes: bytes
    _rows: list[dict[str, Any]]
    _failed: bool
    _closed: bool
    _fd: int
    _identity: tuple[int, int]
    _observed_ms: int

    @classmethod
    def create(
        cls,
        path: Path,
        signer: Ed25519PrivateKey,
        *,
        key_id: str,
        context: dict[str, str],
        plan_digest: str,
        not_before_ms: int,
        expires_at_ms: int,
        maximum_total_lifetime_ms: int,
        maximum_renewals: int,
    ) -> RenewalJournal:
        self = cls()
        self._lock = threading.RLock()
        self._path = Path(path).absolute()
        self._signer = signer
        self._binding = SignerBinding(key_id, signer.public_key().public_bytes_raw())
        self._bytes = b""
        self._rows = []
        self._failed = False
        self._closed = False
        self._observed_ms = _integer(not_before_ms)
        self._path.parent.mkdir(mode=0o700, parents=False, exist_ok=False)
        self._fd = os.open(
            self._path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        stat = os.fstat(self._fd)
        self._identity = (stat.st_dev, stat.st_ino)
        try:
            ancestor = os.open(self._path.parent.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(ancestor)
            finally:
                os.close(ancestor)
            body = {
                "protocol": DOMAIN.decode(),
                "context": _strings(context, _CONTEXT),
                "plan_digest": plan_digest,
                "previous_digest": sha256_digest(b""),
                "state": "ACTIVE",
                "epoch": "0",
                "sequence": "0",
                "nonce": "initial",
                "evidence": {},
                "not_before_ms": str(_integer(not_before_ms)),
                "expires_at_ms": str(_integer(expires_at_ms)),
                "now_ms": str(_integer(not_before_ms)),
                "maximum_total_lifetime_ms": str(_integer(maximum_total_lifetime_ms)),
                "maximum_renewals": str(_integer(maximum_renewals)),
            }
            self._append(body)
        except BaseException:
            self.close()
            raise
        return self

    def _check(self) -> None:
        if self._failed or self._closed:
            raise ValueError("renewal journal terminally fenced")
        try:
            stat = self._path.lstat()
            if (stat.st_dev, stat.st_ino) != self._identity or stat.st_size != len(
                self._bytes
            ):
                raise ValueError("renewal journal replaced or truncated")
            if os.pread(self._fd, len(self._bytes) + 1, 0) != self._bytes:
                raise ValueError("renewal journal edited")
        except BaseException:
            self._failed = True
            raise

    def _append(self, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        _validate(body, self._rows[-1]["body"] if self._rows else None)
        obj = {
            "body": body,
            "key_id": self._binding.key_id,
            "signature": b64u_encode(
                self._signer.sign(DOMAIN + b"\0" + encode_payload(body))
            ),
        }
        raw = encode_payload(obj) + b"\n"
        try:
            os.lseek(self._fd, 0, os.SEEK_END)
            offset = 0
            while offset < len(raw):
                written = os.write(self._fd, raw[offset:])
                if written <= 0:
                    raise OSError("zero-byte journal write")
                offset += written
            os.fsync(self._fd)
            parent = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            stat = self._path.lstat()
            expected = self._bytes + raw
            if (
                (stat.st_dev, stat.st_ino) != self._identity
                or stat.st_size != len(expected)
                or os.pread(self._fd, len(expected) + 1, 0) != expected
            ):
                raise ValueError("renewal journal changed during append")
        except BaseException:
            self._failed = True
            raise
        self._bytes += raw
        self._rows.append(obj)
        return json.loads(encode_payload(obj))

    def transition(
        self,
        state: str,
        epoch: int,
        nonce: str,
        evidence: dict[str, str],
        *,
        now_ms: int,
        expires_at_ms: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._check()
            _integer(epoch)
            _integer(now_ms)
            evidence = _strings(evidence)
            if state == "ACTIVE" and expires_at_ms is None:
                raise ValueError("successor expiration required")
            if expires_at_ms is not None:
                _integer(expires_at_ms)
            for old in self._rows:
                b = old["body"]
                if b["nonce"] == nonce:
                    if (
                        b["state"],
                        int(b["epoch"]),
                        b["evidence"],
                        int(b["now_ms"]),
                    ) != (state, epoch, evidence, now_ms):
                        raise ValueError("nonce reused with changed request")
                    if (
                        expires_at_ms is not None
                        and int(b["expires_at_ms"]) != expires_at_ms
                    ):
                        raise ValueError("nonce reused with changed expiration")
                    return json.loads(encode_payload(old))
            if now_ms < self._observed_ms:
                raise ValueError("journal clock regressed after gate")
            self._observed_ms = now_ms
            previous = self._rows[-1]
            body = dict(previous["body"])
            body.update(
                state=state,
                epoch=str(epoch),
                nonce=nonce,
                evidence=evidence,
                now_ms=str(now_ms),
                sequence=str(len(self._rows)),
                previous_digest=sha256_digest(encode_payload(previous)),
            )
            if expires_at_ms is not None:
                body["expires_at_ms"] = str(_integer(expires_at_ms))
            return self._append(body)

    def gate(self, workload_epoch: int, now_ms: int) -> None:
        with self._lock:
            self._check()
            last = self._rows[-1]["body"]
            if _integer(now_ms) < self._observed_ms:
                raise ValueError("journal gate clock regressed")
            self._observed_ms = now_ms
            if (
                last["state"] != "ACTIVE"
                or _integer(workload_epoch) != int(last["epoch"])
                or not int(last["now_ms"])
                <= _integer(now_ms)
                < int(last["expires_at_ms"])
            ):
                raise ValueError("stale, fenced or expired workload epoch")

    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            self._check()
            return tuple(json.loads(encode_payload(row)) for row in self._rows)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                os.close(self._fd)
