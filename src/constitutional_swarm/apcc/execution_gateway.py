"""APCC external side-effect execution gateway, fencing, and idempotency ledger.

Bridges at-least-once ``AuthorityOutboxSink`` delivery to external side-effect
targets without conflating store-internal commit atomicity with downstream
execution safety:

1. Fail-closed verification: decodes each ``COMMIT`` outbox payload, fetches the
   signed detached envelope from the authority store, verifies full digest-pinned
   ``verify_causal_closure``, fetches fresh ``AuthorityStatus`` for every
   certificate in the closure via ``current_status_batch``, and runs
   ``verify_current`` with a monotonic anti-rollback watermark persisted in the
   gateway ledger.
2. Monotonic fencing + durable idempotency: allocates strictly increasing
   fencing tokens alongside canonical ``framed_digest`` idempotency keys in a
   ``WAL+FULL`` SQLite ledger so crash/timeout/lease-expiry retries never
   double-apply and stale fenced workers are rejected by compliant targets.
3. Credential isolation: target bearer credentials live only inside the
   gateway target adapter (redacted in ``repr``), never in the authority DB or
   untrusted producer/executor payloads.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, Iterator, Protocol, cast

from ..framing import framed_digest
from .codec import CodecError, decode_certificate, decode_envelope
from .crypto import b64u_encode, sha256_digest
from .model import AuthorityStatus, CommitCertificate, FailureCode
from .ports import (
    AuthorityClock,
    AuthorityExecutionStore,
    AuthorityOutboxSink,
    CurrentStatusRequest,
    StatusFreshnessPolicy,
)
from .verifier import (
    CausalClosureLimits,
    PredecessorResolver,
    ScopedTrust,
    verify_causal_closure,
    verify_current,
)

_IDEMPOTENCY_DOMAIN = b"APCC-EFFECT-IDEMPOTENCY-V1"
_TRUST_LOG_GENESIS = sha256_digest(b"APCC-1/trust-log/genesis")
_GATEWAY_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS gateway_sequence (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        next_fencing_token INTEGER NOT NULL CHECK (next_fencing_token >= 1)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS gateway_watermarks (
        authority_store_id TEXT PRIMARY KEY,
        highest_trust_log_sequence TEXT NOT NULL,
        highest_trust_log_head TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS gateway_effects (
        idempotency_key TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        commit_id TEXT NOT NULL,
        certificate_digest TEXT NOT NULL,
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('IN_FLIGHT', 'APPLIED', 'BLOCKED')),
        fencing_token INTEGER NOT NULL CHECK (fencing_token >= 0),
        attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
        target_reference TEXT,
        applied_digest TEXT,
        failure_code TEXT,
        updated_at_ms INTEGER NOT NULL
    )
    """,
)
_PERMANENT_CONSUMPTION_BLOCK_CODES = frozenset(
    {
        FailureCode.AUTHORITY_STATUS_REVOKED,
        FailureCode.AUTHORITY_STATUS_SUPERSEDED,
        FailureCode.ACTOR_REVOKED,
        FailureCode.WORKFLOW_REVOKED,
    }
)


class ExecutionGatewayError(RuntimeError):
    """Fail-closed gateway admission, watermark, ledger, or delivery error."""

    def __init__(
        self, reason: str, *, failure_code: FailureCode | None = None
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.failure_code = failure_code


class StaleFencingTokenError(ExecutionGatewayError):
    """Raised when an external target rejects a stale fencing token (HTTP 409)."""


class TargetAuthorizationError(ExecutionGatewayError):
    """Raised when an external target rejects credentials (HTTP 401/403)."""


class EffectDisposition(StrEnum):
    """Terminal or skip disposition of one outbox delivery attempt."""

    APPLIED = "applied"
    REPLAYED = "replayed"
    BLOCKED = "blocked"
    IGNORED_CONTROL = "ignored_control"


@dataclass(frozen=True, slots=True)
class SideEffectInvocation:
    """Verified, fenced external side-effect request constructed by the gateway."""

    authority_store_id: str
    event_id: str
    commit_id: str
    certificate_digest: str
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    output_digest: str
    idempotency_key: str
    fencing_token: int
    certificate_envelope: bytes
    trust_log_sequence: str
    trust_log_head: str

    def __post_init__(self) -> None:
        if type(self.fencing_token) is not int or self.fencing_token < 1:
            raise ValueError("fencing token must be a positive integer")
        if not self.idempotency_key:
            raise ValueError("idempotency key cannot be empty")


@dataclass(frozen=True, slots=True)
class TargetExecutionReceipt:
    """Receipt returned by an external target after applying or replaying an effect."""

    idempotency_key: str
    fencing_token: int
    target_reference: str
    applied_digest: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class GatewayEffectRecord:
    """Persisted gateway ledger row tracking one canonical idempotency key."""

    idempotency_key: str
    event_id: str
    commit_id: str
    certificate_digest: str
    workflow_id: str
    node_id: str
    state: str
    fencing_token: int
    attempt_count: int
    target_reference: str | None
    applied_digest: str | None
    failure_code: str | None
    updated_at_ms: int


@dataclass(frozen=True, slots=True)
class GatewayExecutionOutcome:
    """Result recorded by :class:`APCCExecutionGateway` for one outbox event."""

    disposition: EffectDisposition
    event_id: str
    idempotency_key: str | None
    fencing_token: int | None
    receipt: TargetExecutionReceipt | None
    failure_code: FailureCode | None


class ExternalSideEffectTarget(Protocol):
    """Downstream target executor accepting verified, fenced invocations."""

    def execute(self, invocation: SideEffectInvocation) -> TargetExecutionReceipt: ...


def derive_effect_idempotency_key(
    authority_store_id: str,
    event_id: str,
    certificate_digest: str,
    commit_id: str,
) -> str:
    """Derive a collision-resistant unpadded base64url idempotency key."""
    return b64u_encode(
        framed_digest(
            _IDEMPOTENCY_DOMAIN,
            authority_store_id,
            event_id,
            certificate_digest,
            commit_id,
        )
    )


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler that never forwards credentials cross-origin."""

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        del msg, newurl
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "external target HTTP redirect refused",
            headers,
            fp,
        )


def _validate_target_endpoint_url(
    endpoint_url: str, *, allow_insecure_http: bool
) -> None:
    if not isinstance(endpoint_url, str) or not endpoint_url:
        raise ValueError("endpoint URL must be a non-empty URL string")
    parsed = urllib.parse.urlsplit(endpoint_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("endpoint URL must use http:// or https://")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("endpoint URL must include a valid host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint URL must not embed basic-auth credentials")
    if scheme == "http" and not allow_insecure_http and hostname not in _LOOPBACK_HOSTS:
        raise ValueError(
            "non-loopback HTTP endpoint rejected without explicit allow_insecure_http"
        )


class CredentialBoundHttpTarget:
    """External HTTP target carrying gateway-only bearer auth, fencing, and idempotency."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        bearer_token: str,
        timeout_seconds: float = 5.0,
        allow_insecure_http: bool = False,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        _validate_target_endpoint_url(
            endpoint_url, allow_insecure_http=allow_insecure_http
        )
        if not isinstance(bearer_token, str) or not bearer_token:
            raise ValueError("bearer token cannot be empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout seconds must be positive")
        self._endpoint_url = endpoint_url
        self._bearer_token = bearer_token
        self._timeout_seconds = float(timeout_seconds)
        if opener is not None:
            self._opener = opener
        else:
            self._opener = urllib.request.build_opener(_NoRedirectHandler()).open

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(endpoint_url={self._endpoint_url!r}, "
            "bearer_token='<redacted>')"
        )

    def execute(self, invocation: SideEffectInvocation) -> TargetExecutionReceipt:
        body = json.dumps(
            {
                "authority_store_id": invocation.authority_store_id,
                "event_id": invocation.event_id,
                "commit_id": invocation.commit_id,
                "certificate_digest": invocation.certificate_digest,
                "workflow_id": invocation.workflow_id,
                "node_id": invocation.node_id,
                "attempt_id": invocation.attempt_id,
                "agent_id": invocation.agent_id,
                "output_digest": invocation.output_digest,
                "idempotency_key": invocation.idempotency_key,
                "fencing_token": invocation.fencing_token,
                "trust_log_sequence": invocation.trust_log_sequence,
                "trust_log_head": invocation.trust_log_head,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._bearer_token}",
                "Idempotency-Key": invocation.idempotency_key,
                "X-Fencing-Token": str(invocation.fencing_token),
                "X-APCC-Event-Id": invocation.event_id,
                "X-APCC-Certificate-Digest": invocation.certificate_digest,
            },
        )
        try:
            with self._opener(request, timeout=self._timeout_seconds) as response:
                status_code = getattr(response, "status", 200)
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            if 300 <= error.code < 400:
                raise ExecutionGatewayError(
                    f"external target HTTP redirect refused ({error.code})"
                ) from error
            if error.code in (401, 403):
                raise TargetAuthorizationError(
                    f"external target rejected authorization ({error.code}): {detail}"
                ) from error
            if error.code == 409:
                raise StaleFencingTokenError(
                    f"external target rejected stale fence or conflict (409): {detail}"
                ) from error
            raise ExecutionGatewayError(
                f"external target HTTP error ({error.code}): {detail}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ExecutionGatewayError(
                f"external target transport error: {error}"
            ) from error

        if status_code not in (200, 201):
            raise ExecutionGatewayError(
                f"unexpected external target status code: {status_code}"
            )
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExecutionGatewayError(
                "external target returned invalid JSON receipt"
            ) from error
        if not isinstance(parsed, Mapping):
            raise ExecutionGatewayError("external target receipt must be a JSON object")

        resp_key = parsed.get("idempotency_key")
        resp_token = parsed.get("fencing_token")
        target_reference = parsed.get("target_reference")
        applied_digest = parsed.get("applied_digest")
        replayed = parsed.get("replayed", False)
        if (
            resp_key != invocation.idempotency_key
            or type(resp_token) is not int
            or resp_token < 1
            or not isinstance(target_reference, str)
            or not target_reference
            or not isinstance(applied_digest, str)
            or not applied_digest
            or type(replayed) is not bool
        ):
            raise ExecutionGatewayError("external target receipt fields are invalid")
        return TargetExecutionReceipt(
            idempotency_key=resp_key,
            fencing_token=resp_token,
            target_reference=target_reference,
            applied_digest=applied_digest,
            replayed=replayed,
        )


class SQLiteExecutionLedger:
    """Durable WAL+FULL SQLite ledger for fencing tokens, watermarks, and effects."""

    def __init__(self, database_path: Path) -> None:
        self._path = Path(database_path)
        self._lock = Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            for stmt in _GATEWAY_SCHEMA_STATEMENTS:
                conn.execute(stmt)
            conn.execute(
                "INSERT OR IGNORE INTO gateway_sequence(singleton, next_fencing_token) "
                "VALUES (1, 1)"
            )

    @property
    def database_path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _write_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._connect()
            try:
                yield conn
            finally:
                conn.close()

    @staticmethod
    def _row_to_record(row: tuple[Any, ...]) -> GatewayEffectRecord:
        return GatewayEffectRecord(
            idempotency_key=str(row[0]),
            event_id=str(row[1]),
            commit_id=str(row[2]),
            certificate_digest=str(row[3]),
            workflow_id=str(row[4]),
            node_id=str(row[5]),
            state=str(row[6]),
            fencing_token=int(row[7]),
            attempt_count=int(row[8]),
            target_reference=str(row[9]) if row[9] is not None else None,
            applied_digest=str(row[10]) if row[10] is not None else None,
            failure_code=str(row[11]) if row[11] is not None else None,
            updated_at_ms=int(row[12]),
        )

    def get_watermark(self, authority_store_id: str) -> tuple[str, str]:
        with self._read_connection() as conn:
            row = conn.execute(
                "SELECT highest_trust_log_sequence, highest_trust_log_head "
                "FROM gateway_watermarks WHERE authority_store_id = ?",
                (authority_store_id,),
            ).fetchone()
        if row is None:
            return ("0", _TRUST_LOG_GENESIS)
        return (str(row[0]), str(row[1]))

    def advance_watermark(
        self, authority_store_id: str, trust_log_sequence: str, trust_log_head: str
    ) -> None:
        seq_int = int(trust_log_sequence)
        if seq_int < 0:
            raise ExecutionGatewayError("trust log sequence cannot be negative")
        with self._write_connection() as conn:
            row = conn.execute(
                "SELECT highest_trust_log_sequence, highest_trust_log_head "
                "FROM gateway_watermarks WHERE authority_store_id = ?",
                (authority_store_id,),
            ).fetchone()
            if row is not None:
                cur_seq = int(row[0])
                cur_head = str(row[1])
                if seq_int < cur_seq or (
                    seq_int == cur_seq and trust_log_head != cur_head
                ):
                    raise ExecutionGatewayError(
                        "authority trust log watermark regression detected",
                        failure_code=FailureCode.AUTHORITY_STATUS_ROLLBACK,
                    )
                if seq_int == cur_seq:
                    return
                conn.execute(
                    "UPDATE gateway_watermarks SET highest_trust_log_sequence = ?, "
                    "highest_trust_log_head = ? WHERE authority_store_id = ?",
                    (trust_log_sequence, trust_log_head, authority_store_id),
                )
                return
            conn.execute(
                "INSERT INTO gateway_watermarks(authority_store_id, "
                "highest_trust_log_sequence, highest_trust_log_head) VALUES (?, ?, ?)",
                (authority_store_id, trust_log_sequence, trust_log_head),
            )

    def get_effect(self, idempotency_key: str) -> GatewayEffectRecord | None:
        with self._read_connection() as conn:
            row = conn.execute(
                "SELECT idempotency_key, event_id, commit_id, certificate_digest, "
                "workflow_id, node_id, state, fencing_token, attempt_count, "
                "target_reference, applied_digest, failure_code, updated_at_ms "
                "FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def begin_attempt(
        self,
        *,
        idempotency_key: str,
        event_id: str,
        commit_id: str,
        certificate_digest: str,
        workflow_id: str,
        node_id: str,
        now_ms: int,
    ) -> tuple[GatewayEffectRecord, bool]:
        with self._write_connection() as conn:
            existing = conn.execute(
                "SELECT idempotency_key, event_id, commit_id, certificate_digest, "
                "workflow_id, node_id, state, fencing_token, attempt_count, "
                "target_reference, applied_digest, failure_code, updated_at_ms "
                "FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                record = self._row_to_record(existing)
                if (
                    record.event_id != event_id
                    or record.commit_id != commit_id
                    or record.certificate_digest != certificate_digest
                ):
                    raise ExecutionGatewayError(
                        "idempotency key collision with mismatched effect identity"
                    )
                if record.state in ("APPLIED", "BLOCKED"):
                    return (record, False)

            seq_row = conn.execute(
                "SELECT next_fencing_token FROM gateway_sequence WHERE singleton = 1"
            ).fetchone()
            if seq_row is None:
                raise ExecutionGatewayError("gateway sequence row missing from ledger")
            token = int(seq_row[0])
            conn.execute(
                "UPDATE gateway_sequence SET next_fencing_token = ? WHERE singleton = 1",
                (token + 1,),
            )
            if existing is None:
                conn.execute(
                    "INSERT INTO gateway_effects(idempotency_key, event_id, commit_id, "
                    "certificate_digest, workflow_id, node_id, state, fencing_token, "
                    "attempt_count, target_reference, applied_digest, failure_code, "
                    "updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, 'IN_FLIGHT', ?, 1, NULL, "
                    "NULL, NULL, ?)",
                    (
                        idempotency_key,
                        event_id,
                        commit_id,
                        certificate_digest,
                        workflow_id,
                        node_id,
                        token,
                        now_ms,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE gateway_effects SET state = 'IN_FLIGHT', fencing_token = ?, "
                    "attempt_count = attempt_count + 1, updated_at_ms = ? "
                    "WHERE idempotency_key = ?",
                    (token, now_ms, idempotency_key),
                )
            updated = conn.execute(
                "SELECT idempotency_key, event_id, commit_id, certificate_digest, "
                "workflow_id, node_id, state, fencing_token, attempt_count, "
                "target_reference, applied_digest, failure_code, updated_at_ms "
                "FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            assert updated is not None
            return (self._row_to_record(updated), True)

    def mark_applied(
        self,
        *,
        idempotency_key: str,
        fencing_token: int,
        receipt: TargetExecutionReceipt,
        now_ms: int,
    ) -> GatewayEffectRecord:
        with self._write_connection() as conn:
            changed = conn.execute(
                "UPDATE gateway_effects SET state = 'APPLIED', target_reference = ?, "
                "applied_digest = ?, failure_code = NULL, updated_at_ms = ? "
                "WHERE idempotency_key = ? AND state = 'IN_FLIGHT' AND fencing_token = ?",
                (
                    receipt.target_reference,
                    receipt.applied_digest,
                    now_ms,
                    idempotency_key,
                    fencing_token,
                ),
            ).rowcount
            if changed != 1:
                raise ExecutionGatewayError(
                    "cannot finalize gateway effect record outside active fencing token"
                )
            row = conn.execute(
                "SELECT idempotency_key, event_id, commit_id, certificate_digest, "
                "workflow_id, node_id, state, fencing_token, attempt_count, "
                "target_reference, applied_digest, failure_code, updated_at_ms "
                "FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            assert row is not None
            return self._row_to_record(row)

    def mark_blocked(
        self,
        *,
        idempotency_key: str,
        event_id: str,
        commit_id: str,
        certificate_digest: str,
        workflow_id: str,
        node_id: str,
        failure_code: FailureCode,
        now_ms: int,
    ) -> GatewayEffectRecord:
        with self._write_connection() as conn:
            existing = conn.execute(
                "SELECT state FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing[0] == "APPLIED":
                    raise ExecutionGatewayError(
                        "cannot block an effect that was already applied"
                    )
                conn.execute(
                    "UPDATE gateway_effects SET state = 'BLOCKED', failure_code = ?, "
                    "updated_at_ms = ? WHERE idempotency_key = ?",
                    (failure_code.value, now_ms, idempotency_key),
                )
            else:
                conn.execute(
                    "INSERT INTO gateway_effects(idempotency_key, event_id, commit_id, "
                    "certificate_digest, workflow_id, node_id, state, fencing_token, "
                    "attempt_count, target_reference, applied_digest, failure_code, "
                    "updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, 'BLOCKED', 0, 0, NULL, "
                    "NULL, ?, ?)",
                    (
                        idempotency_key,
                        event_id,
                        commit_id,
                        certificate_digest,
                        workflow_id,
                        node_id,
                        failure_code.value,
                        now_ms,
                    ),
                )
            row = conn.execute(
                "SELECT idempotency_key, event_id, commit_id, certificate_digest, "
                "workflow_id, node_id, state, fencing_token, attempt_count, "
                "target_reference, applied_digest, failure_code, updated_at_ms "
                "FROM gateway_effects WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            assert row is not None
            return self._row_to_record(row)


class _StorePredecessorResolver(PredecessorResolver):
    """Bridge digest-pinned predecessor lookup to an ``AuthorityExecutionStore``."""

    def __init__(
        self,
        store: AuthorityExecutionStore,
        root_digest: str,
        root_envelope: bytes,
        root_certificate: CommitCertificate,
    ) -> None:
        self._store = store
        self._commit_by_digest: dict[str, str] = {
            ref.certificate_digest: ref.commit_id
            for ref in root_certificate.bindings.predecessors
        }
        self._envelopes: dict[str, bytes] = {root_digest: root_envelope}
        self._certificates: dict[str, CommitCertificate] = {root_digest: root_certificate}

    def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
        cached = self._envelopes.get(certificate_digest)
        if cached is not None:
            return cached
        commit_id = self._commit_by_digest.get(certificate_digest)
        if commit_id is None:
            return None
        envelope = self._store.get_certificate(commit_id)
        if envelope is None:
            return None
        try:
            detached = decode_envelope(envelope)
            if detached.payload_sha256 != certificate_digest:
                return None
            cert = decode_certificate(detached.payload)
        except CodecError:
            return None
        for pred in cert.bindings.predecessors:
            self._commit_by_digest[pred.certificate_digest] = pred.commit_id
        self._envelopes[certificate_digest] = envelope
        self._certificates[certificate_digest] = cert
        return envelope

    def closure_order(self, root_digest: str) -> list[tuple[str, bytes]]:
        """Return unique (digest, envelope) pairs ordered ancestors-first."""
        ordered: list[tuple[str, bytes]] = []
        visited: set[str] = set()

        def visit(digest: str) -> None:
            if digest in visited:
                return
            visited.add(digest)
            cert = self._certificates.get(digest)
            env = self._envelopes.get(digest)
            if cert is None or env is None:
                raise ExecutionGatewayError(
                    "causal closure certificate missing after verification"
                )
            for pred in cert.bindings.predecessors:
                visit(pred.certificate_digest)
            ordered.append((digest, env))

        visit(root_digest)
        return ordered


def _is_control_payload(parsed: object) -> bool:
    return (
        isinstance(parsed, Mapping)
        and "header" not in parsed
        and {"scope", "audit_event_id", "workflow_id"}.issubset(parsed)
    )


def _assert_status_fresh_and_monotonic(
    status: AuthorityStatus,
    *,
    now_ms: int,
    maximum_staleness_ms: int,
    highest_sequence: int,
    highest_head: str,
) -> None:
    this_update = int(status.this_update_ms)
    next_update = int(status.next_update_ms)
    if this_update > now_ms:
        raise ExecutionGatewayError(
            "authority status is not yet valid",
            failure_code=FailureCode.ATTESTATION_NOT_YET_VALID,
        )
    if (
        next_update < now_ms
        or this_update >= next_update
        or now_ms - this_update > maximum_staleness_ms
    ):
        raise ExecutionGatewayError(
            "authority status is expired or too stale",
            failure_code=FailureCode.AUTHORITY_STATUS_EXPIRED,
        )
    seq = int(status.trust_log_sequence)
    if seq < highest_sequence or (
        seq == highest_sequence and status.trust_log_head != highest_head
    ):
        raise ExecutionGatewayError(
            "authority status rollback detected against gateway watermark",
            failure_code=FailureCode.AUTHORITY_STATUS_ROLLBACK,
        )


class APCCExecutionGateway(AuthorityOutboxSink):
    """Consumer gateway bridging APCC COMMIT outbox events to external targets."""

    def __init__(
        self,
        *,
        store: AuthorityExecutionStore,
        trust: ScopedTrust,
        freshness: StatusFreshnessPolicy,
        clock: AuthorityClock,
        ledger: SQLiteExecutionLedger,
        target: ExternalSideEffectTarget,
        causal_limits: CausalClosureLimits = CausalClosureLimits(),
        on_control_event: Callable[[str, Mapping[str, object]], None] | None = None,
    ) -> None:
        self._store = store
        self._trust = trust
        self._freshness = freshness
        self._clock = clock
        self._ledger = ledger
        self._target = target
        self._causal_limits = causal_limits
        self._on_control_event = on_control_event
        self.outcomes: list[GatewayExecutionOutcome] = []

    @property
    def ledger(self) -> SQLiteExecutionLedger:
        return self._ledger

    def deliver(self, event_id: str, payload: bytes) -> None:
        """Execute or fail closed on one persisted APCC outbox event."""
        outcome = self.execute_event(event_id, payload)
        self.outcomes.append(outcome)

    def execute_event(self, event_id: str, payload: bytes) -> GatewayExecutionOutcome:
        """Verify APCC closure & fresh current status, then invoke target with fencing."""
        try:
            decoded_json = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExecutionGatewayError(
                "outbox payload is not valid UTF-8 JSON",
                failure_code=FailureCode.MALFORMED_JSON,
            ) from error

        if _is_control_payload(decoded_json):
            if self._on_control_event is not None:
                self._on_control_event(event_id, cast("Mapping[str, object]", decoded_json))
            return GatewayExecutionOutcome(
                disposition=EffectDisposition.IGNORED_CONTROL,
                event_id=event_id,
                idempotency_key=None,
                fencing_token=None,
                receipt=None,
                failure_code=None,
            )

        try:
            certificate = decode_certificate(payload)
        except CodecError as error:
            raise ExecutionGatewayError(
                f"outbox payload is not a valid commit certificate: {error.code.value}",
                failure_code=error.code,
            ) from error

        payload_digest = sha256_digest(payload)
        authority_store_id = certificate.header.authority_store_id
        commit_id = certificate.decision.commit_id
        idempotency_key = derive_effect_idempotency_key(
            authority_store_id, event_id, payload_digest, commit_id
        )

        existing = self._ledger.get_effect(idempotency_key)
        if existing is not None:
            if (
                existing.event_id != event_id
                or existing.commit_id != commit_id
                or existing.certificate_digest != payload_digest
            ):
                raise ExecutionGatewayError(
                    "ledger idempotency conflict with existing record IDENTITY"
                )
            if existing.state == "APPLIED":
                assert existing.target_reference is not None
                assert existing.applied_digest is not None
                return GatewayExecutionOutcome(
                    disposition=EffectDisposition.REPLAYED,
                    event_id=event_id,
                    idempotency_key=idempotency_key,
                    fencing_token=existing.fencing_token,
                    receipt=TargetExecutionReceipt(
                        idempotency_key=idempotency_key,
                        fencing_token=existing.fencing_token,
                        target_reference=existing.target_reference,
                        applied_digest=existing.applied_digest,
                        replayed=True,
                    ),
                    failure_code=None,
                )
            if existing.state == "BLOCKED":
                blocked_code = (
                    FailureCode(existing.failure_code)
                    if existing.failure_code is not None
                    else FailureCode.AUTHORITY_STATUS_REVOKED
                )
                return GatewayExecutionOutcome(
                    disposition=EffectDisposition.BLOCKED,
                    event_id=event_id,
                    idempotency_key=idempotency_key,
                    fencing_token=None,
                    receipt=None,
                    failure_code=blocked_code,
                )

        envelope = self._store.get_certificate(commit_id)
        if envelope is None:
            raise ExecutionGatewayError(
                "committed certificate envelope not found in authority store",
                failure_code=FailureCode.INVALID_COMMIT_SEAL,
            )

        resolver = _StorePredecessorResolver(
            self._store, payload_digest, envelope, certificate
        )
        closure = verify_causal_closure(
            envelope, trust=self._trust, resolver=resolver, limits=self._causal_limits
        )
        if not closure.ok or closure.certificate_digest != payload_digest:
            raise ExecutionGatewayError(
                f"causal closure verification failed: {closure.code}",
                failure_code=closure.code,
            )

        chain = resolver.closure_order(payload_digest)
        status_requests = tuple(
            CurrentStatusRequest(
                certificate_digest=digest,
                request_nonce=b64u_encode(secrets.token_bytes(16)),
            )
            for digest, _env in chain
        )
        status_results = self._store.current_status_batch(status_requests)
        if len(status_results) != len(chain):
            raise ExecutionGatewayError(
                "authority status batch length mismatch",
                failure_code=FailureCode.AUTHORITY_STATUS_REQUIRED,
            )

        now_ms = int(self._clock.now_ms())
        if now_ms < 0:
            raise ExecutionGatewayError(
                "gateway clock cannot be negative",
                failure_code=FailureCode.INVALID_DECIMAL_STRING,
            )
        now_ms_str = str(now_ms)
        highest_seq_str, highest_head = self._ledger.get_watermark(authority_store_id)
        highest_seq = int(highest_seq_str)
        max_staleness = int(self._freshness.maximum_staleness_ms)

        max_seen_seq = -1
        max_seen_head = highest_head
        for (digest, item_env), req, status_result in zip(
            chain, status_requests, status_results, strict=True
        ):
            if (
                status_result.request != req
                or status_result.status.certificate_digest != digest
            ):
                raise ExecutionGatewayError(
                    "authority status response identity mismatch",
                    failure_code=FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH,
                )
            current_verdict = verify_current(
                item_env,
                trust=self._trust,
                authority_status=status_result.status,
                request_nonce=req.request_nonce,
                now_ms=now_ms_str,
                highest_trust_log_sequence=highest_seq_str,
                highest_trust_log_head=highest_head,
                maximum_staleness_ms=self._freshness.maximum_staleness_ms,
            )
            if not current_verdict.ok:
                code = current_verdict.code
                if code in _PERMANENT_CONSUMPTION_BLOCK_CODES:
                    # Ensure ACTOR_REVOKED / WORKFLOW_REVOKED also satisfy freshness
                    # and anti-rollback before committing a terminal BLOCKED record.
                    _assert_status_fresh_and_monotonic(
                        status_result.status,
                        now_ms=now_ms,
                        maximum_staleness_ms=max_staleness,
                        highest_sequence=highest_seq,
                        highest_head=highest_head,
                    )
                    self._ledger.advance_watermark(
                        authority_store_id,
                        status_result.status.trust_log_sequence,
                        status_result.status.trust_log_head,
                    )
                    self._ledger.mark_blocked(
                        idempotency_key=idempotency_key,
                        event_id=event_id,
                        commit_id=commit_id,
                        certificate_digest=payload_digest,
                        workflow_id=certificate.subject.workflow_id,
                        node_id=certificate.subject.node_id,
                        failure_code=code,
                        now_ms=now_ms,
                    )
                    return GatewayExecutionOutcome(
                        disposition=EffectDisposition.BLOCKED,
                        event_id=event_id,
                        idempotency_key=idempotency_key,
                        fencing_token=None,
                        receipt=None,
                        failure_code=code,
                    )
                raise ExecutionGatewayError(
                    f"current status verification failed: {code}",
                    failure_code=code,
                )
            seq_val = int(status_result.status.trust_log_sequence)
            if seq_val > max_seen_seq:
                max_seen_seq = seq_val
                max_seen_head = status_result.status.trust_log_head

        if max_seen_seq < 0:
            raise ExecutionGatewayError("no authority status verified")
        leaf_status = status_results[-1].status
        self._ledger.advance_watermark(
            authority_store_id, str(max_seen_seq), max_seen_head
        )

        record, should_execute = self._ledger.begin_attempt(
            idempotency_key=idempotency_key,
            event_id=event_id,
            commit_id=commit_id,
            certificate_digest=payload_digest,
            workflow_id=certificate.subject.workflow_id,
            node_id=certificate.subject.node_id,
            now_ms=now_ms,
        )
        if not should_execute:
            if record.state == "APPLIED":
                assert record.target_reference is not None
                assert record.applied_digest is not None
                return GatewayExecutionOutcome(
                    disposition=EffectDisposition.REPLAYED,
                    event_id=event_id,
                    idempotency_key=idempotency_key,
                    fencing_token=record.fencing_token,
                    receipt=TargetExecutionReceipt(
                        idempotency_key=idempotency_key,
                        fencing_token=record.fencing_token,
                        target_reference=record.target_reference,
                        applied_digest=record.applied_digest,
                        replayed=True,
                    ),
                    failure_code=None,
                )
            blocked_code = (
                FailureCode(record.failure_code)
                if record.failure_code is not None
                else FailureCode.AUTHORITY_STATUS_REVOKED
            )
            return GatewayExecutionOutcome(
                disposition=EffectDisposition.BLOCKED,
                event_id=event_id,
                idempotency_key=idempotency_key,
                fencing_token=None,
                receipt=None,
                failure_code=blocked_code,
            )

        invocation = SideEffectInvocation(
            authority_store_id=authority_store_id,
            event_id=event_id,
            commit_id=commit_id,
            certificate_digest=payload_digest,
            workflow_id=certificate.subject.workflow_id,
            node_id=certificate.subject.node_id,
            attempt_id=certificate.subject.attempt_id,
            agent_id=certificate.subject.agent_id,
            output_digest=certificate.subject.output_digest,
            idempotency_key=idempotency_key,
            fencing_token=record.fencing_token,
            certificate_envelope=envelope,
            trust_log_sequence=leaf_status.trust_log_sequence,
            trust_log_head=leaf_status.trust_log_head,
        )
        receipt = self._target.execute(invocation)
        if receipt.idempotency_key != idempotency_key:
            raise ExecutionGatewayError(
                "external target returned receipt with mismatched idempotency key"
            )
        if not receipt.replayed and receipt.fencing_token != record.fencing_token:
            raise ExecutionGatewayError(
                "external target returned receipt with mismatched fencing token"
            )

        self._ledger.mark_applied(
            idempotency_key=idempotency_key,
            fencing_token=record.fencing_token,
            receipt=receipt,
            now_ms=int(self._clock.now_ms()),
        )
        return GatewayExecutionOutcome(
            disposition=(
                EffectDisposition.REPLAYED
                if receipt.replayed
                else EffectDisposition.APPLIED
            ),
            event_id=event_id,
            idempotency_key=idempotency_key,
            fencing_token=record.fencing_token,
            receipt=receipt,
            failure_code=None,
        )


__all__ = [
    "APCCExecutionGateway",
    "CredentialBoundHttpTarget",
    "EffectDisposition",
    "ExecutionGatewayError",
    "ExternalSideEffectTarget",
    "GatewayEffectRecord",
    "GatewayExecutionOutcome",
    "SQLiteExecutionLedger",
    "SideEffectInvocation",
    "StaleFencingTokenError",
    "TargetAuthorizationError",
    "TargetExecutionReceipt",
    "derive_effect_idempotency_key",
]
