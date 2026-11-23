"""Subprocess entry points for the APCC execution-gateway fault suite.

Usage (always launched by ``tests/apcc_gateway_fault_harness.py``)::

    python -m tests.apcc_gateway_fault_procs target <spec.json>
    python -m tests.apcc_gateway_fault_procs worker <spec.json>

``target``: a durable HTTPS side-effect target (stdlib only). It behaves like a
correct production target: bearer auth, ``Idempotency-Key`` dedupe returning the
original result with ``replayed=true``, per-key fencing (a token lower than the
highest seen for that key is rejected with 409), and rejection (409) of a known
key presented with a different tenant/effect identity. Every request that
reaches the application handler is logged before it is answered; applications
go to an append-only table so a double application is observable rather than a
constraint error. It pins TLS 1.2 without session tickets so the byte-level
proxy can locate the encrypted HTTP response without terminating TLS.

``worker``: opens the real authority store and gateway ledger from disk and
runs outbox redelivery (``recover_outbox`` -> ``APCCExecutionGateway.deliver``)
for N cycles, or delivers one injected event. With ``cut_point`` set it
SIGKILLs itself at exactly one of four points, implemented without touching
``src/`` (see ``_CutPointLedger`` and ``_CutPointHTTPSConnection``). Before the
kill it fsyncs a JSON breadcrumb so the parent can prove the cut was reached.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import select
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any

CUT_POINTS = (
    "before_in_flight_write",
    "after_in_flight_commit",
    "after_request_before_response",
    "after_response_before_mark_applied",
)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


# =========================================================================== #
# HTTPS target                                                                 #
# =========================================================================== #

_TARGET_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS key_index ("
    " idempotency_key TEXT PRIMARY KEY, authority_store_id TEXT NOT NULL,"
    " event_id TEXT NOT NULL, commit_id TEXT NOT NULL, certificate_digest TEXT NOT NULL,"
    " output_digest TEXT NOT NULL, highest_fencing_token INTEGER NOT NULL,"
    " target_reference TEXT NOT NULL, applied_digest TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS applied_effects ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, idempotency_key TEXT NOT NULL,"
    " authority_store_id TEXT NOT NULL, event_id TEXT NOT NULL, commit_id TEXT NOT NULL,"
    " certificate_digest TEXT NOT NULL, output_digest TEXT NOT NULL,"
    " fencing_token INTEGER NOT NULL, target_reference TEXT NOT NULL,"
    " applied_digest TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS request_log ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, listener TEXT NOT NULL,"
    " status_code INTEGER NOT NULL, reason TEXT NOT NULL, idempotency_key TEXT,"
    " fencing_token INTEGER, authority_store_id TEXT, commit_id TEXT, body TEXT)",
    "CREATE TABLE IF NOT EXISTS fault_queue ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL"
    " CHECK (kind IN ('status', 'applied_status', 'echo_authorization')),"
    " status_code INTEGER NOT NULL)",
)
_IDENTITY_FIELDS = (
    "authority_store_id",
    "event_id",
    "commit_id",
    "certificate_digest",
    "output_digest",
)


def _target_connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10.0, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _lookup_effect(conn: sqlite3.Connection, idempotency_key: str) -> tuple[Any, ...] | None:
    return conn.execute(
        "SELECT authority_store_id, event_id, commit_id, certificate_digest, output_digest,"
        " highest_fencing_token, target_reference, applied_digest"
        " FROM key_index WHERE idempotency_key = ?",
        (idempotency_key,),
    ).fetchone()


def _make_handler(db_path: Path, token: str, lock: threading.Lock) -> type:
    expected_auth = f"Bearer {token}".encode("utf-8")

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        listener_name = "?"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def _send_json(self, status: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()  # one TLS record: status line + headers
            self.wfile.write(raw)  # a second TLS record: the JSON body
            self.close_connection = True

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or "0")
            raw_body = self.rfile.read(length) if length > 0 else b""
            body_text = raw_body.decode("utf-8", errors="replace")
            idem_key = self.headers.get("Idempotency-Key") or ""
            fence_header = self.headers.get("X-Fencing-Token") or ""
            presented = (self.headers.get("Authorization") or "").encode("utf-8")
            status, reply = self._handle(raw_body, body_text, idem_key, fence_header, presented)
            self._send_json(status, reply)

        def _log(
            self,
            conn: sqlite3.Connection,
            status: int,
            reason: str,
            idem_key: str,
            token: int | None,
            payload: dict[str, Any] | None,
            body_text: str,
        ) -> None:
            conn.execute(
                "INSERT INTO request_log(listener, status_code, reason, idempotency_key,"
                " fencing_token, authority_store_id, commit_id, body)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.listener_name,
                    status,
                    reason,
                    idem_key or None,
                    token,
                    (payload or {}).get("authority_store_id"),
                    (payload or {}).get("commit_id"),
                    body_text,
                ),
            )

        def _handle(
            self,
            raw_body: bytes,
            body_text: str,
            idem_key: str,
            fence_header: str,
            presented: bytes,
        ) -> tuple[int, dict[str, Any]]:
            with lock:
                conn = _target_connect(db_path)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    result = self._decide(
                        conn, raw_body, body_text, idem_key, fence_header, presented
                    )
                    conn.execute("COMMIT")  # durable before any response byte is written
                    return result
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                finally:
                    conn.close()

        def _decide(
            self,
            conn: sqlite3.Connection,
            raw_body: bytes,
            body_text: str,
            idem_key: str,
            fence_header: str,
            presented: bytes,
        ) -> tuple[int, dict[str, Any]]:
            if not hmac.compare_digest(presented, expected_auth):
                self._log(conn, 401, "unauthorized", idem_key, None, None, "")
                return 401, {"error": "unauthorized"}
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                fencing_token = int(fence_header)
                identity = {name: str(payload[name]) for name in _IDENTITY_FIELDS}
                valid = (
                    bool(idem_key)
                    and payload.get("idempotency_key") == idem_key
                    and payload.get("fencing_token") == fencing_token
                    and fencing_token >= 1
                )
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                payload, fencing_token, identity, valid = None, None, {}, False
            if not valid:
                self._log(conn, 400, "bad_request", idem_key, fencing_token, payload, body_text)
                return 400, {"error": "bad_request"}

            fault = conn.execute(
                "SELECT seq, kind, status_code FROM fault_queue ORDER BY seq LIMIT 1"
            ).fetchone()
            if fault is not None:
                conn.execute("DELETE FROM fault_queue WHERE seq = ?", (fault[0],))
            if fault is not None and fault[1] == "status":
                self._log(
                    conn, fault[2], "injected_status", idem_key, fencing_token, payload, body_text
                )
                return int(fault[2]), {"error": "injected", "status": int(fault[2])}
            if fault is not None and fault[1] == "echo_authorization":
                # A misbehaving-but-plausible target that reflects the presented
                # Authorization header in its error body (debug-style errors).
                self._log(
                    conn,
                    fault[2],
                    "injected_echo_auth",
                    idem_key,
                    fencing_token,
                    payload,
                    body_text,
                )
                return int(fault[2]), {
                    "error": "forbidden",
                    "presented_authorization": presented.decode("utf-8", errors="replace"),
                }

            existing = _lookup_effect(conn, idem_key)  # MUTATION-1: ignore the idempotency key
            if existing is not None:
                if tuple(existing[:5]) != tuple(identity[name] for name in _IDENTITY_FIELDS):
                    self._log(
                        conn,
                        409,
                        "idempotency_payload_mismatch",
                        idem_key,
                        fencing_token,
                        payload,
                        body_text,
                    )
                    return 409, {"error": "idempotency_payload_mismatch"}
                if fencing_token < int(existing[5]):  # MUTATION-2: ignore fencing tokens
                    self._log(
                        conn,
                        409,
                        "stale_fencing_token",
                        idem_key,
                        fencing_token,
                        payload,
                        body_text,
                    )
                    return 409, {
                        "error": "stale_fencing_token",
                        "highest_token": int(existing[5]),
                        "received_token": fencing_token,
                    }
                conn.execute(
                    "UPDATE key_index SET highest_fencing_token = ? WHERE idempotency_key = ?",
                    (max(fencing_token, int(existing[5])), idem_key),
                )
                status = 200
                reason = "idempotent_replay"
                receipt = {
                    "idempotency_key": idem_key,
                    "fencing_token": fencing_token,
                    "target_reference": str(existing[6]),
                    "applied_digest": str(existing[7]),
                    "replayed": True,
                }
            else:
                target_reference = (
                    f"target://{identity['authority_store_id']}/{identity['commit_id']}"
                )
                applied_digest = hashlib.sha256(
                    "|".join([idem_key, *[identity[n] for n in _IDENTITY_FIELDS]]).encode()
                ).hexdigest()
                conn.execute(
                    "INSERT OR REPLACE INTO key_index(idempotency_key, authority_store_id,"
                    " event_id, commit_id, certificate_digest, output_digest,"
                    " highest_fencing_token, target_reference, applied_digest)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idem_key,
                        *[identity[n] for n in _IDENTITY_FIELDS],
                        fencing_token,
                        target_reference,
                        applied_digest,
                    ),
                )
                conn.execute(
                    "INSERT INTO applied_effects(idempotency_key, authority_store_id, event_id,"
                    " commit_id, certificate_digest, output_digest, fencing_token,"
                    " target_reference, applied_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idem_key,
                        *[identity[n] for n in _IDENTITY_FIELDS],
                        fencing_token,
                        target_reference,
                        applied_digest,
                    ),
                )
                status = 201
                reason = "applied"
                receipt = {
                    "idempotency_key": idem_key,
                    "fencing_token": fencing_token,
                    "target_reference": target_reference,
                    "applied_digest": applied_digest,
                    "replayed": False,
                }
            if fault is not None and fault[1] == "applied_status":
                status, reason = int(fault[2]), f"{reason}_then_status_{fault[2]}"
            self._log(conn, status, reason, idem_key, fencing_token, payload, body_text)
            return status, receipt

    return _Handler


class _TLSThreadingServer(http.server.ThreadingHTTPServer):
    """Accepts plain TCP; the TLS handshake runs on the per-connection thread."""

    daemon_threads = True

    def __init__(self, handler: type, context: ssl.SSLContext) -> None:
        self.tls_context = context
        self.tls_failures = 0
        super().__init__(("127.0.0.1", 0), handler)

    def finish_request(self, request: Any, client_address: Any) -> None:
        try:
            tls_sock = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            # Handshake refused by the client (bad cert) or reset: the request
            # never reaches the application handler and is never logged.
            self.tls_failures += 1
            return
        try:
            self.RequestHandlerClass(tls_sock, client_address, self)
        finally:
            try:
                tls_sock.close()
            except OSError:
                pass


def _target_main(spec: dict[str, Any]) -> int:
    db_path = Path(spec["db_path"])
    token = os.environ["APCC_FAULT_TARGET_TOKEN"]
    conn = _target_connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        for statement in _TARGET_SCHEMA:
            conn.execute(statement)
    finally:
        conn.close()

    lock = threading.Lock()
    base_handler = _make_handler(db_path, token, lock)
    servers: dict[str, _TLSThreadingServer] = {}
    for name, files in spec["listeners"].items():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # TLS 1.2 + no tickets: after the handshake the only server->client
        # application-data records are the HTTP response (see FaultProxy).
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_TICKET
        context.load_cert_chain(files["cert"], files["key"])
        handler = type(f"_Handler_{name}", (base_handler,), {"listener_name": name})
        servers[name] = _TLSThreadingServer(handler, context)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    threads = [
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        for server in servers.values()
    ]
    for thread in threads:
        thread.start()
    _atomic_write_json(
        Path(spec["ready_path"]),
        {"pid": os.getpid(), "ports": {n: s.server_address[1] for n, s in servers.items()}},
    )
    stop.wait()
    for server in servers.values():
        server.shutdown()
        server.server_close()
    return 0


# =========================================================================== #
# Gateway worker                                                               #
# =========================================================================== #


def _breadcrumb_and_die(marker_path: Path, cut_point: str, detail: dict[str, Any]) -> None:
    """Persist proof that ``cut_point`` was reached, then SIGKILL this process."""
    _atomic_write_json(marker_path, {"cut_point": cut_point, "pid": os.getpid(), **detail})
    os.kill(os.getpid(), signal.SIGKILL)


def _describe_error(error: BaseException) -> dict[str, Any]:
    failure_code = getattr(error, "failure_code", None)
    return {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "mro": [cls.__name__ for cls in type(error).__mro__],
        "message": str(error),
        "failure_code": None if failure_code is None else str(failure_code.value),
        "cause_type": None if error.__cause__ is None else type(error.__cause__).__name__,
        "cause_message": None if error.__cause__ is None else str(error.__cause__),
        "context_type": None if error.__context__ is None else type(error.__context__).__name__,
        "context_message": None if error.__context__ is None else str(error.__context__),
    }


def _worker_main(spec: dict[str, Any]) -> int:
    from constitutional_swarm.apcc.execution_gateway import (
        APCCExecutionGateway,
        CredentialBoundHttpTarget,
        SQLiteExecutionLedger,
        _NoRedirectHandler,
    )
    from constitutional_swarm.apcc.ports import AuthorityRuntime, OutboxRecoveryRequest
    from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
    from tests import apcc_gateway_fault_harness as harness

    cut_point = spec.get("cut_point")
    if cut_point is not None and cut_point not in CUT_POINTS:
        raise ValueError(f"unknown cut point {cut_point!r}")
    marker_path = Path(spec["marker_path"])

    class _CutPointLedger(SQLiteExecutionLedger):
        """Realises cut points (a), (b) and (d) around the real ledger methods."""

        def begin_verified_attempt(self, **kwargs: Any) -> Any:
            if cut_point == "before_in_flight_write":
                # (a) execute_event has verified closure + status but has not
                # opened the IN_FLIGHT write transaction yet.
                _breadcrumb_and_die(
                    marker_path, cut_point, {"idempotency_key": kwargs["idempotency_key"]}
                )
            record, should_execute = super().begin_verified_attempt(**kwargs)
            if cut_point == "after_in_flight_commit" and should_execute:
                # (b) IN_FLIGHT row + fencing token are committed (WAL+FULL);
                # the HTTP request has not been built or sent.
                _breadcrumb_and_die(
                    marker_path,
                    cut_point,
                    {
                        "idempotency_key": record.idempotency_key,
                        "fencing_token": record.fencing_token,
                        "attempt_count": record.attempt_count,
                    },
                )
            return record, should_execute

        def mark_applied(self, **kwargs: Any) -> Any:
            if cut_point == "after_response_before_mark_applied":
                # (d) the target's receipt was received and validated by the
                # gateway; the APPLIED transition has not been written.
                receipt = kwargs["receipt"]
                _breadcrumb_and_die(
                    marker_path,
                    cut_point,
                    {
                        "idempotency_key": kwargs["idempotency_key"],
                        "fencing_token": kwargs["fencing_token"],
                        "receipt": {
                            "idempotency_key": receipt.idempotency_key,
                            "fencing_token": receipt.fencing_token,
                            "target_reference": receipt.target_reference,
                            "applied_digest": receipt.applied_digest,
                            "replayed": receipt.replayed,
                        },
                    },
                )
            return super().mark_applied(**kwargs)

    class _CutPointHTTPSConnection(http.client.HTTPSConnection):
        """Realises cut point (c): request fully sent, response not yet read."""

        def getresponse(self) -> http.client.HTTPResponse:
            if cut_point == "after_request_before_response":
                # The request bytes have been written. Wait (bounded) until the
                # target's response is sitting unread in the socket buffer: the
                # target only answers after its SQLite COMMIT, so readability
                # proves the request reached and was processed by the target.
                assert self.sock is not None
                readable, _, _ = select.select([self.sock], [], [], 20.0)
                if not readable:
                    os._exit(3)  # distinct exit code: cut point NOT reached
                _breadcrumb_and_die(marker_path, cut_point, {"response_bytes_pending_unread": True})
            return super().getresponse()

    class _CustomContextHTTPSHandler(urllib.request.HTTPSHandler):
        def __init__(self, context: ssl.SSLContext) -> None:
            super().__init__(context=context)
            self._fault_suite_context = context

        def https_open(self, req: urllib.request.Request) -> Any:
            return self.do_open(_CutPointHTTPSConnection, req, context=self._fault_suite_context)

    opener: Any
    if spec["ca_file"] is None:
        opener = None  # CredentialBoundHttpTarget's own default opener (system trust)
    else:
        context = ssl.create_default_context(cafile=spec["ca_file"])
        # Same properties as the module's default opener (execution_gateway.py:294):
        # no environment proxies and no redirects; only TLS trust differs.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _CustomContextHTTPSHandler(context),
            _NoRedirectHandler(),
        ).open

    clock = harness.FixedClock(int(spec["now_ms"]))
    config = harness.authority_config(spec["authority_store_id"], spec["store_generation"])

    class _Sink:
        gateway: Any = None

        def deliver(self, event_id: str, payload: bytes) -> None:
            self.gateway.deliver(event_id, payload)

    sink = _Sink()
    runtime = AuthorityRuntime(harness.key_provider(spec["store_generation"]), clock, sink)
    store = SQLiteAuthorityStore.open(Path(spec["store_path"]), config=config, runtime=runtime)
    ledger = _CutPointLedger(Path(spec["ledger_path"]))
    target = CredentialBoundHttpTarget(
        spec["endpoint_url"],
        bearer_token=os.environ["APCC_FAULT_BEARER_TOKEN"],
        timeout_seconds=float(spec["timeout_seconds"]),
        opener=opener,
    )
    trust = harness.gateway_trust(
        spec["authority_store_id"],
        commit_generation=spec["trust_commit_generation"],
        status_generation=spec["trust_status_generation"],
    )
    gateway = APCCExecutionGateway(
        store=store,
        trust=trust,
        freshness=config.freshness,
        clock=clock,
        ledger=ledger,
        target=target,
    )
    sink.gateway = gateway

    cycles: list[dict[str, Any]] = []
    inject = spec.get("inject_event")
    for _ in range(int(spec["cycles"])):
        entry: dict[str, Any] = {"error": None, "delivered_count": None, "pending_count": None}
        try:
            if inject is not None:
                gateway.deliver(inject["event_id"], base64.b64decode(inject["payload_b64"]))
            else:
                recovered = store.recover_outbox(OutboxRecoveryRequest(str(spec["max_items"])))
                entry["delivered_count"] = recovered.delivered_count
                entry["pending_count"] = recovered.pending_count
        except Exception as error:  # recorded for the parent's assertions
            entry["error"] = _describe_error(error)
        cycles.append(entry)

    outcomes = [
        {
            "disposition": outcome.disposition.value,
            "event_id": outcome.event_id,
            "idempotency_key": outcome.idempotency_key,
            "fencing_token": outcome.fencing_token,
            "failure_code": None if outcome.failure_code is None else outcome.failure_code.value,
            "receipt": None
            if outcome.receipt is None
            else {
                "fencing_token": outcome.receipt.fencing_token,
                "target_reference": outcome.receipt.target_reference,
                "applied_digest": outcome.receipt.applied_digest,
                "replayed": outcome.receipt.replayed,
            },
        }
        for outcome in gateway.outcomes
    ]
    _atomic_write_json(
        Path(spec["result_path"]),
        {"cycles": cycles, "outcomes": outcomes, "target_repr": repr(target)},
    )
    return 0


def main(argv: list[str]) -> int:
    role, spec_path = argv[1], Path(argv[2])
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if role == "target":
        return _target_main(spec)
    if role == "worker":
        return _worker_main(spec)
    raise SystemExit(f"unknown role {role!r}")


if __name__ == "__main__":
    socket.setdefaulttimeout(None)
    sys.exit(main(sys.argv))
