"""End-to-end acceptance tests for the APCC External Side-Effect Execution Gateway.

Proves the boundary between APCC store-internal commit atomicity and real
external side effects over loopback HTTP backed by an independent WAL+FULL
SQLite resource database:

1. Happy path: COMMIT -> causal closure + verify_current -> HTTP target applies once.
2. Crash after target apply (dropped HTTP response) -> idempotent redelivery
   with higher fencing token -> exactly-once mutation + ledger replay cache.
3. Outbox lease expiry recovery across active vs expired 30s leases.
4. Zombie worker with stale X-Fencing-Token rejected (HTTP 409 Conflict).
5. Leaf certificate revocation before outbox drain blocks external mutation without
   head-of-line stalling subsequent valid commits.
6. Causal ancestor revocation blocks dependent child execution.
7. Supersession blocks old certificate and executes replacement once.
8. Actor and workflow revocations block external mutation (0 side effects).
9. AuthorityStatus rollback & expiration fail closed without marking outbox DELIVERED.
10. Forged or DENIED payloads rejected fail closed with 0 external calls.
11. Credential isolation: secrets stay in gateway target (redacted repr, absent from
    APCC DB bytes), and direct unauthenticated/bad-token HTTP requests get 401.
"""

from __future__ import annotations

import copy
import http.server
import json
import sqlite3
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from constitutional_swarm.apcc.codec import decode_envelope, encode_certificate
from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.execution_gateway import (
    APCCExecutionGateway,
    CredentialBoundHttpTarget,
    EffectDisposition,
    ExecutionGatewayError,
    ExternalSideEffectTarget,
    SQLiteExecutionLedger,
    SideEffectInvocation,
    StaleFencingTokenError,
    TargetAuthorizationError,
    TargetExecutionReceipt,
)
from constitutional_swarm.apcc.model import (
    CommitCertificate,
    FailureCode,
    RequestOutcome,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AuthorityOutboxSink,
    AuthorityRuntime,
    CurrentStatusRequest,
    CurrentStatusResult,
    OutboxRecoveryRequest,
    RevocationRequest,
    RevocationScope,
    SupersessionCommitted,
    SupersessionRequest,
)
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
from tests.test_apcc_sqlite import (
    _Clock,
    _KeyProvider,
    _advance_candidate,
    _config,
    _initial_contexts,
    _predecessor,
    _request,
)


class _SimulatedWorkerCrash(BaseException):
    """Non-``Exception`` fault leaving an APCC outbox row in ``CLAIMED`` state."""


class _SwitchableOutboxSink:
    """Allows wiring ``SQLiteAuthorityStore`` to ``APCCExecutionGateway`` cleanly."""

    def __init__(self) -> None:
        self._delegate: AuthorityOutboxSink | None = None
        self.calls: list[tuple[str, bytes]] = []

    def attach(self, sink: AuthorityOutboxSink) -> None:
        self._delegate = sink

    def deliver(self, event_id: str, payload: bytes) -> None:
        self.calls.append((event_id, payload))
        if self._delegate is not None:
            self._delegate.deliver(event_id, payload)


class _DurableHttpTargetHarness:
    """Real loopback HTTP server backed by an independent WAL+FULL SQLite DB."""

    def __init__(self, target_db: Path, *, expected_token: str) -> None:
        self.target_db = Path(target_db)
        self.expected_token = expected_token
        self.lock = threading.Lock()
        self.drop_after_commit_once = False
        self._init_db()
        self._server = self._start_server()
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}/execute"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.target_db,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "CREATE TABLE target_fence ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "highest_token INTEGER NOT NULL)"
            )
            conn.execute(
                "INSERT INTO target_fence(singleton, highest_token) VALUES (1, 0)"
            )
            conn.execute(
                "CREATE TABLE applied_effects ("
                "idempotency_key TEXT PRIMARY KEY, "
                "commit_id TEXT NOT NULL, "
                "certificate_digest TEXT NOT NULL, "
                "output_digest TEXT NOT NULL, "
                "fencing_token INTEGER NOT NULL, "
                "target_reference TEXT NOT NULL, "
                "applied_digest TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE request_log ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                "status_code INTEGER NOT NULL, "
                "idempotency_key TEXT, "
                "fencing_token INTEGER, "
                "reason TEXT NOT NULL)"
            )
            conn.commit()
        finally:
            conn.close()

    def _start_server(self) -> http.server.ThreadingHTTPServer:
        harness = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _send_json(self, status: int, body: dict[str, object]) -> None:
                raw = json.dumps(body, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def _record_log(
                self,
                conn: sqlite3.Connection,
                status_code: int,
                idempotency_key: str | None,
                fencing_token: int | None,
                reason: str,
            ) -> None:
                conn.execute(
                    "INSERT INTO request_log(status_code, idempotency_key, "
                    "fencing_token, reason) VALUES (?, ?, ?, ?)",
                    (status_code, idempotency_key, fencing_token, reason),
                )

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {harness.expected_token}":
                    with harness.lock:
                        conn = harness._connect()
                        try:
                            conn.execute("BEGIN IMMEDIATE")
                            self._record_log(
                                conn, 401, self.headers.get("Idempotency-Key"), None, "unauthorized"
                            )
                            conn.commit()
                        finally:
                            conn.close()
                    self._send_json(401, {"error": "unauthorized"})
                    return

                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                    idem_key = self.headers.get("Idempotency-Key") or ""
                    fence_header = self.headers.get("X-Fencing-Token") or ""
                    fencing_token = int(fence_header)
                    commit_id = str(payload["commit_id"])
                    cert_digest = str(payload["certificate_digest"])
                    output_digest = str(payload["output_digest"])
                except Exception:
                    self._send_json(400, {"error": "bad_request"})
                    return

                if not idem_key or idem_key != payload.get("idempotency_key") or fencing_token < 1:
                    self._send_json(400, {"error": "invalid_headers"})
                    return

                drop_reply = False
                with harness.lock:
                    conn = harness._connect()
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        highest = int(
                            conn.execute(
                                "SELECT highest_token FROM target_fence WHERE singleton = 1"
                            ).fetchone()[0]
                        )
                        if fencing_token <= highest:
                            self._record_log(
                                conn, 409, idem_key, fencing_token, "stale_fencing_token"
                            )
                            conn.commit()
                            self._send_json(
                                409,
                                {
                                    "error": "stale_fencing_token",
                                    "highest_token": highest,
                                    "received_token": fencing_token,
                                },
                            )
                            return

                        existing = conn.execute(
                            "SELECT commit_id, certificate_digest, output_digest, "
                            "fencing_token, target_reference, applied_digest "
                            "FROM applied_effects WHERE idempotency_key = ?",
                            (idem_key,),
                        ).fetchone()
                        if existing is not None:
                            if (existing[0], existing[1], existing[2]) != (
                                commit_id,
                                cert_digest,
                                output_digest,
                            ):
                                self._record_log(
                                    conn,
                                    409,
                                    idem_key,
                                    fencing_token,
                                    "idempotency_payload_mismatch",
                                )
                                conn.commit()
                                self._send_json(409, {"error": "idempotency_payload_mismatch"})
                                return
                            conn.execute(
                                "UPDATE target_fence SET highest_token = ? WHERE singleton = 1",
                                (fencing_token,),
                            )
                            self._record_log(
                                conn, 200, idem_key, fencing_token, "idempotent_replay"
                            )
                            conn.commit()
                            response_body: dict[str, object] = {
                                "idempotency_key": idem_key,
                                "fencing_token": fencing_token,
                                "target_reference": str(existing[4]),
                                "applied_digest": str(existing[5]),
                                "replayed": True,
                            }
                            self._send_json(200, response_body)
                            return

                        target_ref = f"target://{commit_id}"
                        applied_digest = sha256_digest(
                            f"{idem_key}:{commit_id}:{output_digest}".encode("utf-8")
                        )
                        conn.execute(
                            "UPDATE target_fence SET highest_token = ? WHERE singleton = 1",
                            (fencing_token,),
                        )
                        conn.execute(
                            "INSERT INTO applied_effects(idempotency_key, commit_id, "
                            "certificate_digest, output_digest, fencing_token, "
                            "target_reference, applied_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                idem_key,
                                commit_id,
                                cert_digest,
                                output_digest,
                                fencing_token,
                                target_ref,
                                applied_digest,
                            ),
                        )
                        self._record_log(conn, 201, idem_key, fencing_token, "applied")
                        conn.commit()
                        if harness.drop_after_commit_once:
                            harness.drop_after_commit_once = False
                            drop_reply = True
                    finally:
                        conn.close()

                if drop_reply:
                    self.close_connection = True
                    return
                self._send_json(
                    201,
                    {
                        "idempotency_key": idem_key,
                        "fencing_token": fencing_token,
                        "target_reference": target_ref,
                        "applied_digest": applied_digest,
                        "replayed": False,
                    },
                )

        return http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)

    def applied_rows(self) -> list[dict[str, object]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT idempotency_key, commit_id, certificate_digest, output_digest, "
                "fencing_token, target_reference, applied_digest "
                "FROM applied_effects ORDER BY fencing_token"
            ).fetchall()
            return [
                {
                    "idempotency_key": str(r[0]),
                    "commit_id": str(r[1]),
                    "certificate_digest": str(r[2]),
                    "output_digest": str(r[3]),
                    "fencing_token": int(r[4]),
                    "target_reference": str(r[5]),
                    "applied_digest": str(r[6]),
                }
                for r in rows
            ]
        finally:
            conn.close()

    def highest_token(self) -> int:
        conn = self._connect()
        try:
            return int(
                conn.execute(
                    "SELECT highest_token FROM target_fence WHERE singleton = 1"
                ).fetchone()[0]
            )
        finally:
            conn.close()

    def request_logs(self) -> list[tuple[int, str | None, int | None, str]]:
        conn = self._connect()
        try:
            return [
                (int(r[0]), str(r[1]) if r[1] is not None else None, r[2], str(r[3]))
                for r in conn.execute(
                    "SELECT status_code, idempotency_key, fencing_token, reason "
                    "FROM request_log ORDER BY seq"
                ).fetchall()
            ]
        finally:
            conn.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


@pytest.fixture
def target_harness(tmp_path: Path):
    harness = _DurableHttpTargetHarness(
        tmp_path / "external_target.sqlite", expected_token="gw-only-secret-token"
    )
    try:
        yield harness
    finally:
        harness.close()


def _provision_and_wire(
    tmp_path: Path,
    target: ExternalSideEffectTarget,
    *,
    db_name: str = "authority.sqlite",
    ledger_name: str = "gateway_ledger.sqlite",
) -> tuple[
    SQLiteAuthorityStore,
    APCCExecutionGateway,
    SQLiteExecutionLedger,
    _SwitchableOutboxSink,
    _Clock,
    APCCAuthorityConfig,
    AuthorityRuntime,
]:
    config = _config()
    clock = _Clock()
    switch_sink = _SwitchableOutboxSink()
    runtime = AuthorityRuntime(_KeyProvider(), clock, switch_sink)
    db_path = tmp_path / db_name
    SQLiteAuthorityStore.provision(
        db_path,
        config=config,
        initial_contexts=_initial_contexts(),
        runtime=runtime,
    )
    store = SQLiteAuthorityStore.open(db_path, config=config, runtime=runtime)
    ledger = SQLiteExecutionLedger(tmp_path / ledger_name)
    gateway = APCCExecutionGateway(
        store=store,
        trust=store._scoped_trust,
        freshness=config.freshness,
        clock=clock,
        ledger=ledger,
        target=target,
    )
    switch_sink.attach(gateway)
    return store, gateway, ledger, switch_sink, clock, config, runtime


def _outbox_states(db_path: Path) -> list[tuple[str, str, str]]:
    with sqlite3.connect(db_path) as conn:
        return [
            (str(r[0]), str(r[1]), str(r[2]))
            for r in conn.execute(
                "SELECT event_id, event_kind, state FROM apcc_outbox ORDER BY event_sequence"
            ).fetchall()
        ]


def test_happy_path_commit_to_external_http_target_once(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req = _request(commit_id="m3-happy-1", nonce_byte=11)
    _advance_candidate(store, req)
    res = store.atomic_commit(req)
    assert res.decision.outcome is RequestOutcome.COMMITTED
    assert res.certificate_digest is not None

    # External side effect has NOT run yet before outbox drain.
    assert target_harness.applied_rows() == []

    recovered = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert recovered.delivered_count == "1"
    assert recovered.pending_count == "0"

    applied = target_harness.applied_rows()
    assert len(applied) == 1
    assert applied[0]["commit_id"] == "m3-happy-1"
    assert applied[0]["certificate_digest"] == res.certificate_digest
    assert applied[0]["fencing_token"] == 1
    assert target_harness.highest_token() == 1
    assert _outbox_states(store.database_path) == [
        (store.get_outbox_event("m3-happy-1").event_id, "COMMIT", "DELIVERED")
    ]
    assert len(gateway.outcomes) == 1
    assert gateway.outcomes[0].disposition is EffectDisposition.APPLIED
    ledger_row = ledger.get_effect(str(applied[0]["idempotency_key"]))
    assert ledger_row is not None
    assert ledger_row.state == "APPLIED"
    assert ledger_row.attempt_count == 1


def test_crash_after_target_apply_redelivers_idempotently_once(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req = _request(commit_id="m3-crash-1", nonce_byte=12)
    _advance_candidate(store, req)
    res = store.atomic_commit(req)
    assert res.decision.outcome is RequestOutcome.COMMITTED
    outbox_ev = store.get_outbox_event("m3-crash-1")

    # Target commits side effect, then drops connection before sending HTTP 201.
    target_harness.drop_after_commit_once = True
    with pytest.raises(ExecutionGatewayError, match="transport"):
        store.recover_outbox(OutboxRecoveryRequest("10"))

    # Target applied once, APCC outbox released back to PENDING.
    applied_after_drop = target_harness.applied_rows()
    assert len(applied_after_drop) == 1
    assert applied_after_drop[0]["fencing_token"] == 1
    assert _outbox_states(store.database_path) == [
        (outbox_ev.event_id, "COMMIT", "PENDING")
    ]
    idem_key = str(applied_after_drop[0]["idempotency_key"])
    assert ledger.get_effect(idem_key) is not None
    assert ledger.get_effect(idem_key).state == "IN_FLIGHT"  # type: ignore[union-attr]

    # Recovery retry sends higher fencing_token=2 with same Idempotency-Key -> replayed=True.
    recovered = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert recovered.delivered_count == "1"
    assert recovered.pending_count == "0"
    assert len(target_harness.applied_rows()) == 1
    assert target_harness.highest_token() == 2
    assert gateway.outcomes[-1].disposition is EffectDisposition.REPLAYED
    assert ledger.get_effect(idem_key).attempt_count == 2  # type: ignore[union-attr]
    logs = target_harness.request_logs()
    assert [(code, token, reason) for code, _k, token, reason in logs] == [
        (201, 1, "applied"),
        (200, 2, "idempotent_replay"),
    ]

    # Duplicate manual delivery hits local ledger without sending another HTTP request.
    dup = gateway.execute_event(outbox_ev.event_id, outbox_ev.payload)
    assert dup.disposition is EffectDisposition.REPLAYED
    assert len(target_harness.request_logs()) == 2


def test_outbox_lease_expiry_recovery_executes_once(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, _ledger, switch_sink, clock, _config_obj, _runtime = (
        _provision_and_wire(tmp_path, http_target)
    )
    req = _request(commit_id="m3-lease-1", nonce_byte=13)
    _advance_candidate(store, req)
    store.atomic_commit(req)
    outbox_ev = store.get_outbox_event("m3-lease-1")

    class _CrashOnceSink:
        def __init__(self) -> None:
            self.armed = True

        def deliver(self, event_id: str, payload: bytes) -> None:
            if self.armed:
                self.armed = False
                raise _SimulatedWorkerCrash("worker killed while holding outbox lease")
            gateway.deliver(event_id, payload)

    switch_sink.attach(_CrashOnceSink())
    with pytest.raises(_SimulatedWorkerCrash):
        store.recover_outbox(OutboxRecoveryRequest("10"))

    # Worker crashed mid-deliver -> CLAIMED with 30s lease.
    assert _outbox_states(store.database_path) == [
        (outbox_ev.event_id, "COMMIT", "CLAIMED")
    ]
    assert target_harness.applied_rows() == []

    # Before lease expiry (+5s): recover_outbox must respect live lease.
    clock.set_sequence((1_760_000_006_000,))
    before_expiry = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert before_expiry.delivered_count == "0"
    assert before_expiry.pending_count == "1"
    assert target_harness.applied_rows() == []

    # Past 30s lease expiry (+31s): reclaim lease, execute once, mark DELIVERED.
    clock.set_sequence((1_760_000_032_000,))
    after_expiry = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert after_expiry.delivered_count == "1"
    assert after_expiry.pending_count == "0"
    assert len(target_harness.applied_rows()) == 1
    assert _outbox_states(store.database_path) == [
        (outbox_ev.event_id, "COMMIT", "DELIVERED")
    ]


def test_zombie_worker_with_stale_fencing_token_rejected_409(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    captured: list[SideEffectInvocation] = []

    class _ZombiePausingTarget:
        def __init__(self) -> None:
            self.pause_commit_id: str | None = "m3-zombie-1"

        def execute(self, invocation: SideEffectInvocation) -> TargetExecutionReceipt:
            if invocation.commit_id == self.pause_commit_id:
                self.pause_commit_id = None
                captured.append(invocation)
                raise ExecutionGatewayError("worker A paused before HTTP send")
            return http_target.execute(invocation)

    store, _gateway, _ledger, _sink, _clock, _config_obj, _runtime = (
        _provision_and_wire(tmp_path, _ZombiePausingTarget())
    )
    req1 = _request(commit_id="m3-zombie-1", nonce_byte=14, node_id="node-1")
    req2 = _request(commit_id="m3-newer-2", nonce_byte=15, node_id="root")
    _advance_candidate(store, req1)
    assert store.atomic_commit(req1).decision.outcome is RequestOutcome.COMMITTED

    # Attempt 1 captures invocation with fencing_token=1, then pauses before HTTP send.
    with pytest.raises(ExecutionGatewayError, match="paused"):
        store.recover_outbox(OutboxRecoveryRequest("1"))
    assert len(captured) == 1
    zombie_invocation = captured[0]
    assert zombie_invocation.fencing_token == 1

    # Commit req2 on another node and advance outbox via direct gateway call or recovery.
    # Here we drain req1 with retry token=2, then commit+drain req2 with token=3? Wait:
    # Even clearer: keep req1 PENDING, let gateway execute req2 directly (token=2),
    # advancing target highest_token=2 BEFORE zombie wakes up with token=1!
    _advance_candidate(store, req2)
    assert store.atomic_commit(req2).decision.outcome is RequestOutcome.COMMITTED
    outbox2 = store.get_outbox_event("m3-newer-2")
    _gateway.deliver(outbox2.event_id, outbox2.payload)
    assert target_harness.highest_token() == 2

    # Zombie worker A wakes up and attempts direct HTTP call with stale fencing_token=1.
    with pytest.raises(StaleFencingTokenError, match="stale"):
        http_target.execute(zombie_invocation)
    assert target_harness.highest_token() == 2
    assert len(target_harness.applied_rows()) == 1
    assert target_harness.applied_rows()[0]["commit_id"] == "m3-newer-2"
    assert (409, zombie_invocation.idempotency_key, 1, "stale_fencing_token") in (
        target_harness.request_logs()
    )

    # Fresh retry via gateway allocates fencing_token=3 and succeeds cleanly.
    recovered = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert recovered.delivered_count == "2"
    assert target_harness.highest_token() == 3
    assert [r["commit_id"] for r in target_harness.applied_rows()] == [
        "m3-newer-2",
        "m3-zombie-1",
    ]


def test_leaf_revocation_before_execution_blocks_external_mutation(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req1 = _request(commit_id="m3-rev-1", nonce_byte=16, node_id="node-1")
    _advance_candidate(store, req1)
    res1 = store.atomic_commit(req1)
    assert res1.certificate_digest is not None

    store.revoke(
        RevocationRequest(
            scope=RevocationScope.CERTIFICATE,
            workflow_id="workflow-1",
            target_id=res1.certificate_digest,
            next_generation="1",
            reason="revoked-before-external-exec",
        )
    )

    # Queue a valid second commit on another node to prove zero head-of-line stall.
    req2 = _request(commit_id="m3-valid-2", nonce_byte=17, node_id="root")
    _advance_candidate(store, req2)
    res2 = store.atomic_commit(req2)
    assert res2.decision.outcome is RequestOutcome.COMMITTED

    recovered = store.recover_outbox(OutboxRecoveryRequest("10"))
    # Outbox rows: req1 (COMMIT, blocked), CONTROL (ignored_control), req2 (COMMIT, applied).
    assert recovered.delivered_count == "3"
    assert recovered.pending_count == "0"
    assert [r["commit_id"] for r in target_harness.applied_rows()] == ["m3-valid-2"]
    assert target_harness.request_logs() == [
        (201, target_harness.applied_rows()[0]["idempotency_key"], 1, "applied")
    ]
    blocked_outcomes = [
        o for o in gateway.outcomes if o.disposition is EffectDisposition.BLOCKED
    ]
    assert len(blocked_outcomes) == 1
    assert blocked_outcomes[0].failure_code is FailureCode.AUTHORITY_STATUS_REVOKED
    assert ledger.get_effect(str(blocked_outcomes[0].idempotency_key)).state == "BLOCKED"  # type: ignore[union-attr]


def test_causal_ancestor_revocation_blocks_child_external_mutation(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, _ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req_parent = _request(commit_id="m3-parent", nonce_byte=18, node_id="node-1")
    _advance_candidate(store, req_parent)
    res_parent = store.atomic_commit(req_parent)
    assert res_parent.certificate_digest is not None
    store.recover_outbox(OutboxRecoveryRequest("10"))
    assert len(target_harness.applied_rows()) == 1

    # Commit child referencing parent as causal predecessor, then revoke parent before child executes.
    req_child = _request(
        commit_id="m3-child",
        nonce_byte=19,
        node_id="child",
        predecessors=[_predecessor(req_parent, res_parent)],
    )
    _advance_candidate(store, req_child)
    assert store.atomic_commit(req_child).decision.outcome is RequestOutcome.COMMITTED

    store.revoke(
        RevocationRequest(
            scope=RevocationScope.CERTIFICATE,
            workflow_id="workflow-1",
            target_id=res_parent.certificate_digest,
            next_generation="1",
            reason="parent-tainted-before-child-exec",
        )
    )
    store.recover_outbox(OutboxRecoveryRequest("10"))

    assert [r["commit_id"] for r in target_harness.applied_rows()] == ["m3-parent"]
    child_outcomes = [
        o
        for o in gateway.outcomes
        if o.disposition is EffectDisposition.BLOCKED
        and o.failure_code is FailureCode.AUTHORITY_STATUS_REVOKED
    ]
    assert len(child_outcomes) == 1


def test_supersession_blocks_old_cert_and_executes_replacement_once(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, _ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req_old = _request(commit_id="m3-sup-old", nonce_byte=20, node_id="node-1")
    _advance_candidate(store, req_old)
    res_old = store.atomic_commit(req_old)
    assert res_old.certificate_digest is not None

    req_new = _request(
        commit_id="m3-sup-new",
        nonce_byte=21,
        node_id="node-1",
        expected_node_version="1",
        attempt_id="attempt-2",
    )
    _advance_candidate(store, req_new)
    sup = store.supersede(SupersessionRequest(res_old.certificate_digest, req_new))
    assert isinstance(sup, SupersessionCommitted)

    recovered = store.recover_outbox(OutboxRecoveryRequest("10"))
    assert recovered.pending_count == "0"
    assert [r["commit_id"] for r in target_harness.applied_rows()] == ["m3-sup-new"]
    blocked = [o for o in gateway.outcomes if o.disposition is EffectDisposition.BLOCKED]
    assert len(blocked) == 1
    assert blocked[0].failure_code is FailureCode.AUTHORITY_STATUS_SUPERSEDED


@pytest.mark.parametrize(
    ("scope", "target_id"),
    [
        (RevocationScope.ACTOR, "agent-1"),
        (RevocationScope.WORKFLOW, "workflow-1"),
    ],
)
def test_actor_and_workflow_revocation_block_external_mutation(
    tmp_path: Path,
    target_harness: _DurableHttpTargetHarness,
    scope: RevocationScope,
    target_id: str,
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, _ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req = _request(commit_id=f"m3-{scope.value.lower()}", nonce_byte=22)
    _advance_candidate(store, req)
    assert store.atomic_commit(req).decision.outcome is RequestOutcome.COMMITTED

    store.revoke(
        RevocationRequest(
            scope=scope,
            workflow_id="workflow-1",
            target_id=target_id,
            next_generation="10",
            reason=f"revoke-{scope.value.lower()}",
        )
    )
    store.recover_outbox(OutboxRecoveryRequest("10"))

    assert target_harness.applied_rows() == []
    blocked = [o for o in gateway.outcomes if o.disposition is EffectDisposition.BLOCKED]
    assert len(blocked) == 1
    assert blocked[0].failure_code is FailureCode.AUTHORITY_STATUS_REVOKED


def test_status_rollback_and_expired_status_fail_closed(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, _gateway, ledger, _sink, clock, config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req1 = _request(commit_id="m3-wm-1", nonce_byte=23, node_id="node-1")
    req2 = _request(commit_id="m3-wm-2", nonce_byte=24, node_id="root")
    _advance_candidate(store, req1)
    assert store.atomic_commit(req1).decision.outcome is RequestOutcome.COMMITTED
    _advance_candidate(store, req2)
    res2 = store.atomic_commit(req2)
    assert res2.certificate_digest is not None

    # Execute req1 & req2 sequentially so gateway ledger watermark reaches trust_log_sequence >= 2.
    store.recover_outbox(OutboxRecoveryRequest("10"))
    assert len(target_harness.applied_rows()) == 2
    wm_seq, wm_head = ledger.get_watermark(config_obj.authority_store_id)
    assert int(wm_seq) == 2

    # Prepare req3 on a third node, then inject a rolled-back status (sequence=1) and expired status.
    req3 = _request(commit_id="m3-wm-3", nonce_byte=25, node_id="middle")
    _advance_candidate(store, req3)
    res3 = store.atomic_commit(req3)
    assert res3.certificate_digest is not None
    ev3 = store.get_outbox_event("m3-wm-3")
    real_status3 = store.current_status(res3.certificate_digest, b64u_encode(b"\x33" * 16))

    class _StatusInjectingStore:
        def __init__(self, inner: SQLiteAuthorityStore, status_mode: str) -> None:
            self._inner = inner
            self._mode = status_mode

        def get_certificate(self, commit_id: str) -> bytes | None:
            return self._inner.get_certificate(commit_id)

        def current_status_batch(
            self, requests: list[CurrentStatusRequest]
        ) -> tuple[CurrentStatusResult, ...]:
            real = self._inner.current_status_batch(list(requests))
            if self._mode == "rollback":
                assert real_status3 is not None
                fake = replace(
                    real[0].status,
                    trust_log_sequence="1",
                    trust_log_head=wm_head,
                )
                # Keep authentic signature over rollback body using store status signer:
                from constitutional_swarm.apcc.codec import encode_authority_status_body
                from constitutional_swarm.apcc.crypto import AUTHORITY_STATUS_DOMAIN
                from constitutional_swarm.apcc.ports import AuthoritySigningRole

                sig = self._inner._runtime.key_provider.sign(
                    AuthoritySigningRole.STATUS,
                    fake.status_key_id,
                    AUTHORITY_STATUS_DOMAIN,
                    encode_authority_status_body(fake),
                )
                return (
                    CurrentStatusResult(
                        real[0].request, replace(fake, signature=sig)
                    ),
                )
            expired = replace(
                real[0].status,
                this_update_ms=str(int(real[0].status.this_update_ms) - 20_000),
                next_update_ms=str(int(real[0].status.this_update_ms) - 10_000),
            )
            from constitutional_swarm.apcc.codec import encode_authority_status_body
            from constitutional_swarm.apcc.crypto import AUTHORITY_STATUS_DOMAIN
            from constitutional_swarm.apcc.ports import AuthoritySigningRole

            sig = self._inner._runtime.key_provider.sign(
                AuthoritySigningRole.STATUS,
                expired.status_key_id,
                AUTHORITY_STATUS_DOMAIN,
                encode_authority_status_body(expired),
            )
            return (
                CurrentStatusResult(
                    real[0].request, replace(expired, signature=sig)
                ),
            )

    rollback_gw = APCCExecutionGateway(
        store=_StatusInjectingStore(store, "rollback"),  # type: ignore[arg-type]
        trust=store._scoped_trust,
        freshness=config_obj.freshness,
        clock=clock,
        ledger=ledger,
        target=http_target,
    )
    with pytest.raises(ExecutionGatewayError) as exc_rb:
        rollback_gw.execute_event(ev3.event_id, ev3.payload)
    assert exc_rb.value.failure_code is FailureCode.AUTHORITY_STATUS_ROLLBACK

    expired_gw = APCCExecutionGateway(
        store=_StatusInjectingStore(store, "expired"),  # type: ignore[arg-type]
        trust=store._scoped_trust,
        freshness=config_obj.freshness,
        clock=clock,
        ledger=ledger,
        target=http_target,
    )
    with pytest.raises(ExecutionGatewayError) as exc_exp:
        expired_gw.execute_event(ev3.event_id, ev3.payload)
    assert exc_exp.value.failure_code is FailureCode.AUTHORITY_STATUS_EXPIRED

    # Neither failure touched target or marked outbox DELIVERED.
    assert len(target_harness.applied_rows()) == 2
    assert any(
        commit == ev3.event_id and state == "PENDING"
        for commit, _kind, state in _outbox_states(store.database_path)
    )


def test_forged_or_denied_outbox_payload_rejected_fail_closed(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    http_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token=target_harness.expected_token
    )
    store, gateway, _ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req = _request(commit_id="m3-forge-base", nonce_byte=26)
    _advance_candidate(store, req)
    res = store.atomic_commit(req)
    assert res.certificate_payload_bytes is not None

    # Mutate outcome in payload to "denied" -> decode/verify rejects fail closed.
    raw_obj = json.loads(res.certificate_payload_bytes.decode("utf-8"))
    denied_obj = copy.deepcopy(raw_obj)
    denied_obj["decision"]["outcome"] = "denied"
    denied_bytes = json.dumps(denied_obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    with pytest.raises(ExecutionGatewayError):
        gateway.execute_event("forged-denied-event", denied_bytes)

    # Forged certificate payload whose digest matches no sealed certificate in store:
    forged_obj = copy.deepcopy(raw_obj)
    forged_obj["decision"]["commit_id"] = "uncommitted-forged-id"
    forged_cert = CommitCertificate.from_object(forged_obj)
    with pytest.raises(ExecutionGatewayError):
        gateway.execute_event("forged-commit-event", encode_certificate(forged_cert))

    assert target_harness.applied_rows() == []
    assert target_harness.request_logs() == []


def test_credential_isolation_executor_cannot_bypass_gateway(
    tmp_path: Path, target_harness: _DurableHttpTargetHarness
) -> None:
    secret = target_harness.expected_token
    http_target = CredentialBoundHttpTarget(target_harness.url, bearer_token=secret)
    assert secret not in repr(http_target)
    assert "<redacted>" in repr(http_target)

    store, _gateway, ledger, _sink, _clock, _config_obj, _runtime = _provision_and_wire(
        tmp_path, http_target
    )
    req = _request(commit_id="m3-iso-1", nonce_byte=27)
    _advance_candidate(store, req)
    res = store.atomic_commit(req)
    assert res.decision.outcome is RequestOutcome.COMMITTED
    store.recover_outbox(OutboxRecoveryRequest("10"))
    assert len(target_harness.applied_rows()) == 1

    # Secret must never be persisted inside authority DB or gateway ledger files.
    secret_bytes = secret.encode("utf-8")
    assert secret_bytes not in store.database_path.read_bytes()
    assert secret_bytes not in ledger.database_path.read_bytes()

    # Executor attempting direct HTTP call without gateway bearer token gets 401.
    direct_req = urllib.request.Request(
        target_harness.url,
        data=json.dumps({"commit_id": "bypass"}).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": "bypass-key",
            "X-Fencing-Token": "99",
        },
    )
    with pytest.raises(urllib.error.HTTPError) as no_auth:
        urllib.request.urlopen(direct_req, timeout=2.0)
    assert no_auth.value.code == 401

    wrong_target = CredentialBoundHttpTarget(
        target_harness.url, bearer_token="wrong-executor-token"
    )
    with pytest.raises(TargetAuthorizationError):
        wrong_target.execute(
            SideEffectInvocation(
                authority_store_id="store-1",
                event_id="ev-bypass",
                commit_id="bypass",
                certificate_digest=res.certificate_digest or "d",
                workflow_id="workflow-1",
                node_id="node-1",
                attempt_id="attempt-1",
                agent_id="agent-1",
                output_digest=req.subject.output_digest,
                idempotency_key="bypass-key-2",
                fencing_token=99,
                certificate_envelope=decode_envelope(
                    res.certificate_envelope_bytes or b""
                ).payload,
                trust_log_sequence="1",
                trust_log_head=sha256_digest(b"h"),
            )
        )
    # Still only the 1 gateway-authorized mutation exists on target.
    assert len(target_harness.applied_rows()) == 1


def test_http_target_rejects_non_loopback_cleartext_by_default() -> None:
    with pytest.raises(ValueError, match="allow_insecure_http"):
        CredentialBoundHttpTarget(
            "http://example.com/execute", bearer_token="gateway-secret"
        )
    with pytest.raises(ValueError, match="embed"):
        CredentialBoundHttpTarget(
            "https://user:pass@example.com/execute", bearer_token="gateway-secret"
        )
    assert CredentialBoundHttpTarget(
        "https://example.com/execute", bearer_token="gateway-secret"
    )
    assert CredentialBoundHttpTarget(
        "http://127.0.0.1:8080/execute", bearer_token="gateway-secret"
    )
    assert CredentialBoundHttpTarget(
        "http://localhost:8080/execute", bearer_token="gateway-secret"
    )
    assert CredentialBoundHttpTarget(
        "http://example.com/execute",
        bearer_token="gateway-secret",
        allow_insecure_http=True,
    )


def test_http_target_refuses_redirect_without_forwarding_credentials() -> None:
    sink_received: list[tuple[dict[str, str], bytes]] = []

    class _SinkHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            sink_received.append(({k: v for k, v in self.headers.items()}, body))
            self.send_response(200)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.do_POST()

    sink_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
    sink_host, sink_port = sink_server.server_address[:2]
    sink_url = f"http://{sink_host}:{sink_port}/exfil"

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", sink_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

    redirect_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    red_host, red_port = redirect_server.server_address[:2]
    redirect_url = f"http://{red_host}:{red_port}/execute"

    t_sink = threading.Thread(target=sink_server.serve_forever, daemon=True)
    t_red = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    t_sink.start()
    t_red.start()
    try:
        http_target = CredentialBoundHttpTarget(
            redirect_url, bearer_token="gateway-secret"
        )
        with pytest.raises(ExecutionGatewayError, match="redirect"):
            http_target.execute(
                SideEffectInvocation(
                    authority_store_id="store-1",
                    event_id="ev-redir",
                    commit_id="c-redir",
                    certificate_digest=sha256_digest(b"c"),
                    workflow_id="workflow-1",
                    node_id="node-1",
                    attempt_id="attempt-1",
                    agent_id="agent-1",
                    output_digest=sha256_digest(b"o"),
                    idempotency_key="idem-redir",
                    fencing_token=1,
                    certificate_envelope=b"{}",
                    trust_log_sequence="1",
                    trust_log_head=sha256_digest(b"h"),
                )
            )
        assert sink_received == []
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()
        sink_server.shutdown()
        sink_server.server_close()
        t_red.join(timeout=2.0)
        t_sink.join(timeout=2.0)
