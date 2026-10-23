"""In-thread APCC authority for contention tests; never isolation evidence.

``authority_child_main`` runs on a thread of the test process so tests can
monkeypatch the store, sink and clock, and scope the SQLite busy_timeout. The
handshake and channel binding mirror ``start_authority``.
"""

from __future__ import annotations

import multiprocessing
import os
import socket
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm import authority_isolation, authority_service
from constitutional_swarm.apcc.crypto import b64u_decode
from constitutional_swarm.authority_child import AuthorityChildConfig, authority_child_main


@dataclass
class InThreadAuthority:
    thread: threading.Thread
    execution: Any
    admin: Any
    status: Any
    endpoints: tuple[socket.socket, ...]
    failures: list[BaseException] = field(default_factory=list)

    def is_alive(self) -> bool:
        return self.thread.is_alive()

    def close(self, timeout: float = 10.0) -> None:
        for client in (self.execution, self.admin._client, self.status):
            client.close()
        for endpoint in self.endpoints:
            endpoint.close()
        self.thread.join(timeout)


def read_key_bundle(config: AuthorityChildConfig) -> bytes:
    """Read the raw key bundle once, before any start consumes it."""
    return Path(config.key_source.location).read_bytes()


def start_in_thread_authority(
    config: AuthorityChildConfig,
    raw_keys: bytes,
    *,
    busy_timeout_ms: int | None = None,
    readiness_timeout: float = 30.0,
) -> InThreadAuthority:
    """Boot ``authority_child_main`` on a thread and bind verified clients."""
    from constitutional_swarm.apcc import sqlite_store

    execution_parent, execution_child = socket.socketpair(socket.AF_UNIX)
    admin_parent, admin_child = socket.socketpair(socket.AF_UNIX)
    status_parent, status_child = socket.socketpair(socket.AF_UNIX)
    ready_parent, ready_child = multiprocessing.get_context("spawn").Pipe(duplex=True)
    failures: list[BaseException] = []
    busy_timeout = sqlite_store._BUSY_TIMEOUT_MS if busy_timeout_ms is not None else None

    def run() -> None:
        # A new thread starts from an empty context, so this scopes the store's
        # foreground busy_timeout to this authority only.
        if busy_timeout is not None:
            busy_timeout.set(busy_timeout_ms)
        try:
            authority_child_main(
                config, execution_child, admin_child, status_child, ready_child
            )
        except BaseException as exc:
            failures.append(exc)
        finally:
            for endpoint in (execution_child, admin_child, status_child):
                endpoint.close()

    thread = threading.Thread(target=run, name="in-thread-authority", daemon=True)
    thread.start()
    try:
        if not ready_parent.poll(readiness_timeout):
            raise TimeoutError("in-thread authority hardening timed out")
        hardened = ready_parent.recv()
        if hardened.get("stage") != "HARDENED_READY":
            raise RuntimeError(f"unexpected hardening message: {hardened!r}")
        ready_parent.send_bytes(raw_keys)
        if not ready_parent.poll(readiness_timeout):
            raise TimeoutError("in-thread authority readiness timed out")
        ready = ready_parent.recv()
        if "startup_error" in ready:
            thread.join(5)
            raise RuntimeError(f"authority startup failed: {failures!r}")
        body = authority_service._verify_readiness(
            ready, config.key_source.expected_identity_public_key, os.getpid()
        )
    finally:
        ready_parent.close()
    ipc_public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(body["ipc_public_key"]))

    def bind(client_type: type, connection: socket.socket, role: str) -> Any:
        return authority_service._bind_verified_child_channel(
            client_type,
            connection,
            channel_role=role,
            session=body["session"],
            authority_pid=os.getpid(),
            ipc_public_key=ipc_public_key,
            max_frame_bytes=config.max_frame_bytes,
        )

    return InThreadAuthority(
        thread=thread,
        execution=bind(authority_service._AuthorityExecutionChannel, execution_parent, "execution"),
        admin=authority_service.AuthorityAdminClient(
            bind(authority_service._JSONClient, admin_parent, "admin")
        ),
        status=bind(authority_service._StatusSigningClient, status_parent, "status-signing"),
        endpoints=(execution_parent, admin_parent, status_parent),
        failures=failures,
    )


def no_process_hardening(monkeypatch: Any) -> None:
    """Keep the in-thread child from re-hardening the pytest process."""
    monkeypatch.setattr(authority_isolation, "harden_current_process", lambda: None)


class OutsideWriter:
    """Hold an outside ``BEGIN IMMEDIATE`` write lock on a background thread."""

    def __init__(self, database: Path | str) -> None:
        self._database = str(database)
        self._locked = threading.Event()
        self._release = threading.Event()
        self._thread: threading.Thread | None = None
        self.errors: list[BaseException] = []

    def acquire(self, timeout: float = 10.0) -> None:
        def hold() -> None:
            connection = sqlite3.connect(self._database, timeout=timeout)
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._locked.set()
                self._release.wait()
                connection.rollback()
            except BaseException as exc:
                self.errors.append(exc)
            finally:
                connection.close()

        self._thread = threading.Thread(target=hold, name="outside-writer", daemon=True)
        self._thread.start()
        if not self._locked.wait(timeout):
            raise TimeoutError(f"outside writer could not lock: {self.errors!r}")

    def release(self, timeout: float = 10.0) -> None:
        self._release.set()
        if self._thread is not None:
            self._thread.join(timeout)
            assert not self._thread.is_alive()

    @property
    def held(self) -> bool:
        return self._locked.is_set() and not self._release.is_set()


def wait_until(predicate: Callable[[], bool], timeout: float, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def recording_sink_class() -> type:
    """Return a fresh outbox sink class that records deliveries per test."""

    class RecordingSink:
        events: list[str] = []
        fail = False
        after_deliver: Callable[[str], None] | None = None

        def deliver(self, event_id: str, payload: bytes) -> None:
            del payload
            if RecordingSink.fail:
                raise RuntimeError("outbox sink unavailable")
            RecordingSink.events.append(event_id)
            if RecordingSink.after_deliver is not None:
                RecordingSink.after_deliver(event_id)

    return RecordingSink


def prepare_commit(authority: InThreadAuthority, key: Any, workflow_id: str = "wf") -> tuple:
    """Drive one node to a signed commit request through the in-thread channels."""
    from constitutional_swarm.artifact import Artifact, ArtifactStore
    from constitutional_swarm.capability import CapabilityRegistry
    from constitutional_swarm.governed_commit import (
        sign_attempt_authorization,
        sign_governed_receipt,
    )
    from constitutional_swarm.swarm import TaskDAG, TaskNode
    from tests.gcb_apcc_support import compose_test_executor, provision_executor_workflow

    dag = TaskDAG(dag_id=workflow_id).add_node(TaskNode(node_id="root"))
    provision_executor_workflow(authority.admin, dag, policy_version="1")
    authority.admin.register_agent(
        workflow_id=workflow_id, agent_id="agent", public_key=key.public_key()
    )
    executor = compose_test_executor(
        CapabilityRegistry(), ArtifactStore(), authority.execution, policy_version="1"
    )
    executor.load_dag(dag)
    authorization = sign_attempt_authorization(executor.prepare_claim("root", "agent"), key)
    executor.claim("root", "agent", authorization)
    payload = executor.produce_result(
        "root",
        Artifact("artifact", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    request = authority.execution.build_request(sign_governed_receipt(payload, key))
    return executor, request


def store_counts(database: Path | str) -> dict[str, Any]:
    """Read durable commit facts without taking the write lock."""
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        return {
            "decisions": connection.execute("SELECT COUNT(*) FROM apcc_decisions").fetchone()[0],
            "commit_index": connection.execute("SELECT COUNT(*) FROM commit_index").fetchone()[0],
            "outbox": dict(
                connection.execute(
                    "SELECT state, COUNT(*) FROM apcc_outbox GROUP BY state"
                ).fetchall()
            ),
            "commit_events": [
                row[0]
                for row in connection.execute(
                    "SELECT event_id FROM apcc_outbox WHERE event_kind='COMMIT' "
                    "ORDER BY event_sequence"
                )
            ],
        }
    finally:
        connection.close()
