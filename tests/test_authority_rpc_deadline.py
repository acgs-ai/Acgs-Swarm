"""Regression tests: a SQLite lock stall the store survives must not kill the authority.

The authority store waits up to its busy_timeout (5 s) for a write lock. The
IPC response deadlines must outlast that wait, or a transient outside writer
fails the controlled boot and tears down every authority child. Longer
deadlines must not slow teardown: close() interrupts an RPC stuck on a hung peer.
"""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import authority_service
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.authority_service import start_authority
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    authority_child_config,
    producer_key,
    provision_executor_workflow,
)

_STORE_BUSY_TIMEOUT_S = 5.0
_LOCK_HOLD_S = 3.0  # longer than the old 2.0 s deadline, shorter than busy_timeout


def test_deadlines_outlast_store_busy_timeout_and_nested_calls() -> None:
    assert authority_service._AUTHORITY_RPC_TIMEOUT_S > _STORE_BUSY_TIMEOUT_S
    assert (
        authority_service._SCHEDULER_RPC_TIMEOUT_S > 2 * authority_service._AUTHORITY_RPC_TIMEOUT_S
    )


def test_commit_survives_outside_writer_lock_within_busy_timeout(tmp_path) -> None:
    key = producer_key("agent")
    database = tmp_path / "authority.db"
    authority = start_authority(
        authority_child_config(database, tmp_path / "authority.keys", producers={"agent": key})
    )
    holder: threading.Thread | None = None
    try:
        dag = TaskDAG(dag_id="wf").add_node(TaskNode(node_id="root"))
        provision_executor_workflow(authority.admin_client, dag, policy_version="1")
        authority.admin_client.register_agent(
            workflow_id="wf", agent_id="agent", public_key=key.public_key()
        )
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        executor.load_dag(dag)
        authorization = sign_attempt_authorization(executor.prepare_claim("root", "agent"), key)
        executor.claim("root", "agent", authorization)
        payload = executor.produce_result(
            "root",
            Artifact("artifact", "root", "agent", "text", "result"),
            authorization=authorization,
        )
        request = executor.build_request(sign_governed_receipt(payload, key))

        locked = threading.Event()
        holder_errors: list[BaseException] = []

        def hold_write_lock() -> None:
            # Wait out the authority's periodic outbox transaction, if any.
            connection = sqlite3.connect(database, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                locked.set()
                time.sleep(_LOCK_HOLD_S)
                connection.rollback()
            except BaseException as exc:
                holder_errors.append(exc)
            finally:
                connection.close()

        holder = threading.Thread(target=hold_write_lock)
        holder.start()
        assert locked.wait(timeout=10.0), holder_errors

        started = time.monotonic()
        decision = executor.commit(request)
        assert time.monotonic() - started >= _LOCK_HOLD_S - 0.5

        assert decision.outcome is CommitOutcome.COMMITTED
        assert authority.is_alive()
        assert authority.controlled_boot.phase.value != "failed"
        committed = executor.authoritative_artifact("artifact")
        assert committed is not None and committed.artifact_id == "artifact"
        holder.join(timeout=_LOCK_HOLD_S + 5.0)
        assert not holder.is_alive()
        assert holder_errors == []
    finally:
        if holder is not None:
            holder.join(timeout=_LOCK_HOLD_S + 5.0)
        authority.close()


def _assert_close_interrupts_hung_rpc(client, rpc, peer: socket.socket) -> None:
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            rpc()
        except BaseException as exc:
            outcome.append(exc)
        else:
            outcome.append(None)

    caller = threading.Thread(target=call)
    caller.start()
    peer.settimeout(5.0)
    assert peer.recv(1)  # the request is on the wire; the caller blocks for a reply
    started = time.monotonic()
    client.close()
    elapsed = time.monotonic() - started
    caller.join(timeout=5.0)
    assert not caller.is_alive()
    assert elapsed < 1.0
    assert len(outcome) == 1 and isinstance(outcome[0], GovernanceBypassDenied)
    with pytest.raises(GovernanceBypassDenied):
        rpc()


def test_authority_client_close_interrupts_rpc_to_hung_peer() -> None:
    left, peer = socket.socketpair()
    try:
        client = authority_service._bind_verified_child_channel(
            authority_service._AuthorityExecutionChannel,
            left,
            channel_role="execution",
            session="session",
            authority_pid=1,
            ipc_public_key=Ed25519PrivateKey.generate().public_key(),
            max_frame_bytes=1 << 16,
        )
        _assert_close_interrupts_hung_rpc(client, client.health, peer)
    finally:
        left.close()
        peer.close()


def test_scheduler_handle_close_interrupts_rpc_to_hung_scheduler() -> None:
    left, peer = socket.socketpair()
    try:
        closed: list[None] = []
        handle = authority_service._SwarmExecutionHandle(
            left,
            SimpleNamespace(pid=None),
            max_frame_bytes=1 << 16,
            on_close=lambda: closed.append(None),
        )
        _assert_close_interrupts_hung_rpc(handle, handle.health, peer)
        handle.close()
        assert len(closed) == 1
    finally:
        left.close()
        peer.close()
