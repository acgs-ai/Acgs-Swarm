"""Regression tests: authority children must survive idle gaps between requests.

The observer and dormant-scheduler children serve one socket each. An idle gap
longer than the per-frame socket timeout (2 s) must not end the child or fail
the controlled boot; only a frame that starts and then stalls may time out.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from constitutional_swarm import authority_ipc
from constitutional_swarm.apcc.observation import AuthorityObservationRequest
from constitutional_swarm.authority_service import (
    start_authority,
    start_authority_observer,
)
from constitutional_swarm.capability import CapabilityRegistry
from tests.gcb_apcc_support import authority_child_config
from tests.test_apcc_observation import _digest, _nonce, _observer_launch

_IDLE_S = 2.5  # longer than the 2.0 s per-frame socket timeout


def test_dormant_scheduler_survives_idle_gap_between_rpcs(tmp_path) -> None:
    authority = start_authority(
        authority_child_config(tmp_path / "authority.db", tmp_path / "authority.keys")
    )
    try:
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert executor.is_complete is False
        time.sleep(_IDLE_S)
        assert executor.is_complete is False
        assert authority.controlled_boot.phase.value != "failed"
    finally:
        authority.close()


def test_observer_survives_idle_gap_between_observations(tmp_path) -> None:
    config = authority_child_config(tmp_path / "observer.db", tmp_path / "observer.keys")
    authority = start_authority(config)
    request = AuthorityObservationRequest(
        protocol_version="APCC-1.0-draft",
        statement_type="apcc.authority-observation-request",
        authority_store_id=config.authority.authority_store_id,
        workflow_id="w",
        node_id="n",
        attempt_id="a",
        expected_commit_id="not-committed",
        expected_operation_digest=_digest(40),
        public_request_digest=_digest(41),
        request_nonce=_nonce(42),
    )
    try:
        observer = start_authority_observer(authority, _observer_launch(config, tmp_path))
        first = observer.client.observe(request)
        time.sleep(_IDLE_S)
        second = observer.client.observe(request)
        assert second.snapshot.state == first.snapshot.state
        assert authority.controlled_boot.observer_ready is True
        assert authority.controlled_boot.phase.value != "failed"
    finally:
        authority.close()


def test_wait_for_frame_returns_on_peer_close() -> None:
    left, right = socket.socketpair()
    try:
        right.close()
        waiter = threading.Thread(target=authority_ipc.wait_for_frame, args=(left,))
        waiter.start()
        waiter.join(timeout=2.0)
        assert not waiter.is_alive(), "wait_for_frame did not return on EOF"
        with pytest.raises(ConnectionError):
            authority_ipc.recv_frame(left, 1024)
    finally:
        left.close()


def test_stalled_frame_still_times_out_after_idle_wait() -> None:
    left, right = socket.socketpair()
    try:
        left.settimeout(0.2)
        right.sendall(struct.pack("!I", 16)[:2])  # half a header, then stall
        authority_ipc.wait_for_frame(left)
        with pytest.raises(TimeoutError):
            authority_ipc.recv_frame(left, 1024)
    finally:
        left.close()
        right.close()
