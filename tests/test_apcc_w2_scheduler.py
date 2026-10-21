"""Bounded scheduler projections share one transport and retain DAG checks."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from constitutional_swarm import authority_service as service
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governed_commit import CommitOutcome, GovernanceBypassDenied
from tests.gcb_apcc_support import authority_child_config, producer_key
from tests.test_apcc_workflow_rotation import _dag, _produce, _provision


@pytest.mark.parametrize("lane", [-1, 16, True, 1.0, "0", None])
def test_rejects_invalid_lane_before_allocating(lane):
    def forbidden():
        pytest.fail("invalid lane allocated a projection")

    with pytest.raises(ValueError, match="invalid_w2_lane"):
        service._scheduler_lane_dispatch(
            {}, forbidden, {"lane": lane, "operation": "load_dag", "request": {}}
        )


@pytest.mark.parametrize(
    "envelope",
    [
        {"lane": 0, "operation": "health", "request": {}, "extra": 1},
        {"lane": 0, "operation": "w2_lane_v1", "request": {}},
        {"lane": 0, "operation": "create_workflow", "request": {}},
        {"lane": 0, "operation": "load_dag", "request": []},
        {"lane": 0, "operation": "health", "request": {}},
    ],
)
def test_lane_envelope_is_closed_and_requires_load(envelope):
    with pytest.raises(ValueError):
        service._scheduler_lane_dispatch({}, lambda: None, envelope)


def test_failed_initial_load_does_not_retain_projection():
    lanes = {}
    with pytest.raises(ValueError):
        service._scheduler_lane_dispatch(
            lanes,
            lambda: None,
            {"lane": 0, "operation": "load_dag", "request": {"extra": 1}},
        )
    assert lanes == {}


def test_context_is_thread_local_restored_on_failure_and_same_handle():
    handle = object.__new__(service._SwarmExecutionHandle)
    handle._lane_context = threading.local()
    barrier = threading.Barrier(16)

    def select(lane):
        with handle.w2_lane(lane) as selected:
            assert type(selected) is service._SwarmExecutionHandle
            assert selected is handle
            barrier.wait(timeout=5)
            assert handle._lane_context.lane == lane
            with pytest.raises(ValueError, match="nested"):
                with handle.w2_lane(lane):
                    pass
        assert not hasattr(handle._lane_context, "lane")

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(select, range(16)))
    with pytest.raises(RuntimeError):
        with handle.w2_lane(1):
            raise RuntimeError("injected")
    assert not hasattr(handle._lane_context, "lane")


def test_spawned_lanes_preserve_independent_workflows_and_complete_only_rotation(
    tmp_path,
):
    key = producer_key()
    config = authority_child_config(
        tmp_path / "lanes.db", tmp_path / "keys", producers={"agent": key}
    )
    authority = service.start_authority(config)
    try:
        first, second, third = _dag("first"), _dag("second"), _dag("third")
        for dag in (first, second, third):
            _provision(authority.admin_client, dag, key)
        handle = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        pid = handle.pid
        for lane, dag in ((0, first), (1, second)):
            with handle.w2_lane(lane):
                handle.load_dag(dag)
                assert not handle.is_complete
        with handle.w2_lane(0):
            with pytest.raises(GovernanceBypassDenied):
                handle.load_dag(third)
            _, receipt = _produce(handle, key, "first")
            request = handle.build_request(receipt)
        with handle.w2_lane(1):
            with pytest.raises(GovernanceBypassDenied):
                handle.commit(request)
            assert not handle.is_complete
        with handle.w2_lane(0):
            assert handle.commit(request).outcome is CommitOutcome.COMMITTED
            assert handle.is_complete
            handle.load_dag(third)
            assert not handle.is_complete
        with handle.w2_lane(1):
            _, receipt = _produce(handle, key, "second")
            assert (
                handle.commit(handle.build_request(receipt)).outcome
                is CommitOutcome.COMMITTED
            )
            assert handle.is_complete
        assert handle.pid == pid
        assert handle.health()["executor_pid"] == pid
    finally:
        authority.close()
