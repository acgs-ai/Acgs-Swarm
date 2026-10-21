"""Real permit ownership and fail-closed functional renewal planning."""

from contextlib import nullcontext
import threading

import pytest

from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan
from constitutional_swarm.apcc_empirical.w2_renewal_campaign import (
    EpochWorkerPool,
    _functional_limits,
)


def _plan(**changes):
    fields = dict(
        duration_ns=1_000_000_000_000,
        scheduled_operations=100,
        admission_grace_ns=25_000_000,
        operation_sla_ns=5_000_000_000,
        drain_ns=1_000_000_000,
        operation_floor=100,
    )
    fields.update(changes)
    return WindowPlan(**fields)


def test_real_four_thousand_seconds_fit_bounded_renewal_plan():
    limits = _functional_limits((_plan(),) * 4, 10_000)
    assert limits == {
        "maximum_renewals": "3",
        "maximum_total_lifetime_ms": "4434000",
        "maximum_single_launch_ms": "1200000",
        "handover_timeout_ms": "10000",
    }


def test_four_warm_windows_have_separate_cold_conditioning_and_budget():
    plans = (_plan(duration_ns=70_000_000_000),) + (_plan(),) * 4
    limits = _functional_limits(plans, 10_000)
    assert limits["maximum_renewals"] == "4"
    assert limits["maximum_total_lifetime_ms"] == "4615000"
    assert sum(p.duration_ns for p in plans[1:]) == 4_000_000_000_000


def test_short_smoke_plan_limits_pass_the_same_standalone_validator():
    from constitutional_swarm.apcc_empirical.w2_renewal_codec import (
        validate_plan_limits,
    )

    limits = _functional_limits((_plan(duration_ns=70_000_000_000),) * 2, 10_000)
    checked = validate_plan_limits(limits)
    assert checked["maximum_single_launch_ms"] <= checked["maximum_total_lifetime_ms"]


@pytest.mark.parametrize(
    "plans,timeout",
    [
        ((_plan(),), 10_000),
        ((_plan(),) * 6, 10_000),
        ((_plan(),) * 2, True),
        ((_plan(),) * 2, 10_001),
        ((_plan(duration_ns=1_200_000_000_000),) * 2, 1000),
        (
            (
                _plan(
                    scheduled_operations=10000,
                    operation_floor=10000,
                    qualification=True,
                ),
            )
            * 2,
            1000,
        ),
    ],
)
def test_invalid_or_qualification_plan_rejected_before_provisioning(plans, timeout):
    with pytest.raises(ValueError):
        _functional_limits(plans, timeout)


def test_epoch_gate_holds_real_permit_before_admission_clock():
    events = []

    class Execution:
        def check_w2_admission_epoch(self):
            events.append("epoch")
            # All but this call's actual permit remain reservable.
            reserved = [pool._permits.acquire(blocking=False) for _ in range(16)]
            assert sum(reserved) == 15
            for value in reserved:
                if value:
                    pool._permits.release()

    def clock():
        events.append("clock")
        return 2

    pool = EpochWorkerPool(Execution(), nullcontext)
    try:
        future = pool.submit_before(
            lambda admitted: admitted, deadline_ns=3, clock=clock
        )
        assert future.result(timeout=2) == 2
        assert events == ["epoch", "clock"]
    finally:
        pool.close()


def test_stale_epoch_fails_before_clock_and_releases_permit():
    class Execution:
        def check_w2_admission_epoch(self):
            raise ValueError("stale epoch")

    pool = EpochWorkerPool(Execution(), nullcontext)
    try:
        with pytest.raises(ValueError, match="stale"):
            pool.submit_before(
                lambda _: pytest.fail("work admitted"),
                deadline_ns=3,
                clock=lambda: pytest.fail("admission timestamp assigned"),
            )
        permits = [pool._permits.acquire(blocking=False) for _ in range(17)]
        assert sum(permits) == 16
        for held in permits:
            if held:
                pool._permits.release()
    finally:
        pool.close()


def test_sixteen_inflight_proofs_exhaust_real_pool_without_epoch_or_clock_call():
    gate_calls = []
    release = threading.Event()

    class Execution:
        def check_w2_admission_epoch(self):
            gate_calls.append(1)

    pool = EpochWorkerPool(Execution(), nullcontext)
    try:
        futures = [
            pool.submit_before(
                lambda _: release.wait(5), deadline_ns=3, clock=lambda: 2
            )
            for _ in range(16)
        ]
        assert all(future is not None for future in futures)
        assert (
            pool.submit_before(
                lambda _: None,
                deadline_ns=3,
                clock=lambda: pytest.fail("overload timestamped"),
            )
            is None
        )
        assert len(gate_calls) == 16
    finally:
        release.set()
        pool.close()
    assert not any(thread.is_alive() for thread in pool._threads)


@pytest.mark.parametrize("expired,fail", [(False, False), (True, False), (False, True)])
def test_admission_tracking_ends_after_actual_permit_release(expired, fail):
    tracking = []
    released = threading.Event()

    class Execution:
        def check_w2_admission_epoch(self):
            if fail:
                raise ValueError("epoch failure")

    def end():
        held = [pool._permits.acquire(blocking=False) for _ in range(17)]
        assert sum(held) == 16
        for reserved in held:
            if reserved:
                pool._permits.release()
        tracking.append("end")
        released.set()

    pool = EpochWorkerPool(
        Execution(),
        nullcontext,
        begin_admission=lambda: tracking.append("begin"),
        end_admission=end,
    )
    try:
        if fail:
            with pytest.raises(ValueError, match="epoch failure"):
                pool.submit_before(lambda _: None, deadline_ns=3, clock=lambda: 2)
        else:
            future = pool.submit_before(
                lambda _: 42, deadline_ns=3, clock=lambda: 3 if expired else 2
            )
            if expired:
                assert future is None
            else:
                assert future.result(timeout=2) == 42
        assert released.wait(2)
        assert tracking == ["begin", "end"]
    finally:
        pool.close()


def test_ledger_publication_follows_permit_release_and_precedes_drain_ack():
    order = []

    class Execution:
        def check_w2_admission_epoch(self):
            pass

    def publish(entry):
        held = [pool._permits.acquire(blocking=False) for _ in range(17)]
        assert sum(held) == 16
        for reserved in held:
            if reserved:
                pool._permits.release()
        assert "_after_release" not in entry
        entry["released"] = True
        order.append("publish")

    pool = EpochWorkerPool(
        Execution(), nullcontext, end_admission=lambda: order.append("drained")
    )
    try:
        future = pool.submit_before(
            lambda _: {"_after_release": publish}, deadline_ns=3, clock=lambda: 2
        )
        assert future.result(timeout=2) == {"released": True}
        assert order == ["publish", "drained"]
    finally:
        pool.close()
