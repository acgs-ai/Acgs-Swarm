"""Real 16-worker release/publication exclusion and failure cleanup."""

from concurrent.futures import Future, ThreadPoolExecutor, CancelledError
from contextlib import nullcontext
import threading
import time

import pytest
from constitutional_swarm.apcc_empirical import w2_renewal_campaign as candidate


class Execution:
    def __init__(self):
        self.checks = 0

    def check_w2_admission_epoch(self):
        self.checks += 1


def assert_all_permits_free(pool):
    held = [pool._permits.acquire(blocking=False) for _ in range(17)]
    assert sum(held) == 16
    for reserved in held:
        if reserved:
            pool._permits.release()


def test_sixteen_plus_one_cannot_overlap_unpublished_release():
    starts = [threading.Event() for _ in range(16)]
    releases = [threading.Event() for _ in range(16)]
    publishing, publish_release = threading.Event(), threading.Event()
    contender, new_clock = threading.Event(), threading.Event()
    intervals = []
    pool = candidate.EpochWorkerPool(Execution(), nullcontext)

    def clock():
        value = time.monotonic_ns()
        intervals.append((value, 1))
        return value

    def operation(index):
        def run(_admitted):
            starts[index].set()
            assert releases[index].wait(5)

            def publish(_entry):
                if index == 0:
                    publishing.set()
                    assert publish_release.wait(5)
                intervals.append((time.monotonic_ns(), -1))

            return {"_after_release": publish}

        return run

    def last_clock():
        new_clock.set()
        return clock()

    def submit_last():
        contender.set()
        return pool.submit_before(
            lambda _admit: {
                "_after_release": lambda _entry: intervals.append(
                    (time.monotonic_ns(), -1)
                )
            },
            deadline_ns=time.monotonic_ns() + 5_000_000_000,
            clock=last_clock,
        )

    try:
        futures = [
            pool.submit_before(
                operation(i),
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
                clock=clock,
            )
            for i in range(16)
        ]
        assert all(start.wait(3) for start in starts)
        releases[0].set()
        assert publishing.wait(3)
        with ThreadPoolExecutor(max_workers=1) as submitter:
            pending = submitter.submit(submit_last)
            assert contender.wait(3)
            assert not new_clock.wait(0.05)
            publish_release.set()
            last = pending.result(3)
            assert last is not None
            for release in releases:
                release.set()
            for future in futures:
                future.result(3)
            last.result(3)
        active = peak = 0
        for _, delta in sorted(intervals):
            active += delta
            peak = max(peak, active)
        assert len(intervals) == 34 and active == 0 and peak == 16
        assert_all_permits_free(pool)
    finally:
        publish_release.set()
        for release in releases:
            release.set()
        pool.close()
    assert not any(thread.is_alive() for thread in pool._threads)


@pytest.mark.parametrize("failure", ["cancelled", "work", "callback"])
def test_release_and_drain_cleanup_survive_cancel_or_failure(monkeypatch, failure):
    tracking = []
    drained = threading.Event()
    callback_ran = []

    def finish():
        assert_all_permits_free(pool)
        tracking.append("end")
        drained.set()

    pool = candidate.EpochWorkerPool(
        Execution(),
        nullcontext,
        begin_admission=lambda: tracking.append("begin"),
        end_admission=finish,
    )
    if failure == "cancelled":

        class CancelledFuture(Future):
            def __init__(self):
                super().__init__()
                self.cancel()

        monkeypatch.setattr(candidate, "Future", CancelledFuture)

    def work(_admitted):
        if failure == "work":
            raise ValueError("work failure")

        def publish(_entry):
            callback_ran.append(True)
            raise ValueError("callback failure")

        return {"_after_release": publish}

    try:
        future = pool.submit_before(work, deadline_ns=3, clock=lambda: 2)
        with pytest.raises(CancelledError if failure == "cancelled" else ValueError):
            future.result(3)
        assert drained.wait(3)
        assert tracking == ["begin", "end"]
        assert callback_ran == ([True] if failure == "callback" else [])
        assert_all_permits_free(pool)
    finally:
        pool.close()
    assert not any(thread.is_alive() for thread in pool._threads)


def test_waiting_for_completion_lock_never_admits_past_deadline():
    publishing, publish_release = threading.Event(), threading.Event()
    contender, clock_seen = threading.Event(), threading.Event()
    tracking = []
    pool = candidate.EpochWorkerPool(
        Execution(),
        nullcontext,
        begin_admission=lambda: tracking.append("begin"),
        end_admission=lambda: tracking.append("end"),
    )

    def work(_admitted):
        def publish(_entry):
            publishing.set()
            assert publish_release.wait(5)

        return {"_after_release": publish}

    def expired_clock():
        clock_seen.set()
        return 3

    def submit_expired():
        contender.set()
        return pool.submit_before(
            lambda _admitted: pytest.fail("expired admission executed"),
            deadline_ns=3,
            clock=expired_clock,
        )

    try:
        first = pool.submit_before(work, deadline_ns=3, clock=lambda: 2)
        assert publishing.wait(3)
        with ThreadPoolExecutor(max_workers=1) as submitter:
            pending = submitter.submit(submit_expired)
            assert contender.wait(3)
            assert not clock_seen.wait(0.05)
            publish_release.set()
            assert pending.result(3) is None
        first.result(3)
        assert clock_seen.is_set()
        assert tracking == ["begin", "end", "begin", "end"]
        assert_all_permits_free(pool)
    finally:
        publish_release.set()
        pool.close()
    assert not any(thread.is_alive() for thread in pool._threads)
