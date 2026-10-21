"""W2 payload, admission, and fail-closed ledger regression tests."""

import threading
from pathlib import Path
import pytest
from constitutional_swarm.apcc_empirical.w2_driver import (
    WorkerPool,
    build_payloads,
    verify_ledger,
)
from constitutional_swarm.apcc_empirical.qualification_v3 import _json, _node_input


def test_all_chain_payloads_have_exact_sizes_and_edges():
    for chain in range(2):
        for index in range(100):
            node, artifact = build_payloads(chain, index)
            assert len(_node_input(node)) == 1024
            assert len(_json(artifact.canonical_dict())) == 4096
            assert node.depends_on == ((f"node-{index - 1:03d}",) if index else ())
            assert artifact.agent_id == f"agent-{index:03d}"


def test_sixteen_live_workers_reject_seventeenth_and_release_on_failure():
    pool = WorkerPool()
    release = threading.Event()
    barrier = threading.Barrier(17)

    def blocked():
        barrier.wait(timeout=10)
        release.wait(timeout=10)
        return threading.get_ident()

    try:
        futures = [pool.submit(blocked) for _ in range(16)]
        barrier.wait(timeout=10)
        assert len(set(pool.worker_ids)) == 16
        assert pool.submit(lambda: None) is None
        release.set()
        assert {future.result(timeout=10) for future in futures} == set(pool.worker_ids)

        def fail():
            raise ValueError("injected")

        future = pool.submit(fail)
        with pytest.raises(ValueError, match="injected"):
            future.result(timeout=10)
    finally:
        release.set()
        pool.close()
    assert pool.submit(lambda: None) is None


def test_replay_rejects_unsealed_tail(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"type":"header"}\n')
    with pytest.raises(ValueError, match="unsealed"):
        verify_ledger(path)


def test_pool_releases_permit_before_future_completion_and_survives_failure():
    pool = WorkerPool()
    try:
        for _ in range(40):
            future = pool.submit(lambda: 1)
            assert future is not None and future.result(timeout=5) == 1
        assert all(thread.is_alive() for thread in pool._threads)
    finally:
        pool.close()


def test_pool_partial_start_failure_cleans_threads(monkeypatch):
    original = threading.Thread.start
    started = []

    def fail_third(thread):
        if len(started) == 2:
            raise RuntimeError("injected start failure")
        original(thread)
        started.append(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_third)
    with pytest.raises(RuntimeError, match="injected start"):
        WorkerPool()
    assert not any(thread.is_alive() for thread in started)


def test_cancelled_pending_job_does_not_kill_worker(monkeypatch):
    from concurrent.futures import CancelledError, Future
    from constitutional_swarm.apcc_empirical import w2_driver

    class CancelAtPickup(Future):
        def set_running_or_notify_cancel(self):
            self.cancel()
            return super().set_running_or_notify_cancel()

    pool = WorkerPool()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(w2_driver, "Future", CancelAtPickup)
            cancelled = pool.submit(lambda: pytest.fail("cancelled job ran"))
            assert cancelled is not None
            with pytest.raises(CancelledError):
                cancelled.result(timeout=5)
        future = pool.submit(lambda: 17)
        assert future is not None and future.result(timeout=5) == 17
        assert all(thread.is_alive() for thread in pool._threads)
    finally:
        pool.close()


def test_permit_released_before_completion_callback_can_submit():
    pool = WorkerPool()
    hold = threading.Event()
    finish = threading.Event()
    barrier = threading.Barrier(16)
    replacement = []
    callback_done = threading.Event()

    def blocked():
        barrier.wait(timeout=5)
        hold.wait(timeout=5)

    try:
        occupied = [pool.submit(blocked) for _ in range(15)]
        barrier.wait(timeout=5)
        future = pool.submit(lambda: finish.wait(timeout=5))
        assert future is not None

        def on_complete(_):
            replacement.append(pool.submit(lambda: 1))
            callback_done.set()

        future.add_done_callback(on_complete)
        finish.set()
        future.result(timeout=5)
        assert callback_done.wait(timeout=5)
        # Callback completion is synchronized by its replacement future/event.
        for thread in pool._threads:
            assert thread.is_alive()
        hold.set()
        for pending in occupied:
            pending.result(timeout=5)
        assert len(replacement) == 1 and replacement[0] is not None
        assert replacement[0].result(timeout=5) == 1
    finally:
        finish.set()
        hold.set()
        pool.close()
