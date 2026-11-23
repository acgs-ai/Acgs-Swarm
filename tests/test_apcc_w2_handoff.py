"""Unit tests for the non-blocking observer handoff in w2_campaign."""

from __future__ import annotations

from concurrent.futures import Future
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
import threading
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from constitutional_swarm.apcc.ports import CausalClosureLimits
from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan


@dataclass(frozen=True)
class _FakeExpectations:
    session_id: str = "sess"


class _TrackingLock:
    """Thread lock wrapper recording lock state, acquire counts, and owner thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.acquire_count = 0
        self.fast_fail_count = 0
        self.owner: int | None = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = (
            self._lock.acquire(blocking, timeout)
            if timeout != -1
            else self._lock.acquire(blocking)
        )
        if ok:
            self.acquire_count += 1
            self.owner = threading.get_ident()
        elif not blocking:
            self.fast_fail_count += 1
        return ok

    def release(self) -> None:
        self.owner = None
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def __enter__(self) -> _TrackingLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


class _TrackingCondition:
    """Reentrant Condition wrapper tracking acquire(blocking=...) depth."""

    def __init__(self) -> None:
        self._rlock = threading.RLock()
        self._cond = threading.Condition(self._rlock)
        self.nonblocking_true = 0
        self.nonblocking_false = 0
        self.depth = 0
        self.owner: int | None = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = (
            self._cond.acquire(blocking, timeout)
            if timeout != -1
            else self._cond.acquire(blocking)
        )
        if ok:
            self.depth += 1
            self.owner = threading.get_ident()
            if not blocking:
                self.nonblocking_true += 1
        elif not blocking:
            self.nonblocking_false += 1
        return ok

    def release(self) -> None:
        self.depth -= 1
        if self.depth == 0:
            self.owner = None
        self._cond.release()

    def wait_for(self, predicate: Any, timeout: float | None = None) -> Any:
        saved = self.depth
        self.depth = 0
        self.owner = None
        try:
            return self._cond.wait_for(predicate, timeout=timeout)
        finally:
            self.depth = saved
            self.owner = threading.get_ident()

    def notify_all(self) -> None:
        self._cond.notify_all()

    def __enter__(self) -> _TrackingCondition:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


@dataclass
class _StubHarness:
    plan: WindowPlan
    snapshot_lock: _TrackingLock
    ordered: _TrackingCondition
    stop: threading.Event
    failed: list[BaseException]
    pool: c.CampaignWorkerPool


def _install_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    on_commit: Any = None,
    on_observe: Any = None,
    on_verify: Any = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []

    class _FakeRequest:
        def __init__(self, idx: int) -> None:
            self.idx = idx

        def canonical_hash(self) -> str:
            return f"req-hash-{self.idx}"

    class _FakeTarget:
        def __init__(self, idx: int) -> None:
            self.idx = idx

        def to_object(self) -> dict[str, Any]:
            return {"idx": self.idx}

    class _FakeAdapter:
        def execute_trusted(self, stimulus: Any, *, execution: Any) -> Any:
            del stimulus, execution
            if on_commit is not None:
                on_commit()
            return SimpleNamespace(authoritative_outcome="committed")

    counter_lock = threading.Lock()
    counter = 0

    def next_idx() -> int:
        nonlocal counter
        with counter_lock:
            val = counter
            counter += 1
            return val

    monkeypatch.setattr(
        c,
        "_config_object",
        lambda _a: {
            "authority_store_id": "s",
            "bindings": [],
            "freshness": {
                "maximum_staleness_ms": "60000",
                "issued_status_lifetime_ms": "60000",
            },
        },
    )
    monkeypatch.setattr(c, "encode_observer_launch_attestation", lambda _l: b"launch")
    monkeypatch.setattr(d, "_expectations", lambda _l: _FakeExpectations())
    monkeypatch.setattr(c, "sign_attempt_authorization", lambda stmt, _p: stmt)
    monkeypatch.setattr(c, "sign_governed_receipt", lambda payload, _p: payload)
    monkeypatch.setattr(c, "_encode_commit_request", lambda req: f"req-{req.idx}")
    monkeypatch.setattr(c, "encode_signed_authority_observation", lambda _r: b"obs")
    monkeypatch.setattr(d, "B6AuthorityAdapter", _FakeAdapter)
    monkeypatch.setattr(
        d,
        "_verify_operation",
        lambda *args, **kwargs: on_verify(args[0]) if on_verify is not None else None,
    )
    monkeypatch.setattr(c, "provenance", lambda: {"files": {}})
    from constitutional_swarm.apcc_empirical.w2_pacing import Accounting

    monkeypatch.setattr(
        c,
        "verify_accounting",
        lambda plan, rows, **kwargs: Accounting(
            scheduled=plan.scheduled_operations,
            committed=sum(1 for r in rows if r.get("outcome") == "committed"),
            overloads=sum(1 for r in rows if r.get("outcome") == "overload"),
            late_completions=0,
            on_time_commits=sum(1 for r in rows if r.get("outcome") == "committed"),
            max_occupancy=1,
            qualified=False,
        ),
    )
    monkeypatch.setattr(
        c,
        "verify_ledger",
        lambda path, *, expected_sha256: {
            "ledger_path": str(path),
            "ledger_sha256": expected_sha256,
            "accounting": {
                "committed": len(events),
                "overloads": 0,
                "late_completions": 0,
            },
        },
    )

    class _FakeExecution:
        pid = 1234

        def w2_lane(self, _lane: int) -> Any:
            return nullcontext()

        def load_dag(self, _dag: Any) -> None:
            return None

        def prepare_claim(self, node_id: str, agent_id: str) -> tuple[str, str]:
            return (node_id, agent_id)

        def claim(self, node_id: str, agent_id: str, auth: Any) -> None:
            del node_id, agent_id, auth

        def produce_result(
            self, node_id: str, artifact: Any, *, authorization: Any
        ) -> tuple[str, Any, Any]:
            return (node_id, artifact, authorization)

        def build_request(self, _receipt: Any) -> _FakeRequest:
            return _FakeRequest(next_idx())

        def observation_target(
            self, request: _FakeRequest, *, request_nonce: str
        ) -> _FakeTarget:
            del request_nonce
            return _FakeTarget(request.idx)

    class _FakeClient:
        def observe(self, target: _FakeTarget) -> dict[str, Any]:
            if on_observe is not None:
                on_observe(target.idx)
            events.append({"observed": target.idx})
            return {"ok": True}

    env = {
        "execution": _FakeExecution(),
        "observer": SimpleNamespace(
            launch_attestation=SimpleNamespace(observer_pid=2345, session_id="sess"),
            client=_FakeClient(),
        ),
    }
    return env, events


def _make_payloads(scheduled: int) -> tuple[dict[int, list[tuple[Any, Any]]], dict[int, object]]:
    chains = scheduled // 100
    payloads = {
        chain: [
            (
                SimpleNamespace(node_id=f"n-{i}"),
                SimpleNamespace(agent_id=f"agent-{i:03d}"),
            )
            for i in range(100)
        ]
        for chain in range(chains)
    }
    dags = {chain: object() for chain in range(chains)}
    return payloads, dags


def _run_synthetic_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    scheduled: int = 100,
    duration_ns: int = 500_000_000,
    on_commit: Any = None,
    on_observe: Any = None,
    on_verify: Any = None,
    completion_after_release: bool = False,
) -> tuple[dict[str, Any], _StubHarness, list[dict[str, Any]]]:
    env, events = _install_stubs(
        monkeypatch,
        on_commit=on_commit,
        on_observe=on_observe,
        on_verify=on_verify,
    )
    plan = WindowPlan(
        duration_ns=duration_ns,
        scheduled_operations=scheduled,
        admission_grace_ns=duration_ns,
        operation_sla_ns=5_000_000_000,
        drain_ns=2_000_000_000,
        operation_floor=scheduled,
    )
    snapshot_lock = _TrackingLock()
    ordered = _TrackingCondition()
    stop = threading.Event()
    failed: list[BaseException] = []
    pool = c.CampaignWorkerPool()
    harness = _StubHarness(plan, snapshot_lock, ordered, stop, failed, pool)
    payloads, dags = _make_payloads(scheduled)
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]
    try:
        result = c._execute_window(
            tmp_path,
            plan=plan,
            child=SimpleNamespace(
                authority=SimpleNamespace(
                    trust_bindings=(), causal_limits=CausalClosureLimits()
                )
            ),
            controller=Ed25519PrivateKey.generate(),
            source={"files": {}},
            run_id="handoff-test",
            authority=SimpleNamespace(pid=1111),
            observer=env["observer"],
            execution=env["execution"],
            pool=pool,
            stop=stop,
            ordered=ordered,
            snapshot_lock=snapshot_lock,
            failed=failed,
            payloads=payloads,
            dags=dags,
            producers=producers,
            stream=object(),
            certificates={},
            window_index=0,
            chain_offset=0,
            previous_ledger=None,
            plans=(plan,),
            completion_after_release=completion_after_release,
        )
        return result, harness, events
    finally:
        pool.close()


def test_handoff_fast_path_uses_single_snapshot_hold_and_overlaps_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verify_states: list[tuple[bool, int]] = []
    saw_snapshot_locked_in_verify: list[bool] = []
    lock_ref: list[_TrackingLock] = []

    def _on_verify(row: dict[str, Any]) -> None:
        del row
        saw_snapshot_locked_in_verify.append(lock_ref[0].locked())
        acquired_by_peer: list[bool] = []

        def _probe() -> None:
            ok = lock_ref[0].acquire(blocking=True, timeout=0.5)
            if ok:
                lock_ref[0].release()
            acquired_by_peer.append(ok)

        peer = threading.Thread(target=_probe)
        peer.start()
        peer.join(timeout=1.0)
        verify_states.append(
            (acquired_by_peer == [True], len(saw_snapshot_locked_in_verify))
        )

    env, _ = _install_stubs(monkeypatch, on_verify=_on_verify)
    plan = WindowPlan(
        duration_ns=500_000_000,
        scheduled_operations=100,
        admission_grace_ns=500_000_000,
        operation_sla_ns=5_000_000_000,
        drain_ns=2_000_000_000,
        operation_floor=100,
    )
    snapshot_lock = _TrackingLock()
    lock_ref.append(snapshot_lock)
    ordered = _TrackingCondition()
    stop = threading.Event()
    failed: list[BaseException] = []
    pool = c.CampaignWorkerPool()
    payloads, dags = _make_payloads(100)
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]
    try:
        res = c._execute_window(
            tmp_path,
            plan=plan,
            child=SimpleNamespace(authority=SimpleNamespace(trust_bindings=())),
            controller=Ed25519PrivateKey.generate(),
            source={"files": {}},
            run_id="fast-path",
            authority=SimpleNamespace(pid=1111),
            observer=env["observer"],
            execution=env["execution"],
            pool=pool,
            stop=stop,
            ordered=ordered,
            snapshot_lock=snapshot_lock,
            failed=failed,
            payloads=payloads,
            dags=dags,
            producers=producers,
            stream=object(),
            certificates={},
            window_index=0,
            chain_offset=0,
            previous_ledger=None,
            plans=(plan,),
        )
    finally:
        pool.close()

    assert res["accounting"]["committed"] == 100
    assert not failed
    assert ordered.nonblocking_true == 100
    # 100 fast-path worker acquires (1 per op) + 100 _on_verify probe acquires.
    assert snapshot_lock.acquire_count == 100 + len(verify_states)
    assert all(not locked for locked in saw_snapshot_locked_in_verify)
    assert all(peer_ok for peer_ok, _ in verify_states)
    assert not snapshot_lock.locked()
    assert ordered.depth == 0


def test_handoff_falls_back_cleanly_when_ordered_contended_or_out_of_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot_lock = _TrackingLock()
    ordered = _TrackingCondition()
    stop = threading.Event()
    failed: list[BaseException] = []
    ordered_acquired = threading.Event()
    commit_entered = threading.Event()
    snapshot_free_after_commit = threading.Event()

    def _on_commit() -> None:
        commit_entered.set()

    env, _ = _install_stubs(monkeypatch, on_commit=_on_commit)
    plan = WindowPlan(
        duration_ns=400_000_000,
        scheduled_operations=100,
        admission_grace_ns=400_000_000,
        operation_sla_ns=5_000_000_000,
        drain_ns=2_000_000_000,
        operation_floor=100,
    )
    pool = c.CampaignWorkerPool()
    payloads, dags = _make_payloads(100)
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]

    def _hold_ordered_until_snapshot_freed() -> None:
        with ordered:
            ordered_acquired.set()
            assert commit_entered.wait(timeout=5.0)
            assert snapshot_lock.acquire(blocking=True, timeout=5.0)
            snapshot_lock.release()
            snapshot_free_after_commit.set()
            ordered.notify_all()

    watcher = threading.Thread(target=_hold_ordered_until_snapshot_freed)
    watcher.start()
    assert ordered_acquired.wait(timeout=5.0)
    try:
        res = c._execute_window(
            tmp_path,
            plan=plan,
            child=SimpleNamespace(authority=SimpleNamespace(trust_bindings=())),
            controller=Ed25519PrivateKey.generate(),
            source={"files": {}},
            run_id="slow-fallback",
            authority=SimpleNamespace(pid=1111),
            observer=env["observer"],
            execution=env["execution"],
            pool=pool,
            stop=stop,
            ordered=ordered,
            snapshot_lock=snapshot_lock,
            failed=failed,
            payloads=payloads,
            dags=dags,
            producers=producers,
            stream=object(),
            certificates={},
            window_index=0,
            chain_offset=0,
            previous_ledger=None,
            plans=(plan,),
        )
    finally:
        watcher.join(timeout=5.0)
        pool.close()

    assert snapshot_free_after_commit.is_set()
    assert res["accounting"]["committed"] == 100
    assert ordered.nonblocking_false >= 1
    assert snapshot_lock.acquire_count >= 101
    assert not snapshot_lock.locked()
    assert ordered.depth == 0


def test_handoff_wrong_ticket_branch_releases_ordered_and_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_after: list[Any] = []
    orig_pool_cls = c.CampaignWorkerPool

    class _DelayedReleasePool(orig_pool_cls):
        def submit_before(
            self, function: Any, *, deadline_ns: int, clock: Any
        ) -> Future[Any] | None:
            def _wrapped(admitted_ns: int) -> Any:
                entry = function(admitted_ns)
                after = entry.pop("_after_release", None)
                if after is not None:
                    seen_after.append(after)
                    if entry["proof"]["index"] == 0:
                        threading.Event().wait(0.02)
                    after(entry)
                return entry

            return super().submit_before(_wrapped, deadline_ns=deadline_ns, clock=clock)

    monkeypatch.setattr(c, "CampaignWorkerPool", _DelayedReleasePool)
    result, harness, _ = _run_synthetic_window(
        tmp_path,
        monkeypatch,
        scheduled=200,
        duration_ns=2_000_000_000,
        completion_after_release=True,
    )
    assert result["accounting"]["committed"] == 200
    assert len(seen_after) == 200
    assert harness.ordered.nonblocking_true + harness.ordered.nonblocking_false >= 200
    assert not harness.snapshot_lock.locked()
    assert harness.ordered.depth == 0


@pytest.mark.parametrize("fail_stage", ("commit", "fast_observe"))
def test_handoff_exceptions_release_snapshot_and_ordered_locks_without_deadlock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_stage: str
) -> None:
    commit_started = threading.Event()
    ordered_acquired = threading.Event()
    release_ordered = threading.Event()

    def _on_commit() -> None:
        if fail_stage == "commit":
            commit_started.set()
            raise RuntimeError(f"boom during {fail_stage}")

    def _on_observe(_idx: int) -> None:
        if fail_stage == "fast_observe":
            raise RuntimeError(f"boom during {fail_stage}")

    env, _ = _install_stubs(
        monkeypatch, on_commit=_on_commit, on_observe=_on_observe
    )
    plan = WindowPlan(
        duration_ns=200_000_000,
        scheduled_operations=100,
        admission_grace_ns=200_000_000,
        operation_sla_ns=5_000_000_000,
        drain_ns=1_000_000_000,
        operation_floor=100,
    )
    snapshot_lock = _TrackingLock()
    ordered = _TrackingCondition()
    stop = threading.Event()
    failed: list[BaseException] = []
    pool = c.CampaignWorkerPool()
    payloads, dags = _make_payloads(100)
    producers = [Ed25519PrivateKey.generate() for _ in range(100)]

    def _hold_ordered_and_wait_snapshot() -> None:
        with ordered:
            ordered_acquired.set()
            assert commit_started.wait(timeout=5.0)
            assert snapshot_lock.acquire(blocking=True, timeout=5.0)
            snapshot_lock.release()
            release_ordered.set()

    holder = threading.Thread(target=_hold_ordered_and_wait_snapshot)
    if fail_stage == "commit":
        holder.start()
        assert ordered_acquired.wait(timeout=5.0)
    try:
        with pytest.raises((RuntimeError, InterruptedError)):
            c._execute_window(
                tmp_path,
                plan=plan,
                child=SimpleNamespace(authority=SimpleNamespace(trust_bindings=())),
                controller=Ed25519PrivateKey.generate(),
                source={"files": {}},
                run_id=f"err-{fail_stage}",
                authority=SimpleNamespace(pid=1111),
                observer=env["observer"],
                execution=env["execution"],
                pool=pool,
                stop=stop,
                ordered=ordered,
                snapshot_lock=snapshot_lock,
                failed=failed,
                payloads=payloads,
                dags=dags,
                producers=producers,
                stream=object(),
                certificates={},
                window_index=0,
                chain_offset=0,
                previous_ledger=None,
                plans=(plan,),
            )
    finally:
        if fail_stage == "commit":
            holder.join(timeout=5.0)
        pool.close()

    assert any(f"boom during {fail_stage}" in str(err) for err in failed)
    if fail_stage == "commit":
        assert release_ordered.is_set()
    assert not snapshot_lock.locked()
    assert ordered.depth == 0
