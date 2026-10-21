"""Warm continuation is bounded and replay requires every predecessor ledger."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan


def _plan():
    return WindowPlan(
        duration_ns=70_000_000_000,
        scheduled_operations=100,
        admission_grace_ns=700_000_000,
        operation_sla_ns=5_000_000_000,
        drain_ns=5_000_000_000,
        operation_floor=100,
    )


def test_lifetime_rejects_four_low_rate_windows_before_filesystem_mutation(tmp_path):
    plan = replace(_plan(), duration_ns=1_000_000_000_000)
    with pytest.raises(ValueError, match="observer lifetime bound"):
        c.run_repetition(tmp_path / "absent", plans=(plan,) * 4)
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("plans", [(), (_plan(),) * 5, [_plan()], (None,)])
def test_repetition_requires_bounded_explicit_plans(plans):
    with pytest.raises(ValueError):
        c._repetition_lifetime(plans)


def test_repetition_lifetime_includes_each_drain_and_margin():
    plan = replace(_plan(), duration_ns=250_000_000_000)
    assert c._repetition_lifetime((plan,) * 4) == 1_120_000


def test_admission_timestamps_after_permit_acquisition_and_releases_late_permit():
    pool = c.CampaignWorkerPool()
    ran = []

    def clock():
        # Exactly one permit must already be held when the clock is sampled.
        acquired = []
        try:
            while pool._permits.acquire(blocking=False):
                acquired.append(True)
            assert len(acquired) == 15
        finally:
            for _ in acquired:
                pool._permits.release()
        return 10

    try:
        assert pool.submit_before(ran.append, deadline_ns=10, clock=clock) is None
        assert ran == []
        future = pool.submit_before(ran.append, deadline_ns=11, clock=clock)
        assert future is not None
        future.result(timeout=5)
        assert ran == [10]
    finally:
        pool.close()


def test_admission_clock_failure_releases_permit():
    pool = c.CampaignWorkerPool()

    def failed_clock():
        raise ValueError("clock failed")

    try:
        with pytest.raises(ValueError, match="clock failed"):
            pool.submit_before(lambda admitted: None, deadline_ns=1, clock=failed_clock)
        for _ in range(16):
            assert pool._permits.acquire(blocking=False)
        assert not pool._permits.acquire(blocking=False)
        for _ in range(16):
            pool._permits.release()
    finally:
        pool.close()


@pytest.fixture(scope="module")
def warm_repetition(tmp_path_factory):
    directory = tmp_path_factory.mktemp("w2-warm") / "run"
    return c.run_repetition(directory, plans=(_plan(), _plan()))


def test_warm_reuses_handles_with_fresh_clock_and_global_chain_identity(
    warm_repetition,
):
    windows = warm_repetition["windows"]
    assert len(windows) == 2
    headers = []
    for window in windows:
        assert window["accounting"]["committed"] == 100
        assert window["campaign_eligible"] is False
        path = Path(window["ledger_path"])
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        headers.append(rows[0])
        assert {entry["proof"]["chain"] for entry in rows[1:-1]} == {len(headers) - 1}
        assert rows[1]["pacing"]["scheduled_ns"] == 0
    assert [header["phase"] for header in headers] == ["cold", "warm"]
    for field in (
        "authority_pid",
        "executor_pid",
        "observer_pid",
        "launch",
        "expected_public_config",
        "worker_ids",
    ):
        assert headers[0][field] == headers[1][field]
    assert headers[1]["started_wall_ms"] > headers[0]["started_wall_ms"]
    assert (
        c.verify_ledger(
            Path(windows[1]["ledger_path"]), expected_sha256=windows[1]["ledger_sha256"]
        )
        == windows[1]
    )


def test_truncated_manifest_rejected_even_with_fresh_external_hash(
    warm_repetition, tmp_path
):
    path = Path(warm_repetition["manifest_path"])
    manifest = json.loads(path.read_bytes())
    manifest["windows"] = manifest["windows"][:1]
    target = tmp_path / "repetition.json"
    target.write_bytes(c.d._json(manifest) + b"\n")
    first = Path(warm_repetition["windows"][0]["ledger_path"])
    (tmp_path / first.name).write_bytes(first.read_bytes())
    with pytest.raises(ValueError, match="identity/link"):
        c.verify_repetition(target, expected_sha256=c.d._sha(target.read_bytes()))


def test_warm_replay_rejects_missing_predecessor(warm_repetition, tmp_path):
    second = warm_repetition["windows"][1]
    original = Path(second["ledger_path"])
    isolated = tmp_path / original.name
    isolated.write_bytes(original.read_bytes())
    with pytest.raises(FileNotFoundError):
        c.verify_ledger(isolated, expected_sha256=second["ledger_sha256"])
