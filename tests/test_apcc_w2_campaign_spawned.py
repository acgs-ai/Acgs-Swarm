"""Real fixed-window execution and controller-resealed campaign fault cases."""

import hashlib
import json
import os
from pathlib import Path
import threading

import pytest

from constitutional_swarm.apcc.crypto import b64u_encode
from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan


def plan(duration=40_000_000_000, scheduled=100):
    return WindowPlan(
        duration, scheduled, 390_000_000, 5_000_000_000, 10_000_000_000, 100
    )


@pytest.fixture(scope="module")
def campaign(tmp_path_factory):
    directory = tmp_path_factory.mktemp("w2-campaign")
    captured = {}
    original = d.q._configuration

    def configuration(*args, **kwargs):
        result = original(*args, **kwargs)
        captured["controller"] = result[3]
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(d.q, "_configuration", configuration)
        result = c.run_window(directory / "run", plan=plan(140_000_000_000, 200))
    ledger = Path(result["ledger_path"])
    values = [json.loads(line) for line in ledger.read_bytes().splitlines()]
    assert result["accounting"]["committed"] == 200
    assert result["campaign_eligible"] is False
    return directory, values, captured["controller"], result


def test_real_window_independent_cli(campaign):
    import subprocess
    import sys

    _, _, _, result = campaign
    replay = subprocess.run(
        [
            sys.executable,
            "scripts/run_apcc_w2_campaign.py",
            "verify",
            "--ledger",
            result["ledger_path"],
            "--expected-sha256",
            result["ledger_sha256"],
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["result"]["accounting"]["committed"] == 200


@pytest.mark.parametrize(
    "fault",
    [
        "overloads",
        "skew",
        "splice",
        "downgrade",
        "truncate",
        "worker_overlap",
        "late_count",
        "slot",
        "profile_digest",
        "launch_pid",
        "authority_key",
        "input_hash",
        "output_hash",
        "nonce",
        "commit_id",
        "predecessor",
        "observation",
        "pacing_bind",
        "floor",
    ],
)
def test_campaign_resealed_mutations(campaign, fault):
    directory, original, controller, _ = campaign
    values = json.loads(json.dumps(original))
    header, footer = values[0], values[-1]
    operations = [entry for entry in values if entry["type"] == "operation"]
    row = operations[1]["proof"]
    pace = operations[1]["pacing"]
    if fault == "overloads":
        footer["accounting"]["overloads"] += 1
    elif fault == "skew":
        header["started_wall_ms"] += 10_000
    elif fault == "splice":
        row["chain"] += 1
    elif fault == "downgrade":
        header["expected_public_config"].pop("causal_profile")
        header["config_sha256"] = d._sha(d._json(header["expected_public_config"]))
    elif fault == "truncate":
        values.remove(operations[-1])
    elif fault == "worker_overlap":
        pace["worker_id"] = operations[0]["pacing"]["worker_id"]
        pace["started_ns"] = 0
    elif fault == "late_count":
        footer["accounting"]["late_completions"] += 1
    elif fault == "slot":
        pace["deadline_ns"] += 1
    elif fault == "profile_digest":
        header["config_sha256"] = "0" * 64
    elif fault == "launch_pid":
        header["observer_pid"] += 1
    elif fault == "authority_key":
        header["trust"][0]["public_key"] = header["controller_public_key"]
    elif fault == "input_hash":
        row["request"]["receipt"]["payload"]["input_digest"] = "sha256:" + "0" * 64
    elif fault == "output_hash":
        row["request"]["receipt"]["payload"]["output_digest"] = "sha256:" + "0" * 64
    elif fault == "nonce":
        row["nonce"] = operations[0]["proof"]["nonce"]
    elif fault == "commit_id":
        row["request_hash"] = operations[0]["proof"]["request_hash"]
    elif fault == "predecessor":
        row["node_index"] -= 1
    elif fault == "observation":
        row["observation"] = operations[0]["proof"]["observation"]
    elif fault == "pacing_bind":
        pace["commit_end_ns"] -= 1
    elif fault == "floor":
        header["plan"]["qualification"] = True
    prefix = b"".join(d._json(value) + b"\n" for value in values[:-1])
    footer["prefix_sha256"] = d._sha(prefix)
    footer.pop("signature")
    footer["signature"] = b64u_encode(controller.sign(c.DOMAIN + d._json(footer)))
    raw = prefix + d._json(footer) + b"\n"
    path = directory / f"fault-{fault}.jsonl"
    path.write_bytes(raw)
    with pytest.raises(Exception):
        c.verify_ledger(path, expected_sha256=hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("fault", ["cancel", "observer_crash", "permit_exhaustion"])
def test_failure_cleanup(tmp_path, monkeypatch, fault):
    pids = []
    stop = threading.Event()
    observer_holder = []
    original_start = c.start_authority
    original_observer = c.start_authority_observer

    def start(*args, **kwargs):
        handle = original_start(*args, **kwargs)
        pids.extend([handle.pid, handle._scheduler_worker.pid])
        return handle

    def observer(*args, **kwargs):
        handle = original_observer(*args, **kwargs)
        pids.append(int(handle.launch_attestation.observer_pid))
        observer_holder.append(handle)
        return handle

    monkeypatch.setattr(c, "start_authority", start)
    monkeypatch.setattr(c, "start_authority_observer", observer)
    original_execute = d.B6AuthorityAdapter.execute_trusted

    def execute(*args, **kwargs):
        result = original_execute(*args, **kwargs)
        if fault == "cancel":
            stop.set()
        elif fault == "observer_crash":
            os.kill(int(observer_holder[0].launch_attestation.observer_pid), 9)
        return result

    monkeypatch.setattr(d.B6AuthorityAdapter, "execute_trusted", execute)
    if fault == "permit_exhaustion":
        monkeypatch.setattr(
            c.CampaignWorkerPool, "submit_before", lambda self, function, **kwargs: None
        )
        result = c.run_window(tmp_path / "run", plan=plan(1_000_000_000), cancel=stop)
        assert result["accounting"]["overloads"] == 100
        assert result["accounting"]["committed"] == 0
    else:
        with pytest.raises(Exception):
            c.run_window(tmp_path / "run", plan=plan(1_000_000_000), cancel=stop)
        ledgers = tuple((tmp_path / "run").glob("*.jsonl"))
        assert ledgers
        assert all(
            not path.read_bytes().endswith(b'"type":"footer"}\n') for path in ledgers
        )
    assert pids
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    assert not any(
        thread.name.startswith("w2-worker-") for thread in threading.enumerate()
    )
    assert not tuple((tmp_path / "run").glob("*.key"))
    descriptor_dir = Path("/proc/self/fd")
    if descriptor_dir.exists():
        for descriptor in descriptor_dir.iterdir():
            try:
                target = descriptor.resolve(strict=True)
            except FileNotFoundError:
                continue
            assert not target.is_relative_to(tmp_path / "run")


@pytest.mark.parametrize("fault", ["permit_exhaustion", "cancel", "observer_crash"])
def test_real_sixteen_permit_multichain_fault_cleanup(tmp_path, monkeypatch, fault):
    """Fixture-only verification hold induces saturation; production has no gate."""
    stop = threading.Event()
    release = threading.Event()
    saturated = threading.Event()
    owned_pids = []
    observer_holder = []
    original_start = c.start_authority
    original_observer = c.start_authority_observer
    original_verify = d._verify_operation
    original_submit = c.CampaignWorkerPool.submit_before

    def start(*args, **kwargs):
        handle = original_start(*args, **kwargs)
        owned_pids.extend([handle.pid, handle._scheduler_worker.pid])
        return handle

    def observer(*args, **kwargs):
        handle = original_observer(*args, **kwargs)
        owned_pids.append(int(handle.launch_attestation.observer_pid))
        observer_holder.append(handle)
        return handle

    def verify(row, *args, **kwargs):
        if row["index"] == 0:
            assert release.wait(20), "fixture never filled all 16 real permits"
        return original_verify(row, *args, **kwargs)

    def submit(pool, function, **kwargs):
        result = original_submit(pool, function, **kwargs)
        if result is None and pool._permits._value == 0 and not saturated.is_set():
            saturated.set()
            if fault == "cancel":
                stop.set()
            elif fault == "observer_crash":
                os.kill(int(observer_holder[0].launch_attestation.observer_pid), 9)
            # Preserve one observed rejection before returning permits.
            threading.Timer(0.05, release.set).start()
        return result

    monkeypatch.setattr(c, "start_authority", start)
    monkeypatch.setattr(c, "start_authority_observer", observer)
    monkeypatch.setattr(d, "_verify_operation", verify)
    monkeypatch.setattr(c.CampaignWorkerPool, "submit_before", submit)
    policy = WindowPlan(
        2_000_000_000, 1600, 500_000_000, 10_000_000_000, 15_000_000_000, 100
    )
    try:
        if fault == "permit_exhaustion":
            result = c.run_window(tmp_path / "run", plan=policy, cancel=stop)
            assert result["accounting"]["overloads"] > 0
            assert result["accounting"]["max_occupancy"] == 16
            assert result["campaign_eligible"] is False
        else:
            with pytest.raises(Exception):
                c.run_window(tmp_path / "run", plan=policy, cancel=stop)
    finally:
        release.set()
    assert saturated.is_set()
    assert owned_pids
    for pid in owned_pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    assert not any(
        thread.name.startswith("w2-worker-") for thread in threading.enumerate()
    )
