"""Pure fixture tests only: these never launch authority or workload processes."""

import copy
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
import pytest
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical import w2_numeric_cold as n
from constitutional_swarm.apcc_empirical.w2_campaign_plan import (
    diagnostic_window_plan,
    frozen_plan_sha256,
)
from constitutional_swarm.apcc_empirical.w2_pacing import verify_accounting

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "tests/fixtures/apcc_w2/coverage-candidate.json"
SEED = "rbvmXgcYX0rklrCXS4k1IEZOpOHFxCyQNhdptsEGOdg"


def test_complete_345_coverage_mapping():
    row = n.validate_coverage(
        json.loads(COVERAGE.read_bytes()),
        ROOT / "experiments/apcc-1/matrix.v2.json",
        frozen_plan_sha256(),
    )
    assert row["seed"] == 104729 and row["repetition"] == 0


@pytest.mark.parametrize(
    "mutation",
    ["truncate", "floor", "seed", "duration", "series", "sample", "duplicate"],
)
def test_coverage_mutations(mutation):
    value = json.loads(COVERAGE.read_bytes())
    if mutation == "truncate":
        value["windows"].pop()
    if mutation == "floor":
        value["windows"][20]["minimum_on_time_commits"] = 200
    if mutation == "seed":
        value["windows"][10]["sub_seed_b64u"] = SEED
    if mutation == "duration":
        value["windows"][-1]["mapped_window_ms"] = 30000
    if mutation == "series":
        value["series"][-1]["ordered_trial_ids"].reverse()
    if mutation == "sample":
        value["windows"][20]["stimulus_sample"]["input_sha256"] = "0" * 64
    if mutation == "duplicate":
        value["windows"][1] = copy.deepcopy(value["windows"][0])
    with pytest.raises(ValueError):
        n.validate_coverage(
            value, ROOT / "experiments/apcc-1/matrix.v2.json", frozen_plan_sha256()
        )


def test_payloads_fixed_size_deterministic_and_seed_affects_bytes():
    seen = set()
    for chain, node in ((0, 0), (0, 99), (99, 99)):
        task, artifact = n.seeded_payloads(SEED, chain, node)
        assert len(d._node_input(task)) == 1024
        assert len(d._json(artifact.canonical_dict())) == 4096
        assert (task, artifact) == n.seeded_payloads(SEED, chain, node)
        seen.add(d._sha(d._node_input(task)))
    assert len(seen) == 3
    assert n.seeded_payloads(SEED, 0, 0) != d.build_payloads(0, 0)


@pytest.mark.parametrize(
    "elapsed,accepted", [(197999, True), (198000, False), (-1, False)]
)
def test_setup_boundary(elapsed, accepted):
    context = object.__new__(n.Context)
    context.begin_setup()
    launch = SimpleNamespace(not_before_ms="1000000", not_after_ms="2200000")
    if accepted:
        context.check_setup(
            launch, 1000000 + elapsed, diagnostic_window_plan("cell_10_pps")
        )
    else:
        with pytest.raises(ValueError):
            context.check_setup(
                launch, 1000000 + elapsed, diagnostic_window_plan("cell_10_pps")
            )


def test_failure_prefix_not_fabricated_and_success_rejects():
    plan = diagnostic_window_plan("cell_10_pps")
    row = {
        **asdict(plan.slot(0)),
        "outcome": "overload",
        "decision_ns": 25000000,
        "reason": "permit_exhausted",
    }
    count = verify_accounting(
        plan,
        [row],
        worker_ids=list(range(1, 17)),
        failure_prefix=True,
        slot_hard_ceiling_ns=225000000,
    )
    assert count.scheduled == 10000 and count.overloads == 1 and count.committed == 0
    assert 10000 - count.overloads - count.committed == 9999
    with pytest.raises(ValueError):
        verify_accounting(plan, [row], worker_ids=list(range(1, 17)))


@pytest.mark.parametrize("end,late", [(200000000, False), (200000001, True)])
def test_sla_includes_published_release(end, late):
    plan = diagnostic_window_plan("cell_10_pps")
    row = {
        **asdict(plan.slot(0)),
        "outcome": "committed",
        "admitted_ns": 0,
        "started_ns": 1,
        "commit_end_ns": 2,
        "end_ns": end,
        "worker_id": 1,
    }
    result = verify_accounting(
        plan,
        [row],
        worker_ids=list(range(1, 17)),
        failure_prefix=True,
        slot_hard_ceiling_ns=225000000,
    )
    assert result.late_completions == int(late)
    assert n.Context.is_late(row, plan) == late


def test_fixture_gate_never_authorizes(tmp_path):
    with pytest.raises(ValueError):
        n.validate_acceptance({"fixture": True}, tmp_path)


@pytest.mark.parametrize("name", ["../private", "/tmp/private", "a/../b", "a//b"])
def test_external_path_confinement(tmp_path, name):
    with pytest.raises(ValueError):
        n.child(tmp_path, name)


def test_duplicate_noncanonical_json_rejected():
    with pytest.raises(ValueError):
        n.canonical(b'{"x":1,"x":1}')


def test_real_pool_releases_before_publication_then_blocks_fatal_admission():
    """Thread fixture only; no APCC authority, observer, SQLite or workload."""
    import threading
    from contextlib import nullcontext
    from constitutional_swarm.apcc_empirical.w2_renewal_campaign import EpochWorkerPool

    execution = SimpleNamespace(check_w2_admission_epoch=lambda: None)
    pool = EpochWorkerPool(execution, nullcontext)
    fatal = threading.Event()
    pool._numeric_fatal = fatal
    observed = []

    def publication(entry):
        # The pool lock is held here, so the underlying permit state cannot race.
        observed.append(pool._permits._value)
        fatal.set()

    try:
        future = pool.submit_before(
            lambda now: {"_after_release": publication}, deadline_ns=10, clock=lambda: 1
        )
        assert future.result(timeout=5) == {}
        assert observed == [16]
        assert (
            pool.submit_before(lambda now: None, deadline_ns=10, clock=lambda: 1)
            is None
        )
    finally:
        pool.close()


def test_claimed_prefix_counts_reject_forged_overloads():
    plan = diagnostic_window_plan("cell_10_pps")
    row = {
        **asdict(plan.slot(0)),
        "outcome": "overload",
        "decision_ns": 25000000,
        "reason": "permit_exhausted",
    }
    counts = asdict(
        verify_accounting(
            plan, [row], worker_ids=list(range(1, 17)), failure_prefix=True
        )
    )
    counts["overloads"] = 10000
    with pytest.raises(ValueError):
        verify_accounting(
            plan,
            [row],
            worker_ids=list(range(1, 17)),
            failure_prefix=True,
            claimed_counts=counts,
        )


def test_prefix_holes_rejected():
    plan = diagnostic_window_plan("cell_10_pps")
    row = {
        **asdict(plan.slot(1)),
        "outcome": "overload",
        "decision_ns": 125000000,
        "reason": "permit_exhausted",
    }
    with pytest.raises(ValueError):
        verify_accounting(
            plan, [row], worker_ids=list(range(1, 17)), failure_prefix=True
        )


def test_failure_audit_rejects_fabricated_unexecuted_denominator():
    policy = object.__new__(n.NumericPolicy)
    policy.failure_audit = True
    footer = {
        "numeric_outcome": {"status": "fatal", "unexecuted": 9998, "admitted": 0},
        "accounting": {"committed": 0, "overloads": 1, "late_completions": 0},
    }
    with pytest.raises(ValueError):
        policy.check_footer({}, footer, None, None, {})


def test_success_audit_rejects_failure_prefix():
    policy = object.__new__(n.NumericPolicy)
    policy.failure_audit = False
    footer = {
        "numeric_outcome": {"status": "fatal", "unexecuted": 9999, "admitted": 0},
        "accounting": {
            "committed": 0,
            "overloads": 1,
            "late_completions": 0,
            "on_time_commits": 0,
        },
    }
    with pytest.raises(ValueError):
        policy.check_footer({}, footer, None, None, {})


def test_symlink_inputs_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"{}")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(ValueError):
        n.pinned(alias, d._sha(b"{}"))


def test_bool_worker_id_rejected():
    plan = diagnostic_window_plan("cell_10_pps")
    with pytest.raises(ValueError):
        verify_accounting(
            plan, [], worker_ids=[True, *range(2, 17)], failure_prefix=True
        )


def test_total_origin_guard_includes_prelaunch_bootstrap():
    context = object.__new__(n.Context)
    context.controller_origin_monotonic_ns = 1
    context.progress = {}
    launch = SimpleNamespace(not_before_ms="1000000", not_after_ms="2200000")
    with pytest.raises(n.SetupLimitError):
        context.check_setup(
            launch,
            1000001,
            diagnostic_window_plan("cell_10_pps"),
            now_ns=198_000_000_001,
        )


def test_actual_launch_lifetime_cannot_be_extended():
    context = object.__new__(n.Context)
    context.controller_origin_monotonic_ns = 1
    context.progress = {}
    launch = SimpleNamespace(not_before_ms="1000000", not_after_ms="2200001")
    with pytest.raises(n.SetupLimitError):
        context.check_setup(
            launch, 1000000, diagnostic_window_plan("cell_10_pps"), now_ns=2
        )


def test_full_synthetic_denominator_is_only_controller_fixture():
    plan = diagnostic_window_plan("cell_10_pps")
    rows = []
    for i in range(10000):
        slot = plan.slot(i)
        t = slot.scheduled_ns
        rows.append(
            {
                **asdict(slot),
                "outcome": "committed",
                "admitted_ns": t,
                "started_ns": t + 1,
                "commit_end_ns": t + 2,
                "end_ns": t + 3,
                "worker_id": slot.chain_index % 16 + 1,
            }
        )
    result = verify_accounting(
        plan, rows, worker_ids=list(range(1, 17)), slot_hard_ceiling_ns=225000000
    )
    assert result.committed == result.on_time_commits == 10000
    assert result.late_completions == result.overloads == 0
    assert result.qualified is False  # No authority proof or qualification claim.


def test_same_worker_overlapping_prefix_rejected():
    plan = diagnostic_window_plan("cell_10_pps")
    rows = []
    for i in range(2):
        slot = plan.slot(i)
        t = slot.scheduled_ns
        rows.append(
            {
                **asdict(slot),
                "outcome": "committed",
                "admitted_ns": t,
                "started_ns": t + 1,
                "commit_end_ns": t + 2,
                "end_ns": t + 150000000,
                "worker_id": 1,
            }
        )
    with pytest.raises(ValueError, match="overlapping"):
        verify_accounting(
            plan,
            rows,
            worker_ids=list(range(1, 17)),
            failure_prefix=True,
            slot_hard_ceiling_ns=225000000,
        )


def test_source_change_after_acceptance_fails_closed():
    context = object.__new__(n.Context)
    context.accepted_provenance = {}
    with pytest.raises(ValueError, match="source changed"):
        context.provenance()


@pytest.mark.parametrize("which", ["input", "output"])
def test_payload_hook_cannot_weaken_fixed_byte_contract(which):
    from dataclasses import replace

    def malicious_builder(chain, index):
        task, artifact = d.build_payloads(chain, index)
        return (
            replace(task, description="") if which == "input" else task,
            replace(artifact, content="") if which == "output" else artifact,
        )

    with pytest.raises(ValueError, match="fixed canonical byte sizes"):
        d._expected_payload_bytes(0, 0, malicious_builder)


def test_fresh_cli_blocks_ambient_startup_and_instrumentation(tmp_path, monkeypatch):
    import subprocess

    marker = tmp_path / "startup-ran"
    (tmp_path / "sitecustomize.py").write_text(
        f'open({str(marker)!r},"w").write("BAD")'
    )
    script = tmp_path / "probe.py"
    script.write_text(
        'import json,os,sys; print(json.dumps({"isolated":sys.flags.isolated,"no_site":sys.flags.no_site,"pythonpath":"PYTHONPATH" in os.environ,"coverage":"COVERAGE_PROCESS_START" in os.environ,"otel":"OTEL_SERVICE_NAME" in os.environ}))'
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("COVERAGE_PROCESS_START", "bad")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "bad")
    command, env = n.fresh_cli_command(script, [])
    result = subprocess.run(
        command, env=env, capture_output=True, text=True, check=True, cwd=tmp_path
    )
    assert json.loads(result.stdout) == {
        "isolated": 1,
        "no_site": 1,
        "pythonpath": False,
        "coverage": False,
        "otel": False,
    }
    assert not marker.exists()


def test_numeric_cli_imports_in_isolated_no_site_process():
    import subprocess

    command, env = n.fresh_cli_command(
        ROOT / "scripts/run_apcc_w2_numeric_cold.py", ["--help"]
    )
    result = subprocess.run(
        command, env=env, capture_output=True, text=True, check=True
    )
    assert "audit-failure" in result.stdout and "qualify-capsule" in result.stdout


def test_cli_cancellation_handler_sets_event_and_restores_handlers():
    import importlib.util
    import signal

    spec = importlib.util.spec_from_file_location(
        "numeric_cli_fixture", ROOT / "scripts/run_apcc_w2_numeric_cold.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    before = {
        number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)
    }
    with module.cancellation_scope() as cancel:
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        assert cancel.is_set()
    assert {number: signal.getsignal(number) for number in before} == before


def test_cancel_event_reaches_runner_and_cleanup_failure_is_not_success(
    tmp_path, monkeypatch
):
    import threading

    cancel = threading.Event()
    cancel.set()
    cleaned = []

    def fixture_runner(output, *, plans, handover_timeout_ms, numeric_context, cancel):
        try:
            assert cancel.is_set()
            raise InterruptedError("fixture cancellation")
        finally:
            cleaned.append(True)

    monkeypatch.setattr(n.runner, "run_repetition", fixture_runner)
    with pytest.raises(InterruptedError):
        n.run_cold(tmp_path, object.__new__(n.Context), cancel=cancel)
    assert cleaned == [True] and not (tmp_path / "numeric-result.json").exists()


def witness_fixture(
    tmp_path, *, fsync_elapsed=1_001_000_000_000, terminal_elapsed=1_000_000_000_000
):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from constitutional_swarm.apcc.crypto import b64u_encode

    signer = Ed25519PrivateKey.generate()
    header = {
        "numeric_setup": {"epoch_monotonic_ns": 100},
        "plan": asdict(diagnostic_window_plan("cell_10_pps")),
        "controller_public_key": b64u_encode(d._public(signer)),
        "started_wall_ms": 1000000,
    }
    footer = {
        "elapsed_ns": terminal_elapsed,
        "terminal_proof_completed_ns": terminal_elapsed,
        "terminal_proof": {"node_index": 99, "verification_time_ms": 2000000},
        "numeric_outcome": {"status": "complete", "admitted": 10000, "unexecuted": 0},
        "accounting": {
            "committed": 10000,
            "overloads": 0,
            "late_completions": 0,
            "on_time_commits": 10000,
        },
    }
    body = n.drain_body(header, "a" * 64, 100 + fsync_elapsed, terminal_elapsed)
    record = {
        "body": body,
        "key_id": "controller-accounting-v1",
        "signature": b64u_encode(signer.sign(n.DRAIN_DOMAIN + d._json(body))),
    }
    raw = d._json(record)
    (tmp_path / "drain-witness.json").write_bytes(raw)
    return header, footer, raw


@pytest.mark.parametrize("delay", [1_001_000_000_001, 1_005_000_000_000])
def test_late_actual_fsync_rejects_success_but_failure_retains_zero_late_ops(
    tmp_path, monkeypatch, delay
):
    header, footer, raw = witness_fixture(tmp_path, fsync_elapsed=delay)
    policy = object.__new__(n.NumericPolicy)
    policy.directory = tmp_path
    policy.ledger_sha = "a" * 64
    policy.failure_audit = False
    policy.payload_builder = None
    with pytest.raises(ValueError, match="durable ledger drain"):
        policy.check_footer(header, footer, None, None, {})
    monkeypatch.setattr(
        d, "_verify_operation", lambda *args, **kwargs: None
    )  # Clock-only fixture; no authority qualification.
    policy.failure_audit = True
    policy.check_footer(header, footer, None, None, {})
    assert footer["accounting"]["late_completions"] == 0
    assert (
        n.verify_drain_witness(raw, header, footer, "a" * 64)["window_drain_violation"]
        is True
    )


def test_terminal_wall_clock_cannot_borrow_elapsed_slack(tmp_path, monkeypatch):
    header, footer, raw = witness_fixture(tmp_path)
    footer["terminal_proof"]["verification_time_ms"] = 2001001
    policy = object.__new__(n.NumericPolicy)
    policy.directory = tmp_path
    policy.ledger_sha = "a" * 64
    policy.failure_audit = False
    policy.payload_builder = None
    monkeypatch.setattr(d, "_verify_operation", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="terminal proof clock"):
        policy.check_footer(header, footer, None, None, {})


@pytest.mark.parametrize(
    "field,value",
    [
        ("ledger_sha256", "b" * 64),
        ("ledger_fsync_elapsed_ns", 0),
        ("window_drain_violation", False),
    ],
)
def test_signed_drain_witness_mutations_rejected(tmp_path, field, value):
    header, footer, raw = witness_fixture(tmp_path, fsync_elapsed=1_001_000_000_001)
    record = json.loads(raw)
    record["body"][field] = value
    with pytest.raises(Exception):
        n.verify_drain_witness(d._json(record), header, footer, "a" * 64)


def test_failure_record_preserves_primary_cleanup_and_exact_prefix(
    tmp_path, monkeypatch
):
    tmp_path = tmp_path / "new-run"
    context = object.__new__(n.Context)
    context.begin_setup()
    context.binding = {"fixture": True}
    context.progress.update(
        phase="pacing",
        admitted=2,
        overloads=1,
        proofs_completed=1,
        workflows_created=100,
        agents_registered=10000,
    )
    primary = TimeoutError("observer crashed")
    cleanup = RuntimeError("close failed")

    def fail(*args, **kwargs):
        tmp_path.mkdir()
        (tmp_path / "window-000.jsonl").write_bytes(b'{"type":"header"}\n')
        context.primary_error = primary
        context.cleanup_errors.append(cleanup)
        raise cleanup

    monkeypatch.setattr(n.runner, "run_repetition", fail)
    with pytest.raises(TimeoutError, match="observer crashed"):
        n.run_cold(tmp_path, context)
    record = json.loads((tmp_path / "failed-attempt.json").read_bytes())
    assert record["primary_error"]["type"] == "TimeoutError"
    assert record["cleanup_errors"][0]["type"] == "RuntimeError"
    assert (record["admitted"], record["overloads"], record["unexecuted"]) == (
        2,
        1,
        9997,
    )
    assert record["observed_artifacts"]["window-000.jsonl"]["sha256"] == d._sha(
        (tmp_path / "window-000.jsonl").read_bytes()
    )
    assert (
        record["prefix_proofs_audited"] is False
        and record["campaign_eligible"] is False
    )


def test_functional_loader_rejects_numeric_without_explicit_opt_in(tmp_path):
    from constitutional_swarm.apcc_empirical import w2_renewal_replay as replay

    raw = d._json({"revision": "w2-numeric-cold-v1"}) + b"\n"
    (tmp_path / "renewal-plan.json").write_bytes(raw)
    with pytest.raises(ValueError, match="functional verifier rejects"):
        replay._load_plan(tmp_path, d._sha(raw))


def test_failure_evidence_write_error_does_not_hide_primary(tmp_path, monkeypatch):
    output = tmp_path / "new-attempt"
    context = object.__new__(n.Context)
    context.begin_setup()
    context.binding = {"fixture": True}

    def fail(*args, **kwargs):
        output.mkdir()
        raise InterruptedError("cancelled")

    monkeypatch.setattr(n.runner, "run_repetition", fail)
    monkeypatch.setattr(
        n.runner, "_write", lambda *args: (_ for _ in ()).throw(OSError("disk full"))
    )
    with pytest.raises(InterruptedError, match="cancelled") as error:
        n.run_cold(output, context)
    assert any("could not be persisted" in note for note in error.value.__notes__)
    assert not (output / "failed-attempt.json").exists()


def test_failed_attempt_does_not_write_into_preexisting_directory(
    tmp_path, monkeypatch
):
    context = object.__new__(n.Context)
    context.begin_setup()
    context.binding = {"fixture": True}

    def fail(*args, **kwargs):
        raise FileExistsError("existing directory")

    monkeypatch.setattr(n.runner, "run_repetition", fail)
    with pytest.raises(FileExistsError):
        n.run_cold(tmp_path, context)
    assert not (tmp_path / "failed-attempt.json").exists()


def test_setup_failure_records_measured_progress_without_fake_overloads(
    tmp_path, monkeypatch
):
    output = tmp_path / "setup-failed"
    context = object.__new__(n.Context)
    context.begin_setup()
    context.binding = {"fixture": True}
    context.progress.update(
        phase="setup",
        workflows_created=2,
        agents_registered=137,
        setup_elapsed_ns=198000000001,
    )

    def fail(*args, **kwargs):
        output.mkdir()
        raise n.SetupLimitError("setup deadline")

    monkeypatch.setattr(n.runner, "run_repetition", fail)
    with pytest.raises(n.SetupLimitError):
        n.run_cold(output, context)
    record = json.loads((output / "failed-attempt.json").read_bytes())
    assert record["setup_progress"]["agents_registered"] == 137
    assert (record["admitted"], record["overloads"], record["unexecuted"]) == (
        0,
        0,
        10000,
    )
