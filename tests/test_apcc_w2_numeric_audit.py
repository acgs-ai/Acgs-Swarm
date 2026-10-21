"""Read-only replay tests; external actual-evidence paths supplied by environment."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_apcc_w2_numeric_audit.py"
spec = importlib.util.spec_from_file_location("standalone_auditor", SCRIPT)
assert spec and spec.loader
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def test_subclass_adds_only_diagnostic_initialization():
    class Existing:
        def __init__(self, value):
            self.value = value

        def begin_setup(self):
            raise AssertionError("execution setup must never run")

    value = cli.replay_context_class(Existing)(17)
    assert vars(value) == {"value": 17, "progress": {}}


def test_pin_and_duplicate_rejection(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"x")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        cli.pinned(path, "0" * 64)
    with pytest.raises(ValueError, match="duplicate"):
        json.loads('{"a":1,"a":2}', object_pairs_hook=cli.exact_pairs)


@pytest.fixture
def actual():
    filename = os.environ.get("APCC_NUMERIC_AUDIT_TEST_INPUTS")
    if not filename:
        pytest.skip("supply external actual replay test inputs JSON")
    return json.loads(Path(filename).read_text())


def command(actual, action="audit-failure"):
    packages = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    bootstrap = (
        f"import sys,runpy;sys.dont_write_bytecode=True;sys.path.extend({packages!r});"
        "sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    values = {
        **actual,
        "auditor-sha256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
    }
    args = [sys.executable, "-I", "-S", "-c", bootstrap, str(SCRIPT), action]
    for name, value in values.items():
        args.extend(["--" + name, value])
    return args


def run(actual, action="audit-failure"):
    env = {
        k: v
        for k, v in os.environ.items()
        if k in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
    }
    return subprocess.run(
        command(actual, action), env=env, capture_output=True, text=True, timeout=120
    )


def test_real_failure_replay_isolated(actual):
    result = run(actual)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["status"] == "verified" and value["campaign_eligible"] is False
    assert value["generation_manifest_sha256"] == actual["generation-manifest-sha256"]


def test_real_failure_cannot_be_success(actual):
    result = run(actual, "verify")
    assert result.returncode == 1
    assert "failed success" in result.stderr


@pytest.mark.parametrize(
    "name",
    [
        "generation-manifest-sha256",
        "acceptance-sha256",
        "result-sha256",
        "runtime-plan-sha256",
    ],
)
def test_wrong_external_pins_rejected(actual, name):
    result = run({**actual, name: "0" * 64})
    assert result.returncode == 1
    assert json.loads(result.stderr)["status"] == "failed"


def test_constructor_setup_bounds_still_enforced(actual):
    # Fresh process constructs the real accepted Context; no monkeypatches or authority.
    packages = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    body = f"""
import sys,runpy
sys.dont_write_bytecode=True
sys.path.extend({packages!r})
ns=runpy.run_path({str(SCRIPT)!r})
from pathlib import Path
from types import SimpleNamespace
args={actual!r}
n,_=ns['load_generation'](Path(args['generation-root']),Path(args['generation-manifest']),args['generation-manifest-sha256'])
c=ns['replay_context_class'](n.Context)(Path(args['inputs']),numeric_sha=args['numeric-sha256'],coverage_sha=args['coverage-sha256'],acceptance_sha=args['acceptance-sha256'])
assert c.progress == {{}}
c.controller_origin_monotonic_ns=1000000000
launch=SimpleNamespace(not_before_ms='1000',not_after_ms='1201000')
plan=n.diagnostic_window_plan('cell_10_pps')
c.check_setup(launch,1001,plan,now_ns=1001000000)
assert c.progress['setup_elapsed_ns']==1000000
try:c.check_setup(launch,199000,plan,now_ns=199000000000)
except n.SetupLimitError:pass
else:raise AssertionError('setup boundary weakened')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", body],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mutation", ["truncation", "profile"])
def test_mutated_ledger_rejected(actual, tmp_path, mutation):
    import shutil

    source = Path(actual["path"])
    manifest = json.loads(source.read_bytes())
    for filename in manifest["files"]:
        shutil.copyfile(source.parent / filename, tmp_path / filename)
    ledger = tmp_path / "window-000.jsonl"
    lines = ledger.read_bytes().splitlines()
    if mutation == "truncation":
        lines.pop()
    else:
        header = json.loads(lines[0])
        assert header["expected_public_config"]["causal_profile"] == "w2-linear-100"
        header["expected_public_config"]["causal_profile"] = "default"
        lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    ledger.write_bytes(b"\n".join(lines) + b"\n")
    manifest["files"]["window-000.jsonl"] = hashlib.sha256(
        ledger.read_bytes()
    ).hexdigest()
    result_path = tmp_path / "numeric-result.json"
    result_path.write_bytes(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    )
    result = run(
        {
            **actual,
            "path": str(result_path),
            "result-sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        }
    )
    assert result.returncode == 1
    assert json.loads(result.stderr)["status"] == "failed"


def test_real_setup_method_with_initialized_replay_diagnostics(monkeypatch):
    from types import SimpleNamespace
    from constitutional_swarm.apcc_empirical import w2_numeric_cold as n

    # Only constructor input loading is isolated; the original setup checks run.
    initialized = []

    def inputs_only(self):
        initialized.append(self)

    monkeypatch.setattr(n.Context, "__init__", inputs_only)
    context = cli.replay_context_class(n.Context)()
    assert initialized == [context]
    assert context.progress == {}
    context.controller_origin_monotonic_ns = 1_000_000_000
    launch = SimpleNamespace(not_before_ms="1000", not_after_ms="1201000")
    plan = n.diagnostic_window_plan("cell_10_pps")
    context.check_setup(launch, 1001, plan, now_ns=1_001_000_000)
    assert context.progress["setup_elapsed_ns"] == 1_000_000
    with pytest.raises(n.SetupLimitError):
        context.check_setup(launch, 199000, plan, now_ns=199_000_000_000)
