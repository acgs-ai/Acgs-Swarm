"""Fresh CLI evidence and external digest manifests fail closed."""

import hashlib
import json
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical.w2_renewal_evidence import (
    audit_replays,
    read_external_digests,
    scan_owned_resources,
)


def test_external_digest_requires_exact_regular_contained_unique_files(tmp_path):
    ledger = tmp_path / "window-000.jsonl"
    ledger.write_bytes(b"example\n")
    digest = hashlib.sha256(ledger.read_bytes()).hexdigest()
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text(f"{digest}  window-000.jsonl\n")
    assert read_external_digests(manifest) == {"window-000.jsonl": digest}
    for name in ("../escape", "/etc/passwd", "./window-000.jsonl"):
        manifest.write_text(f"{digest}  {name}\n")
        with pytest.raises(ValueError):
            read_external_digests(manifest)
    manifest.write_text(f"{digest}  window-000.jsonl\n" * 2)
    with pytest.raises(ValueError, match="duplicate"):
        read_external_digests(manifest)
    alias = tmp_path / "alias.jsonl"
    alias.symlink_to(ledger)
    manifest.write_text(f"{digest}  alias.jsonl\n")
    with pytest.raises(ValueError, match="symlink"):
        read_external_digests(manifest)


def test_digest_manifest_rejects_changed_bytes(tmp_path):
    (tmp_path / "window-000.jsonl").write_bytes(b"changed")
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text(f"{'0' * 64}  window-000.jsonl\n")
    with pytest.raises(ValueError, match="digest"):
        read_external_digests(manifest)


def test_replay_uses_fresh_cli_and_retains_rejection_not_qualification(tmp_path):
    script = tmp_path / "verifier.py"
    script.write_text(
        "import json, os, sys\n"
        "print(json.dumps({'status':'verified','pid':os.getpid(),"
        "'result':{'campaign_eligible':False}}))\n"
        "sys.exit(0)\n"
    )
    for name in ("window-000.jsonl", "repetition.json"):
        (tmp_path / name).write_bytes(b"opaque fake fixture - not runtime evidence\n")
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text("".join(
        f"{hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()}  {name}\n"
        for name in ("window-000.jsonl", "repetition.json")
    ))
    report = audit_replays(manifest, cli=script, timeout_seconds=10)
    assert report["campaign_eligible"] is False
    assert report["all_verified"] is True
    assert len({r["stdout"]["pid"] for r in report["replays"]}) == 2
    script.write_text("import sys\nprint('invalid')\nsys.exit(1)\n")
    rejected = audit_replays(manifest, cli=script, timeout_seconds=10)
    assert rejected["all_verified"] is False
    assert all(r["returncode"] == 1 for r in rejected["replays"])


def test_replay_rejects_eligibility_true_or_missing(tmp_path):
    script = tmp_path / "verifier.py"
    ledger = tmp_path / "window-000.jsonl"
    ledger.write_bytes(b"fixture")
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text(f"{hashlib.sha256(ledger.read_bytes()).hexdigest()}  {ledger.name}\n")
    for result in ({"campaign_eligible": True}, {}):
        script.write_text(f"print({json.dumps({'status':'verified','result':result})!r})\n")
        assert audit_replays(manifest, cli=script)["all_verified"] is False


def test_cleanup_scans_other_process_file_descriptors(tmp_path):
    import subprocess
    import sys

    if not Path("/proc/self/fd").is_dir():
        pytest.skip("Linux process audit required")
    database = tmp_path / "authority.sqlite"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys,time; f=open(sys.argv[1],'w'); print('ready',flush=True); time.sleep(60)", str(database)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        audit = scan_owned_resources(tmp_path, owned_pids=[child.pid])
        assert audit["clean"] is False
        assert child.pid in audit["live_owned_pids"]
        assert any(row["pid"] == child.pid for row in audit["open_run_descriptors"])
    finally:
        child.terminate()
        child.wait(timeout=10)
        child.stdout.close()
    after = scan_owned_resources(tmp_path, owned_pids=[child.pid])
    assert after["owned_pids_absent"] is True
    assert after["open_run_descriptors"] == []
    assert after["clean"] == (not after["inaccessible_pids"])


def test_replay_disables_site_startup_and_inherited_instrumentation(tmp_path, monkeypatch):
    script = tmp_path / "verifier.py"
    script.write_text(
        "import sys, os, json\n"
        "assert sys.flags.isolated and sys.flags.no_site\n"
        "assert not any(k.startswith(('COVERAGE_', 'OTEL_')) for k in os.environ)\n"
        "print(json.dumps({'status':'verified','result':{'campaign_eligible':False}}))\n"
    )
    (tmp_path / "sitecustomize.py").write_text("raise RuntimeError('instrumented startup')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("COVERAGE_PROCESS_START", "untrusted")
    monkeypatch.setenv("OTEL_PYTHON_AUTO_INSTRUMENTATION_ENABLED", "true")
    ledger = tmp_path / "window-000.jsonl"
    ledger.write_bytes(b"fixture")
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text(f"{hashlib.sha256(ledger.read_bytes()).hexdigest()}  {ledger.name}\n")
    assert audit_replays(manifest, cli=script)["all_verified"] is True


def test_inaccessible_nonlisted_pid_cannot_prove_descriptor_absence(tmp_path, monkeypatch):
    original = Path.iterdir

    def process_tables(path):
        if str(path) == "/proc":
            return iter([Path("/proc/1")])
        if str(path) == "/proc/1/fd":
            raise PermissionError("unobservable process table")
        return original(path)

    monkeypatch.setattr(Path, "iterdir", process_tables)
    report = scan_owned_resources(tmp_path, owned_pids=[])
    assert report["owned_pids_absent"] is True
    assert report["inaccessible_pids"] == [1]
    assert report["fd_absence_proven"] is False
    assert report["clean"] is False


def test_renewal_cli_requires_explicit_external_plan_pin(tmp_path):
    script = tmp_path / "verifier.py"
    script.write_text(
        "import argparse,json\n"
        "p=argparse.ArgumentParser();p.add_argument('command');"
        "p.add_argument('--ledger');p.add_argument('--expected-sha256');"
        "p.add_argument('--expected-plan-sha256',required=True);a=p.parse_args()\n"
        "assert a.expected_plan_sha256=='ab'*32\n"
        "print(json.dumps({'status':'verified','result':{'campaign_eligible':False}}))\n"
    )
    ledger = tmp_path / "window-000.jsonl"
    ledger.write_bytes(b"fixture")
    manifest = tmp_path / "LEDGER-SHA256SUMS"
    manifest.write_text(f"{hashlib.sha256(ledger.read_bytes()).hexdigest()}  {ledger.name}\n")
    assert audit_replays(manifest, cli=script)["all_verified"] is False
    report = audit_replays(manifest, cli=script, expected_plan_sha256="ab" * 32)
    assert report["all_verified"] is True
    assert report["expected_plan_sha256"] == "ab" * 32


@pytest.mark.parametrize("pin", ["A" * 64, "g" * 64, "0" * 63, True])
def test_invalid_external_plan_pin_rejects_before_cli_launch(tmp_path, pin):
    with pytest.raises(ValueError, match="plan SHA256"):
        audit_replays(tmp_path / "absent-manifest", cli=tmp_path / "absent-cli", expected_plan_sha256=pin)
