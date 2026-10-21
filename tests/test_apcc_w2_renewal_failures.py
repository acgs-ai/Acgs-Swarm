"""Instrumented real-window failure prefixes, audited by uninstrumented CLI.

Slow tests execute actual 70-second, 100-operation W2 windows. They never
qualify campaigns. Every valid completed window is positively replayed before
an incomplete repetition is rejected; runtime faults and artifact mutations
are labelled separately in the retained evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import sysconfig
import time
from dataclasses import replace
from pathlib import Path

import pytest

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc_empirical import w2_renewal_campaign as campaign
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan
from constitutional_swarm.apcc_empirical.w2_renewal_runtime import W2RenewalService
from constitutional_swarm.governance_errors import GovernanceBypassDenied


def _json(value):
    return campaign.d._json(value) + b"\n"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _cli(directory, command, target):
    root = Path(campaign.__file__).resolve().parents[3]
    cli = root / "scripts/run_apcc_w2_renewal.py"
    paths = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    bootstrap = (
        f"import sys,runpy;sys.path.extend({paths!r});"
        "sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    args = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        bootstrap,
        str(cli),
        command,
        "--ledger" if command == "verify" else "--manifest",
        str(target),
        "--expected-sha256",
        _sha(target.read_bytes()),
        "--expected-plan-sha256",
        _sha((directory / "renewal-plan.json").read_bytes()),
    ]
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env={
            k: v
            for k, v in os.environ.items()
            if k
            in {
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "LC_ALL",
            }
        },
    )
    return {
        "command": args,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "instrumented": False,
        "fresh_process": True,
    }


class _InjectedStop(RuntimeError):
    pass


@pytest.mark.slow
@pytest.mark.parametrize(
    "fault",
    [
        "pre-handover-expiry",
        "mid-handover-observer-crash",
        "cancel-after-drain",
        "post-seal-stale-epoch",
        "split-brain-prepare",
        "unapproved-rollover",
    ],
)
def test_real_window_failure_prefix_and_isolated_rejection(
    tmp_path, monkeypatch, fault
):
    output = Path(os.environ.get("APCC_W2_FAILURE_EVIDENCE", str(tmp_path))) / fault
    events = []
    real_start = campaign.start_w2_renewal_authority
    real_renew = W2RenewalService.renew
    real_control = W2RenewalService._control

    def start(child, config, launch, **kwargs):
        if fault == "pre-handover-expiry":
            launch = replace(launch, launch_lifetime_ms=90_000)
        return real_start(child, config, launch, **kwargs)

    def control(self, operation, request, **kwargs):
        result = real_control(self, operation, request, **kwargs)
        if operation == "drain":
            events.append({"boundary": "durable-DRAINED", "epoch": self.epoch})
            if fault == "mid-handover-observer-crash":
                pid = self.observer.pid
                os.kill(pid, signal.SIGKILL)
                events.append({"fault": "SIGKILL-owned-observer", "pid": pid})
                raise _InjectedStop("observer killed after durable drain")
            if fault == "cancel-after-drain":
                raise InterruptedError("injected cancellation after durable drain")
        if operation == "prepare" and fault == "split-brain-prepare":
            events.append({"boundary": "first-PREPARED", "epoch": self.epoch})
            # Deterministic serialization of two independently identified
            # contenders on the authenticated authority control channel.
            try:
                real_control(self, "prepare", request, request_id="competing-prepare")
            except GovernanceBypassDenied as error:
                events.append({"rejection": "competing-prepare", "error": str(error)})
                raise
            raise AssertionError("second independently identified prepare accepted")
        return result

    def renew(self, **kwargs):
        events.append({"boundary": "complete-window-before-renew", "epoch": self.epoch})
        if fault == "pre-handover-expiry":
            deadline = int(self.observer.launch_attestation.not_after_ms)
            while int(time.time() * 1000) <= deadline:
                time.sleep(min(0.1, max(0.001, (deadline - time.time() * 1000) / 1000)))
            events.append(
                {
                    "boundary": "real-signed-expiry",
                    "not_after_ms": deadline,
                    "now_ms": int(time.time() * 1000),
                }
            )
        if fault == "unapproved-rollover":
            kwargs["launch_lifetime_ms"] = 1_200_001
            events.append(
                {"fault": "oversized-real-successor", "lifetime_ms": 1_200_001}
            )
        result = real_renew(self, **kwargs)
        if fault == "post-seal-stale-epoch":
            with pytest.raises(GovernanceBypassDenied) as denied:
                self.authority.admin_client._client._rpc(
                    "w2_epoch_v1",
                    {
                        "epoch": 0,
                        "plan_digest": self.config.plan_digest,
                        "operation": "health",
                        "request": {},
                    },
                )
            events.append(
                {
                    "rejection": "stale-epoch-0-after-activation-1",
                    "error": str(denied.value),
                }
            )
            raise _InjectedStop(
                "stale epoch rejected after durable successor activation"
            )
        return result

    monkeypatch.setattr(campaign, "start_w2_renewal_authority", start)
    monkeypatch.setattr(W2RenewalService, "_control", control)
    monkeypatch.setattr(W2RenewalService, "renew", renew)
    plan = WindowPlan(
        70_000_000_000, 100, 5_000_000_000, 10_000_000_000, 10_000_000_000, 100
    )
    caught = None
    try:
        campaign.run_repetition(output, plans=(plan, plan), handover_timeout_ms=10_000)
    except (Exception, KeyboardInterrupt) as error:
        caught = {"type": type(error).__name__, "message": str(error)}
    assert caught is not None, "fault did not terminate the planned repetition"
    assert any(e.get("boundary") == "complete-window-before-renew" for e in events), (
        caught
    )

    ledger = output / "window-000.jsonl"
    assert ledger.is_file(), caught
    raw_plan = (output / "renewal-plan.json").read_bytes()
    public_plan = json.loads(raw_plan)
    journal = (output / "private-journal/journal.jsonl").read_bytes()
    rows = [json.loads(line) for line in journal.splitlines()]
    (output / "renewal-journal.jsonl").write_bytes(journal)
    manifest = {
        "revision": "w2-renewal-repetition-v1",
        "repetition_id": public_plan["repetition_id"],
        "plan": {"filename": "renewal-plan.json", "sha256": _sha(raw_plan)},
        "windows": [{"filename": ledger.name, "sha256": _sha(ledger.read_bytes())}],
        "journal": {
            "filename": "renewal-journal.jsonl",
            "sha256": _sha(journal),
            "tip_digest": sha256_digest(campaign.d._json(rows[-1])),
        },
        "campaign_eligible": False,
    }
    partial = output / "repetition.json"
    partial.write_bytes(_json(manifest))
    (output / "LEDGER-SHA256SUMS").write_text(
        f"{_sha(ledger.read_bytes())}  {ledger.name}\n{_sha(partial.read_bytes())}  repetition.json\n"
    )
    (output / "PLAN-SHA256SUMS").write_text(f"{_sha(raw_plan)}  renewal-plan.json\n")
    positive = _cli(output, "verify", ledger)
    negative = _cli(output, "verify-repetition", partial)
    resources = json.loads((output / "cleanup.json").read_bytes())
    owned = [
        json.loads(line)
        for line in (output / "owned-processes.jsonl").read_text().splitlines()
    ]
    self_descriptors = []
    for path in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(path).removesuffix(" (deleted)")
        except FileNotFoundError:
            continue
        if target.startswith(str(output.resolve()) + "/"):
            self_descriptors.append({"fd": path.name, "target": target})
    absence = []
    for item in owned:
        try:
            os.kill(item["pid"], 0)
        except ProcessLookupError:
            absence.append(item["pid"])
    report = {
        "kind": "instrumented-runtime-fault-with-public-full-profile-window-prefix",
        "fault": fault,
        "campaign_eligible": False,
        "events": events,
        "failure": caught,
        "final_journal_state": rows[-1]["body"]["state"],
        "owned_processes": owned,
        "absent_owned_pids": absence,
        "controller_run_descriptors": self_descriptors,
        "owned_cleanup_proven": bool(owned)
        and len(absence) == len(owned)
        and not self_descriptors,
        "global_scan": resources,
        "valid_prefix_replay": positive,
        "incomplete_repetition_rejection": negative,
        "partial_manifest": "test-constructed from genuine completed window and signed journal; missing planned epoch intentionally retained",
    }
    (output / "failure-evidence.json").write_bytes(_json(report))
    assert report["owned_cleanup_proven"], report
    assert positive["returncode"] == 0, positive
    assert negative["returncode"] == 1, negative
    assert "renewal repetition truncated or substituted" in negative["stderr"], negative


@pytest.mark.slow
@pytest.mark.parametrize(
    "mutation", ["unsealed-predecessor", "truncated-signed-journal"]
)
def test_full_profile_linked_artifact_rejection(tmp_path, mutation):
    reference = os.environ.get("APCC_W2_FAILURE_REFERENCE")
    if not reference:
        pytest.skip("requires an externally retained complete renewal repetition")
    source = Path(reference)
    output = Path(os.environ.get("APCC_W2_FAILURE_EVIDENCE", str(tmp_path))) / mutation
    output.mkdir(parents=True, exist_ok=False)
    names = [
        "renewal-plan.json",
        "repetition.json",
        "renewal-journal.jsonl",
        "window-000.jsonl",
        "window-001.jsonl",
    ]
    for name in names:
        shutil.copyfile(source / name, output / name)
    original = {name: _sha((output / name).read_bytes()) for name in names}
    positive = _cli(output, "verify-repetition", output / "repetition.json")
    assert positive["returncode"] == 0, positive
    if mutation == "unsealed-predecessor":
        path = output / "window-000.jsonl"
        lines = path.read_bytes().splitlines(keepends=True)
        assert json.loads(lines[-1])["type"] == "footer"
        path.write_bytes(b"".join(lines[:-1]))
        negative = _cli(output, "verify", output / "window-001.jsonl")
    else:
        path = output / "renewal-journal.jsonl"
        lines = path.read_bytes().splitlines(keepends=True)
        assert len(lines) > 1
        path.write_bytes(b"".join(lines[:-1]))
        negative = _cli(output, "verify-repetition", output / "repetition.json")
    report = {
        "kind": "public-artifact-mutation-not-runtime-crash",
        "mutation": mutation,
        "campaign_eligible": False,
        "reference": str(source),
        "original_sha256": original,
        "mutated_path": path.name,
        "mutated_sha256": _sha(path.read_bytes()),
        "positive_reference_replay": positive,
        "negative_mutation_replay": negative,
    }
    (output / "failure-evidence.json").write_bytes(_json(report))
    (output / "ARTIFACT-SHA256SUMS").write_text(
        "".join(f"{_sha((output / name).read_bytes())}  {name}\n" for name in names)
    )
    assert negative["returncode"] == 1, negative
    assert "digest" in negative["stderr"] or "SHA256" in negative["stderr"], negative
