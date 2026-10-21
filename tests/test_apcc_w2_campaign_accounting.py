"""Controller-seal/accounting integration; authority replay is tested separately.

The header authority check is deliberately stubbed here. These synthetic ledgers
contain only overloads and provide no authority or campaign qualification evidence.
"""

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode
from constitutional_swarm.apcc.observation import (
    decode_observer_launch_attestation,
    encode_observer_launch_attestation,
)
from constitutional_swarm.apcc_empirical import w2_campaign as campaign
from constitutional_swarm.apcc_empirical import w2_driver as diagnostic
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan, verify_accounting


@pytest.fixture
def sealed_overloads(tmp_path, monkeypatch):
    monkeypatch.setattr(
        campaign, "_header_check", lambda header: SimpleNamespace(session_id="unit")
    )
    policy = WindowPlan(1000, 100, 10, 100, 100, 100)
    key = Ed25519PrivateKey.generate()
    header = {
        "type": "header",
        "plan": asdict(policy),
        "trust": [],
        "worker_ids": list(range(1, 17)),
        "provenance": {"unit": "synthetic"},
        "controller_public_key": b64u_encode(diagnostic._public(key)),
        "previous_ledger": None,
        "window_index": 0,
        "chain_offset": 0,
        "run_id": "synthetic",
        "phase": "cold",
    }
    rows = [
        {
            "type": "overload",
            "pacing": {
                **asdict(policy.slot(i)),
                "outcome": "overload",
                "decision_ns": policy.slot(i).deadline_ns,
                "reason": "permit_exhausted" if i == 0 else "predecessor_uncommitted",
            },
        }
        for i in range(100)
    ]
    accounting = verify_accounting(
        policy, [row["pacing"] for row in rows], worker_ids=header["worker_ids"]
    )
    footer = {
        "type": "footer",
        "accounting": asdict(accounting),
        "elapsed_ns": 1000,
        "campaign_eligible": False,
        "provenance_after": header["provenance"],
    }

    def seal(mutate=lambda h, r, f: None):
        mutate(header, rows, footer)
        prefix = b"".join(diagnostic._json(row) + b"\n" for row in [header, *rows])
        footer.pop("signature", None)
        footer["prefix_sha256"] = hashlib.sha256(prefix).hexdigest()
        footer["signature"] = b64u_encode(
            key.sign(campaign.DOMAIN + diagnostic._json(footer))
        )
        raw = prefix + diagnostic._json(footer) + b"\n"
        path = tmp_path / "synthetic.jsonl"
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    return seal


def test_controller_only_overloads_never_qualify(sealed_overloads):
    path, digest = sealed_overloads()
    result = campaign.verify_ledger(path, expected_sha256=digest)
    assert result["accounting"]["overloads"] == 100
    assert result["accounting"]["committed"] == 0
    assert result["campaign_eligible"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda h, r, f: f["accounting"].update(overloads=99),
        lambda h, r, f: r[0]["pacing"].update(scheduled_ns=1),
        lambda h, r, f: r[0]["pacing"].update(chain_index=1),
        lambda h, r, f: r.pop(),
        lambda h, r, f: f.update(elapsed_ns=999),
        lambda h, r, f: f.update(campaign_eligible=True),
        lambda h, r, f: f.update(provenance_after={"changed": True}),
    ],
)
def test_resealed_campaign_accounting_mutations_fail(sealed_overloads, mutation):
    path, digest = sealed_overloads(mutation)
    with pytest.raises(ValueError):
        campaign.verify_ledger(path, expected_sha256=digest)


def test_external_digest_and_controller_seal_are_required(sealed_overloads):
    path, digest = sealed_overloads()
    with pytest.raises(ValueError, match="external digest"):
        campaign.verify_ledger(path, expected_sha256="0" * 64)
    raw = path.read_bytes().replace(b'"elapsed_ns":1000', b'"elapsed_ns":1001')
    path.write_bytes(raw)
    with pytest.raises(InvalidSignature):
        campaign.verify_ledger(path, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_unsealed_truncation_fails(sealed_overloads):
    path, _ = sealed_overloads()
    raw = path.read_bytes()[:-1]
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="truncated"):
        campaign.verify_ledger(path, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_overload_envelope_cannot_hide_committed_pacing_without_proofs(
    sealed_overloads,
):
    def forge(header, rows, footer):
        policy = WindowPlan(**header["plan"])
        for i, row in enumerate(rows):
            row["pacing"] = {
                **asdict(policy.slot(i)),
                "outcome": "committed",
                "admitted_ns": i * 10,
                "started_ns": i * 10,
                "commit_end_ns": i * 10 + 1,
                "end_ns": i * 10 + 2,
                "worker_id": i % 16 + 1,
            }
        footer["accounting"] = asdict(
            verify_accounting(
                policy, [row["pacing"] for row in rows], worker_ids=header["worker_ids"]
            )
        )

    path, digest = sealed_overloads(forge)
    with pytest.raises(ValueError, match="overload envelope"):
        campaign.verify_ledger(path, expected_sha256=digest)


@pytest.mark.parametrize(
    "fault", ["controller_key", "launch_signature", "config_field"]
)
def test_real_header_rejects_invalid_launch_or_configuration(fault):
    # Read only the already sealed public diagnostic header. Replacing its
    # controller key preserves structurally valid metadata but invalidates the
    # launch signature. This calls the real header check, with no proof rows.
    path = Path(__file__).resolve().parents[1] / (
        "experiments/apcc-1/w2-causal-profile-20261017/ledgers/cli-100.jsonl"
    )
    with path.open() as ledger:
        header = json.loads(ledger.readline())
    policy = WindowPlan(1000, 100, 10, 100, 100, 100)
    header.update(
        revision="w2-campaign-v1",
        observer_experiment=diagnostic._EXPERIMENT,
        window_index=0,
        chain_offset=0,
        phase="cold",
        repetition_id=header["run_id"],
        warm_mode="same-handles-continuation",
        plan=asdict(policy),
        window_plans=[asdict(policy)],
    )
    if fault == "controller_key":
        header["controller_public_key"] = b64u_encode(
            diagnostic._public(Ed25519PrivateKey.generate())
        )
    elif fault == "launch_signature":
        launch = decode_observer_launch_attestation(b64u_decode(header["launch"]))
        header["launch"] = b64u_encode(
            encode_observer_launch_attestation(
                replace(launch, controller_signature=b64u_encode(bytes(64)))
            )
        )
    else:
        header["expected_public_config"]["controller_invented_authority"] = True
    with pytest.raises(ValueError):
        campaign._header_check(header)
