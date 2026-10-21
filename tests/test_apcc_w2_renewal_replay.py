"""Independent external-plan and authority-checkpoint rejection checks."""

import json
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.sqlite_store import (
    _SEMANTIC_CHECKPOINT_DOMAIN,
    _semantic_checkpoint_body,
)
from constitutional_swarm.apcc_empirical import qualification_v3 as q
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical import w2_renewal_replay as r
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan


def plan_data():
    from dataclasses import asdict

    window = WindowPlan(
        duration_ns=1_000_000_000,
        scheduled_operations=100,
        admission_grace_ns=1_000_000,
        operation_sla_ns=1_000_000,
        drain_ns=1_000_000,
        operation_floor=100,
    )
    return dict(
        revision="w2-renewal-functional-v1",
        repetition_id="run",
        authority_store_id="store",
        authority_session_id="session",
        renewal_key_id="renewal-key",
        renewal_public_key=b64u_encode(bytes(32)),
        controller_public_key=b64u_encode(bytes([1]) * 32),
        config_digest=sha256_digest(b"config"),
        profile="W2_LINEAR_100",
        limits=dict(
            maximum_renewals="3",
            maximum_total_lifetime_ms="10000",
            handover_timeout_ms="1000",
            maximum_single_launch_ms="2000",
        ),
        windows=[asdict(window)] * 4,
        campaign_eligible=False,
    )


def write_plan(path, value):
    raw = d._json(value) + b"\n"
    (path / "renewal-plan.json").write_bytes(raw)
    return d._sha(raw)


def test_external_plan_valid_four_epochs(tmp_path):
    plan = plan_data()
    pin = write_plan(tmp_path, plan)
    assert r._load_plan(tmp_path, pin) == plan


def test_cold_conditioning_plus_four_warm_epochs(tmp_path):
    plan = plan_data()
    plan["windows"].append(dict(plan["windows"][0]))
    plan["limits"]["maximum_renewals"] = "4"
    pin = write_plan(tmp_path, plan)
    assert len(r._load_plan(tmp_path, pin)["windows"]) == 5


@pytest.mark.parametrize(
    "mutation",
    [
        "floor-qualification",
        "extra",
        "missing",
        "profile",
        "eligible",
        "windows-zero",
        "windows-six",
        "renewal-count",
        "total-budget",
        "single-cap",
        "noncanonical",
        "wrong-pin",
    ],
)
def test_external_plan_negative_cases(tmp_path, mutation):
    plan = plan_data()
    if mutation == "floor-qualification":
        plan["windows"][0]["qualification"] = True
    elif mutation == "extra":
        plan["extra"] = "unknown"
    elif mutation == "missing":
        del plan["controller_public_key"]
    elif mutation == "profile":
        plan["profile"] = "default"
    elif mutation == "eligible":
        plan["campaign_eligible"] = True
    elif mutation == "windows-zero":
        plan["windows"] = []
    elif mutation == "windows-six":
        plan["windows"] += [dict(plan["windows"][0]) for _ in range(2)]
    elif mutation == "renewal-count":
        plan["limits"]["maximum_renewals"] = "2"
    elif mutation == "total-budget":
        plan["limits"]["maximum_total_lifetime_ms"] = "5000"
    elif mutation == "single-cap":
        plan["limits"]["maximum_single_launch_ms"] = "1000"
    pin = write_plan(tmp_path, plan)
    if mutation == "noncanonical":
        raw = json.dumps(plan, indent=2).encode() + b"\n"
        (tmp_path / "renewal-plan.json").write_bytes(raw)
        pin = d._sha(raw)
    elif mutation == "wrong-pin":
        pin = "0" * 64
    with pytest.raises(ValueError):
        r._load_plan(tmp_path, pin)


def checkpoint(tmp_path):
    child, *_ = q._configuration(tmp_path, "checkpoint-replay")
    signer = Ed25519PrivateKey.generate()
    binding = replace(
        child.authority.commit_trust, public_key=signer.public_key().public_bytes_raw()
    )
    config = replace(
        child.authority,
        causal_profile=AuthorityCausalProfile.W2_LINEAR_100,
        commit_trust=binding,
    )
    schema = sha256_digest(b"schema")
    raw = _semantic_checkpoint_body(config, schema, 7, sha256_digest(b"prior"))
    proof = dict(
        body=b64u_encode(raw),
        checkpoint_digest=sha256_digest(raw),
        key_id=binding.key_id,
        signature=b64u_encode(signer.sign(_SEMANTIC_CHECKPOINT_DOMAIN + b"\0" + raw)),
    )
    return proof, config, schema


def test_checkpoint_exact_signature_and_w2_config(tmp_path):
    proof, config, schema = checkpoint(tmp_path)
    assert r._checkpoint(proof, config, schema) == proof["checkpoint_digest"]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "key-alias",
        "signature",
        "digest",
        "schema",
        "config",
        "body-unknown",
        "body-counter",
        "body-default",
    ],
)
def test_checkpoint_mutations_rejected(tmp_path, mutation):
    from constitutional_swarm.apcc.crypto import b64u_decode

    proof, config, schema = checkpoint(tmp_path)
    if mutation == "extra":
        proof["algorithm"] = "Ed25519"
    elif mutation == "key-alias":
        proof["key_id"] = "alias"
    elif mutation == "signature":
        proof["signature"] = b64u_encode(bytes(64))
    elif mutation == "digest":
        proof["checkpoint_digest"] = sha256_digest(b"wrong")
    elif mutation == "schema":
        schema = sha256_digest(b"wrong")
    elif mutation == "config":
        config = replace(config, causal_profile=AuthorityCausalProfile.DEFAULT)
    else:
        body = json.loads(b64u_decode(proof["body"]))
        if mutation == "body-unknown":
            body["extra"] = "unknown"
        elif mutation == "body-counter":
            body["change_sequence"] = "07"
        elif mutation == "body-default":
            del body["authority_config_digest"]
        proof["body"] = b64u_encode(d._json(body))
    with pytest.raises((ValueError, InvalidSignature)):
        r._checkpoint(proof, config, schema)


def test_repetition_truncation_rejected_before_any_ledger(tmp_path):
    pin = write_plan(tmp_path, plan_data())
    manifest = dict(
        revision="w2-renewal-repetition-v1",
        repetition_id="run",
        plan=dict(filename="renewal-plan.json", sha256=pin),
        windows=[],
        journal=dict(
            filename="renewal-journal.jsonl",
            sha256="0" * 64,
            tip_digest=sha256_digest(b"tip"),
        ),
        campaign_eligible=False,
    )
    raw = d._json(manifest) + b"\n"
    path = tmp_path / "repetition.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="truncated"):
        r.verify_repetition(path, expected_sha256=d._sha(raw), expected_plan_sha256=pin)


def test_symlink_plan_rejected(tmp_path):
    raw = d._json(plan_data()) + b"\n"
    (tmp_path / "elsewhere.json").write_bytes(raw)
    (tmp_path / "renewal-plan.json").symlink_to("elsewhere.json")
    with pytest.raises(ValueError, match="symlink"):
        r._load_plan(tmp_path, d._sha(raw))


def prepared_successor():
    continuity, launch = sha256_digest(b"continuity"), sha256_digest(b"launch")
    prepared = {
        "now_ms": "200",
        "evidence": {
            "next_epoch": "1",
            "launch_digest": launch,
            "continuity_digest": continuity,
        },
    }
    retired = {
        "now_ms": "210",
        "evidence": {
            "observer_pid": "41",
            "successor_launch_digest": launch,
            "continuity_digest": continuity,
        },
    }
    active = {
        "now_ms": "220",
        "evidence": {"launch_digest": launch, "continuity_digest": continuity},
    }
    args = dict(
        epoch=1,
        continuity_digest=continuity,
        launch_digest=launch,
        prior_pid="41",
        issued_at_ms="200",
        prior_expires_at_ms="300",
        successor_expires_at_ms="400",
        delegation_expires_at_ms="500",
    )
    return prepared, retired, active, args


def test_prepared_successor_can_activate_later_with_exact_durable_identity():
    prepared, retired, active, args = prepared_successor()
    r._prepared_successor(prepared, retired, active, **args)


@pytest.mark.parametrize(
    "mutation",
    [
        "unbound-prepare",
        "prepare-fork",
        "retire-fork",
        "active-fork",
        "continuity-fork",
        "late-prepare",
        "early-active",
        "expired-prior",
        "expired-successor",
        "expired-delegation",
    ],
)
def test_prepared_successor_binding_rejects_forks_and_expiry(mutation):
    prepared, retired, active, args = prepared_successor()
    if mutation == "unbound-prepare":
        prepared["evidence"] = {"next_epoch": "1"}
    elif mutation == "prepare-fork":
        prepared["evidence"]["launch_digest"] = sha256_digest(b"fork")
    elif mutation == "retire-fork":
        retired["evidence"]["successor_launch_digest"] = sha256_digest(b"fork")
    elif mutation == "active-fork":
        active["evidence"]["launch_digest"] = sha256_digest(b"fork")
    elif mutation == "continuity-fork":
        retired["evidence"]["continuity_digest"] = sha256_digest(b"fork")
    elif mutation == "late-prepare":
        prepared["now_ms"] = "201"
    elif mutation == "early-active":
        active["now_ms"] = "199"
    elif mutation == "expired-prior":
        args["prior_expires_at_ms"] = "220"
    elif mutation == "expired-successor":
        args["successor_expires_at_ms"] = "220"
    elif mutation == "expired-delegation":
        args["delegation_expires_at_ms"] = "220"
    with pytest.raises(ValueError, match="prepared successor"):
        r._prepared_successor(prepared, retired, active, **args)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "stale-observation",
        "wrong-epoch",
        "wrong-plan",
        "forged-signature",
        "signer-alias",
        "unknown-field",
    ],
)
def test_observer_signed_tail_binds_exact_terminal_stream(mutation):
    from constitutional_swarm.apcc.model import LogicalNodeState
    from constitutional_swarm.apcc.observation import (
        AuthorityObservationSnapshot,
        AuthorityObservationState,
        encode_signed_authority_observation,
    )
    from constitutional_swarm.apcc_empirical.w2_renewal_runtime import (
        sign_observer_tail,
        verify_observer_tail,
    )
    from tests.test_apcc_observation import (
        _launch_for_observer_key,
        _request,
        _sign_snapshot,
    )

    observer, controller = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    launch = _launch_for_observer_key(
        observer.public_key().public_bytes_raw(), controller
    )
    # The tail signature binds bytes independently of authority consumability;
    # the full replay separately rejects absent operations via _verify_operation.
    snapshot = AuthorityObservationSnapshot(
        _request(),
        AuthorityObservationState.ABSENT,
        None,
        None,
        None,
        None,
        None,
        LogicalNodeState("workflow-1", "node-1", "0", None),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )
    observation, _ = _sign_snapshot(
        snapshot, observer, launch_digest=launch.canonical_digest
    )
    plan = sha256_digest(b"external-plan")
    tail = sign_observer_tail(
        observer,
        dict(
            launch_digest=launch.canonical_digest,
            session_id=launch.session_id,
            observation_sequence=observation.sequence,
            observation_digest=sha256_digest(
                encode_signed_authority_observation(observation)
            ),
            epoch="0",
            plan_digest=plan,
            nonce=b64u_encode(bytes(16)),
        ),
    )
    epoch = 0
    if mutation == "stale-observation":
        observation, _ = _sign_snapshot(
            snapshot, observer, launch_digest=launch.canonical_digest, sequence="2"
        )
    elif mutation == "wrong-epoch":
        epoch = 1
    elif mutation == "wrong-plan":
        plan = sha256_digest(b"different-plan")
    elif mutation == "forged-signature":
        tail["signature"] = b64u_encode(bytes(64))
    elif mutation == "signer-alias":
        tail["key_id"] = sha256_digest(b"alias")
    elif mutation == "unknown-field":
        tail["body"]["extra"] = "unknown"
    if mutation is None:
        assert (
            verify_observer_tail(
                d._json(tail),
                launch=launch,
                observation=observation,
                epoch=epoch,
                plan_digest=plan,
            )
            == tail
        )
    else:
        with pytest.raises((ValueError, InvalidSignature)):
            verify_observer_tail(
                d._json(tail),
                launch=launch,
                observation=observation,
                epoch=epoch,
                plan_digest=plan,
            )
