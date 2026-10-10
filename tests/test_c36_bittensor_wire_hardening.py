"""C36 regression tests: Bittensor wire authentication.

Every test is phrased as an invalid-input regression: the forged, unbound, or
misconfigured input must be rejected.  Structural checks run without bittensor;
real-signature paths use ``pytest.importorskip("bittensor")``.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from constitutional_swarm.bittensor.synapse_adapter import (
    GovernanceDeliberation,
    deliberation_to_bt,
)
from constitutional_swarm.bittensor.synapses import DeliberationSynapse

_REQUEST_FIELDS = (
    "task_id",
    "task_dag_json",
    "constitution_hash",
    "domain",
    "required_capabilities",
    "deadline_seconds",
    "escalation_type",
    "impact_score",
    "impact_vector",
    "context",
    "request_timestamp",
)

_CONSTITUTION = (
    "name: c36-wire-test\nrules:\n"
    "  - id: safety\n"
    "    text: Preserve safety and explain governance decisions\n"
    "    severity: high\n"
    "    hardcoded: false\n"
)


def _constitution_file(tmp_path) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "c36-constitution.yaml"
    path.write_text(_CONSTITUTION, encoding="utf-8")
    return str(path)


def _dispatched(constitution_hash: str = "c" * 64) -> GovernanceDeliberation:
    return deliberation_to_bt(
        DeliberationSynapse(
            task_id="c36-task",
            task_dag_json='{"goal":"original case"}',
            constitution_hash=constitution_hash,
            domain="governance",
            required_capabilities=("judgment",),
            deadline_seconds=60,
            escalation_type="context_sensitivity",
            impact_score=0.5,
            impact_vector={"safety": 0.5},
            context="original case text",
            timestamp=1_700_000_000.0,
        )
    )


def _response_ns(dispatched, *, axon_hotkey="miner-a", miner_uid="miner-a", **overrides):  # type: ignore[no-untyped-def]
    fields = {name: getattr(dispatched, name) for name in _REQUEST_FIELDS}
    fields.update(
        judgment="approve",
        reasoning="bounded",
        artifact_hash="artifact",
        dna_valid=True,
        dna_violations=[],
        dna_latency_ns=0,
        miner_uid=miner_uid,
        miner_constitution_hash=dispatched.constitution_hash,
        response_timestamp=1.0,
        response_protocol_version=2,
        response_signer_hotkey=miner_uid,
        response_signature="0x00",
        request_content_hash=dispatched.request_content_hash,
        error_message=None,
        axon=SimpleNamespace(hotkey=axon_hotkey, nonce=1, uuid="u", signature="0x00"),
        dendrite=SimpleNamespace(hotkey="validator-hk"),
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _load_deploy():  # type: ignore[no-untyped-def]
    import importlib.util
    from pathlib import Path

    script_path = Path(__file__).parents[1] / "scripts" / "testnet_deploy.py"
    spec = importlib.util.spec_from_file_location("c36_testnet_deploy", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stub_crypto(monkeypatch):  # type: ignore[no-untyped-def]
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    calls: list[str] = []
    monkeypatch.setattr(
        adapter, "verify_axon_response_signature", lambda *_a, **_k: calls.append("axon")
    )
    monkeypatch.setattr(
        adapter, "verify_judgment_response_signature", lambda *_a, **_k: calls.append("body")
    )
    return calls


# ---------------------------------------------------------------------------
# bittensor-dendrite-1: one library authenticator; the client drops failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"axon": SimpleNamespace(hotkey="")}, "authenticated hotkey"),
        ({"axon": None}, "authenticated hotkey"),
        ({"axon_hotkey": "attacker"}, "does not match request target"),
        ({"miner_uid": "victim"}, "miner_uid"),
        ({"miner_uid": ""}, "miner_uid"),
        ({"request_content_hash": "forged"}, "dispatched request"),
    ],
)
def test_c36_authenticate_response_rejects_unbound_identity_or_request(
    monkeypatch, overrides, message
):
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    calls = _stub_crypto(monkeypatch)
    dispatched = _dispatched()
    response = _response_ns(dispatched, **overrides)
    with pytest.raises(ValueError, match=message):
        authenticate_response(
            response,
            dispatched=dispatched,
            expected_axon_hotkey="miner-a",
            expected_dendrite_hotkey="validator-hk",
        )
    assert calls == [], "structural rejection must precede signature verification"


def test_c36_authenticate_response_requires_both_signature_checks(monkeypatch):
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    calls = _stub_crypto(monkeypatch)
    dispatched = _dispatched()
    judgment = authenticate_response(
        _response_ns(dispatched, axon_hotkey="  MINER-A‍ ", miner_uid="miner-a"),
        dispatched=dispatched,
        expected_axon_hotkey="miner-a",
        expected_dendrite_hotkey="validator-hk",
    )
    assert calls == ["axon", "body"]
    assert judgment.miner_uid == "miner-a"
    assert judgment.task_id == dispatched.task_id


@pytest.mark.asyncio
async def test_c36_network_client_drops_unauthenticated_spoofed_response(tmp_path):
    from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

    client = ValidatorDendriteClient(constitution_path=_constitution_file(tmp_path))
    spoof = GovernanceDeliberation(
        task_id="spoof",
        task_dag_json="{}",
        constitution_hash=client.constitution_hash,
        domain="d",
        judgment="approve",
        miner_uid="victim-miner",
        miner_constitution_hash=client.constitution_hash,
    )
    client._wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address="validator-hk"))
    client._dendrite = AsyncMock(return_value=[spoof])
    client._metagraph = SimpleNamespace(axons=[SimpleNamespace(hotkey="attacker-hk")])
    judgments = await client.query_miners(
        DeliberationSynapse(
            task_id="spoof",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="d",
        )
    )
    assert judgments == []


@pytest.mark.asyncio
async def test_c36_network_client_fails_closed_on_response_count_mismatch(tmp_path, monkeypatch):
    from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

    _stub_crypto(monkeypatch)
    client = ValidatorDendriteClient(constitution_path=_constitution_file(tmp_path))
    client._wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address="validator-hk"))
    dispatched_holder: dict[str, GovernanceDeliberation] = {}

    async def fake_dendrite(*, axons, synapse, timeout):
        del axons, timeout
        dispatched_holder["syn"] = synapse
        return [GovernanceDeliberation(**synapse.model_dump())]

    client._dendrite = fake_dendrite
    client._metagraph = SimpleNamespace(
        axons=[SimpleNamespace(hotkey="miner-a"), SimpleNamespace(hotkey="miner-b")]
    )
    judgments = await client.query_miners(
        DeliberationSynapse(
            task_id="count",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="d",
        )
    )
    assert judgments == []


@pytest.mark.asyncio
async def test_c36_network_client_without_local_dendrite_hotkey_fails_closed(tmp_path):
    from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

    client = ValidatorDendriteClient(constitution_path=_constitution_file(tmp_path))
    response = GovernanceDeliberation(
        task_id="nohk",
        task_dag_json="{}",
        constitution_hash=client.constitution_hash,
        domain="d",
        judgment="approve",
        miner_uid="miner-a",
        miner_constitution_hash=client.constitution_hash,
    )
    client._wallet = None
    client._dendrite = AsyncMock(return_value=[response])
    client._metagraph = SimpleNamespace(axons=[SimpleNamespace(hotkey="miner-a")])
    judgments = await client.query_miners(
        DeliberationSynapse(
            task_id="nohk",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="d",
        )
    )
    assert judgments == []


@pytest.mark.asyncio
async def test_c36_testnet_script_routes_through_library_authenticator(monkeypatch):
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    deploy = _load_deploy()
    assert not hasattr(deploy, "_verify_axon_response_signature"), (
        "response authentication must live only in the library"
    )
    seen: dict[str, object] = {}

    class Sentinel(Exception):
        pass

    def recorder(response, **kwargs):
        seen.update(kwargs, response=response)
        raise Sentinel

    monkeypatch.setattr(adapter, "authenticate_response", recorder)
    synapse = DeliberationSynapse(
        task_id="script",
        task_dag_json="{}",
        constitution_hash="c" * 64,
        domain="d",
    )
    response = object()
    with pytest.raises(Sentinel):
        await deploy._record_authenticated_response(
            response,
            expected_hotkey="miner-a",
            expected_dendrite_hotkey="validator-hk",
            authorized_identities={"miner-a"},
            validator=None,
            owner=None,
            case=SimpleNamespace(synapse=synapse),
            peer_routes={},
        )
    assert seen["response"] is response
    assert seen["expected_axon_hotkey"] == "miner-a"
    assert seen["expected_dendrite_hotkey"] == "validator-hk"
    assert seen["dispatched"].request_content_hash == synapse.content_hash


@pytest.mark.asyncio
async def test_c36_testnet_script_rejects_unauthorized_target_before_authentication(
    monkeypatch,
):
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    deploy = _load_deploy()
    monkeypatch.setattr(
        adapter,
        "authenticate_response",
        lambda *_a, **_k: pytest.fail("unauthorized target reached authentication"),
    )
    with pytest.raises(ValueError, match="not authorized"):
        await deploy._record_authenticated_response(
            object(),
            expected_hotkey="untrusted",
            expected_dendrite_hotkey="validator-hk",
            authorized_identities={"miner-a"},
            validator=None,
            owner=None,
            case=SimpleNamespace(synapse=None),
            peer_routes={},
        )


# ---------------------------------------------------------------------------
# bittensor-wire-1: every request field the miner consumes is bound
# ---------------------------------------------------------------------------


def test_c36_transport_hash_fields_cover_every_consumed_request_field():
    assert set(GovernanceDeliberation.required_hash_fields) >= set(_REQUEST_FIELDS)


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("context", "attacker rewritten case text"),
        ("domain", "finance"),
        ("deadline_seconds", 0),
        ("impact_vector", {"safety": 1.0}),
        ("escalation_type", "forged"),
        ("impact_score", 99.0),
        ("required_capabilities", ["other"]),
    ],
)
def test_c36_signed_response_bytes_bind_request_context(field, forged):
    from constitutional_swarm.bittensor.synapse_adapter import (
        canonical_judgment_response_bytes,
    )

    dispatched = _dispatched()
    original = canonical_judgment_response_bytes(_response_ns(dispatched))
    tampered = canonical_judgment_response_bytes(_response_ns(dispatched, **{field: forged}))
    assert original != tampered
    assert original.startswith(b"constitutional-swarm.bittensor-judgment-response.v2\x00")


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("context", "attacker rewritten case text"),
        ("deadline_seconds", 0),
        ("impact_vector", {"safety": 1.0}),
    ],
)
def test_c36_authenticate_response_rejects_tampered_request_context(monkeypatch, field, forged):
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    calls = _stub_crypto(monkeypatch)
    dispatched = _dispatched()
    with pytest.raises(ValueError, match="dispatched request"):
        authenticate_response(
            _response_ns(dispatched, **{field: forged}),
            dispatched=dispatched,
            expected_axon_hotkey="miner-a",
            expected_dendrite_hotkey="validator-hk",
        )
    assert calls == []


def test_c36_judgment_response_rejects_legacy_protocol_version():
    from constitutional_swarm.bittensor.synapse_adapter import (
        JUDGMENT_RESPONSE_PROTOCOL_VERSION,
        verify_judgment_response_signature,
    )

    assert JUDGMENT_RESPONSE_PROTOCOL_VERSION == 2
    response = _response_ns(_dispatched(), response_protocol_version=1)
    with pytest.raises(ValueError, match="protocol version"):
        verify_judgment_response_signature(
            response,
            expected_signer_hotkey="miner-a",
            expected_dendrite_hotkey="validator-hk",
        )


def test_c36_request_binding_rejects_non_finite_values():
    from constitutional_swarm.bittensor.synapse_adapter import request_binding_digest

    with pytest.raises(ValueError):
        request_binding_digest(_response_ns(_dispatched(), impact_score=float("nan")))


# ---------------------------------------------------------------------------
# bittensor-axon-1: signing key required unless explicitly opted out
# ---------------------------------------------------------------------------


def test_c36_axon_server_without_signing_key_is_rejected():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    with pytest.raises(ValueError, match="response_signing_key"):
        MinerAxonServer(SimpleNamespace(agent_id="miner-a"))
    with pytest.raises(ValueError, match="response_signing_key"):
        MinerAxonServer(SimpleNamespace(agent_id="miner-a"), allow_unauthenticated=True)


def test_c36_axon_server_rejects_signing_key_for_other_identity():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    with pytest.raises(ValueError, match="agent_id"):
        MinerAxonServer(
            SimpleNamespace(agent_id="miner-a"),
            response_signing_key=SimpleNamespace(ss58_address="miner-b"),
        )
    with pytest.raises(ValueError, match="SS58"):
        MinerAxonServer(
            SimpleNamespace(agent_id="miner-a"),
            response_signing_key=SimpleNamespace(ss58_address=""),
        )


def test_c36_axon_server_unsigned_requires_explicit_opt_in():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    server = MinerAxonServer(SimpleNamespace(agent_id="miner-a"), allow_unsigned_responses=True)
    assert server.miner.agent_id == "miner-a"
    signed = MinerAxonServer(
        SimpleNamespace(agent_id="miner-a"),
        response_signing_key=SimpleNamespace(ss58_address=" MINER-A "),
    )
    assert signed.miner.agent_id == "miner-a"


# ---------------------------------------------------------------------------
# bittensor-adapter-1: a missing miner constitution hash is not agreement
# ---------------------------------------------------------------------------


def test_c36_bt_to_judgment_rejects_missing_miner_constitution_hash():
    from constitutional_swarm.bittensor.synapse_adapter import bt_to_judgment

    response = GovernanceDeliberation(
        task_id="t",
        task_dag_json="{}",
        constitution_hash="requested-hash",
        domain="d",
        judgment="approve",
        miner_uid="miner-a",
    )
    with pytest.raises(ValueError, match="miner_constitution_hash"):
        bt_to_judgment(response)


# ---------------------------------------------------------------------------
# bittensor-dead-2 (miner part)
# ---------------------------------------------------------------------------


def test_c36_miner_has_no_unwired_acceptance_recorders():
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner

    assert not hasattr(ConstitutionalMiner, "record_acceptance")
    assert not hasattr(ConstitutionalMiner, "record_rejection")


# ---------------------------------------------------------------------------
# bench-eval-11: authority keys load through H3
# ---------------------------------------------------------------------------


def _write_authority_keyfile(path) -> None:  # type: ignore[no-untyped-def]
    import json

    path.write_text(
        json.dumps(
            {
                "assigner_id": "c36-assigner",
                "assigner_private_key_hex": "11" * 32,
                "request_signing_private_key_hex": "22" * 32,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_c36_authority_keyfile_rejects_hard_linked_secret(tmp_path):
    deploy = _load_deploy()
    keyfile = tmp_path / "authority-keys.json"
    _write_authority_keyfile(keyfile)
    os.link(keyfile, tmp_path / "authority-keys-alias.json")
    with pytest.raises(ValueError, match="authority key file"):
        deploy._load_authority_keys(str(keyfile))


def test_c36_authority_keyfile_rejects_special_mode_bits(tmp_path):
    deploy = _load_deploy()
    keyfile = tmp_path / "authority-keys.json"
    _write_authority_keyfile(keyfile)
    keyfile.chmod(0o1600)
    if os.stat(keyfile).st_mode & 0o1000 == 0:
        pytest.skip("filesystem does not retain the sticky bit")
    with pytest.raises(ValueError, match="authority key file"):
        deploy._load_authority_keys(str(keyfile))


def test_c36_authority_keyfile_still_loads_private_file(tmp_path):
    deploy = _load_deploy()
    keyfile = tmp_path / "authority-keys.json"
    _write_authority_keyfile(keyfile)
    assert deploy._load_authority_keys(str(keyfile)).assigner_id == "c36-assigner"


def test_c36_authority_keys_help_requires_chmod_600(monkeypatch, capsys):
    import sys

    deploy = _load_deploy()
    monkeypatch.setattr(sys, "argv", ["testnet_deploy.py", "validator", "--help"])
    with pytest.raises(SystemExit):
        deploy.main()
    assert "chmod 600" in " ".join(capsys.readouterr().out.split())


# ---------------------------------------------------------------------------
# Real-signature paths (bittensor required)
# ---------------------------------------------------------------------------


def _bt_signed_server(bt, tmp_path):  # type: ignore[no-untyped-def]
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig

    miner_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())

    async def deliberate(_task, _context, _metadata):
        return "approve", "bounded and compliant"

    miner = ConstitutionalMiner(
        MinerConfig(
            constitution_path=_constitution_file(tmp_path), agent_id=miner_key.ss58_address
        ),
        deliberation_handler=deliberate,
    )
    server = MinerAxonServer(miner, allow_unauthenticated=True, response_signing_key=miner_key)
    return miner_key, server


async def _bt_exchange(server, axon_key, validator_key, dispatched, *, tamper=None):  # type: ignore[no-untyped-def]
    wire = GovernanceDeliberation(**dispatched.model_dump())
    wire.dendrite.hotkey = validator_key.ss58_address
    if tamper is not None:
        tamper(wire)
    response = await server.forward(wire)
    assert response.error_message is None
    nonce, uuid = 424242, "c36-uuid"
    response.axon.hotkey = axon_key.ss58_address
    response.axon.nonce = nonce
    response.axon.uuid = uuid
    message = f"{nonce}.{validator_key.ss58_address}.{axon_key.ss58_address}.{uuid}"
    response.axon.signature = "0x" + axon_key.sign(message).hex()
    return response


@pytest.mark.asyncio
async def test_c36_bt_signed_response_authenticates_and_tampering_is_rejected(tmp_path):
    bt = pytest.importorskip("bittensor")
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    miner_key, server = _bt_signed_server(bt, tmp_path)
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dispatched = _dispatched(server.miner.constitution_hash)
    response = await _bt_exchange(server, miner_key, validator_key, dispatched)

    judgment = authenticate_response(
        response,
        dispatched=dispatched,
        expected_axon_hotkey=miner_key.ss58_address,
        expected_dendrite_hotkey=validator_key.ss58_address,
    )
    assert judgment.judgment == "approve"

    response.judgment = "deny"
    with pytest.raises(ValueError, match="body signature"):
        authenticate_response(
            response,
            dispatched=dispatched,
            expected_axon_hotkey=miner_key.ss58_address,
            expected_dendrite_hotkey=validator_key.ss58_address,
        )


@pytest.mark.asyncio
async def test_c36_bt_relay_rewritten_context_is_rejected(tmp_path):
    bt = pytest.importorskip("bittensor")
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    miner_key, server = _bt_signed_server(bt, tmp_path)
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dispatched = _dispatched(server.miner.constitution_hash)

    def rewrite(wire):  # type: ignore[no-untyped-def]
        wire.context = "attacker rewritten case text"

    response = await _bt_exchange(server, miner_key, validator_key, dispatched, tamper=rewrite)
    with pytest.raises(ValueError, match="dispatched request"):
        authenticate_response(
            response,
            dispatched=dispatched,
            expected_axon_hotkey=miner_key.ss58_address,
            expected_dendrite_hotkey=validator_key.ss58_address,
        )


@pytest.mark.asyncio
async def test_c36_bt_axon_signed_by_other_key_is_rejected(tmp_path):
    bt = pytest.importorskip("bittensor")
    from constitutional_swarm.bittensor.synapse_adapter import authenticate_response

    miner_key, server = _bt_signed_server(bt, tmp_path)
    attacker = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dispatched = _dispatched(server.miner.constitution_hash)
    response = await _bt_exchange(server, miner_key, validator_key, dispatched)
    message = (
        f"{response.axon.nonce}.{validator_key.ss58_address}.{miner_key.ss58_address}.c36-uuid"
    )
    response.axon.signature = "0x" + attacker.sign(message).hex()
    with pytest.raises(ValueError, match="axon signature"):
        authenticate_response(
            response,
            dispatched=dispatched,
            expected_axon_hotkey=miner_key.ss58_address,
            expected_dendrite_hotkey=validator_key.ss58_address,
        )


@pytest.mark.asyncio
async def test_c36_bt_network_client_admits_only_authenticated_axon(tmp_path):
    bt = pytest.importorskip("bittensor")
    from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

    miner_key, server = _bt_signed_server(bt, tmp_path)
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    client = ValidatorDendriteClient(constitution_path=_constitution_file(tmp_path))
    client._wallet = SimpleNamespace(hotkey=validator_key)
    good_axon = SimpleNamespace(hotkey=miner_key.ss58_address)
    victim_axon = SimpleNamespace(hotkey=validator_key.ss58_address)

    async def fake_dendrite(*, axons, synapse, timeout):
        del timeout
        signed = await _bt_exchange(server, miner_key, validator_key, synapse)
        # Second axon slot replays the same signed response under another identity.
        replay = GovernanceDeliberation(**signed.model_dump())
        replay.axon.hotkey = victim_axon.hotkey
        assert len(axons) == 2
        return [signed, replay]

    client._dendrite = fake_dendrite
    client._metagraph = SimpleNamespace(axons=[good_axon, victim_axon])
    judgments = await client.query_miners(
        DeliberationSynapse(
            task_id="bt-net",
            task_dag_json='{"goal":"x"}',
            constitution_hash=client.constitution_hash,
            domain="governance",
            context="case",
        )
    )
    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    assert [j.miner_uid for j in judgments] == [normalize_voter_id(miner_key.ss58_address)]


def test_c36_bt_transport_body_hash_survives_json_round_trip():
    import json

    pytest.importorskip("bittensor")
    syn = deliberation_to_bt(
        DeliberationSynapse(
            task_id="body-hash",
            task_dag_json='{"goal":"x"}',
            constitution_hash="c" * 64,
            domain="governance",
            required_capabilities=("a", "b"),
            impact_score=0.25,
            impact_vector={"safety": 0.5, "privacy": 0.125},
            context="case text",
            timestamp=1_700_000_000.123456,
        )
    )
    # Mirrors the axon: rebuild the synapse from the JSON body and rehash it.
    wire = GovernanceDeliberation(**json.loads(json.dumps(syn.model_dump())))
    assert wire.body_hash == syn.body_hash
    tampered = GovernanceDeliberation(**json.loads(json.dumps(syn.model_dump())))
    tampered.context = "attacker rewritten case text"
    assert tampered.body_hash != syn.body_hash


# ---------------------------------------------------------------------------
# Rework r1: transport verification composed in front of local checks
# ---------------------------------------------------------------------------


def _transport_synapse(**dendrite):  # type: ignore[no-untyped-def]
    fields = {"hotkey": "validator-hk", "signature": "0xsig"}
    fields.update(dendrite)
    return SimpleNamespace(dendrite=SimpleNamespace(**fields), computed_body_hash="h" * 64)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("synapse", "message"),
    [
        (_transport_synapse(hotkey=""), "dendrite hotkey"),
        (_transport_synapse(hotkey=None), "dendrite hotkey"),
        (_transport_synapse(signature=""), "signature is missing"),
        (_transport_synapse(signature=None), "signature is missing"),
        (SimpleNamespace(dendrite=None), "dendrite hotkey"),
    ],
)
async def test_c36_verify_transport_rejects_unsigned_or_anonymous_request(synapse, message):
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    async def default_verify(_synapse):  # type: ignore[no-untyped-def]
        pytest.fail("default_verify must not be reached for an unsigned request")

    with pytest.raises(ValueError, match=message):
        await MinerAxonServer.verify_transport(synapse, default_verify)


@pytest.mark.asyncio
async def test_c36_verify_transport_rejects_missing_body_hash_and_propagates_default():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    unsigned_body = _transport_synapse()
    unsigned_body.computed_body_hash = ""
    with pytest.raises(ValueError, match="body hash"):
        await MinerAxonServer.verify_transport(unsigned_body, lambda _s: None)

    calls: list[object] = []

    async def failing_default(synapse):  # type: ignore[no-untyped-def]
        calls.append(synapse)
        raise RuntimeError("Nonce is too old")

    request = _transport_synapse()
    with pytest.raises(RuntimeError, match="Nonce"):
        await MinerAxonServer.verify_transport(request, failing_default)
    assert calls == [request]


def test_c36_attach_to_refuses_axon_without_default_verify():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    server = MinerAxonServer(SimpleNamespace(agent_id="m"), allow_unsigned_responses=True)

    class BareAxon:
        def attach(self, **_handlers):  # type: ignore[no-untyped-def]
            pytest.fail("attach must not happen without default_verify")

    with pytest.raises(ValueError, match="default_verify"):
        server.attach_to(BareAxon())


@pytest.mark.asyncio
async def test_c36_attach_to_verify_fn_always_runs_default_verify():
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer

    server = MinerAxonServer(
        SimpleNamespace(agent_id="m"),
        trusted_validator_hotkeys={"validator-hk"},
        allow_unsigned_responses=True,
    )
    attached: dict[str, object] = {}
    seen: list[object] = []

    class FakeAxon:
        async def default_verify(self, synapse):  # type: ignore[no-untyped-def]
            seen.append(synapse)

        def attach(self, **handlers):  # type: ignore[no-untyped-def]
            attached.update(handlers)

    server.attach_to(FakeAxon())
    request = _transport_synapse()
    await attached["verify_fn"](request)  # type: ignore[operator]
    assert seen == [request]
    assert attached["blacklist_fn"](request) == (False, "trusted validator")  # type: ignore[operator]
    forged = _transport_synapse(hotkey="attacker")
    blocked, _reason = attached["blacklist_fn"](forged)  # type: ignore[operator]
    assert blocked is True


# ---------------------------------------------------------------------------
# Rework r1: bounded deadlines
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deadline", [0, -1, 86_401, True, 1.5])
def test_c36_miner_rejects_unbounded_or_non_positive_deadline(tmp_path, deadline):
    import asyncio

    from constitutional_swarm.bittensor.miner import ConstitutionalMiner, InvalidDeadlineError
    from constitutional_swarm.bittensor.protocol import MinerConfig

    called: list[str] = []

    async def deliberate(task, _context, _metadata):  # type: ignore[no-untyped-def]
        called.append(task)
        return "approve", "ok"

    miner = ConstitutionalMiner(
        MinerConfig(constitution_path=_constitution_file(tmp_path), agent_id="m"),
        deliberation_handler=deliberate,
    )
    request = DeliberationSynapse(
        task_id="deadline",
        task_dag_json="{}",
        constitution_hash=miner.constitution_hash,
        domain="d",
        deadline_seconds=deadline,  # type: ignore[arg-type]
    )
    with pytest.raises(InvalidDeadlineError):
        asyncio.run(miner.process(request))
    assert called == []


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", [0, -5, 10**9])
async def test_c36_axon_forward_rejects_invalid_deadline(tmp_path, deadline):
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig

    async def deliberate(_task, _context, _metadata):  # type: ignore[no-untyped-def]
        pytest.fail("handler must not run for an invalid deadline")

    miner = ConstitutionalMiner(
        MinerConfig(constitution_path=_constitution_file(tmp_path), agent_id="m"),
        deliberation_handler=deliberate,
    )
    server = MinerAxonServer(miner, allow_unsigned_responses=True)
    request = GovernanceDeliberation(
        task_id="deadline",
        task_dag_json="{}",
        constitution_hash=miner.constitution_hash,
        domain="d",
        deadline_seconds=deadline,
    )
    response = await server.forward(request)
    assert response.judgment is None
    assert response.error_message is not None
    assert "deadline_seconds" in response.error_message


@pytest.mark.asyncio
async def test_c36_network_client_never_dispatches_zero_deadline(tmp_path):
    from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

    client = ValidatorDendriteClient(constitution_path=_constitution_file(tmp_path))
    client._wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address="validator-hk"))
    sent: list[int] = []

    async def fake_dendrite(*, axons, synapse, timeout):  # type: ignore[no-untyped-def]
        del axons, timeout
        sent.append(synapse.deadline_seconds)
        return []

    client._dendrite = fake_dendrite
    client._metagraph = SimpleNamespace(axons=[])
    await client.query_miners(
        DeliberationSynapse(
            task_id="sub-second",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="d",
        ),
        timeout=0.25,
    )
    assert sent == [1]


# ---------------------------------------------------------------------------
# Rework r1: testnet miner trusted validators, validator count mismatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", " , ", None])
def test_c36_testnet_miner_requires_trusted_validators(monkeypatch, raw):
    import argparse

    deploy = _load_deploy()
    monkeypatch.setattr(
        deploy, "_check_bittensor", lambda: pytest.fail("must fail before touching bittensor")
    )
    args = argparse.Namespace(
        constitution="unused.yaml",
        wallet_name="w",
        wallet_hotkey="h",
        netuid=1,
        port=8091,
        capabilities="",
        domains="",
        trusted_validators=raw,
    )
    with pytest.raises(ValueError, match="trusted validator"):
        deploy.cmd_miner(args)


def test_c36_testnet_miner_cli_requires_trusted_validators_flag(monkeypatch, capsys):
    import sys

    deploy = _load_deploy()
    monkeypatch.setattr(sys, "argv", ["testnet_deploy.py", "miner", "--help"])
    with pytest.raises(SystemExit):
        deploy.main()
    assert "--trusted-validators" in capsys.readouterr().out


def test_c36_testnet_validator_discards_round_on_response_count_mismatch(monkeypatch, tmp_path):
    import argparse
    import time

    bt = pytest.importorskip("bittensor")
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    deploy = _load_deploy()
    case = SimpleNamespace(
        synapse=DeliberationSynapse(
            task_id="count-mismatch",
            task_dag_json="{}",
            constitution_hash="c" * 64,
            domain="governance",
        )
    )
    filled = deliberation_to_bt(case.synapse)
    filled.judgment = "approve"
    monkeypatch.setattr(
        adapter,
        "authenticate_response",
        lambda *_a, **_k: pytest.fail("mismatched responses must not be authenticated"),
    )

    class Validator:
        constitution_hash = "c" * 64
        stats: dict[str, int] = {}

        def compute_emission_weights(self):  # type: ignore[no-untyped-def]
            return {}

    class Owner:
        def package_case(self, *_args):  # type: ignore[no-untyped-def]
            return case

    metagraph = SimpleNamespace(
        n=1,
        hotkeys=["miner-a"],
        axons=[SimpleNamespace(hotkey="miner-a")],
        sync=lambda: None,
    )

    class Dendrite:
        def __init__(self, **_kwargs):  # type: ignore[no-untyped-def]
            pass

        async def __call__(self, **_kwargs):  # type: ignore[no-untyped-def]
            return [filled, filled]

    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    monkeypatch.setattr(deploy, "_check_bittensor", lambda: None)
    monkeypatch.setattr(
        deploy,
        "_load_authority_keys",
        lambda _p: SimpleNamespace(
            assigner_id="a", assigner_private_key=object(), request_signing_private_key=object()
        ),
    )
    monkeypatch.setattr(
        deploy,
        "_load_authorized_voter_keys",
        lambda _p: {"miner-a": SimpleNamespace(route=("127.0.0.1", 9000))},
    )
    monkeypatch.setattr(
        deploy, "_build_validator_runtime", lambda *_a, **_k: (Validator(), Owner())
    )
    monkeypatch.setattr(
        bt,
        "wallet",
        lambda **_k: SimpleNamespace(name="v", hotkey=validator_key, hotkey_str="v"),
        raising=False,
    )
    monkeypatch.setattr(
        bt,
        "subtensor",
        lambda **_k: SimpleNamespace(
            register=lambda **_kw: None, metagraph=lambda **_kw: metagraph
        ),
        raising=False,
    )
    monkeypatch.setattr(bt, "Dendrite", Dendrite)
    monkeypatch.setattr(time, "sleep", lambda _s: (_ for _ in ()).throw(KeyboardInterrupt))
    constitution = tmp_path / "constitution.yaml"
    constitution.write_text("name: t\nrules: []\n", encoding="utf-8")
    deploy.cmd_validator(
        argparse.Namespace(
            constitution=str(constitution),
            authorized_voters="unused.json",
            authority_keys="unused.json",
            peers=5,
            quorum=3,
            wallet_name="v",
            wallet_hotkey="v",
            netuid=1,
            epoch_seconds=1,
        )
    )


# ---------------------------------------------------------------------------
# Rework r1: real bittensor axon over localhost HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c36_bt_real_axon_enforces_transport_authentication(tmp_path):
    bt = pytest.importorskip("bittensor")
    aiohttp = pytest.importorskip("aiohttp")
    import asyncio
    import socket
    import uuid

    from bittensor.core.dendrite import Dendrite

    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig
    from constitutional_swarm.bittensor.synapse_adapter import (
        verify_judgment_response_signature,
    )

    wallet = bt.Wallet(name="c36", hotkey="c36", path=str(tmp_path / "wallets"))
    wallet.create_new_coldkey(overwrite=True, use_password=False, suppress=True)
    wallet.create_new_hotkey(overwrite=True, use_password=False, suppress=True)
    validator = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    attacker = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())

    async def deliberate(_task, _context, _metadata):  # type: ignore[no-untyped-def]
        return "approve", "bounded and compliant"

    miner = ConstitutionalMiner(
        MinerConfig(
            constitution_path=_constitution_file(tmp_path),
            agent_id=wallet.hotkey.ss58_address,
        ),
        deliberation_handler=deliberate,
    )
    server = MinerAxonServer(
        miner,
        trusted_validator_hotkeys={validator.ss58_address},
        response_signing_key=wallet.hotkey,
    )
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    axon = bt.Axon(wallet=wallet, ip="127.0.0.1", external_ip="127.0.0.1", port=port)
    server.attach_to(axon)
    axon.start()
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                await asyncio.sleep(0.05)
        target = SimpleNamespace(ip="127.0.0.1", port=port, hotkey=wallet.hotkey.ss58_address)

        def build(signer, *, claimed_hotkey=None):  # type: ignore[no-untyped-def]
            synapse = _dispatched(miner.constitution_hash)
            requester = SimpleNamespace(
                external_ip="127.0.0.1", uuid=str(uuid.uuid4()), keypair=signer
            )
            synapse = Dendrite.preprocess_synapse_for_request(requester, target, synapse, 12.0)
            if claimed_hotkey is not None:
                synapse.dendrite.hotkey = claimed_hotkey
            return synapse

        async def send(synapse, body=None):  # type: ignore[no-untyped-def]
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/GovernanceDeliberation",
                    headers=synapse.to_headers(),
                    json=body if body is not None else synapse.model_dump(),
                ) as reply:
                    payload = await reply.json(content_type=None)
                    return reply.status, payload

        honest = build(validator)
        status, payload = await send(honest)
        assert status == 200, payload
        response = GovernanceDeliberation(**payload)
        assert response.judgment == "approve"
        response.dendrite.hotkey = validator.ss58_address
        verify_judgment_response_signature(
            response,
            expected_signer_hotkey=wallet.hotkey.ss58_address,
            expected_dendrite_hotkey=validator.ss58_address,
        )

        replay_status, _ = await send(honest)
        assert replay_status == 401

        forged_status, _ = await send(build(attacker, claimed_hotkey=validator.ss58_address))
        assert forged_status == 401

        unsigned = build(validator)
        unsigned.dendrite.signature = None
        unsigned_status, _ = await send(unsigned)
        assert unsigned_status == 401

        tampered = build(validator)
        body = tampered.model_dump()
        body["context"] = "attacker rewritten case text"
        tampered_status, tampered_payload = await send(tampered, body)
        assert tampered_status != 200
        assert not (isinstance(tampered_payload, dict) and tampered_payload.get("judgment"))
    finally:
        axon.stop()
