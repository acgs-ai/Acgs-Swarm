"""C30 regression tests: gossip transport security and CRDT merge hot path.

Findings covered:
- gossip-1: the gossip shared secret must never cross a non-loopback link in
  plaintext; non-loopback hosts default to TLS.
- opt-dead-3: unreferenced ``SwarmNode._select_nodes_for_gossip`` is removed.
- opt-perf-6: the gossip server verifies each node's CID once, and metadata
  already normalized under the default limits is not re-normalized.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import math
import ssl
from typing import Any

import pytest
from constitutional_swarm import gossip_protocol, merkle_crdt
from constitutional_swarm.gossip_protocol import (
    GossipClient,
    GossipServer,
    SwarmNode,
    _encode_envelope,
    _node_to_wire,
    _wire_to_node,
)
from constitutional_swarm.merkle_crdt import (
    DAGNode,
    FrozenJSONDict,
    MerkleCRDT,
    compute_cid,
    normalize_json_value,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RecordingConnect:
    """Fake ``websockets.connect`` that records the URI and kwargs, then fails."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, uri: str, **kwargs: Any) -> Any:
        self.calls.append((uri, kwargs))
        raise OSError("recording connect: no network")


def _node(payload: str = "x", *, parents: tuple[str, ...] = ()) -> DAGNode:
    cid = compute_cid("a", payload, parents)
    return DAGNode(cid=cid, agent_id="a", payload=payload, parent_cids=parents)


def _self_signed(tmp_path) -> tuple[str, str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile), str(certfile)


# ---------------------------------------------------------------------------
# gossip-1: transport security
# ---------------------------------------------------------------------------


class TestGossip1ServerTransportSecurity:
    def test_non_loopback_server_without_tls_material_is_rejected(self):
        with pytest.raises(ValueError, match="TLS server requires"):
            GossipServer(MerkleCRDT("s"), host="0.0.0.0", secret_token="secret")

    def test_swarm_node_on_non_loopback_without_tls_material_is_rejected(self):
        with pytest.raises(ValueError, match="TLS server requires"):
            SwarmNode("n", host="10.0.0.5", secret_token="secret")

    def test_plaintext_non_loopback_server_refuses_secret_token(self):
        with pytest.raises(ValueError, match="plaintext"):
            GossipServer(
                MerkleCRDT("s"),
                host="0.0.0.0",
                secret_token="secret",
                transport_security="plaintext",
            )

    def test_plaintext_ws_url_non_loopback_server_refuses_secret_token(self):
        with pytest.raises(ValueError, match="plaintext"):
            GossipServer(MerkleCRDT("s"), host="ws://10.0.0.5", secret_token="secret")

    def test_loopback_server_defaults_to_plaintext(self):
        server = GossipServer(MerkleCRDT("s"), host="127.0.0.1", secret_token="secret")
        assert server.ssl_context is None

    def test_explicit_plaintext_non_loopback_without_token_is_allowed(self):
        server = GossipServer(
            MerkleCRDT("s"),
            host="0.0.0.0",
            allow_unauthenticated=True,
            transport_security="plaintext",
        )
        assert server.ssl_context is None

    def test_tls_server_material_is_built_and_passed_to_serve(self, tmp_path, monkeypatch):
        websockets = pytest.importorskip("websockets")

        certfile, keyfile, _ = _self_signed(tmp_path)
        server = GossipServer(
            MerkleCRDT("s"),
            host="0.0.0.0",
            secret_token="secret",
            certfile=certfile,
            keyfile=keyfile,
        )
        assert isinstance(server.ssl_context, ssl.SSLContext)
        seen: dict[str, Any] = {}

        async def fake_serve(handler, host, port, **kwargs):
            seen.update(kwargs)
            raise OSError("no bind in test")

        monkeypatch.setattr(websockets, "serve", fake_serve)
        with pytest.raises(OSError):
            asyncio.run(server.start())
        assert seen["ssl"] is server.ssl_context

    @pytest.mark.parametrize("mode", ["TLS", "", "none"])
    def test_unknown_transport_security_is_rejected(self, mode):
        with pytest.raises(ValueError, match="transport_security"):
            GossipServer(MerkleCRDT("s"), allow_unauthenticated=True, transport_security=mode)
        with pytest.raises(ValueError, match="transport_security"):
            GossipClient(transport_security=mode)

    def test_server_rejects_client_side_context(self):
        client_ctx = ssl.create_default_context()
        with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
            GossipServer(
                MerkleCRDT("s"),
                host="0.0.0.0",
                secret_token="secret",
                transport_security="tls",
                ssl_context=client_ctx,
            )


class TestGossip1ClientTransportSecurity:
    @pytest.mark.parametrize(
        ("client_kwargs", "host"),
        [
            ({"transport_security": "plaintext"}, "10.0.0.1"),
            ({}, "ws://10.0.0.1"),
            ({"transport_security": "plaintext"}, "0.0.0.0"),
        ],
    )
    async def test_sync_refuses_plaintext_secret_to_non_loopback(self, client_kwargs, host):
        connect = _RecordingConnect()
        client = GossipClient(connect=connect, **client_kwargs)
        source = MerkleCRDT("src")
        source.append("hello")
        with pytest.raises(ValueError, match="plaintext"):
            await client.sync(host, 9000, source, secret_token="secret")
        assert connect.calls == []

    @pytest.mark.parametrize(
        ("client_kwargs", "host"),
        [
            ({"transport_security": "plaintext"}, "10.0.0.1"),
            ({}, "ws://10.0.0.1"),
        ],
    )
    async def test_send_batch_refuses_plaintext_secret_to_non_loopback(
        self, client_kwargs, host
    ):
        connect = _RecordingConnect()
        client = GossipClient(connect=connect, **client_kwargs)
        with pytest.raises(ValueError, match="plaintext"):
            await client.send_batch(host, 9000, [_node()], secret_token="secret")
        assert connect.calls == []

    async def test_auto_non_loopback_uses_wss_with_ssl_context(self):
        connect = _RecordingConnect()
        client = GossipClient(connect=connect)
        source = MerkleCRDT("src")
        source.append("hello")
        result = await client.sync("10.0.0.1", 9000, source, secret_token="secret")
        assert result == {"complete": False, "nodes_sent": 0}
        assert await client.send_batch("10.0.0.1", 9000, [_node()], secret_token="s") is False
        assert [uri for uri, _ in connect.calls] == ["wss://10.0.0.1:9000"] * 2
        assert all(isinstance(kw["ssl"], ssl.SSLContext) for _, kw in connect.calls)

    async def test_loopback_stays_plaintext(self):
        connect = _RecordingConnect()
        client = GossipClient(connect=connect)
        source = MerkleCRDT("src")
        source.append("hello")
        await client.sync("127.0.0.1", 9000, source, secret_token="secret")
        await client.sync("::1", 9001, source, secret_token="secret")
        assert [uri for uri, _ in connect.calls] == ["ws://127.0.0.1:9000", "ws://[::1]:9001"]
        assert all(kw["ssl"] is None for _, kw in connect.calls)

    async def test_explicit_tls_context_is_used(self):
        ctx = ssl.create_default_context()
        connect = _RecordingConnect()
        client = GossipClient(connect=connect, transport_security="tls", ssl_context=ctx)
        await client.send_batch("127.0.0.1", 9000, [_node()], secret_token="s")
        assert connect.calls == [("wss://127.0.0.1:9000", {"ssl": ctx})]

    def test_auto_client_rejects_explicit_context(self):
        with pytest.raises(ValueError, match="auto transport"):
            GossipClient(ssl_context=ssl.create_default_context())

    @pytest.mark.parametrize(
        ("check_hostname", "verify_mode"),
        [(False, ssl.CERT_NONE), (False, ssl.CERT_OPTIONAL)],
    )
    def test_client_rejects_non_verifying_context(self, tmp_path, check_hostname, verify_mode):
        ctx = ssl.create_default_context()
        ctx.check_hostname = check_hostname
        ctx.verify_mode = verify_mode
        with pytest.raises(ValueError, match="must verify peers"):
            GossipClient(transport_security="tls", ssl_context=ctx)
        certfile, keyfile, _ = _self_signed(tmp_path)
        with pytest.raises(ValueError, match="must verify peers"):
            SwarmNode(
                "n",
                secret_token="s",
                transport_security="tls",
                certfile=certfile,
                keyfile=keyfile,
                client_ssl_context=ctx,
            )

    def test_client_rejects_hostname_check_disabled_only(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # verify_mode stays CERT_REQUIRED
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        with pytest.raises(ValueError, match="must verify peers"):
            GossipClient(transport_security="tls", ssl_context=ctx)

    def test_client_rejects_server_side_context(self):
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with pytest.raises(ValueError, match="PROTOCOL_TLS_CLIENT"):
            GossipClient(transport_security="tls", ssl_context=server_ctx)


async def test_gossip1_tls_round_trip_over_loopback(tmp_path):
    """Real end-to-end TLS gossip: explicit TLS server and client on loopback."""
    pytest.importorskip("websockets")
    certfile, keyfile, cafile = _self_signed(tmp_path)
    client_ctx = ssl.create_default_context(cafile=cafile)
    async with SwarmNode(
        "a",
        secret_token="secret",
        transport_security="tls",
        certfile=certfile,
        keyfile=keyfile,
        client_ssl_context=client_ctx,
    ) as a, SwarmNode(
        "b",
        secret_token="secret",
        transport_security="tls",
        certfile=certfile,
        keyfile=keyfile,
        client_ssl_context=client_ctx,
    ) as b:
        a.registry.add("127.0.0.1", b.actual_port)
        a.crdt.append("over tls")
        summary = await a.gossip_round(n_peers=1)
        assert summary["successes"] == 1
        assert b.crdt.all_cids() == a.crdt.all_cids()

        # A plaintext client cannot talk to the TLS server.
        plain = GossipClient(transport_security="plaintext")
        assert (
            await plain.send_batch("127.0.0.1", b.actual_port, [_node("p")], secret_token="secret")
            is False
        )


async def test_gossip1_default_client_context_refuses_untrusted_self_signed_server(tmp_path):
    """The default (system trust store) client context must not accept a self-signed peer."""
    pytest.importorskip("websockets")
    certfile, keyfile, _ = _self_signed(tmp_path)
    target = MerkleCRDT("target")
    server = GossipServer(
        target,
        secret_token="secret",
        transport_security="tls",
        certfile=certfile,
        keyfile=keyfile,
    )
    await server.start()
    try:
        client = GossipClient(transport_security="tls")
        assert client.ssl_context is None  # default context built per call
        sent = await client.send_batch(
            "127.0.0.1", server.actual_port, [_node("untrusted")], secret_token="secret"
        )
        source = MerkleCRDT("src")
        source.append("untrusted sync")
        synced = await client.sync("127.0.0.1", server.actual_port, source, secret_token="secret")
    finally:
        await server.stop()
    assert sent is False
    assert synced == {"complete": False, "nodes_sent": 0}
    assert target.size == 0


# ---------------------------------------------------------------------------
# opt-dead-3
# ---------------------------------------------------------------------------


def test_opt_dead3_select_nodes_for_gossip_removed():
    assert not hasattr(SwarmNode, "_select_nodes_for_gossip")


# ---------------------------------------------------------------------------
# opt-perf-6: single verification, single normalization
# ---------------------------------------------------------------------------


class TestOptPerf6:
    def test_wire_decode_normalizes_metadata_once(self, monkeypatch):
        node = DAGNode(
            cid=compute_cid("a", "p", (), metadata={"k": [1, {"z": 2}]}),
            agent_id="a",
            payload="p",
            metadata={"k": [1, {"z": 2}]},
        )
        wire = _node_to_wire(node)
        calls = []
        original = merkle_crdt.normalize_json_value

        def counting(value, **kwargs):
            calls.append(value)
            return original(value, **kwargs)

        monkeypatch.setattr(merkle_crdt, "normalize_json_value", counting)
        monkeypatch.setattr(gossip_protocol, "normalize_json_value", counting)
        decoded = _wire_to_node(wire)
        assert len(calls) == 1
        assert decoded.verify_cid()
        assert decoded.metadata == node.metadata

    def test_hand_built_frozen_dict_is_still_normalized(self):
        raw = FrozenJSONDict({"k": [1, 2]})
        node = DAGNode(cid="0" * 64, agent_id="a", payload="p", metadata=raw)
        assert type(node.metadata["k"]) is merkle_crdt.FrozenJSONList

    def test_hand_built_frozen_dict_with_nan_is_rejected(self):
        with pytest.raises(ValueError, match="finite"):
            DAGNode(
                cid="0" * 64,
                agent_id="a",
                payload="p",
                metadata=FrozenJSONDict({"k": math.nan}),
            )

    def test_looser_limit_normalization_does_not_bypass_metadata_limits(self):
        deep: Any = 0
        for _ in range(merkle_crdt.MAX_METADATA_DEPTH + 2):
            deep = {"d": deep}
        loose = normalize_json_value(deep, max_depth=merkle_crdt.MAX_METADATA_DEPTH + 10)
        assert isinstance(loose, FrozenJSONDict)
        with pytest.raises(ValueError, match="depth"):
            DAGNode(cid="0" * 64, agent_id="a", payload="p", metadata=loose)

    def test_merge_verified_nodes_inserts_without_reverifying(self, monkeypatch):
        nodes = [_node("one"), _node("two")]
        crdt = MerkleCRDT("t")
        calls = []
        monkeypatch.setattr(
            DAGNode, "verify_cid", lambda self: calls.append(self.cid) or True
        )
        assert crdt._merge_verified_nodes(nodes) == 2
        assert crdt._merge_verified_nodes(nodes) == 0
        assert calls == []
        assert crdt.all_cids() == {n.cid for n in nodes}

    @pytest.mark.parametrize("frame_kind", ["legacy", "nodes"])
    async def test_server_verifies_each_node_once(self, monkeypatch, frame_kind):
        from tests.test_c7_mesh_hardening import _c7_gossip_pair

        root = _node("root")
        child = _node("child", parents=(root.cid,))
        calls: list[str] = []
        original = DAGNode.verify_cid

        def counting(self):
            calls.append(self.cid)
            return original(self)

        monkeypatch.setattr(DAGNode, "verify_cid", counting)
        target = MerkleCRDT("t")
        server = GossipServer(target, allow_unauthenticated=True)
        client_ws, server_ws = _c7_gossip_pair()
        wire = [_node_to_wire(root), _node_to_wire(child)]
        if frame_kind == "legacy":
            await client_ws.send(json.dumps(wire))
        else:
            await client_ws.send(
                _encode_envelope("frontier", cids=[child.cid], page=0, final=True)
            )
        task = asyncio.create_task(server._handle_connection(server_ws))
        if frame_kind == "nodes":
            fetch = json.loads(await client_ws.recv())
            assert fetch["type"] == "fetch"
            await client_ws.send(_encode_envelope("nodes", nodes=wire))
            await client_ws.send(_encode_envelope("complete", complete=True))
        else:
            ack = json.loads(await client_ws.recv())
            assert ack["ok"] is True
            await client_ws.close()
        await asyncio.wait_for(task, 5)
        assert target.all_cids() == {root.cid, child.cid}
        assert sorted(calls) == sorted([root.cid, child.cid])

    async def test_server_still_rejects_forged_cid(self):
        from tests.test_c7_mesh_hardening import _c7_gossip_pair

        forged = _node_to_wire(_node("real"))
        forged["payload"] = "tampered"
        target = MerkleCRDT("t")
        server = GossipServer(target, allow_unauthenticated=True)
        client_ws, server_ws = _c7_gossip_pair()
        await client_ws.send(json.dumps([forged]))
        task = asyncio.create_task(server._handle_connection(server_ws))
        ack = json.loads(await client_ws.recv())
        await client_ws.close()
        await asyncio.wait_for(task, 5)
        assert ack["ok"] is False
        assert target.size == 0
