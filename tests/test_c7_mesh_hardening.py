"""Regression coverage for the C7 mesh hardening findings."""

from dataclasses import dataclass

import pytest


# BEGIN C7 GOSSIP


class _C7GossipEndpoint:
    def __init__(self) -> None:
        import asyncio

        self.incoming = asyncio.Queue()
        self.peer = None
        self.remote_address = ("memory", 0)
        self.sent = []
        self.close_code = None
        self.close_reason = None

    async def send(self, message):
        self.sent.append(message)
        await self.peer.incoming.put(message)

    async def recv(self):
        item = await self.incoming.get()
        if item is _C7_GOSSIP_CLOSED:
            raise StopAsyncIteration
        return item

    async def close(self, code=1000, reason=""):
        self.close_code = code
        self.close_reason = reason
        await self.peer.incoming.put(_C7_GOSSIP_CLOSED)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.recv()
        except StopAsyncIteration:
            raise StopAsyncIteration from None


class _C7GossipConnection:
    def __init__(self, endpoint, server_task) -> None:
        self.endpoint = endpoint
        self.server_task = server_task

    async def __aenter__(self):
        return self.endpoint

    async def __aexit__(self, *_):
        await self.endpoint.close()
        await self.server_task


_C7_GOSSIP_CLOSED = object()


def _c7_gossip_pair():
    left = _C7GossipEndpoint()
    right = _C7GossipEndpoint()
    left.peer = right
    right.peer = left
    return left, right


class TestC7MerkleMetadata:
    def test_metadata_is_detached_recursively_immutable_and_cid_stable(self):
        import pytest

        from constitutional_swarm.gossip_protocol import _node_to_wire, _wire_to_node
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        supplied = {"nested": {"values": [1, 2]}, "label": "stable"}
        source = MerkleCRDT("source")
        node = source.append("payload", metadata=supplied)
        supplied["nested"]["values"].append(3)

        assert node.verify_cid()
        assert node.metadata == {"nested": {"values": [1, 2]}, "label": "stable"}
        with pytest.raises(TypeError):
            node.metadata["label"] = "changed"
        with pytest.raises((AttributeError, TypeError)):
            node.metadata["nested"]["values"].append(3)
        with pytest.raises(TypeError):
            node.metadata._data = {}

        target = MerkleCRDT("target")
        assert target.merge(source) == 1
        merged = target.get(node.cid)
        assert merged is not None and merged.verify_cid()
        wire = _node_to_wire(merged)
        wire["metadata"]["nested"]["values"].append(99)
        assert merged.verify_cid()
        rebuilt = _wire_to_node(_node_to_wire(merged))
        assert rebuilt.verify_cid()

    def test_invalid_metadata_and_duplicate_parents_fail_at_constructor(self):
        import pytest

        from constitutional_swarm.merkle_crdt import DAGNode

        with pytest.raises(ValueError):
            DAGNode(cid="0" * 64, agent_id="a", payload="p", metadata={"x": float("nan")})
        with pytest.raises(TypeError):
            DAGNode(cid="0" * 64, agent_id="a", payload="p", metadata={1: "bad"})
        with pytest.raises(ValueError):
            DAGNode(
                cid="0" * 64,
                agent_id="a",
                payload="p",
                parent_cids=("1" * 64, "1" * 64),
            )


class TestC7MerkleTopology:
    def test_indexed_topological_order_visits_every_node_once(self):
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        crdt = MerkleCRDT("topology")
        roots = []
        for idx in range(80):
            payload = f"root-{idx}"
            cid = compute_cid("a", payload, ())
            roots.append(DAGNode(cid=cid, agent_id="a", payload=payload))
        parent_cids = tuple(node.cid for node in roots)
        join_cid = compute_cid("a", "join", parent_cids)
        join = DAGNode(cid=join_cid, agent_id="a", payload="join", parent_cids=parent_cids)
        assert crdt.merge_nodes([join, *roots]) == 81

        order = crdt.topological_order()
        positions = {node.cid: index for index, node in enumerate(order)}
        assert len(order) == 81
        assert len(positions) == 81
        assert all(positions[parent.cid] < positions[join.cid] for parent in roots)
        assert crdt.heads == frozenset({join.cid})


class TestC7GossipWireValidation:
    def test_hostile_wire_values_fail_closed(self):
        import json

        import pytest

        from constitutional_swarm.gossip_protocol import MAX_BATCH_BYTES, decode_batch

        valid = {
            "cid": "0" * 64,
            "agent_id": "a",
            "payload": "p",
            "payload_type": "artifact",
            "parent_cids": [],
            "bodes_passed": False,
            "constitutional_hash": "",
            "metadata": {},
        }
        hostile = [
            json.dumps(["not-an-object"]),
            json.dumps([{**valid, "parent_cids": "abc"}]),
            json.dumps([{**valid, "parent_cids": ["1" * 64, "1" * 64]}]),
            json.dumps([{**valid, "bodes_passed": 1}]),
            json.dumps([{**valid, "metadata": []}]),
            "[" * 80 + "]" * 80,
            json.dumps([{**valid, "payload": "é" * MAX_BATCH_BYTES}]),
        ]
        for message in hostile:
            with pytest.raises(ValueError):
                decode_batch(message)
        with pytest.raises(ValueError):
            decode_batch(b"[]")

    def test_envelope_schema_and_resource_limits_are_exact(self):
        import pytest

        from constitutional_swarm.gossip_protocol import (
            MAX_SESSION_BYTES,
            MAX_SESSION_NODES,
            GossipServer,
            _decode_envelope,
            _encode_envelope,
        )
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        with pytest.raises(ValueError, match="unexpected fields"):
            _decode_envelope(
                _encode_envelope(
                    "frontier", cids=[], page=0, final=True, attacker_controlled=True
                )
            )
        with pytest.raises(ValueError, match="budget"):
            _decode_envelope(
                _encode_envelope("fetch", cids=[], budget=MAX_SESSION_NODES + 1)
            )
        with pytest.raises(ValueError):
            GossipServer(MerkleCRDT("target"), max_nodes_per_session=True)
        with pytest.raises(ValueError):
            GossipServer(
                MerkleCRDT("target"), max_bytes_per_session=MAX_SESSION_BYTES + 1
            )

    async def test_session_byte_budget_rejects_before_dispatch(self):
        import asyncio
        import json

        from constitutional_swarm.gossip_protocol import GossipServer, _encode_envelope
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        client_ws, server_ws = _c7_gossip_pair()
        server = GossipServer(
            MerkleCRDT("target"),
            allow_unauthenticated=True,
            max_bytes_per_session=32,
        )
        task = asyncio.create_task(server._handle_connection(server_ws))
        await client_ws.send(
            _encode_envelope("frontier", cids=["0" * 64], page=0, final=True)
        )

        response = json.loads(await client_ws.recv())
        await task
        assert response["type"] == "error"
        assert "byte budget" in response["message"]


class TestC7GossipAntiEntropy:
    async def _sync_once(self, source, target, *, chunk_size=64, session_nodes=4096):
        import asyncio

        from constitutional_swarm.gossip_protocol import GossipClient, GossipServer

        client_ws, server_ws = _c7_gossip_pair()
        server = GossipServer(
            target,
            allow_unauthenticated=True,
            max_nodes_per_session=session_nodes,
        )
        server_task = asyncio.create_task(server._handle_connection(server_ws))
        client = GossipClient(
            connect=lambda *_args, **_kwargs: _C7GossipConnection(client_ws, server_task)
        )
        result = await client.sync("memory", 0, source, chunk_size=chunk_size)
        return result, client_ws.sent, server_ws.sent

    async def test_more_than_one_thousand_nodes_converge_in_bounded_chunks(self):
        import json

        from constitutional_swarm.gossip_protocol import MAX_BATCH_NODES
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        source = MerkleCRDT("source")
        for idx in range(1005):
            source.append(f"node-{idx}")
        target = MerkleCRDT("target")

        result, client_frames, _ = await self._sync_once(source, target, chunk_size=128)

        assert result["complete"] is True
        assert result["nodes_sent"] == 1005
        assert target.all_cids() == source.all_cids()
        node_frames = [
            decoded
            for frame in client_frames
            if isinstance((decoded := json.loads(frame)), dict)
            and decoded.get("type") == "nodes"
        ]
        assert len(node_frames) > 1
        assert all(0 < len(frame["nodes"]) <= min(128, MAX_BATCH_NODES) for frame in node_frames)

    async def test_partial_session_resumes_missing_ancestry_below_known_head(self):
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        source = MerkleCRDT("source")
        for idx in range(9):
            source.append(f"node-{idx}")
        target = MerkleCRDT("target")

        first, _, _ = await self._sync_once(source, target, chunk_size=2, session_nodes=3)
        assert first["complete"] is False
        assert 0 < target.size <= 3
        assert source.heads.issubset(target.all_cids())

        for _ in range(4):
            result, _, _ = await self._sync_once(
                source, target, chunk_size=2, session_nodes=3
            )
            if result["complete"]:
                break
        assert result["complete"] is True
        assert target.all_cids() == source.all_cids()

    async def test_wide_frontier_converges_across_paged_advertisement(self):
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        source = MerkleCRDT("source")
        roots = []
        for index in range(600):
            payload = f"root-{index}"
            roots.append(
                DAGNode(
                    cid=compute_cid("source", payload, ()),
                    agent_id="source",
                    payload=payload,
                )
            )
        assert source.merge_nodes(roots) == len(roots)
        target = MerkleCRDT("target")

        result, client_frames, _ = await self._sync_once(
            source, target, chunk_size=73, session_nodes=700
        )

        assert result == {"complete": True, "nodes_sent": 600}
        assert target.all_cids() == source.all_cids()
        assert sum('"type":"frontier"' in frame for frame in client_frames) == 3

    async def test_scan_limit_checkpoint_does_not_false_complete(self, monkeypatch):
        import constitutional_swarm.gossip_protocol as gossip_protocol
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        monkeypatch.setattr(gossip_protocol, "MAX_ANCESTRY_SCAN", 3)
        source = MerkleCRDT("source")
        for index in range(4):
            source.append(f"chain-{index}")
        target = MerkleCRDT("target")
        ordered = source.topological_order()
        assert target.merge_nodes(ordered[1:]) == 3

        result, _, _ = await self._sync_once(source, target)

        assert result["complete"] is False
        assert result["nodes_sent"] == 1
        assert target.all_cids() == source.all_cids()

    async def test_frontier_pages_make_progress_before_round_budget(self, monkeypatch):
        import constitutional_swarm.gossip_protocol as gossip_protocol
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        monkeypatch.setattr(gossip_protocol, "MAX_FRONTIER_CIDS", 2)
        monkeypatch.setattr(gossip_protocol, "MAX_PROTOCOL_ROUNDS", 4)
        source = MerkleCRDT("source")
        roots = [
            DAGNode(
                cid=compute_cid("source", f"wide-{index}", ()),
                agent_id="source",
                payload=f"wide-{index}",
            )
            for index in range(7)
        ]
        assert source.merge_nodes(roots) == 7
        target = MerkleCRDT("target")

        sizes = []
        for _ in range(8):
            result, _, _ = await self._sync_once(source, target, chunk_size=2)
            sizes.append(target.size)
            if result["complete"]:
                break

        assert any(after > before for before, after in zip([0, *sizes], sizes))
        assert result["complete"] is True
        assert target.all_cids() == source.all_cids()

    def test_node_chunk_partition_serializes_each_node_once(self, monkeypatch):
        import constitutional_swarm.gossip_protocol as gossip_protocol
        from constitutional_swarm.merkle_crdt import DAGNode, compute_cid

        nodes = [
            DAGNode(
                cid=compute_cid("source", f"node-{index}", ()),
                agent_id="source",
                payload=f"node-{index}",
            )
            for index in range(200)
        ]
        calls = 0
        original = gossip_protocol._node_to_wire

        def counting_node_to_wire(node):
            nonlocal calls
            calls += 1
            return original(node)

        monkeypatch.setattr(gossip_protocol, "_node_to_wire", counting_node_to_wire)
        chunks = gossip_protocol.GossipClient._node_chunks(nodes, 100)

        assert [len(chunk) for chunk in chunks] == [100, 100]
        assert calls == len(nodes)

    async def test_terminal_ack_controls_send_batch_success(self):
        import asyncio

        from constitutional_swarm.gossip_protocol import GossipClient, GossipServer
        from constitutional_swarm.merkle_crdt import DAGNode, compute_cid

        valid_cid = compute_cid("a", "good", ())
        tampered = DAGNode(cid=valid_cid, agent_id="a", payload="bad")
        client_ws, server_ws = _c7_gossip_pair()
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        server = GossipServer(MerkleCRDT("target"), allow_unauthenticated=True)
        task = asyncio.create_task(server._handle_connection(server_ws))
        client = GossipClient(connect=lambda *_a, **_k: _C7GossipConnection(client_ws, task))
        assert await client.send_batch("memory", 0, [tampered], timeout=1.0) is False


class TestC7GossipAuthentication:
    async def test_auth_timeout_and_connection_cap_release(self):
        import asyncio

        from constitutional_swarm.gossip_protocol import GossipServer
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        server = GossipServer(
            MerkleCRDT("target"),
            secret_token="secret",
            auth_timeout_s=0.02,
            max_connections=1,
        )
        first_client, first_server = _c7_gossip_pair()
        first = asyncio.create_task(server._handle_connection(first_server))
        await asyncio.sleep(0)

        second_client, second_server = _c7_gossip_pair()
        await server._handle_connection(second_server)
        assert second_server.close_code == 4429

        await first
        assert first_server.close_code == 4408

        third_client, third_server = _c7_gossip_pair()
        await third_client.send('{"type":"auth","token":"secret"}')
        await third_client.close()
        await server._handle_connection(third_server)
        assert third_server.close_code is None

    async def test_auth_uses_constant_time_compare(self, monkeypatch):
        import hmac

        from constitutional_swarm.gossip_protocol import GossipServer
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        calls = []
        original = hmac.compare_digest

        def recording_compare(left, right):
            calls.append((left, right))
            return original(left, right)

        monkeypatch.setattr(hmac, "compare_digest", recording_compare)
        client_ws, server_ws = _c7_gossip_pair()
        await client_ws.send('{"type":"auth","token":"secret"}')
        await client_ws.close()
        server = GossipServer(MerkleCRDT("target"), secret_token="secret")
        await server._handle_connection(server_ws)
        assert calls == [(b"secret", b"secret")]


# END C7 GOSSIP


# BEGIN C7 MESH
def _c7_mesh_with_agents(**kwargs):
    from acgs_lite import Constitution
    from constitutional_swarm.mesh import ConstitutionalMesh

    kwargs.setdefault("evidence_mode", "single_operator_dev")
    if "settlement_store" in kwargs or "settlement_store_path" in kwargs:
        kwargs.setdefault("quorum", 3)
    mesh = ConstitutionalMesh(Constitution.default(), seed=17, **kwargs)
    for agent_id in ("a", "b", "c", "d"):
        mesh.register_local_signer(agent_id)
    return mesh


def _c7_other_constitution():
    from acgs_lite import Constitution, Rule

    return Constitution.from_rules(
        [
            Rule(
                id="C7-ROTATED",
                text="Reject rotated marker",
                severity="critical",
                keywords=["rotated-marker"],
            )
        ],
        name="c7-rotated",
    )


class TestC7SpectralPureReads:
    def test_synthetic_warmup_commits_all_observations_once(self) -> None:
        import importlib.util
        import random
        from pathlib import Path

        from constitutional_swarm.spectral_sphere import SpectralSphereManifold

        script_path = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "eval_swe_bench_synthetic.py"
        )
        spec = importlib.util.spec_from_file_location("c7_eval_swe_bench_synthetic", script_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class RecordingManifold(SpectralSphereManifold):
            def __init__(self) -> None:
                super().__init__(4)
                self.batch_sizes: list[int] = []

            def update_trust_batch(self, updates: list[tuple[int, int, float]]) -> None:
                self.batch_sizes.append(len(updates))
                super().update_trust_batch(updates)

        manifold = RecordingManifold()
        agents = module._make_agents(4, random.Random(2042))
        module._warmup_trust(
            agents,
            manifold,
            random.Random(1042),
            warmup_tasks_per_agent=8,
        )

        assert manifold.batch_sizes == [16]
        assert manifold.commit_generation == 1
        projected = manifold.trust_matrix
        assert manifold.project().matrix == projected
        assert manifold.trust_matrix == projected
        assert manifold.commit_generation == 1

    def test_reads_do_not_commit_projection_or_ema_state(self) -> None:
        from constitutional_swarm.spectral_sphere import SpectralSphereManifold

        manifold = SpectralSphereManifold(3)
        before = dict(vars(manifold))

        manifold.project()
        manifold.trust_matrix
        manifold.spectral_norm
        manifold.is_stable
        manifold.influence_vector(0)
        manifold.summary()

        assert vars(manifold) == before

    def test_batch_updates_commit_ema_once(self) -> None:
        from constitutional_swarm.spectral_sphere import SpectralSphereManifold

        manifold = SpectralSphereManifold(3, smoothing=0.5)
        manifold.update_trust(0, 1, 0.4)
        generation = manifold.commit_generation
        manifold.update_trust_batch([(0, 1, 0.2), (0, 2, 0.6)])

        assert manifold.commit_generation == generation + 1
        assert manifold.trust_matrix[0][1] > 0.4

    def test_constitution_only_rotation_preserves_committed_ema(self) -> None:
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.8)])
        mesh.update_trust([("a", "b", 0.2), ("a", "c", 0.6)])
        assert mesh._manifold is not None
        manifold = mesh._manifold
        generation = manifold.commit_generation
        projected = manifold.trust_matrix

        mesh.rotate_constitution(_c7_other_constitution(), preserve_trust=True)

        assert mesh._manifold is manifold
        assert mesh._manifold.commit_generation == generation
        assert mesh.trust_matrix == projected


class TestC7MeshTrustIdentity:
    def test_unregister_preserves_directional_trust_by_agent_id(self) -> None:
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.11), ("a", "c", 0.33), ("c", "a", 0.44)])

        mesh.unregister_agent("b")

        snapshot = mesh.raw_trust_snapshot()
        assert snapshot.value("a", "c") == 0.33
        assert snapshot.value("c", "a") == 0.44

    def test_archive_restore_is_directional_and_round_based(self) -> None:
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.4), ("b", "a", 0.8)])
        mesh.unregister_agent("a")
        mesh.advance_trust_rounds(2)
        mesh.register_local_signer("a")

        snapshot = mesh.raw_trust_snapshot()
        factor = (1.0 - mesh._TRUST_DECAY_RATE) ** 2
        assert snapshot.value("a", "b") == 0.4 * factor
        assert snapshot.value("b", "a") == 0.8 * factor

    def test_repeated_middle_index_churn_never_reassigns_trust(self) -> None:
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.11), ("a", "c", 0.33), ("c", "a", 0.44)])

        for _ in range(3):
            mesh.unregister_agent("b")
            snapshot = mesh.raw_trust_snapshot()
            assert snapshot.value("a", "c") == 0.33
            assert snapshot.value("c", "a") == 0.44
            mesh.register_local_signer("b")

        snapshot = mesh.raw_trust_snapshot()
        assert snapshot.value("a", "b") == 0.11
        assert snapshot.value("a", "c") == 0.33
        assert snapshot.value("c", "a") == 0.44

    def test_archive_waits_until_both_departed_agents_return(self) -> None:
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.4), ("b", "a", 0.8)])
        mesh.unregister_agent("a")
        mesh.unregister_agent("b")

        mesh.register_local_signer("a")
        assert "a" in mesh._trust_archive
        mesh.register_local_signer("b")

        snapshot = mesh.raw_trust_snapshot()
        assert snapshot.value("a", "b") == 0.4
        assert snapshot.value("b", "a") == 0.8
        assert "a" not in mesh._trust_archive


class TestC7MeshConstitutionBoundaries:
    def test_historical_settlement_does_not_block_rotated_restart(self, tmp_path) -> None:
        from constitutional_swarm.mesh import ConstitutionalMesh

        path = tmp_path / "settlements.jsonl"
        writer = _c7_mesh_with_agents(settlement_store_path=path)
        settled = writer.full_validation("a", "safe output", "artifact")

        reader = ConstitutionalMesh(
            _c7_other_constitution(), quorum=3, settlement_store_path=path
        )

        try:
            reader.get_result(settled.assignment_id)
        except KeyError:
            pass
        else:
            raise AssertionError("historical settlement leaked into active constitution")

    def test_stale_assignment_is_rejected_before_vote_mutation(self) -> None:
        import pytest

        from constitutional_swarm.mesh import MeshSnapshotStaleError

        mesh = _c7_mesh_with_agents()
        assignment = mesh.request_validation("a", "safe output", "artifact")
        voter = assignment.peers[0]
        mesh.rotate_constitution(_c7_other_constitution())

        with pytest.raises(MeshSnapshotStaleError):
            mesh.sign_vote(assignment.assignment_id, voter, approved=True)
        assert mesh._votes[assignment.assignment_id] == []

    def test_every_pending_operation_fails_closed_after_rotation(self) -> None:
        import pytest

        from constitutional_swarm.mesh import MeshSnapshotStaleError

        mesh = _c7_mesh_with_agents()
        assignment = mesh.request_validation("a", "safe output", "artifact")
        voter = assignment.peers[0]
        signature = mesh.sign_vote(assignment.assignment_id, voter, approved=True)
        mesh.rotate_constitution(_c7_other_constitution())

        operations = (
            lambda: mesh.get_result(assignment.assignment_id),
            lambda: mesh.validate_and_vote(assignment.assignment_id, voter),
            lambda: mesh.prepare_remote_vote(assignment.assignment_id, voter),
            lambda: mesh.submit_vote(
                assignment.assignment_id,
                voter,
                approved=True,
                signature=signature,
            ),
            lambda: mesh.settle(assignment.assignment_id),
        )
        for operation in operations:
            with pytest.raises(MeshSnapshotStaleError):
                operation()
        assert mesh._votes[assignment.assignment_id] == []

    def test_fresh_work_reclaims_stale_pending_capacity(self) -> None:
        mesh = _c7_mesh_with_agents(max_pending_assignments=1)
        stale = mesh.request_validation("a", "safe output", "old-artifact")
        mesh.rotate_constitution(_c7_other_constitution())

        fresh = mesh.request_validation("a", "safe output", "new-artifact")

        assert stale.assignment_id not in mesh._assignments
        assert stale.assignment_id not in mesh._votes
        assert fresh.assignment_id in mesh._assignments


class TestC7MeshCapacity:
    def test_failed_reconciliation_preserves_existing_frozen_result(self) -> None:
        import pytest

        from constitutional_swarm.mesh import SettlementPersistenceError

        class FailingStore:
            def __init__(self) -> None:
                self.pending = {}

            def append(self, record) -> None:
                raise OSError("phase 2 remains unavailable")

            def load_all(self):
                return []

            def mark_pending(self, record) -> None:
                self.pending[str(record.assignment["assignment_id"])] = record

            def clear_pending(self, assignment_id: str) -> None:
                self.pending.pop(assignment_id, None)

            def load_pending(self):
                return list(self.pending.values())

            def pending_count(self) -> int:
                return len(self.pending)

            def describe(self):
                return {"backend": "failing-test-store"}

        store = FailingStore()
        mesh = _c7_mesh_with_agents(settlement_store=store)
        with pytest.raises(SettlementPersistenceError):
            mesh.full_validation("a", "safe output", "artifact")

        assignment_id = next(iter(mesh._final_results))
        frozen_result = mesh.get_result(assignment_id)
        frozen_votes = tuple(mesh._votes[assignment_id])

        report = mesh.reconcile_pending_settlements()

        assert report.failed == 1
        assert mesh.get_result(assignment_id) is frozen_result
        assert tuple(mesh._votes[assignment_id]) == frozen_votes

    def test_positive_quorum_and_peer_counts_are_required(self) -> None:
        import pytest

        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh

        for kwargs in (
            {"peers_per_validation": 0},
            {"peers_per_validation": -1},
            {"quorum": 0},
            {"quorum": -1},
        ):
            with pytest.raises(ValueError):
                ConstitutionalMesh(Constitution.default(), **kwargs)

    def test_pending_capacity_rejects_without_evicting_inflight_work(self) -> None:
        import pytest

        from constitutional_swarm.mesh import MeshCapacityError

        mesh = _c7_mesh_with_agents(max_pending_assignments=1)
        first = mesh.request_validation("a", "first", "first")

        with pytest.raises(MeshCapacityError):
            mesh.request_validation("a", "second", "second")
        assert set(mesh._assignments) == {first.assignment_id}

    def test_settlement_compacts_pending_state_and_bounds_history(self) -> None:
        mesh = _c7_mesh_with_agents(max_pending_assignments=1, max_settled_results=1)
        first = mesh.full_validation("a", "first", "first")
        second = mesh.full_validation("a", "second", "second")

        assert first.assignment_id not in mesh._assignments
        assert first.assignment_id not in mesh._votes
        assert mesh._assignments[second.assignment_id].content == ""
        assert second.assignment_id not in mesh._votes
        assert second.assignment_id not in mesh._settled_voters
        assert len(mesh._final_results) == 1
        assert mesh.summary()["total_validations"] == 2

    def test_startup_cache_bound_keeps_lifetime_totals(self, tmp_path) -> None:
        from constitutional_swarm.mesh import ConstitutionalMesh

        path = tmp_path / "settlements.jsonl"
        writer = _c7_mesh_with_agents(settlement_store_path=path)
        settled = [
            writer.full_validation("a", f"output-{index}", f"artifact-{index}")
            for index in range(3)
        ]

        reader = ConstitutionalMesh(
            writer._constitution,
            quorum=3,
            settlement_store_path=path,
            max_settled_results=1,
            vote_registry=writer.vote_registry,
            assigner_private_key=writer._assigner_private_key,
            assigner_id=writer.assigner_id,
            evidence_mode="single_operator_dev",
        )

        assert len(reader._final_results) == 1
        assert reader.summary()["total_validations"] == 3
        assert reader.summary()["settled"] == 3
        assert next(reversed(reader._final_results)) == settled[-1].assignment_id

    def test_shadow_metric_history_is_bounded(self) -> None:
        mesh = _c7_mesh_with_agents(
            use_manifold=True,
            manifold_type="birkhoff",
            shadow_spectral=True,
            max_shadow_metrics=1,
        )
        mesh.full_validation("a", "first", "first")
        mesh.full_validation("a", "second", "second")

        assert len(mesh._shadow_metrics) == 1
# END C7 MESH

# BEGIN C7 RUNTIME

def _c7_runtime_dna(**kwargs):
    from acgs_lite import Rule
    from constitutional_swarm.dna import AgentDNA

    return AgentDNA.from_rules(
        [Rule(id="C7", text="Reject forbidden_marker", severity="critical",
              keywords=["forbidden_marker"])], **kwargs
    )


class TestC7Runtime:
    def test_all_argument_forms_are_governed(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        dna = _c7_runtime_dna()
        calls = []

        @dna.govern
        def function(first, second="safe", *items, note="safe", **extras):
            calls.append(True)
            return "safe"

        assert function("safe", "safe", "safe", note="safe", extra="safe") == "safe"
        for args, kwargs in [
            (("safe", "forbidden_marker"), {}),
            (("safe", "safe", "forbidden_marker"), {}),
            (("safe",), {"note": "forbidden_marker"}),
            (("safe",), {"extra": "forbidden_marker"}),
            ((), {"first": "safe", "second": "forbidden_marker"}),
        ]:
            with pytest.raises(ConstitutionalViolationError):
                function(*args, **kwargs)
        assert len(calls) == 1

    def test_bound_defaults_are_governed(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        @_c7_runtime_dna().govern
        def function(first="safe", second="forbidden_marker"):
            return "safe"

        with pytest.raises(ConstitutionalViolationError):
            function()

    def test_bound_argument_payload_is_complete_and_named(self):
        import json

        dna = _c7_runtime_dna()
        seen = []
        original = dna.validate

        def recording(value):
            seen.append(value)
            return original(value)

        dna.validate = recording

        @dna.govern
        def function(first, second="default", *items, note="named", **extras):
            return None

        assert function("one", "two", "three", flag="four") is None
        assert json.loads(seen[0]) == {
            "extras": {"flag": "four"},
            "first": "one",
            "items": ["three"],
            "note": "named",
            "second": "two",
        }

    def test_method_arguments_and_receiver_identity(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        dna = _c7_runtime_dna()

        class Worker:
            def __repr__(self):
                return "forbidden_marker receiver"

            @dna.govern
            def method(self, prompt, later="safe"):
                return "safe"

            @classmethod
            @dna.govern
            def class_method(cls, prompt):
                return "safe"

            @staticmethod
            @dna.govern
            def static_method(self):
                return "safe"

        assert Worker().method("safe") == "safe"
        assert Worker.class_method("safe") == "safe"
        with pytest.raises(ConstitutionalViolationError):
            Worker().method("safe", "forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            Worker.class_method("forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            Worker.static_method("forbidden_marker")

        @dna.govern
        def free_function(self, later="safe"):
            return "safe"

        with pytest.raises(ConstitutionalViolationError):
            free_function("forbidden_marker")

    def test_receiver_identity_cannot_be_forged_with_wrapped(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        def free_function(self):
            return "safe"

        governed = _c7_runtime_dna().govern(free_function)

        class ForgedReceiver:
            def __repr__(self):
                return "forbidden_marker"

            def decoy(self):
                return None

        ForgedReceiver.decoy.__wrapped__ = free_function
        with pytest.raises(ConstitutionalViolationError):
            governed(ForgedReceiver())

    async def test_async_inputs_and_outputs(self):
        import pytest
        from dataclasses import dataclass
        from acgs_lite import ConstitutionalViolationError

        dna = _c7_runtime_dna()

        @dataclass
        class Output:
            value: str

        @dna.govern
        async def function(first, *, later="safe"):
            return "safe"

        @dna.govern
        async def returns_object(first):
            return Output("forbidden_marker")

        assert await function("safe") == "safe"
        with pytest.raises(ConstitutionalViolationError):
            await function("safe", later="forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            await returns_object("safe")

    def test_structured_and_repr_outputs_cannot_bypass(self):
        import pytest
        from dataclasses import dataclass
        from acgs_lite import ConstitutionalViolationError

        @dataclass
        class Output:
            value: str

        class ReprOutput:
            def __repr__(self):
                return "forbidden_marker"

        class StrOutput:
            def __str__(self):
                return "forbidden_marker"

        for result in [Output("forbidden_marker"), ReprOutput(), StrOutput(),
                       {"nested": Output("forbidden_marker")}]:
            def function(prompt):
                return result
            governed = _c7_runtime_dna().govern(function)
            with pytest.raises(ConstitutionalViolationError):
                governed("safe")

        assert _c7_runtime_dna(validate_output=False).govern(
            lambda prompt: Output("forbidden_marker")
        )("safe") == Output("forbidden_marker")
        assert _c7_runtime_dna().govern(lambda prompt: None)("safe") is None

    def test_custom_str_cannot_suppress_sync_output_validation(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        class EmptyStringOutput:
            def __str__(self):
                return ""

            def __repr__(self):
                return "EmptyStringOutput(secret='forbidden_marker')"

        class BenignStringOutput:
            def __str__(self):
                return "safe"

            def __repr__(self):
                return "BenignStringOutput(secret='forbidden_marker')"

        for result in (EmptyStringOutput(), BenignStringOutput()):
            with pytest.raises(ConstitutionalViolationError):
                _c7_runtime_dna().govern(lambda prompt: result)("safe")

    async def test_custom_str_cannot_suppress_async_output_validation(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        class EmptyStringOutput:
            def __str__(self):
                return ""

            def __repr__(self):
                return "EmptyStringOutput(secret='forbidden_marker')"

        class BenignStringOutput:
            def __str__(self):
                return "safe"

            def __repr__(self):
                return "BenignStringOutput(secret='forbidden_marker')"

        for result in (EmptyStringOutput(), BenignStringOutput()):
            async def function(prompt):
                return result

            with pytest.raises(ConstitutionalViolationError):
                await _c7_runtime_dna().govern(function)("safe")

    def test_single_string_and_unicode_content_preserved(self):
        from acgs_lite import Rule, ConstitutionalViolationError
        from constitutional_swarm.dna import AgentDNA
        import pytest

        dna = AgentDNA.from_rules([Rule(
            id="unicode", text="Reject 敏感内容", severity="critical", keywords=["敏感内容"]
        )])
        seen = []
        original = dna.validate

        def recording(value):
            seen.append(value)
            return original(value)

        dna.validate = recording
        assert dna.govern(lambda prompt: "safe")("original text") == "safe"
        assert seen[0] == "original text"
        with pytest.raises(ConstitutionalViolationError):
            dna.govern(lambda first, later: "safe")("safe", {"value": "敏感内容"})

    def test_governance_serialization_failures_are_loud(self):
        import pytest

        class BrokenRepr:
            def __repr__(self):
                raise RuntimeError("cannot represent governed value")

        governed_input = _c7_runtime_dna().govern(
            lambda first, later: "safe"
        )
        with pytest.raises(RuntimeError, match="cannot represent governed value"):
            governed_input("safe", BrokenRepr())

        governed_output = _c7_runtime_dna().govern(
            lambda prompt: BrokenRepr()
        )
        with pytest.raises(RuntimeError, match="cannot represent governed value"):
            governed_output("safe")

    def test_executor_owns_nested_state_at_every_boundary(self):
        from constitutional_swarm.artifact import ArtifactStore
        from constitutional_swarm.capability import CapabilityRegistry
        from constitutional_swarm.execution import ExecutionStatus
        from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

        node = TaskNode(node_id="root", metadata={"nested": {"values": ["original"]}})
        dag = TaskDAG(dag_id="c7-ownership").add_node(node)
        first = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        second = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        first.load_dag(dag)
        second.load_dag(dag)
        assert node.status == ExecutionStatus.BLOCKED
        assert first.dag.nodes["root"].status == ExecutionStatus.READY
        node.metadata["nested"]["values"].append("caller")
        assert first.dag.nodes["root"].metadata["nested"]["values"] == ["original"]
        first.dag.nodes["root"].metadata["nested"]["values"].append("snapshot")
        first.available_tasks("worker")[0].metadata["nested"]["values"].append("available")
        assert first.dag.nodes["root"].metadata["nested"]["values"] == ["original"]
        assert second.dag.nodes["root"].metadata["nested"]["values"] == ["original"]

    def test_executor_rejects_metadata_it_cannot_own(self):
        import pytest
        from constitutional_swarm.artifact import ArtifactStore
        from constitutional_swarm.capability import CapabilityRegistry
        from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

        class SharedOnly:
            def __deepcopy__(self, memo):
                raise RuntimeError("metadata ownership transfer failed")

        dag = TaskDAG(dag_id="c7-copy-failure").add_node(
            TaskNode(node_id="root", metadata={"nested": SharedOnly()})
        )
        executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        with pytest.raises(TypeError, match="unsupported task metadata type"):
            executor.load_dag(dag)

    def test_executor_rejects_metadata_that_forges_deepcopy(self):
        import pytest
        from constitutional_swarm.artifact import ArtifactStore
        from constitutional_swarm.capability import CapabilityRegistry
        from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

        class SharedMutable:
            def __init__(self):
                self.values = ["original"]

            def __deepcopy__(self, memo):
                return self

        shared = SharedMutable()
        dag = TaskDAG(dag_id="c7-copy-alias").add_node(
            TaskNode(node_id="root", metadata={"nested": shared})
        )
        executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        with pytest.raises(TypeError, match="unsupported task metadata type"):
            executor.load_dag(dag)

    def test_frozen_metadata_copy_bypasses_construction_hooks(self):
        from dataclasses import dataclass

        from constitutional_swarm.artifact import ArtifactStore
        from constitutional_swarm.capability import CapabilityRegistry
        from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

        external = ["caller-owned"]
        hooks = []

        @dataclass(frozen=True)
        class HookedFrozen:
            values: list[str]

            def __post_init__(self):
                hooks.append("called")
                object.__setattr__(self, "values", external)

        value = HookedFrozen(["ignored"])
        hooks.clear()
        dag = TaskDAG(dag_id="c7-frozen-hook").add_node(
            TaskNode(node_id="root", metadata={"value": value})
        )
        executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        executor.load_dag(dag)

        assert hooks == []
        external.append("mutated-after-load")
        assert executor.dag.nodes["root"].metadata["value"].values == [
            "caller-owned"
        ]

    def test_executor_canonicalizes_outer_task_node_ownership(self):
        from dataclasses import dataclass

        from constitutional_swarm.artifact import ArtifactStore
        from constitutional_swarm.capability import CapabilityRegistry
        from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

        external_metadata = {"nested": {"values": ["caller-owned"]}}
        dependencies = []
        capabilities = []
        hooks = []

        @dataclass
        class HookedNode(TaskNode):
            def __post_init__(self):
                hooks.append("called")
                self.metadata = external_metadata

        node = HookedNode(
            node_id="root",
            depends_on=dependencies,
            required_capabilities=capabilities,
        )
        hooks.clear()
        executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
        executor.load_dag(TaskDAG(dag_id="c7-node-hook").add_node(node))

        assert hooks == []
        external_metadata["nested"]["values"].append("mutated-after-load")
        dependencies.append("caller-dependency")
        capabilities.append("caller-capability")
        snapshot = executor.dag
        assert type(snapshot.nodes["root"]) is TaskNode
        assert snapshot.nodes["root"].metadata["nested"]["values"] == [
            "caller-owned"
        ]
        assert snapshot.nodes["root"].depends_on == ()
        assert snapshot.nodes["root"].required_capabilities == ()


    def test_aliased_method_receiver_is_excluded_by_identity(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        def original_method(self, prompt):
            return "safe"

        class Worker:
            alias = _c7_runtime_dna().govern(original_method)

            def __repr__(self):
                return "forbidden_marker receiver"

        class Child(Worker):
            pass

        assert Worker().alias("safe") == "safe"
        assert Child().alias("safe") == "safe"
        with pytest.raises(ConstitutionalViolationError):
            Child().alias("forbidden_marker")

# END C7 RUNTIME


class TestC7ResumeMeshReview:
    _vote_registries = {}
    _assigner_credentials = {}

    class _CapturingStore:
        def __init__(self, *, fail_append=False, block_mark_pending=False, block_append=False):
            import threading

            self.fail_append = fail_append
            self.block_mark_pending = block_mark_pending
            self.block_append = block_append
            self.pending = {}
            self.settled = {}
            self.mark_pending_entered = threading.Event()
            self.append_entered = threading.Event()
            self.release = threading.Event()

        def append(self, record):
            assignment_id = str(record.assignment["assignment_id"])
            if self.block_append:
                self.append_entered.set()
                assert self.release.wait(5)
            if self.fail_append:
                raise OSError("phase 2 unavailable")
            self.settled[assignment_id] = record

        def load_all(self):
            return list(self.settled.values())

        def mark_pending(self, record):
            assignment_id = str(record.assignment["assignment_id"])
            self.pending[assignment_id] = record
            if self.block_mark_pending:
                self.mark_pending_entered.set()
                assert self.release.wait(5)

        def clear_pending(self, assignment_id):
            self.pending.pop(assignment_id, None)

        def load_pending(self):
            return list(self.pending.values())

        def pending_count(self):
            return len(self.pending)

        def describe(self):
            return {"backend": "c7-review-store"}

    @classmethod
    def _pending_record(cls, constitution, artifact_id):
        import pytest
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from constitutional_swarm.mesh import ConstitutionalMesh, SettlementPersistenceError
        from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

        store = cls._CapturingStore(fail_append=True)
        registry = VoteSignerRegistry()
        assigner_private_key = Ed25519PrivateKey.generate()
        assigner_id = "c7-test-assigner"
        registry.register(
            assigner_id,
            assigner_private_key.public_key(),
            roles={"assigner"},
        )
        mesh = ConstitutionalMesh(
            constitution,
            seed=917,
            quorum=3,
            settlement_store=store,
            vote_registry=registry,
            assigner_private_key=assigner_private_key,
            assigner_id=assigner_id,
            evidence_mode="single_operator_dev",
        )
        for agent_id in ("a", "b", "c", "d"):
            mesh.register_local_signer(agent_id)
        with pytest.raises(SettlementPersistenceError):
            mesh.full_validation("a", "safe output", artifact_id)
        assert len(store.pending) == 1
        record = next(iter(store.pending.values()))
        assignment_id = str(record.assignment["assignment_id"])
        cls._vote_registries[assignment_id] = registry
        cls._assigner_credentials[assignment_id] = (
            mesh._assigner_private_key,
            mesh.assigner_id,
        )
        return record

    @classmethod
    def _registry_for(cls, record):
        return cls._vote_registries[str(record.assignment["assignment_id"])]

    @classmethod
    def _assigner_kwargs_for(cls, record):
        private_key, assigner_id = cls._assigner_credentials[
            str(record.assignment["assignment_id"])
        ]
        return {
            "assigner_private_key": private_key,
            "assigner_id": assigner_id,
        }

    @staticmethod
    def _store(kind, path):
        from constitutional_swarm.settlement_store import (
            JSONLSettlementStore,
            SQLiteSettlementStore,
        )

        if kind == "jsonl":
            return JSONLSettlementStore(path.with_suffix(".jsonl"))
        return SQLiteSettlementStore(path.with_suffix(".db"))

    def test_reconciliation_report_preserves_legacy_positional_fields(self):
        from constitutional_swarm.mesh import ReconciliationReport

        report = ReconciliationReport(1, 2, 3, 4, ["legacy-error"])

        assert report.attempted == 1
        assert report.settled == 2
        assert report.skipped_recovered == 3
        assert report.failed == 4
        assert report.errors == ["legacy-error"]
        assert report.skipped_constitution == 0

    def test_settle_rotation_fence_rejects_away_and_back_same_hash(self, monkeypatch):
        import threading

        from constitutional_swarm.mesh import MeshSnapshotStaleError

        store = self._CapturingStore(block_mark_pending=True)
        mesh = _c7_mesh_with_agents(settlement_store=store)
        original_constitution = mesh._constitution
        assignment = mesh.request_validation("a", "safe output", "settle-race")
        monkeypatch.setattr(mesh, "_maybe_finalize_result", lambda _assignment_id: False)
        for voter in assignment.peers:
            mesh.validate_and_vote(assignment.assignment_id, voter)

        errors = []

        def settle():
            try:
                mesh.settle(assignment.assignment_id)
            except Exception as exc:  # captured for assertion in the parent thread
                errors.append(exc)

        thread = threading.Thread(target=settle)
        thread.start()
        assert store.mark_pending_entered.wait(5)
        mesh.rotate_constitution(_c7_other_constitution())
        mesh.rotate_constitution(original_constitution)
        store.release.set()
        thread.join(5)

        assert not thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], MeshSnapshotStaleError)
        assert assignment.assignment_id not in mesh._final_results
        assert assignment.assignment_id in store.pending
        assert store.settled == {}

    def test_reconciliation_rotation_fence_never_installs_stale_active_result(self):
        import threading

        import pytest
        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh

        constitution = Constitution.default()
        record = self._pending_record(constitution, "reconcile-race")
        assignment_id = str(record.assignment["assignment_id"])
        store = self._CapturingStore(block_append=True)
        store.mark_pending(record)
        mesh = ConstitutionalMesh(
            constitution,
            seed=919,
            quorum=3,
            settlement_store=store,
            auto_reconcile=False,
            vote_registry=self._registry_for(record),
            **self._assigner_kwargs_for(record),
            evidence_mode="single_operator_dev",
        )
        reports = []

        thread = threading.Thread(target=lambda: reports.append(mesh.reconcile_pending_settlements()))
        thread.start()
        assert store.append_entered.wait(5)
        mesh.rotate_constitution(_c7_other_constitution())
        store.release.set()
        thread.join(5)

        assert not thread.is_alive()
        assert len(reports) == 1
        assert reports[0].attempted == 1
        assert reports[0].settled == 0
        assert reports[0].skipped_constitution == 1
        assert reports[0].failed == 0
        assert assignment_id in store.pending
        assert assignment_id in store.settled
        with pytest.raises(KeyError):
            mesh.get_result(assignment_id)

    def test_jsonl_and_sqlite_load_only_current_records_from_mixed_history(self, tmp_path):
        import pytest
        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh

        current = Constitution.default()
        current_record = self._pending_record(current, "mixed-current")
        historical_record = self._pending_record(
            _c7_other_constitution(), "mixed-historical"
        )
        current_id = str(current_record.assignment["assignment_id"])
        historical_id = str(historical_record.assignment["assignment_id"])

        for kind in ("jsonl", "sqlite"):
            store = self._store(kind, tmp_path / f"mixed-{kind}")
            store.append(historical_record)
            store.append(current_record)
            mesh = ConstitutionalMesh(
                current,
                quorum=3,
                settlement_store=store,
                auto_reconcile=False,
                vote_registry=self._registry_for(current_record),
                **self._assigner_kwargs_for(current_record),
                evidence_mode="single_operator_dev",
            )

            assert mesh.get_result(current_id).constitutional_hash == current.hash
            with pytest.raises(KeyError):
                mesh.get_result(historical_id)

    def test_jsonl_and_sqlite_fail_closed_on_every_inconsistent_hash_tag(self, tmp_path):
        from dataclasses import replace

        import pytest
        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh

        constitution = Constitution.default()
        record = self._pending_record(constitution, "tag-mismatch")
        mismatches = {
            "record": replace(record, constitutional_hash="foreign"),
            "assignment": replace(
                record,
                assignment={**record.assignment, "constitutional_hash": "foreign"},
            ),
            "result": replace(
                record,
                result={**record.result, "constitutional_hash": "foreign"},
            ),
            "proof": replace(
                record,
                result={
                    **record.result,
                    "proof": {**record.result["proof"], "constitutional_hash": "foreign"},
                },
            ),
        }

        for kind in ("jsonl", "sqlite"):
            for tag, mismatched in mismatches.items():
                store = self._store(kind, tmp_path / f"mismatch-{kind}-{tag}")
                store.append(mismatched)
                with pytest.raises(ValueError, match="constitutional hash"):
                    ConstitutionalMesh(
                        constitution,
                        quorum=3,
                        settlement_store=store,
                        auto_reconcile=False,
                    )

    def test_foreign_pending_is_counted_skipped_and_left_untouched(self):
        import pytest
        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh

        record = self._pending_record(_c7_other_constitution(), "foreign-pending")
        assignment_id = str(record.assignment["assignment_id"])
        store = self._CapturingStore()
        store.mark_pending(record)
        mesh = ConstitutionalMesh(
            Constitution.default(),
            quorum=3,
            settlement_store=store,
            auto_reconcile=False,
        )

        report = mesh.reconcile_pending_settlements()

        assert report.attempted == 0
        assert report.settled == 0
        assert report.skipped_constitution == 1
        assert report.failed == 0
        assert store.pending_count() == 1
        assert store.load_all() == []
        with pytest.raises(KeyError):
            mesh.get_result(assignment_id)

    def test_real_stores_retry_matching_phase_two_after_rotate_away_and_back(
        self, tmp_path
    ):
        import threading

        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh
        from constitutional_swarm.settlement_store import (
            JSONLSettlementStore,
            SQLiteSettlementStore,
        )

        class BlockingJSONLStore(JSONLSettlementStore):
            def __init__(self, path):
                super().__init__(path)
                self.append_entered = threading.Event()
                self.release = threading.Event()
                self.block_once = True

            def append(self, record):
                super().append(record)
                if self.block_once:
                    self.block_once = False
                    self.append_entered.set()
                    assert self.release.wait(5)

        class BlockingSQLiteStore(SQLiteSettlementStore):
            def __init__(self, path):
                super().__init__(path)
                self.append_entered = threading.Event()
                self.release = threading.Event()
                self.block_once = True

            def append(self, record):
                super().append(record)
                if self.block_once:
                    self.block_once = False
                    self.append_entered.set()
                    assert self.release.wait(5)

        constitution = Constitution.default()
        for kind, store_type, suffix in (
            ("jsonl", BlockingJSONLStore, ".jsonl"),
            ("sqlite", BlockingSQLiteStore, ".db"),
        ):
            record = self._pending_record(constitution, f"idempotent-{kind}")
            assignment_id = str(record.assignment["assignment_id"])
            store = store_type(tmp_path / f"idempotent-{kind}{suffix}")
            store.mark_pending(record)
            mesh = ConstitutionalMesh(
                constitution,
                seed=923,
                quorum=3,
                settlement_store=store,
                auto_reconcile=False,
                vote_registry=self._registry_for(record),
                **self._assigner_kwargs_for(record),
                evidence_mode="single_operator_dev",
            )
            reports = []

            thread = threading.Thread(
                target=lambda: reports.append(mesh.reconcile_pending_settlements())
            )
            thread.start()
            assert store.append_entered.wait(5)
            mesh.rotate_constitution(_c7_other_constitution())
            store.release.set()
            thread.join(5)

            assert not thread.is_alive()
            assert reports[0].settled == 0
            assert reports[0].skipped_constitution == 1
            assert store.pending_count() == 1
            assert len(store.load_all()) == 1

            mesh.rotate_constitution(constitution)
            retry = mesh.reconcile_pending_settlements()

            assert retry.attempted == 1
            assert retry.settled == 1
            assert retry.failed == 0
            assert retry.errors == []
            assert store.pending_count() == 0
            assert len(store.load_all()) == 1
            assert mesh.get_result(assignment_id).constitutional_hash == constitution.hash

    def test_retry_rejects_conflicting_durable_snapshot(self, tmp_path):
        from dataclasses import replace

        import pytest
        from acgs_lite import Constitution
        from constitutional_swarm.mesh import ConstitutionalMesh
        from constitutional_swarm.settlement_store import JSONLSettlementStore

        constitution = Constitution.default()
        pending = self._pending_record(constitution, "durable-conflict")
        assignment_id = str(pending.assignment["assignment_id"])
        store = JSONLSettlementStore(tmp_path / "durable-conflict.jsonl")
        mesh = ConstitutionalMesh(
            constitution,
            quorum=3,
            settlement_store=store,
            auto_reconcile=False,
            vote_registry=self._registry_for(pending),
            **self._assigner_kwargs_for(pending),
            evidence_mode="single_operator_dev",
        )
        conflicting = replace(
            pending,
            assignment={**pending.assignment, "is_recovered": True},
            result={**pending.result, "votes_for": int(pending.result["votes_for"]) + 1},
            is_recovered=True,
            receipt_digest="0" * 64,
            votes=(),
        )
        store.append(conflicting)
        store.mark_pending(pending)

        report = mesh.reconcile_pending_settlements()

        assert report.attempted == 1
        assert report.settled == 0
        assert report.failed == 1
        assert len(report.errors) == 1
        assert "conflicts with pending snapshot" in report.errors[0]
        assert store.pending_count() == 1
        with pytest.raises(KeyError):
            mesh.get_result(assignment_id)


class TestC7ResumeRuntimeReview:
    def test_direct_call_cannot_spoof_a_bound_receiver(self):
        import pytest
        from acgs_lite import ConstitutionalViolationError

        def free_function(self):
            return "safe"

        governed = _c7_runtime_dna().govern(free_function)

        class ForgedReceiver:
            alias = governed

            def __repr__(self):
                return "forbidden_marker"

        with pytest.raises(ConstitutionalViolationError):
            governed(ForgedReceiver())
        assert ForgedReceiver().alias() == "safe"

    async def test_descriptor_binding_preserves_callable_kinds(self):
        import inspect

        import pytest
        from acgs_lite import ConstitutionalViolationError

        dna = _c7_runtime_dna()

        class Worker:
            def __repr__(self):
                return "forbidden_marker receiver"

            @dna.govern
            def method(self, prompt):
                return prompt

            @classmethod
            @dna.govern
            def class_method(cls, prompt):
                return prompt

            @staticmethod
            @dna.govern
            def static_method(prompt):
                return prompt

            @dna.govern
            async def async_method(self, prompt):
                return prompt

        assert Worker().method("safe") == "safe"
        assert Worker.class_method("safe") == "safe"
        assert Worker.static_method("safe") == "safe"
        assert await Worker().async_method("safe") == "safe"
        assert tuple(inspect.signature(Worker().method).parameters) == ("prompt",)
        assert tuple(inspect.signature(Worker().async_method).parameters) == ("prompt",)
        assert inspect.iscoroutinefunction(Worker.async_method)
        assert inspect.iscoroutinefunction(Worker().async_method)
        with pytest.raises(ConstitutionalViolationError):
            Worker().method("forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            Worker.class_method("forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            Worker.static_method("forbidden_marker")
        with pytest.raises(ConstitutionalViolationError):
            await Worker().async_method("forbidden_marker")

    def test_dataclass_copy_hook_cannot_hide_sync_input_or_output(self):
        from dataclasses import dataclass

        import pytest
        from acgs_lite import ConstitutionalViolationError

        class Sneaky:
            def __repr__(self):
                return "forbidden_marker"

            def __deepcopy__(self, memo):
                return "safe"

        @dataclass
        class Payload:
            value: object

        dna = _c7_runtime_dna()
        governed_input = dna.govern(lambda first, later: "safe")
        governed_output = dna.govern(lambda prompt: Payload(Sneaky()))

        with pytest.raises(ConstitutionalViolationError):
            governed_input("safe", Payload(Sneaky()))
        with pytest.raises(ConstitutionalViolationError):
            governed_output("safe")

    async def test_dataclass_copy_hook_cannot_hide_async_input_or_output(self):
        from dataclasses import dataclass

        import pytest
        from acgs_lite import ConstitutionalViolationError

        class Sneaky:
            def __repr__(self):
                return "forbidden_marker"

            def __deepcopy__(self, memo):
                return "safe"

        @dataclass
        class Payload:
            value: object

        dna = _c7_runtime_dna()

        @dna.govern
        async def governed_input(first, later):
            return "safe"

        @dna.govern
        async def governed_output(prompt):
            return Payload(Sneaky())

        with pytest.raises(ConstitutionalViolationError):
            await governed_input("safe", Payload(Sneaky()))
        with pytest.raises(ConstitutionalViolationError):
            await governed_output("safe")

    def test_structural_serialization_rejects_cycles(self):
        import pytest

        cyclic = []
        cyclic.append(cyclic)
        governed = _c7_runtime_dna().govern(lambda first, later: "safe")

        with pytest.raises(ValueError, match="cyclic"):
            governed("safe", cyclic)

    async def test_malformed_parent_cid_is_rejected_before_merge(self):
        import asyncio
        import json

        from constitutional_swarm.gossip_protocol import GossipServer, encode_batch
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        malformed_parent = "not-a-sha256-cid"
        cid = compute_cid("attacker", "payload", (malformed_parent,))
        poisoned = DAGNode(
            cid=cid,
            agent_id="attacker",
            payload="payload",
            parent_cids=(malformed_parent,),
        )
        target = MerkleCRDT("target")
        client_ws, server_ws = _c7_gossip_pair()
        server = GossipServer(target, allow_unauthenticated=True)
        task = asyncio.create_task(server._handle_connection(server_ws))

        await client_ws.send(encode_batch([poisoned]))
        response = json.loads(await client_ws.recv())
        if not task.done():
            await client_ws.close()
        await task

        assert response["type"] == "error"
        assert "parent_cids" in response["message"]
        assert target.size == 0


class TestC7DNADefaultRepresentationHardening:
    def test_default_repr_instances_fail_closed_for_input_and_output(self):
        import pytest

        class DictPayload:
            def __init__(self, value):
                self.value = value

        class SlotsPayload:
            __slots__ = ("value",)

            def __init__(self, value):
                self.value = value

        class DefaultBase:
            pass

        class DefaultSubclass(DefaultBase):
            pass

        class AliasedDefault:
            __repr__ = object.__repr__
            __str__ = object.__str__

        dna = _c7_runtime_dna()
        governed_input = dna.govern(lambda first, later: "safe")
        values = (
            DictPayload("forbidden_marker"),
            SlotsPayload("forbidden_marker"),
            DefaultSubclass(),
            AliasedDefault(),
        )

        for value in values:
            with pytest.raises(TypeError, match="unsupported governed value type"):
                governed_input("safe", value)
            with pytest.raises(TypeError, match="unsupported governed value type"):
                dna.govern(lambda prompt: value)("safe")

    def test_opaque_default_repr_objects_fail_closed_on_input_and_output(self):
        import pytest

        class OpaquePayload:
            __slots__ = ()

        dna = _c7_runtime_dna()
        governed_input = dna.govern(lambda first, later: "safe")
        governed_output = dna.govern(lambda prompt: OpaquePayload())

        with pytest.raises(TypeError, match="unsupported governed value type"):
            governed_input("safe", OpaquePayload())
        with pytest.raises(TypeError, match="unsupported governed value type"):
            governed_output("safe")

    def test_default_repr_structural_traversal_is_bounded(self):
        import pytest

        value = []
        for _ in range(80):
            value = [value]

        governed = _c7_runtime_dna().govern(lambda first, later: "safe")
        with pytest.raises(ValueError, match="maximum depth"):
            governed("safe", value)


class _C7HostileDict(dict):
    def __repr__(self):
        return "safe"

    def __len__(self):
        return 0

    def __iter__(self):
        return iter(("safe",))

    def items(self):
        return (("safe", "safe"),)


class _C7HostileList(list):
    def __repr__(self):
        return "safe"

    def __len__(self):
        return 0

    def __iter__(self):
        return iter(("safe",))


class _C7HostileTuple(tuple):
    def __repr__(self):
        return "safe"

    def __len__(self):
        return 0

    def __iter__(self):
        return iter(("safe",))


@dataclass(init=False, repr=False)
class _C7DataclassHostileDict(_C7HostileDict):
    pass


@dataclass(init=False, repr=False)
class _C7DataclassHostileList(_C7HostileList):
    pass


@dataclass(init=False, repr=False)
class _C7DataclassHostileTuple(_C7HostileTuple):
    pass


_C7_CONTAINER_SUBCLASS_CASES = (
    pytest.param(
        lambda value: _C7HostileDict({"secret": value}),
        id="dict-subclass",
    ),
    pytest.param(lambda value: _C7HostileList([value]), id="list-subclass"),
    pytest.param(lambda value: _C7HostileTuple((value,)), id="tuple-subclass"),
)

_C7_DATACLASS_CONTAINER_SUBCLASS_CASES = (
    pytest.param(
        lambda value: _C7DataclassHostileDict({"secret": value}),
        id="dataclass-dict-subclass",
    ),
    pytest.param(
        lambda value: _C7DataclassHostileList([value]),
        id="dataclass-list-subclass",
    ),
    pytest.param(
        lambda value: _C7DataclassHostileTuple((value,)),
        id="dataclass-tuple-subclass",
    ),
)


class TestC7DNAContainerSubclassHardening:
    @pytest.mark.parametrize("payload_factory", _C7_CONTAINER_SUBCLASS_CASES)
    @pytest.mark.parametrize("boundary", ("input", "output"))
    def test_container_subclass_hooks_cannot_hide_forbidden_content(
        self, payload_factory, boundary
    ):
        from acgs_lite import ConstitutionalViolationError

        payload = payload_factory("forbidden_marker")
        dna = _c7_runtime_dna()
        with pytest.raises(ConstitutionalViolationError):
            if boundary == "input":
                dna.govern(lambda prompt, later: "safe")("safe", payload)
            else:
                dna.govern(lambda prompt: payload)("safe")

    @pytest.mark.parametrize(
        "payload_factory", _C7_DATACLASS_CONTAINER_SUBCLASS_CASES
    )
    @pytest.mark.parametrize("boundary", ("input", "output"))
    def test_dataclass_marker_cannot_bypass_container_subclass_governance(
        self, payload_factory, boundary
    ):
        from acgs_lite import ConstitutionalViolationError

        payload = payload_factory("forbidden_marker")
        dna = _c7_runtime_dna()
        with pytest.raises(ConstitutionalViolationError):
            if boundary == "input":
                dna.govern(lambda prompt, later: "safe")("safe", payload)
            else:
                dna.govern(lambda prompt: payload)("safe")

    @pytest.mark.parametrize("payload_factory", _C7_CONTAINER_SUBCLASS_CASES)
    @pytest.mark.parametrize("boundary", ("input", "output"))
    def test_safe_container_subclasses_remain_governable(
        self, payload_factory, boundary
    ):
        payload = payload_factory("allowed_content")
        dna = _c7_runtime_dna()
        if boundary == "input":
            result = dna.govern(lambda prompt, later: "safe")("safe", payload)
            assert result == "safe"
        else:
            result = dna.govern(lambda prompt: payload)("safe")
            assert result is payload

    @pytest.mark.parametrize("container_type", (_C7HostileDict, _C7HostileList))
    def test_container_subclass_cycles_remain_bounded(self, container_type):
        value = container_type()
        if isinstance(value, dict):
            dict.__setitem__(value, "self", value)
        else:
            list.append(value, value)

        governed = _c7_runtime_dna().govern(lambda prompt, later: "safe")
        with pytest.raises(ValueError, match="cyclic"):
            governed("safe", value)

    def test_container_subclass_size_limit_ignores_overridden_len(self):
        value = _C7HostileList(["safe"] * 10_001)
        governed = _c7_runtime_dna().govern(lambda prompt, later: "safe")

        with pytest.raises(ValueError, match="maximum item count"):
            governed("safe", value)


class TestC7PaperBatchReconciliation:
    def test_paper_builder_commits_one_rng_ordered_batch(self):
        from scripts.reproduce_paper_claims import _make_spectral

        manifold = _make_spectral(10, 42)
        assert manifold.commit_generation == 1

    def test_paper_retention_matches_published_base(self):
        import pytest
        from scripts.reproduce_paper_claims import _retention_series

        retention = _retention_series(
            kind="spectral", n=10, seed=42, cycles=[10], residual_alpha=0.0
        )["10"]
        assert retention == pytest.approx(0.04496, abs=0.000005)


# BEGIN C7 CURRENT MERKLE REPAIR


class TestC7CurrentMerkleClosureIndex:
    async def test_fully_synced_deep_chain_completes_without_resend(self, monkeypatch):
        import asyncio

        import constitutional_swarm.gossip_protocol as gossip_protocol
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        monkeypatch.setattr(gossip_protocol, "MAX_ANCESTRY_SCAN", 100)
        source = MerkleCRDT("source")
        for index in range(300):
            source.append(f"chain-{index}")

        target = MerkleCRDT("target")

        async def sync_once():
            client_ws, server_ws = _c7_gossip_pair()
            server = gossip_protocol.GossipServer(
                target, allow_unauthenticated=True
            )
            server_task = asyncio.create_task(server._handle_connection(server_ws))
            client = gossip_protocol.GossipClient(
                connect=lambda *_args, **_kwargs: _C7GossipConnection(
                    client_ws, server_task
                )
            )
            return await client.sync("memory", 0, source, chunk_size=64)

        first = await sync_once()
        follow_up = await sync_once()

        assert first == {"complete": True, "nodes_sent": 300}
        assert follow_up == {"complete": True, "nodes_sent": 0}
        assert target.all_cids() == source.all_cids()

    def test_out_of_order_parent_arrival_closes_descendants(self):
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        root_cid = compute_cid("source", "root", ())
        child_cid = compute_cid("source", "child", (root_cid,))
        leaf_cid = compute_cid("source", "leaf", (child_cid,))
        nodes = [
            DAGNode(
                cid=leaf_cid,
                agent_id="source",
                payload="leaf",
                parent_cids=(child_cid,),
            ),
            DAGNode(
                cid=child_cid,
                agent_id="source",
                payload="child",
                parent_cids=(root_cid,),
            ),
            DAGNode(cid=root_cid, agent_id="source", payload="root"),
        ]
        target = MerkleCRDT("target")

        assert target.merge_nodes(nodes[:2]) == 2
        assert target.missing_ancestry((leaf_cid,), limit=10, scan_limit=10) == (
            root_cid,
        )
        assert target.merge_nodes(nodes[2:]) == 1
        assert target.missing_ancestry((leaf_cid,), limit=10, scan_limit=1) == ()


class TestC7CurrentFrozenJSONListContract:
    def test_equality_inequality_and_hash_are_consistent(self):
        import pytest

        from constitutional_swarm.merkle_crdt import FrozenJSONList

        frozen = FrozenJSONList((1, 2))
        assert frozen == [1, 2]
        assert frozen == (1, 2)
        assert not frozen != [1, 2]
        assert not frozen != (1, 2)
        assert frozen != [1, 3]
        with pytest.raises(TypeError):
            hash(frozen)


class TestC7CurrentMetadataLimitOrdering:
    def test_oversized_metadata_is_rejected_before_invalid_cid(self):
        import pytest

        from constitutional_swarm.gossip_protocol import (
            MAX_METADATA_BYTES,
            _wire_to_node,
        )

        with pytest.raises(
            ValueError, match=f"metadata exceeds {MAX_METADATA_BYTES} bytes"
        ):
            _wire_to_node(
                {
                    "cid": "invalid",
                    "agent_id": "source",
                    "payload": "payload",
                    "metadata": {"value": "x" * (MAX_METADATA_BYTES + 1)},
                }
            )


# END C7 CURRENT MERKLE REPAIR


class TestC7CurrentMeshRepair:
    @staticmethod
    def _store(tmp_path, backend):
        from constitutional_swarm.settlement_store import (
            JSONLSettlementStore,
            SQLiteSettlementStore,
        )

        if backend == "jsonl":
            return JSONLSettlementStore(tmp_path / "votes.jsonl")
        return SQLiteSettlementStore(tmp_path / "votes.db")

    @staticmethod
    def _assert_vote_evidence(record):
        assert record is not None
        assert record.votes
        assert all(vote["signature"] for vote in record.votes)
        assert all(vote["key_id"] for vote in record.votes)
        assert all("public_key_hex" not in vote for vote in record.votes)

    def test_normal_settlement_retains_votes_in_jsonl_and_sqlite(self, tmp_path):
        for backend in ("jsonl", "sqlite"):
            store = self._store(tmp_path / backend, backend)
            mesh = _c7_mesh_with_agents(settlement_store=store)

            result = mesh.full_validation("a", "safe", f"normal-{backend}")

            self._assert_vote_evidence(store.get(result.assignment_id))

    def test_retry_settlement_retains_votes_in_jsonl_and_sqlite(self, tmp_path):
        import pytest

        from constitutional_swarm.mesh import SettlementPersistenceError
        from constitutional_swarm.settlement_store import (
            JSONLSettlementStore,
            SQLiteSettlementStore,
        )

        class FailOnceJSONLStore(JSONLSettlementStore):
            fail_next_append = True

            def append(self, record):
                if self.fail_next_append:
                    self.fail_next_append = False
                    raise OSError("injected append failure")
                return super().append(record)

        class FailOnceSQLiteStore(SQLiteSettlementStore):
            fail_next_append = True

            def append(self, record):
                if self.fail_next_append:
                    self.fail_next_append = False
                    raise OSError("injected append failure")
                return super().append(record)

        stores = (
            FailOnceJSONLStore(tmp_path / "retry.jsonl"),
            FailOnceSQLiteStore(tmp_path / "retry.db"),
        )
        for index, store in enumerate(stores):
            mesh = _c7_mesh_with_agents(settlement_store=store)
            with pytest.raises(SettlementPersistenceError):
                mesh.full_validation("a", "safe", f"retry-{index}")
            pending = store.load_pending()
            assert len(pending) == 1
            self._assert_vote_evidence(pending[0])

            report = mesh.reconcile_pending_settlements()

            assert report.settled == 1
            assignment_id = str(pending[0].assignment["assignment_id"])
            self._assert_vote_evidence(store.get(assignment_id))

    def test_trust_alias_mutation_cannot_reach_canonical_state(self):
        mesh = _c7_mesh_with_agents(use_manifold=True, manifold_type="spectral")
        mesh.update_trust([("a", "b", 0.4), ("b", "a", 0.8)])
        values_alias = mesh._trust_store
        before_values = mesh.raw_trust_snapshot()
        before_generation = mesh._state_generation
        before_round = mesh._trust_state.round_number
        before_routing = mesh._routing_snapshot_locked()

        values_alias[("a", "b")] = 999.0
        values_alias[("a", "c")] = float("nan")

        assert mesh.raw_trust_snapshot() == before_values
        assert mesh._routing_snapshot_locked() == before_routing
        assert mesh._state_generation == before_generation
        assert mesh._trust_state.round_number == before_round

        mesh.unregister_agent("a")
        archive_alias = mesh._trust_archive
        canonical_archive = mesh._trust_state.archive
        archived_generation = mesh._state_generation
        archived_round = mesh._trust_state.round_number
        archived_routing = mesh._routing_snapshot_locked()

        archive_alias["a"].relationships["b"] = (999.0, 999.0, -1)
        archive_alias.clear()

        assert mesh._trust_state.archive == canonical_archive
        assert mesh._routing_snapshot_locked() == archived_routing
        assert mesh._state_generation == archived_generation
        assert mesh._trust_state.round_number == archived_round

    def test_shadow_dimension_drift_is_repaired_and_logged(self, caplog):
        import logging

        mesh = _c7_mesh_with_agents(
            use_manifold=True,
            manifold_type="birkhoff",
            shadow_spectral=True,
        )
        assert mesh._shadow_manifold is not None
        mesh._shadow_manifold._n = 1

        with caplog.at_level(logging.ERROR, logger="constitutional_swarm.mesh.core"):
            result = mesh.full_validation("a", "safe", "shadow-drift")

        assert result.settled is True
        assert mesh._shadow_manifold is not None
        assert mesh._shadow_manifold.num_agents == mesh.agent_count
        assert "Shadow manifold dimension mismatch" in caplog.text


# BEGIN C7 INCREMENTAL FRONTIER REPAIR


class TestC7IncrementalFrontierIndex:
    class _NoIterationDict(dict):
        def __iter__(self):
            raise AssertionError("frontier operations must not iterate the node map")

        def keys(self):
            raise AssertionError("frontier operations must not scan node-map keys")

    def test_frontier_snapshot_does_not_iterate_node_map(self):
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        replica = MerkleCRDT("source")
        node = replica.append("root")
        replica._nodes = self._NoIterationDict(replica._nodes)

        assert replica.frontier_snapshot() == (node.cid,)

    def test_append_does_not_iterate_existing_node_map(self):
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        replica = MerkleCRDT("source")
        root = replica.append("root")
        replica._nodes = self._NoIterationDict(replica._nodes)

        child = replica.append("child")

        assert child.parent_cids == (root.cid,)
        assert replica.frontier_snapshot() == (child.cid,)

    def test_heads_match_reference_for_child_before_parent_and_duplicates(self):
        from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

        root_cid = compute_cid("source", "root", ())
        child_cid = compute_cid("source", "child", (root_cid,))
        leaf_cid = compute_cid("source", "leaf", (child_cid,))
        root = DAGNode(cid=root_cid, agent_id="source", payload="root")
        child = DAGNode(
            cid=child_cid,
            agent_id="source",
            payload="child",
            parent_cids=(root_cid,),
        )
        leaf = DAGNode(
            cid=leaf_cid,
            agent_id="source",
            payload="leaf",
            parent_cids=(child_cid,),
        )
        replica = MerkleCRDT("target")

        def reference_heads():
            cids = replica.all_cids()
            parents_with_stored_children = {
                parent
                for cid in cids
                for parent in replica.get(cid).parent_cids
                if parent in cids
            }
            return frozenset(cids - parents_with_stored_children)

        for node in (leaf, root, child):
            assert replica.merge_nodes([node]) == 1
            assert replica.heads == reference_heads()

        before = replica.heads
        assert replica.merge_nodes([root, child, leaf]) == 0
        assert replica.heads == before == reference_heads() == frozenset({leaf_cid})


# END C7 INCREMENTAL FRONTIER REPAIR
