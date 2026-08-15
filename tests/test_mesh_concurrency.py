"""Deterministic concurrency tests for lock-free mesh validation."""

from __future__ import annotations

import threading

import pytest
from acgs_lite import Constitution, Rule
from constitutional_swarm import ConstitutionalMesh
from constitutional_swarm.mesh.exceptions import MeshHaltedError, MeshSnapshotStaleError


def _mesh_with_policy(policy, *, n: int = 5) -> ConstitutionalMesh:
    mesh = ConstitutionalMesh(Constitution.default(), seed=42, trust_policy=policy)
    for index in range(n):
        mesh.register_local_signer(f"agent-{index:02d}")
    return mesh


def test_projection_does_not_block_other_mesh_ops() -> None:
    entered = threading.Event()
    release = threading.Event()

    def policy(available, needed, producer_id):
        entered.set()
        assert release.wait(timeout=2)
        return list(available)[:needed]

    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []
    result: list[object] = []

    def _request() -> None:
        try:
            result.append(mesh.request_validation("agent-00", "summarize notes", "a1"))
        except BaseException as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    # The mesh lock must be free while the injected policy is blocked.
    assert mesh.get_reputation("agent-01") >= 0
    assert mesh.agent_count == 5
    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert errors == []
    assert result


def test_halt_during_projection_fails_closed() -> None:
    entered = threading.Event()
    release = threading.Event()

    def policy(available, needed, producer_id):
        entered.set()
        assert release.wait(timeout=2)
        return list(available)[:needed]

    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh.request_validation("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh.halt()
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, (MeshHaltedError, MeshSnapshotStaleError)) for exc in errors)
    assert mesh._assignments == {}


def test_unregister_during_projection_does_not_commit_missing_peer() -> None:
    entered = threading.Event()
    release = threading.Event()
    chosen = ["agent-01", "agent-02", "agent-03"]

    def policy(available, needed, producer_id):
        entered.set()
        assert release.wait(timeout=2)
        return chosen[:needed]

    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh.request_validation("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh.unregister_agent("agent-01")
    release.set()
    worker.join(timeout=2)
    assert errors
    assert "agent-01" not in {
        peer
        for assignment in mesh._assignments.values()
        for peer in assignment.peers
    }


def test_constitution_rotation_during_projection_fails_closed() -> None:
    entered = threading.Event()
    release = threading.Event()

    def policy(available, needed, producer_id):
        entered.set()
        assert release.wait(timeout=2)
        return list(available)[:needed]

    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh.request_validation("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    rotated = Constitution.from_rules([Rule(id="R", text="new", keywords=["x"])])
    mesh.rotate_constitution(rotated)
    release.set()
    worker.join(timeout=2)
    new_hash = mesh.constitutional_hash
    for assignment in mesh._assignments.values():
        assert assignment.constitutional_hash == new_hash
    if errors:
        assert any(isinstance(exc, (MeshHaltedError, MeshSnapshotStaleError)) for exc in errors)


def test_policy_exception_releases_lock() -> None:
    def policy(available, needed, producer_id):
        raise RuntimeError("projector exploded")

    mesh = _mesh_with_policy(policy)
    with pytest.raises(RuntimeError, match="projector exploded"):
        mesh.request_validation("agent-00", "summarize notes", "a1")
    assert mesh.get_reputation("agent-01") >= 0
    mesh2 = ConstitutionalMesh(Constitution.default(), seed=42)
    for index in range(5):
        mesh2.register_local_signer(f"agent-{index:02d}")
    assignment = mesh2.request_validation("agent-00", "summarize notes", "a1")
    assert assignment.peers


def test_peer_selection_deterministic_for_same_seed() -> None:
    first = ConstitutionalMesh(Constitution.default(), seed=7)
    second = ConstitutionalMesh(Constitution.default(), seed=7)
    for index in range(6):
        first.register_local_signer(f"agent-{index:02d}")
        second.register_local_signer(f"agent-{index:02d}")
    a = first.request_validation("agent-00", "summarize notes", "one")
    b = second.request_validation("agent-00", "summarize notes", "one")
    assert a.peers == b.peers


def test_dna_cache_invalidates_on_rotation() -> None:
    mesh = ConstitutionalMesh(Constitution.default(), seed=42)
    for index in range(4):
        mesh.register_local_signer(f"agent-{index:02d}")
    assignment = mesh.request_validation("agent-00", "summarize notes", "a1")
    voter = assignment.peers[0]
    mesh.validate_and_vote(assignment.assignment_id, voter)
    cached = mesh._voter_dna[voter]
    assignment_again = mesh.request_validation("agent-00", "summarize notes", "a1b")
    if voter in assignment_again.peers:
        mesh.validate_and_vote(assignment_again.assignment_id, voter)
        assert mesh._voter_dna[voter][1] is cached[1]
    generation = cached[0]
    mesh.rotate_constitution(Constitution.default())
    assert voter not in mesh._voter_dna
    assignment2 = mesh.request_validation("agent-00", "summarize notes", "a2")
    mesh.validate_and_vote(assignment2.assignment_id, assignment2.peers[0])
    assert mesh._voter_dna[assignment2.peers[0]][0] != generation


def test_default_trust_policy_is_uniform() -> None:
    mesh = ConstitutionalMesh(Constitution.default())
    assert mesh._trust_policy == "uniform"
    assert mesh._use_manifold is False


def test_birkhoff_requires_explicit_opt_in() -> None:
    mesh = ConstitutionalMesh(Constitution.default(), trust_policy="birkhoff")
    assert mesh._trust_policy == "birkhoff"
    assert mesh._use_manifold is True
    legacy = ConstitutionalMesh(Constitution.default(), use_manifold=True)
    assert legacy._use_manifold is True
    assert legacy._trust_policy == "birkhoff"
