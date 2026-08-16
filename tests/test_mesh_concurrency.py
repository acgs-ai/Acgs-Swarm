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
    assert any(
        isinstance(exc, (MeshHaltedError, MeshSnapshotStaleError)) for exc in errors
    )
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
        peer for assignment in mesh._assignments.values() for peer in assignment.peers
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
        assert any(
            isinstance(exc, (MeshHaltedError, MeshSnapshotStaleError)) for exc in errors
        )


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
        assert mesh._voter_dna[voter][2] is cached[2]
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


def _block_policy():
    entered = threading.Event()
    release = threading.Event()

    def policy(available, needed, producer_id):
        assert isinstance(available, tuple)
        entered.set()
        assert release.wait(timeout=2)
        return list(available)[:needed]

    return policy, entered, release


def test_register_during_projection_fails_closed() -> None:
    policy, entered, release = _block_policy()
    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh.register_local_signer("agent-99")
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_reputation_change_during_projection_fails_closed() -> None:
    policy, entered, release = _block_policy()
    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh._agents["agent-01"].reputation += 0.25
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_trust_matrix_change_during_projection_fails_closed() -> None:
    entered = threading.Event()
    release = threading.Event()

    def policy(available, needed, producer_id):
        entered.set()
        assert release.wait(timeout=2)
        return list(available)[:needed]

    mesh = ConstitutionalMesh(
        Constitution.default(),
        seed=42,
        trust_policy="spectral",
    )
    for index in range(5):
        mesh.register_local_signer(f"agent-{index:02d}")
    # Override after construction so the snapshot still captures live trust.
    mesh._custom_trust_policy = policy
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    assert mesh._manifold is not None
    mesh._manifold.update_trust(0, 1, 0.4)
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_dna_replacement_during_projection_fails_closed() -> None:
    policy, entered, release = _block_policy()
    mesh = _mesh_with_policy(policy)
    from constitutional_swarm import AgentDNA

    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh._dna = AgentDNA(constitution=mesh._constitution, agent_id="replaced")
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_dna_disable_during_projection_fails_closed() -> None:
    policy, entered, release = _block_policy()
    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh._dna.disable()
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_custom_policy_replacement_during_projection_fails_closed() -> None:
    policy, entered, release = _block_policy()
    mesh = _mesh_with_policy(policy)
    errors: list[BaseException] = []

    def _request() -> None:
        try:
            mesh._request_validation_once("agent-00", "summarize notes", "a1")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=_request)
    worker.start()
    assert entered.wait(timeout=2)
    mesh._custom_trust_policy = lambda available, needed, producer_id: list(available)[
        :needed
    ]
    release.set()
    worker.join(timeout=2)
    assert any(isinstance(exc, MeshSnapshotStaleError) for exc in errors)


def test_mutated_cached_dna_is_not_reused() -> None:
    mesh = ConstitutionalMesh(Constitution.default(), seed=42)
    for index in range(4):
        mesh.register_local_signer(f"agent-{index:02d}")
    assignment = mesh.request_validation("agent-00", "summarize notes", "a1")
    voter = assignment.peers[0]
    mesh.validate_and_vote(assignment.assignment_id, voter)
    cached = mesh._voter_dna[voter]
    rogue = Constitution.from_rules([Rule(id="R", text="rogue", keywords=["leak"])])
    cached[2].constitution = rogue
    rebuilt = mesh._voter_dna_locked(voter)
    assert rebuilt.constitution.hash == mesh.constitutional_hash
    assert rebuilt.constitution.hash != rogue.hash
    assert mesh._voter_dna[voter][1] == mesh.constitutional_hash


def test_custom_policy_receives_detached_tuple() -> None:
    seen: list[object] = []

    def policy(available, needed, producer_id):
        seen.append((available, needed, producer_id))
        return list(available)[:needed]

    mesh = _mesh_with_policy(policy)
    mesh.request_validation("agent-00", "summarize notes", "a1")
    available, needed, producer_id = seen[0]
    assert isinstance(available, tuple)
    assert needed == 3
    assert producer_id == "agent-00"
