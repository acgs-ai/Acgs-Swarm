"""
P1-STATE-CONTINUITY — mesh trust preservation across agent churn and constitution rotation.

Tests verify:
1. Trust between remaining agents survives unregister/register of a different agent.
2. A returning agent gets restored trust (non-zero) with decay applied.
3. rotate_constitution(preserve_trust=True) retains non-uniform trust matrix.
4. rotate_constitution(preserve_trust=False) resets trust to zero.
"""

from __future__ import annotations

from acgs_lite import Constitution
from constitutional_swarm import ConstitutionalMesh


def _mesh_with_manifold(n: int) -> ConstitutionalMesh:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, use_manifold=True)
    for i in range(n):
        mesh.register_local_signer(f"agent-{i}", domain="test")
    return mesh


def _inject_trust(mesh: ConstitutionalMesh) -> None:
    """Inject trust through the ID-stable owner API."""
    agent_ids = tuple(mesh._agent_indices)
    mesh.update_trust(
        [
            (from_agent, to_agent, 0.5 + (from_index * 0.1))
            for from_index, from_agent in enumerate(agent_ids)
            for to_agent in agent_ids
            if from_agent != to_agent
        ]
    )


def _trust_sum(mesh: ConstitutionalMesh) -> float:
    """Sum of all raw trust values — proxy for 'non-zero trust exists'."""
    return sum(sum(row) for row in mesh.raw_trust_snapshot().matrix)


class TestAgentChurn:
    def test_remaining_agents_trust_survives_unregister(self) -> None:
        """Trust between A and B is preserved when C is unregistered."""
        mesh = _mesh_with_manifold(3)
        _inject_trust(mesh)
        trust_before = _trust_sum(mesh)
        assert trust_before > 0.0

        mesh.unregister_agent("agent-2")
        trust_after = _trust_sum(mesh)

        # Trust between remaining agents should still exist
        assert trust_after > 0.0, (
            "Trust between remaining agents was wiped on unregister. "
            f"Before={trust_before:.3f}, After={trust_after:.3f}"
        )

    def test_trust_survives_register_new_agent(self) -> None:
        """Trust between A and B is preserved when C joins."""
        mesh = _mesh_with_manifold(2)
        _inject_trust(mesh)
        trust_before = _trust_sum(mesh)
        assert trust_before > 0.0

        mesh.register_local_signer("agent-new", domain="test")
        trust_after = _trust_sum(mesh)

        assert trust_after > 0.0, (
            "Trust between existing agents was wiped when a new agent joined. "
            f"Before={trust_before:.3f}, After={trust_after:.3f}"
        )

    def test_returning_agent_gets_restored_trust(self) -> None:
        """An agent that leaves and rejoins gets non-zero archived trust restored."""
        mesh = _mesh_with_manifold(3)
        _inject_trust(mesh)

        # Record agent-0's trust relationships
        # Unregister agent-0 — trust should be archived
        mesh.unregister_agent("agent-0")
        assert "agent-0" in mesh._trust_archive, "Trust archive should contain departed agent"

        # Re-register agent-0 — archive should be restored with decay
        mesh.register_local_signer("agent-0", domain="test")
        snapshot = mesh.raw_trust_snapshot()
        restored = sum(snapshot.matrix[snapshot.agent_ids.index("agent-0")])
        assert restored > 0.0, "Returning agent should have non-zero trust restored from archive"
        assert "agent-0" not in mesh._trust_archive, "Archive should be cleared after restore"


class TestConstitutionRotation:
    def test_rotate_constitution_preserve_trust_retains_values(self) -> None:
        """rotate_constitution(preserve_trust=True) keeps non-uniform trust matrix."""
        mesh = _mesh_with_manifold(3)
        _inject_trust(mesh)
        trust_before = _trust_sum(mesh)
        assert trust_before > 0.0

        new_constitution = Constitution.default()
        mesh.rotate_constitution(new_constitution, preserve_trust=True)

        trust_after = _trust_sum(mesh)
        assert trust_after > 0.0, (
            f"Trust was wiped after rotate_constitution(preserve_trust=True). "
            f"Before={trust_before:.3f}, After={trust_after:.3f}"
        )

    def test_rotate_constitution_no_preserve_resets_trust(self) -> None:
        """rotate_constitution(preserve_trust=False) resets trust to zero."""
        mesh = _mesh_with_manifold(3)
        _inject_trust(mesh)
        assert _trust_sum(mesh) > 0.0

        new_constitution = Constitution.default()
        mesh.rotate_constitution(new_constitution, preserve_trust=False)

        trust_after = _trust_sum(mesh)
        assert trust_after == 0.0, (
            f"Trust should be zero after rotate_constitution(preserve_trust=False), "
            f"got {trust_after:.3f}"
        )

    def test_rotate_constitution_updates_hash(self) -> None:
        """rotate_constitution replaces the constitution regardless of preserve_trust."""
        mesh = _mesh_with_manifold(2)
        new_constitution = Constitution.default()
        mesh.rotate_constitution(new_constitution, preserve_trust=True)
        assert mesh._constitution is new_constitution
