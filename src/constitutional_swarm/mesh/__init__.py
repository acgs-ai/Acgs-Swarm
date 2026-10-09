"""Compatibility facade for the Constitutional Mesh package split."""

from constitutional_swarm.mesh.core import ConstitutionalMesh
from constitutional_swarm.mesh.exceptions import (
    AssignmentSettledError,
    DuplicateVoteError,
    InsufficientPeersError,
    InvalidVoteSignatureError,
    MeshCapacityError,
    MeshHaltedError,
    MeshSnapshotStaleError,
    RecoveredAssignmentError,
    RemoteVoteReplayError,
    SettlementPersistenceError,
    UnauthorizedVoterError,
)
from constitutional_swarm.mesh.peers import PeerAssignment
from constitutional_swarm.mesh.settlement import MeshProof, MeshResult, ReconciliationReport
from constitutional_swarm.mesh.voting import RemoteVoteRequest, ValidationVote
from constitutional_swarm.mesh.vote_envelope import SignedAssignment

__all__ = [
    "AssignmentSettledError",
    "ConstitutionalMesh",
    "DuplicateVoteError",
    "InsufficientPeersError",
    "InvalidVoteSignatureError",
    "MeshCapacityError",
    "MeshHaltedError",
    "MeshSnapshotStaleError",
    "MeshProof",
    "MeshResult",
    "PeerAssignment",
    "ReconciliationReport",
    "RecoveredAssignmentError",
    "RemoteVoteReplayError",
    "RemoteVoteRequest",
    "SettlementPersistenceError",
    "SignedAssignment",
    "UnauthorizedVoterError",
    "ValidationVote",
]
