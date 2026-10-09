"""Constitutional Mesh — Byzantine-tolerant peer validation with cryptographic proof.

The defensible core of constitutional_swarm. Every agent's output is validated by randomly
assigned peers using the ACGS constitutional engine. No single
validator bottleneck. Tolerates up to 1/3 faulty/malicious agents.

Cryptographic proof chain:
  1. Producer creates output with constitutional hash
  2. Mesh assigns random peers (producer excluded — MACI)
  3. Each peer validates via embedded DNA (local acgs-lite engine)
  4. Votes are signed with the peer's Ed25519 private key
  5. Quorum result produces a Merkle proof linking:
     - Producer's output hash
     - Each peer's vote + constitutional hash
     - Final acceptance/rejection decision
  6. Anyone can verify the proof independently

No competitor can replicate this: agents constitutionally validating
each other's work, with cryptographic proof. There is no published
sub-microsecond product latency claim.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import random
import threading
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from acgs_lite import Constitution
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.dna import AgentDNA
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
from constitutional_swarm.mesh.peers import (
    PeerAssignment,
    _AgentInfo,
    _matrix_spectral_norm,
    _summarize_metric,
    _trust_variance,
)
from constitutional_swarm.mesh.settlement import (
    MeshProof,
    MeshResult,
    ReconciliationReport,
)
from constitutional_swarm.mesh.voting import RemoteVoteRequest, ValidationVote
from constitutional_swarm.mesh.vote_envelope import (
    SignedAssignment,
    VoteEnvelope,
    VoteSignerRegistry,
    canonical_assigned_peers_hash,
    normalize_voter_id,
    sign_assignment,
    sign_vote_envelope as create_vote_envelope,
    signed_assignment_digest,
    signed_assignment_from_dict,
    signed_assignment_to_dict,
    compute_vote_envelope_root,
    verify_assignment_vote_envelopes,
    verify_signed_assignment,
    verify_vote_envelope,
    vote_envelope_from_dict,
    vote_envelope_hash,
    vote_envelope_to_dict,
)
from constitutional_swarm.mesh.trust import TrustSnapshot, _TrustState
from constitutional_swarm.settlement_store import (
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
    SettlementStore,
    SQLiteSettlementStore,
)

if TYPE_CHECKING:
    import constitutional_swarm.spectral_sphere as spectral_sphere_mod
    from constitutional_swarm.manifold import GovernanceManifold
    from constitutional_swarm.remote_vote_transport import (
        RemoteVoteClient,
        RemoteVoteResponse,
    )


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constitutional Mesh
# ---------------------------------------------------------------------------


class ConstitutionalMesh:
    """Byzantine-tolerant peer validation mesh with cryptographic proof.

    Every agent's output is validated by randomly assigned peers using
    the ACGS constitutional engine. The mesh produces a Merkle proof
    that anyone can independently verify.

    Properties:
    - O(1) governance cost per agent (local DNA validation)
    - Byzantine fault tolerant (tolerates < 1/3 faulty agents)
    - No single validator bottleneck
    - MACI-compliant (no self-validation)
    - Cryptographic proof chain for auditability
    - Local validation via AgentDNA (full pipeline tests bound average latency under 10ms)
    """

    def __init__(
        self,
        constitution: Constitution,
        *,
        peers_per_validation: int = 3,
        quorum: int = 2,
        seed: int | None = None,
        use_manifold: bool = False,
        manifold_type: Literal["birkhoff", "spectral"] = "birkhoff",
        trust_policy: Literal["uniform", "spectral", "birkhoff"] | Any = "uniform",
        shadow_spectral: bool = False,
        risk_scoring: bool = False,
        settlement_store_path: str | Path | None = None,
        settlement_store: SettlementStore | None = None,
        auto_reconcile: bool = True,
        request_signing_private_key: Ed25519PrivateKey | bytes | str | None = None,
        receipt_signing_private_key: Ed25519PrivateKey | bytes | str | None = None,
        max_pending_assignments: int = 10_000,
        max_settled_results: int = 10_000,
        max_shadow_metrics: int = 1_000,
        complete_evidence: bool = False,
        vote_registry: VoteSignerRegistry | None = None,
        evidence_mode: Literal["independent", "single_operator_dev"] = "independent",
        assigner_private_key: Ed25519PrivateKey | bytes | str | None = None,
        assigner_id: str | None = None,
    ) -> None:
        if peers_per_validation < 1:
            raise ValueError("peers_per_validation must be at least 1")
        if quorum < 1 or quorum > peers_per_validation:
            raise ValueError(
                f"Quorum ({quorum}) must be between 1 and peers_per_validation "
                f"({peers_per_validation})"
            )
        if quorum <= peers_per_validation // 2:
            raise ValueError("quorum must be a strict majority of peers_per_validation")
        if evidence_mode not in {"independent", "single_operator_dev"}:
            raise ValueError("invalid evidence_mode")
        if (settlement_store is not None or settlement_store_path is not None) and quorum < 3:
            raise ValueError("persistent proof-grade settlements require quorum >= 3")
        for name, value in (
            ("max_pending_assignments", max_pending_assignments),
            ("max_settled_results", max_settled_results),
            ("max_shadow_metrics", max_shadow_metrics),
        ):
            if value < 1:
                raise ValueError(f"{name} must be at least 1")
        if manifold_type not in {"birkhoff", "spectral"}:
            raise ValueError(
                f"manifold_type must be 'birkhoff' or 'spectral', got {manifold_type!r}"
            )
        custom_policy = trust_policy if callable(trust_policy) else None
        if custom_policy is None and trust_policy not in {
            "uniform",
            "spectral",
            "birkhoff",
        }:
            raise ValueError(
                "trust_policy must be 'uniform', 'spectral', 'birkhoff', or a callable, "
                f"got {trust_policy!r}"
            )
        if custom_policy is not None:
            resolved_policy = "custom"
            use_manifold = False
        elif use_manifold and trust_policy == "uniform":
            # Legacy: use_manifold=True + default trust_policy keeps manifold_type.
            resolved_policy = manifold_type
        else:
            resolved_policy = str(trust_policy)
            use_manifold = resolved_policy in {"spectral", "birkhoff"}
            if use_manifold:
                manifold_type = resolved_policy  # type: ignore[assignment]
        self._constitution = constitution
        self._dna = AgentDNA(
            constitution=constitution,
            agent_id="mesh-validator",
            risk_scoring=risk_scoring,
        )
        self._risk_scoring = risk_scoring
        self._peers_per_validation = peers_per_validation
        self._quorum = quorum
        self._complete_evidence = complete_evidence
        self._evidence_mode = evidence_mode
        # Seeded randomness is only used for deterministic peer assignment in tests/benchmarks.
        self._rng = random.Random(seed) if seed is not None else random.SystemRandom()
        self._agents: dict[str, _AgentInfo] = {}
        self._agent_vote_public_keys: dict[str, Ed25519PublicKey] = {}
        self._agent_vote_private_keys: dict[str, Ed25519PrivateKey] = {}
        registry_was_supplied = vote_registry is not None
        self._vote_registry = vote_registry or VoteSignerRegistry()
        if registry_was_supplied and (assigner_private_key is None or assigner_id is None):
            raise ValueError(
                "an externally supplied vote_registry requires explicit "
                "assigner_private_key and assigner_id"
            )
        self._assigner_private_key = (
            Ed25519PrivateKey.generate()
            if assigner_private_key is None
            else self._coerce_private_key(assigner_private_key)
        )
        self._assigner_id = normalize_voter_id(assigner_id or "mesh-assigner")
        if registry_was_supplied:
            self._assigner_key_id = hashlib.sha256(
                self._assigner_private_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).hexdigest()
            self._vote_registry.authorize(
                self._assigner_id, self._assigner_key_id, role="assigner"
            )
        else:
            self._assigner_key_id = self._vote_registry.register(
                self._assigner_id,
                self._assigner_private_key.public_key(),
                roles={"assigner"},
            )
        self._assigner_trust_root = self._vote_registry.frozen_copy()
        self._request_signing_private_key = (
            Ed25519PrivateKey.generate()
            if request_signing_private_key is None
            else self._coerce_private_key(request_signing_private_key)
        )
        self._request_signing_public_key = (
            self._request_signing_private_key.public_key()
        )
        # Dedicated settlement-receipt key. Request, vote-envelope, and receipt
        # signatures use distinct domain-separated canonical payloads. Callers
        # may pass the same material, but the default is a distinct key.
        self._receipt_signing_private_key = (
            Ed25519PrivateKey.generate()
            if receipt_signing_private_key is None
            else self._coerce_private_key(receipt_signing_private_key)
        )
        self._receipt_signing_public_key = (
            self._receipt_signing_private_key.public_key()
        )
        self._assignments: dict[str, PeerAssignment] = {}
        self._votes: dict[str, list[ValidationVote]] = {}
        self._vote_envelopes: dict[str, list[VoteEnvelope]] = {}
        self._signed_envelopes_by_signature: OrderedDict[str, VoteEnvelope] = (
            OrderedDict()
        )
        self._final_results: OrderedDict[str, MeshResult] = OrderedDict()
        self._max_pending_assignments = max_pending_assignments
        self._max_settled_results = max_settled_results
        self._total_validations = 0
        self._total_votes = 0
        self._total_settled = 0
        self._use_manifold = use_manifold
        self._manifold_type = manifold_type
        self._trust_policy = resolved_policy
        self._custom_trust_policy = custom_policy
        self._state_generation = 0
        self._constitution_generation = 0
        self._voter_dna: dict[str, tuple[int, str, AgentDNA]] = {}
        self._manifold: (
            GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold | None
        ) = None
        self._shadow_spectral = (
            use_manifold and manifold_type == "birkhoff" and shadow_spectral
        )
        if self._shadow_spectral:
            self._shadow_manifold: spectral_sphere_mod.SpectralSphereManifold | None = (
                None
            )
            self._shadow_metrics: deque[dict[str, float | str]] = deque(
                maxlen=max_shadow_metrics
            )
        self._trust_state = _TrustState(
            decay_rate=self._TRUST_DECAY_RATE,
            archive_limit=self._TRUST_ARCHIVE_MAX,
        )
        self._sync_trust_aliases()
        self._settled_assignments: set[str] = set()
        self._settled_voters: dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._halted = False
        if settlement_store is not None and settlement_store_path is not None:
            raise ValueError(
                "Specify either settlement_store or settlement_store_path, not both"
            )
        self._settlement_store = settlement_store
        if self._settlement_store is None and settlement_store_path is not None:
            if str(settlement_store_path).endswith(".db"):
                self._settlement_store = SQLiteSettlementStore(settlement_store_path)
            else:
                self._settlement_store = JSONLSettlementStore(settlement_store_path)
        self._load_settlements()
        if auto_reconcile:
            reconciliation_report = self.reconcile_pending_settlements()
            log_fn = logger.warning if reconciliation_report.failed > 0 else logger.info
            log_fn(
                "Startup settlement reconciliation completed",
                extra={
                    "auto_reconcile": True,
                    "settlement_backend": self._describe_settlement_backend(),
                    **reconciliation_report.as_log_fields(),
                },
            )

    def _check_halted(self) -> None:
        """Raise if mesh is halted."""
        if self._halted:
            raise MeshHaltedError("Mesh is halted — all operations blocked")

    def halt(self) -> None:
        """Kill switch — halt all mesh operations immediately.

        While halted, request_validation, submit_vote, validate_and_vote,
        and full_validation all raise MeshHaltedError.
        EU AI Act Art. 14(3): human-initiated halt capability.
        """
        with self._lock:
            self._halted = True
            self._state_generation += 1

    def resume(self) -> None:
        """Resume mesh operations after a halt."""
        with self._lock:
            self._halted = False
            self._state_generation += 1

    @property
    def is_halted(self) -> bool:
        """Whether the mesh is currently halted."""
        with self._lock:
            return self._halted

    @property
    def constitutional_hash(self) -> str:
        """The constitutional hash shared by all mesh participants."""
        return self._constitution.hash

    @property
    def vote_registry(self) -> VoteSignerRegistry:
        """Return the locked signer registry used to authorize vote evidence."""
        return self._vote_registry

    @property
    def assigner_id(self) -> str:
        """Return the identity whose pinned key authorizes mesh assignments."""
        return self._assigner_id

    def get_assigner_public_key(self) -> str:
        """Return the pinned assignment-authority public key as lowercase hex."""
        return self._assigner_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

    @property
    def agent_count(self) -> int:
        """Number of registered agents."""
        with self._lock:
            return len(self._agents)

    # -- Agent management --------------------------------------------------

    def _normalize_agent_id(self, agent_id: str) -> str:
        """Normalize a voter identity and reject the reserved assigner principal."""
        normalized = normalize_voter_id(agent_id)
        if normalized == self._assigner_id:
            raise ValueError("assignment authority identity is reserved")
        return normalized

    def register_remote_agent(
        self,
        agent_id: str,
        domain: str = "",
        *,
        vote_public_key: Ed25519PublicKey | bytes | str,
    ) -> None:
        """Register a remote peer with a public key only.

        The mesh can verify this agent's votes but cannot sign on their behalf.
        """
        agent_id = self._normalize_agent_id(agent_id)
        public_key = self._coerce_public_key(vote_public_key)
        with self._lock:
            self._vote_registry.replace(
                agent_id, public_key, roles={"voter", "validator"}
            )
            self._agents[agent_id] = _AgentInfo(agent_id=agent_id, domain=domain)
            self._agent_vote_public_keys[agent_id] = public_key
            self._agent_vote_private_keys.pop(agent_id, None)
            if self._use_manifold and agent_id not in self._agent_indices:
                self._trust_state.register(agent_id)
                self._sync_trust_aliases()
                self._rebuild_manifold()
            self._state_generation += 1

    def register_local_signer(
        self,
        agent_id: str,
        domain: str = "",
        *,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
    ) -> None:
        """Register an in-process signer whose private key is managed locally."""
        agent_id = self._normalize_agent_id(agent_id)
        private_key = (
            self._coerce_private_key(vote_private_key)
            if vote_private_key is not None
            else Ed25519PrivateKey.generate()
        )
        with self._lock:
            self._vote_registry.replace(
                agent_id, private_key.public_key(), roles={"voter", "validator"}
            )
            self._agents[agent_id] = _AgentInfo(agent_id=agent_id, domain=domain)
            self._agent_vote_private_keys[agent_id] = private_key
            self._agent_vote_public_keys[agent_id] = private_key.public_key()
            if self._use_manifold and agent_id not in self._agent_indices:
                self._trust_state.register(agent_id)
                self._sync_trust_aliases()
                self._rebuild_manifold()
            self._state_generation += 1

    def register_agent(self, *args: Any, **kwargs: Any) -> None:
        """Removed in v0.3.0. Use register_local_signer() or register_remote_agent()."""
        raise AttributeError(
            "register_agent() removed in v0.3.0. "
            "Use register_local_signer() for local agents or "
            "register_remote_agent() for remote peers. "
            "See https://github.com/dislovelhl/constitutional-swarm/blob/main/MIGRATION.md"
        )

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent from the mesh, archiving their trust relationships."""
        agent_id = self._normalize_agent_id(agent_id)
        with self._lock:
            self._agents.pop(agent_id, None)
            self._agent_vote_public_keys.pop(agent_id, None)
            self._agent_vote_private_keys.pop(agent_id, None)
            self._vote_registry.unregister(agent_id)
            if self._use_manifold and agent_id in self._agent_indices:
                self._trust_state.unregister(agent_id)
                self._sync_trust_aliases()
                self._rebuild_manifold()
            self._voter_dna.pop(agent_id, None)
            self._state_generation += 1

    def rotate_constitution(
        self,
        new_constitution: Constitution,
        *,
        preserve_trust: bool = False,
    ) -> None:
        """Replace the mesh constitution with a new one.

        Args:
            new_constitution: The new constitution to apply.
            preserve_trust: If True, carry forward the current trust matrix into
                the new manifold rather than resetting to zero.  Use this when
                the constitution update is a policy amendment (same agents, new
                rules) rather than a full governance reset.  Default False to
                avoid inadvertently carrying adversarial trust state across a
                security-motivated rotation.
        """
        with self._lock:
            self._constitution = new_constitution
            self._dna = AgentDNA(
                constitution=new_constitution,
                agent_id="mesh-validator",
                risk_scoring=self._risk_scoring,
            )
            self._constitution_generation += 1
            self._state_generation += 1
            self._voter_dna.clear()
            if self._use_manifold:
                if not preserve_trust:
                    # Hard reset — null manifold first so _save_trust_to_store is a no-op
                    self._manifold = None
                    if self._shadow_spectral:
                        self._shadow_manifold = None
                        self._shadow_metrics.clear()
                    self._trust_state.reset()
                    self._sync_trust_aliases()
                    self._rebuild_manifold()

    def _voter_dna_locked(self, voter_id: str) -> AgentDNA:
        """Return voter DNA bound to the current constitution identity.

        The cache stores ``(generation, constitution_hash, dna)``. A cached
        object whose constitution hash no longer matches, or that was disabled
        or replaced, is discarded so an externally mutated AgentDNA cannot
        ride an already-validated cache entry.
        """
        constitution_hash = self._constitution.hash
        cached = self._voter_dna.get(voter_id)
        if cached is not None:
            generation, stored_hash, dna = cached
            if (
                generation == self._constitution_generation
                and stored_hash == constitution_hash
                and dna.constitution.hash == constitution_hash
                and not dna.is_disabled
            ):
                return dna
            self._voter_dna.pop(voter_id, None)
        dna = AgentDNA(
            constitution=self._constitution,
            agent_id=voter_id,
            strict=False,
        )
        self._voter_dna[voter_id] = (
            self._constitution_generation,
            constitution_hash,
            dna,
        )
        return dna

    def get_reputation(self, agent_id: str) -> float:
        """Get an agent's reputation score."""
        agent_id = normalize_voter_id(agent_id)
        with self._lock:
            info = self._agents.get(agent_id)
            if info is None:
                raise KeyError(f"Agent {agent_id} not registered")
            return info.reputation

    # -- Validation flow ---------------------------------------------------

    def request_validation(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
        *,
        task_id: str | None = None,
    ) -> PeerAssignment:
        """Request peer validation of a producer's output.

        DNA validation and trust projection run outside the mesh lock.
        The assignment is committed only after re-checking halt,
        membership, and constitution generation.

        Raises:
            ConstitutionalViolationError: Content violates constitution.
            InsufficientPeersError: Not enough peers available.
            KeyError: Producer not registered.
            MeshHaltedError: Mesh is halted.
            MeshSnapshotStaleError: Snapshot became invalid and retries exhausted.
        """
        producer_id = normalize_voter_id(producer_id)
        last_stale: MeshSnapshotStaleError | None = None
        for _ in range(3):
            try:
                return self._request_validation_once(
                    producer_id, content, artifact_id, task_id or artifact_id
                )
            except MeshSnapshotStaleError as exc:
                last_stale = exc
        assert last_stale is not None
        raise last_stale

    def _request_validation_once(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
        task_id: str | None = None,
    ) -> PeerAssignment:
        task_id = task_id or artifact_id
        with self._lock:
            self._check_halted()
            self._discard_stale_assignments_locked()
            if self._pending_assignment_count_locked() >= self._max_pending_assignments:
                raise MeshCapacityError(
                    f"mesh pending assignment capacity {self._max_pending_assignments} reached"
                )
            if producer_id not in self._agents:
                raise KeyError(f"Producer {producer_id} not registered")
            dna = self._dna
            available = [aid for aid in self._agents if aid != producer_id]
            snapshot = self._routing_snapshot_locked()
            snapshot_hash = snapshot["constitution_hash"]
            trust_raw = snapshot["trust"]
            agent_indices = dict(self._agent_indices)
            selection_seed = f"{self._rng.getrandbits(256):064x}"

        dna_result = dna.validate(content)
        base_needed = min(self._peers_per_validation, len(available))
        if self._risk_scoring and dna_result.risk_score >= 0.8:
            needed = len(available)
        elif self._risk_scoring and dna_result.risk_score >= 0.5:
            needed = min(base_needed + 1, len(available))
        else:
            needed = base_needed
        if needed < self._quorum:
            raise InsufficientPeersError(
                f"Need {self._quorum} peers for quorum, only {needed} available"
            )
        peers = tuple(
            self._select_peers_unlocked(
                available,
                needed,
                producer_id,
                trust_raw=trust_raw,
                agent_indices=agent_indices,
                rng=random.Random(selection_seed),
            )
        )
        self._validate_selected_peers(
            peers,
            available=available,
            needed=needed,
            custom_policy=self._custom_trust_policy is not None,
        )

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
        assignment_id = uuid.uuid4().hex[:12]
        issued_at = time.time()
        effective_quorum = max(self._quorum, len(peers) // 2 + 1)
        signed_assignment = sign_assignment(
            self._assigner_private_key,
            task_id=task_id,
            assignment_id=assignment_id,
            assigner_id=self._assigner_id,
            producer_id=producer_id,
            artifact_id=artifact_id,
            content_hash=content_hash,
            constitutional_hash=snapshot_hash,
            assigned_peers=peers,
            quorum=effective_quorum,
            selection_seed=selection_seed,
            issued_at=issued_at,
        )
        assignment = PeerAssignment(
            assignment_id=assignment_id,
            producer_id=producer_id,
            artifact_id=artifact_id,
            content=content,
            content_hash=content_hash,
            peers=signed_assignment.assigned_peers,
            constitutional_hash=snapshot_hash,
            timestamp=issued_at,
            task_id=task_id,
            assigned_peers_hash=canonical_assigned_peers_hash(
                signed_assignment.assigned_peers
            ),
            assigned_peer_count=len(signed_assignment.assigned_peers),
            quorum=signed_assignment.quorum,
            evidence_mode=self._evidence_mode,
            signed_assignment=signed_assignment,
        )

        with self._lock:
            self._check_halted()
            if not self._routing_snapshot_matches_locked(snapshot):
                raise MeshSnapshotStaleError(
                    "mesh membership, constitution, reputation, trust, DNA, "
                    "or policy changed during validation"
                )
            if producer_id not in self._agents:
                raise MeshSnapshotStaleError(
                    f"Producer {producer_id} unregistered during validation"
                )
            missing = [peer for peer in peers if peer not in self._agents]
            if missing:
                raise MeshSnapshotStaleError(
                    f"Assigned peers unregistered during validation: {missing}"
                )
            if assignment.constitutional_hash != self.constitutional_hash:
                raise MeshSnapshotStaleError(
                    "constitution hash changed during validation"
                )
            if self._pending_assignment_count_locked() >= self._max_pending_assignments:
                raise MeshCapacityError(
                    f"mesh pending assignment capacity {self._max_pending_assignments} reached"
                )
            self._assignments[assignment.assignment_id] = assignment
            self._votes[assignment.assignment_id] = []
            self._total_validations += 1
            self._agents[producer_id].validations_received += 1
            return assignment

    def _copy_raw_trust_locked(self) -> list[list[float]] | None:
        if not self._use_manifold or self._manifold is None:
            return None
        return [list(row) for row in self._manifold.trust_matrix]

    def _routing_snapshot_locked(self) -> dict[str, Any]:
        """Capture every input that can invalidate snapshot-compute-commit."""
        return {
            "generation": self._state_generation,
            "constitution_generation": self._constitution_generation,
            "constitution_hash": self.constitutional_hash,
            "dna_id": id(self._dna),
            "dna_hash": self._dna.hash,
            "dna_disabled": self._dna.is_disabled,
            "policy_id": id(self._custom_trust_policy),
            "agents": frozenset(self._agents),
            "reputations": {
                agent_id: info.reputation for agent_id, info in self._agents.items()
            },
            "trust": self._copy_raw_trust_locked(),
        }

    def _routing_snapshot_matches_locked(self, snapshot: dict[str, Any]) -> bool:
        current = self._routing_snapshot_locked()
        return current == snapshot

    def _select_peers_unlocked(
        self,
        available: list[str],
        needed: int,
        producer_id: str,
        *,
        trust_raw: list[list[float]] | None,
        agent_indices: dict[str, int] | None = None,
        rng: random.Random | random.SystemRandom | None = None,
    ) -> list[str]:
        selection_rng = self._rng if rng is None else rng
        indices = self._agent_indices if agent_indices is None else agent_indices
        if self._custom_trust_policy is not None:
            # Detached, immutable inputs: the callable must not observe live
            # mesh state and cannot mutate the snapshot peer list in place.
            try:
                selected = list(
                    self._custom_trust_policy(
                        tuple(available), int(needed), str(producer_id)
                    )
                )
            except TypeError as exc:
                raise ValueError(
                    "custom peer selection must return an iterable of peer identities"
                ) from exc
            return selected[:needed]
        if not self._use_manifold or trust_raw is None or producer_id not in indices:
            return list(selection_rng.sample(available, k=needed))
        producer_idx = indices[producer_id]
        trust_row = trust_raw[producer_idx]
        weight_map: dict[str, float] = {}
        for aid in available:
            idx = indices.get(aid)
            weight = trust_row[idx] if idx is not None else 0.01
            weight_map[aid] = max(weight, 0.01)
        return self._sample_weighted_peers(
            available, needed, weight_map, rng=selection_rng
        )

    @staticmethod
    def _validate_selected_peers(
        selected: tuple[Any, ...],
        *,
        available: list[str],
        needed: int,
        custom_policy: bool,
    ) -> None:
        """Reject invalid routing output before assignment state is constructed."""

        prefix = "custom peer selection" if custom_policy else "peer selection"
        if len(selected) != needed:
            raise ValueError(f"{prefix} must return exactly {needed} peers")
        canonical: list[str] = []
        for peer in selected:
            if not isinstance(peer, str):
                raise ValueError(f"{prefix} must return string peer identities")
            try:
                normalized = normalize_voter_id(peer)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"{prefix} must return canonical peer identities"
                ) from exc
            if peer != normalized:
                raise ValueError(f"{prefix} must return canonical peer identities")
            canonical.append(normalized)
        if len(set(canonical)) != len(canonical):
            raise ValueError(f"{prefix} must return distinct peer identities")
        available_set = set(available)
        if any(peer not in available_set for peer in canonical):
            raise ValueError(f"{prefix} returned an unavailable or producer identity")

    def submit_vote(
        self,
        assignment_id: str,
        voter_id: str,
        *,
        approved: bool,
        reason: str = "",
        signature: str,
    ) -> ValidationVote:
        """Submit a peer's validation vote.

        Each peer validates the content against their constitutional DNA
        and casts an approve/reject vote.

        Raises:
            KeyError: Assignment not found.
            UnauthorizedVoterError: Voter not assigned to this validation.
            DuplicateVoteError: Voter already voted.
            MeshHaltedError: Mesh is halted.
        """
        with self._lock:
            self._check_halted()
            if assignment_id in self._final_results:
                raise AssignmentSettledError(
                    f"Assignment {assignment_id} is already settled"
                )
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            if assignment.is_recovered:
                raise RecoveredAssignmentError(
                    f"Assignment {assignment_id} is already durably settled"
                )
            if voter_id not in assignment.peers:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not assigned to validation {assignment_id}"
                )
            if voter_id not in self._agents:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not a registered mesh agent"
                )
            try:
                envelope = self._signed_envelopes_by_signature[signature]
                verified = verify_vote_envelope(
                    envelope,
                    self._vote_registry,
                    task_id=assignment.task_id,
                    assignment_id=assignment.assignment_id,
                    producer_id=assignment.producer_id,
                    artifact_id=assignment.artifact_id,
                    content_hash=assignment.content_hash,
                    constitutional_hash=assignment.constitutional_hash,
                )
                self._verify_envelope_assignment_metadata(verified, assignment)
                if (
                    verified.voter_id != normalize_voter_id(voter_id)
                    or verified.approved is not approved
                    or verified.reason != reason
                ):
                    raise ValueError("vote envelope does not match submitted vote")
            except (KeyError, ValueError, InvalidSignature) as exc:
                raise InvalidVoteSignatureError(
                    f"Invalid or unsigned vote envelope for {voter_id} on {assignment_id}"
                ) from exc

            existing = self._votes.get(assignment_id, [])
            if any(v.voter_id == voter_id for v in existing):
                raise DuplicateVoteError(f"{voter_id} already voted on {assignment_id}")
            self._signed_envelopes_by_signature.pop(signature, None)

            vote = ValidationVote(
                assignment_id=assignment_id,
                voter_id=voter_id,
                approved=approved,
                reason=reason,
                signature=signature,
                constitutional_hash=assignment.constitutional_hash,
                content_hash=assignment.content_hash,
                timestamp=time.time(),
            )
            self._votes[assignment_id] = [*existing, vote]
            self._vote_envelopes[assignment_id] = [
                *self._vote_envelopes.get(assignment_id, []),
                verified,
            ]
            self._total_votes += 1

            if voter_id in self._agents:
                self._agents[voter_id].validations_performed += 1

            # Update reputations if quorum reached
            self._maybe_settle_reputations(assignment_id)

        if self._maybe_finalize_result(assignment_id):
            self.settle(assignment_id)

        return vote

    def get_result(self, assignment_id: str) -> MeshResult:
        """Get the validation result for an assignment.

        Returns the frozen settled result when quorum has been finalized.
        Before settlement, this returns a preview result without a proof.
        """
        with self._lock:
            final = self._final_results.get(assignment_id)
            if final is not None:
                return final

            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            return self._preview_result(assignment)

    def settle(self, assignment_id: str) -> MeshResult:
        """Freeze a quorum result into an immutable proof snapshot.

        The settlement snapshot is written to the backing store *outside* the
        mesh lock so that slow or remote I/O in the store does not block
        concurrent callers. A durable pending marker is written before the
        in-memory result is installed, and the completed durable record is then
        appended before the pending marker is cleared.
        """
        with self._lock:
            final = self._final_results.get(assignment_id)
            if final is not None:
                recovered = self._assignments.get(assignment_id)
                if recovered is not None and recovered.is_recovered:
                    raise RecoveredAssignmentError(
                        f"Assignment {assignment_id} is already durably settled"
                    )
                return final
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            if assignment.is_recovered:
                raise RecoveredAssignmentError(
                    f"Assignment {assignment_id} is already durably settled"
                )

            preview = self._preview_result(assignment)
            if not preview.quorum_met:
                raise ValueError(
                    f"Assignment {assignment_id} cannot settle before quorum is reached"
                )

            settled_at = time.time()
            final = MeshResult(
                assignment_id=preview.assignment_id,
                accepted=preview.accepted,
                votes_for=preview.votes_for,
                votes_against=preview.votes_against,
                quorum_met=True,
                pending_votes=preview.pending_votes,
                constitutional_hash=preview.constitutional_hash,
                proof=self._build_proof(
                    assignment,
                    accepted=preview.accepted,
                    timestamp=settled_at,
                ),
                vote_envelopes=preview.vote_envelopes,
                settled=True,
                settled_at=settled_at,
                signed_assignment=assignment.signed_assignment,
            )
            settled_votes = list(self._vote_envelopes.get(assignment_id, []))
            pending_record = self._record_with_serialized_votes(
                self._build_settlement_record(assignment, final),
                settled_votes,
            )
            recovered_assignment = replace(assignment, is_recovered=True)
            settled_record = self._build_settlement_record(recovered_assignment, final)
            settlement_fence = self._constitution_fence_locked()
        # Persist outside the lock — store I/O must not block mesh operations.
        # A durable pending marker is written first so startup reconciliation can
        # recover frozen-but-not-yet-durable settlements after a crash.
        try:
            if self._settlement_store is not None:
                self._settlement_store.mark_pending(pending_record)
                self._maybe_crash("after-pending")
            with self._lock:
                existing = self._final_results.get(assignment_id)
                if existing is not None:
                    return existing
                if not self._constitution_fence_matches_locked(settlement_fence):
                    raise MeshSnapshotStaleError(
                        f"Assignment {assignment_id} crossed a constitution rotation "
                        "during settlement"
                    )
                # This install is the settlement linearization point. A later
                # rotation may make the result historical while Phase 2 persists.
                self._remember_final_result_locked(assignment_id, final)
            self._persist_settlement_record(settled_record, votes=settled_votes)
            self._maybe_crash("after-append")
            if self._settlement_store is not None:
                self._settlement_store.clear_pending(assignment_id)
            with self._lock:
                self._assignments[assignment_id] = replace(
                    recovered_assignment,
                    content="",
                )
                self._votes.pop(assignment_id, None)
                self._settled_assignments.discard(assignment_id)
                self._settled_voters.pop(assignment_id, None)
                self._total_settled += 1
        except MeshSnapshotStaleError:
            raise
        except Exception as exc:
            raise SettlementPersistenceError(
                f"Settlement {assignment_id} was frozen in memory but could not be persisted"
            ) from exc
        return final

    def validate_and_vote(
        self,
        assignment_id: str,
        voter_id: str,
    ) -> ValidationVote:
        """Convenience: peer validates content via DNA and auto-votes.

        The peer runs the content through their own constitutional DNA.
        If it passes, they vote approved. If it fails, they vote rejected
        with the violation as the reason.
        """
        with self._lock:
            self._check_halted()
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            self._assert_assignment_payload_complete(assignment)
            if voter_id not in self._agent_vote_private_keys:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not a locally managed signer; "
                    "use prepare_remote_vote() and submit_vote() for remote peers"
                )
            content = assignment.content
            voter_dna = self._voter_dna_locked(voter_id)

        result = voter_dna.validate(content)

        if result.valid:
            return self.submit_vote(
                assignment_id,
                voter_id,
                approved=True,
                reason="constitutional check passed",
                signature=self.sign_vote(
                    assignment_id,
                    voter_id,
                    approved=True,
                    reason="constitutional check passed",
                ),
            )
        return self.submit_vote(
            assignment_id,
            voter_id,
            approved=False,
            reason="; ".join(result.violations),
            signature=self.sign_vote(
                assignment_id,
                voter_id,
                approved=False,
                reason="; ".join(result.violations),
            ),
        )

    # -- Bulk operations ---------------------------------------------------

    def full_validation(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
        *,
        task_id: str | None = None,
    ) -> MeshResult:
        """End-to-end validation for locally managed signer peers only.

        This path auto-runs peer validation and signatures in-process.
        For remote public-key-only peers, use:
          1. request_validation()
          2. prepare_remote_vote()
          3. remote signer validates + signs externally
          4. submit_vote()
          5. get_result()/settle()
        """
        assignment = self.request_validation(
            producer_id, content, artifact_id, task_id=task_id
        )
        for peer_id in assignment.peers:
            try:
                self.validate_and_vote(assignment.assignment_id, peer_id)
            except (AssignmentSettledError, RecoveredAssignmentError):
                break
            with self._lock:
                if assignment.assignment_id in self._final_results:
                    break
        result = self.get_result(assignment.assignment_id)
        if result.quorum_met and not result.settled:
            return self.settle(assignment.assignment_id)
        return result

    async def collect_remote_votes(
        self,
        assignment_id: str,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: RemoteVoteClient | None = None,
        timeout: float = 5.0,
    ) -> MeshResult:
        """Collect votes for an existing assignment from local and remote peers.

        Local signer peers are validated/signed in-process. Public-key-only peers
        receive a `RemoteVoteRequest` over the supplied transport routes.
        """
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            peer_ids = assignment.peers

        _Client: type[RemoteVoteClient] | None
        try:
            from constitutional_swarm.remote_vote_transport import (
                RemoteVoteClient as _Client,
            )
        except ImportError:
            _Client = None

        if client is None:
            if _Client is None:
                raise ImportError(
                    "Remote vote collection requires constitutional_swarm.remote_vote_transport"
                )
            client = _Client()

        for peer_id in peer_ids:
            if assignment_id in self._final_results:
                break
            if peer_id in self._agent_vote_private_keys:
                try:
                    self.validate_and_vote(assignment_id, peer_id)
                except AssignmentSettledError:
                    break
                continue

            route = peer_routes.get(peer_id)
            if route is None:
                raise KeyError(
                    f"No route found for remote peer '{peer_id}'. "
                    f"Pass peer_routes={{'{peer_id}': (host, port), ...}}"
                    " to collect_remote_votes()."
                )
            request = self.prepare_remote_vote(assignment_id, peer_id)
            response = await client.request_vote(
                route[0], route[1], request, timeout=timeout
            )
            self._submit_remote_vote_response(assignment_id, peer_id, response)

        result = self.get_result(assignment_id)
        if result.quorum_met and not result.settled:
            return self.settle(assignment_id)
        return result

    async def full_validation_remote(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: RemoteVoteClient | None = None,
        timeout: float = 5.0,
    ) -> MeshResult:
        """End-to-end validation that supports public-key-only remote peers."""
        assignment = self.request_validation(producer_id, content, artifact_id)
        return await self.collect_remote_votes(
            assignment.assignment_id,
            peer_routes=peer_routes,
            client=client,
            timeout=timeout,
        )

    def prepare_remote_vote(
        self, assignment_id: str, voter_id: str
    ) -> RemoteVoteRequest:
        """Build a signable vote request for a public-key-only remote peer."""
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            self._assert_assignment_payload_complete(assignment)
            if voter_id not in assignment.peers:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not assigned to validation {assignment_id}"
                )
            public_key = self._agent_vote_public_keys.get(voter_id)
            if public_key is None:
                raise UnauthorizedVoterError(
                    f"{voter_id} has no registered vote public key"
                )
            voter_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
            nonce = uuid.uuid4().hex
            timestamp = time.time()
            request_signer_public_key = self.get_request_signing_public_key()
            request_signature = self._request_signing_private_key.sign(
                self.build_remote_vote_request_payload(
                    assignment_id=assignment.assignment_id,
                    voter_id=voter_id,
                    producer_id=assignment.producer_id,
                    artifact_id=assignment.artifact_id,
                    content=assignment.content,
                    content_hash=assignment.content_hash,
                    constitutional_hash=assignment.constitutional_hash,
                    voter_public_key=voter_public_key,
                    nonce=nonce,
                    timestamp=timestamp,
                    task_id=assignment.task_id,
                    assigned_peers=assignment.peers,
                    quorum=self._effective_quorum(assignment),
                    evidence_mode=self._assignment_evidence_mode(assignment),
                    signed_assignment=assignment.signed_assignment,
                    protocol_version=3,
                )
            ).hex()
            return RemoteVoteRequest(
                assignment_id=assignment.assignment_id,
                voter_id=voter_id,
                producer_id=assignment.producer_id,
                artifact_id=assignment.artifact_id,
                content=assignment.content,
                content_hash=assignment.content_hash,
                constitutional_hash=assignment.constitutional_hash,
                voter_public_key=voter_public_key,
                nonce=nonce,
                timestamp=timestamp,
                request_signer_public_key=request_signer_public_key,
                request_signature=request_signature,
                task_id=assignment.task_id,
                assigned_peers=assignment.peers,
                quorum=self._effective_quorum(assignment),
                evidence_mode=self._assignment_evidence_mode(assignment),
                protocol_version=3,
                signed_assignment=assignment.signed_assignment,
            )

    def _submit_remote_vote_response(
        self,
        assignment_id: str,
        voter_id: str,
        response: RemoteVoteResponse,
    ) -> ValidationVote:
        envelope = response.envelope
        if envelope.assignment_id != assignment_id:
            raise ValueError(
                f"Remote vote response assignment mismatch:"
                f" {envelope.assignment_id} != {assignment_id}"
            )
        if envelope.voter_id != voter_id:
            raise ValueError(
                f"Remote vote response voter mismatch: {envelope.voter_id} != {voter_id}"
            )
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            if envelope.constitutional_hash != assignment.constitutional_hash:
                raise ValueError("Remote vote response constitution mismatch")
            if envelope.content_hash != assignment.content_hash:
                raise ValueError("Remote vote response content hash mismatch")
        return self.submit_vote_envelope(envelope)

    @staticmethod
    def build_remote_vote_request_payload(
        *,
        assignment_id: str,
        voter_id: str,
        producer_id: str,
        artifact_id: str,
        content: str,
        content_hash: str,
        constitutional_hash: str,
        voter_public_key: str,
        nonce: str,
        timestamp: float,
        task_id: str = "",
        assigned_peers: Sequence[str] = (),
        quorum: int = 0,
        evidence_mode: Literal["independent", "single_operator_dev"] = "independent",
        protocol_version: int = 3,
        signed_assignment: SignedAssignment | None = None,
    ) -> bytes:
        import json

        if protocol_version not in {2, 3}:
            raise ValueError("unsupported remote vote request protocol version")
        canonical_peers = tuple(sorted(normalize_voter_id(peer) for peer in assigned_peers))
        if not canonical_peers or len(canonical_peers) != len(set(canonical_peers)):
            raise ValueError("remote vote request requires distinct assigned peers")
        if normalize_voter_id(voter_id) not in canonical_peers:
            raise ValueError("remote vote request voter is not in assigned_peers")
        if type(quorum) is not int or not 1 <= quorum <= len(canonical_peers):
            raise ValueError("remote vote request quorum is outside the electorate")
        if quorum <= len(canonical_peers) // 2:
            raise ValueError("remote vote request quorum must be a strict majority")
        if evidence_mode not in {"independent", "single_operator_dev"}:
            raise ValueError("remote vote request evidence_mode is invalid")
        if protocol_version == 3:
            if signed_assignment is None:
                raise ValueError("remote vote request requires signed assignment")
            authority = signed_assignment
            if (
                authority.assignment_id != assignment_id
                or authority.task_id != (task_id or artifact_id)
                or authority.producer_id != producer_id
                or authority.artifact_id != artifact_id
                or authority.content_hash != content_hash
                or authority.constitutional_hash != constitutional_hash
                or authority.assigned_peers != canonical_peers
                or authority.quorum != quorum
            ):
                raise ValueError("remote vote request signed assignment bindings mismatch")
        payload = {
            "artifact_id": artifact_id,
            "assignment_id": assignment_id,
            "constitutional_hash": constitutional_hash,
            "content": content,
            "content_hash": content_hash,
            "nonce": nonce,
            "producer_id": producer_id,
            "protocol_version": protocol_version,
            "assigned_peers": canonical_peers,
            "quorum": quorum,
            "evidence_mode": evidence_mode,
            "timestamp": format(timestamp, ".17g"),
            "task_id": task_id or artifact_id,
            "voter_id": voter_id,
            "voter_public_key": voter_public_key,
        }
        if protocol_version == 3:
            payload["signed_assignment"] = signed_assignment_to_dict(authority)
            payload["assignment_digest"] = signed_assignment_digest(authority)
        domain = (
            b"constitutional-swarm.remote-vote-request.v3\x00"
            if protocol_version == 3
            else b"constitutional-swarm.remote-vote-request.v2\x00"
        )
        return domain + json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @staticmethod
    def _evict_remote_vote_nonce_cache_entries(
        nonce_cache: OrderedDict[str, float],
        *,
        now: float,
        replay_window_seconds: float,
    ) -> None:
        expiry_cutoff = now - replay_window_seconds
        while nonce_cache:
            oldest_nonce, last_seen = next(iter(nonce_cache.items()))
            if last_seen > expiry_cutoff:
                break
            nonce_cache.pop(oldest_nonce)

    @staticmethod
    def verify_remote_vote_request(
        request: RemoteVoteRequest,
        *,
        replay_window_seconds: float = 300.0,
        nonce_cache: OrderedDict[str, float] | None = None,
        now: float | None = None,
    ) -> bool:
        """Verify a remote vote request signature."""
        if type(request.protocol_version) is not int or request.protocol_version != 3:
            raise ValueError("Remote vote request uses an unsupported protocol version")
        if type(request.timestamp) is not float or not math.isfinite(request.timestamp):
            raise ValueError("Remote vote request timestamp must be a finite float")
        string_fields = (
            request.assignment_id,
            request.voter_id,
            request.producer_id,
            request.artifact_id,
            request.content,
            request.content_hash,
            request.constitutional_hash,
            request.voter_public_key,
            request.nonce,
            request.request_signer_public_key,
            request.request_signature,
            request.task_id,
        )
        if any(not isinstance(value, str) for value in string_fields):
            raise ValueError("Remote vote request contains a non-string field")
        if replay_window_seconds <= 0:
            raise ValueError("Remote vote replay window must be positive")
        current_time = time.time() if now is None else now
        if not request.nonce:
            raise ValueError("Remote vote request is missing nonce")
        if abs(current_time - request.timestamp) > replay_window_seconds:
            raise ValueError("Remote vote request timestamp is outside replay window")
        try:
            public_key = ConstitutionalMesh._coerce_public_key(
                request.request_signer_public_key
            )
            public_key.verify(
                bytes.fromhex(request.request_signature),
                ConstitutionalMesh.build_remote_vote_request_payload(
                    assignment_id=request.assignment_id,
                    voter_id=request.voter_id,
                    producer_id=request.producer_id,
                    artifact_id=request.artifact_id,
                    content=request.content,
                    content_hash=request.content_hash,
                    constitutional_hash=request.constitutional_hash,
                    voter_public_key=request.voter_public_key,
                    nonce=request.nonce,
                    timestamp=float(request.timestamp),
                    task_id=request.task_id or request.artifact_id,
                    assigned_peers=request.assigned_peers,
                    quorum=request.quorum,
                    evidence_mode=request.evidence_mode,
                    protocol_version=request.protocol_version,
                    signed_assignment=request.signed_assignment,
                ),
            )
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("Remote vote request signature is invalid") from exc
        if nonce_cache is not None:
            ConstitutionalMesh._evict_remote_vote_nonce_cache_entries(
                nonce_cache,
                now=current_time,
                replay_window_seconds=replay_window_seconds,
            )
            if request.nonce in nonce_cache:
                raise RemoteVoteReplayError(
                    f"Remote vote request nonce {request.nonce!r}"
                    " was already used inside the replay window"
                )
            if len(nonce_cache) >= 10_000:
                raise RemoteVoteReplayError(
                    "Remote vote request nonce capacity reached for signer"
                )
            nonce_cache[request.nonce] = current_time
            nonce_cache.move_to_end(request.nonce)
        return True

    @staticmethod
    def _content_matches_hash(content: str, content_hash: str) -> bool:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32] == content_hash

    @classmethod
    def _assert_assignment_payload_complete(cls, assignment: PeerAssignment) -> None:
        if not cls._content_matches_hash(assignment.content, assignment.content_hash):
            raise ValueError(
                f"Assignment {assignment.assignment_id} payload is unavailable"
                " or does not match its content hash"
            )

    def _require_current_assignment_constitution(
        self, assignment: PeerAssignment
    ) -> None:
        if assignment.constitutional_hash != self.constitutional_hash:
            raise MeshSnapshotStaleError(
                f"Assignment {assignment.assignment_id} belongs to a stale constitution"
            )

    def _constitution_fence_locked(self) -> tuple[int, str]:
        """Capture the active constitution generation and content hash."""
        return self._constitution_generation, self.constitutional_hash

    def _constitution_fence_matches_locked(self, fence: tuple[int, str]) -> bool:
        """Return whether no constitution rotation crossed an external I/O phase."""
        generation, constitutional_hash = fence
        return (
            self._constitution_generation == generation
            and self.constitutional_hash == constitutional_hash
        )

    # -- Stats -------------------------------------------------------------

    def _pending_assignment_count_locked(self) -> int:
        return sum(
            1 for assignment in self._assignments.values() if not assignment.is_recovered
        )

    def _discard_stale_assignments_locked(self) -> None:
        """Reclaim bounded pending capacity from invalidated constitutions."""
        stale_ids = [
            assignment_id
            for assignment_id, assignment in self._assignments.items()
            if not assignment.is_recovered
            and assignment.constitutional_hash != self.constitutional_hash
        ]
        for assignment_id in stale_ids:
            self._assignments.pop(assignment_id, None)
            self._votes.pop(assignment_id, None)
            self._settled_assignments.discard(assignment_id)
            self._settled_voters.pop(assignment_id, None)
        if stale_ids:
            self._state_generation += 1

    def _remember_final_result_locked(
        self, assignment_id: str, result: MeshResult
    ) -> None:
        self._final_results[assignment_id] = result
        self._final_results.move_to_end(assignment_id)
        while len(self._final_results) > self._max_settled_results:
            evicted_id, _ = self._final_results.popitem(last=False)
            self._assignments.pop(evicted_id, None)
            self._votes.pop(evicted_id, None)
            self._settled_assignments.discard(evicted_id)
            self._settled_voters.pop(evicted_id, None)

    def summary(self) -> dict[str, Any]:
        """Mesh statistics."""
        with self._lock:
            total_validations = self._total_validations
            total_votes = self._total_votes
            settled = self._total_settled
            pending = self._pending_assignment_count_locked()
        pending_settlements = (
            0
            if self._settlement_store is None
            else self._settlement_store.pending_count()
        )
        settlement_storage = (
            {"enabled": False, "backend": None, "pending": 0}
            if self._settlement_store is None
            else {
                "enabled": True,
                "pending": pending_settlements,
                **self._settlement_store.describe(),
            }
        )
        with self._lock:
            return {
                "agents": len(self._agents),
                "constitutional_hash": self.constitutional_hash,
                "total_validations": total_validations,
                "settled": settled,
                "pending": pending,
                "pending_settlements": pending_settlements,
                "total_votes": total_votes,
                "settlement_storage": settlement_storage,
                "avg_reputation": (
                    sum(a.reputation for a in self._agents.values()) / len(self._agents)
                    if self._agents
                    else 0.0
                ),
            }

    # -- Manifold integration ----------------------------------------------

    @property
    def trust_matrix(self) -> tuple[tuple[float, ...], ...] | None:
        """The projected trust matrix, or None if manifold integration is disabled."""
        with self._lock:
            if self._manifold is None:
                return None
            return self._manifold.trust_matrix

    def manifold_summary(self) -> dict[str, Any] | None:
        """Manifold statistics, or None if manifold disabled."""
        with self._lock:
            if self._manifold is None:
                return None
            return {
                "manifold_type": self._manifold_type,
                **self._manifold.summary(),
            }

    def shadow_metrics_summary(self) -> dict[str, Any] | None:
        """Aggregate shadow manifold metrics, or None when shadow mode is inactive."""
        with self._lock:
            metrics = getattr(self, "_shadow_metrics", None)
            if not metrics:
                return None
            return {
                "count": len(metrics),
                "birkhoff_variance": _summarize_metric(metrics, "birkhoff_variance"),
                "spectral_variance": _summarize_metric(metrics, "spectral_variance"),
                "birkhoff_spectral_norm": _summarize_metric(
                    metrics, "birkhoff_spectral_norm"
                ),
                "spectral_spectral_norm": _summarize_metric(
                    metrics, "spectral_spectral_norm"
                ),
            }

    def _select_peers(
        self,
        available: list[str],
        needed: int,
        producer_id: str,
    ) -> list[str]:
        """Select peers, optionally weighted by manifold trust.

        When ``_use_manifold`` is True and the manifold is converged,
        peer selection is weighted by the manifold trust vector from the
        producer to each candidate.  One slot is always filled by random
        selection (exploration) to prevent permanent exclusion of
        low-trust peers.

        Falls back to uniform random sampling when the manifold is
        disabled, not yet converged, or the producer is not indexed.
        """
        return self._select_peers_unlocked(
            available,
            needed,
            producer_id,
            trust_raw=self._copy_raw_trust_locked(),
        )

    def _sample_weighted_peers(
        self,
        available: list[str],
        needed: int,
        weight_map: dict[str, float],
        *,
        rng: random.Random | random.SystemRandom | None = None,
    ) -> list[str]:
        selection_rng = self._rng if rng is None else rng
        if needed >= len(available):
            return list(available)

        # Single-peer case: use weighted selection directly (no exploration slot)
        if needed == 1:
            return [
                self._weighted_pick(
                    available,
                    [weight_map[a] for a in available],
                    rng=selection_rng,
                )
            ]

        # Reserve 1 slot for pure random (exploration) to prevent
        # permanent exclusion of low-trust peers.
        random_pick = selection_rng.choice(available)
        selected = {random_pick}

        # Fill remaining slots via weighted sampling (without replacement)
        remaining_needed = needed - 1
        remaining_pool = [a for a in available if a not in selected]
        remaining_weights = [weight_map[a] for a in remaining_pool]

        for _ in range(remaining_needed):
            if not remaining_pool:
                break
            total = sum(remaining_weights)
            if total <= 0:
                pick = selection_rng.choice(remaining_pool)
                pick_idx = remaining_pool.index(pick)
            else:
                r = selection_rng.random() * total
                cumulative = 0.0
                pick_idx = len(remaining_pool) - 1
                pick = remaining_pool[pick_idx]
                for j, w in enumerate(remaining_weights):
                    cumulative += w
                    if cumulative >= r:
                        pick_idx = j
                        pick = remaining_pool[j]
                        break
            selected.add(pick)
            # O(1) removal via swap-and-pop (order within remaining_pool does
            # not matter — weighted selection re-evaluates the whole pool each
            # iteration).
            last = len(remaining_pool) - 1
            if pick_idx != last:
                remaining_pool[pick_idx] = remaining_pool[last]
                remaining_weights[pick_idx] = remaining_weights[last]
            remaining_pool.pop()
            remaining_weights.pop()

        return list(selected)

    def _weighted_pick(
        self,
        pool: list[str],
        weights: list[float],
        *,
        rng: random.Random | random.SystemRandom | None = None,
    ) -> str:
        """Pick one item from pool with probability proportional to weights."""
        selection_rng = self._rng if rng is None else rng
        total = sum(weights)
        if total <= 0:
            return selection_rng.choice(pool)
        r = selection_rng.random() * total
        cumulative = 0.0
        for j, w in enumerate(weights):
            cumulative += w
            if cumulative >= r:
                return pool[j]
        return pool[-1]

    _TRUST_ARCHIVE_MAX: int = 1000
    _TRUST_DECAY_RATE: float = 0.05  # fraction lost per re-join round

    def _sync_trust_aliases(self) -> None:
        """Expose read-compatible aliases while `_TrustState` remains authoritative."""
        self._agent_indices = self._trust_state.indices
        self._trust_store = self._trust_state.values
        self._trust_archive = self._trust_state.archive

    def raw_trust_snapshot(self) -> TrustSnapshot:
        """Return a detached ID-addressable snapshot of canonical raw trust."""
        with self._lock:
            return self._trust_state.raw_snapshot()

    def update_trust(self, updates: list[tuple[str, str, float]]) -> None:
        """Apply one ID-keyed trust batch and advance one logical trust round."""
        with self._lock:
            shadow = self._synchronized_shadow_manifold_locked()
            self._trust_state.apply_updates(updates)
            self._sync_trust_aliases()
            indices = self._agent_indices
            indexed = [(indices[a], indices[b], delta) for a, b, delta in updates]
            if self._manifold is not None:
                batch = getattr(self._manifold, "update_trust_batch", None)
                if batch is not None:
                    batch(indexed)
                else:
                    for from_index, to_index, delta in indexed:
                        self._manifold.update_trust(from_index, to_index, delta)
                    self._manifold.project()
            if shadow is not None:
                shadow.update_trust_batch(indexed)
            if updates:
                self._state_generation += 1

    def _synchronized_shadow_manifold_locked(
        self,
    ) -> spectral_sphere_mod.SpectralSphereManifold | None:
        """Repair a stale shadow dimension before applying the next trust batch."""
        shadow = getattr(self, "_shadow_manifold", None)
        expected_size = len(self._agent_indices)
        if shadow is None or shadow.num_agents == expected_size:
            return shadow
        logger.error(
            "Shadow manifold dimension mismatch; rebuilding from canonical trust",
            extra={
                "shadow_agents": shadow.num_agents,
                "expected_agents": expected_size,
            },
        )
        rebuilt = cast(
            "spectral_sphere_mod.SpectralSphereManifold",
            self._build_manifold(expected_size, "spectral"),
        )
        self._restore_manifold_snapshot(rebuilt)
        self._shadow_manifold = rebuilt
        return rebuilt

    def advance_trust_rounds(self, count: int) -> None:
        """Advance logical trust rounds without using wall-clock time."""
        with self._lock:
            self._trust_state.advance_rounds(count)

    def _rebuild_manifold(self) -> None:
        """Rebuild the manifold with the current number of agents, preserving trust state."""
        n = len(self._agent_indices)
        if n == 0:
            self._manifold = None
            if self._shadow_spectral:
                self._shadow_manifold = None
            return
        self._manifold = self._build_manifold(n, self._manifold_type)
        self._restore_manifold_snapshot(self._manifold)
        if self._shadow_spectral:
            # "spectral" always yields a SpectralSphereManifold (the shadow's type).
            self._shadow_manifold = cast(
                "spectral_sphere_mod.SpectralSphereManifold",
                self._build_manifold(n, "spectral"),
            )
            self._restore_manifold_snapshot(self._shadow_manifold)

    def _restore_manifold_snapshot(
        self,
        manifold: GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold,
    ) -> None:
        matrix = [list(row) for row in self._trust_state.raw_snapshot().matrix]
        replace_raw = getattr(manifold, "replace_raw_trust", None)
        if replace_raw is not None:
            replace_raw(matrix)
        else:
            manifold._raw_trust = matrix
            manifold.project()

    def _build_manifold(
        self,
        n: int,
        manifold_type: Literal["birkhoff", "spectral"],
    ) -> GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold:
        """Instantiate the configured manifold type lazily."""
        if manifold_type == "spectral":
            import constitutional_swarm.spectral_sphere as spectral_sphere_mod_local

            return spectral_sphere_mod_local.SpectralSphereManifold(num_agents=n, r=1.0)
        from constitutional_swarm.manifold import GovernanceManifold

        return GovernanceManifold(n)

    # -- Internal ----------------------------------------------------------

    def _maybe_settle_reputations(self, assignment_id: str) -> None:
        """Update reputations when quorum is reached.

        Tracks which voters have already been reputation-adjusted via
        _settled_voters to prevent double-application. Late voters
        arriving after quorum are individually adjusted on arrival.
        Manifold updates are applied exactly once at first settlement.
        """
        result = self.get_result(assignment_id)
        if not result.quorum_met:
            return

        votes = self._votes.get(assignment_id, [])
        majority_approved = result.accepted
        first_settlement = assignment_id not in self._settled_assignments

        settled_voters = self._settled_voters.setdefault(assignment_id, set())

        for vote in votes:
            if vote.voter_id in settled_voters:
                continue
            settled_voters.add(vote.voter_id)
            agent = self._agents.get(vote.voter_id)
            if agent is None:
                continue
            if vote.approved == majority_approved:
                agent.reputation = min(2.0, agent.reputation + 0.01)
            else:
                agent.reputation = max(0.0, agent.reputation - 0.05)
            self._state_generation += 1

        if first_settlement:
            self._settled_assignments.add(assignment_id)
            if self._manifold is not None:
                assignment = self._assignments[assignment_id]
                updates = [
                    (
                        assignment.producer_id,
                        vote.voter_id,
                        0.1 if vote.approved == majority_approved else -0.5,
                    )
                    for vote in votes
                    if vote.voter_id in self._agent_indices
                ]
                if assignment.producer_id in self._agent_indices and updates:
                    self.update_trust(updates)
                    shadow = getattr(self, "_shadow_manifold", None)
                    if shadow is not None:
                        self._shadow_metrics.append(
                            {
                                "assignment_id": assignment_id,
                                "birkhoff_variance": _trust_variance(
                                    self._manifold.trust_matrix
                                ),
                                "spectral_variance": _trust_variance(
                                    shadow.trust_matrix
                                ),
                                "birkhoff_spectral_norm": _matrix_spectral_norm(
                                    self._manifold.trust_matrix
                                ),
                                "spectral_spectral_norm": _matrix_spectral_norm(
                                    shadow.trust_matrix
                                ),
                            }
                        )

    def _maybe_finalize_result(self, assignment_id: str) -> bool:
        """Return whether the first quorum-reaching result should be frozen."""
        with self._lock:
            if assignment_id in self._final_results:
                return False
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                return False
            return self._preview_result(assignment).quorum_met

    def _preview_result(self, assignment: PeerAssignment) -> MeshResult:
        """Compute the current non-final view of an assignment."""
        self._require_current_assignment_constitution(assignment)
        votes = self._votes.get(assignment.assignment_id, [])
        votes_for = sum(1 for v in votes if v.approved)
        votes_against = sum(1 for v in votes if not v.approved)
        total_peers = len(assignment.peers)
        pending = total_peers - len(votes)

        accepted, rejected = self._settlement_outcomes(
            assignment, votes_for=votes_for, votes_against=votes_against
        )
        quorum_met = accepted or rejected
        if pending:
            quorum_met = False

        return MeshResult(
            assignment_id=assignment.assignment_id,
            accepted=accepted,
            votes_for=votes_for,
            votes_against=votes_against,
            quorum_met=quorum_met,
            pending_votes=pending,
            constitutional_hash=assignment.constitutional_hash,
            proof=None,
            vote_envelopes=tuple(
                self._vote_envelopes.get(assignment.assignment_id, ())
            ),
            settled=False,
            settled_at=None,
            signed_assignment=assignment.signed_assignment,
        )

    def _settlement_outcomes(
        self,
        assignment: PeerAssignment,
        *,
        votes_for: int,
        votes_against: int,
    ) -> tuple[bool, bool]:
        """Return mutually exclusive outcomes using the actual assigned peer set."""
        strict_majority = len(assignment.peers) // 2 + 1
        quorum = self._effective_quorum(assignment)
        accepted = votes_for >= quorum and votes_for >= strict_majority
        rejected = votes_against >= quorum and votes_against >= strict_majority
        return accepted, rejected

    def _effective_quorum(self, assignment: PeerAssignment) -> int:
        """Return the signed quorum floor for the actual assigned electorate."""
        if assignment.quorum:
            return assignment.quorum
        return max(self._quorum, len(assignment.peers) // 2 + 1)

    def _verify_envelope_assignment_metadata(
        self, envelope: VoteEnvelope, assignment: PeerAssignment
    ) -> None:
        """Bind one signed response to the mesh's complete assignment metadata."""
        if assignment.signed_assignment is None:
            raise ValueError("signed assignment evidence is required")
        if (
            envelope.protocol_version != 3
            or envelope.assignment_digest
            != signed_assignment_digest(assignment.signed_assignment)
            or
            envelope.assigned_peer_count != len(assignment.peers)
            or envelope.assigned_peers_hash
            != canonical_assigned_peers_hash(assignment.peers)
            or envelope.quorum != self._effective_quorum(assignment)
            or envelope.evidence_mode != self._assignment_evidence_mode(assignment)
        ):
            raise ValueError("vote envelope electorate metadata does not match assignment")

    def _build_proof(
        self,
        assignment: PeerAssignment,
        *,
        accepted: bool,
        timestamp: float,
    ) -> MeshProof:
        """Build a stable proof snapshot for a settled assignment."""
        envelopes = tuple(self._vote_envelopes.get(assignment.assignment_id, ()))
        ordered = tuple(sorted(envelopes, key=lambda item: (item.voter_id, item.key_id)))
        vote_hashes = tuple(vote_envelope_hash(item) for item in ordered)
        root_hash = compute_vote_envelope_root(
            task_id=assignment.task_id,
            assignment_id=assignment.assignment_id,
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            accepted=accepted,
            envelopes=ordered,
        )
        return MeshProof(
            assignment_id=assignment.assignment_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            vote_hashes=vote_hashes,
            root_hash=root_hash,
            accepted=accepted,
            timestamp=timestamp,
            task_id=assignment.task_id,
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            protocol_version=2,
        )

    def _persist_settlement(
        self, assignment: PeerAssignment, result: MeshResult
    ) -> None:
        """Append a settled assignment/result snapshot to disk when configured."""
        votes = list(self._votes.get(assignment.assignment_id, []))
        self._persist_settlement_record(
            self._build_settlement_record(assignment, result),
            votes=votes,
        )

    def _persist_settlement_record(
        self,
        record: SettlementRecord,
        *,
        votes: list[Any],
    ) -> None:
        """Append a pre-built settlement record when configured.

        When a store is configured, also emit a v0.1 receipt bound to the
        protocol settlement digest. Receipt write happens first so a settlement
        is never marked as having verifiable evidence unless the receipt exists.
        """
        if self._settlement_store is None:
            return
        from cryptography.hazmat.primitives import serialization

        from constitutional_swarm.governance_receipts import (
            GovernanceReceiptBundle,
            SignatureRecord,
            build_receipt,
            payload_canonical_bytes,
            receipt_from_mesh_settlement,
        )
        from constitutional_swarm.settlement_evidence import (
            RECEIPT_SIGNER_KEY_ID,
            committed_receipt_index,
            evidence_lock,
            receipt_path_for,
            store_filesystem_path,
            write_receipt_atomic,
        )

        assignment_id = str(record.assignment["assignment_id"])
        try:
            completed_record = self._record_with_serialized_votes(record, votes)
            unsigned = receipt_from_mesh_settlement(
                completed_record,
                list(completed_record.votes),
                trusted_signers=self.receipt_trust_registry(),
                require_independent_votes=self._evidence_mode != "single_operator_dev",
            )
            payload_bytes = payload_canonical_bytes(unsigned.payload)
            signing_key = self._receipt_signing_private_key
            signing_public = self._receipt_signing_public_key
            signature = signing_key.sign(payload_bytes)
            public_hex = signing_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
            receipt = build_receipt(
                payload=unsigned.payload,
                signatures=[
                    SignatureRecord(
                        key_id=RECEIPT_SIGNER_KEY_ID,
                        algorithm="ed25519",
                        public_key_hex=public_hex,
                        signature_hex=signature.hex(),
                    )
                ],
            )
        except Exception as exc:
            raise SettlementPersistenceError(
                f"Settlement {assignment_id} receipt could not be built"
            ) from exc
        bound = replace(completed_record, receipt_digest=receipt.payload_digest)
        if store_filesystem_path(self._settlement_store) is None:
            # In-memory adapters have no receipt file; still persist the pointer.
            self._settlement_store.append(bound)
            return
        receipt_path = receipt_path_for(self._settlement_store, assignment_id)
        with evidence_lock(self._settlement_store):
            referenced = committed_receipt_index(self._settlement_store)
            if assignment_id in referenced:
                # A committed pointer already exists. Do not replace the file.
                self._settlement_store.append(bound)
                return
            try:
                write_receipt_atomic(
                    receipt_path,
                    GovernanceReceiptBundle(receipts=[receipt]),
                )
                self._maybe_crash("after-receipt")
            except Exception as exc:
                raise SettlementPersistenceError(
                    f"Settlement {assignment_id} receipt could not be persisted"
                ) from exc
            try:
                self._settlement_store.append(bound)
            except Exception:
                still_referenced = committed_receipt_index(self._settlement_store)
                if assignment_id not in still_referenced:
                    receipt_path.unlink(missing_ok=True)
                raise

    def _receipt_bundle_path(self, assignment_id: str) -> Path:
        from constitutional_swarm.settlement_evidence import receipt_path_for

        if self._settlement_store is None:
            return Path(f"mesh-settlements.jsonl.{assignment_id}.receipt.json")
        return receipt_path_for(self._settlement_store, assignment_id)

    def _load_settlements(self) -> None:
        """Load settled assignments/results from disk when configured."""
        if self._settlement_store is None:
            return

        for record in self._settlement_store.load_all():
            assignment = self._deserialize_assignment(record.assignment)
            assignment = replace(assignment, is_recovered=True)
            result = self._deserialize_result(record.result)
            if not self._stored_record_is_current(record, assignment, result):
                continue
            try:
                envelopes, result = self._verified_settlement_evidence(
                    record, assignment, result
                )
            except (TypeError, ValueError):
                logger.warning(
                    "quarantining settlement %s without authorized vote evidence",
                    assignment.assignment_id,
                )
                continue
            self._assignments[assignment.assignment_id] = assignment
            self._vote_envelopes[assignment.assignment_id] = list(envelopes)
            self._votes.setdefault(assignment.assignment_id, [])
            self._remember_final_result_locked(assignment.assignment_id, result)
            self._total_validations += 1
            self._total_settled += 1

    def _stored_record_is_current(
        self,
        record: SettlementRecord,
        assignment: PeerAssignment,
        result: MeshResult,
    ) -> bool:
        """Validate stored hash tags and classify active versus historical records."""
        tags = {
            record.constitutional_hash,
            assignment.constitutional_hash,
            result.constitutional_hash,
        }
        if "" in tags or len(tags) != 1:
            raise ValueError("Persisted settlement constitutional hash tags disagree")
        if result.proof is not None and result.proof.constitutional_hash not in tags:
            raise ValueError("Persisted settlement proof constitutional hash disagrees")
        return assignment.constitutional_hash == self.constitutional_hash

    def _verified_settlement_evidence(
        self,
        record: SettlementRecord,
        assignment: PeerAssignment,
        result: MeshResult,
    ) -> tuple[tuple[VoteEnvelope, ...], MeshResult]:
        """Verify schema-v2 voter evidence and recompute every derived result field."""
        if record.schema_version != 2:
            raise ValueError("proof-grade mesh settlement requires schema version 2")
        if not record.votes:
            raise ValueError("mesh settlement has no vote envelopes")
        if assignment.signed_assignment is None:
            raise ValueError("proof-grade mesh settlement requires signed assignment")
        if (
            assignment.signed_assignment.assigner_id != self._assigner_id
            or assignment.signed_assignment.key_id != self._assigner_key_id
        ):
            raise ValueError("signed assignment does not match mesh assignment authority")
        verify_signed_assignment(
            assignment.signed_assignment,
            self._assigner_trust_root,
            task_id=assignment.task_id,
            assignment_id=assignment.assignment_id,
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
        )
        envelopes = verify_assignment_vote_envelopes(
            assignment.signed_assignment,
            record.votes,
            self._vote_registry,
            task_id=assignment.task_id,
            assignment_id=assignment.assignment_id,
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            expected_assigned_peers=assignment.peers,
            expected_quorum=self._effective_quorum(assignment),
            require_independent=self._evidence_mode != "single_operator_dev",
        )
        for envelope in envelopes:
            self._verify_envelope_assignment_metadata(envelope, assignment)
        assigned = {normalize_voter_id(peer) for peer in assignment.peers}
        if any(item.voter_id not in assigned for item in envelopes):
            raise ValueError("mesh settlement contains an unassigned voter")
        if self._complete_evidence and len(envelopes) != len(assignment.peers):
            raise ValueError("complete-evidence settlement is missing peer votes")

        votes_for = sum(item.approved for item in envelopes)
        votes_against = len(envelopes) - votes_for
        accepted, rejected = self._settlement_outcomes(
            assignment, votes_for=votes_for, votes_against=votes_against
        )
        if accepted == rejected:
            raise ValueError("mesh settlement has no unique quorum outcome")
        proof = result.proof
        envelope_hashes = tuple(
            vote_envelope_hash(item)
            for item in sorted(envelopes, key=lambda item: (item.voter_id, item.key_id))
        )
        if (
            result.assignment_id != assignment.assignment_id
            or result.votes_for != votes_for
            or result.votes_against != votes_against
            or result.pending_votes != len(assignment.peers) - len(envelopes)
            or result.accepted != accepted
            or not result.quorum_met
            or proof is None
            or proof.protocol_version != 2
            or proof.assignment_id != assignment.assignment_id
            or proof.task_id != assignment.task_id
            or proof.producer_id != assignment.producer_id
            or proof.artifact_id != assignment.artifact_id
            or proof.content_hash != assignment.content_hash
            or proof.constitutional_hash != assignment.constitutional_hash
            or proof.accepted != accepted
            or proof.vote_hashes != envelope_hashes
            or not proof.verify()
        ):
            raise ValueError("mesh settlement disagrees with verified vote envelopes")
        return envelopes, replace(
            result,
            vote_envelopes=envelopes,
            signed_assignment=assignment.signed_assignment,
        )

    def reconcile_pending_settlements(self) -> ReconciliationReport:
        """Replay durable pending settlements into the primary store once."""
        backend = self._describe_settlement_backend()
        if self._settlement_store is None:
            logger.info(
                "Pending settlement reconciliation started",
                extra={"settlement_backend": backend, "pending_records": 0},
            )
            report = ReconciliationReport()
            logger.info(
                "Pending settlement reconciliation completed",
                extra={"settlement_backend": backend, **report.as_log_fields()},
            )
            return report

        pending_records = self._settlement_store.load_pending()
        logger.info(
            "Pending settlement reconciliation started",
            extra={
                "settlement_backend": backend,
                "pending_records": len(pending_records),
            },
        )
        report = ReconciliationReport()

        for record in pending_records:
            assignment_id = str(record.assignment.get("assignment_id", "<unknown>"))
            errors = list(report.errors)
            try:
                assignment = self._deserialize_assignment(record.assignment)
                assignment = replace(assignment, is_recovered=record.is_recovered)
                result = self._deserialize_result(record.result)
                with self._lock:
                    if not self._stored_record_is_current(record, assignment, result):
                        report = replace(
                            report,
                            skipped_constitution=report.skipped_constitution + 1,
                        )
                        continue
                    reconciliation_fence = self._constitution_fence_locked()
                    existing_assignment = self._assignments.get(
                        assignment.assignment_id
                    )
                    if assignment.is_recovered or (
                        existing_assignment is not None
                        and existing_assignment.is_recovered
                    ):
                        self._settlement_store.clear_pending(assignment.assignment_id)
                        report = replace(
                            report,
                            skipped_recovered=report.skipped_recovered + 1,
                            errors=errors,
                        )
                        continue
                envelopes, result = self._verified_settlement_evidence(
                    record, assignment, result
                )
                recovered_votes = list(envelopes)

                report = replace(
                    report,
                    attempted=report.attempted + 1,
                    errors=errors,
                )
                durable_record = self._build_settlement_record(
                    replace(assignment, is_recovered=True),
                    result,
                )
                expected_durable = self._expected_durable_record(
                    durable_record,
                    votes=recovered_votes,
                )
                existing_durable = self._durable_settlement(assignment.assignment_id)
                if existing_durable is None:
                    try:
                        self._persist_settlement_record(
                            durable_record,
                            votes=recovered_votes,
                        )
                    except DuplicateSettlementError:
                        pass
                    existing_durable = self._durable_settlement(
                        assignment.assignment_id
                    )
                self._require_matching_durable_settlement(
                    expected_durable,
                    existing_durable,
                )
                with self._lock:
                    if not self._constitution_fence_matches_locked(reconciliation_fence):
                        # Phase 2 is durable history, but it must not become active
                        # state after crossing a constitution rotation. Keep the
                        # now-foreign pending marker for the stale-record policy.
                        report = replace(
                            report,
                            skipped_constitution=report.skipped_constitution + 1,
                            errors=errors,
                        )
                        continue
                    current_assignment = self._assignments.get(assignment.assignment_id)
                    if current_assignment is None:
                        self._assignments[assignment.assignment_id] = replace(
                            assignment,
                            is_recovered=True,
                            content="",
                        )
                        self._total_validations += 1
                    elif not current_assignment.is_recovered:
                        self._assignments[assignment.assignment_id] = replace(
                            current_assignment,
                            is_recovered=True,
                            content="",
                        )
                    if assignment.assignment_id not in self._final_results:
                        self._remember_final_result_locked(assignment.assignment_id, result)
                    self._vote_envelopes[assignment.assignment_id] = list(envelopes)
                    self._votes.pop(assignment.assignment_id, None)
                    self._settled_assignments.discard(assignment.assignment_id)
                    self._settled_voters.pop(assignment.assignment_id, None)
                    self._total_settled += 1
                self._settlement_store.clear_pending(assignment.assignment_id)
                report = replace(
                    report,
                    settled=report.settled + 1,
                    errors=errors,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                errors.append(f"{assignment_id}: {exc}")
                report = replace(
                    report,
                    failed=report.failed + 1,
                    errors=errors,
                )

        logger.info(
            "Pending settlement reconciliation completed",
            extra={"settlement_backend": backend, **report.as_log_fields()},
        )
        return report

    def _expected_durable_record(
        self,
        record: SettlementRecord,
        *,
        votes: list[Any],
    ) -> SettlementRecord:
        """Return the exact immutable record produced by successful Phase 2."""
        from constitutional_swarm.governance_receipts import (
            receipt_from_mesh_settlement,
        )

        completed_record = self._record_with_serialized_votes(record, votes)
        receipt = receipt_from_mesh_settlement(
            completed_record,
            list(completed_record.votes),
            trusted_signers=self.receipt_trust_registry(),
            require_independent_votes=self._evidence_mode != "single_operator_dev",
        )
        return replace(completed_record, receipt_digest=receipt.payload_digest)

    def _record_with_serialized_votes(
        self,
        record: SettlementRecord,
        votes: list[Any],
    ) -> SettlementRecord:
        """Install the exact authenticated vote evidence used by receipts."""
        return replace(record, votes=self._vote_dicts(votes))

    def _durable_settlement(self, assignment_id: str) -> SettlementRecord | None:
        """Load one durable settlement by identity and reject duplicate history."""
        if self._settlement_store is None:
            return None
        matches = [
            record
            for record in self._settlement_store.load_all()
            if str(record.assignment.get("assignment_id", "")) == assignment_id
        ]
        if len(matches) > 1:
            raise ValueError(
                f"Durable settlement {assignment_id} appears more than once"
            )
        return matches[0] if matches else None

    @staticmethod
    def _require_matching_durable_settlement(
        expected: SettlementRecord,
        existing: SettlementRecord | None,
    ) -> None:
        """Fail closed unless an existing Phase-2 record is byte-semantically equal."""
        assignment_id = str(expected.assignment.get("assignment_id", "<unknown>"))
        if existing is None:
            raise ValueError(
                f"Durable settlement {assignment_id} disappeared after duplicate append"
            )
        if existing != expected:
            raise ValueError(
                f"Durable settlement {assignment_id} conflicts with pending snapshot"
            )

    def retry_pending_settlements(self) -> ReconciliationReport:
        """Backward-compatible alias for pending settlement reconciliation."""
        return self.reconcile_pending_settlements()

    def _describe_settlement_backend(self) -> str | None:
        """Return the configured settlement backend for structured logs."""
        if self._settlement_store is None:
            return None
        return str(self._settlement_store.describe().get("backend"))

    def _maybe_crash(self, point: str) -> None:
        if getattr(self, "_settle_crash_point", None) == point:
            os._exit(17)

    def _public_key_hex(self, voter_id: str) -> str | None:
        public_key = self._agent_vote_public_keys.get(voter_id)
        if public_key is None:
            return None
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def receipt_trust_registry(self) -> dict[str, dict[str, Any]]:
        """Export public grants without mutating the mesh trust registry.

        A verifier must obtain and pin these grants through an external trust
        channel. The signer's own export is not itself an attestation.
        """
        from constitutional_swarm.settlement_evidence import RECEIPT_SIGNER_KEY_ID

        grants: dict[str, dict[str, Any]] = self._vote_registry.trust_grants(
            role="validator"
        )
        grants.update(self._assigner_trust_root.trust_grants(role="assigner"))
        with self._lock:
            receipt_public = self._receipt_signing_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
        grants[RECEIPT_SIGNER_KEY_ID] = {
            "identity_id": "mesh-settlement",
            "public_key_hex": receipt_public,
            "roles": ["settlement"],
        }
        return grants

    def _vote_dicts(self, votes: list[Any]) -> tuple[dict[str, Any], ...]:
        from constitutional_swarm.mesh.vote_envelope import vote_envelope_to_dict

        payload: list[dict[str, Any]] = []
        for vote in votes:
            if isinstance(vote, VoteEnvelope):
                payload.append(vote_envelope_to_dict(vote))
                continue
            if isinstance(vote, dict):
                item = dict(vote)
                if not item.get("public_key_hex"):
                    item["public_key_hex"] = self._public_key_hex(str(item.get("voter_id", "")))
                payload.append(item)
                continue
            payload.append(
                {
                    "assignment_id": vote.assignment_id,
                    "voter_id": vote.voter_id,
                    "approved": vote.approved,
                    "reason": vote.reason,
                    "signature": vote.signature,
                    "constitutional_hash": vote.constitutional_hash,
                    "content_hash": vote.content_hash,
                    "timestamp": vote.timestamp,
                    "public_key_hex": self._public_key_hex(vote.voter_id),
                }
            )
        return tuple(payload)

    def _build_settlement_record(
        self, assignment: PeerAssignment, result: MeshResult
    ) -> SettlementRecord:
        return SettlementRecord(
            assignment=self._serialize_assignment(assignment),
            result=self._serialize_result(result),
            constitutional_hash=assignment.constitutional_hash,
            is_recovered=assignment.is_recovered,
            schema_version=2,
        )

    def _serialize_assignment(self, assignment: PeerAssignment) -> dict[str, Any]:
        return {
            "assignment_id": assignment.assignment_id,
            "task_id": assignment.task_id,
            "producer_id": assignment.producer_id,
            "artifact_id": assignment.artifact_id,
            "content_hash": assignment.content_hash,
            "peers": list(assignment.peers),
            "assigned_peers_hash": canonical_assigned_peers_hash(assignment.peers),
            "assigned_peer_count": len(assignment.peers),
            "quorum": self._effective_quorum(assignment),
            "evidence_mode": self._assignment_evidence_mode(assignment),
            "constitutional_hash": assignment.constitutional_hash,
            "timestamp": assignment.timestamp,
            "is_recovered": assignment.is_recovered,
            "signed_assignment": (
                signed_assignment_to_dict(assignment.signed_assignment)
                if assignment.signed_assignment is not None
                else None
            ),
        }

    @staticmethod
    def _deserialize_assignment(data: dict[str, Any]) -> PeerAssignment:
        required_metadata = {
            "assigned_peers_hash",
            "assigned_peer_count",
            "quorum",
            "evidence_mode",
            "signed_assignment",
        }
        missing = required_metadata - data.keys()
        if missing:
            raise ValueError(
                f"Persisted settlement assignment missing {sorted(missing)[0]}"
            )
        peers = tuple(str(peer) for peer in data["peers"])
        assigned_peer_count = data["assigned_peer_count"]
        quorum = data["quorum"]
        evidence_mode = data["evidence_mode"]
        assigned_peers_hash = data["assigned_peers_hash"]
        if (
            isinstance(assigned_peer_count, bool)
            or not isinstance(assigned_peer_count, int)
            or assigned_peer_count != len(peers)
        ):
            raise ValueError("Persisted settlement assigned_peer_count is invalid")
        if (
            not isinstance(assigned_peers_hash, str)
            or assigned_peers_hash != canonical_assigned_peers_hash(peers)
        ):
            raise ValueError("Persisted settlement assigned_peers_hash is invalid")
        if (
            isinstance(quorum, bool)
            or not isinstance(quorum, int)
            or quorum <= len(peers) // 2
            or quorum > len(peers)
        ):
            raise ValueError("Persisted settlement quorum is invalid")
        if evidence_mode not in {"independent", "single_operator_dev"}:
            raise ValueError("Persisted settlement evidence_mode is invalid")
        signed_data = data["signed_assignment"]
        if not isinstance(signed_data, dict):
            raise ValueError("Persisted settlement signed_assignment is invalid")
        signed_assignment = signed_assignment_from_dict(signed_data)
        return PeerAssignment(
            assignment_id=str(data["assignment_id"]),
            producer_id=str(data["producer_id"]),
            artifact_id=str(data["artifact_id"]),
            content=str(data.get("content", "")),
            content_hash=str(data["content_hash"]),
            peers=peers,
            constitutional_hash=str(data["constitutional_hash"]),
            timestamp=float(data["timestamp"]),
            task_id=str(data.get("task_id", data["artifact_id"])),
            is_recovered=bool(data.get("is_recovered", False)),
            assigned_peers_hash=assigned_peers_hash,
            assigned_peer_count=assigned_peer_count,
            quorum=quorum,
            evidence_mode=evidence_mode,
            signed_assignment=signed_assignment,
        )

    @staticmethod
    def _serialize_proof(proof: MeshProof | None) -> dict[str, Any] | None:
        if proof is None:
            return None
        return {
            "assignment_id": proof.assignment_id,
            "content_hash": proof.content_hash,
            "constitutional_hash": proof.constitutional_hash,
            "vote_hashes": list(proof.vote_hashes),
            "root_hash": proof.root_hash,
            "accepted": proof.accepted,
            "timestamp": proof.timestamp,
            "task_id": proof.task_id,
            "producer_id": proof.producer_id,
            "artifact_id": proof.artifact_id,
            "protocol_version": proof.protocol_version,
        }

    @staticmethod
    def _deserialize_proof(data: dict[str, Any] | None) -> MeshProof | None:
        if data is None:
            return None
        if "protocol_version" not in data:
            raise ValueError("persisted mesh proof is missing protocol_version")
        return MeshProof(
            assignment_id=str(data["assignment_id"]),
            content_hash=str(data["content_hash"]),
            constitutional_hash=str(data["constitutional_hash"]),
            vote_hashes=tuple(str(vote_hash) for vote_hash in data["vote_hashes"]),
            root_hash=str(data["root_hash"]),
            accepted=bool(data["accepted"]),
            timestamp=float(data["timestamp"]),
            task_id=str(data.get("task_id", "")),
            producer_id=str(data.get("producer_id", "")),
            artifact_id=str(data.get("artifact_id", "")),
            protocol_version=int(data["protocol_version"]),
        )

    def _serialize_result(self, result: MeshResult) -> dict[str, Any]:
        return {
            "assignment_id": result.assignment_id,
            "accepted": result.accepted,
            "votes_for": result.votes_for,
            "votes_against": result.votes_against,
            "quorum_met": result.quorum_met,
            "pending_votes": result.pending_votes,
            "constitutional_hash": result.constitutional_hash,
            "proof": self._serialize_proof(result.proof),
            "settled": result.settled,
            "settled_at": result.settled_at,
            "vote_envelopes": [
                vote_envelope_to_dict(item) for item in result.vote_envelopes
            ],
            "signed_assignment": (
                signed_assignment_to_dict(result.signed_assignment)
                if result.signed_assignment is not None
                else None
            ),
        }

    def _deserialize_result(self, data: dict[str, Any]) -> MeshResult:
        signed_data = data.get("signed_assignment")
        return MeshResult(
            assignment_id=str(data["assignment_id"]),
            accepted=bool(data["accepted"]),
            votes_for=int(data["votes_for"]),
            votes_against=int(data["votes_against"]),
            quorum_met=bool(data["quorum_met"]),
            pending_votes=int(data["pending_votes"]),
            constitutional_hash=str(data["constitutional_hash"]),
            proof=self._deserialize_proof(data.get("proof")),
            vote_envelopes=tuple(
                vote_envelope_from_dict(item)
                for item in data.get("vote_envelopes", [])
            ),
            settled=bool(data.get("settled", False)),
            settled_at=(
                float(data["settled_at"])
                if data.get("settled_at") is not None
                else None
            ),
            signed_assignment=(
                signed_assignment_from_dict(signed_data)
                if isinstance(signed_data, dict)
                else None
            ),
        )

    def sign_vote(
        self,
        assignment_id: str,
        voter_id: str,
        *,
        approved: bool,
        reason: str = "",
    ) -> str:
        """Create an Ed25519 vote signature for a registered voter.

        This convenience method exists for local/in-process agents and tests.
        In distributed deployments, agents should hold their own private key and
        produce the same signature client-side.
        """
        voter_id = normalize_voter_id(voter_id)
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._require_current_assignment_constitution(assignment)
            signing_key = self._agent_vote_private_keys.get(voter_id)
            if signing_key is None:
                raise UnauthorizedVoterError(
                    f"{voter_id} has no registered vote signing key"
                )
            envelope = create_vote_envelope(
                signing_key,
                voter_id=voter_id,
                task_id=assignment.task_id,
                assignment_id=assignment.assignment_id,
                producer_id=assignment.producer_id,
                artifact_id=assignment.artifact_id,
                content_hash=assignment.content_hash,
                constitutional_hash=assignment.constitutional_hash,
                decision="approved" if approved else "denied",
                reason=reason,
                nonce=uuid.uuid4().hex,
                issued_at=time.time(),
                assigned_peers=assignment.peers,
                quorum=self._effective_quorum(assignment),
                evidence_mode=self._assignment_evidence_mode(assignment),
                assignment_digest=signed_assignment_digest(
                    assignment.signed_assignment
                ) if assignment.signed_assignment is not None else "",
            )
            if len(self._signed_envelopes_by_signature) >= 10_000:
                raise MeshCapacityError("pending locally signed vote capacity reached")
            self._signed_envelopes_by_signature[envelope.signature] = envelope
            return envelope.signature

    def _assignment_evidence_mode(
        self, assignment: PeerAssignment
    ) -> Literal["independent", "single_operator_dev"]:
        """Classify signer custody for the entire assigned electorate."""
        locally_held = sum(
            peer in self._agent_vote_private_keys for peer in assignment.peers
        )
        if locally_held > 1 and self._evidence_mode != "single_operator_dev":
            raise ValueError(
                "signing for multiple assigned voter identities requires explicit "
                "evidence_mode='single_operator_dev'"
            )
        if assignment.evidence_mode is not None:
            return assignment.evidence_mode
        if self._evidence_mode == "single_operator_dev":
            return "single_operator_dev"
        return "independent"

    def sign_vote_envelope(
        self,
        assignment_id: str,
        voter_id: str,
        *,
        approved: bool,
        reason: str = "",
    ) -> VoteEnvelope:
        signature = self.sign_vote(
            assignment_id, voter_id, approved=approved, reason=reason
        )
        with self._lock:
            return self._signed_envelopes_by_signature[signature]

    def submit_vote_envelope(self, envelope: VoteEnvelope) -> ValidationVote:
        with self._lock:
            assignment = self._assignments.get(envelope.assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {envelope.assignment_id} not found")
            if envelope.voter_id not in assignment.peers:
                raise UnauthorizedVoterError(
                    f"{envelope.voter_id} is not assigned to validation "
                    f"{envelope.assignment_id}"
                )
            verify_vote_envelope(
                envelope,
                self._vote_registry,
                task_id=assignment.task_id,
                assignment_id=assignment.assignment_id,
                producer_id=assignment.producer_id,
                artifact_id=assignment.artifact_id,
                content_hash=assignment.content_hash,
                constitutional_hash=assignment.constitutional_hash,
                expected_assignment_digest=(
                    signed_assignment_digest(assignment.signed_assignment)
                    if assignment.signed_assignment is not None
                    else None
                ),
            )
            self._verify_envelope_assignment_metadata(envelope, assignment)
            self._signed_envelopes_by_signature[envelope.signature] = envelope
        try:
            return self.submit_vote(
                envelope.assignment_id,
                envelope.voter_id,
                approved=envelope.approved,
                reason=envelope.reason,
                signature=envelope.signature,
            )
        finally:
            with self._lock:
                self._signed_envelopes_by_signature.pop(envelope.signature, None)

    def get_vote_public_key(self, agent_id: str) -> str:
        """Return the registered Ed25519 public key as a hex string."""
        agent_id = normalize_voter_id(agent_id)
        with self._lock:
            public_key = self._agent_vote_public_keys.get(agent_id)
            if public_key is None:
                raise KeyError(f"Agent {agent_id} not registered")
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()

    def get_request_signing_public_key(self) -> str:
        """Return the mesh request-signing public key as a hex string."""
        return self._request_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @classmethod
    def verify_vote_signature(
        cls,
        *,
        public_key: Ed25519PublicKey | bytes | str,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
        signature: str,
        protocol_version: int = 2,
    ) -> bool:
        """Verify a detached Ed25519 vote signature."""
        key = cls._coerce_public_key(public_key)
        try:
            key.verify(
                bytes.fromhex(signature),
                cls._vote_payload_bytes(
                    assignment_id=assignment_id,
                    voter_id=voter_id,
                    approved=approved,
                    reason=reason,
                    constitutional_hash=constitutional_hash,
                    content_hash=content_hash,
                    protocol_version=protocol_version,
                ),
            )
        except (ValueError, InvalidSignature):
            return False
        return True

    @classmethod
    def build_vote_payload(
        cls,
        *,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
        protocol_version: int = 2,
    ) -> bytes:
        """Build an explicitly versioned detached vote payload."""
        return cls._vote_payload_bytes(
            assignment_id=assignment_id,
            voter_id=voter_id,
            approved=approved,
            reason=reason,
            constitutional_hash=constitutional_hash,
            content_hash=content_hash,
            protocol_version=protocol_version,
        )

    @staticmethod
    def _coerce_public_key(value: Ed25519PublicKey | bytes | str) -> Ed25519PublicKey:
        if isinstance(value, Ed25519PublicKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def _coerce_private_key(
        value: Ed25519PrivateKey | bytes | str,
    ) -> Ed25519PrivateKey:
        if isinstance(value, Ed25519PrivateKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def _vote_payload_bytes(
        *,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
        protocol_version: int,
    ) -> bytes:
        if protocol_version != 2:
            raise ValueError("unsupported detached vote payload protocol version")
        import json

        structured_payload = {
            "approved": approved,
            "assignment_id": assignment_id,
            "constitutional_hash": constitutional_hash,
            "content_hash": content_hash,
            "protocol_version": 2,
            "reason": reason,
            "voter_id": normalize_voter_id(voter_id),
        }
        return b"constitutional-swarm.detached-vote.v2\x00" + json.dumps(
            structured_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
