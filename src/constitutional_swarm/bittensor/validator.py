"""Constitutional Swarm Validator — Bittensor validator runtime.

Wraps ConstitutionalMesh + GovernanceManifold into a Bittensor-compatible
validator that:
  1. Receives miner judgments (JudgmentSynapse)
  2. Runs full mesh validation (DNA pre-check + peer votes + Merkle proof)
  3. Updates trust manifold (Sinkhorn-Knopp projection)
  4. Returns grading result with cryptographic proof (ValidationSynapse)
  5. Computes TAO emission weights from validated raw-trust signals

Bittensor SDK is NOT required — this module uses constitutional_swarm
primitives only.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from acgs_lite import Constitution

from constitutional_swarm.bittensor._validation import _validate_finite
from constitutional_swarm.bittensor.emission_calculator import (
    DEFAULT_EMISSION_WEIGHTS,
    EmissionCalculator,
    EmissionWeights,
    MinerEmissionInput,
)
from constitutional_swarm.bittensor.protocol import MinerTier, ValidatorConfig
from constitutional_swarm.bittensor.synapses import JudgmentSynapse, ValidationSynapse
from constitutional_swarm.mesh import ConstitutionalMesh, MeshResult


@dataclass
class ValidatorStats:
    """Runtime statistics for a constitutional validator."""

    validations_performed: int = 0
    judgments_accepted: int = 0
    judgments_rejected: int = 0
    total_validation_time_ms: float = 0.0
    constitution_mismatches: int = 0

    @property
    def acceptance_rate(self) -> float:
        if self.validations_performed == 0:
            return 0.0
        return self.judgments_accepted / self.validations_performed

    @property
    def avg_validation_ms(self) -> float:
        if self.validations_performed == 0:
            return 0.0
        return self.total_validation_time_ms / self.validations_performed


class UnknownMinerError(ValueError):
    """Raised when an unregistered miner submits a judgment."""


def _validate_manifold_snapshot(
    mesh_agents: set[str],
    indices: dict[str, int],
    raw_trust: tuple[tuple[float, ...], ...] | None,
    *,
    manifold_present: bool,
) -> None:
    """Reject inconsistent or unsafe trust snapshots before scoring miners."""
    for agent_id, index in indices.items():
        if type(index) is not int:
            raise ValueError(f"manifold index for {agent_id!r} must be an integer")

    size = len(indices)
    if set(indices.values()) != set(range(size)):
        raise ValueError("manifold indices must be unique and contiguous from zero")

    if not manifold_present:
        if indices:
            raise ValueError("manifold indices exist while the manifold is disabled")
        return

    if set(indices) != mesh_agents:
        raise ValueError("manifold indices must cover every registered mesh agent")
    if raw_trust is None:
        return
    if len(raw_trust) != size or any(len(row) != size for row in raw_trust):
        raise ValueError(f"manifold raw trust matrix must be square with size {size}")

    for row_index, row in enumerate(raw_trust):
        for column_index, value in enumerate(row):
            _validate_finite(
                f"manifold raw trust[{row_index}][{column_index}]",
                value,
                minimum=None,
            )


def _snapshot_mesh_emission_state(
    mesh: ConstitutionalMesh,
    requested_uids: list[str],
) -> tuple[
    set[str],
    dict[str, float],
    dict[str, int],
    tuple[tuple[float, ...], ...] | None,
    bool,
]:
    """Capture detached emission inputs under the mesh lock.

    TODO: replace this private compatibility boundary with a public
    ``ConstitutionalMesh.emission_snapshot()`` API.
    """
    with mesh._lock:
        mesh_agents = set(mesh._agents)
        reputations = {
            uid: mesh._agents[uid].reputation
            for uid in requested_uids
            if uid in mesh._agents
        }
        indices = dict(mesh._agent_indices)
        manifold = mesh._manifold
        raw = None if manifold is None else getattr(manifold, "_raw_trust", None)
        raw_trust = None if raw is None else tuple(tuple(row) for row in raw)
    return mesh_agents, reputations, indices, raw_trust, manifold is not None


def _manifold_signals(
    indices: dict[str, int],
    raw_trust: tuple[tuple[float, ...], ...] | None,
) -> dict[str, float] | None:
    """Return shifted raw column-mass signals, or None without variation."""
    if raw_trust is None or not raw_trust:
        return None
    scale = max(abs(value) for row in raw_trust for value in row)
    if scale == 0.0:
        return None
    size = len(raw_trust)
    column_mass = [
        math.fsum(row[column] / scale for row in raw_trust) / size
        for column in range(size)
    ]
    low = min(column_mass)
    if max(column_mass) == low:
        return None
    shifted = [value - low for value in column_mass]
    return {uid: shifted[index] for uid, index in indices.items()}


def _weights_without_manifold() -> EmissionWeights:
    """Redistribute the unavailable manifold coefficient proportionally."""
    weights = DEFAULT_EMISSION_WEIGHTS
    remainder = 1.0 - weights.manifold_trust
    return EmissionWeights(
        manifold_trust=0.0,
        reputation=weights.reputation / remainder,
        tier=weights.tier / remainder,
        precedent=weights.precedent / remainder,
        authenticity=weights.authenticity / remainder,
    )


class ConstitutionalValidator:
    """Bittensor validator runtime for constitutional governance subnet.

    Usage:
        validator = ConstitutionalValidator(
            config=ValidatorConfig(constitution_path="governance.yaml"),
        )
        # Register miners as mesh participants
        validator.register_miner("miner-01", domain="privacy")
        validator.register_miner("miner-02", domain="privacy")
        validator.register_miner("miner-03", domain="finance")

        # Validate a miner's judgment
        result = validator.validate(judgment_synapse)

        # Get TAO emission weights
        weights = validator.compute_emission_weights()
    """

    def __init__(self, config: ValidatorConfig) -> None:
        self._config = config
        self._constitution = Constitution.from_yaml(config.constitution_path)
        self._mesh = ConstitutionalMesh(
            self._constitution,
            peers_per_validation=config.peers_per_validation,
            quorum=config.quorum,
            use_manifold=config.use_manifold,
        )
        self._stats = ValidatorStats()
        self._stats_lock = threading.Lock()
        self._known_miners: set[str] = set()
        self._miner_tiers: dict[str, MinerTier] = {}
        self._miner_domains: dict[str, str] = {}
        self._previous_hash: str | None = None
        self._registry_lock = threading.RLock()

    @property
    def constitution_hash(self) -> str:
        with self._registry_lock:
            return self._constitution.hash

    @property
    def previous_hash(self) -> str | None:
        with self._registry_lock:
            return self._previous_hash

    def rotate_constitution(self, new_constitution: Constitution) -> None:
        """Rotate to a new constitution, preserving the old hash as a grace window.

        During the grace window, synapses matching either the current or
        previous constitution hash are accepted. Call this again to close
        the window (the previous hash advances to the now-old current hash).
        """
        with self._registry_lock:
            old_hash = self._constitution.hash
            new_mesh = ConstitutionalMesh(
                new_constitution,
                peers_per_validation=self._config.peers_per_validation,
                quorum=self._config.quorum,
                use_manifold=self._config.use_manifold,
            )
            for miner_uid in self._known_miners:
                domain = self._miner_domains.get(miner_uid, "")
                new_mesh.register_local_signer(miner_uid, domain=domain)
            self._constitution = new_constitution
            self._mesh = new_mesh
            self._previous_hash = old_hash

    @property
    def stats(self) -> ValidatorStats:
        with self._stats_lock:
            return replace(self._stats)

    @property
    def mesh(self) -> ConstitutionalMesh:
        with self._registry_lock:
            return self._mesh

    def register_miner(
        self,
        miner_uid: str,
        domain: str = "",
        tier: MinerTier = MinerTier.APPRENTICE,
    ) -> None:
        """Register a miner as a mesh participant.

        Adds the miner to the known set, mesh, tier map, and domain map.
        Only miners registered via this method may submit judgments.
        """
        with self._registry_lock:
            self._mesh.register_local_signer(miner_uid, domain=domain)
            self._known_miners.add(miner_uid)
            self._miner_tiers[miner_uid] = tier
            self._miner_domains[miner_uid] = domain

    def unregister_miner(self, miner_uid: str) -> None:
        """Remove a miner from the mesh."""
        with self._registry_lock:
            self._mesh.unregister_agent(miner_uid)
            self._known_miners.discard(miner_uid)
            self._miner_tiers.pop(miner_uid, None)
            self._miner_domains.pop(miner_uid, None)

    def validate(self, synapse: JudgmentSynapse) -> ValidationSynapse:
        """Validate a miner's governance judgment.

        Steps:
          1. Verify constitution hash matches (current or previous during rollover)
          2. Reject unknown miners (must be pre-registered)
          3. Run full mesh validation (DNA + peers + Merkle proof)
          4. Return ValidationSynapse with proof

        The mesh internally:
          a. Runs DNA pre-check on the judgment content
          b. Assigns random peers (excluding the miner — MACI)
          c. Each peer validates via their own DNA
          d. Quorum decides acceptance
          e. Generates Merkle proof
          f. Updates reputation scores
          g. Projects trust onto governance manifold

        Raises:
            UnknownMinerError: If the miner is not pre-registered.
        """
        start = time.monotonic()

        with self._registry_lock:
            current_hash = self._constitution.hash
            accepted_hashes = {current_hash}
            if self._previous_hash is not None:
                accepted_hashes.add(self._previous_hash)
            known_miner = synapse.miner_uid in self._known_miners
            mesh = self._mesh

        if synapse.constitutional_hash not in accepted_hashes:
            with self._stats_lock:
                self._stats.constitution_mismatches += 1
            return ValidationSynapse(
                task_id=synapse.task_id,
                assignment_id="",
                accepted=False,
                votes_for=0,
                votes_against=0,
                quorum_met=False,
                constitutional_hash=current_hash,
            )

        # Step 2: Reject unknown miners — no auto-registration
        if not known_miner:
            raise UnknownMinerError(
                f"Miner {synapse.miner_uid!r} is not registered. "
                f"Call register_miner() before submitting judgments."
            )

        # Step 3: Full mesh validation
        result = mesh.full_validation(
            producer_id=synapse.miner_uid,
            content=synapse.judgment,
            artifact_id=synapse.artifact_hash,
        )

        elapsed_ms = (time.monotonic() - start) * 1000
        with self._stats_lock:
            self._stats.total_validation_time_ms += elapsed_ms
            self._stats.validations_performed += 1
            if result.accepted:
                self._stats.judgments_accepted += 1
            else:
                self._stats.judgments_rejected += 1

        # Step 4: Build ValidationSynapse
        return self._result_to_synapse(synapse.task_id, result)

    def compute_emission_weights(
        self,
        miner_uids: list[str] | None = None,
    ) -> dict[str, float]:
        """Compute weights with the canonical emission formula.

        Raw trust column mass is used because projected Birkhoff columns are
        constant by construction. When raw trust is unavailable or has no
        spread, its coefficient is dropped and the other coefficients are
        renormalized. Explicit unknown UIDs remain in the result with zero
        weight; duplicate requests are deduplicated in first-seen order, and an
        explicit empty list requests no miners.
        """
        with self._registry_lock:
            requested = list(self._miner_tiers) if miner_uids is None else list(miner_uids)
            uids = list(dict.fromkeys(requested))
            if not uids:
                return {}
            tiers = dict(self._miner_tiers)
            known_miners = set(self._known_miners)
            mesh = self._mesh
            mesh_agents, reputations, indices, raw_trust, manifold_present = (
                _snapshot_mesh_emission_state(mesh, uids)
            )

        _validate_manifold_snapshot(
            mesh_agents,
            indices,
            raw_trust,
            manifold_present=manifold_present,
        )
        manifold_signals = _manifold_signals(indices, raw_trust)
        emission_weights = (
            DEFAULT_EMISSION_WEIGHTS
            if manifold_signals is not None
            else _weights_without_manifold()
        )
        registered = known_miners & mesh_agents
        inputs: list[MinerEmissionInput] = []
        for uid in uids:
            inputs.append(
                MinerEmissionInput(
                    miner_uid=uid,
                    tier=tiers.get(uid, MinerTier.APPRENTICE),
                    manifold_trust=(
                        0.0 if manifold_signals is None else manifold_signals.get(uid, 0.0)
                    ),
                    reputation=reputations.get(uid, 0.0),
                    precedent_contributions=0,
                    avg_authenticity=0.0,
                )
            )

        calculated = EmissionCalculator(
            weights=emission_weights,
            registered_miners=registered,
        ).compute(inputs).as_weight_dict()
        return {uid: calculated[uid] for uid in uids}

    def get_miner_reputation(self, miner_uid: str) -> float:
        """Get a miner's current reputation score."""
        return self._mesh.get_reputation(miner_uid)

    def summary(self) -> dict[str, Any]:
        """Combined validator + mesh + manifold statistics."""
        stats = self.stats
        with self._registry_lock:
            mesh = self._mesh
            registered_miners = len(self._miner_tiers)
            constitution_hash = self._constitution.hash
        return {
            "validator_stats": {
                "validations": stats.validations_performed,
                "accepted": stats.judgments_accepted,
                "rejected": stats.judgments_rejected,
                "acceptance_rate": stats.acceptance_rate,
                "avg_validation_ms": stats.avg_validation_ms,
            },
            "mesh": mesh.summary(),
            "manifold": mesh.manifold_summary(),
            "registered_miners": registered_miners,
            "constitution_hash": constitution_hash,
        }

    def _result_to_synapse(
        self,
        task_id: str,
        result: MeshResult,
    ) -> ValidationSynapse:
        proof = result.proof
        return ValidationSynapse(
            task_id=task_id,
            assignment_id=result.assignment_id,
            accepted=result.accepted,
            votes_for=result.votes_for,
            votes_against=result.votes_against,
            quorum_met=result.quorum_met,
            proof_root_hash=proof.root_hash if proof else "",
            proof_vote_hashes=proof.vote_hashes if proof else (),
            proof_content_hash=proof.content_hash if proof else "",
            constitutional_hash=result.constitutional_hash,
            trust_update=self._mesh.manifold_summary() or {},
        )
