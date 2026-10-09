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

import hashlib
import math
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from acgs_lite import Constitution
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

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
from constitutional_swarm.mesh.vote_envelope import (
    VoteSignerRegistry,
    normalize_voter_id,
    verify_assignment_vote_envelopes,
    vote_envelope_hash,
)


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


def _vote_private_key(
    value: Ed25519PrivateKey | bytes | str | None,
) -> Ed25519PrivateKey:
    """Canonicalize locally managed vote-signing key material."""
    if value is None:
        return Ed25519PrivateKey.generate()
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, str):
        if (
            len(value) != 64
            or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("vote private key must be 64 lowercase hex chars")
        try:
            value = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("vote private key must be 64 lowercase hex chars") from exc
    if not isinstance(value, bytes):
        raise TypeError("vote private key must be Ed25519 key material")
    try:
        return Ed25519PrivateKey.from_private_bytes(value)
    except ValueError as exc:
        raise ValueError("vote private key must contain exactly 32 bytes") from exc


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

    def __init__(
        self,
        config: ValidatorConfig,
        *,
        vote_registry: VoteSignerRegistry | None = None,
        assigner_private_key: Ed25519PrivateKey | bytes | str | None = None,
        assigner_id: str = "mesh-assigner",
        request_signing_private_key: Ed25519PrivateKey | bytes | str | None = None,
    ) -> None:
        self._config = config
        self._constitution = Constitution.from_yaml(config.constitution_path)
        self._assigner_private_key = _vote_private_key(assigner_private_key)
        self._assigner_id = normalize_voter_id(assigner_id)
        self._request_signing_private_key = _vote_private_key(request_signing_private_key)
        self._mesh = ConstitutionalMesh(
            self._constitution,
            peers_per_validation=config.peers_per_validation,
            quorum=config.quorum,
            use_manifold=config.use_manifold,
            complete_evidence=config.complete_evidence,
            vote_registry=vote_registry,
            assigner_private_key=self._assigner_private_key,
            assigner_id=self._assigner_id,
            request_signing_private_key=self._request_signing_private_key,
            evidence_mode=(
                "single_operator_dev" if config.single_operator_dev else "independent"
            ),
        )
        self._stats = ValidatorStats()
        self._stats_lock = threading.Lock()
        self._known_miners: set[str] = set()
        self._miner_tiers: dict[str, MinerTier] = {}
        self._miner_domains: dict[str, str] = {}
        self._miner_vote_private_keys: dict[str, Ed25519PrivateKey] = {}
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
                complete_evidence=self._config.complete_evidence,
                vote_registry=self._mesh.vote_registry,
                assigner_private_key=self._assigner_private_key,
                assigner_id=self._assigner_id,
                request_signing_private_key=self._request_signing_private_key,
                evidence_mode=(
                    "single_operator_dev"
                    if self._config.single_operator_dev
                    else "independent"
                ),
            )
            for miner_uid in self._known_miners:
                domain = self._miner_domains.get(miner_uid, "")
                private_key = self._miner_vote_private_keys.get(miner_uid)
                if private_key is not None:
                    new_mesh.register_local_signer(
                        miner_uid,
                        domain=domain,
                        vote_private_key=private_key,
                    )
                else:
                    new_mesh.register_remote_agent(
                        miner_uid,
                        domain=domain,
                        vote_public_key=bytes.fromhex(
                            self._mesh.get_vote_public_key(miner_uid)
                        ),
                    )
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
        *,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
        vote_public_key: Ed25519PublicKey | bytes | str | None = None,
    ) -> None:
        """Register a miner as a mesh participant.

        Adds the miner to the known set, mesh, tier map, and domain map.
        Only miners registered via this method may submit judgments.
        """
        canonical_uid = normalize_voter_id(miner_uid)
        with self._registry_lock:
            if canonical_uid in self._known_miners:
                raise ValueError(f"canonical miner identity {canonical_uid!r} is already registered")
            if self._config.single_operator_dev:
                if vote_public_key is not None:
                    raise ValueError(
                        "single-operator dev registration accepts a local private key, "
                        "not a remote public key"
                    )
                private_key = _vote_private_key(vote_private_key)
            else:
                if vote_private_key is not None:
                    raise ValueError(
                        "default validator mode refuses voter private keys; provision "
                        "the remote voter's public key"
                    )
                if vote_public_key is None:
                    if self._miner_vote_private_keys:
                        raise ValueError(
                            "default validator mode may hold only its own local identity key; "
                            "provision every voter with a remote public key"
                        )
                    private_key = _vote_private_key(None)
                else:
                    private_key = None
            if private_key is None:
                if vote_public_key is None:
                    raise RuntimeError("remote voter registration requires a public key")
                self._mesh.register_remote_agent(
                    canonical_uid,
                    domain=domain,
                    vote_public_key=vote_public_key,
                )
            else:
                self._mesh.register_local_signer(
                    canonical_uid,
                    domain=domain,
                    vote_private_key=private_key,
                )
            self._known_miners.add(canonical_uid)
            self._miner_tiers[canonical_uid] = tier
            self._miner_domains[canonical_uid] = domain
            if private_key is not None:
                self._miner_vote_private_keys[canonical_uid] = private_key

    def unregister_miner(self, miner_uid: str) -> None:
        """Remove a miner from the mesh."""
        canonical_uid = normalize_voter_id(miner_uid)
        with self._registry_lock:
            self._mesh.unregister_agent(canonical_uid)
            self._known_miners.discard(canonical_uid)
            self._miner_tiers.pop(canonical_uid, None)
            self._miner_domains.pop(canonical_uid, None)
            self._miner_vote_private_keys.pop(canonical_uid, None)

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
        producer_id = normalize_voter_id(synapse.miner_uid)

        with self._registry_lock:
            current_hash = self._constitution.hash
            accepted_hashes = {current_hash}
            if self._previous_hash is not None:
                accepted_hashes.add(self._previous_hash)
            known_miner = producer_id in self._known_miners
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

        if not self._config.single_operator_dev:
            raise RuntimeError(
                "default validator mode uses remote public-key voters; call "
                "validate_remote() with explicit peer routes"
            )

        # Step 3: Full mesh validation
        result = mesh.full_validation(
            producer_id=producer_id,
            content=synapse.judgment,
            artifact_id=synapse.artifact_hash,
            task_id=synapse.task_id,
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
        return self._result_to_synapse(synapse, result)

    async def validate_remote(
        self,
        synapse: JudgmentSynapse,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: Any | None = None,
        timeout: float = 5.0,
    ) -> ValidationSynapse:
        """Validate by collecting signatures from public-key-only remote voters."""
        start = time.monotonic()
        producer_id = normalize_voter_id(synapse.miner_uid)
        with self._registry_lock:
            current_hash = self._constitution.hash
            accepted_hashes = {current_hash}
            if self._previous_hash is not None:
                accepted_hashes.add(self._previous_hash)
            known_miner = producer_id in self._known_miners
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
        if not known_miner:
            raise UnknownMinerError(
                f"Miner {synapse.miner_uid!r} is not registered. "
                f"Call register_miner() before submitting judgments."
            )
        assignment = mesh.request_validation(
            producer_id,
            synapse.judgment,
            synapse.artifact_hash,
            task_id=synapse.task_id,
        )
        result = await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes=peer_routes,
            client=client,
            timeout=timeout,
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        with self._stats_lock:
            self._stats.total_validation_time_ms += elapsed_ms
            self._stats.validations_performed += 1
            if result.accepted:
                self._stats.judgments_accepted += 1
            else:
                self._stats.judgments_rejected += 1
        return self._result_to_synapse(synapse, result)

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
        judgment: JudgmentSynapse,
        result: MeshResult,
    ) -> ValidationSynapse:
        proof = result.proof
        producer_id = normalize_voter_id(judgment.miner_uid)
        content_hash = hashlib.sha256(judgment.judgment.encode("utf-8")).hexdigest()[:32]
        with self._registry_lock:
            current_constitutional_hash = self._constitution.hash
            mesh = self._mesh
            vote_registry = mesh.vote_registry
        authoritative_result = mesh.get_result(result.assignment_id)
        if result.constitutional_hash != current_constitutional_hash:
            raise ValueError("mesh result constitution does not match validator constitution")
        if result.signed_assignment is None:
            raise ValueError("mesh result is missing its signed assignment")
        if result.signed_assignment != authoritative_result.signed_assignment:
            raise ValueError("signed assignment differs from authoritative mesh evidence")
        verified_envelopes = verify_assignment_vote_envelopes(
            result.signed_assignment,
            result.vote_envelopes,
            vote_registry,
            task_id=judgment.task_id,
            assignment_id=result.assignment_id,
            producer_id=producer_id,
            artifact_id=judgment.artifact_hash,
            content_hash=content_hash,
            constitutional_hash=result.constitutional_hash,
            require_independent=not self._config.single_operator_dev,
        )
        if verified_envelopes != authoritative_result.vote_envelopes:
            raise ValueError("vote envelopes differ from authoritative mesh evidence")
        votes_for = sum(
            envelope.decision == "approved" for envelope in verified_envelopes
        )
        votes_against = len(verified_envelopes) - votes_for
        signed_quorum = result.signed_assignment.quorum
        strict_majority = len(verified_envelopes) // 2 + 1
        expected_quorum = max(self._config.quorum, strict_majority)
        if signed_quorum != expected_quorum:
            raise ValueError("signed vote quorum does not match validator policy")
        if (
            self._config.complete_evidence
            and len(verified_envelopes) < self._config.peers_per_validation
        ):
            raise ValueError("signed vote evidence is below the complete-evidence peer floor")
        accepted = votes_for >= signed_quorum and votes_for >= strict_majority
        rejected = votes_against >= signed_quorum and votes_against >= strict_majority
        quorum_met = accepted or rejected
        if (votes_for, votes_against) != (result.votes_for, result.votes_against):
            raise ValueError("mesh result tally does not match signed vote envelopes")
        if (result.accepted, result.quorum_met) != (accepted, quorum_met):
            raise ValueError("mesh result outcome does not match signed vote envelopes")
        if proof is None:
            raise ValueError("mesh result is missing its protocol v2 proof")
        ordered_envelopes = sorted(
            verified_envelopes, key=lambda item: (item.voter_id, item.key_id)
        )
        expected_vote_hashes = tuple(
            vote_envelope_hash(envelope) for envelope in ordered_envelopes
        )
        if (
            proof.protocol_version != 2
            or proof.task_id != judgment.task_id
            or proof.assignment_id != result.assignment_id
            or proof.producer_id != producer_id
            or proof.artifact_id != judgment.artifact_hash
            or proof.content_hash != content_hash
            or proof.constitutional_hash != current_constitutional_hash
            or proof.accepted != accepted
            or proof.vote_hashes != expected_vote_hashes
            or not proof.verify()
        ):
            raise ValueError("mesh result proof does not match signed vote envelopes")
        return ValidationSynapse(
            task_id=judgment.task_id,
            assignment_id=result.assignment_id,
            accepted=accepted,
            votes_for=votes_for,
            votes_against=votes_against,
            quorum_met=quorum_met,
            proof_root_hash=proof.root_hash,
            proof_vote_hashes=proof.vote_hashes,
            proof_content_hash=proof.content_hash,
            constitutional_hash=current_constitutional_hash,
            vote_envelopes=verified_envelopes,
            signed_assignment=result.signed_assignment,
            trust_update=self._mesh.manifold_summary() or {},
        )
