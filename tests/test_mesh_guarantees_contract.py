"""Contract tests locking the four-layer ConstitutionalMesh guarantee boundaries.

Covers Step 5 (Parallel Gate) of the Acgs-Swarm Phase 1 Task Order:
  1. Majority quorum configuration & persistent quorum >= 3 enforcement (with 3-of-5
     approval settlement succeeding once all 5 assigned votes arrive).
  2. Duplicate task_id submission produces independent assignment IDs (not deduplicated).
  3. Partial quorum preview returns accepted=True while remaining unsettled and
     non-settleable before every assigned peer has voted.
  4. Transport timeouts fail closed without shrinking the assigned peer roster or
     lowering quorum; settled assignments reject late votes.
  5. All four downstream consumers reject unsettled partial-approval previews or
     incomplete vote-envelope evidence.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from acgs_lite import Constitution, Rule
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import (
    AssignmentSettledError,
    ConstitutionalMesh,
    SettlementRecord,
    SQLiteSettlementStore,
)
from constitutional_swarm.bittensor.cascade import (
    CascadeStage,
    PrecedentCandidate,
    PrecedentCascade,
)
from constitutional_swarm.bittensor.precedent_store import PrecedentStore
from constitutional_swarm.bittensor.protocol import ValidatorConfig
from constitutional_swarm.bittensor.synapses import JudgmentSynapse
from constitutional_swarm.bittensor.validator import ConstitutionalValidator
from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement
from constitutional_swarm.mesh.exceptions import RecoveredAssignmentError
from constitutional_swarm.mesh.vote_envelope import (
    compute_vote_envelope_root,
    sign_vote_envelope,
    signed_assignment_digest,
)
from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse


def _constitution() -> Constitution:
    rules = [
        Rule(
            id="SAFE-001",
            text="Preserve safety and require documented rationale",
            severity="high",
            keywords=["unsafe bypass"],
        )
    ]
    return Constitution.from_rules(rules, name="mesh-contract-test")


def _constitution_yaml(tmp_path) -> str:
    path = tmp_path / "mesh-contract-constitution.yaml"
    path.write_text(
        "name: mesh-contract-test\n"
        "rules:\n"
        "  - id: SAFE-001\n"
        "    text: Preserve safety and require documented rationale\n"
        "    severity: high\n"
        "    hardcoded: false\n",
        encoding="utf-8",
    )
    return str(path)


def _signed_vote(
    mesh: ConstitutionalMesh,
    assignment_id: str,
    voter_id: str,
    *,
    approved: bool,
    reason: str = "contract-check",
):
    sig = mesh.sign_vote(assignment_id, voter_id, approved=approved, reason=reason)
    return mesh.submit_vote(
        assignment_id,
        voter_id,
        approved=approved,
        reason=reason,
        signature=sig,
    )


def _envelope_for_request(
    private_key: Ed25519PrivateKey,
    request,
    *,
    decision: str = "approved",
    reason: str = "independent constitutional check",
):
    return sign_vote_envelope(
        private_key,
        voter_id=request.voter_id,
        task_id=request.task_id,
        assignment_id=request.assignment_id,
        producer_id=request.producer_id,
        artifact_id=request.artifact_id,
        content_hash=request.content_hash,
        constitutional_hash=request.constitutional_hash,
        decision=decision,
        reason=reason,
        nonce=request.nonce,
        issued_at=request.timestamp,
        assigned_peers=request.assigned_peers,
        quorum=request.quorum,
        evidence_mode=request.evidence_mode,
        assignment_digest=signed_assignment_digest(request.signed_assignment),
    )


def test_mesh_quorum_validation_and_persistent_three_of_five_settlement(tmp_path) -> None:
    const = _constitution()
    with pytest.raises(ValueError, match="strict majority"):
        ConstitutionalMesh(const, peers_per_validation=4, quorum=2)

    with pytest.raises(ValueError, match="quorum >= 3"):
        ConstitutionalMesh(
            const,
            peers_per_validation=3,
            quorum=2,
            settlement_store=SQLiteSettlementStore(tmp_path / "too-small.db"),
            evidence_mode="single_operator_dev",
        )

    store_path = tmp_path / "mesh-3of5.db"
    mesh = ConstitutionalMesh(
        const,
        peers_per_validation=5,
        quorum=3,
        settlement_store=SQLiteSettlementStore(store_path),
        evidence_mode="single_operator_dev",
        seed=7,
    )
    mesh.register_local_signer("producer-00", domain="safety")
    for idx in range(5):
        mesh.register_local_signer(f"peer-{idx:02d}", domain="safety")

    assignment = mesh.request_validation(
        "producer-00",
        "Approve bounded action with explicit audit log",
        "art-3of5",
        task_id="task-3of5",
    )
    assert len(assignment.peers) == 5

    for idx, peer in enumerate(assignment.peers):
        _signed_vote(mesh, assignment.assignment_id, peer, approved=(idx < 3))

    settled = mesh.get_result(assignment.assignment_id)
    assert settled.accepted is True
    assert settled.votes_for == 3
    assert settled.votes_against == 2
    assert settled.quorum_met is True
    assert settled.settled is True
    assert settled.proof is not None

    with pytest.raises(RecoveredAssignmentError):
        mesh.settle(assignment.assignment_id)

    persisted = SQLiteSettlementStore(store_path).load_all()
    assert len(persisted) == 1
    assert persisted[0].assignment["assignment_id"] == assignment.assignment_id


def test_duplicate_task_submission_creates_distinct_assignments() -> None:
    mesh = ConstitutionalMesh(
        _constitution(),
        peers_per_validation=3,
        quorum=2,
        evidence_mode="single_operator_dev",
        seed=11,
    )
    mesh.register_local_signer("producer-dup", domain="safety")
    for idx in range(3):
        mesh.register_local_signer(f"peer-{idx:02d}", domain="safety")

    first = mesh.request_validation(
        "producer-dup",
        "Identical safe payload",
        "art-dup",
        task_id="task-dup-001",
    )
    second = mesh.request_validation(
        "producer-dup",
        "Identical safe payload",
        "art-dup",
        task_id="task-dup-001",
    )

    assert first.assignment_id != second.assignment_id
    assert mesh.get_result(first.assignment_id).settled is False
    assert mesh.get_result(second.assignment_id).settled is False


def test_partial_approvals_preview_accepted_but_cannot_settle() -> None:
    mesh = ConstitutionalMesh(
        _constitution(),
        peers_per_validation=3,
        quorum=2,
        evidence_mode="single_operator_dev",
        seed=13,
    )
    mesh.register_local_signer("producer-part", domain="safety")
    for idx in range(3):
        mesh.register_local_signer(f"peer-{idx:02d}", domain="safety")

    assignment = mesh.request_validation(
        "producer-part",
        "Partial approval boundary test",
        "art-part",
        task_id="task-part",
    )
    for peer in assignment.peers[:2]:
        _signed_vote(mesh, assignment.assignment_id, peer, approved=True)

    preview = mesh.get_result(assignment.assignment_id)
    assert preview.accepted is True
    assert preview.votes_for == 2
    assert preview.votes_against == 0
    assert preview.pending_votes == 1
    assert preview.quorum_met is False
    assert preview.settled is False
    assert preview.proof is None
    assert len(preview.vote_envelopes) == 2

    with pytest.raises(ValueError, match="cannot settle before quorum is reached"):
        mesh.settle(assignment.assignment_id)


def test_timeout_preserves_roster_and_settled_rejects_late_vote() -> None:
    mesh = ConstitutionalMesh(
        _constitution(),
        peers_per_validation=3,
        quorum=2,
        evidence_mode="single_operator_dev",
        seed=17,
    )
    mesh.register_local_signer("producer-timeout", domain="safety")
    peer_keys: dict[str, Ed25519PrivateKey] = {}
    peer_routes: dict[str, tuple[str, int]] = {}
    for idx in range(3):
        peer_id = f"remote-peer-{idx:02d}"
        key = Ed25519PrivateKey.generate()
        peer_keys[peer_id] = key
        peer_routes[peer_id] = (peer_id, 9100 + idx)
        mesh.register_remote_agent(
            peer_id,
            domain="safety",
            vote_public_key=key.public_key(),
        )

    assignment = mesh.request_validation(
        "producer-timeout",
        "Remote vote timeout fail-closed test",
        "art-timeout",
        task_id="task-timeout",
    )
    original_peers = assignment.peers
    failing_peer = original_peers[2]

    class _PartialTimeoutClient:
        async def request_vote(self, host: str, port: int, request, *, timeout: float):
            del port, timeout
            if host == failing_peer:
                raise TimeoutError("simulated peer RPC timeout")
            return RemoteVoteResponse(
                _envelope_for_request(peer_keys[host], request, decision="approved")
            )

    with pytest.raises(TimeoutError, match="simulated peer RPC timeout"):
        asyncio.run(
            mesh.collect_remote_votes(
                assignment.assignment_id,
                peer_routes=peer_routes,
                client=_PartialTimeoutClient(),
            )
        )

    stored_assignment = mesh._assignments[assignment.assignment_id]
    assert stored_assignment.peers == original_peers
    assert len(stored_assignment.peers) == 3

    unsettled = mesh.get_result(assignment.assignment_id)
    assert unsettled.settled is False
    assert unsettled.quorum_met is False
    assert unsettled.pending_votes == 1

    assert stored_assignment.signed_assignment is not None
    mesh.submit_vote_envelope(
        sign_vote_envelope(
            peer_keys[failing_peer],
            voter_id=failing_peer,
            task_id=stored_assignment.task_id,
            assignment_id=stored_assignment.assignment_id,
            producer_id=stored_assignment.producer_id,
            artifact_id=stored_assignment.artifact_id,
            content_hash=stored_assignment.content_hash,
            constitutional_hash=stored_assignment.constitutional_hash,
            decision="approved",
            reason="recovery vote",
            nonce=uuid.uuid4().hex,
            issued_at=time.time(),
            assigned_peers=stored_assignment.peers,
            quorum=stored_assignment.quorum,
            evidence_mode=stored_assignment.evidence_mode,
            assignment_digest=signed_assignment_digest(stored_assignment.signed_assignment),
        )
    )
    settled = mesh.get_result(assignment.assignment_id)
    assert settled.settled is True
    assert settled.quorum_met is True

    with pytest.raises(AssignmentSettledError):
        mesh.submit_vote(
            assignment.assignment_id,
            original_peers[0],
            approved=True,
            reason="late vote",
            signature="0" * 128,
        )


def test_downstream_consumers_reject_unsettled_or_partial_evidence(tmp_path) -> None:
    const = _constitution()

    # 1. Governance receipt builder rejects incomplete 3-of-5 electorate preview
    mesh_r = ConstitutionalMesh(
        const,
        peers_per_validation=5,
        quorum=3,
        evidence_mode="single_operator_dev",
        seed=23,
    )
    mesh_r.register_local_signer("producer-receipt", domain="safety")
    for idx in range(5):
        mesh_r.register_local_signer(f"rpeer-{idx:02d}", domain="safety")

    asgn_r = mesh_r.request_validation(
        "producer-receipt",
        "Governance receipt completeness check",
        "art-receipt",
        task_id="task-receipt",
    )
    for peer in asgn_r.peers[:3]:
        _signed_vote(mesh_r, asgn_r.assignment_id, peer, approved=True)
    partial_r = mesh_r.get_result(asgn_r.assignment_id)
    assert partial_r.accepted is True
    assert partial_r.quorum_met is False
    assert partial_r.settled is False

    partial_record = SettlementRecord(
        assignment=mesh_r._serialize_assignment(asgn_r),
        result={
            "accepted": partial_r.accepted,
            "votes_for": partial_r.votes_for,
            "votes_against": partial_r.votes_against,
            "quorum_met": partial_r.quorum_met,
            "pending_votes": partial_r.pending_votes,
            "settled": partial_r.settled,
        },
        constitutional_hash=mesh_r.constitutional_hash,
        schema_version=2,
    )
    with pytest.raises(ValueError):
        receipt_from_mesh_settlement(
            partial_record,
            list(partial_r.vote_envelopes),
            trusted_signers=mesh_r.receipt_trust_registry(),
            require_independent_votes=False,
        )

    # Complete 5/5 settlement succeeds when the full roster votes
    for peer in asgn_r.peers[3:]:
        _signed_vote(mesh_r, asgn_r.assignment_id, peer, approved=True)
    settled_r = mesh_r.get_result(asgn_r.assignment_id)
    full_record = SettlementRecord(
        assignment=mesh_r._serialize_assignment(asgn_r),
        result={
            "accepted": settled_r.accepted,
            "votes_for": settled_r.votes_for,
            "votes_against": settled_r.votes_against,
            "quorum_met": settled_r.quorum_met,
            "pending_votes": settled_r.pending_votes,
            "settled": settled_r.settled,
            "proof_root": settled_r.proof.root_hash if settled_r.proof else "",
        },
        constitutional_hash=mesh_r.constitutional_hash,
        schema_version=2,
    )
    receipt = receipt_from_mesh_settlement(
        full_record,
        list(settled_r.vote_envelopes),
        trusted_signers=mesh_r.receipt_trust_registry(),
        require_independent_votes=False,
    )
    assert receipt.payload.signed_assignment is not None
    assert receipt.payload.signed_assignment["assignment_id"] == asgn_r.assignment_id
    assert len(receipt.payload.validator_votes) == 5

    # 2. ConstitutionalValidator._result_to_synapse rejects unsettled 3-of-5 preview
    const_path = _constitution_yaml(tmp_path)
    validator = ConstitutionalValidator(
        ValidatorConfig(
            constitution_path=const_path,
            peers_per_validation=5,
            quorum=3,
            single_operator_dev=True,
        )
    )
    validator.register_miner("producer-val", domain="safety")
    for idx in range(5):
        validator.register_miner(f"vpeer-{idx:02d}", domain="safety")

    val_assignment = validator.mesh.request_validation(
        "producer-val",
        "Validator synapse settlement gate",
        "art-val",
        task_id="task-val",
    )
    for peer in val_assignment.peers[:3]:
        _signed_vote(validator.mesh, val_assignment.assignment_id, peer, approved=True)
    val_preview = validator.mesh.get_result(val_assignment.assignment_id)
    assert val_preview.accepted is True
    assert val_preview.quorum_met is False
    assert val_preview.settled is False

    judgment = JudgmentSynapse(
        task_id="task-val",
        miner_uid="producer-val",
        judgment="Validator synapse settlement gate",
        reasoning="Documented constitutional rationale",
        artifact_hash="art-val",
        constitutional_hash=validator.constitution_hash,
        domain="safety",
    )
    with pytest.raises(ValueError):
        validator._result_to_synapse(judgment, val_preview)

    # 3. PrecedentCascade._valid_mesh_result rejects unsettled preview
    cascade = PrecedentCascade(const, validator.mesh)
    candidate = PrecedentCandidate(
        candidate_id="cand-01",
        judgment_text="Validator synapse settlement gate",
        reasoning_text="Documented constitutional rationale",
        domain="safety",
        miner_uid="producer-val",
        constitutional_hash=validator.constitution_hash,
        stage_results=(),
        current_stage=CascadeStage.MESH_VALIDATION,
        alive=True,
    )
    assert cascade._valid_mesh_result(candidate, val_preview) is False

    # 4. PrecedentStore.verify_validation_evidence rejects valid partial 3-of-5 envelopes
    indep_mesh = ConstitutionalMesh(
        const,
        peers_per_validation=5,
        quorum=3,
        evidence_mode="independent",
        seed=29,
    )
    indep_mesh.register_local_signer("producer-store", domain="safety")
    indep_keys: dict[str, Ed25519PrivateKey] = {}
    for idx in range(5):
        peer_id = f"indep-peer-{idx:02d}"
        key = Ed25519PrivateKey.generate()
        indep_keys[peer_id] = key
        indep_mesh.register_remote_agent(
            peer_id,
            domain="safety",
            vote_public_key=key.public_key(),
        )

    judgment_text = "Bounded precedent approval with full constitutional rationale"
    store_asgn = indep_mesh.request_validation(
        "producer-store",
        judgment_text,
        "art-store",
        task_id="task-store",
    )
    assert store_asgn.signed_assignment is not None
    asgn_digest = signed_assignment_digest(store_asgn.signed_assignment)
    all_envelopes = [
        sign_vote_envelope(
            indep_keys[peer_id],
            voter_id=peer_id,
            task_id=store_asgn.task_id,
            assignment_id=store_asgn.assignment_id,
            producer_id=store_asgn.producer_id,
            artifact_id=store_asgn.artifact_id,
            content_hash=store_asgn.content_hash,
            constitutional_hash=store_asgn.constitutional_hash,
            decision="approved",
            reason="independent approval",
            nonce=uuid.uuid4().hex,
            issued_at=time.time(),
            assigned_peers=store_asgn.peers,
            quorum=store_asgn.quorum,
            evidence_mode="independent",
            assignment_digest=asgn_digest,
        )
        for peer_id in store_asgn.peers
    ]

    store = PrecedentStore(
        indep_mesh.constitutional_hash,
        min_votes_for_precedent=3,
        min_total_validators=5,
        vote_registry=indep_mesh.vote_registry.frozen_copy(),
    )
    partial_envelopes = all_envelopes[:3]
    partial_root = compute_vote_envelope_root(
        task_id=store_asgn.task_id,
        assignment_id=store_asgn.assignment_id,
        producer_id=store_asgn.producer_id,
        artifact_id=store_asgn.artifact_id,
        content_hash=store_asgn.content_hash,
        constitutional_hash=store_asgn.constitutional_hash,
        accepted=True,
        envelopes=partial_envelopes,
    )
    with pytest.raises(ValueError):
        store.verify_validation_evidence(
            task_id=store_asgn.task_id,
            producer_id=store_asgn.producer_id,
            judgment=judgment_text,
            votes_for=3,
            votes_against=0,
            accepted=True,
            proof_root_hash=partial_root,
            assignment_id=store_asgn.assignment_id,
            artifact_id=store_asgn.artifact_id,
            content_hash=store_asgn.content_hash,
            constitutional_hash=store_asgn.constitutional_hash,
            vote_envelopes=partial_envelopes,
            signed_assignment=store_asgn.signed_assignment,
        )

    # Control: identical complete 5-of-5 evidence passes
    full_root = compute_vote_envelope_root(
        task_id=store_asgn.task_id,
        assignment_id=store_asgn.assignment_id,
        producer_id=store_asgn.producer_id,
        artifact_id=store_asgn.artifact_id,
        content_hash=store_asgn.content_hash,
        constitutional_hash=store_asgn.constitutional_hash,
        accepted=True,
        envelopes=all_envelopes,
    )
    verified = store.verify_validation_evidence(
        task_id=store_asgn.task_id,
        producer_id=store_asgn.producer_id,
        judgment=judgment_text,
        votes_for=5,
        votes_against=0,
        accepted=True,
        proof_root_hash=full_root,
        assignment_id=store_asgn.assignment_id,
        artifact_id=store_asgn.artifact_id,
        content_hash=store_asgn.content_hash,
        constitutional_hash=store_asgn.constitutional_hash,
        vote_envelopes=all_envelopes,
        signed_assignment=store_asgn.signed_assignment,
    )
    assert len(verified) == 5
