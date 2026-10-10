"""Draft C14 precedent regressions for parent merge into the mandated test file.

New C14 symbols are imported inside helpers/tests so this draft can be copied
before the implementation exists without breaking test-module collection.
"""

import pytest


def _c14_external_assigner(registry):  # type: ignore[no-untyped-def]
    """Provision the stable assignment authority required by an external registry."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"c14-external-registry-assigner").digest()
    )
    if not registry.trust_grants(role="assigner"):
        registry.register("c14-external-assigner", key.public_key(), roles={"assigner"})
    return {
        "assigner_private_key": key,
        "assigner_id": "c14-external-assigner",
    }


def _c14_precedent_constitution_file(tmp_path):  # type: ignore[no-untyped-def]
    path = tmp_path / "c14-precedent-constitution.yaml"
    path.write_text(
        "name: c14-precedent-test\nrules:\n"
        "  - id: safety\n"
        "    text: Preserve safety and explain governance decisions\n"
        "    severity: high\n"
        "    hardcoded: false\n",
        encoding="utf-8",
    )
    return str(path)


def _c14_precedent_pipeline(tmp_path, *, approved=True):  # type: ignore[no-untyped-def]
    import asyncio

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
    from constitutional_swarm.bittensor.synapses import JudgmentSynapse
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator
    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        sign_vote_envelope,
        signed_assignment_digest,
    )
    from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse

    constitution_path = _c14_precedent_constitution_file(tmp_path)
    owner_registry = VoteSignerRegistry()
    validator = ConstitutionalValidator(ValidatorConfig(constitution_path=constitution_path))
    producer = "  C14\u200d-PRODUCER  "
    peers = tuple(f"c14-validator-{index}" for index in range(5))
    validator.register_miner(producer, domain="governance")
    voter_keys = {}
    peer_routes = {}
    for peer_id in peers:
        private_key = Ed25519PrivateKey.generate()
        voter_keys[peer_id] = private_key
        peer_routes[peer_id] = (peer_id, 9000)
        validator.register_miner(
            peer_id,
            domain="governance",
            vote_public_key=private_key.public_key(),
        )
        owner_registry.register(
            peer_id,
            private_key.public_key(),
            roles={"voter", "validator"},
        )
    for grant in validator.mesh.vote_registry.trust_grants(role="assigner").values():
        owner_registry.register(
            str(grant["identity_id"]),
            bytes.fromhex(str(grant["public_key_hex"])),
            roles={"assigner"},
        )
    owner = SubnetOwner(constitution_path, vote_registry=owner_registry)

    class ExternalVoteClient:
        async def request_vote(self, host, port, request, *, timeout):
            del port, timeout
            return RemoteVoteResponse(
                sign_vote_envelope(
                    voter_keys[host],
                    voter_id=request.voter_id,
                    task_id=request.task_id,
                    assignment_id=request.assignment_id,
                    producer_id=request.producer_id,
                    artifact_id=request.artifact_id,
                    content_hash=request.content_hash,
                    constitutional_hash=request.constitutional_hash,
                    decision="approved" if approved else "denied",
                    reason="independent constitutional decision",
                    nonce=request.nonce,
                    issued_at=request.timestamp,
                    assigned_peers=request.assigned_peers,
                    quorum=request.quorum,
                    evidence_mode=request.evidence_mode,
                    assignment_digest=signed_assignment_digest(request.signed_assignment),
                )
            )

    case = owner.package_case(
        "Make a safe governance decision with rationale",
        "governance",
    )
    judgment = JudgmentSynapse(
        task_id=case.synapse.task_id,
        miner_uid=producer,
        judgment="Approve the safe governance action with documented safeguards",
        reasoning="The action is bounded, reviewable, and constitutionally compliant",
        artifact_hash="c14-artifact-hash",
        constitutional_hash=owner.constitution_hash,
        domain="governance",
    )
    validation = asyncio.run(
        validator.validate_remote(
            judgment,
            peer_routes=peer_routes,
            client=ExternalVoteClient(),
        )
    )
    return owner, validator, case, judgment, validation


def test_c14_precedent_validator_defaults_collect_complete_three_of_five_evidence() -> None:
    from constitutional_swarm.bittensor.protocol import ValidatorConfig

    config = ValidatorConfig(constitution_path="unused")
    assert config.peers_per_validation == 5
    assert config.quorum == 3
    assert config.complete_evidence is True


def test_c14_precedent_synapse_hashes_reject_colon_partition_collisions() -> None:
    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        deliberation_to_bt,
    )
    from constitutional_swarm.bittensor.synapses import DeliberationSynapse, JudgmentSynapse

    common = {
        "judgment": "approve:safely",
        "reasoning": "reason",
        "artifact_hash": "artifact",
        "constitutional_hash": "constitution",
    }
    left = JudgmentSynapse(task_id="task:miner", miner_uid="one", **common)
    right = JudgmentSynapse(task_id="task", miner_uid="miner:one", **common)
    assert left.content_hash != right.content_hash

    wire_left = GovernanceDeliberation(
        task_id="task:constitution",
        constitution_hash="one",
        task_dag_json="dag",
    )
    wire_right = GovernanceDeliberation(
        task_id="task",
        constitution_hash="constitution:one",
        task_dag_json="dag",
    )
    assert wire_left.request_content_hash != wire_right.request_content_hash
    internal = DeliberationSynapse(
        task_id="task",
        task_dag_json="dag",
        constitution_hash="constitution",
        domain="governance",
    )
    assert deliberation_to_bt(internal).request_content_hash == internal.content_hash


def test_c14_precedent_real_pipeline_preserves_original_verified_envelopes(tmp_path) -> None:
    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)

    assert validation.accepted is True
    assert validation.quorum_met is True
    assert len(validation.vote_envelopes) == 5
    assert len({envelope.voter_id for envelope in validation.vote_envelopes}) == 5
    assert (validation.votes_for, validation.votes_against) == (5, 0)

    precedent = owner.record_result(case, judgment, validation)
    assert precedent is not None
    assert precedent.vote_envelopes == validation.vote_envelopes
    assert (precedent.votes_for, precedent.votes_against) == (5, 0)
    assert precedent.miner_uid == "c14-producer"
    assert owner.precedent_store.active_records()[0].vote_envelopes == validation.vote_envelopes


def test_c14_precedent_validator_reverifies_mesh_envelopes_before_transport(tmp_path) -> None:
    import dataclasses

    import pytest
    _owner, validator, _case, judgment, _validation = _c14_precedent_pipeline(tmp_path)
    result = validator.mesh.get_result(_validation.assignment_id)
    tampered = dataclasses.replace(result.vote_envelopes[0], reason="tampered in transit")
    injected = dataclasses.replace(
        result,
        vote_envelopes=(tampered, *result.vote_envelopes[1:]),
    )

    with pytest.raises(ValueError, match="signature"):
        validator._result_to_synapse(judgment, injected)


def test_c14_validator_recomputes_outcome_and_requires_v2_proof(tmp_path) -> None:
    import dataclasses

    _owner, validator, _case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    result = validator.mesh.get_result(validation.assignment_id)

    with pytest.raises(ValueError, match="outcome"):
        validator._result_to_synapse(
            judgment,
            dataclasses.replace(result, accepted=not result.accepted),
        )

    assert result.proof is not None
    legacy_proof = dataclasses.replace(result.proof, protocol_version=1)
    with pytest.raises(ValueError, match="protocol v2|proof"):
        validator._result_to_synapse(
            judgment,
            dataclasses.replace(result, proof=legacy_proof),
        )


def test_c14_precedent_rejects_unsigned_aggregate_only_admission(tmp_path) -> None:
    import hashlib

    import pytest

    from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore
    from constitutional_swarm.bittensor.protocol import EscalationType

    constitutional_hash = "608508a9bd224290"
    store = PrecedentStore(constitutional_hash)
    unsigned = PrecedentRecord.create(
        case_id="c14-unsigned-case",
        task_id="c14-unsigned-task",
        miner_uid="c14-producer",
        judgment="approve",
        reasoning="caller supplied",
        votes_for=3,
        votes_against=2,
        proof_root_hash=hashlib.sha256(b"caller-controlled").hexdigest()[:32],
        escalation_type=EscalationType.UNKNOWN,
        impact_vector={},
        constitutional_hash=constitutional_hash,
    )

    with pytest.raises(ValueError, match="signed vote envelope|trust registry"):
        store.admit(unsigned)
    assert store.size == 0


def test_c14_precedent_recomputes_tallies_and_rejects_supplied_mismatch(tmp_path) -> None:
    import dataclasses

    import pytest

    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    forged = dataclasses.replace(validation, votes_for=3, votes_against=2)

    with pytest.raises(ValueError, match="tally|vote count"):
        owner.record_result(case, judgment, forged)
    assert owner.precedent_store.size == 0
    assert case.case_id in owner.active_cases


def test_c14_owner_rejects_false_rejected_result_before_state_change(tmp_path) -> None:
    import dataclasses

    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    forged = dataclasses.replace(
        validation,
        accepted=False,
        quorum_met=True,
    )

    with pytest.raises(ValueError, match="acceptance|proof root|quorum"):
        owner.record_result(case, judgment, forged)
    assert owner.precedent_store.size == 0
    assert owner.metrics.total_judgments == 0
    assert owner.metrics.total_validations == 0
    assert owner.metrics.precedents_created == 0
    assert case.case_id in owner.active_cases


def test_c14_owner_verifies_valid_denial_and_rejects_false_quorum(tmp_path) -> None:
    import dataclasses

    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(
        tmp_path,
        approved=False,
    )
    assert validation.accepted is False
    assert validation.quorum_met is True
    assert (validation.votes_for, validation.votes_against) == (0, 5)

    forged = dataclasses.replace(validation, quorum_met=False)
    with pytest.raises(ValueError, match="quorum"):
        owner.record_result(case, judgment, forged)
    assert owner.metrics.total_validations == 0
    assert case.case_id in owner.active_cases

    assert owner.record_result(case, judgment, validation) is None
    assert owner.metrics.total_judgments == 1
    assert owner.metrics.total_validations == 1
    assert owner.metrics.precedents_created == 0
    assert case.case_id not in owner.active_cases


def test_c14_precedent_rejects_tampered_and_duplicate_key_envelopes_before_state(
    tmp_path,
) -> None:
    import dataclasses

    import pytest

    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    original = validation.vote_envelopes
    tampered = dataclasses.replace(original[0], reason=original[0].reason + " altered")
    bad_signature = dataclasses.replace(
        validation,
        vote_envelopes=(tampered, *original[1:]),
    )
    with pytest.raises(ValueError, match="signature|authentic"):
        owner.record_result(case, judgment, bad_signature)

    duplicate_key = dataclasses.replace(original[1], key_id=original[0].key_id)
    repeated_key = dataclasses.replace(
        validation,
        vote_envelopes=(original[0], duplicate_key, *original[2:]),
    )
    with pytest.raises(ValueError, match="duplicate.*key|key.*duplicate"):
        owner.record_result(case, judgment, repeated_key)

    assert owner.precedent_store.size == 0
    assert owner.metrics.precedents_created == 0
    assert case.case_id in owner.active_cases


def test_c14_precedent_rejects_envelope_binding_tamper(tmp_path) -> None:
    import dataclasses

    import pytest

    owner, _validator, case, judgment, validation = _c14_precedent_pipeline(tmp_path)
    original = validation.vote_envelopes

    for field, value in (
        ("task_id", "wrong-task"),
        ("assignment_id", "wrong-assignment"),
        ("producer_id", "wrong-producer"),
        ("artifact_id", "wrong-artifact"),
        ("content_hash", "0" * 32),
        ("constitutional_hash", "wrong-constitution"),
    ):
        changed = dataclasses.replace(original[0], **{field: value})
        forged = dataclasses.replace(validation, vote_envelopes=(changed, *original[1:]))
        with pytest.raises(ValueError, match=field.replace("_", " ") + "|binding|signature"):
            owner.record_result(case, judgment, forged)

    assert owner.precedent_store.size == 0
    assert case.case_id in owner.active_cases


def test_c14_precedent_validator_registry_normalizes_ids_and_rejects_collisions(
    tmp_path,
) -> None:
    import pytest

    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator

    validator = ConstitutionalValidator(
        ValidatorConfig(constitution_path=_c14_precedent_constitution_file(tmp_path))
    )
    validator.register_miner("  C14\u200d-VOTER  ")
    assert validator.mesh.get_vote_public_key("c14-voter")
    with pytest.raises(ValueError, match="canonical|already registered|collision"):
        validator.register_miner("c14-voter")


def c14_precedent_test_registry():
    """Build the deterministic trust registry used by legacy precedent fixtures."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"c14-test-assigner").digest()
    )
    registry.register(
        "c14-test-assigner",
        assigner_key.public_key(),
        roles={"assigner"},
    )
    for index in range(32):
        private_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"c14-test-voter-{index}".encode()).digest()
        )
        registry.register(f"c14-test-voter-{index}", private_key.public_key())
    return registry


def c14_precedent_signed_record(
    *,
    case_id="case-admission",
    task_id="task-admission",
    miner_uid="miner-admission",
    judgment="deny unsafe request",
    reasoning="constitutional rationale",
    votes_for=3,
    votes_against=2,
    escalation_type=None,
    impact_vector=None,
    constitutional_hash="608508a9bd224290",
    ambiguous_dimensions=("safety", "security"),
):
    """Create authentic signed evidence while retaining caller-supplied counts."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.bittensor.precedent_store import PrecedentRecord
    from constitutional_swarm.bittensor.protocol import EscalationType
    from constitutional_swarm.mesh.vote_envelope import (
        compute_vote_envelope_root,
        normalize_voter_id,
        sign_assignment,
        sign_vote_envelope,
        signed_assignment_digest,
    )

    escalation_type = escalation_type or EscalationType.CONSTITUTIONAL_CONFLICT
    assignment_id = f"assignment-{task_id}"
    artifact_id = f"artifact-{task_id}"
    content_hash = hashlib.sha256(judgment.encode()).hexdigest()[:32]
    valid_counts = all(
        type(value) is int and value >= 0 for value in (votes_for, votes_against)
    )
    total = votes_for + votes_against if valid_counts else 5
    approvals = votes_for if valid_counts else 3
    assigned_peers = tuple(f"c14-test-voter-{index}" for index in range(total))
    quorum = total // 2 + 1
    assigner_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"c14-test-assigner").digest()
    )
    signed_assignment = sign_assignment(
        assigner_key,
        task_id=task_id,
        assignment_id=assignment_id,
        assigner_id="c14-test-assigner",
        producer_id=normalize_voter_id(miner_uid),
        artifact_id=artifact_id,
        content_hash=content_hash,
        constitutional_hash=constitutional_hash,
        assigned_peers=assigned_peers,
        quorum=quorum,
        selection_seed=f"c14-selection-{task_id}",
        issued_at=0.0,
    )
    assignment_digest = signed_assignment_digest(signed_assignment)
    envelopes = []
    for index in range(total):
        private_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"c14-test-voter-{index}".encode()).digest()
        )
        envelopes.append(
            sign_vote_envelope(
                private_key,
                voter_id=f"c14-test-voter-{index}",
                task_id=task_id,
                assignment_id=assignment_id,
                producer_id=normalize_voter_id(miner_uid),
                artifact_id=artifact_id,
                content_hash=content_hash,
                constitutional_hash=constitutional_hash,
                decision="approved" if index < approvals else "denied",
                reason="test fixture vote",
                nonce=f"{task_id}-{index}",
                issued_at=float(index + 1),
                assigned_peers=assigned_peers,
                quorum=quorum,
                assignment_digest=assignment_digest,
            )
        )
    root = compute_vote_envelope_root(
        task_id=task_id,
        assignment_id=assignment_id,
        producer_id=normalize_voter_id(miner_uid),
        artifact_id=artifact_id,
        content_hash=content_hash,
        constitutional_hash=constitutional_hash,
        accepted=True,
        envelopes=envelopes,
    )
    return PrecedentRecord.create(
        case_id=case_id,
        task_id=task_id,
        miner_uid=miner_uid,
        judgment=judgment,
        reasoning=reasoning,
        votes_for=votes_for,
        votes_against=votes_against,
        proof_root_hash=root,
        escalation_type=escalation_type,
        impact_vector=impact_vector or {"safety": 0.9, "security": 0.8},
        constitutional_hash=constitutional_hash,
        ambiguous_dimensions=ambiguous_dimensions,
        assignment_id=assignment_id,
        artifact_id=artifact_id,
        content_hash=content_hash,
        vote_envelopes=tuple(envelopes),
        signed_assignment=signed_assignment,
    )


def c14_precedent_test_store(constitutional_hash="608508a9bd224290", **kwargs):
    from constitutional_swarm.bittensor.precedent_store import PrecedentStore

    return PrecedentStore(
        constitutional_hash,
        vote_registry=c14_precedent_test_registry(),
        **kwargs,
    )


def c14_trust_validator_voters(registry, validator, voter_ids) -> None:
    """Provision an owner-side registry from an independently known validator set."""
    for voter_id in voter_ids:
        registry.register(
            voter_id,
            bytes.fromhex(validator.mesh.get_vote_public_key(voter_id)),
        )
    for grant in validator.mesh.vote_registry.trust_grants(role="assigner").values():
        registry.register(
            str(grant["identity_id"]),
            bytes.fromhex(str(grant["public_key_hex"])),
            roles={"assigner"},
        )


def test_c14_precedent_direct_store_rejects_judgment_tamper() -> None:
    import dataclasses

    import pytest

    record = c14_precedent_signed_record()
    store = c14_precedent_test_store()
    with pytest.raises(ValueError, match="content hash|judgment"):
        store.admit(dataclasses.replace(record, judgment="altered after voting"))
    assert store.size == 0


def test_c14_precedent_direct_store_rejects_producer_self_vote() -> None:
    import pytest

    with pytest.raises(ValueError, match="producer|self"):
        c14_precedent_signed_record(miner_uid="c14-test-voter-0")


def test_c14_cycle2_vote_envelope_binds_complete_electorate() -> None:
    import hashlib

    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        canonical_assigned_peers_hash,
        sign_vote_envelope,
        verify_vote_envelopes,
    )

    peers = tuple(f"cycle2-voter-{index}" for index in range(5))
    registry = VoteSignerRegistry()
    keys = []
    for index, peer in enumerate(peers):
        key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"cycle2-key-{index}".encode()).digest()
        )
        keys.append(key)
        registry.register(peer, key.public_key())
    envelopes = tuple(
        sign_vote_envelope(
            key,
            voter_id=peer,
            task_id="cycle2-task",
            assignment_id="cycle2-assignment",
            producer_id="cycle2-producer",
            artifact_id="cycle2-artifact",
            content_hash="a" * 64,
            constitutional_hash="b" * 64,
            decision="approved" if index < 3 else "denied",
            reason="bound electorate",
            nonce=f"cycle2-nonce-{index}",
            issued_at=float(index + 1),
            assigned_peers=peers,
            quorum=3,
            evidence_mode="independent",
            protocol_version=2,
        )
        for index, (peer, key) in enumerate(zip(peers, keys, strict=True))
    )

    assert envelopes[0].assigned_peers_hash == canonical_assigned_peers_hash(peers)
    assert envelopes[0].assigned_peer_count == 5
    with pytest.raises(ValueError, match="assigned|electorate|complete"):
        verify_vote_envelopes(
            envelopes[:4],
            registry,
            task_id="cycle2-task",
            assignment_id="cycle2-assignment",
            producer_id="cycle2-producer",
            artifact_id="cycle2-artifact",
            content_hash="a" * 64,
            constitutional_hash="b" * 64,
            expected_assigned_peers=peers,
            expected_quorum=3,
            require_independent=True,
        )


def test_c14_cycle2_frozen_vote_registry_is_public_only_and_immutable() -> None:
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    registry = VoteSignerRegistry()
    registry.register("cycle2-voter", Ed25519PrivateKey.generate().public_key())
    frozen = registry.frozen_copy()

    assert frozen is not registry
    assert frozen.frozen is True
    before = frozen.trust_grants(role="voter")
    registry.replace("cycle2-voter", Ed25519PrivateKey.generate().public_key())
    assert frozen.trust_grants(role="voter") == before
    with pytest.raises(AttributeError):
        frozen.unregister("cycle2-voter")


def test_c14_cycle2_multi_identity_local_signing_requires_explicit_dev_mode() -> None:
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(Constitution.default(), seed=914)
    for agent_id in ("producer", "voter-a", "voter-b", "voter-c"):
        mesh.register_local_signer(agent_id)
    assignment = mesh.request_validation("producer", "safe work", "artifact")
    with pytest.raises(ValueError, match="single_operator_dev"):
        mesh.sign_vote_envelope(
            assignment.assignment_id, assignment.peers[0], approved=True
        )

    dev_mesh = ConstitutionalMesh(
        Constitution.default(), seed=914, evidence_mode="single_operator_dev"
    )
    for agent_id in ("producer", "voter-a", "voter-b", "voter-c"):
        dev_mesh.register_local_signer(agent_id)
    dev_assignment = dev_mesh.request_validation("producer", "safe work", "artifact")
    envelope = dev_mesh.sign_vote_envelope(
        dev_assignment.assignment_id, dev_assignment.peers[0], approved=True
    )
    assert envelope.evidence_mode == "single_operator_dev"


def test_c14_cycle2_invalid_submission_does_not_consume_pending_envelope() -> None:
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh, InvalidVoteSignatureError

    mesh = ConstitutionalMesh(
        Constitution.default(), seed=915, evidence_mode="single_operator_dev"
    )
    for agent_id in ("producer", "voter-a", "voter-b", "voter-c"):
        mesh.register_local_signer(agent_id)
    assignment = mesh.request_validation("producer", "safe work", "artifact")
    voter_id = assignment.peers[0]
    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id, voter_id, approved=True, reason="signed reason"
    )

    with pytest.raises(InvalidVoteSignatureError):
        mesh.submit_vote(
            assignment.assignment_id,
            voter_id,
            approved=True,
            reason="tampered reason",
            signature=envelope.signature,
        )
    assert envelope.signature in mesh._signed_envelopes_by_signature

    vote = mesh.submit_vote(
        assignment.assignment_id,
        voter_id,
        approved=True,
        reason="signed reason",
        signature=envelope.signature,
    )
    assert vote.signature == envelope.signature
"""Draft C14 receipt regressions for concatenation into the mandated test module.

All imports of not-yet-implemented C14 APIs are local so this draft is safe to
inspect and its tests collect on the base once copied into the suite.
"""


def c14_receipt_roles():
    from constitutional_swarm.governance_receipts import RoleIdentity

    return {
        role: RoleIdentity(role=role, identity_id=f"c14-{role}", display_name=role)
        for role in ("constitution_author", "executor", "validator", "auditor")
    }


def c14_receipt_record(*, accepted: bool = True):
    from constitutional_swarm.settlement_store import SettlementRecord

    return SettlementRecord(
        assignment={
            "assignment_id": "c14-assignment",
            "task_id": "c14-task",
            "artifact_id": "c14-artifact",
            "producer_id": "c14-producer",
            "content_hash": "a" * 64,
            "peers": ["c14-validator"],
        },
        result={"accepted": accepted},
        constitutional_hash="b" * 64,
        schema_version=2,
    )


def c14_receipt_sign(receipt, *, key_id: str = "c14-settlement-key"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.governance_receipts import (
        GovernanceReceiptBundle,
        SignatureRecord,
        build_receipt,
        payload_canonical_bytes,
    )

    private_key = Ed25519PrivateKey.generate()
    public_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    signed = build_receipt(
        payload=receipt.payload,
        signatures=[
            SignatureRecord(
                key_id=key_id,
                algorithm="ed25519",
                public_key_hex=public_hex,
                signature_hex=private_key.sign(payload_canonical_bytes(receipt.payload)).hex(),
            )
        ],
    )
    return GovernanceReceiptBundle(receipts=[signed]), public_hex


def c14_receipt_vote_envelope():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        key_id_for_public_key,
        sign_vote_envelope,
    )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    key_id = key_id_for_public_key(public_key)
    envelope = sign_vote_envelope(
        private_key,
        voter_id="c14-validator",
        key_id=key_id,
        task_id="c14-task",
        assignment_id="c14-assignment",
        producer_id="c14-producer",
        artifact_id="c14-artifact",
        content_hash="a" * 64,
        constitutional_hash="b" * 64,
        decision="approved",
        reason="approved",
        nonce="c14-nonce",
        issued_at=1.0,
        assigned_peers=["c14-validator"],
        quorum=1,
        protocol_version=2,
    )
    grant = {
        "identity_id": "c14-validator",
        "public_key_hex": public_hex,
        "roles": ["validator"],
    }
    return envelope, key_id, grant


def test_c14_receipt_rejects_unverified_inline_vote_evidence():
    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    with pytest.raises(ValueError, match="signed assignment"):
        receipt_from_mesh_settlement(
            c14_receipt_record(),
            [
                {
                    "voter_id": "not-registered",
                    "approved": True,
                    "reason": "claimed approval",
                    "signature": "not-a-signature",
                }
            ],
            trusted_signers={},
        )


def test_c14_receipt_never_synthesizes_vote_evidence():
    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    with pytest.raises(ValueError, match="vote envelope"):
        receipt_from_mesh_settlement(c14_receipt_record(), [])


def test_c14_receipt_recomputes_settlement_tally_from_envelopes():
    from dataclasses import replace

    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    record = _c14_v2_receipt_record(peers)
    forged_tally = replace(
        record,
        result={
            **record.result,
            "votes_for": 99,
            "votes_against": 0,
        },
    )
    with pytest.raises(ValueError, match="votes_for"):
        receipt_from_mesh_settlement(
            forged_tally,
            envelopes,
            trusted_signers=grants,
        )


def test_c14_receipt_rejects_signer_not_authorized_for_signed_role():
    from constitutional_swarm.governance_receipts import (
        receipt_from_mesh_settlement,
        verify_bundle,
    )

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    unsigned = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    bundle, public_hex = c14_receipt_sign(unsigned)
    verdict = verify_bundle(
        bundle,
        trusted_signers={
            **grants,
            "c14-settlement-key": {
                "identity_id": "c14-coordinator",
                "public_key_hex": public_hex,
                "roles": ["coordinator"],
            }
        },
    )
    assert verdict.valid is False
    assert any(issue.code == "signer_role_unauthorized" for issue in verdict.issues)


def test_c14_settlement_receipt_cannot_self_downgrade_required_signer_role():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.governance_receipts import (
        GovernanceReceiptBundle,
        SignatureRecord,
        build_receipt,
        payload_canonical_bytes,
        receipt_from_mesh_settlement,
        verify_bundle,
    )
    from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    unsigned = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    downgraded_payload = unsigned.payload.model_copy(
        update={
            "metadata": {
                **unsigned.payload.metadata,
                "signer_role": "validator",
            }
        }
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    key_id = key_id_for_public_key(public_key)
    signed = build_receipt(
        payload=downgraded_payload,
        signatures=[
            SignatureRecord(
                key_id=key_id,
                algorithm="ed25519",
                public_key_hex=public_hex,
                signature_hex=private_key.sign(
                    payload_canonical_bytes(downgraded_payload)
                ).hex(),
            )
        ],
    )
    verdict = verify_bundle(
        GovernanceReceiptBundle(receipts=[signed]),
        trusted_signers={
            **grants,
            key_id: {
                "identity_id": "c14-validator-signer",
                "public_key_hex": public_hex,
                "roles": ["validator"],
            },
        },
    )
    assert verdict.valid is False
    assert any(issue.code == "signer_role_mismatch" for issue in verdict.issues)


def test_c14_receipt_accepts_structured_settlement_role_grant():
    from constitutional_swarm.governance_receipts import (
        receipt_from_mesh_settlement,
        verify_bundle,
    )

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    unsigned = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    bundle, public_hex = c14_receipt_sign(unsigned)
    verdict = verify_bundle(
        bundle,
        trusted_signers={
            **grants,
            "c14-settlement-key": {
                "identity_id": "c14-settlement",
                "public_key_hex": public_hex,
                "roles": ["settlement"],
            }
        },
    )
    assert verdict.valid is True


def test_c14_receipt_cli_accepts_structured_trust_registry(tmp_path):
    import json

    from constitutional_swarm.governance_receipts import (
        bundle_to_json,
        receipt_from_mesh_settlement,
    )
    from constitutional_swarm.governance_receipts_cli import main

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    unsigned = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    bundle, public_hex = c14_receipt_sign(unsigned)
    trust = {
        **grants,
        "c14-settlement-key": {
            "identity_id": "c14-settlement",
            "public_key_hex": public_hex,
            "roles": ["settlement"],
        },
    }
    bundle_path = tmp_path / "bundle.json"
    trust_path = tmp_path / "trust.json"
    bundle_path.write_text(bundle_to_json(bundle), encoding="utf-8")
    trust_path.write_text(json.dumps(trust), encoding="utf-8")

    assert main([str(bundle_path), "--trusted-signers", str(trust_path)]) == 0


def test_c14_receipt_trust_registry_rejects_normalized_identity_collision():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.governance_receipts import (
        receipt_from_mesh_settlement,
        verify_bundle,
    )

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    unsigned = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    bundle, public_hex = c14_receipt_sign(unsigned)
    other_public_hex = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    verdict = verify_bundle(
        bundle,
        trusted_signers={
            **grants,
            "c14-settlement-key": {
                "identity_id": "c14-settlement",
                "public_key_hex": public_hex,
                "roles": ["settlement"],
            },
            "c14-collision": {
                "identity_id": "C14-‍settlement",
                "public_key_hex": other_public_hex,
                "roles": ["coordinator"],
            },
        },
    )
    assert verdict.valid is False
    assert any(issue.code == "trust_registry_invalid" for issue in verdict.issues)


def test_c14_aggregate_only_receipt_is_not_proof_grade():
    from constitutional_swarm.governance_receipts import (
        ReceiptPayload,
        ValidatorVote,
        build_receipt,
        verify_bundle,
    )

    unsigned = build_receipt(
        payload=ReceiptPayload(
            receipt_id="c14-legacy-aggregate",
            action="c14-artifact",
            policy_version="c14",
            policy_hash="b" * 64,
            roles=c14_receipt_roles(),
            evidence_hashes={"content": "a" * 64},
            decision="approved",
            validator_votes=[
                ValidatorVote(
                    validator_id="c14-validator",
                    decision="approve",
                    rationale="aggregate claim only",
                )
            ],
            rejected_alternative="unsigned",
            metadata={"signer_role": "coordinator"},
        )
    )
    bundle, public_hex = c14_receipt_sign(unsigned)
    verdict = verify_bundle(
        bundle,
        trusted_signers={
            "c14-settlement-key": {
                "identity_id": "c14-coordinator",
                "public_key_hex": public_hex,
                "roles": ["coordinator"],
            }
        },
    )
    assert verdict.valid is False
    assert any(issue.code == "vote_envelope_missing" for issue in verdict.issues)


def test_c14_validator_ids_strip_unicode_format_aliases():
    import pytest
    from pydantic import ValidationError

    from constitutional_swarm.governance_receipts import ReceiptPayload, ValidatorVote

    with pytest.raises((ValueError, ValidationError), match="unique"):
        ReceiptPayload(
            receipt_id="c14-id-normalization",
            action="c14-artifact",
            policy_version="c14",
            policy_hash="b" * 64,
            roles=c14_receipt_roles(),
            evidence_hashes={"content": "a" * 64},
            decision="approved",
            validator_votes=[
                ValidatorVote(
                    validator_id="validator-a",
                    decision="approve",
                    rationale="first",
                ),
                ValidatorVote(
                    validator_id="validator-\u200da",
                    decision="approve",
                    rationale="format alias",
                ),
            ],
            rejected_alternative="duplicate identity",
        )


def test_c14_signature_public_key_rejects_noncanonical_hex_at_boundary():
    import pytest
    from pydantic import ValidationError

    from constitutional_swarm.governance_receipts import SignatureRecord

    with pytest.raises((ValueError, ValidationError), match="hex"):
        SignatureRecord(
            key_id="c14-key",
            algorithm="ed25519",
            public_key_hex="GG" * 32,
            signature_hex="00" * 64,
        )


def test_c14_settlement_store_preserves_vote_envelopes_unchanged(tmp_path):
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    envelope = {
        "protocol_version": 1,
        "voter_id": "validator-a",
        "key_id": "1" * 64,
        "task_id": "c14-task",
        "assignment_id": "c14-assignment",
        "producer_id": "c14-producer",
        "artifact_id": "c14-artifact",
        "content_hash": "a" * 64,
        "constitutional_hash": "b" * 64,
        "decision": "approved",
        "reason": "approved",
        "nonce": "c14-nonce",
        "issued_at": 1.0,
        "signature": "2" * 128,
    }
    record = c14_receipt_record()
    record = record.__class__(
        assignment=record.assignment,
        result=record.result,
        constitutional_hash=record.constitutional_hash,
        schema_version=record.schema_version,
        votes=(envelope,),
    )
    store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
    store.append(record)
    assert store.load_all()[0].votes == (envelope,)


def test_c14_mesh_rejects_non_majority_approval_quorum():
    import pytest
    from acgs_lite import Constitution
    from constitutional_swarm import ConstitutionalMesh

    with pytest.raises(ValueError, match="strict majority"):
        ConstitutionalMesh(
            Constitution.default(), peers_per_validation=4, quorum=2
        )


def test_c14_mesh_complete_evidence_waits_for_all_five_signed_envelopes():
    from acgs_lite import Constitution
    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=5,
        quorum=3,
        complete_evidence=True,
        seed=414,
        evidence_mode="single_operator_dev",
    )
    mesh.register_local_signer("producer")
    for index in range(5):
        mesh.register_local_signer(f"voter-{index}")
    assignment = mesh.request_validation(
        "producer", "safe", "artifact", task_id="c14-task"
    )
    envelopes = []
    decisions = (True, True, True, False, False)
    for voter_id, approved in zip(
        assignment.peers[:-1], decisions[:-1], strict=True
    ):
        envelope = mesh.sign_vote_envelope(
            assignment.assignment_id,
            voter_id,
            approved=approved,
            reason="approve" if approved else "deny",
        )
        mesh.submit_vote_envelope(envelope)
        envelopes.append(envelope)
    assert not mesh.get_result(assignment.assignment_id).quorum_met

    last = mesh.sign_vote_envelope(
        assignment.assignment_id,
        assignment.peers[-1],
        approved=decisions[-1],
        reason="deny",
    )
    mesh.submit_vote_envelope(last)
    envelopes.append(last)
    result = mesh.get_result(assignment.assignment_id)
    assert result.accepted is True
    assert (result.votes_for, result.votes_against) == (3, 2)
    assert result.vote_envelopes == tuple(envelopes)


def test_c14_vote_envelope_rejects_unknown_version_and_tampering():
    import dataclasses
    import pytest

    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        verify_vote_envelope,
    )

    envelope, _key_id, grant = c14_receipt_vote_envelope()
    registry = VoteSignerRegistry()
    registry.register(
        grant["identity_id"],
        grant["public_key_hex"],
        roles={"validator"},
    )
    with pytest.raises(ValueError, match="protocol version"):
        dataclasses.replace(envelope, protocol_version=99)
    with pytest.raises(ValueError, match="signature"):
        verify_vote_envelope(
            dataclasses.replace(envelope, reason="tampered:reason"),
            registry,
            task_id=envelope.task_id,
            assignment_id=envelope.assignment_id,
            producer_id=envelope.producer_id,
            artifact_id=envelope.artifact_id,
            content_hash=envelope.content_hash,
            constitutional_hash=envelope.constitutional_hash,
            required_role="validator",
        )


def test_c14_vote_batch_rejects_self_vote_and_duplicate_identity():
    import pytest

    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        verify_vote_envelopes,
    )

    envelope, _key_id, grant = c14_receipt_vote_envelope()
    registry = VoteSignerRegistry()
    registry.register(
        grant["identity_id"], grant["public_key_hex"], roles={"validator"}
    )
    bindings = dict(
        task_id=envelope.task_id,
        assignment_id=envelope.assignment_id,
        producer_id=envelope.producer_id,
        artifact_id=envelope.artifact_id,
        content_hash=envelope.content_hash,
        constitutional_hash=envelope.constitutional_hash,
        required_role="validator",
    )
    with pytest.raises(ValueError, match="distinct"):
        verify_vote_envelopes((envelope, envelope), registry, **bindings)
    with pytest.raises(ValueError, match="producer identity"):
        verify_vote_envelopes(
            (envelope,),
            registry,
            **{**bindings, "producer_id": envelope.voter_id},
        )


def test_c14_vote_envelope_canonical_encoding_separates_field_partitions():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        canonical_vote_envelope_bytes,
        sign_vote_envelope,
    )

    key = Ed25519PrivateKey.generate()
    common = dict(
        voter_id="validator-a",
        producer_id="producer",
        artifact_id="artifact",
        content_hash="a" * 32,
        constitutional_hash="b" * 64,
        decision="approved",
        reason="reason:with:separators",
        nonce="nonce",
        issued_at=1.0,
        assigned_peers=("validator-a",),
        quorum=1,
        protocol_version=2,
    )
    left = sign_vote_envelope(
        key, task_id="task:assignment", assignment_id="one", **common
    )
    right = sign_vote_envelope(
        key, task_id="task", assignment_id="assignment:one", **common
    )
    assert canonical_vote_envelope_bytes(left) != canonical_vote_envelope_bytes(right)
    assert left.signature != right.signature


def test_c14_remote_request_canonical_encoding_separates_field_partitions():
    from constitutional_swarm import ConstitutionalMesh

    common = dict(
        producer_id="producer",
        artifact_id="artifact",
        content="safe:content",
        content_hash="a" * 32,
        constitutional_hash="b" * 64,
        voter_public_key="c" * 64,
        nonce="nonce",
        timestamp=1.0,
        task_id="task",
        protocol_version=2,
    )
    left = ConstitutionalMesh.build_remote_vote_request_payload(
        assignment_id="assign:voter",
        voter_id="one",
        assigned_peers=("one",),
        quorum=1,
        **common,
    )
    right = ConstitutionalMesh.build_remote_vote_request_payload(
        assignment_id="assign",
        voter_id="voter:one",
        assigned_peers=("voter:one",),
        quorum=1,
        **common,
    )
    assert left != right


def test_c14_remote_request_decoder_rejects_schema_and_scalar_confusion():
    import json
    import pytest

    from acgs_lite import Constitution
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.remote_vote_transport import (
        decode_remote_vote_request,
        encode_remote_vote_request,
    )

    mesh = ConstitutionalMesh(Constitution.default(), seed=1337)
    mesh.register_local_signer("producer")
    mesh.register_remote_agent(
        "voter",
        vote_public_key=Ed25519PrivateKey.generate().public_key(),
    )
    for voter_id in ("voter-two", "voter-three"):
        mesh.register_remote_agent(
            voter_id,
            vote_public_key=Ed25519PrivateKey.generate().public_key(),
        )
    assignment = mesh.request_validation("producer", "safe", "artifact", task_id="task")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "voter")
    payload = json.loads(encode_remote_vote_request(request))
    for mutation in (
        {**payload, "protocol_version": 99},
        {**payload, "timestamp": True},
        {**payload, "unexpected": "field"},
    ):
        with pytest.raises(ValueError, match="Malformed remote vote request"):
            decode_remote_vote_request(json.dumps(mutation))


def test_c14_remote_peer_authorizes_before_allocating_nonce_state():
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer

    constitution = Constitution.default()
    trusted = ConstitutionalMesh(constitution, seed=414)
    attacker = ConstitutionalMesh(
        constitution, seed=415, evidence_mode="single_operator_dev"
    )
    peer = LocalRemotePeer(
        agent_id="remote",
        constitution=constitution,
        trusted_request_signers={trusted.get_request_signing_public_key()},
        trusted_assigners=attacker.vote_registry.frozen_copy(),
    )
    attacker.register_local_signer("producer")
    attacker.register_remote_agent("remote", vote_public_key=peer.public_key_hex)
    attacker.register_local_signer("peer-two")
    attacker.register_local_signer("peer-three")
    assignment = attacker.request_validation("producer", "safe", "artifact")
    request = attacker.prepare_remote_vote(assignment.assignment_id, "remote")

    with pytest.raises(ValueError, match="not trusted"):
        peer.handle_vote_request(request)
    assert peer._request_nonce_caches == {}


def test_c14_remote_peer_rejects_noncanonical_signer_fingerprint():
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import LocalRemotePeer
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    with pytest.raises(ValueError, match="canonical lowercase hex"):
        LocalRemotePeer(
            agent_id="remote",
            constitution=Constitution.default(),
            trusted_request_signers={"AA" * 32},
            trusted_assigners=VoteSignerRegistry().frozen_copy(),
        )


def test_c14_remote_peer_partitions_nonce_caches_per_authorized_signer():
    import pytest
    from acgs_lite import Constitution
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer
    from constitutional_swarm.mesh import RemoteVoteReplayError

    constitution = Constitution.default()
    assigner_key = Ed25519PrivateKey.generate()
    meshes = [
        ConstitutionalMesh(
            constitution,
            seed=420 + index,
            evidence_mode="single_operator_dev",
            assigner_private_key=assigner_key,
            assigner_id="shared-remote-assigner",
        )
        for index in range(2)
    ]
    peer = LocalRemotePeer(
        agent_id="remote",
        constitution=constitution,
        trusted_request_signers={
            mesh.get_request_signing_public_key() for mesh in meshes
        },
        trusted_assigners=meshes[0].vote_registry.frozen_copy(),
    )
    requests = []
    for mesh in meshes:
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("remote", vote_public_key=peer.public_key_hex)
        mesh.register_local_signer("peer-two")
        mesh.register_local_signer("peer-three")
        assignment = mesh.request_validation("producer", "safe", "artifact")
        request = mesh.prepare_remote_vote(assignment.assignment_id, "remote")
        peer.handle_vote_request(request)
        requests.append(request)

    assert set(peer._request_nonce_caches) == {
        mesh.get_request_signing_public_key() for mesh in meshes
    }
    assert all(len(cache) == 1 for cache in peer._request_nonce_caches.values())
    with pytest.raises(RemoteVoteReplayError):
        peer.handle_vote_request(requests[0])
    assert len(peer._request_nonce_caches[requests[1].request_signer_public_key]) == 1


def test_c14_mesh_recovery_requires_verified_envelopes_and_explicit_registry(
    tmp_path,
):
    from dataclasses import replace

    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    constitution = Constitution.default()
    registry = VoteSignerRegistry()
    valid_store = JSONLSettlementStore(tmp_path / "valid.jsonl")
    writer = ConstitutionalMesh(
        constitution,
        peers_per_validation=4,
        quorum=3,
        complete_evidence=True,
        settlement_store=valid_store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=430,
        evidence_mode="single_operator_dev",
    )
    writer.register_local_signer("producer")
    for index in range(4):
        writer.register_local_signer(f"voter-{index}")
    result = writer.full_validation("producer", "safe", "artifact", task_id="task")

    recovered = ConstitutionalMesh(
        constitution,
        peers_per_validation=4,
        quorum=3,
        complete_evidence=True,
        settlement_store=valid_store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=431,
        evidence_mode="single_operator_dev",
    ).get_result(result.assignment_id)
    assert recovered.vote_envelopes == result.vote_envelopes

    valid_record = valid_store.load_all()[0]
    forged_store = JSONLSettlementStore(tmp_path / "forged.jsonl")
    forged_store.append(
        replace(
            valid_record,
            result={
                **valid_record.result,
                "accepted": False,
                "votes_for": 2,
                "votes_against": 2,
            },
        )
    )
    forged_reader = ConstitutionalMesh(
        constitution,
        peers_per_validation=4,
        quorum=3,
        complete_evidence=True,
        settlement_store=forged_store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=432,
        evidence_mode="single_operator_dev",
    )
    with pytest.raises(KeyError, match="not found"):
        forged_reader.get_result(result.assignment_id)


def test_c14_pending_recovery_reverifies_original_envelopes(tmp_path):
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.mesh import SettlementPersistenceError
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    class FailOnceStore(JSONLSettlementStore):
        fail_next = True

        def append(self, record):
            if self.fail_next:
                self.fail_next = False
                raise OSError("injected append failure")
            return super().append(record)

    constitution = Constitution.default()
    registry = VoteSignerRegistry()
    store = FailOnceStore(tmp_path / "pending.jsonl")
    writer = ConstitutionalMesh(
        constitution,
        settlement_store=store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=440,
        quorum=3,
        evidence_mode="single_operator_dev",
    )
    writer.register_local_signer("producer")
    for index in range(3):
        writer.register_local_signer(f"voter-{index}")
    with pytest.raises(SettlementPersistenceError):
        writer.full_validation("producer", "safe", "artifact", task_id="task")
    pending = store.load_pending()
    assert len(pending) == 1

    reader = ConstitutionalMesh(
        constitution,
        settlement_store=store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=441,
        quorum=3,
        evidence_mode="single_operator_dev",
    )
    recovered = reader.get_result(str(pending[0].assignment["assignment_id"]))
    assert recovered.settled is True
    assert recovered.vote_envelopes
    assert store.load_pending() == []


def test_c14_registry_failure_is_atomic_for_new_and_replaced_agents():
    import pytest
    from acgs_lite import Constitution
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(Constitution.default())
    alice_key = Ed25519PrivateKey.generate()
    bob_key = Ed25519PrivateKey.generate()
    mesh.register_remote_agent("alice", vote_public_key=alice_key.public_key())
    mesh.register_remote_agent("bob", vote_public_key=bob_key.public_key())
    alice_public = mesh.get_vote_public_key("alice")
    bob_public = mesh.get_vote_public_key("bob")

    with pytest.raises(ValueError, match="another voter identity"):
        mesh.register_remote_agent("mallory", vote_public_key=alice_key.public_key())
    assert mesh.agent_count == 2
    with pytest.raises(KeyError, match="not registered"):
        mesh.get_vote_public_key("mallory")

    with pytest.raises(ValueError, match="another voter identity"):
        mesh.register_remote_agent("alice", vote_public_key=bob_key.public_key())
    assert mesh.get_vote_public_key("alice") == alice_public
    assert mesh.get_vote_public_key("bob") == bob_public


def test_c14_untrusted_vote_envelope_never_enters_pending_signature_cache():
    import dataclasses
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(
        Constitution.default(), seed=450, evidence_mode="single_operator_dev"
    )
    mesh.register_local_signer("producer")
    for index in range(3):
        mesh.register_local_signer(f"voter-{index}")
    assignment = mesh.request_validation("producer", "safe", "artifact")
    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id, assignment.peers[0], approved=True
    )
    mesh._signed_envelopes_by_signature.clear()
    forged = dataclasses.replace(envelope, key_id="0" * 64)

    with pytest.raises(ValueError, match="not authorized"):
        mesh.submit_vote_envelope(forged)
    assert mesh._signed_envelopes_by_signature == {}


def test_c14_risk_expanded_assignment_requires_actual_peer_majority():
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(
        Constitution.default(),
        peers_per_validation=3,
        quorum=2,
        risk_scoring=True,
        seed=460,
        evidence_mode="single_operator_dev",
    )
    for agent_id in ("producer", "voter-0", "voter-1", "voter-2", "voter-3"):
        mesh.register_local_signer(agent_id)
    assignment = mesh.request_validation(
        "producer",
        "delete all user records from production database",
        "artifact",
    )
    assert len(assignment.peers) == 4

    for voter_id, approved in zip(
        assignment.peers, (True, True, False, False), strict=True
    ):
        envelope = mesh.sign_vote_envelope(
            assignment.assignment_id, voter_id, approved=approved
        )
        mesh.submit_vote_envelope(envelope)

    result = mesh.get_result(assignment.assignment_id)
    assert (result.votes_for, result.votes_against) == (2, 2)
    assert result.quorum_met is False
    assert result.settled is False


def test_c14_remote_request_rejects_nonfinite_timestamp_before_nonce_state():
    from dataclasses import replace
    import json
    from collections import OrderedDict

    import pytest
    from acgs_lite import Constitution
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.remote_vote_transport import (
        decode_remote_vote_request,
        encode_remote_vote_request,
    )

    mesh = ConstitutionalMesh(Constitution.default(), seed=1701)
    mesh.register_local_signer("producer")
    for voter_id in ("voter", "voter-two", "voter-three"):
        mesh.register_remote_agent(
            voter_id,
            vote_public_key=Ed25519PrivateKey.generate().public_key(),
        )
    assignment = mesh.request_validation("producer", "safe", "artifact", task_id="task")
    valid_request = mesh.prepare_remote_vote(assignment.assignment_id, "voter")
    valid_payload = json.loads(encode_remote_vote_request(valid_request))
    for timestamp in (float("nan"), float("inf"), float("-inf")):
        request = replace(valid_request, timestamp=timestamp)
        with pytest.raises(ValueError):
            encode_remote_vote_request(request)
        payload = {**valid_payload, "timestamp": timestamp}
        with pytest.raises(ValueError, match="finite float"):
            decode_remote_vote_request(json.dumps(payload))
        nonce_cache = OrderedDict()
        with pytest.raises(ValueError, match="finite float"):
            ConstitutionalMesh.verify_remote_vote_request(
                request, nonce_cache=nonce_cache, now=1.0
            )
        assert nonce_cache == OrderedDict()


def test_c14_unregister_normalized_alias_removes_all_agent_state():
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh

    mesh = ConstitutionalMesh(Constitution.default())
    mesh.register_local_signer("  Voter\u200d-One  ")
    assert mesh.get_vote_public_key("VOTER-ONE")

    mesh.unregister_agent(" VOTER\u200d-ONE ")

    assert mesh.agent_count == 0
    with pytest.raises(KeyError, match="not registered"):
        mesh.get_vote_public_key("voter-one")
    with pytest.raises(ValueError, match="not authorized"):
        mesh.vote_registry.authorize("voter-one", "0" * 64)


def test_c14_trust_grants_never_escalate_voter_role_to_validator():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    registry = VoteSignerRegistry()
    key = Ed25519PrivateKey.generate().public_key()
    voter_key_id = registry.register("voter", key, roles={"voter"})
    validator_key_id = registry.register(
        "validator", Ed25519PrivateKey.generate().public_key(), roles={"validator"}
    )

    grants = registry.trust_grants(role="validator")
    assert voter_key_id not in grants
    assert grants[validator_key_id]["roles"] == ["validator"]


def test_c14_detached_vote_live_path_rejects_legacy_and_v2_separates_fields():
    import pytest

    from constitutional_swarm import ConstitutionalMesh

    common = dict(
        approved=True,
        reason="reason:with:colons",
        constitutional_hash="constitution",
        content_hash="content",
    )
    left = dict(assignment_id="assignment:voter", voter_id="one", **common)
    right = dict(assignment_id="assignment", voter_id="voter:one", **common)

    with pytest.raises(ValueError, match="unsupported"):
        ConstitutionalMesh.build_vote_payload(**left, protocol_version=1)
    assert ConstitutionalMesh.build_vote_payload(**left) != (
        ConstitutionalMesh.build_vote_payload(**right)
    )
    with pytest.raises(ValueError, match="unsupported"):
        ConstitutionalMesh.build_vote_payload(**left, protocol_version=99)


def test_c14_receipt_preserves_empty_reason_envelope_and_projects_display_text():
    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    envelope = envelopes[0]
    # Re-sign because reason is part of the authenticated envelope.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key, sign_vote_envelope

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    voter_key_id = key_id_for_public_key(public_key)
    voter_grant = {
        "identity_id": envelope.voter_id,
        "public_key_hex": public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex(),
        "roles": ["validator"],
    }
    envelope = sign_vote_envelope(
        private_key,
        voter_id=envelope.voter_id,
        task_id=envelope.task_id,
        assignment_id=envelope.assignment_id,
        producer_id=envelope.producer_id,
        artifact_id=envelope.artifact_id,
        content_hash=envelope.content_hash,
        constitutional_hash=envelope.constitutional_hash,
        decision=envelope.decision,
        reason="",
        nonce=envelope.nonce,
        issued_at=envelope.issued_at,
        assigned_peers=peers,
        quorum=3,
        assignment_digest=envelope.assignment_digest,
    )
    grants.pop(envelopes[0].key_id)
    grants[voter_key_id] = voter_grant
    envelopes[0] = envelope
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    assert receipt.payload.vote_envelopes[0]["reason"] == ""
    assert receipt.payload.validator_votes[0].rationale == "No rationale provided"


def test_c14_receipt_rejects_tie_and_non_boolean_outcome():
    from dataclasses import replace

    import pytest
    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate(
        (True, True, False, False), quorum=3
    )
    tied = replace(
        _c14_v2_receipt_record(peers),
        result={"accepted": True, "votes_for": 2, "votes_against": 2},
    )
    with pytest.raises(ValueError, match="strict-majority"):
        receipt_from_mesh_settlement(tied, envelopes, trusted_signers=grants)

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    invalid_bool = replace(_c14_v2_receipt_record(peers), result={"accepted": 1})
    with pytest.raises(ValueError, match="boolean"):
        receipt_from_mesh_settlement(invalid_bool, envelopes, trusted_signers=grants)


def test_c14_schema_v2_recovery_requires_explicit_v2_proof(tmp_path, caplog):
    from dataclasses import replace

    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    constitution = Constitution.default()
    registry = VoteSignerRegistry()
    source = JSONLSettlementStore(tmp_path / "source.jsonl")
    writer = ConstitutionalMesh(
        constitution,
        quorum=3,
        settlement_store=source,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=470,
        evidence_mode="single_operator_dev",
    )
    for agent_id in ("producer", "voter-0", "voter-1", "voter-2"):
        writer.register_local_signer(agent_id)
    result = writer.full_validation("producer", "safe", "artifact", task_id="task")
    record = source.get(result.assignment_id)
    assert record is not None
    proof = dict(record.result["proof"])

    missing_store = JSONLSettlementStore(tmp_path / "missing.jsonl")
    missing_store.append(
        replace(
            record,
            result={
                **record.result,
                "proof": {key: value for key, value in proof.items() if key != "protocol_version"},
            },
        )
    )
    # C28 mesh-settle-1: a malformed record is quarantined, never authoritative.
    with caplog.at_level("WARNING", logger="constitutional_swarm.mesh.core"):
        reader = ConstitutionalMesh(
            constitution,
            quorum=3,
            settlement_store=missing_store,
            vote_registry=registry,
            **_c14_external_assigner(registry),
        )
    assert f"quarantining settlement {result.assignment_id}" in caplog.text
    assert "missing protocol_version" in caplog.text
    with pytest.raises(KeyError, match="not found"):
        reader.get_result(result.assignment_id)

    legacy_store = JSONLSettlementStore(tmp_path / "legacy.jsonl")
    legacy_store.append(
        replace(record, result={**record.result, "proof": {**proof, "protocol_version": 1}})
    )
    reader = ConstitutionalMesh(
        constitution,
        quorum=3,
        settlement_store=legacy_store,
        vote_registry=registry,
        **_c14_external_assigner(registry),
    )
    with pytest.raises(KeyError, match="not found"):
        reader.get_result(result.assignment_id)

    mode_tampered = JSONLSettlementStore(tmp_path / "mode-tampered.jsonl")
    mode_tampered.append(
        replace(
            record,
            assignment={**record.assignment, "evidence_mode": "independent"},
        )
    )
    reader = ConstitutionalMesh(
        constitution,
        peers_per_validation=5,
        quorum=5,
        settlement_store=mode_tampered,
        vote_registry=registry,
        **_c14_external_assigner(registry),
    )
    with pytest.raises(KeyError, match="not found"):
        reader.get_result(result.assignment_id)


def _c14_load_testnet_deploy_module():
    import importlib.util
    from pathlib import Path

    script_path = Path(__file__).parents[1] / "scripts" / "testnet_deploy.py"
    spec = importlib.util.spec_from_file_location("c14_testnet_deploy", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_c14_rule_codifier_without_store_is_read_only_and_cannot_admit():
    import pytest

    from constitutional_swarm.bittensor.rule_codifier import RuleCodifier
    from constitutional_swarm.constants import CONSTITUTIONAL_HASH

    codifier = RuleCodifier(CONSTITUTIONAL_HASH)
    assert codifier.find_clusters([]) == []
    with pytest.raises(ValueError, match="injected trusted PrecedentStore"):
        _ = codifier.precedent_store
    with pytest.raises(ValueError, match="injected trusted PrecedentStore"):
        codifier.find_clusters([c14_precedent_signed_record(case_id="no-store")])


def test_c14_precedent_backed_codifier_requires_store_before_observation():
    import pytest

    from constitutional_swarm.bittensor.precedent_backed_codifier import (
        PrecedentBackedCodifier,
    )

    codifier = PrecedentBackedCodifier()
    assert codifier.find_clusters([]) == []
    assert codifier.propose_rules([]) == []
    with pytest.raises(ValueError, match="injected trusted PrecedentStore"):
        codifier.observe(c14_precedent_signed_record(case_id="no-store-adapter"))


def test_c14_testnet_validator_rejects_missing_voter_grants_before_runtime(
    tmp_path, monkeypatch
):
    import argparse

    import pytest

    deploy = _c14_load_testnet_deploy_module()
    runtime_checked = False

    def _unexpected_runtime_check():
        nonlocal runtime_checked
        runtime_checked = True
        raise AssertionError("runtime check must follow voter grant validation")

    monkeypatch.setattr(deploy, "_check_bittensor", _unexpected_runtime_check)
    args = argparse.Namespace(
        constitution=str(tmp_path / "missing.yaml"),
        authorized_voters=str(tmp_path / "missing-voters.json"),
    )
    with pytest.raises(ValueError, match="authorized voter"):
        deploy.cmd_validator(args)
    assert runtime_checked is False


def test_c14_testnet_voter_grants_reject_empty_malformed_and_ambiguous_entries(
    tmp_path,
):
    import json

    import pytest

    deploy = _c14_load_testnet_deploy_module()
    grants_path = tmp_path / "invalid-authorized-voters.json"
    valid = [
        {
            "identity_id": f"validator-{index}",
            "public_key_hex": f"{index + 1:02x}" * 32,
            "vote_host": f"voter-{index}.invalid",
            "vote_port": 9000 + index,
        }
        for index in range(6)
    ]
    invalid_documents = (
        {"authorized_voters": []},
        {"authorized_voters": valid[:5]},
        {"authorized_voters": [{**valid[0], "public_key_hex": "GG" * 32}, *valid[1:]]},
        {
            "authorized_voters": [
                valid[0],
                {**valid[1], "identity_id": "  VALIDATOR-0\u200d  "},
                *valid[2:],
            ]
        },
        {
            "authorized_voters": [
                valid[0],
                {**valid[1], "public_key_hex": valid[0]["public_key_hex"]},
                *valid[2:],
            ]
        },
    )
    for document in invalid_documents:
        grants_path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(ValueError, match="authorized voter|duplicate|shared"):
            deploy._load_authorized_voter_keys(str(grants_path))


def test_c14_testnet_provisioning_separates_frozen_owner_trust(tmp_path):
    import json

    import pytest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    deploy = _c14_load_testnet_deploy_module()
    constitution_path = _c14_precedent_constitution_file(tmp_path)
    grants = []
    for index in range(6):
        private_key = Ed25519PrivateKey.generate()
        grants.append(
            {
                "identity_id": f"validator-{index}",
                "public_key_hex": private_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ).hex(),
                "vote_host": f"voter-{index}.invalid",
                "vote_port": 9000 + index,
            }
        )
    grants_path = tmp_path / "authorized-voters.json"
    grants_path.write_text(
        json.dumps({"authorized_voters": grants}),
        encoding="utf-8",
    )

    voter_keys = deploy._load_authorized_voter_keys(str(grants_path))
    validator, owner = deploy._build_validator_runtime(
        constitution_path,
        voter_keys,
        peers=5,
        quorum=3,
    )
    owner_registry = owner.precedent_store.vote_registry
    assert owner_registry is not None
    assert owner_registry is not validator.mesh.vote_registry
    assert owner_registry.frozen is True
    assert len(validator.mesh.vote_registry.trust_grants(role="validator")) == 6
    public_keys_before = {
        identity: validator.mesh.get_vote_public_key(identity)
        for identity in voter_keys
    }
    from acgs_lite import Constitution

    validator.rotate_constitution(Constitution.from_yaml(constitution_path))
    assert {
        identity: validator.mesh.get_vote_public_key(identity)
        for identity in voter_keys
    } == public_keys_before

    replacement = Ed25519PrivateKey.generate().public_key()
    validator.mesh.vote_registry.replace(
        "validator-1", replacement, roles={"voter", "validator"}
    )
    assert owner_registry.trust_grants(role="validator") != (
        validator.mesh.vote_registry.trust_grants(role="validator")
    )
    with pytest.raises(AttributeError):
        owner_registry.replace("validator-2", replacement)


def _c14_testnet_response(*, authenticated_hotkey: str, miner_uid: str, case, owner):
    from types import SimpleNamespace

    from constitutional_swarm.bittensor.synapse_adapter import (
        REQUEST_BINDING_FIELDS,
        deliberation_to_bt,
    )

    dispatched = deliberation_to_bt(case.synapse)
    return SimpleNamespace(
        **{name: getattr(dispatched, name) for name in REQUEST_BINDING_FIELDS},
        axon=SimpleNamespace(hotkey=authenticated_hotkey),
        miner_uid=miner_uid,
        judgment="Approve with explicit safeguards and audit evidence",
        reasoning="The action is bounded and constitutionally compliant",
        artifact_hash="c14-authenticated-response-artifact",
        miner_constitution_hash=owner.constitution_hash,
        dna_valid=True,
        dna_violations=[],
        dna_latency_ns=0,
        response_timestamp=1.0,
        request_content_hash=case.synapse.content_hash,
    )


@pytest.mark.asyncio
async def test_c14_testnet_dispatch_rejects_spoofed_or_missing_authenticated_hotkey(
    monkeypatch,
):
    from types import SimpleNamespace

    import pytest

    deploy = _c14_load_testnet_deploy_module()
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    monkeypatch.setattr(adapter, "verify_axon_response_signature", lambda *_a, **_kw: None)
    monkeypatch.setattr(adapter, "verify_judgment_response_signature", lambda *_a, **_kw: None)
    from constitutional_swarm.bittensor.synapses import DeliberationSynapse

    case = SimpleNamespace(
        synapse=DeliberationSynapse(
            task_id="authenticated-task",
            task_dag_json='{"task":"authenticated-task"}',
            constitution_hash="c" * 64,
            domain="governance",
        )
    )
    owner = SimpleNamespace(constitution_hash="c" * 64)

    class RejectIfCalled:
        async def validate_remote(self, _judgment, **_kwargs):
            raise AssertionError("validation must follow authenticated identity checks")

        def record_result(self, *_args):
            raise AssertionError("admission must follow authenticated identity checks")

    validator = RejectIfCalled()
    for authenticated_hotkey, miner_uid, message in (
        ("untrusted-b", "authorized-a", "not authorized"),
        ("", "authorized-a", "authenticated hotkey"),
        ("authorized-a", "untrusted-b", "does not match"),
    ):
        response = _c14_testnet_response(
            authenticated_hotkey=authenticated_hotkey,
            miner_uid=miner_uid,
            case=case,
            owner=owner,
        )
        with pytest.raises(ValueError, match=message):
            await deploy._record_authenticated_response(
                response,
                expected_hotkey=authenticated_hotkey or "authorized-a",
                expected_dendrite_hotkey="local-validator",
                authorized_identities={"authorized-a"},
                validator=validator,
                owner=validator,
                case=case,
                peer_routes={},
            )


@pytest.mark.asyncio
async def test_c14_testnet_dispatch_accepts_canonical_authenticated_identity(monkeypatch):
    from types import SimpleNamespace

    deploy = _c14_load_testnet_deploy_module()
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    monkeypatch.setattr(adapter, "verify_axon_response_signature", lambda *_a, **_kw: None)
    monkeypatch.setattr(adapter, "verify_judgment_response_signature", lambda *_a, **_kw: None)
    from constitutional_swarm.bittensor.synapses import DeliberationSynapse

    case = SimpleNamespace(
        synapse=DeliberationSynapse(
            task_id="authenticated-task",
            task_dag_json='{"task":"authenticated-task"}',
            constitution_hash="c" * 64,
            domain="governance",
        )
    )
    owner_context = SimpleNamespace(constitution_hash="c" * 64)
    response = _c14_testnet_response(
        authenticated_hotkey="  AUTHORIZED-A\u200d  ",
        miner_uid="authorized-a",
        case=case,
        owner=owner_context,
    )
    validated = object()
    admitted = object()

    class Validator:
        async def validate_remote(self, judgment, **kwargs):
            assert judgment.miner_uid == "authorized-a"
            assert kwargs["peer_routes"] == {}
            return validated

    class Owner:
        def record_result(self, received_case, judgment, validation):
            assert received_case is case
            assert judgment.miner_uid == "authorized-a"
            assert validation is validated
            return admitted

    assert (
        await deploy._record_authenticated_response(
            response,
            expected_hotkey="authorized-a",
            expected_dendrite_hotkey="local-validator",
            authorized_identities={"authorized-a"},
            validator=Validator(),
            owner=Owner(),
            case=case,
            peer_routes={},
        )
        is admitted
    )


@pytest.mark.asyncio
async def test_c14_testnet_authenticated_dispatch_admits_configured_voter(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from constitutional_swarm.mesh.vote_envelope import (
        sign_vote_envelope,
        signed_assignment_digest,
    )
    from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse

    deploy = _c14_load_testnet_deploy_module()
    import constitutional_swarm.bittensor.synapse_adapter as adapter

    monkeypatch.setattr(adapter, "verify_axon_response_signature", lambda *_a, **_kw: None)
    monkeypatch.setattr(adapter, "verify_judgment_response_signature", lambda *_a, **_kw: None)
    private_keys = {
        f"validator-{index}": Ed25519PrivateKey.generate() for index in range(6)
    }
    voter_keys = {
        identity: deploy._AuthorizedVoter(
            private_key.public_key(),
            (identity, 9000 + index),
        )
        for index, (identity, private_key) in enumerate(private_keys.items())
    }
    validator, owner = deploy._build_validator_runtime(
        _c14_precedent_constitution_file(tmp_path),
        voter_keys,
        peers=5,
        quorum=3,
    )
    case = owner.package_case("safe authenticated action", "governance")
    response = _c14_testnet_response(
        authenticated_hotkey="validator-0",
        miner_uid="validator-0",
        case=case,
        owner=owner,
    )
    class ExternalVoteClient:
        async def request_vote(self, host, port, request, *, timeout):
            del port, timeout
            return RemoteVoteResponse(
                sign_vote_envelope(
                    private_keys[host],
                    voter_id=request.voter_id,
                    task_id=request.task_id,
                    assignment_id=request.assignment_id,
                    producer_id=request.producer_id,
                    artifact_id=request.artifact_id,
                    content_hash=request.content_hash,
                    constitutional_hash=request.constitutional_hash,
                    decision="approved",
                    reason="independent remote approval",
                    nonce=request.nonce,
                    issued_at=request.timestamp,
                    assigned_peers=request.assigned_peers,
                    quorum=request.quorum,
                    evidence_mode=request.evidence_mode,
                    assignment_digest=signed_assignment_digest(request.signed_assignment),
                )
            )

    admitted = await deploy._record_authenticated_response(
        response,
        expected_hotkey="validator-0",
        expected_dendrite_hotkey="local-validator",
        authorized_identities=set(voter_keys),
        validator=validator,
        owner=owner,
        case=case,
        peer_routes={identity: grant.route for identity, grant in voter_keys.items()},
        vote_client=ExternalVoteClient(),
    )
    assert admitted is not None
    assert owner.precedent_store.size == 1


def test_c14_testnet_runtime_requires_one_more_signer_than_selected_peers(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import pytest

    deploy = _c14_load_testnet_deploy_module()
    voter_keys = {
        f"validator-{index}": Ed25519PrivateKey.generate() for index in range(7)
    }
    with pytest.raises(ValueError, match="at least 8 authorized voter identities"):
        deploy._build_validator_runtime(
            _c14_precedent_constitution_file(tmp_path),
            voter_keys,
            peers=7,
            quorum=4,
        )


def test_c14_testnet_rejects_missing_configured_metagraph_identity():
    from types import SimpleNamespace

    import pytest

    deploy = _c14_load_testnet_deploy_module()
    metagraph = SimpleNamespace(
        hotkeys=["authorized-a"],
        axons=[SimpleNamespace(hotkey="authorized-a")],
    )
    with pytest.raises(RuntimeError, match="missing configured authorized voter"):
        deploy._authorized_metagraph_axons(
            metagraph,
            {"authorized-a", "missing-b"},
        )


def test_c14_shipped_fixture_binds_signed_producer_to_declared_executor():
    from constitutional_swarm.governance_fixtures import (
        collusion_bundle,
        fixture_trusted_signers,
        slow_burn_bundle,
        valid_provenance_bundle,
    )
    from constitutional_swarm.mesh.vote_envelope import canonical_assigned_peers_hash

    bundles = [valid_provenance_bundle(), collusion_bundle(), slow_burn_bundle()]
    expected_peers = [
        "review-agent",
        "audit-agent",
        "deploy-agent",
        "privacy-agent",
    ]
    trusted = fixture_trusted_signers()
    for bundle in bundles:
        for receipt in bundle.receipts:
            payload = receipt.payload
            producer_id = payload.metadata["producer_id"]
            envelopes = payload.vote_envelopes or []
            assert payload.roles["executor"].identity_id == producer_id
            assert payload.assigned_peers == expected_peers
            assert len(envelopes) == len(expected_peers)
            assert {envelope["voter_id"] for envelope in envelopes} == set(expected_peers)
            assert {envelope["producer_id"] for envelope in envelopes} == {producer_id}
            assert {envelope["protocol_version"] for envelope in envelopes} == {3}
            assert {envelope["assigned_peer_count"] for envelope in envelopes} == {4}
            assert {envelope["quorum"] for envelope in envelopes} == {3}
            assert {envelope["evidence_mode"] for envelope in envelopes} == {
                "independent"
            }
            assert {envelope["assigned_peers_hash"] for envelope in envelopes} == {
                canonical_assigned_peers_hash(expected_peers)
            }
            assert payload.metadata["vote_evidence_version"] == (
                "constitutional-swarm.vote-envelope.v3"
            )
            assert payload.metadata["signer_role"] == "settlement"
            for signature in receipt.signatures:
                assert "settlement" in trusted[signature.key_id]["roles"]
    assert bundles[0].answer_key["proposer"] == "migration-plan-agent"


def test_c14_testnet_verifies_axon_response_signature_against_selected_target():
    from types import SimpleNamespace

    bt = pytest.importorskip("bittensor")

    from constitutional_swarm.bittensor.synapse_adapter import verify_axon_response_signature

    target = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    attacker = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dendrite = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    nonce = 123456789
    uuid = "c14-response-uuid"
    message = f"{nonce}.{dendrite.ss58_address}.{target.ss58_address}.{uuid}"

    def response(signature):
        return SimpleNamespace(
            dendrite=SimpleNamespace(hotkey=dendrite.ss58_address),
            axon=SimpleNamespace(
                hotkey=target.ss58_address,
                nonce=nonce,
                uuid=uuid,
                signature=signature,
            ),
        )

    valid = "0x" + target.sign(message).hex()
    verify_axon_response_signature(
        response(valid),
        expected_axon_hotkey=target.ss58_address,
        expected_dendrite_hotkey=dendrite.ss58_address,
    )
    for invalid in (None, "", "0x" + attacker.sign(message).hex()):
        with pytest.raises(ValueError, match="signature"):
            verify_axon_response_signature(
                response(invalid),
                expected_axon_hotkey=target.ss58_address,
                expected_dendrite_hotkey=dendrite.ss58_address,
            )


def test_c14_judgment_response_signature_binds_request_target_and_body():
    bt = pytest.importorskip("bittensor")

    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        sign_judgment_response,
        verify_judgment_response_signature,
    )

    target = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    attacker = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dendrite = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    response = GovernanceDeliberation(
        task_id="signed-response-task",
        task_dag_json='{"task":"signed-response-task"}',
        constitution_hash="c" * 64,
        domain="governance",
        judgment="approve",
        reasoning="bounded and compliant",
        artifact_hash="artifact-hash",
        miner_uid=target.ss58_address,
        response_timestamp=123.0,
    )
    response.dendrite.hotkey = dendrite.ss58_address
    sign_judgment_response(response, target)
    verify_judgment_response_signature(
        response,
        expected_signer_hotkey=target.ss58_address,
        expected_dendrite_hotkey=dendrite.ss58_address,
    )

    response.judgment = "tampered"
    with pytest.raises(ValueError, match="body signature"):
        verify_judgment_response_signature(
            response,
            expected_signer_hotkey=target.ss58_address,
            expected_dendrite_hotkey=dendrite.ss58_address,
        )
    response.judgment = "approve"
    response.response_signer_hotkey = attacker.ss58_address
    with pytest.raises(ValueError, match="signer"):
        verify_judgment_response_signature(
            response,
            expected_signer_hotkey=target.ss58_address,
            expected_dendrite_hotkey=dendrite.ss58_address,
        )


def test_c14_validator_command_dispatches_only_body_signed_target_response(
    monkeypatch, tmp_path, capsys
):
    import argparse
    import time
    from types import SimpleNamespace

    bt = pytest.importorskip("bittensor")

    from constitutional_swarm.bittensor.synapse_adapter import (
        deliberation_to_bt,
        sign_judgment_response,
    )
    from constitutional_swarm.bittensor.synapses import DeliberationSynapse

    deploy = _c14_load_testnet_deploy_module()
    target = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    dendrite_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    case = SimpleNamespace(
        synapse=DeliberationSynapse(
            task_id="command-authenticated-task",
            task_dag_json='{"task":"command-authenticated-task"}',
            constitution_hash="c" * 64,
            domain="governance",
        )
    )

    def response(*, tampered: bool):
        wire = deliberation_to_bt(case.synapse)
        wire.judgment = "approve"
        wire.reasoning = "bounded and compliant"
        wire.artifact_hash = "command-artifact"
        wire.miner_uid = target.ss58_address
        wire.miner_constitution_hash = case.synapse.constitution_hash
        wire.response_timestamp = 123.0
        wire.dendrite.hotkey = dendrite_key.ss58_address
        wire.axon.hotkey = target.ss58_address
        wire.axon.nonce = 123456789
        wire.axon.uuid = "command-response-uuid"
        sign_judgment_response(wire, target)
        message = (
            f"{wire.axon.nonce}.{dendrite_key.ss58_address}."
            f"{target.ss58_address}.{wire.axon.uuid}"
        )
        wire.axon.signature = "0x" + target.sign(message).hex()
        if tampered:
            wire.judgment = "tampered after signing"
        return wire

    class Validator:
        constitution_hash = "c" * 64
        stats = {}

        def __init__(self):
            self.validated = 0

        async def validate_remote(self, _judgment, **_kwargs):
            self.validated += 1
            return object()

        def compute_emission_weights(self):
            return {}

    class Owner:
        constitution_hash = "c" * 64

        def __init__(self):
            self.recorded = 0

        def package_case(self, *_args):
            return case

        def record_result(self, *_args):
            self.recorded += 1
            return object()

    constitution = tmp_path / "constitution.yaml"
    constitution.write_text("name: command-test\nrules: []\n", encoding="utf-8")
    args = argparse.Namespace(
        constitution=str(constitution),
        authorized_voters="unused.json",
        authority_keys="unused-authority.json",
        peers=5,
        quorum=3,
        wallet_name="validator",
        wallet_hotkey="default",
        netuid=1,
        epoch_seconds=1,
    )

    for tampered, expected_records in ((True, 0), (False, 1)):
        validator = Validator()
        owner = Owner()
        metagraph = SimpleNamespace(
            n=1,
            hotkeys=[target.ss58_address],
            axons=[SimpleNamespace(hotkey=target.ss58_address)],
            sync=lambda: None,
        )
        subtensor = SimpleNamespace(
            register=lambda **_kwargs: None,
            metagraph=lambda **_kwargs: metagraph,
        )

        class Dendrite:
            def __init__(self, **_kwargs):
                pass

            async def __call__(self, **_kwargs):
                return [response(tampered=tampered)]

        monkeypatch.setattr(deploy, "_check_bittensor", lambda: None)
        monkeypatch.setattr(
            deploy,
            "_load_authority_keys",
            lambda _path: SimpleNamespace(
                assigner_id="test-assigner",
                assigner_private_key=object(),
                request_signing_private_key=object(),
            ),
        )
        monkeypatch.setattr(
                deploy,
                "_load_authorized_voter_keys",
                lambda _path: {
                    target.ss58_address.casefold(): SimpleNamespace(
                        route=("127.0.0.1", 9000)
                    )
                },
        )
        monkeypatch.setattr(
            deploy,
            "_build_validator_runtime",
            lambda *_args, **_kwargs: (validator, owner),
        )
        monkeypatch.setattr(
            bt,
            "wallet",
            lambda **_kwargs: SimpleNamespace(
                name="validator",
                hotkey=dendrite_key,
                hotkey_str=dendrite_key.ss58_address,
            ),
            raising=False,
        )
        monkeypatch.setattr(bt, "subtensor", lambda **_kwargs: subtensor, raising=False)
        monkeypatch.setattr(bt, "Dendrite", Dendrite)
        monkeypatch.setattr(time, "sleep", lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt))

        deploy.cmd_validator(args)
        assert validator.validated == expected_records
        assert owner.recorded == expected_records

    assert "body signature is invalid" in capsys.readouterr().err


async def test_c14_miner_axon_signs_request_bound_judgment_body(tmp_path):
    bt = pytest.importorskip("bittensor")

    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig
    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        verify_judgment_response_signature,
    )

    miner_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    constitution_path = _c14_precedent_constitution_file(tmp_path)

    async def deliberate(_task, _context, _metadata):
        return "approve", "bounded and compliant"

    miner = ConstitutionalMiner(
        MinerConfig(
            constitution_path=constitution_path,
            agent_id=miner_key.ss58_address,
        ),
        deliberation_handler=deliberate,
    )
    server = MinerAxonServer(
        miner,
        allow_unauthenticated=True,
        response_signing_key=miner_key,
    )
    request = GovernanceDeliberation(
        task_id="signed-axon-task",
        task_dag_json='{"task":"signed-axon-task"}',
        constitution_hash=miner.constitution_hash,
        domain="governance",
    )
    request.dendrite.hotkey = validator_key.ss58_address
    response = await server.forward(request)
    verify_judgment_response_signature(
        response,
        expected_signer_hotkey=miner_key.ss58_address,
        expected_dendrite_hotkey=validator_key.ss58_address,
    )


def test_c14_testnet_miner_uses_wallet_address_as_signed_producer(
    monkeypatch, tmp_path
):
    import argparse
    import asyncio
    from types import SimpleNamespace

    bt = pytest.importorskip("bittensor")

    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        verify_judgment_response_signature,
    )

    deploy = _c14_load_testnet_deploy_module()
    miner_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    validator_key = bt.Keypair.create_from_mnemonic(bt.Keypair.generate_mnemonic())
    wallet = SimpleNamespace(
        name="miner-wallet",
        hotkey=miner_key,
        hotkey_str="default",
    )
    attached = {}

    class Axon:
        async def default_verify(self, _synapse):
            return None

        def attach(self, **handlers):
            attached.update(handlers)

        def serve(self, **_kwargs):
            return self

        def start(self):
            return None

        def stop(self):
            return None

    subtensor = SimpleNamespace(register=lambda **_kwargs: None)
    monkeypatch.setattr(deploy, "_check_bittensor", lambda: None)
    monkeypatch.setattr(bt, "wallet", lambda **_kwargs: wallet, raising=False)
    monkeypatch.setattr(bt, "subtensor", lambda **_kwargs: subtensor, raising=False)
    monkeypatch.setattr(bt, "axon", lambda **_kwargs: Axon(), raising=False)
    monkeypatch.setattr(bt, "logging", SimpleNamespace(info=lambda *_args: None))
    original_new_event_loop = asyncio.new_event_loop

    def stopped_loop():
        loop = original_new_event_loop()
        loop.call_soon(loop.stop)
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", stopped_loop)
    args = argparse.Namespace(
        constitution=_c14_precedent_constitution_file(tmp_path),
        wallet_name="miner-wallet",
        wallet_hotkey="default",
        netuid=1,
        port=8091,
        capabilities="governance-judgment",
        domains="governance",
        trusted_validators=validator_key.ss58_address,
    )
    deploy.cmd_miner(args)

    from acgs_lite import Constitution

    request = GovernanceDeliberation(
        task_id="deployed-miner-task",
        task_dag_json='{"task":"deployed-miner-task"}',
        constitution_hash=Constitution.from_yaml(args.constitution).hash,
        domain="governance",
    )
    request.dendrite.hotkey = validator_key.ss58_address
    loop = original_new_event_loop()
    try:
        response = loop.run_until_complete(attached["forward_fn"](request))
    finally:
        loop.close()
    assert response.miner_uid == miner_key.ss58_address
    verify_judgment_response_signature(
        response,
        expected_signer_hotkey=miner_key.ss58_address,
        expected_dendrite_hotkey=validator_key.ss58_address,
    )


def test_c14_receipt_binds_vote_envelopes_to_signed_assignment_roster():
    from dataclasses import replace

    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    record = _c14_v2_receipt_record(peers)
    outsider = replace(
        record,
        assignment={**record.assignment, "peers": [*peers[:-1], "never-assigned"]},
    )
    with pytest.raises(ValueError, match="expected peers"):
        receipt_from_mesh_settlement(outsider, envelopes, trusted_signers=grants)
    duplicate = replace(
        record,
        assignment={
            **record.assignment,
            "peers": [*peers[:-1], peers[0]],
        },
    )
    with pytest.raises(ValueError, match="distinct canonical"):
        receipt_from_mesh_settlement(duplicate, envelopes, trusted_signers=grants)
    producer = replace(
        record,
        assignment={**record.assignment, "peers": [*peers[:-1], "c14-v2-producer"]},
    )
    with pytest.raises(ValueError, match="producer identity"):
        receipt_from_mesh_settlement(producer, envelopes, trusted_signers=grants)
    receipt = receipt_from_mesh_settlement(
        record, envelopes, trusted_signers=grants
    )
    assert receipt.payload.assigned_peers == peers
    assert receipt.payload.metadata["assigned_peer_count"] == "5"


def test_c14_receipt_verifier_uses_signed_roster_for_membership_and_denominator():
    from constitutional_swarm.governance_receipts import (
        receipt_from_mesh_settlement,
        verify_bundle,
    )

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    outside_payload = receipt.payload.model_copy(
        update={"assigned_peers": [*peers[:-1], "never-assigned"]}
    )
    outside_bundle, receipt_public = c14_receipt_sign(
        receipt.model_copy(update={"payload": outside_payload})
    )
    trusted = {
        **grants,
        "c14-settlement-key": {
            "identity_id": "c14-settlement",
            "public_key_hex": receipt_public,
            "roles": ["settlement"],
        },
    }
    verdict = verify_bundle(outside_bundle, trusted_signers=trusted)
    assert verdict.valid is False
    assert "vote_electorate_invalid" in {issue.code for issue in verdict.issues}
    count_payload = receipt.payload.model_copy(
        update={
            "metadata": {**receipt.payload.metadata, "assigned_peer_count": "4"}
        }
    )
    count_bundle, receipt_public = c14_receipt_sign(
        receipt.model_copy(update={"payload": count_payload})
    )
    trusted["c14-settlement-key"]["public_key_hex"] = receipt_public
    verdict = verify_bundle(count_bundle, trusted_signers=trusted)
    assert verdict.valid is False
    assert "vote_peer_count_invalid" in {issue.code for issue in verdict.issues}


def test_c14_custom_peer_selection_fails_before_assignment_commit():
    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh

    policies = (
        (
            lambda available, needed, producer: [
                producer,
                available[0],
                available[1],
            ],
            "unavailable or producer",
        ),
        (
            lambda available, needed, producer: [
                available[0],
                available[0],
                available[1],
            ],
            "distinct",
        ),
        (lambda available, needed, producer: [available[0]], "exactly 3"),
    )
    for policy, message in policies:
        mesh = ConstitutionalMesh(
            Constitution.default(),
            peers_per_validation=3,
            quorum=2,
            trust_policy=policy,
        )
        for agent_id in ("producer", "peer-a", "peer-b", "peer-c"):
            mesh.register_local_signer(agent_id)
        with pytest.raises(ValueError, match=message):
            mesh.request_validation("producer", "safe content", "artifact")
        assert mesh.summary()["pending"] == 0
        assert mesh.summary()["total_validations"] == 0


def test_c14_testnet_weight_lookup_uses_canonical_metagraph_identity():
    deploy = _c14_load_testnet_deploy_module()
    raw_hotkey = "5FP9ECygsPrdLA9hoc1f4fHws1poDSB18E9tEqRRZueTFTuo"
    assert deploy._weight_values_for_metagraph(
        {raw_hotkey.casefold(): 0.75},
        [raw_hotkey],
    ) == [0.75]


def test_c14_default_validator_refuses_other_voter_private_keys(tmp_path):
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator

    validator = ConstitutionalValidator(
        ValidatorConfig(constitution_path=_c14_precedent_constitution_file(tmp_path))
    )
    validator.register_miner("validator-runtime")
    with pytest.raises(ValueError, match="refuses voter private keys"):
        validator.register_miner(
            "remote-voter",
            vote_private_key=Ed25519PrivateKey.generate(),
        )
    with pytest.raises(ValueError, match="only its own local identity key"):
        validator.register_miner("second-local-identity")


def test_c14_testnet_runtime_refuses_private_key_grant_mapping(tmp_path):
    import pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    deploy = _c14_load_testnet_deploy_module()
    private_grants = {
        f"remote-voter-{index}": Ed25519PrivateKey.generate()
        for index in range(6)
    }
    with pytest.raises(TypeError, match="only public-key authorized voter grants"):
        deploy._build_validator_runtime(
            _c14_precedent_constitution_file(tmp_path),
            private_grants,
        )


def test_c14_single_operator_dev_evidence_is_rejected_by_default_owner(tmp_path):
    import pytest

    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
    from constitutional_swarm.bittensor.synapses import JudgmentSynapse
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    constitution_path = _c14_precedent_constitution_file(tmp_path)
    validator = ConstitutionalValidator(
        ValidatorConfig(
            constitution_path=constitution_path,
            single_operator_dev=True,
        )
    )
    validator.register_miner("producer")
    owner_registry = VoteSignerRegistry()
    for index in range(5):
        voter_id = f"dev-voter-{index}"
        validator.register_miner(voter_id)
        owner_registry.register(
            voter_id,
            bytes.fromhex(validator.mesh.get_vote_public_key(voter_id)),
            roles={"voter", "validator"},
        )
    c14_trust_validator_voters(owner_registry, validator, ())
    owner = SubnetOwner(constitution_path, vote_registry=owner_registry)
    case = owner.package_case("safe dev-mode action", "governance")
    judgment = JudgmentSynapse(
        task_id=case.synapse.task_id,
        miner_uid="producer",
        judgment="Approve the safe action with documented safeguards",
        reasoning="bounded",
        artifact_hash="dev-artifact",
        constitutional_hash=owner.constitution_hash,
        domain="governance",
    )
    validation = validator.validate(judgment)
    assert {item.evidence_mode for item in validation.vote_envelopes} == {
        "single_operator_dev"
    }
    with pytest.raises(ValueError, match="independent vote evidence"):
        owner.record_result(case, judgment, validation)


def test_c14_standalone_research_example_requires_external_vote_evidence(capsys):
    import importlib.util
    from pathlib import Path

    example_path = (
        Path(__file__).parent.parent / "examples" / "mac_acgs_autonomous_research.py"
    )
    spec = importlib.util.spec_from_file_location(
        "c14_mac_acgs_autonomous_research",
        example_path,
    )
    assert spec is not None and spec.loader is not None
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)

    assert example.main() == 2
    assert "external signed precedents" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_c14_default_validator_collects_independent_remote_votes(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
    from constitutional_swarm.bittensor.synapses import JudgmentSynapse
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator
    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        sign_vote_envelope,
        signed_assignment_digest,
    )
    from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse

    constitution_path = _c14_precedent_constitution_file(tmp_path)
    validator = ConstitutionalValidator(
        ValidatorConfig(constitution_path=constitution_path)
    )
    validator.register_miner("producer")
    owner_registry = VoteSignerRegistry()
    voter_keys = {
        f"remote-voter-{index}": Ed25519PrivateKey.generate()
        for index in range(5)
    }
    routes = {}
    for index, (voter_id, private_key) in enumerate(voter_keys.items()):
        validator.register_miner(
            voter_id,
            vote_public_key=private_key.public_key(),
        )
        owner_registry.register(
            voter_id,
            private_key.public_key(),
            roles={"voter", "validator"},
        )
        routes[voter_id] = (voter_id, 9000 + index)
    for grant in validator.mesh.vote_registry.trust_grants(role="assigner").values():
        owner_registry.register(
            str(grant["identity_id"]),
            bytes.fromhex(str(grant["public_key_hex"])),
            roles={"assigner"},
        )
    owner = SubnetOwner(constitution_path, vote_registry=owner_registry)

    class ExternalVoteClient:
        async def request_vote(self, host, port, request, *, timeout):
            del port, timeout
            envelope = sign_vote_envelope(
                voter_keys[host],
                voter_id=request.voter_id,
                task_id=request.task_id,
                assignment_id=request.assignment_id,
                producer_id=request.producer_id,
                artifact_id=request.artifact_id,
                content_hash=request.content_hash,
                constitutional_hash=request.constitutional_hash,
                decision="approved",
                reason="external constitutional check passed",
                nonce=request.nonce,
                issued_at=request.timestamp,
                assigned_peers=request.assigned_peers,
                quorum=request.quorum,
                evidence_mode=request.evidence_mode,
                assignment_digest=signed_assignment_digest(request.signed_assignment),
            )
            return RemoteVoteResponse(envelope)

    case = owner.package_case("safe remote governance action", "governance")
    judgment = JudgmentSynapse(
        task_id=case.synapse.task_id,
        miner_uid="producer",
        judgment="Approve the safe remote action with documented safeguards",
        reasoning="bounded and independently reviewed",
        artifact_hash="remote-artifact",
        constitutional_hash=owner.constitution_hash,
        domain="governance",
    )
    validation = await validator.validate_remote(
        judgment,
        peer_routes=routes,
        client=ExternalVoteClient(),
    )
    assert len(validation.vote_envelopes) == 5
    assert {item.evidence_mode for item in validation.vote_envelopes} == {"independent"}
    admitted = owner.record_result(case, judgment, validation)
    assert admitted is not None
    assert owner.precedent_store.size == 1


def _c14_v2_receipt_electorate(
    decisions=(True, True, True, False, False), *, quorum=3
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        key_id_for_public_key,
        sign_vote_envelope,
        signed_assignment_digest,
    )

    peers = [f"c14-v2-validator-{index}" for index in range(len(decisions))]
    signed_assignment = _c14_receipt_signed_assignment(peers, quorum=quorum)
    envelopes = []
    assigner_public_key = _c14_receipt_assigner_key().public_key()
    assigner_key_id = key_id_for_public_key(assigner_public_key)
    grants = {
        assigner_key_id: {
            "identity_id": "c14-v2-assigner",
            "public_key_hex": assigner_public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "roles": ["assigner"],
        }
    }
    for index, (peer, approved) in enumerate(zip(peers, decisions, strict=True)):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = key_id_for_public_key(public_key)
        grants[key_id] = {
            "identity_id": peer,
            "public_key_hex": public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "roles": ["validator"],
        }
        envelopes.append(
            sign_vote_envelope(
                private_key,
                voter_id=peer,
                key_id=key_id,
                task_id="c14-v2-task",
                assignment_id="c14-v2-assignment",
                producer_id="c14-v2-producer",
                artifact_id="c14-v2-artifact",
                content_hash="c" * 64,
                constitutional_hash="d" * 64,
                decision="approved" if approved else "denied",
                reason=f"vote-{index}",
                nonce=f"c14-v2-nonce-{index}",
                issued_at=float(index + 1),
                assigned_peers=peers,
                quorum=quorum,
                evidence_mode="independent",
                assignment_digest=signed_assignment_digest(signed_assignment),
            )
        )
    return peers, envelopes, grants


def _c14_receipt_assigner_key():  # type: ignore[no-untyped-def]
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"c14-v2-receipt-assigner").digest()
    )


def _c14_receipt_signed_assignment(peers, *, quorum):  # type: ignore[no-untyped-def]
    from constitutional_swarm.mesh.vote_envelope import sign_assignment

    return sign_assignment(
        _c14_receipt_assigner_key(),
        task_id="c14-v2-task",
        assignment_id="c14-v2-assignment",
        assigner_id="c14-v2-assigner",
        producer_id="c14-v2-producer",
        artifact_id="c14-v2-artifact",
        content_hash="c" * 64,
        constitutional_hash="d" * 64,
        assigned_peers=peers,
        quorum=quorum,
        selection_seed="c14-v2-selection-seed",
        issued_at=1.0,
    )


def _c14_v2_receipt_record(peers, *, accepted=True, quorum=3):
    from constitutional_swarm.mesh.vote_envelope import signed_assignment_to_dict
    from constitutional_swarm.settlement_store import SettlementRecord

    return SettlementRecord(
        assignment={
            "assignment_id": "c14-v2-assignment",
            "task_id": "c14-v2-task",
            "artifact_id": "c14-v2-artifact",
            "producer_id": "c14-v2-producer",
            "content_hash": "c" * 64,
            "peers": list(peers),
            "quorum": quorum,
            "signed_assignment": signed_assignment_to_dict(
                _c14_receipt_signed_assignment(peers, quorum=quorum)
            ),
        },
        result={"accepted": accepted},
        constitutional_hash="d" * 64,
        schema_version=2,
    )


def test_c14_v2_receipt_requires_complete_signed_electorate_and_quorum_floor():
    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    with pytest.raises(ValueError, match="complete|assigned"):
        receipt_from_mesh_settlement(
            _c14_v2_receipt_record(peers), envelopes[:3], trusted_signers=grants
        )

    two_quorum_peers, two_quorum_envelopes, two_quorum_grants = (
        _c14_v2_receipt_electorate((True, True, False), quorum=2)
    )
    with pytest.raises(ValueError, match="quorum|three|3"):
        receipt_from_mesh_settlement(
            _c14_v2_receipt_record(two_quorum_peers, quorum=2),
            two_quorum_envelopes,
            trusted_signers=two_quorum_grants,
        )

    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    assert receipt.payload.decision == "approved"
    assert receipt.payload.metadata["quorum"] == "3"


def test_c14_v2_receipt_enforces_signed_quorum_above_simple_majority():
    import pytest

    from constitutional_swarm.governance_receipts import receipt_from_mesh_settlement

    peers, envelopes, grants = _c14_v2_receipt_electorate(quorum=4)
    with pytest.raises(ValueError, match="no unique"):
        receipt_from_mesh_settlement(
            _c14_v2_receipt_record(peers, quorum=4),
            envelopes,
            trusted_signers=grants,
        )

    peers, envelopes, grants = _c14_v2_receipt_electorate(
        (True, True, True, True, False), quorum=4
    )
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers, quorum=4),
        envelopes,
        trusted_signers=grants,
    )
    assert receipt.payload.decision == "approved"


def test_c14_v2_receipt_verifier_rejects_roster_shrink_and_quorum_rewrite():
    from constitutional_swarm.governance_receipts import (
        benchmark_summary,
        receipt_from_mesh_settlement,
        verify_bundle,
    )

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    shrunk = receipt.model_copy(
        update={"payload": receipt.payload.model_copy(update={"assigned_peers": peers[:3]})}
    )
    shrunk_bundle, receipt_public = c14_receipt_sign(shrunk)
    trust = {
        **grants,
        "c14-settlement-key": {
            "identity_id": "c14-v2-settlement",
            "public_key_hex": receipt_public,
            "roles": ["settlement"],
        },
    }
    verdict = verify_bundle(shrunk_bundle, trusted_signers=trust)
    assert verdict.valid is False
    assert {
        "vote_electorate_invalid",
        "vote_peer_assignment_invalid",
        "vote_peer_count_invalid",
    } & {issue.code for issue in verdict.issues}
    summary = benchmark_summary(
        bundle=shrunk_bundle,
        correct_answers=1,
        required_answers=1,
        time_limit_minutes=1,
        governed_harm=0.0,
        ungoverned_harm=1.0,
        n_roles=4,
        k_compromised=0,
        first_failure_k=1,
        wall_clock_seconds=0.1,
        token_estimate=1,
        dollar_estimate=0.0,
        model_backend="test",
        command_line="test",
        trusted_signers=trust,
        expected_signer_role="settlement",
    )
    assert summary["verifier_valid"] is False

    rewritten = receipt.model_copy(
        update={
            "payload": receipt.payload.model_copy(
                update={"metadata": {**receipt.payload.metadata, "quorum": "1"}}
            )
        }
    )
    rewritten_bundle, receipt_public = c14_receipt_sign(rewritten)
    trust["c14-settlement-key"]["public_key_hex"] = receipt_public
    verdict = verify_bundle(rewritten_bundle, trusted_signers=trust)
    assert verdict.valid is False
    assert "vote_quorum_invalid" in {issue.code for issue in verdict.issues}


def test_c14_v2_receipt_vote_evidence_requires_settlement_signer_role():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.governance_receipts import (
        GovernanceReceiptBundle,
        SignatureRecord,
        build_receipt,
        payload_canonical_bytes,
        receipt_from_mesh_settlement,
        verify_bundle,
    )
    from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key

    peers, envelopes, grants = _c14_v2_receipt_electorate()
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    payload = receipt.payload.model_copy(
        update={
            "evidence_hashes": {
                key: value
                for key, value in receipt.payload.evidence_hashes.items()
                if key != "settlement"
            },
            "metadata": {**receipt.payload.metadata, "signer_role": "coordinator"},
        }
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = key_id_for_public_key(public_key)
    public_hex = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    signed = build_receipt(
        payload=payload,
        signatures=[
            SignatureRecord(
                key_id=key_id,
                algorithm="ed25519",
                public_key_hex=public_hex,
                signature_hex=private_key.sign(payload_canonical_bytes(payload)).hex(),
            )
        ],
    )
    verdict = verify_bundle(
        GovernanceReceiptBundle(receipts=[signed]),
        trusted_signers={
            **grants,
            key_id: {
                "identity_id": "c14-v2-coordinator",
                "public_key_hex": public_hex,
                "roles": ["coordinator"],
            },
        },
        expected_signer_role="coordinator",
    )
    assert verdict.valid is False
    assert "signer_role_mismatch" in {issue.code for issue in verdict.issues}


def test_c14_receipt_cli_forwards_expected_signer_role(tmp_path, monkeypatch):
    import json

    import constitutional_swarm.governance_receipts_cli as cli
    from constitutional_swarm.governance_receipts import (
        VerificationVerdict,
        bundle_to_json,
        receipt_from_mesh_settlement,
    )

    seen = {}

    def fake_verify(bundle, **kwargs):
        seen.update(kwargs)
        return VerificationVerdict(
            valid=True, mode="fail_closed", signature_status="valid"
        )

    monkeypatch.setattr(cli, "verify_bundle", fake_verify)
    peers, envelopes, grants = _c14_v2_receipt_electorate()
    receipt = receipt_from_mesh_settlement(
        _c14_v2_receipt_record(peers), envelopes, trusted_signers=grants
    )
    bundle, _public_hex = c14_receipt_sign(receipt)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        bundle_to_json(bundle), encoding="utf-8"
    )
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps({}), encoding="utf-8")
    assert (
        cli.main(
            [
                str(bundle_path),
                "--trusted-signers",
                str(trust_path),
                "--expected-signer-role",
                "settlement",
            ]
        )
        == 0
    )
    assert seen["expected_signer_role"] == "settlement"


def test_c14_cycle2_cascade_accepts_bound_v2_evidence_and_rejects_candidate_replay():
    import hashlib
    import time
    from dataclasses import replace

    from acgs_lite import Constitution
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.bittensor.cascade import (
        CascadeStage,
        PrecedentCandidate,
        PrecedentCascade,
    )
    from constitutional_swarm.mesh import MeshProof, MeshResult
    from constitutional_swarm.mesh.vote_envelope import (
        VoteSignerRegistry,
        compute_vote_envelope_root,
        sign_assignment,
        sign_vote_envelope,
        signed_assignment_digest,
        vote_envelope_hash,
    )

    constitution = Constitution.default()
    candidate = PrecedentCandidate(
        candidate_id="candidate-bound-v2",
        judgment_text="Publish governance reasons with privacy safeguards",
        reasoning_text="Accountability and privacy remain jointly protected",
        domain="governance",
        miner_uid="candidate-producer",
        constitutional_hash=constitution.hash,
        stage_results=(),
        current_stage=CascadeStage.MESH_VALIDATION,
        alive=True,
    )
    peers = ("cascade-voter-1", "cascade-voter-2", "cascade-voter-3")
    registry = VoteSignerRegistry()
    assigner_key = Ed25519PrivateKey.generate()
    registry.register("cascade-assigner", assigner_key.public_key(), roles={"assigner"})
    keys = {}
    for peer in peers:
        keys[peer] = Ed25519PrivateKey.generate()
        registry.register(peer, keys[peer].public_key(), roles={"voter", "validator"})
    content_hash = hashlib.sha256(candidate.judgment_text.encode()).hexdigest()[:32]
    signed_assignment = sign_assignment(
        assigner_key,
        task_id=candidate.candidate_id,
        assignment_id="assignment-bound-v2",
        assigner_id="cascade-assigner",
        producer_id=candidate.miner_uid,
        artifact_id=candidate.candidate_id,
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        assigned_peers=peers,
        quorum=3,
        selection_seed="c14-cascade-selection",
        issued_at=1_800_000_000.0,
    )
    envelopes = tuple(
        sign_vote_envelope(
            keys[peer],
            voter_id=peer,
            task_id=candidate.candidate_id,
            assignment_id="assignment-bound-v2",
            producer_id=candidate.miner_uid,
            artifact_id=candidate.candidate_id,
            content_hash=content_hash,
            constitutional_hash=constitution.hash,
            decision="approved",
            reason="independent approval",
            nonce=f"nonce-{peer}",
            issued_at=1_800_000_000.0,
            assigned_peers=peers,
            quorum=3,
            evidence_mode="independent",
            assignment_digest=signed_assignment_digest(signed_assignment),
        )
        for peer in peers
    )
    ordered = tuple(sorted(envelopes, key=lambda item: (item.voter_id, item.key_id)))
    vote_hashes = tuple(vote_envelope_hash(item) for item in ordered)
    proof = MeshProof(
        assignment_id="assignment-bound-v2",
        content_hash=content_hash,
        constitutional_hash=constitution.hash,
        vote_hashes=vote_hashes,
        root_hash=compute_vote_envelope_root(
            task_id=candidate.candidate_id,
            assignment_id="assignment-bound-v2",
            producer_id=candidate.miner_uid,
            artifact_id=candidate.candidate_id,
            content_hash=content_hash,
            constitutional_hash=constitution.hash,
            accepted=True,
            envelopes=ordered,
        ),
        accepted=True,
        timestamp=time.time(),
        task_id=candidate.candidate_id,
        producer_id=candidate.miner_uid,
        artifact_id=candidate.candidate_id,
        protocol_version=2,
    )
    result = MeshResult(
        assignment_id=proof.assignment_id,
        accepted=True,
        votes_for=3,
        votes_against=0,
        quorum_met=True,
        pending_votes=0,
        constitutional_hash=constitution.hash,
        proof=proof,
        settled=True,
        settled_at=time.time(),
        vote_envelopes=ordered,
        signed_assignment=signed_assignment,
    )
    cascade = PrecedentCascade(constitution, vote_registry=registry)

    assert cascade._valid_mesh_result(candidate, result) is True
    assert cascade._valid_mesh_result(
        replace(candidate, candidate_id="same-content-other-candidate"), result
    ) is False
    assert cascade._valid_mesh_result(
        replace(candidate, miner_uid="other-producer"), result
    ) is False


def test_c14_cycle2_recovery_uses_signed_historical_quorum_and_rejects_metadata_tamper(
    tmp_path, caplog
):
    from dataclasses import replace

    import pytest
    from acgs_lite import Constitution

    from constitutional_swarm import ConstitutionalMesh
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    constitution = Constitution.default()
    registry = VoteSignerRegistry()
    source = JSONLSettlementStore(tmp_path / "historical-quorum.jsonl")
    writer = ConstitutionalMesh(
        constitution,
        peers_per_validation=5,
        quorum=4,
        settlement_store=source,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        evidence_mode="single_operator_dev",
        seed=481,
    )
    writer.register_local_signer("producer")
    for index in range(5):
        writer.register_local_signer(f"historical-voter-{index}")
    result = writer.full_validation(
        "producer", "safe historical decision", "historical-artifact", task_id="historical-task"
    )

    recovered = ConstitutionalMesh(
        constitution,
        peers_per_validation=5,
        quorum=5,
        settlement_store=source,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        seed=482,
        evidence_mode="single_operator_dev",
    ).get_result(result.assignment_id)
    assert recovered.accepted is True
    assert recovered.votes_for == 5

    record = source.get(result.assignment_id)
    assert record is not None
    hash_tampered = JSONLSettlementStore(tmp_path / "hash-tampered.jsonl")
    hash_tampered.append(
        replace(
            record,
            assignment={**record.assignment, "assigned_peers_hash": "0" * 64},
        )
    )
    # C28 mesh-settle-1: a malformed record is quarantined, never authoritative.
    with caplog.at_level("WARNING", logger="constitutional_swarm.mesh.core"):
        reader = ConstitutionalMesh(
            constitution,
            peers_per_validation=5,
            quorum=5,
            settlement_store=hash_tampered,
            vote_registry=registry,
            **_c14_external_assigner(registry),
            evidence_mode="single_operator_dev",
        )
    assert f"quarantining settlement {result.assignment_id}" in caplog.text
    assert "assigned_peers_hash" in caplog.text
    with pytest.raises(KeyError, match="not found"):
        reader.get_result(result.assignment_id)

    quorum_tampered = JSONLSettlementStore(tmp_path / "quorum-tampered.jsonl")
    quorum_tampered.append(
        replace(record, assignment={**record.assignment, "quorum": 5})
    )
    reader = ConstitutionalMesh(
        constitution,
        peers_per_validation=5,
        quorum=5,
        settlement_store=quorum_tampered,
        vote_registry=registry,
        **_c14_external_assigner(registry),
        evidence_mode="single_operator_dev",
    )
    with pytest.raises(KeyError, match="not found"):
        reader.get_result(result.assignment_id)
