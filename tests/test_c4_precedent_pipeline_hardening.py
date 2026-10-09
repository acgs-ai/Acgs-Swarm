"""Regression tests for C4 precedent admission and governance boundaries."""

from __future__ import annotations
import dataclasses
import hashlib
import threading
import time
import warnings

import pytest
from constitutional_swarm.bittensor.precedent_backed_codifier import PrecedentBackedCodifier
from constitutional_swarm.bittensor.precedent_store import PrecedentRecord, PrecedentStore
from constitutional_swarm.bittensor.protocol import EscalationType
from constitutional_swarm.bittensor.rule_codifier import PrecedentCluster, RuleCodifier
from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
from constitutional_swarm.bittensor.synapses import JudgmentSynapse, ValidationSynapse
from constitutional_swarm.mesh.settlement import MeshProof, _compute_merkle_root
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from acgs_lite import Constitution
from constitutional_swarm import ConstitutionalMesh
from constitutional_swarm.bittensor import nmc_protocol as nmc_mod
from constitutional_swarm.bittensor.cascade import (
    STAGE_ORDER,
    CascadeResult,
    CascadeStage,
    PrecedentCandidate,
    PrecedentCascade,
)
from constitutional_swarm.bittensor.nmc_protocol import NMCSession
from types import SimpleNamespace
from acgs_lite import AuditPolicy, CaseConfig, SelectionPolicy, TrustConfig
from constitutional_swarm.bittensor.axon_server import MinerAxonServer
from constitutional_swarm.bittensor.emission_calculator import MinerEmissionInput
from constitutional_swarm.bittensor.governance_coordinator import CoordinatorConfig, GovernanceCoordinator
from constitutional_swarm.bittensor.protocol import MinerTier


class _GuardTrackingStore(PrecedentStore):
    def __init__(self, constitutional_hash: str) -> None:
        super().__init__(constitutional_hash)
        self.guarded_source_sets: list[tuple[str, ...]] = []

    def guard_active_sources(self, precedent_ids):  # type: ignore[no-untyped-def]
        self.guarded_source_sets.append(tuple(precedent_ids))
        return super().guard_active_sources(precedent_ids)

def _admission_record(
    *,
    case_id: str = "case-admission",
    task_id: str = "task-admission",
    votes_for: int = 3,
    votes_against: int = 2,
    constitutional_hash: str = CONSTITUTIONAL_HASH,
    judgment: str = "deny unsafe request",
    vector: dict[str, float] | None = None,
) -> PrecedentRecord:
    return PrecedentRecord.create(
        case_id=case_id,
        task_id=task_id,
        miner_uid="miner-admission",
        judgment=judgment,
        reasoning="constitutional rationale",
        votes_for=votes_for,
        votes_against=votes_against,
        proof_root_hash="proof-admission",
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        impact_vector=vector or {"safety": 0.9, "security": 0.8},
        constitutional_hash=constitutional_hash,
        ambiguous_dimensions=("safety", "security"),
    )


def test_admission_default_quorum_is_fail_closed_3_of_at_least_5() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    with pytest.raises(ValueError, match="total validators"):
        store.add(_admission_record(case_id="three-of-four", votes_for=3, votes_against=1))
    with pytest.raises(ValueError, match="validator votes"):
        store.add(_admission_record(case_id="two-of-two", votes_for=2, votes_against=0))
    store.add(_admission_record(case_id="three-of-five", votes_for=3, votes_against=2))
    assert store.size == 1


@pytest.mark.parametrize(
    ("votes_for", "votes_against"), [(-1, 6), (3, -1), (True, 4), (3, False)]
)
def test_admission_rejects_non_integer_or_negative_vote_counts(
    votes_for: int, votes_against: int
) -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    with pytest.raises((TypeError, ValueError), match="vote"):
        store.add(_admission_record(votes_for=votes_for, votes_against=votes_against))


def test_admission_threshold_configuration_cannot_weaken_3_of_5_floor() -> None:
    with pytest.raises(ValueError, match="min_votes_for_precedent"):
        PrecedentStore(CONSTITUTIONAL_HASH, min_votes_for_precedent=2)
    with pytest.raises(ValueError, match="min_total_validators"):
        PrecedentStore(CONSTITUTIONAL_HASH, min_total_validators=4)


def test_admission_recomputes_grade_and_deduplicates_case_task_source() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    admitted = dataclasses.replace(_admission_record(), validator_grade=1.0)
    store.add(admitted)
    [stored] = store.active_records()
    assert stored.validator_grade == pytest.approx(3 / 5)
    replay = dataclasses.replace(admitted, precedent_id="different-id")
    with pytest.raises(ValueError, match="already|duplicate"):
        store.add(replay)


def test_admission_clones_mutable_record_input_and_output() -> None:
    vector = {"safety": 0.9, "security": 0.8}
    record = _admission_record(vector=vector)
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    store.add(record)
    vector["safety"] = 0.0
    record.impact_vector["security"] = 0.0
    [snapshot] = store.active_records()
    assert snapshot.impact_vector == {"safety": 0.9, "security": 0.8}
    snapshot.impact_vector["safety"] = 0.1
    [fresh_snapshot] = store.active_records()
    assert fresh_snapshot.impact_vector == {"safety": 0.9, "security": 0.8}


@pytest.mark.parametrize(
    ("case_id", "task_id"),
    [("case-admission", "changed-task"), ("changed-case", "task-admission")],
)
def test_admission_source_identity_cannot_be_replayed_with_one_changed_id(
    case_id: str, task_id: str
) -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    record = _admission_record()
    store.add(record)
    replay = dataclasses.replace(
        record, precedent_id="replayed-id", case_id=case_id, task_id=task_id
    )
    with pytest.raises(ValueError, match="already|duplicate"):
        store.add(replay)
    assert store.size == 1


class _admission_lock_probe:
    def __init__(self) -> None:
        self.held = False

    def __enter__(self) -> None:
        assert not self.held
        self.held = True

    def __exit__(self, *_exc: object) -> None:
        self.held = False


class _admission_guarded_records(dict[str, PrecedentRecord]):
    def __init__(self, probe: _admission_lock_probe, record: PrecedentRecord) -> None:
        super().__init__({record.precedent_id: record})
        self._probe = probe

    def values(self):  # type: ignore[no-untyped-def]
        assert self._probe.held, "record iteration must occur while the store lock is held"
        return super().values()

    def __len__(self) -> int:
        assert self._probe.held, "record length must be read while the store lock is held"
        return super().__len__()


def test_admission_all_store_reads_snapshot_under_lock() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    probe = _admission_lock_probe()
    store._lock = probe  # type: ignore[assignment]
    store._records = _admission_guarded_records(probe, _admission_record())
    assert store.size == 1
    assert store.total_stored == 1
    assert store.retrieve({"safety": 0.9}).matches
    assert store.escalation_distribution() == {"constitutional_conflict": 1}
    assert store.miner_contribution_counts() == {"miner-admission": 1}


def test_admission_adapter_routes_observations_through_store() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    codifier = PrecedentBackedCodifier(
        precedent_store=store, min_cluster_size=1, min_validator_agreement=0.5
    )
    good = _admission_record()
    store.add(good)
    [canonical] = store.active_records()
    codifier.observe(canonical)
    codifier.observe(canonical)
    assert store.size == 1
    low_vote = _admission_record(
        case_id="low-vote", task_id="low-vote", votes_for=1, votes_against=0
    )
    wrong_hash = _admission_record(
        case_id="wrong-hash", task_id="wrong-hash", constitutional_hash="wrong"
    )
    with pytest.raises(ValueError):
        codifier.observe(low_vote)
    with pytest.raises(ValueError):
        codifier.observe(wrong_hash)
    assert store.size == 1


def _admission_codifier_with_one_record() -> tuple[PrecedentStore, RuleCodifier, PrecedentRecord]:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    record = _admission_record()
    store.add(record)
    codifier = RuleCodifier(
        CONSTITUTIONAL_HASH,
        precedent_store=store,
        min_cluster_size=1,
        min_validator_agreement=0.5,
    )
    return store, codifier, record


def test_admission_revocation_between_cluster_and_proposal_fails_closed() -> None:
    store, codifier, record = _admission_codifier_with_one_record()
    clusters = codifier.find_clusters(store.active_records())
    store.revoke(record.precedent_id)
    with pytest.raises(ValueError, match="active|revoked"):
        codifier.propose_rules(clusters)


def test_admission_revocation_between_proposal_and_approval_fails_closed() -> None:
    store, codifier, record = _admission_codifier_with_one_record()
    [candidate] = codifier.propose_rules(codifier.find_clusters(store.active_records()))
    store.revoke(record.precedent_id)
    with pytest.raises(ValueError, match="active|revoked"):
        codifier.approve(candidate.candidate_id)


def test_admission_proposal_uses_one_detached_cluster_snapshot() -> None:
    store, codifier, source_a = _admission_codifier_with_one_record()
    [cluster] = codifier.find_clusters(store.active_records())
    source_b = _admission_record(
        case_id="case-mutation-target",
        task_id="task-mutation-target",
        judgment="approve caller-mutated source",
        vector={"privacy": 0.95},
    )
    store.add(source_b)

    original_source_ids = list(cluster.precedent_ids)
    original_dimensions = list(cluster.dominant_dimensions)
    original_agreement = cluster.validator_agreement
    original_escalation = cluster.escalation_type
    validated = threading.Event()
    resume = threading.Event()
    actual_validate = codifier._validate_cluster

    def validate_then_pause(candidate_cluster: PrecedentCluster) -> None:
        actual_validate(candidate_cluster)
        validated.set()
        assert resume.wait(timeout=2), "proposal thread did not receive resume signal"

    codifier._validate_cluster = validate_then_pause  # type: ignore[method-assign]
    proposed: list = []
    errors: list[BaseException] = []

    def propose() -> None:
        try:
            proposed.extend(codifier.propose_rules([cluster]))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=propose)
    worker.start()
    assert validated.wait(timeout=2), "proposal did not reach post-validation pause"
    cluster.precedent_ids[:] = [source_b.precedent_id]
    cluster.centroid_vector.clear()
    cluster.centroid_vector["privacy"] = 0.95
    cluster.dominant_dimensions[:] = ["privacy"]
    cluster.majority_judgment = "approve caller-mutated source"
    cluster.validator_agreement = 1.0
    cluster.escalation_type = EscalationType.CONTEXT_SENSITIVITY.value
    resume.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert errors == []
    [candidate] = proposed
    assert candidate.source_precedent_ids == original_source_ids
    assert candidate.dominant_dimensions == original_dimensions
    assert candidate.validator_agreement == original_agreement
    assert candidate.escalation_type == original_escalation

    store.revoke(source_a.precedent_id)
    with pytest.raises(ValueError, match="active|revoked"):
        codifier.approve(candidate.candidate_id)


def test_admission_revocation_between_approval_and_activation_fails_closed() -> None:
    store, codifier, record = _admission_codifier_with_one_record()
    [candidate] = codifier.propose_rules(codifier.find_clusters(store.active_records()))
    codifier.approve(candidate.candidate_id)
    store.revoke(record.precedent_id)
    with pytest.raises(ValueError, match="active|revoked"):
        codifier.activate(candidate.candidate_id, "name: test\nrules: []\n")


def test_admission_spoofed_cluster_payload_cannot_propose_rule() -> None:
    _store, codifier, record = _admission_codifier_with_one_record()
    spoof = PrecedentCluster(
        cluster_id="spoof",
        precedent_ids=[record.precedent_id],
        centroid_vector={"safety": 1.0},
        dominant_dimensions=["safety"],
        majority_judgment="approve attacker supplied rule",
        validator_agreement=1.0,
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT.value,
    )
    with pytest.raises(ValueError, match="canonical|cluster|source"):
        codifier.propose_rules([spoof])


def _admission_constitution_file(tmp_path) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "admission-constitution.yaml"
    path.write_text(
        "name: admission-test\nrules:\n"
        "  - id: safety-01\n"
        "    text: Do not cause harm\n"
        "    severity: critical\n"
        "    hardcoded: true\n"
    )
    return str(path)


def _admission_owner_inputs(owner: SubnetOwner):  # type: ignore[no-untyped-def]
    return _proof_bound_owner_inputs(owner)


def test_admission_subnet_owner_uses_injected_store_and_admits_once(tmp_path) -> None:
    constitution_path = _admission_constitution_file(tmp_path)
    owner_probe = SubnetOwner(constitution_path)
    store = PrecedentStore(owner_probe.constitution_hash)
    owner = SubnetOwner(constitution_path, precedent_store=store)
    case, judgment, validation = _admission_owner_inputs(owner)
    admitted = owner.record_result(case, judgment, validation)
    assert admitted is not None
    assert store.size == 1
    assert owner.precedents == list(store.active_records())
    with pytest.raises(ValueError, match="already|duplicate|active"):
        owner.record_result(case, judgment, validation)
    assert store.size == 1


@pytest.mark.parametrize(
    "mismatch", ["judgment-task", "validation-task", "judgment-hash", "validation-hash"]
)
def test_admission_subnet_owner_rejects_task_and_hash_mismatch(tmp_path, mismatch: str) -> None:
    owner = SubnetOwner(_admission_constitution_file(tmp_path))
    case, judgment, validation = _admission_owner_inputs(owner)
    if mismatch == "judgment-task":
        judgment = dataclasses.replace(judgment, task_id="wrong-task")
    elif mismatch == "validation-task":
        validation = dataclasses.replace(validation, task_id="wrong-task")
    elif mismatch == "judgment-hash":
        judgment = dataclasses.replace(judgment, constitutional_hash="wrong-hash")
    else:
        validation = dataclasses.replace(validation, constitutional_hash="wrong-hash")
    with pytest.raises(ValueError, match="task|hash"):
        owner.record_result(case, judgment, validation)
    assert owner.precedent_store.size == 0


def test_admission_subnet_owner_rejects_claimed_acceptance_without_quorum(tmp_path) -> None:
    owner = SubnetOwner(_admission_constitution_file(tmp_path))
    case, judgment, validation = _admission_owner_inputs(owner)
    validation = dataclasses.replace(
        validation, votes_for=2, votes_against=0, quorum_met=False
    )
    with pytest.raises(ValueError, match="quorum|validator"):
        owner.record_result(case, judgment, validation)
    assert owner.precedent_store.size == 0





def _nmc_complete_session(
    ordered_judgments: list[tuple[str, str]],
) -> NMCSession:
    """Commit and reveal one independently identified vote per miner."""
    miners = {miner_uid for miner_uid, _ in ordered_judgments}
    session = NMCSession(
        case_id="C4-majority",
        required_miners=miners,
        min_reveals=len(miners),
    )
    nonces = {miner_uid: f"nonce-{miner_uid}" for miner_uid in miners}
    for miner_uid, judgment in ordered_judgments:
        session.accept_commitment(
            miner_uid,
            nmc_mod.compute_commitment_hash(judgment, nonces[miner_uid]),
        )
    for miner_uid, judgment in ordered_judgments:
        session.accept_reveal(miner_uid, judgment, nonces[miner_uid])
    return session


@pytest.mark.parametrize(
    "ordered_judgments",
    [
        [
            ("deny-miner", "deny"),
            ("allow-1", "allow"),
            ("allow-2", "allow"),
            ("allow-3", "allow"),
            ("allow-4", "allow"),
        ],
        [
            ("allow-4", "allow"),
            ("allow-3", "allow"),
            ("allow-2", "allow"),
            ("allow-1", "allow"),
            ("deny-miner", "deny"),
        ],
    ],
)
def test_nmc_duplicate_content_flags_but_cannot_flip_identity_majority(
    ordered_judgments: list[tuple[str, str]],
) -> None:
    session = _nmc_complete_session(ordered_judgments)

    consensus = session.synthesize()

    assert consensus.judgment_text == "allow"
    assert consensus.confidence == pytest.approx(4 / 5)
    assert consensus.valid_reveal_count == 5
    assert consensus.excluded_miners == ()
    assert len(consensus.sybil_flags) == 3


def test_nmc_commitment_encoding_is_unambiguous_and_reveal_cannot_equivocate() -> None:
    first = ("approve:a", "b")
    second = ("approve", "a:b")

    first_hash = nmc_mod.compute_commitment_hash(*first)
    second_hash = nmc_mod.compute_commitment_hash(*second)

    assert first_hash != second_hash
    session = NMCSession(
        case_id="C4-commitment",
        required_miners={"miner-1"},
        min_reveals=1,
    )
    session.accept_commitment("miner-1", first_hash)
    with pytest.raises(ValueError, match="does not match commitment"):
        session.accept_reveal("miner-1", *second)


def test_nmc_invalid_synthesis_method_rejected_without_state_mutation() -> None:
    session = _nmc_complete_session(
        [("miner-1", "allow"), ("miner-2", "deny"), ("miner-3", "allow")]
    )
    state_before = session.state
    consensus_before = session.consensus

    with pytest.raises(TypeError, match="SynthesisMethod"):
        session.synthesize("typo")  # type: ignore[arg-type]

    assert session.state is state_before
    assert session.consensus is consensus_before


def _nmc_mesh(constitution: Constitution, *, quorum: int) -> ConstitutionalMesh:
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=3,
        quorum=quorum,
        seed=42,
    )
    mesh.register_local_signer("producer")
    for index in range(3):
        mesh.register_local_signer(f"validator-{index}")
    return mesh


def _nmc_run_cascade(cascade: PrecedentCascade) -> PrecedentCandidate:
    return cascade.run_full_cascade(
        judgment="Publish governance reasons with privacy safeguards",
        reasoning="The amendment preserves accountability and personal privacy",
        domain="governance",
        miner_uid="producer",
    )


def test_cascade_fails_closed_when_mesh_is_unavailable() -> None:
    cascade = PrecedentCascade(
        Constitution.default(),
        mesh=None,
        min_consensus_miners=3,
    )

    candidate = _nmc_run_cascade(cascade)

    assert candidate.alive is False
    assert candidate.stage_results[-1].stage is CascadeStage.MESH_VALIDATION
    assert candidate.stage_results[-1].passed is False
    assert "mesh" in candidate.stage_results[-1].detail.lower()


def test_cascade_rejects_mesh_settlement_below_required_miner_quorum() -> None:
    constitution = Constitution.default()
    mesh = _nmc_mesh(constitution, quorum=2)
    cascade = PrecedentCascade(
        constitution,
        mesh,
        min_consensus_miners=3,
        consensus_threshold=2 / 3,
    )

    candidate = _nmc_run_cascade(cascade)

    assert candidate.alive is False
    assert candidate.stage_results[-1].stage is CascadeStage.MULTI_MINER_CONSENSUS
    assert candidate.stage_results[-1].passed is False
    assert "2/3" in candidate.stage_results[-1].detail


def test_cascade_accepts_real_signature_verified_three_miner_quorum() -> None:
    constitution = Constitution.default()
    mesh = _nmc_mesh(constitution, quorum=3)
    cascade = PrecedentCascade(
        constitution,
        mesh,
        min_consensus_miners=3,
        consensus_threshold=2 / 3,
    )

    candidate = _nmc_run_cascade(cascade)

    assert candidate.alive is True
    assert [result.stage for result in candidate.stage_results] == STAGE_ORDER
    assert candidate.stage_results[1].passed is True
    assert candidate.stage_results[2].passed is True
    assert cascade.accept(candidate) is not None


def test_cascade_accept_rejects_forged_completed_candidate() -> None:
    constitution = Constitution.default()
    forged_results = tuple(
        CascadeResult(
            stage=stage,
            passed=True,
            latency_ns=0,
            detail="forged",
        )
        for stage in STAGE_ORDER
    )
    forged = PrecedentCandidate(
        candidate_id="not-issued-by-this-cascade",
        judgment_text="Attacker supplied amendment",
        reasoning_text="Attacker supplied evidence",
        domain="governance",
        miner_uid="attacker",
        constitutional_hash=constitution.hash,
        stage_results=forged_results,
        current_stage=CascadeStage.CONSTITUTIONAL_COMPATIBILITY,
        alive=True,
    )
    cascade = PrecedentCascade(
        constitution,
        _nmc_mesh(constitution, quorum=3),
        min_consensus_miners=3,
    )

    assert cascade.accept(forged) is None

# Coordinator / axon regression slice.

def _coord_with_auto_audit(check_fn):
    gc = GovernanceCoordinator(CoordinatorConfig(
        case_config=CaseConfig(claim_timeout_minutes=60, submission_timeout_minutes=120,
                               validation_timeout_minutes=480),
        selection_policy=SelectionPolicy(require_domain_match=True),
        audit_policy=AuditPolicy(sample_rate=1.0, correct_reward=0.01),
        trust_config=TrustConfig(initial_score=0.8, time_decay_rate=0.0),
        auto_audit=True, audit_check_fn=check_fn))
    for i in range(10):
        gc.register_validator(f"coord-val-{i}", trust_score=0.8,
                              domains=["governance"], model=f"model-{i%3}")
    return gc

def test_coord_auto_audit_requires_explicit_check_function():
    with pytest.raises(ValueError, match="audit_check_fn"):
        GovernanceCoordinator(CoordinatorConfig(auto_audit=True))

def test_coord_manual_audit_requires_explicit_check_function():
    with pytest.raises(ValueError, match="check_fn"):
        GovernanceCoordinator().run_audit_cycle()

def test_coord_auto_audit_uses_configured_oracle_for_rejected_case():
    calls = []
    def reject_oracle(case_id, submission_hash):
        calls.append((case_id, submission_hash))
        return "reject"
    gc = _coord_with_auto_audit(reject_oracle)
    cid = gc.create_case("reject unsafe action", domain="governance")
    gc.assign_miner(cid, "coord-miner")
    gc.submit_result(cid, "coord-miner", {})
    sel = gc.select_and_begin_validation(cid, seed="ab"*32)
    votes = {v: "reject" for v in sel.selected}
    gc.finalize_case(cid, accepted=False, validator_votes=votes)
    assert calls and calls[0][0] == cid
    assert gc.auditor.unchecked_count() == 0
    for vid in sel.selected:
        profile = gc.auditor.profile(vid)
        assert profile is not None
        assert profile.spot_check_correct == 1
        assert profile.spot_check_wrong == 0

def test_coord_unconfigured_registered_miner_set_fails_loudly():
    with pytest.raises(ValueError, match="registered_miners"):
        GovernanceCoordinator().compute_emissions(
            [MinerEmissionInput("unregistered", tier=MinerTier.MASTER, reputation=1.0)]
        )

def test_coord_registered_miners_and_authenticity_work_without_manifold():
    gc = GovernanceCoordinator(CoordinatorConfig(registered_miners={"auth-high", "auth-low"}))
    gc.record_miner_authenticity("auth-high", 1.0)
    gc.record_miner_authenticity("auth-low", 0.0)
    cycle = gc.compute_emissions([
        MinerEmissionInput("auth-high", tier=MinerTier.MASTER),
        MinerEmissionInput("auth-low", tier=MinerTier.MASTER),
        MinerEmissionInput("sybil", tier=MinerTier.MASTER, reputation=100.0)])
    by_uid = {e.miner_uid: e for e in cycle.emissions}
    assert cycle.active_miners == 2
    assert by_uid["auth-high"].raw_score > by_uid["auth-low"].raw_score
    assert by_uid["sybil"].emission_weight == 0.0

def test_coord_axon_rejects_body_and_axon_hotkey_spoof():
    server = MinerAxonServer(SimpleNamespace(constitution_hash="c"),
                             trusted_validator_hotkeys={"trusted"})
    body = SimpleNamespace(impact_score=999.0, validator_hotkey="trusted")
    axon = SimpleNamespace(impact_score=999.0, axon=SimpleNamespace(hotkey="trusted"))
    assert server.blacklist(body) is True
    assert server.priority(body) == 0.0
    assert server.blacklist(axon) is True

def test_coord_axon_accepts_authenticated_dendrite_hotkey():
    server = MinerAxonServer(SimpleNamespace(constitution_hash="c"),
                             trusted_validator_hotkeys={"trusted"})
    syn = SimpleNamespace(impact_score=4.0, dendrite=SimpleNamespace(hotkey="trusted"),
                          validator_hotkey="spoof")
    assert server.blacklist(syn) is False
    assert server.priority(syn) == 4.0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"consensus_threshold": 0.0}, "consensus_threshold"),
        ({"consensus_threshold": 1.1}, "consensus_threshold"),
        ({"consensus_threshold": True}, "consensus_threshold"),
        ({"min_consensus_miners": 0}, "min_consensus_miners"),
        ({"min_consensus_miners": 1.5}, "min_consensus_miners"),
    ],
)
def test_cascade_consensus_configuration_is_validated(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        PrecedentCascade(Constitution.default(), **kwargs)


def test_cascade_accept_is_instance_bound_and_single_use() -> None:
    constitution = Constitution.default()
    cascade = PrecedentCascade(
        constitution,
        _nmc_mesh(constitution, quorum=3),
        min_consensus_miners=3,
    )
    candidate = _nmc_run_cascade(cascade)

    assert cascade.accept(dataclasses.replace(candidate)) is None
    assert cascade.accept(candidate) is not None
    assert cascade.accept(candidate) is None


# ---------------------------------------------------------------------------
# Review-gap regressions: canonical source, atomic revocation, proof binding
# ---------------------------------------------------------------------------


def test_codifier_rejects_raw_and_cross_store_precedents() -> None:
    raw = _admission_record(case_id="raw", task_id="raw")
    target_store = PrecedentStore(CONSTITUTIONAL_HASH)
    codifier = RuleCodifier(CONSTITUTIONAL_HASH, precedent_store=target_store)
    with pytest.raises(ValueError, match="canonical|admitted|source"):
        codifier.find_clusters([raw])
    assert target_store.size == 0

    source_store = PrecedentStore(CONSTITUTIONAL_HASH)
    source_store.add(raw)
    [canonical] = source_store.active_records()
    with pytest.raises(ValueError, match="canonical|admitted|source"):
        codifier.find_clusters([canonical])
    assert target_store.size == 0


def test_adapter_observe_consumes_only_exact_canonical_records() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    raw = _admission_record(case_id="adapter", task_id="adapter")
    adapter = PrecedentBackedCodifier(precedent_store=store)
    with pytest.raises(ValueError, match="canonical|admitted|source"):
        adapter.observe(raw)
    assert store.size == 0

    store.add(raw)
    [canonical] = store.active_records()
    adapter.observe(canonical)
    adapter.observe(canonical)
    assert adapter.precedents == [canonical]

    mutated = dataclasses.replace(canonical, judgment="mutated after admission")
    with pytest.raises(ValueError, match="canonical|source"):
        adapter.observe(mutated)
    assert adapter.precedents == [canonical]


def test_precedent_source_guard_serializes_revocation() -> None:
    store = PrecedentStore(CONSTITUTIONAL_HASH)
    record = _admission_record(case_id="guard", task_id="guard")
    store.add(record)
    entered = threading.Event()
    release = threading.Event()
    revoked = threading.Event()

    def hold_guard() -> None:
        with store.guard_active_sources([record.precedent_id]):
            entered.set()
            assert release.wait(2)

    def revoke() -> None:
        assert entered.wait(2)
        store.revoke(record.precedent_id)
        revoked.set()

    guard_thread = threading.Thread(target=hold_guard)
    revoke_thread = threading.Thread(target=revoke)
    guard_thread.start()
    revoke_thread.start()
    assert entered.wait(2)
    assert not revoked.wait(0.05)
    release.set()
    guard_thread.join(2)
    revoke_thread.join(2)
    assert not guard_thread.is_alive()
    assert not revoke_thread.is_alive()
    assert revoked.is_set()
    assert store.size == 0


def test_codifier_guards_sources_during_each_state_transition() -> None:
    store = _GuardTrackingStore(CONSTITUTIONAL_HASH)
    record = _admission_record(case_id="transitions", task_id="transitions")
    store.add(record)
    [canonical] = store.active_records()
    codifier = RuleCodifier(
        CONSTITUTIONAL_HASH,
        precedent_store=store,
        min_cluster_size=1,
        min_validator_agreement=0.5,
    )
    [cluster] = codifier.find_clusters([canonical])
    [candidate] = codifier.propose_rules([cluster])
    codifier.approve(candidate.candidate_id)
    codifier.activate(candidate.candidate_id, "name: test\nrules: []\n")
    expected = (record.precedent_id,)
    assert store.guarded_source_sets == [expected, expected, expected]


def _proof_bound_owner_inputs(owner: SubnetOwner):  # type: ignore[no-untyped-def]
    case = owner.package_case(
        "proof-bound safety conflict",
        "safety",
        escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        impact_vector={"safety": 0.9},
    )
    judgment = JudgmentSynapse(
        task_id=case.synapse.task_id,
        miner_uid="miner-proof",
        judgment="deny unsafe request",
        reasoning="constitutional rationale",
        artifact_hash="artifact-proof",
        constitutional_hash=owner.constitution_hash,
    )
    assignment_id = "assignment-proof"
    content_hash = hashlib.sha256(judgment.judgment.encode("utf-8")).hexdigest()[:32]
    vote_hashes = tuple(hashlib.sha256(f"vote-{i}".encode()).hexdigest()[:32] for i in range(5))
    root_hash = _compute_merkle_root(
        assignment_id,
        content_hash,
        owner.constitution_hash,
        vote_hashes,
        True,
    )
    proof = MeshProof(
        assignment_id=assignment_id,
        content_hash=content_hash,
        constitutional_hash=owner.constitution_hash,
        vote_hashes=vote_hashes,
        root_hash=root_hash,
        accepted=True,
        timestamp=time.time(),
    )
    assert proof.verify()
    validation = ValidationSynapse(
        task_id=case.synapse.task_id,
        assignment_id=proof.assignment_id,
        accepted=True,
        votes_for=3,
        votes_against=2,
        quorum_met=True,
        proof_root_hash=proof.root_hash,
        proof_vote_hashes=proof.vote_hashes,
        proof_content_hash=proof.content_hash,
        constitutional_hash=owner.constitution_hash,
        timestamp=proof.timestamp,
    )
    return case, judgment, validation


def test_subnet_owner_accepts_complete_judgment_bound_mesh_proof(tmp_path) -> None:
    owner = SubnetOwner(_admission_constitution_file(tmp_path))
    case, judgment, validation = _proof_bound_owner_inputs(owner)
    precedent = owner.record_result(case, judgment, validation)
    assert precedent is not None
    assert precedent.proof_root_hash == validation.proof_root_hash
    assert owner.precedent_store.size == 1
    assert case.case_id not in owner.active_cases


@pytest.mark.parametrize(
    "mutation",
    [
        "assignment",
        "root",
        "content",
        "vote-count",
        "duplicate-vote",
        "empty-vote",
    ],
)
def test_subnet_owner_rejects_incomplete_or_unbound_proof_without_side_effects(
    tmp_path, mutation: str
) -> None:
    owner = SubnetOwner(_admission_constitution_file(tmp_path))
    case, judgment, validation = _proof_bound_owner_inputs(owner)
    if mutation == "assignment":
        validation = dataclasses.replace(validation, assignment_id="")
    elif mutation == "root":
        validation = dataclasses.replace(validation, proof_root_hash="wrong")
    elif mutation == "content":
        validation = dataclasses.replace(validation, proof_content_hash="wrong")
    elif mutation == "vote-count":
        validation = dataclasses.replace(validation, proof_vote_hashes=validation.proof_vote_hashes[:-1])
    elif mutation == "duplicate-vote":
        validation = dataclasses.replace(
            validation,
            proof_vote_hashes=(validation.proof_vote_hashes[0],) * 5,
        )
    else:
        validation = dataclasses.replace(
            validation,
            proof_vote_hashes=("",) + validation.proof_vote_hashes[1:],
        )

    before_summary = owner.summary()
    with pytest.raises(ValueError, match="proof|content|vote|assignment"):
        owner.record_result(case, judgment, validation)
    assert owner.summary() == before_summary
    assert owner.precedent_store.size == 0
    assert case.case_id in owner.active_cases


class TestC4ReviewCoordinator:
    """Independent-review regressions for emission admission."""

    def test_explicit_empty_registered_miner_set_pays_nobody(self) -> None:
        coordinator = GovernanceCoordinator(CoordinatorConfig(registered_miners=set()))

        cycle = coordinator.compute_emissions(
            [MinerEmissionInput("unregistered", tier=MinerTier.MASTER, reputation=1.0)]
        )

        assert cycle.active_miners == 0
        assert cycle.as_weight_dict() == {"unregistered": 0.0}

    def test_duplicate_miner_uid_is_rejected_before_emission_compute(self) -> None:
        coordinator = GovernanceCoordinator(
            CoordinatorConfig(registered_miners={"duplicated", "other"})
        )

        with pytest.raises(ValueError, match="duplicate miner_uid.*duplicated"):
            coordinator.compute_emissions(
                [
                    MinerEmissionInput(
                        "duplicated",
                        tier=MinerTier.MASTER,
                        manifold_trust=1.0,
                        reputation=1.0,
                    ),
                    MinerEmissionInput(
                        "duplicated",
                        tier=MinerTier.MASTER,
                        manifold_trust=1.0,
                        reputation=1.0,
                    ),
                    MinerEmissionInput("other", tier=MinerTier.MASTER),
                ]
            )


class TestC4ReviewAdmission:
    """Independent-review regressions for precedent admission and activation."""

    def test_admission_rejects_minority_and_tied_tallies(self) -> None:
        store = PrecedentStore(CONSTITUTIONAL_HASH)

        with pytest.raises(ValueError, match="super-majority|majority"):
            store.add(
                _admission_record(
                    case_id="minority-three-of-thirteen",
                    task_id="minority-three-of-thirteen",
                    votes_for=3,
                    votes_against=10,
                )
            )
        with pytest.raises(ValueError, match="majority"):
            store.add(
                _admission_record(
                    case_id="tie-five-of-ten",
                    task_id="tie-five-of-ten",
                    votes_for=5,
                    votes_against=5,
                )
            )
        with pytest.raises(ValueError, match="super-majority"):
            store.add(
                _admission_record(
                    case_id="simple-majority-six-of-eleven",
                    task_id="simple-majority-six-of-eleven",
                    votes_for=6,
                    votes_against=5,
                )
            )

        store.add(
            _admission_record(
                case_id="super-majority-three-of-five",
                task_id="super-majority-three-of-five",
                votes_for=3,
                votes_against=2,
            )
        )
        assert store.size == 1

    def test_admission_configuration_cannot_weaken_super_majority_ratio(self) -> None:
        with pytest.raises(ValueError, match="super-majority|ratio"):
            PrecedentStore(
                CONSTITUTIONAL_HASH,
                min_votes_for_precedent=3,
                min_total_validators=10,
            )

        store = PrecedentStore(
            CONSTITUTIONAL_HASH,
            min_votes_for_precedent=6,
            min_total_validators=10,
        )
        store.add(
            _admission_record(
                case_id="configured-six-of-ten",
                task_id="configured-six-of-ten",
                votes_for=6,
                votes_against=4,
            )
        )
        assert store.size == 1

    def test_active_source_guard_allows_safe_store_reentry(self) -> None:
        store = PrecedentStore(CONSTITUTIONAL_HASH)
        record = _admission_record(case_id="reentrant", task_id="reentrant")
        store.add(record)
        observed: list[object] = []

        def reenter_store() -> None:
            with store.guard_active_sources([record.precedent_id]):
                observed.append(store.size)
                observed.append(store.active_records_by_id([record.precedent_id]))
                observed.append(store.retrieve({"safety": 0.9}).top_match is not None)

        worker = threading.Thread(target=reenter_store, daemon=True)
        worker.start()
        worker.join(timeout=1)

        assert not worker.is_alive(), "guard_active_sources deadlocked on store re-entry"
        assert observed == [1, (store.active_records()[0],), True]

    def test_rule_codifier_supports_successive_activations_from_one_admission_epoch(
        self,
    ) -> None:
        store = PrecedentStore(CONSTITUTIONAL_HASH)
        records = [
            _admission_record(
                case_id="successive-safety",
                task_id="successive-safety",
                vector={"safety": 1.0},
            ),
            _admission_record(
                case_id="successive-privacy",
                task_id="successive-privacy",
                vector={"privacy": 1.0},
            ),
        ]
        for record in records:
            store.add(record)
        codifier = RuleCodifier(
            CONSTITUTIONAL_HASH,
            precedent_store=store,
            min_cluster_size=1,
            min_validator_agreement=0.5,
        )
        clusters = codifier.find_clusters(list(store.active_records()))
        candidates = codifier.propose_rules(clusters)
        assert len(candidates) == 2

        codifier.approve(candidates[0].candidate_id)
        _, yaml_after_first = codifier.activate(
            candidates[0].candidate_id, "name: test\nrules: []\n"
        )
        hash_after_first = codifier.constitutional_hash
        codifier.approve(candidates[1].candidate_id)
        codifier.activate(candidates[1].candidate_id, yaml_after_first)

        assert codifier.constitutional_hash != hash_after_first
        assert len(codifier.active_rules) == 2


class TestC4ReviewProtocol:
    @pytest.mark.parametrize("exclude_sybils", [True, False])
    def test_explicit_exclude_sybils_argument_is_deprecated(
        self, exclude_sybils: bool
    ) -> None:
        with pytest.warns(DeprecationWarning, match="exclude_sybils"):
            NMCSession(
                case_id="deprecated-exclusion",
                exclude_sybils=exclude_sybils,
            )

        with pytest.warns(DeprecationWarning, match="exclude_sybils"):
            nmc_mod.NMCCoordinator(exclude_sybils=exclude_sybils)

    def test_omitted_exclude_sybils_argument_does_not_warn(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            NMCSession(case_id="default-exclusion")
            coordinator = nmc_mod.NMCCoordinator()
            coordinator.create_session("default-coordinator-exclusion")

        assert not [item for item in caught if item.category is DeprecationWarning]

    @pytest.mark.parametrize(
        ("method", "expected_confidence"),
        [
            (nmc_mod.SynthesisMethod.MAJORITY_VOTE, 2 / 5),
            (nmc_mod.SynthesisMethod.WEIGHTED_VOTE, 2 / 5),
            (nmc_mod.SynthesisMethod.UNANIMOUS, 0.0),
        ],
    )
    def test_tie_break_is_deterministic_across_reveal_order(
        self,
        method: nmc_mod.SynthesisMethod,
        expected_confidence: float,
    ) -> None:
        forward = _nmc_complete_session(
            [
                ("zeta-1", "zeta"),
                ("zeta-2", "zeta"),
                ("alpha-1", "alpha"),
                ("alpha-2", "alpha"),
                ("other", "other"),
            ]
        ).synthesize(method)
        reverse = _nmc_complete_session(
            [
                ("alpha-2", "alpha"),
                ("alpha-1", "alpha"),
                ("zeta-2", "zeta"),
                ("zeta-1", "zeta"),
                ("other", "other"),
            ]
        ).synthesize(method)

        assert forward.judgment_text == reverse.judgment_text == "alpha"
        assert forward.confidence == reverse.confidence == pytest.approx(
            expected_confidence
        )

    def test_rejected_candidate_releases_issuance_and_mesh_state(self) -> None:
        constitution = Constitution.default()
        cascade = PrecedentCascade(
            constitution,
            _nmc_mesh(constitution, quorum=2),
            min_consensus_miners=3,
            consensus_threshold=2 / 3,
        )

        candidate = _nmc_run_cascade(cascade)

        assert candidate.alive is False
        assert candidate.current_stage is CascadeStage.CONSTITUTIONAL_COMPATIBILITY
        assert candidate.candidate_id not in cascade._issued
        assert candidate.candidate_id not in cascade._mesh_results

    def test_codifier_ties_choose_stable_lexical_winners(self) -> None:
        shared_prefix = "a" * 100
        specifications = [
            (shared_prefix + "-zeta", EscalationType.CONTEXT_SENSITIVITY),
            (shared_prefix + "-zeta", EscalationType.CONTEXT_SENSITIVITY),
            (shared_prefix + "-alpha", EscalationType.CONSTITUTIONAL_CONFLICT),
            (shared_prefix + "-alpha", EscalationType.CONSTITUTIONAL_CONFLICT),
        ]

        def codify(ordered_specs):  # type: ignore[no-untyped-def]
            store = PrecedentStore(CONSTITUTIONAL_HASH)
            for index, (judgment, escalation_type) in enumerate(ordered_specs):
                record = dataclasses.replace(
                    _admission_record(
                        case_id=f"tie-{index}",
                        task_id=f"tie-{index}",
                        judgment=judgment,
                    ),
                    escalation_type=escalation_type,
                )
                store.add(record)
            codifier = RuleCodifier(
                CONSTITUTIONAL_HASH,
                precedent_store=store,
                min_cluster_size=1,
                min_validator_agreement=0.0,
            )
            [cluster] = codifier.find_clusters(list(store.active_records()))
            [candidate] = codifier.propose_rules([cluster])
            return cluster, candidate

        forward_cluster, forward_candidate = codify(specifications)
        reverse_cluster, reverse_candidate = codify(list(reversed(specifications)))

        expected_judgment = shared_prefix + "-alpha"
        assert forward_cluster.escalation_type == reverse_cluster.escalation_type
        assert forward_cluster.escalation_type == "constitutional_conflict"
        assert forward_cluster.majority_judgment == expected_judgment
        assert reverse_cluster.majority_judgment == expected_judgment
        assert forward_candidate.rule_text == reverse_candidate.rule_text
