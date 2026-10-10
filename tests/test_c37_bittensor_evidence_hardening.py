"""C37 regressions: Bittensor precedent evidence, owner ids, validator and coordinator.

Every test is phrased as an invalid-input regression: the object under test carries a value
that the verifier must not trust, and the test expects rejection (or the trusted value).
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import re
import sys
from datetime import UTC, datetime, timedelta

import pytest
from acgs_lite import CaseState

from constitutional_swarm.bittensor import precedent_store as precedent_store_module
from constitutional_swarm.bittensor.governance_coordinator import (
    CoordinatorConfig,
    GovernanceCoordinator,
)
from constitutional_swarm.bittensor.protocol import (
    SubnetMetrics,
    ValidatorConfig,
)
from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
from constitutional_swarm.bittensor.synapses import JudgmentSynapse, ValidationSynapse
from constitutional_swarm.bittensor.validator import ConstitutionalValidator
from constitutional_swarm.mesh.vote_envelope import vote_envelope_hash
from tests.test_c14_protocol_hardening import (
    c14_precedent_signed_record,
    c14_precedent_test_store,
)

_CONSTITUTION_YAML = (
    "name: c37-evidence-test\nrules:\n"
    "  - id: safety\n"
    "    text: Preserve safety and explain governance decisions\n"
    "    severity: high\n"
    "    hardcoded: false\n"
)


def _constitution_file(tmp_path) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "c37-constitution.yaml"
    path.write_text(_CONSTITUTION_YAML, encoding="utf-8")
    return str(path)


def _ts(minutes: int) -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# bittensor-precedent-1: precedent metadata must be well-formed at every boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [1.5, -0.1, math.nan, math.inf, -math.inf, True, "0.5", None],
)
def test_precedent_record_rejects_invalid_impact_value(bad_value: object) -> None:
    with pytest.raises(ValueError, match="impact_vector"):
        c14_precedent_signed_record(
            impact_vector={"safety": 0.9, "security": bad_value},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize("method", ["add", "admit"])
@pytest.mark.parametrize("bad_value", [1.5, math.nan, -0.1])
def test_store_rejects_signed_record_with_tampered_impact_vector(
    method: str, bad_value: float
) -> None:
    store = c14_precedent_test_store()
    record = c14_precedent_signed_record()
    with pytest.raises(ValueError, match="impact_vector"):
        getattr(store, method)(
            dataclasses.replace(record, impact_vector={"safety": bad_value, "security": 0.8})
        )
    assert store.size == 0


@pytest.mark.parametrize("method", ["add", "admit"])
def test_store_revalidates_impact_vector_mutated_after_construction(method: str) -> None:
    store = c14_precedent_test_store()
    record = c14_precedent_signed_record()
    record.impact_vector["safety"] = math.nan
    with pytest.raises(ValueError, match="impact_vector"):
        getattr(store, method)(record)
    assert store.size == 0


@pytest.mark.parametrize("bad_dimensions", [("safety", ""), ("safety", 7), ["safety"]])
def test_precedent_record_rejects_malformed_ambiguous_dimensions(bad_dimensions: object) -> None:
    record = c14_precedent_signed_record()
    with pytest.raises(ValueError, match="ambiguous_dimensions"):
        dataclasses.replace(record, ambiguous_dimensions=bad_dimensions)


def test_precedent_record_rejects_non_enum_escalation_type() -> None:
    record = c14_precedent_signed_record()
    with pytest.raises(TypeError, match="escalation_type"):
        dataclasses.replace(record, escalation_type="constitutional_conflict")


@pytest.mark.parametrize("field_name", ["case_id", "task_id"])
def test_precedent_record_rejects_empty_source_identifier(field_name: str) -> None:
    record = c14_precedent_signed_record()
    with pytest.raises(ValueError, match=field_name):
        dataclasses.replace(record, **{field_name: ""})


def test_valid_signed_record_still_admits_and_auto_resolves() -> None:
    store = c14_precedent_test_store()
    admitted = store.admit(c14_precedent_signed_record())
    result = store.retrieve({"safety": 0.9, "security": 0.8}, k=1)
    assert result.auto_resolution_source == admitted.precedent_id


# ---------------------------------------------------------------------------
# bittensor-owner-1: owner identifiers carry full uuid4 entropy
# ---------------------------------------------------------------------------


def test_owner_case_and_task_ids_are_full_128_bit_identifiers(tmp_path) -> None:
    owner = SubnetOwner(_constitution_file(tmp_path))
    case = owner.package_case("privacy conflict", "privacy")
    assert re.fullmatch(r"[0-9a-f]{32}", case.case_id)
    assert re.fullmatch(r"[0-9a-f]{32}", case.synapse.task_id)


# ---------------------------------------------------------------------------
# bittensor-opt-1: one canonical content hash and vote ordering
# ---------------------------------------------------------------------------


def test_judgment_content_hash_matches_signed_evidence_definition() -> None:
    from constitutional_swarm.bittensor.synapses import judgment_content_hash

    judgment = "deny unsafe request"
    expected = hashlib.sha256(judgment.encode("utf-8")).hexdigest()[:32]
    assert judgment_content_hash(judgment) == expected
    assert c14_precedent_signed_record(judgment=judgment).content_hash == expected


def test_ordered_vote_hashes_is_order_independent() -> None:
    from constitutional_swarm.bittensor.synapses import ordered_vote_hashes

    record = c14_precedent_signed_record()
    envelopes = record.vote_envelopes
    expected = tuple(
        vote_envelope_hash(item)
        for item in sorted(envelopes, key=lambda item: (item.voter_id, item.key_id))
    )
    assert ordered_vote_hashes(envelopes) == expected
    assert ordered_vote_hashes(tuple(reversed(envelopes))) == expected


# ---------------------------------------------------------------------------
# bittensor-opt-3 / opt-4: store indexes and shared summary helpers
# ---------------------------------------------------------------------------


def test_store_rejects_duplicate_source_after_revocation() -> None:
    store = c14_precedent_test_store()
    first = store.admit(c14_precedent_signed_record(case_id="c37-case", task_id="c37-task"))
    store.revoke(first.precedent_id, reason="test")
    with pytest.raises(ValueError, match="case_id"):
        store.add(c14_precedent_signed_record(case_id="c37-case", task_id="c37-other"))
    with pytest.raises(ValueError, match="task_id"):
        store.add(c14_precedent_signed_record(case_id="c37-other", task_id="c37-task"))


def test_retrieve_returns_detached_top_k_copies() -> None:
    store = c14_precedent_test_store()
    for index in range(3):
        store.admit(
            c14_precedent_signed_record(case_id=f"case-{index}", task_id=f"task-{index}")
        )
    result = store.retrieve({"safety": 0.9, "security": 0.8}, k=2)
    assert [match.rank for match in result.matches] == [1, 2]
    result.matches[0].precedent.impact_vector["safety"] = 0.0
    assert all(r.impact_vector["safety"] == 0.9 for r in store.active_records())


def test_summary_projection_follows_escalation_rate_projection() -> None:
    store = c14_precedent_test_store()
    store.admit(c14_precedent_signed_record())
    summary = store.summary()
    assert summary["projected_escalation_rate"] == store.escalation_rate_projection()
    assert summary["escalation_distribution"] == store.escalation_distribution()


# ---------------------------------------------------------------------------
# bittensor-coord-1: finalisation votes must come from the recorded selection
# ---------------------------------------------------------------------------


def _coordinator_in_validation() -> tuple[GovernanceCoordinator, str, tuple[str, ...]]:
    gc = GovernanceCoordinator(CoordinatorConfig())
    for index in range(10):
        gc.register_validator(
            f"val-{index:03d}",
            trust_score=0.9,
            domains=["finance"],
            model=["gpt-4", "claude-3", "gemini-2"][index % 3],
        )
    gc.register_validator("claimer", trust_score=0.9, domains=["finance"], model="gpt-4")
    cid = gc.create_case("evaluate", domain="finance", _now=_ts(0))
    gc.assign_miner(cid, "claimer", _now=_ts(1))
    gc.submit_result(cid, "claimer", {"verdict": "allow"}, _now=_ts(2))
    selection = gc.select_and_begin_validation(cid, seed="ab" * 32, _now=_ts(3))
    return gc, cid, tuple(selection.selected)


def _assert_not_finalized(gc: GovernanceCoordinator, cid: str) -> None:
    case = gc.case(cid)
    assert case is not None
    assert case.state == CaseState.VALIDATING
    assert gc.auditor.unchecked_count() == 0


def test_finalize_rejects_vote_from_validator_outside_selection() -> None:
    gc, cid, selected = _coordinator_in_validation()
    outsider = next(f"val-{i:03d}" for i in range(10) if f"val-{i:03d}" not in selected)
    votes = {vid: "approve" for vid in selected}
    votes[outsider] = "approve"
    with pytest.raises(ValueError, match="selected"):
        gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_vote_from_claimer() -> None:
    gc, cid, selected = _coordinator_in_validation()
    votes = {vid: "approve" for vid in selected}
    votes["claimer"] = "approve"
    with pytest.raises(ValueError, match="claimer|selected"):
        gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_unknown_vote_decision() -> None:
    gc, cid, selected = _coordinator_in_validation()
    votes = {vid: "approve" for vid in selected}
    votes[selected[0]] = "abstain"
    with pytest.raises(ValueError, match="decision"):
        gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_outcome_contradicting_supplied_votes() -> None:
    gc, cid, selected = _coordinator_in_validation()
    votes = {vid: "reject" for vid in selected}
    with pytest.raises(ValueError, match="outcome"):
        gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_votes_for_case_without_recorded_selection() -> None:
    gc = GovernanceCoordinator(CoordinatorConfig())
    cid = gc.create_case("evaluate", domain="finance", _now=_ts(0))
    with pytest.raises(ValueError, match="selection"):
        gc.finalize_case(cid, accepted=True, validator_votes={"val": "approve"}, _now=_ts(4))


def test_finalize_accepts_majority_votes_from_selection() -> None:
    gc, cid, selected = _coordinator_in_validation()
    votes = {vid: "approve" for vid in selected}
    votes[selected[-1]] = "reject"
    gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    case = gc.case(cid)
    assert case is not None and case.state == CaseState.FINALIZED
    assert gc.auditor.unchecked_count() == 1


# ---------------------------------------------------------------------------
# bittensor-coord-2: re-registration cannot reset trust or reactivate
# ---------------------------------------------------------------------------


def test_duplicate_validator_registration_is_rejected_without_mutation() -> None:
    gc = GovernanceCoordinator(CoordinatorConfig())
    gc.register_validator("val-1", trust_score=0.3, domains=["finance"])
    gc.deactivate_validator("val-1")
    with pytest.raises(ValueError, match="already registered"):
        gc.register_validator("val-1", trust_score=0.99, domains=["finance"])
    entry = gc.validator_pool.get("val-1")
    assert entry is not None
    assert entry.active is False
    assert entry.trust_score == pytest.approx(0.3)


def test_validator_registration_rejects_identity_known_only_to_trust_manager() -> None:
    gc = GovernanceCoordinator(CoordinatorConfig())
    gc.trust_manager.register("val-ghost")
    with pytest.raises(ValueError, match="already registered"):
        gc.register_validator("val-ghost", trust_score=0.99)
    assert gc.validator_pool.get("val-ghost") is None


# ---------------------------------------------------------------------------
# bittensor-validator-1: one mesh snapshot per synapse
# ---------------------------------------------------------------------------


def _dev_validator(tmp_path) -> ConstitutionalValidator:  # type: ignore[no-untyped-def]
    validator = ConstitutionalValidator(
        ValidatorConfig(
            constitution_path=_constitution_file(tmp_path),
            peers_per_validation=5,
            quorum=3,
            use_manifold=True,
            single_operator_dev=True,
        )
    )
    for uid in ("producer", "peer-1", "peer-2", "peer-3", "peer-4", "peer-5"):
        validator.register_miner(uid, domain="governance")
    return validator


def test_validation_synapse_trust_update_uses_captured_mesh(tmp_path, monkeypatch) -> None:
    validator = _dev_validator(tmp_path)
    captured = validator.mesh
    original_get_result = captured.get_result

    class _RotatedMesh:
        def manifold_summary(self) -> dict[str, object]:
            raise AssertionError("trust_update read a mesh other than the evidence mesh")

    def _rotate_then_get_result(assignment_id: str):  # type: ignore[no-untyped-def]
        # Simulate rotate_constitution() landing after _result_to_synapse snapshots
        # its mesh (get_result is its first call after the snapshot).
        if sys._getframe(1).f_code.co_name == "_result_to_synapse":
            validator._mesh = _RotatedMesh()  # type: ignore[assignment]
        return original_get_result(assignment_id)

    monkeypatch.setattr(captured, "get_result", _rotate_then_get_result)
    synapse = validator.validate(
        JudgmentSynapse(
            task_id="c37-task",
            miner_uid="producer",
            judgment="Privacy takes precedence over transparency in this case",
            reasoning="consent was not given",
            artifact_hash="c37-artifact",
            constitutional_hash=captured.constitutional_hash,
        )
    )
    assert synapse.trust_update == (captured.manifold_summary() or {})


def test_get_miner_reputation_is_deprecated_and_locked(tmp_path) -> None:
    validator = _dev_validator(tmp_path)
    with pytest.warns(DeprecationWarning, match="get_miner_reputation"):
        reputation = validator.get_miner_reputation("producer")
    assert reputation == validator.mesh.get_reputation("producer")


# ---------------------------------------------------------------------------
# bittensor-dead-1 / dead-2: inert configuration is rejected, dead names deprecated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("factory", "kwargs"),
    [
        (ValidatorConfig, {"constitution_path": "x", "authenticity_detection": True}),
        (ValidatorConfig, {"constitution_path": "x", "reputation_decay_rate": 0.5}),
        (SubnetMetrics, {"avg_judgment_time_seconds": 1.0}),
        (SubnetMetrics, {"active_validators": 3}),
        (SubnetMetrics, {"manifold_spectral_bound": 0.9}),
    ],
)
def test_inert_configuration_fields_are_rejected(factory: type, kwargs: dict) -> None:
    with pytest.raises(TypeError):
        factory(**kwargs)


def test_validation_synapse_has_no_unpopulated_authenticity_score() -> None:
    names = {field.name for field in dataclasses.fields(ValidationSynapse)}
    assert "authenticity_score" not in names


def test_precedent_revoked_error_is_deprecated_but_importable() -> None:
    with pytest.warns(DeprecationWarning, match="PrecedentRevokedError"):
        error_type = precedent_store_module.PrecedentRevokedError
    assert issubclass(error_type, RuntimeError)


def test_coordinator_has_no_unused_pending_audit_state() -> None:
    assert not hasattr(GovernanceCoordinator(CoordinatorConfig()), "_pending_audit")


def test_rejected_trust_score_leaves_no_partial_registration() -> None:
    gc = GovernanceCoordinator(CoordinatorConfig())
    with pytest.raises(ValueError, match="score"):
        gc.register_validator("val-bad", trust_score=1.5)
    assert gc.validator_pool.get("val-bad") is None
    assert "val-bad" not in gc.trust_manager.list_agents()


# ---------------------------------------------------------------------------
# C37 rework r1 (M2): finalisation needs a vote from every selected validator
# ---------------------------------------------------------------------------


def test_finalize_rejects_empty_vote_set_for_selected_case() -> None:
    gc, cid, _selected = _coordinator_in_validation()
    with pytest.raises(ValueError, match="every selected validator"):
        gc.finalize_case(cid, accepted=True, validator_votes={}, _now=_ts(4))
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_single_vote_acceptance() -> None:
    gc, cid, selected = _coordinator_in_validation()
    with pytest.raises(ValueError, match="every selected validator"):
        gc.finalize_case(
            cid, accepted=True, validator_votes={selected[0]: "approve"}, _now=_ts(4)
        )
    _assert_not_finalized(gc, cid)


def test_finalize_rejects_partial_vote_coverage() -> None:
    gc, cid, selected = _coordinator_in_validation()
    votes = {vid: "approve" for vid in selected[:-1]}
    with pytest.raises(ValueError, match="every selected validator"):
        gc.finalize_case(cid, accepted=True, validator_votes=votes, _now=_ts(4))
    _assert_not_finalized(gc, cid)
