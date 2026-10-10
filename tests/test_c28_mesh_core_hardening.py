"""Regression coverage for the C28 mesh-core hardening findings."""

from __future__ import annotations

import dataclasses
import uuid

import pytest


def _c28_mesh(**kwargs):
    from acgs_lite import Constitution
    from constitutional_swarm.mesh import ConstitutionalMesh

    kwargs.setdefault("evidence_mode", "single_operator_dev")
    if "settlement_store" in kwargs or "settlement_store_path" in kwargs:
        kwargs.setdefault("quorum", 3)
    mesh = ConstitutionalMesh(Constitution.default(), seed=28, **kwargs)
    for agent_id in ("a", "b", "c", "d", "e"):
        mesh.register_local_signer(agent_id)
    return mesh


def _c28_reader(writer, store):
    from constitutional_swarm.mesh import ConstitutionalMesh

    return ConstitutionalMesh(
        writer._constitution,
        quorum=3,
        settlement_store=store,
        vote_registry=writer.vote_registry,
        assigner_private_key=writer._assigner_private_key,
        assigner_id=writer.assigner_id,
        evidence_mode="single_operator_dev",
    )


def _c28_tampering_store(path, tamper):
    """A JSONL store whose ``load_all`` rewrites records to model bad history."""
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    class _TamperingStore(JSONLSettlementStore):
        def load_all(self):
            return [tamper(record) for record in super().load_all()]

    return _TamperingStore(path)


# -- mesh-settle-1 ----------------------------------------------------------


def test_c28_malformed_historical_settlement_is_quarantined_not_fatal(tmp_path, caplog):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    bad = writer.full_validation("a", "first output", "artifact-1")
    good = writer.full_validation("a", "second output", "artifact-2")
    assert bad.settled and good.settled

    def strip_signed_assignment(record):
        if record.assignment["assignment_id"] != bad.assignment_id:
            return record
        assignment = dict(record.assignment)
        assignment.pop("signed_assignment", None)
        return dataclasses.replace(record, assignment=assignment)

    with caplog.at_level("WARNING", logger="constitutional_swarm.mesh.core"):
        reader = _c28_reader(writer, _c28_tampering_store(path, strip_signed_assignment))

    assert f"quarantining settlement {bad.assignment_id}" in caplog.text
    assert "missing signed_assignment" in caplog.text

    assert good.assignment_id in reader._final_results
    assert bad.assignment_id not in reader._final_results
    assert bad.assignment_id not in reader._assignments


def test_c28_settlement_with_disagreeing_hash_tags_is_quarantined(tmp_path, caplog):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    bad = writer.full_validation("a", "first output", "artifact-1")
    good = writer.full_validation("a", "second output", "artifact-2")

    def corrupt_hash_tag(record):
        if record.assignment["assignment_id"] != bad.assignment_id:
            return record
        return dataclasses.replace(record, constitutional_hash="f" * 16)

    with caplog.at_level("WARNING", logger="constitutional_swarm.mesh.core"):
        reader = _c28_reader(writer, _c28_tampering_store(path, corrupt_hash_tag))

    assert f"quarantining settlement {bad.assignment_id}" in caplog.text
    assert "hash tags disagree" in caplog.text

    assert good.assignment_id in reader._final_results
    assert bad.assignment_id not in reader._final_results


# -- opt-dead-4: pinned verifier still rejects unassigned voter evidence -----


def test_c28_settlement_with_unassigned_voter_envelope_is_quarantined(tmp_path, caplog):
    from constitutional_swarm.mesh.vote_envelope import (
        sign_vote_envelope,
        vote_envelope_from_dict,
        vote_envelope_to_dict,
    )

    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    settled = writer.full_validation("a", "output", "artifact")
    assignment = writer._assignments[settled.assignment_id]
    outsider = next(
        agent
        for agent in ("b", "c", "d", "e")
        if agent not in assignment.peers
    )

    def swap_in_outsider(record):
        votes = list(record.votes)
        honest = vote_envelope_from_dict(votes[0])
        forged = sign_vote_envelope(
            writer._agent_vote_private_keys[outsider],
            voter_id=outsider,
            task_id=honest.task_id,
            assignment_id=honest.assignment_id,
            producer_id=honest.producer_id,
            artifact_id=honest.artifact_id,
            content_hash=honest.content_hash,
            constitutional_hash=honest.constitutional_hash,
            decision=honest.decision,
            reason=honest.reason,
            nonce=uuid.uuid4().hex,
            issued_at=honest.issued_at,
            assigned_peers=assignment.peers,
            quorum=honest.quorum,
            evidence_mode=honest.evidence_mode,
            assignment_digest=honest.assignment_digest,
        )
        votes[0] = vote_envelope_to_dict(forged)
        return dataclasses.replace(record, votes=tuple(votes))

    with caplog.at_level("WARNING", logger="constitutional_swarm.mesh.core"):
        reader = _c28_reader(writer, _c28_tampering_store(path, swap_in_outsider))

    assert f"quarantining settlement {settled.assignment_id}" in caplog.text
    assert "assigned_peers_hash" in caplog.text

    assert settled.assignment_id not in reader._final_results


# -- mesh-core-1 -------------------------------------------------------------


def test_c28_sign_vote_rejects_unassigned_voter_without_caching():
    from constitutional_swarm.mesh import UnauthorizedVoterError

    mesh = _c28_mesh()
    assignment = mesh.request_validation("a", "content", "artifact")
    outsider = next(
        agent for agent in ("b", "c", "d", "e") if agent not in assignment.peers
    )

    with pytest.raises(UnauthorizedVoterError):
        mesh.sign_vote(assignment.assignment_id, outsider, approved=True)
    with pytest.raises(UnauthorizedVoterError):
        mesh.validate_and_vote(assignment.assignment_id, outsider)
    with pytest.raises(UnauthorizedVoterError):
        mesh.sign_vote_envelope(assignment.assignment_id, outsider, approved=True)

    assert len(mesh._signed_envelopes_by_signature) == 0


def test_c28_sign_vote_rejects_settled_assignment_without_caching():
    from constitutional_swarm.mesh import AssignmentSettledError

    mesh = _c28_mesh()
    result = mesh.full_validation("a", "content", "artifact")
    assert result.settled
    assignment = mesh._assignments[result.assignment_id]

    with pytest.raises(AssignmentSettledError):
        mesh.sign_vote(result.assignment_id, assignment.peers[0], approved=True)

    assert len(mesh._signed_envelopes_by_signature) == 0


def test_c28_failed_validate_and_vote_does_not_leak_signed_envelope():
    from constitutional_swarm.mesh import DuplicateVoteError

    mesh = _c28_mesh(quorum=3)
    assignment = mesh.request_validation("a", "content", "artifact")
    voter = assignment.peers[0]
    mesh.validate_and_vote(assignment.assignment_id, voter)

    for _ in range(3):
        with pytest.raises(DuplicateVoteError):
            mesh.validate_and_vote(assignment.assignment_id, voter)

    assert len(mesh._signed_envelopes_by_signature) == 0


def test_c28_unsubmitted_signed_envelopes_are_purged_on_settlement():
    mesh = _c28_mesh()
    assignment = mesh.request_validation("a", "content", "artifact")
    mesh.sign_vote(assignment.assignment_id, assignment.peers[0], approved=False)
    other = mesh.request_validation("a", "other", "artifact-2")
    mesh.sign_vote(other.assignment_id, other.peers[0], approved=True)
    assert len(mesh._signed_envelopes_by_signature) == 2

    for voter in assignment.peers:
        mesh.validate_and_vote(assignment.assignment_id, voter)
        if mesh.get_result(assignment.assignment_id).settled:
            break

    assert mesh.get_result(assignment.assignment_id).settled
    remaining = list(mesh._signed_envelopes_by_signature.values())
    assert [item.assignment_id for item in remaining] == [other.assignment_id]


def test_c28_unsubmitted_sign_vote_envelope_entry_is_purged_on_settlement():
    mesh = _c28_mesh()
    assignment = mesh.request_validation("a", "content", "artifact")

    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id, assignment.peers[0], approved=False
    )
    assert envelope.signature in mesh._signed_envelopes_by_signature

    # The envelope is abandoned; the voter casts a fresh vote instead.
    for voter in assignment.peers:
        mesh.validate_and_vote(assignment.assignment_id, voter)
        if mesh.get_result(assignment.assignment_id).settled:
            break

    assert mesh.get_result(assignment.assignment_id).settled
    assert mesh._signed_envelopes_by_signature == {}


def test_c28_signed_envelopes_are_purged_on_settled_result_eviction():
    mesh = _c28_mesh(max_settled_results=1)
    first = mesh.full_validation("a", "first", "artifact-1")
    assert first.settled
    pending = mesh.request_validation("a", "pending", "artifact-2")
    signature = mesh.sign_vote(pending.assignment_id, pending.peers[0], approved=True)
    # Model an entry that outlived the settled first assignment.
    mesh._signed_envelopes_by_signature["stray"] = dataclasses.replace(
        mesh._signed_envelopes_by_signature[signature],
        assignment_id=first.assignment_id,
    )

    second = mesh.full_validation("a", "second", "artifact-3")

    assert second.settled
    assert first.assignment_id not in mesh._final_results
    assert "stray" not in mesh._signed_envelopes_by_signature
    assert signature in mesh._signed_envelopes_by_signature


# -- mesh-trust-1 (core part) -----------------------------------------------


def test_c28_assigner_trust_root_is_pinned_and_immutable():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    mesh = _c28_mesh()
    root = mesh.assigner_trust_root

    assert root.frozen is True
    assert not hasattr(root, "replace")
    assert not hasattr(root, "register")
    grants = root.trust_grants(role="assigner")
    assert [grant["identity_id"] for grant in grants.values()] == [mesh.assigner_id]

    mesh.vote_registry.register(
        "late-voter", Ed25519PrivateKey.generate().public_key()
    )
    assert root.public_key_for_identity("late-voter") is None
    assert mesh.assigner_trust_root is root


# -- opt-dead-1 --------------------------------------------------------------


def test_c28_vote_serialization_rejects_non_envelope_evidence():
    from constitutional_swarm.mesh import ValidationVote

    mesh = _c28_mesh()
    legacy_vote = ValidationVote(
        assignment_id="x",
        voter_id="b",
        approved=True,
        reason="",
        signature="00",
        constitutional_hash=mesh.constitutional_hash,
        content_hash="0" * 64,
        timestamp=0.0,
    )

    with pytest.raises(TypeError):
        mesh._vote_dicts([legacy_vote])
    with pytest.raises(TypeError):
        mesh._vote_dicts([{"voter_id": "b", "approved": True}])


def test_c28_dead_mesh_helpers_are_removed():
    from constitutional_swarm.mesh import ConstitutionalMesh

    for name in ("_persist_settlement", "_public_key_hex", "_select_peers"):
        assert not hasattr(ConstitutionalMesh, name), name
    assert hasattr(ConstitutionalMesh, "_select_peers_unlocked")


# -- C28 rework r1: quarantine visibility ------------------------------------


def _c28_assert_quarantined(reader, assignment_id, cause):
    quarantined = reader.quarantined_settlements
    assert quarantined[assignment_id] == cause
    with pytest.raises(TypeError):
        quarantined[assignment_id] = "ok"  # type: ignore[index]
    summary = reader.summary()
    assert summary["quarantined_settlements"] == 1
    assert summary["quarantined_settlement_ids"] == [assignment_id]


def test_c28_r1_malformed_settlement_is_reported_in_summary(tmp_path):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    bad = writer.full_validation("a", "first output", "artifact-1")
    writer.full_validation("a", "second output", "artifact-2")

    def strip_signed_assignment(record):
        if record.assignment["assignment_id"] != bad.assignment_id:
            return record
        assignment = dict(record.assignment)
        assignment.pop("signed_assignment", None)
        return dataclasses.replace(record, assignment=assignment)

    reader = _c28_reader(writer, _c28_tampering_store(path, strip_signed_assignment))

    _c28_assert_quarantined(reader, bad.assignment_id, "malformed")


def test_c28_r1_hash_tag_mismatch_is_reported_in_summary(tmp_path):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    bad = writer.full_validation("a", "first output", "artifact-1")

    def corrupt_hash_tag(record):
        return dataclasses.replace(record, constitutional_hash="f" * 16)

    reader = _c28_reader(writer, _c28_tampering_store(path, corrupt_hash_tag))

    _c28_assert_quarantined(reader, bad.assignment_id, "hash_tag_mismatch")


def test_c28_r1_unauthorized_evidence_is_reported_in_summary(tmp_path):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    bad = writer.full_validation("a", "output", "artifact")

    def drop_a_vote(record):
        return dataclasses.replace(record, votes=tuple(record.votes)[1:])

    reader = _c28_reader(writer, _c28_tampering_store(path, drop_a_vote))

    _c28_assert_quarantined(reader, bad.assignment_id, "evidence_rejected")


def test_c28_r1_clean_store_reports_no_quarantine(tmp_path):
    path = tmp_path / "settlements.jsonl"
    writer = _c28_mesh(settlement_store_path=path)
    writer.full_validation("a", "output", "artifact")

    reader = _c28_reader(writer, _c28_tampering_store(path, lambda record: record))

    assert reader.quarantined_settlements == {}
    assert reader.summary()["quarantined_settlements"] == 0
    assert reader.summary()["quarantined_settlement_ids"] == []


# -- C28 rework r1: complete_evidence is a no-op ------------------------------


def test_c28_r1_complete_evidence_argument_is_deprecated():
    import warnings

    from acgs_lite import Constitution
    from constitutional_swarm.mesh import ConstitutionalMesh

    for value in (True, False):
        with pytest.warns(DeprecationWarning, match="complete_evidence"):
            ConstitutionalMesh(Constitution.default(), complete_evidence=value)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        ConstitutionalMesh(Constitution.default())


# -- C28 rework r1: sign_vote_envelope is atomic -----------------------------


def test_c28_r1_sign_vote_envelope_is_atomic_against_concurrent_purge():
    import threading

    mesh = _c28_mesh()
    assignment = mesh.request_validation("a", "content", "artifact")
    real_sign_vote = mesh.sign_vote
    purger: list[threading.Thread] = []

    def sign_then_race(*args, **kwargs):
        signature = real_sign_vote(*args, **kwargs)

        def purge():
            with mesh._lock:
                mesh._purge_signed_envelopes_locked(assignment.assignment_id)

        thread = threading.Thread(target=purge)
        thread.start()
        thread.join(timeout=0.2)
        purger.append(thread)
        return signature

    mesh.sign_vote = sign_then_race  # type: ignore[method-assign]
    try:
        envelope = mesh.sign_vote_envelope(
            assignment.assignment_id, assignment.peers[0], approved=True
        )
    finally:
        for thread in purger:
            thread.join()

    assert envelope.assignment_id == assignment.assignment_id


@pytest.mark.parametrize("complete_evidence", [True, False])
def test_c28_r2_validator_construction_and_rotation_emit_no_deprecation(
    tmp_path, complete_evidence
):
    import warnings

    from acgs_lite import Constitution
    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator

    path = tmp_path / "c28-constitution.yaml"
    path.write_text(
        "name: c28\nrules:\n  - id: safety-01\n    text: Do not cause physical harm\n"
        "    severity: critical\n    hardcoded: true\n    keywords: [harm]\n",
        encoding="utf-8",
    )
    config = ValidatorConfig(
        constitution_path=str(path),
        peers_per_validation=5 if complete_evidence else 3,
        quorum=3 if complete_evidence else 2,
        complete_evidence=complete_evidence,
        single_operator_dev=True,
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        validator = ConstitutionalValidator(config)
        validator.rotate_constitution(Constitution.from_yaml(str(path)))

    assert validator.mesh.constitutional_hash == Constitution.from_yaml(str(path)).hash
