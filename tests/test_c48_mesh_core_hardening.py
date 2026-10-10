"""Regression coverage for the C48 mesh-core wiring and performance findings."""

from __future__ import annotations

import dataclasses
from collections import OrderedDict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _c48_mesh(**kwargs):
    from acgs_lite import Constitution
    from constitutional_swarm.mesh import ConstitutionalMesh

    kwargs.setdefault("evidence_mode", "single_operator_dev")
    if "settlement_store" in kwargs or "settlement_store_path" in kwargs:
        kwargs.setdefault("quorum", 3)
    mesh = ConstitutionalMesh(Constitution.default(), seed=48, **kwargs)
    for agent_id in ("a", "b", "c", "d", "e"):
        mesh.register_local_signer(agent_id)
    return mesh


def _c48_rotated_constitution():
    from acgs_lite import Constitution, Rule

    return Constitution.from_rules(
        [
            Rule(
                id="C48-ROTATED",
                text="Reject rotated marker",
                severity="critical",
                keywords=["c48-rotated-marker"],
            )
        ],
        name="c48-rotated",
    )


def _c48_stored_evidence(mesh, store, assignment_id):
    record = next(
        record
        for record in store.load_all()
        if record.assignment["assignment_id"] == assignment_id
    )
    assignment = dataclasses.replace(
        mesh._deserialize_assignment(record.assignment), is_recovered=True
    )
    return record, assignment, mesh._deserialize_result(record.result)


def _c48_signed_request(mesh, *, nonce, timestamp):
    from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteRequest

    assignment = mesh.request_validation("a", f"remote content {nonce}", f"art-{nonce}")
    voter_id = assignment.peers[0]
    voter_public_key = mesh.get_vote_public_key(voter_id)
    quorum = assignment.quorum
    signature = mesh._request_signing_private_key.sign(
        ConstitutionalMesh.build_remote_vote_request_payload(
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
            quorum=quorum,
            evidence_mode="single_operator_dev",
            protocol_version=3,
            signed_assignment=assignment.signed_assignment,
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
        request_signer_public_key=mesh.get_request_signing_public_key(),
        request_signature=signature,
        task_id=assignment.task_id,
        assigned_peers=assignment.peers,
        quorum=quorum,
        evidence_mode="single_operator_dev",
        protocol_version=3,
        signed_assignment=assignment.signed_assignment,
    )


# -- mesh-trust-1 (core wiring) ---------------------------------------------


def test_c48_recovery_verifies_assigner_against_pinned_trust_root_not_live_registry(
    tmp_path,
):
    path = tmp_path / "settlements.jsonl"
    mesh = _c48_mesh(settlement_store_path=path)
    settled = mesh.full_validation("a", "pinned assigner output", "artifact-pinned")
    record, assignment, result = _c48_stored_evidence(
        mesh, mesh._settlement_store, settled.assignment_id
    )

    # A later mutation of the live registry must not change which assignment
    # authority verifies durable history: the authority was pinned at construction.
    mesh._vote_registry.replace(
        mesh.assigner_id,
        Ed25519PrivateKey.generate().public_key(),
        roles={"assigner"},
    )

    envelopes, verified = mesh._verified_settlement_evidence(record, assignment, result)
    assert len(envelopes) == len(assignment.peers)
    assert verified.signed_assignment == assignment.signed_assignment


def test_c48_recovery_passes_trust_root_and_pins_to_envelope_verifier(
    tmp_path, monkeypatch
):
    from constitutional_swarm.mesh import core

    path = tmp_path / "settlements.jsonl"
    mesh = _c48_mesh(settlement_store_path=path)
    settled = mesh.full_validation("a", "wired output", "artifact-wired")
    record, assignment, result = _c48_stored_evidence(
        mesh, mesh._settlement_store, settled.assignment_id
    )
    seen = []
    real = core.verify_assignment_vote_envelopes

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(core, "verify_assignment_vote_envelopes", spy)
    mesh._verified_settlement_evidence(record, assignment, result)

    assert len(seen) == 1
    assert seen[0]["assigner_trust_root"] is mesh.assigner_trust_root
    assert seen[0]["expected_assigner_id"] == mesh.assigner_id
    assert seen[0]["expected_assigner_key_id"] == mesh.assigner_key_id


def test_c48_recovery_rejects_assignment_from_rogue_live_assigner_grant(tmp_path):
    from constitutional_swarm.mesh.vote_envelope import sign_assignment

    path = tmp_path / "settlements.jsonl"
    mesh = _c48_mesh(settlement_store_path=path)
    settled = mesh.full_validation("a", "rogue assigner output", "artifact-rogue")
    record, assignment, result = _c48_stored_evidence(
        mesh, mesh._settlement_store, settled.assignment_id
    )
    rogue_key = Ed25519PrivateKey.generate()
    mesh._vote_registry.register("rogue-assigner", rogue_key.public_key(), roles={"assigner"})
    original = assignment.signed_assignment
    forged = sign_assignment(
        rogue_key,
        task_id=original.task_id,
        assignment_id=original.assignment_id,
        assigner_id="rogue-assigner",
        producer_id=original.producer_id,
        artifact_id=original.artifact_id,
        content_hash=original.content_hash,
        constitutional_hash=original.constitutional_hash,
        assigned_peers=original.assigned_peers,
        quorum=original.quorum,
        selection_seed=original.selection_seed,
        issued_at=original.issued_at,
    )

    with pytest.raises(ValueError):
        mesh._verified_settlement_evidence(
            record, dataclasses.replace(assignment, signed_assignment=forged), result
        )


def test_c48_validator_pins_mesh_trust_root_for_vote_evidence(tmp_path, monkeypatch):
    from constitutional_swarm.bittensor import validator as validator_mod
    from tests.test_c14_protocol_hardening import _c14_precedent_pipeline

    _, validator, _, judgment, validation = _c14_precedent_pipeline(tmp_path)
    mesh = validator.mesh
    result = mesh.get_result(validation.assignment_id)
    seen = []
    real = validator_mod.verify_assignment_vote_envelopes

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(validator_mod, "verify_assignment_vote_envelopes", spy)
    validator._result_to_synapse(judgment, result)

    assert len(seen) == 1
    assert seen[0]["assigner_trust_root"] is mesh.assigner_trust_root
    assert seen[0]["expected_assigner_id"] == mesh.assigner_id
    assert seen[0]["expected_assigner_key_id"] == mesh.assigner_key_id


def test_c48_validator_ignores_later_live_assigner_rotation(tmp_path):
    from tests.test_c14_protocol_hardening import _c14_precedent_pipeline

    _, validator, _, judgment, validation = _c14_precedent_pipeline(tmp_path)
    mesh = validator.mesh
    result = mesh.get_result(validation.assignment_id)
    mesh._vote_registry.replace(
        mesh.assigner_id,
        Ed25519PrivateKey.generate().public_key(),
        roles={"assigner"},
    )

    synapse = validator._result_to_synapse(judgment, result)
    assert synapse.assignment_id == validation.assignment_id


def _c48_votes_under_late_live_assigner(
    mesh, evidence_mode="single_operator_dev", rogue_key=None
):
    """Forge an assignment signed by an assigner registered after construction.

    The rogue grant goes through the public ``mesh.vote_registry`` (live by
    design, see C28); genuine voters then sign envelopes bound to the forgery.
    """
    import time
    import uuid

    from constitutional_swarm.mesh.vote_envelope import (
        sign_assignment,
        sign_vote_envelope,
        signed_assignment_digest,
    )

    assignment = mesh.request_validation("a", "late assigner content", "artifact-late")
    if rogue_key is None:
        rogue_key = Ed25519PrivateKey.generate()
        mesh.vote_registry.register(
            "late-assigner", rogue_key.public_key(), roles={"assigner"}
        )
    original = assignment.signed_assignment
    forged = sign_assignment(
        rogue_key,
        task_id=original.task_id,
        assignment_id=original.assignment_id,
        assigner_id="late-assigner",
        producer_id=original.producer_id,
        artifact_id=original.artifact_id,
        content_hash=original.content_hash,
        constitutional_hash=original.constitutional_hash,
        assigned_peers=original.assigned_peers,
        quorum=original.quorum,
        selection_seed=original.selection_seed,
        issued_at=original.issued_at,
    )
    envelopes = tuple(
        sign_vote_envelope(
            mesh._agent_vote_private_keys[peer],
            voter_id=peer,
            task_id=assignment.task_id,
            assignment_id=assignment.assignment_id,
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            decision="approved",
            reason="ok",
            nonce=uuid.uuid4().hex,
            issued_at=time.time(),
            assigned_peers=assignment.peers,
            quorum=assignment.quorum,
            evidence_mode=evidence_mode,
            assignment_digest=signed_assignment_digest(forged),
        )
        for peer in assignment.peers
    )
    bindings = {
        "task_id": assignment.task_id,
        "assignment_id": assignment.assignment_id,
        "producer_id": assignment.producer_id,
        "artifact_id": assignment.artifact_id,
        "content_hash": assignment.content_hash,
        "constitutional_hash": assignment.constitutional_hash,
        "require_independent": False,
    }
    return forged, envelopes, bindings


def test_c48_signer_registered_into_live_registry_cannot_authorize_assignment_votes():
    from constitutional_swarm.mesh.vote_envelope import verify_assignment_vote_envelopes

    mesh = _c48_mesh()
    forged, envelopes, bindings = _c48_votes_under_late_live_assigner(mesh)

    # Control: trusting the live registry for the assigner role accepts the forgery.
    assert verify_assignment_vote_envelopes(
        forged, envelopes, mesh.vote_registry, **bindings
    )
    # Every mesh-backed verifier pins the frozen root instead, which rejects it.
    with pytest.raises(ValueError):
        verify_assignment_vote_envelopes(
            forged,
            envelopes,
            mesh.vote_registry,
            assigner_trust_root=mesh.assigner_trust_root,
            **bindings,
        )
    with pytest.raises(ValueError, match="pinned assigner"):
        verify_assignment_vote_envelopes(
            forged,
            envelopes,
            mesh.vote_registry,
            assigner_trust_root=mesh.assigner_trust_root,
            expected_assigner_id=mesh.assigner_id,
            expected_assigner_key_id=mesh.assigner_key_id,
            **bindings,
        )
    assert mesh.assigner_trust_root.public_key_for_identity("late-assigner") is None


def test_c48_cascade_with_mesh_pins_mesh_trust_root(monkeypatch):
    from acgs_lite import Constitution
    from constitutional_swarm.bittensor import cascade as cascade_mod
    from constitutional_swarm.bittensor.cascade import (
        CascadeStage,
        PrecedentCandidate,
        PrecedentCascade,
    )

    mesh = _c48_mesh()
    candidate = PrecedentCandidate(
        candidate_id="c48-candidate",
        judgment_text="Publish governance reasons with privacy safeguards",
        reasoning_text="Accountability and privacy are jointly protected",
        domain="governance",
        miner_uid="a",
        constitutional_hash=mesh.constitutional_hash,
        stage_results=(),
        current_stage=CascadeStage.MESH_VALIDATION,
        alive=True,
    )
    result = mesh.full_validation(
        "a", candidate.judgment_text, candidate.candidate_id, task_id=candidate.candidate_id
    )
    mesh.vote_registry.register(
        "late-assigner", Ed25519PrivateKey.generate().public_key(), roles={"assigner"}
    )
    cascade = PrecedentCascade(
        Constitution.default(),
        mesh,
        vote_registry=mesh.vote_registry,
        min_consensus_miners=3,
        consensus_threshold=0.6,
    )
    seen = []
    real = cascade_mod.verify_assignment_vote_envelopes

    def spy(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(cascade_mod, "verify_assignment_vote_envelopes", spy)
    cascade._valid_mesh_result(candidate, result)

    assert len(seen) == 1
    assert seen[0]["assigner_trust_root"] is mesh.assigner_trust_root
    assert seen[0]["expected_assigner_id"] == mesh.assigner_id
    assert seen[0]["expected_assigner_key_id"] == mesh.assigner_key_id


# -- opt-dup-1 (core part) --------------------------------------------------


@pytest.mark.parametrize(
    "transform",
    [str.upper, lambda value: f" {value}", lambda value: f"{value}\n"],
    ids=["uppercase", "leading-space", "trailing-newline"],
)
def test_c48_mesh_key_coercion_rejects_non_canonical_hex(transform):
    from constitutional_swarm.mesh import ConstitutionalMesh
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    public_hex = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    private_hex = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()

    with pytest.raises(ValueError, match="canonical lowercase hex"):
        ConstitutionalMesh._coerce_public_key(transform(public_hex))
    with pytest.raises(ValueError, match="canonical lowercase hex"):
        ConstitutionalMesh._coerce_private_key(transform(private_hex))
    mesh = _c48_mesh()
    with pytest.raises(ValueError, match="canonical lowercase hex"):
        mesh.register_remote_agent("remote-x", vote_public_key=transform(public_hex))


def test_c48_mesh_uses_shared_content_hash():
    from constitutional_swarm.mesh import core
    from constitutional_swarm.mesh.vote_envelope import content_hash

    mesh = _c48_mesh()
    assignment = mesh.request_validation("a", "shared hash content", "artifact-hash")
    assert assignment.content_hash == content_hash("shared hash content")
    assert core.content_hash is content_hash


# -- remote vote request nonce admission ------------------------------------


def test_c48_bad_signature_request_never_records_its_nonce():
    from constitutional_swarm.mesh import ConstitutionalMesh

    mesh = _c48_mesh()
    request = _c48_signed_request(mesh, nonce="bad-sig", timestamp=1_000.0)
    forged = dataclasses.replace(request, request_signature="00" * 64)
    cache: OrderedDict[str, float] = OrderedDict()

    with pytest.raises(ValueError, match="signature is invalid"):
        ConstitutionalMesh.verify_remote_vote_request(forged, nonce_cache=cache, now=1_000.0)
    assert cache == OrderedDict()
    # The genuine request is still admissible: the forged attempt burned nothing.
    assert ConstitutionalMesh.verify_remote_vote_request(
        request, nonce_cache=cache, now=1_000.0
    )
    assert list(cache) == ["bad-sig"]


def test_c48_replayed_nonce_is_rejected_before_any_cache_change():
    from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteReplayError

    mesh = _c48_mesh()
    request = _c48_signed_request(mesh, nonce="replayed", timestamp=1_000.0)
    cache: OrderedDict[str, float] = OrderedDict()
    ConstitutionalMesh.verify_remote_vote_request(request, nonce_cache=cache, now=1_000.0)
    snapshot = OrderedDict(cache)

    with pytest.raises(RemoteVoteReplayError, match="already used"):
        ConstitutionalMesh.verify_remote_vote_request(request, nonce_cache=cache, now=1_010.0)
    assert cache == snapshot


def test_c48_unauthenticated_request_cannot_probe_nonce_cache():
    from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteReplayError

    mesh = _c48_mesh()
    request = _c48_signed_request(mesh, nonce="probed", timestamp=1_000.0)
    cache: OrderedDict[str, float] = OrderedDict()
    ConstitutionalMesh.verify_remote_vote_request(request, nonce_cache=cache, now=1_000.0)
    snapshot = OrderedDict(cache)
    forged = dataclasses.replace(request, request_signature="00" * 64)

    # A cached nonce is invisible to a caller without a valid signature.
    with pytest.raises(ValueError, match="signature is invalid") as excinfo:
        ConstitutionalMesh.verify_remote_vote_request(forged, nonce_cache=cache, now=1_010.0)
    assert not isinstance(excinfo.value, RemoteVoteReplayError)
    assert cache == snapshot


def test_c48_future_dated_request_cannot_be_replayed_after_receipt_window():
    from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteReplayError

    window = 300.0
    mesh = _c48_mesh()
    # Signed with the maximum accepted forward skew.
    request = _c48_signed_request(mesh, nonce="future-dated", timestamp=1_000.0 + window)
    cache: OrderedDict[str, float] = OrderedDict()
    ConstitutionalMesh.verify_remote_vote_request(
        request, nonce_cache=cache, replay_window_seconds=window, now=1_000.0
    )

    # The timestamp is still inside the window, so the nonce must still be held.
    with pytest.raises(RemoteVoteReplayError, match="already used"):
        ConstitutionalMesh.verify_remote_vote_request(
            request,
            nonce_cache=cache,
            replay_window_seconds=window,
            now=1_000.0 + window + 1.0,
        )


def test_c48_nonce_sweep_is_complete_not_head_only():
    from constitutional_swarm.mesh import ConstitutionalMesh

    window = 300.0
    mesh = _c48_mesh()
    late = _c48_signed_request(mesh, nonce="late", timestamp=1_000.0 + window)
    early = _c48_signed_request(mesh, nonce="early", timestamp=1_000.0 - window)
    probe = _c48_signed_request(mesh, nonce="probe", timestamp=1_000.0 + window)
    cache: OrderedDict[str, float] = OrderedDict()
    for request in (late, early):
        ConstitutionalMesh.verify_remote_vote_request(
            request, nonce_cache=cache, replay_window_seconds=window, now=1_000.0
        )

    ConstitutionalMesh.verify_remote_vote_request(
        probe, nonce_cache=cache, replay_window_seconds=window, now=1_000.0 + window + 1.0
    )
    # "early" expired behind the still-live head entry and must be swept anyway.
    assert "early" not in cache
    assert "late" in cache and "probe" in cache
    assert cache["late"] == 1_000.0 + 2 * window


# -- opt-perf-1 -------------------------------------------------------------


def test_c48_peer_assignment_carries_its_signed_assignment_digest():
    from constitutional_swarm.mesh.vote_envelope import signed_assignment_digest

    mesh = _c48_mesh()
    assignment = mesh.request_validation("a", "digest content", "artifact-digest")
    expected = signed_assignment_digest(assignment.signed_assignment)

    assert assignment.signed_assignment_digest == expected
    recovered = dataclasses.replace(assignment, is_recovered=True, content="")
    assert recovered.signed_assignment_digest == expected
    assert dataclasses.replace(assignment, signed_assignment=None).signed_assignment_digest == ""


def test_c48_submitted_envelope_is_verified_once_without_digest_recompute(monkeypatch):
    from constitutional_swarm.mesh import core

    mesh = _c48_mesh()
    assignment = mesh.request_validation("a", "single verify content", "artifact-once")
    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id, assignment.peers[0], approved=True, reason="ok"
    )
    verify_calls = []
    digest_calls = []
    real_verify = core.verify_vote_envelope
    real_digest = core.signed_assignment_digest

    def counting_verify(*args, **kwargs):
        verify_calls.append(1)
        return real_verify(*args, **kwargs)

    def counting_digest(*args, **kwargs):
        digest_calls.append(1)
        return real_digest(*args, **kwargs)

    monkeypatch.setattr(core, "verify_vote_envelope", counting_verify)
    monkeypatch.setattr(core, "signed_assignment_digest", counting_digest)
    vote = mesh.submit_vote_envelope(envelope)

    assert vote.voter_id == envelope.voter_id
    assert len(verify_calls) == 1
    assert digest_calls == []
    assert mesh._vote_envelopes[assignment.assignment_id][0].signature == envelope.signature
    assert envelope.signature not in mesh._signed_envelopes_by_signature


def test_c48_submit_vote_envelope_still_rejects_tampered_duplicate_and_halted():
    from constitutional_swarm.mesh import DuplicateVoteError, MeshHaltedError

    mesh = _c48_mesh()
    assignment = mesh.request_validation("a", "envelope guards", "artifact-guards")
    voter = assignment.peers[0]
    envelope = mesh.sign_vote_envelope(
        assignment.assignment_id, voter, approved=True, reason="ok"
    )
    with pytest.raises(ValueError):
        mesh.submit_vote_envelope(dataclasses.replace(envelope, reason="tampered"))
    assert mesh._votes[assignment.assignment_id] == []

    mesh.submit_vote_envelope(envelope)
    with pytest.raises(DuplicateVoteError):
        mesh.submit_vote_envelope(envelope)

    second = mesh.sign_vote_envelope(
        assignment.assignment_id, assignment.peers[1], approved=True, reason="ok"
    )
    mesh.halt()
    with pytest.raises(MeshHaltedError):
        mesh.submit_vote_envelope(second)
    assert len(mesh._votes[assignment.assignment_id]) == 1


# -- opt-perf-2 -------------------------------------------------------------


class _IterationCountingDict(dict):
    iterations = 0

    def values(self):
        type(self).iterations += 1
        return super().values()

    def items(self):
        type(self).iterations += 1
        return super().items()

    def __iter__(self):
        type(self).iterations += 1
        return super().__iter__()


def test_c48_request_validation_does_not_scan_assignments_without_rotation():
    mesh = _c48_mesh()
    for index in range(5):
        mesh.request_validation("a", f"scan content {index}", f"artifact-scan-{index}")
    counting = _IterationCountingDict(mesh._assignments)
    _IterationCountingDict.iterations = 0
    mesh._assignments = counting

    mesh.request_validation("a", "no scan content", "artifact-no-scan")
    assert _IterationCountingDict.iterations == 0
    assert mesh.summary()["pending"] == 6


def test_c48_pending_counter_tracks_settle_rotation_and_capacity():
    from constitutional_swarm.mesh import MeshCapacityError

    mesh = _c48_mesh(max_pending_assignments=3)

    def scanned_pending():
        return sum(not item.is_recovered for item in mesh._assignments.values())

    settled = mesh.full_validation("a", "settled content", "artifact-settled")
    assert settled.settled
    first = mesh.request_validation("a", "pending one", "artifact-p1")
    mesh.request_validation("a", "pending two", "artifact-p2")
    mesh.request_validation("a", "pending three", "artifact-p3")
    assert mesh._pending_assignment_count_locked() == scanned_pending() == 3
    with pytest.raises(MeshCapacityError):
        mesh.request_validation("a", "over capacity", "artifact-over")

    mesh.rotate_constitution(_c48_rotated_constitution())
    fresh = mesh.request_validation("a", "after rotation", "artifact-rotated")
    assert first.assignment_id not in mesh._assignments
    assert settled.assignment_id in mesh._assignments
    assert mesh._pending_assignment_count_locked() == scanned_pending() == 1
    assert mesh.summary()["pending"] == 1
    assert fresh.assignment_id in mesh._assignments


def test_c48_pending_counter_survives_eviction_of_settled_results():
    mesh = _c48_mesh(max_settled_results=1)
    for index in range(3):
        mesh.full_validation("a", f"evicted content {index}", f"artifact-evict-{index}")
    mesh.request_validation("a", "still pending", "artifact-still")

    assert mesh._pending_assignment_count_locked() == 1
    assert sum(not item.is_recovered for item in mesh._assignments.values()) == 1


# -- opt-perf-3 / governance-19 ---------------------------------------------


def _c48_flaky_sqlite_store(path):
    from constitutional_swarm.settlement_store import SQLiteSettlementStore

    class _FlakyStore(SQLiteSettlementStore):
        fail_appends = True
        load_all_calls = 0

        def append(self, record):
            if self.fail_appends:
                raise OSError("simulated append outage")
            super().append(record)

        def load_all(self):
            type(self).load_all_calls += 1
            return super().load_all()

    return _FlakyStore(path)


def test_c48_reconcile_loads_durable_store_once_per_pass(tmp_path):
    from constitutional_swarm.mesh import SettlementPersistenceError

    store = _c48_flaky_sqlite_store(tmp_path / "settlements.db")
    writer = _c48_mesh(settlement_store=store, auto_reconcile=False)
    for index in range(3):
        with pytest.raises(SettlementPersistenceError):
            writer.full_validation("a", f"outage content {index}", f"artifact-outage-{index}")
    assert store.pending_count() == 3

    store.fail_appends = False
    type(store).load_all_calls = 0
    report = writer.reconcile_pending_settlements()

    assert report.settled == 3 and report.failed == 0
    assert type(store).load_all_calls == 1
    assert store.pending_count() == 0
    assert len(store.load_all()) == 3


def test_c48_reconcile_still_rejects_duplicate_durable_history(tmp_path):
    from constitutional_swarm.mesh import SettlementPersistenceError
    from constitutional_swarm.settlement_store import JSONLSettlementStore

    class _DuplicatingStore(JSONLSettlementStore):
        fail_appends = True

        def append(self, record):
            if self.fail_appends:
                raise OSError("simulated append outage")
            super().append(record)

        def load_all(self):
            records = super().load_all()
            return records + records

    store = _DuplicatingStore(tmp_path / "settlements.jsonl")
    writer = _c48_mesh(settlement_store=store, auto_reconcile=False)
    with pytest.raises(SettlementPersistenceError):
        writer.full_validation("a", "duplicate content", "artifact-duplicate")
    store.fail_appends = False
    # Commit the Phase-2 record directly so the next pass sees it twice.
    pending = store.load_pending()[0]
    writer._persist_settlement_record(
        writer._build_settlement_record(
            dataclasses.replace(
                writer._deserialize_assignment(pending.assignment), is_recovered=True
            ),
            writer._deserialize_result(pending.result),
        ),
        votes=list(writer._deserialize_result(pending.result).vote_envelopes),
    )

    report = writer.reconcile_pending_settlements()
    assert report.failed == 1
    assert "appears more than once" in report.errors[0]


def test_c48_settlement_write_does_not_rebuild_committed_receipt_index(
    tmp_path, monkeypatch
):
    from constitutional_swarm import settlement_evidence
    from constitutional_swarm.settlement_store import SQLiteSettlementStore

    calls = []
    real_index = settlement_evidence.committed_receipt_index

    def counting_index(store):
        calls.append(1)
        return real_index(store)

    monkeypatch.setattr(settlement_evidence, "committed_receipt_index", counting_index)
    mesh = _c48_mesh(settlement_store=SQLiteSettlementStore(tmp_path / "s.db"))
    result = mesh.full_validation("a", "indexed write", "artifact-indexed")

    assert result.settled
    assert calls == []
    stored = mesh._settlement_store.get(result.assignment_id)
    assert stored is not None and stored.receipt_digest
    assert mesh._receipt_bundle_path(result.assignment_id).exists()


# -- Rework round 1 ---------------------------------------------------------


def _c48_rotate_like_validator(mesh):
    """Rebuild the mesh the way ConstitutionalValidator.rotate_constitution does."""
    from constitutional_swarm.mesh import ConstitutionalMesh

    rotated = ConstitutionalMesh(
        _c48_rotated_constitution(),
        seed=49,
        vote_registry=mesh.vote_registry,
        assigner_private_key=mesh._assigner_private_key,
        assigner_id=mesh.assigner_id,
        evidence_mode="single_operator_dev",
    )
    for agent_id, private_key in mesh._agent_vote_private_keys.items():
        rotated.register_local_signer(agent_id, vote_private_key=private_key)
    return rotated


def _c48_external_receipt_verify(forged, envelopes, bindings, trusted_signers):
    from constitutional_swarm.governance_receipts import (
        _parse_trust_grants,
        _verify_bound_vote_envelopes,
    )
    from constitutional_swarm.mesh.vote_envelope import (
        signed_assignment_to_dict,
        vote_envelope_to_dict,
    )

    params = dict(bindings)
    params.pop("require_independent")
    return _verify_bound_vote_envelopes(
        signed_assignment_to_dict(forged),
        [vote_envelope_to_dict(item) for item in envelopes],
        _parse_trust_grants(trusted_signers),
        require_independent_votes=False,
        **params,
    )


def test_c48_rotated_mesh_does_not_inherit_late_live_assigner_grant():
    mesh = _c48_mesh()
    rogue_key = Ed25519PrivateKey.generate()
    mesh.vote_registry.register("late-assigner", rogue_key.public_key(), roles={"assigner"})

    rotated = _c48_rotate_like_validator(mesh)

    assert rotated.assigner_trust_root.public_key_for_identity("late-assigner") is None
    assert [
        grant["identity_id"]
        for grant in rotated.assigner_trust_root.trust_grants(role="assigner").values()
    ] == [rotated.assigner_id]
    exported = rotated.receipt_trust_registry()
    assert all(grant["identity_id"] != "late-assigner" for grant in exported.values())
    assert [
        grant["identity_id"] for grant in exported.values() if "assigner" in grant["roles"]
    ] == [rotated.assigner_id]

    forged, envelopes, bindings = _c48_votes_under_late_live_assigner(
        rotated, rogue_key=rogue_key
    )
    # An external verifier pinning nothing but the exported registry rejects it ...
    with pytest.raises(ValueError):
        _c48_external_receipt_verify(forged, envelopes, bindings, exported)
    # ... while the same verifier would accept it had the rogue grant been exported.
    from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key

    with_rogue = dict(exported)
    with_rogue[key_id_for_public_key(rogue_key.public_key())] = {
        "identity_id": "late-assigner",
        "public_key_hex": rogue_key.public_key().public_bytes_raw().hex(),
        "roles": ["assigner"],
    }
    assert _c48_external_receipt_verify(forged, envelopes, bindings, with_rogue)


def test_c48_validator_rotation_does_not_trust_late_live_assigner(tmp_path):
    from tests.test_c14_protocol_hardening import _c14_precedent_pipeline

    _, validator, _, _, _ = _c14_precedent_pipeline(tmp_path)
    validator.mesh.vote_registry.register(
        "late-assigner", Ed25519PrivateKey.generate().public_key(), roles={"assigner"}
    )
    validator.rotate_constitution(_c48_rotated_constitution())
    mesh = validator.mesh

    assert mesh.constitutional_hash == _c48_rotated_constitution().hash
    assert mesh.assigner_trust_root.public_key_for_identity("late-assigner") is None
    assert all(
        grant["identity_id"] != "late-assigner"
        for grant in mesh.receipt_trust_registry().values()
    )


def test_c48_mesh_nonce_is_still_held_at_exact_window_edge():
    from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteReplayError

    window = 300.0
    mesh = _c48_mesh()
    request = _c48_signed_request(mesh, nonce="edge", timestamp=1_000.0)
    cache: OrderedDict[str, float] = OrderedDict()
    ConstitutionalMesh.verify_remote_vote_request(
        request, nonce_cache=cache, replay_window_seconds=window, now=1_000.0
    )

    # abs(now - timestamp) == W is still accepted, so the nonce must still block.
    with pytest.raises(RemoteVoteReplayError, match="already used"):
        ConstitutionalMesh.verify_remote_vote_request(
            request, nonce_cache=cache, replay_window_seconds=window, now=1_000.0 + window
        )


def test_c48_remote_peer_nonce_is_still_held_at_exact_window_edge():
    from constitutional_swarm.mesh import RemoteVoteReplayError
    from tests.test_remote_vote_envelope import _build_signed_request

    _, peer, request = _build_signed_request(nonce="peer-edge", timestamp=1_000.0)
    peer._clock = lambda: 1_000.0
    peer.handle_vote_request(request)

    peer._clock = lambda: 1_300.0  # exactly timestamp + replay window
    with pytest.raises(RemoteVoteReplayError, match="already used"):
        peer.handle_vote_request(request)


def _c48_independent_cascade_result(mesh, *, assigner_key, assigner_id):
    """A fully coherent settled result whose assignment is signed by ``assigner_key``."""
    import time

    from constitutional_swarm.bittensor.cascade import CascadeStage, PrecedentCandidate
    from constitutional_swarm.bittensor.synapses import judgment_content_hash
    from constitutional_swarm.mesh import MeshProof, MeshResult
    from constitutional_swarm.mesh.vote_envelope import (
        compute_vote_envelope_root,
        sign_assignment,
        sign_vote_envelope,
        signed_assignment_digest,
        vote_envelope_hash,
    )

    candidate = PrecedentCandidate(
        candidate_id="c48-cascade-candidate",
        judgment_text="Publish governance reasons with privacy safeguards",
        reasoning_text="Accountability and privacy are jointly protected",
        domain="governance",
        miner_uid="a",
        constitutional_hash=mesh.constitutional_hash,
        stage_results=(),
        current_stage=CascadeStage.MESH_VALIDATION,
        alive=True,
    )
    peers = ("b", "c", "d")
    payload_hash = judgment_content_hash(candidate.judgment_text)
    common = {
        "task_id": candidate.candidate_id,
        "assignment_id": "c48-cascade-assignment",
        "producer_id": candidate.miner_uid,
        "artifact_id": candidate.candidate_id,
        "content_hash": payload_hash,
        "constitutional_hash": mesh.constitutional_hash,
    }
    signed_assignment = sign_assignment(
        assigner_key,
        assigner_id=assigner_id,
        assigned_peers=peers,
        quorum=3,
        selection_seed="c48-cascade-selection",
        issued_at=1_800_000_000.0,
        **common,
    )
    envelopes = tuple(
        sign_vote_envelope(
            mesh._agent_vote_private_keys[peer],
            voter_id=peer,
            decision="approved",
            reason="independent approval",
            nonce=f"nonce-{peer}",
            issued_at=1_800_000_000.0,
            assigned_peers=peers,
            quorum=3,
            evidence_mode="independent",
            assignment_digest=signed_assignment_digest(signed_assignment),
            **common,
        )
        for peer in peers
    )
    ordered = tuple(sorted(envelopes, key=lambda item: (item.voter_id, item.key_id)))
    proof = MeshProof(
        assignment_id=common["assignment_id"],
        content_hash=payload_hash,
        constitutional_hash=mesh.constitutional_hash,
        vote_hashes=tuple(vote_envelope_hash(item) for item in ordered),
        root_hash=compute_vote_envelope_root(accepted=True, envelopes=ordered, **common),
        accepted=True,
        timestamp=time.time(),
        task_id=candidate.candidate_id,
        producer_id=candidate.miner_uid,
        artifact_id=candidate.candidate_id,
        protocol_version=2,
    )
    result = MeshResult(
        assignment_id=common["assignment_id"],
        accepted=True,
        votes_for=3,
        votes_against=0,
        quorum_met=True,
        pending_votes=0,
        constitutional_hash=mesh.constitutional_hash,
        proof=proof,
        vote_envelopes=envelopes,
        settled=True,
        settled_at=time.time(),
        signed_assignment=signed_assignment,
    )
    return candidate, result


def test_c48_cascade_rejects_result_signed_by_late_live_assigner():
    from acgs_lite import Constitution
    from constitutional_swarm.bittensor.cascade import PrecedentCascade

    mesh = _c48_mesh()
    rogue_key = Ed25519PrivateKey.generate()
    mesh.vote_registry.register("late-assigner", rogue_key.public_key(), roles={"assigner"})

    def cascade(with_mesh):
        return PrecedentCascade(
            Constitution.default(),
            mesh if with_mesh else None,
            vote_registry=mesh.vote_registry,
            min_consensus_miners=3,
            consensus_threshold=0.6,
        )

    genuine = _c48_independent_cascade_result(
        mesh, assigner_key=mesh._assigner_private_key, assigner_id=mesh.assigner_id
    )
    forged = _c48_independent_cascade_result(
        mesh, assigner_key=rogue_key, assigner_id="late-assigner"
    )

    assert cascade(with_mesh=True)._valid_mesh_result(*genuine) is True
    assert cascade(with_mesh=True)._valid_mesh_result(*forged) is False
    # Control: only the mesh pin blocks it; the caller-supplied snapshot trusts it.
    assert cascade(with_mesh=False)._valid_mesh_result(*forged) is True
