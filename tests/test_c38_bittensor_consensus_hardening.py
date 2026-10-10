"""C38 regressions: Bittensor consensus (NMC) and rule codification hardening.

Each test is phrased as an invalid-input / attack regression: the hostile input
must be rejected, and no state may change when it is.
"""

from __future__ import annotations

import dataclasses

import pytest
import yaml

from constitutional_swarm.bittensor import nmc_protocol as nmc_mod
from constitutional_swarm.bittensor import rule_codifier as rc_mod
from constitutional_swarm.bittensor import threshold_updater as tu_mod
from constitutional_swarm.bittensor.nmc_protocol import (
    NMCCoordinator,
    NMCSession,
    SynthesisMethod,
    compute_commitment_hash,
)
from constitutional_swarm.bittensor.precedent_backed_codifier import PrecedentBackedCodifier
from constitutional_swarm.bittensor.rule_codifier import (
    RuleCandidateStatus,
    RuleCodifier,
    _append_rule_to_yaml,
    constitution_hash,
)
from constitutional_swarm.bittensor.threshold_updater import (
    BayesianThresholdUpdater,
    DimensionEvidence,
)
from tests.test_c14_protocol_hardening import (
    c14_precedent_signed_record,
    c14_precedent_test_store,
)

_BASE_YAML = "name: c38\nrules:\n  - id: R1\n    text: base rule\nmeta:\n  owner: x\n"
_BASE_HASH = constitution_hash(_BASE_YAML)
_GOVERNOR = "governor-1"
_DIMS = ("safety", "security", "privacy", "fairness", "reliability", "transparency", "efficiency")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _commit(session: NMCSession, miner_uid: str, judgment: str, nonce: str) -> str:
    return compute_commitment_hash(
        judgment,
        nonce,
        session_id=session.session_id,
        case_id=session.case_id,
        miner_uid=miner_uid,
    )


def _record(case_id: str, *, constitutional_hash: str = _BASE_HASH, **kwargs):  # type: ignore[no-untyped-def]
    kwargs.setdefault("votes_for", 5)
    kwargs.setdefault("votes_against", 0)
    kwargs.setdefault("impact_vector", dict.fromkeys(_DIMS, 0.1) | {"security": 0.9})
    kwargs.setdefault("ambiguous_dimensions", ("security",))
    return c14_precedent_signed_record(
        case_id=case_id,
        task_id=f"task-{case_id}",
        constitutional_hash=constitutional_hash,
        **kwargs,
    )


def _approved_codifier(governors=(_GOVERNOR,)):  # type: ignore[no-untyped-def]
    store = c14_precedent_test_store(_BASE_HASH)
    canonical = store.admit(_record("codify-1"))
    codifier = RuleCodifier(
        _BASE_HASH,
        precedent_store=store,
        min_cluster_size=1,
        min_validator_agreement=0.5,
        governors=governors,
    )
    [candidate] = codifier.propose_rules(codifier.find_clusters([canonical]))
    return codifier, candidate


# ---------------------------------------------------------------------------
# bittensor-rest-3: commitments bound to session, case and miner identity
# ---------------------------------------------------------------------------


def test_c38_copied_commitment_hash_is_rejected_at_commit_time() -> None:
    session = NMCSession("C38-copy", required_miners={"A", "B", "C"})
    victim_hash = _commit(session, "A", "allow", "nonce-a")
    session.accept_commitment("A", victim_hash)

    with pytest.raises(ValueError, match="duplicate commitment"):
        session.accept_commitment("B", victim_hash)
    assert session.committed_miners == {"A"}


def test_c38_copier_cannot_replay_victims_reveal_under_own_identity() -> None:
    """PoC from the finding: B copies A's (judgment, nonce) to flip a 1-1 split."""
    session = NMCSession("C38-replay", required_miners={"A", "B", "C"})
    session.accept_commitment("A", _commit(session, "A", "allow", "nonce-a"))
    # B commits a hash it can open with A's material under its OWN identity:
    # with identity binding, A's (judgment, nonce) cannot open B's commitment.
    session.accept_commitment("B", _commit(session, "B", "deny", "nonce-b"))
    session.accept_commitment("C", _commit(session, "C", "deny", "nonce-c"))
    session.accept_reveal("A", "allow", "nonce-a")
    with pytest.raises(ValueError, match="does not match commitment"):
        session.accept_reveal("B", "allow", "nonce-a")
    assert session.revealed_miners == {"A"}


def test_c38_commitment_from_another_session_cannot_be_replayed() -> None:
    first = NMCSession("C38-case", required_miners={"A", "B"})
    second = NMCSession("C38-case", required_miners={"A", "B"})
    stale = _commit(first, "A", "allow", "nonce-a")

    second.accept_commitment("A", stale)
    second.accept_commitment("B", _commit(second, "B", "deny", "nonce-b"))
    with pytest.raises(ValueError, match="does not match commitment"):
        second.accept_reveal("A", "allow", "nonce-a")


def test_c38_commitment_preimage_binds_every_context_field() -> None:
    base = {"session_id": "s", "case_id": "c", "miner_uid": "m"}
    reference = compute_commitment_hash("allow", "n", **base)
    for field_name in base:
        changed = dict(base, **{field_name: base[field_name] + "x"})
        assert compute_commitment_hash("allow", "n", **changed) != reference
    # Typed length-prefixed framing: shifting bytes between fields changes the hash.
    assert compute_commitment_hash("allow", "n", session_id="sc", case_id="", miner_uid="m") != (
        compute_commitment_hash("allow", "n", session_id="s", case_id="c", miner_uid="m")
    )


@pytest.mark.parametrize("bad_hash", ["", "abc", "Z" * 64, "A" * 64, 123])
def test_c38_malformed_commitment_hash_is_rejected(bad_hash: object) -> None:
    session = NMCSession("C38-malformed", required_miners={"A", "B"})
    with pytest.raises((TypeError, ValueError)):
        session.accept_commitment("A", bad_hash)  # type: ignore[arg-type]
    assert session.committed_miners == set()


# ---------------------------------------------------------------------------
# bittensor-rest-4: roster is mandatory
# ---------------------------------------------------------------------------


def test_c38_session_without_roster_is_rejected() -> None:
    with pytest.raises(TypeError):
        NMCSession("C38-open")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="required_miners"):
        NMCSession("C38-empty", required_miners=set())
    with pytest.raises(ValueError, match="required_miners"):
        NMCSession("C38-blank", required_miners={""})


def test_c38_coordinator_session_without_roster_is_rejected() -> None:
    coordinator = NMCCoordinator()
    with pytest.raises(TypeError):
        coordinator.create_session("C38-open")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="required_miners"):
        coordinator.create_session("C38-empty", required_miners=set())
    assert coordinator.get_session("C38-empty") is None


def test_c38_self_named_sybils_cannot_join_rostered_session() -> None:
    """PoC from the finding: 5 self-named sybils outvote 1 honest miner."""
    session = NMCSession("C38-sybil", required_miners={"honest"}, min_reveals=1)
    for index in range(5):
        sybil = f"sybil-{index}"
        with pytest.raises(ValueError, match="not required"):
            session.accept_commitment(sybil, _commit(session, sybil, "allow", f"n{index}"))
    session.accept_commitment("honest", _commit(session, "honest", "deny", "nh"))
    session.accept_reveal("honest", "deny", "nh")
    assert session.synthesize().judgment_text == "deny"


# ---------------------------------------------------------------------------
# bittensor-rest-13: coordinator forwarding, `is None` defaults, idempotency
# ---------------------------------------------------------------------------


def test_c38_coordinator_forwards_trusted_miner_weights() -> None:
    coordinator = NMCCoordinator()
    session = coordinator.create_session(
        "C38-weights",
        required_miners={"m1", "m2", "m3"},
        miner_weights={"m1": 5.0, "m2": 1.0, "m3": 1.0},
    )
    votes = {"m1": "allow", "m2": "deny", "m3": "deny"}
    for miner, judgment in votes.items():
        session.accept_commitment(miner, _commit(session, miner, judgment, f"n-{miner}"))
    for miner, judgment in votes.items():
        session.accept_reveal(miner, judgment, f"n-{miner}")

    consensus = session.synthesize(SynthesisMethod.WEIGHTED_VOTE)

    assert consensus.judgment_text == "allow"
    assert consensus.confidence == pytest.approx(5 / 7)


@pytest.mark.parametrize(
    "overrides",
    [{"min_reveals": 0}, {"deadline_seconds": 0}, {"deadline_seconds": float("nan")}],
)
def test_c38_coordinator_rejects_falsy_overrides_instead_of_defaulting(overrides) -> None:  # type: ignore[no-untyped-def]
    coordinator = NMCCoordinator()
    with pytest.raises(ValueError):
        coordinator.create_session("C38-falsy", required_miners={"m1", "m2"}, **overrides)
    assert coordinator.get_session("C38-falsy") is None


def _synthesizable_session() -> NMCSession:
    session = NMCSession(
        "C38-resynth",
        required_miners={"m1", "m2", "m3"},
        miner_weights={"m1": 0.1, "m2": 0.1, "m3": 9.0},
    )
    votes = {"m1": "allow", "m2": "allow", "m3": "deny"}
    for miner, judgment in votes.items():
        session.accept_commitment(miner, _commit(session, miner, judgment, f"n-{miner}"))
    for miner, judgment in votes.items():
        session.accept_reveal(miner, judgment, f"n-{miner}")
    return session


def test_c38_synthesize_cannot_be_rerun_with_another_method() -> None:
    session = _synthesizable_session()
    first = session.synthesize(SynthesisMethod.MAJORITY_VOTE)

    with pytest.raises(ValueError, match="already synthesized"):
        session.synthesize(SynthesisMethod.WEIGHTED_VOTE)
    assert session.consensus is first
    assert session.synthesize(SynthesisMethod.MAJORITY_VOTE) is first


# ---------------------------------------------------------------------------
# bittensor-rest-9: governor separation of duty and base-hash binding
# ---------------------------------------------------------------------------


def test_c38_approve_requires_a_rostered_governor() -> None:
    codifier, candidate = _approved_codifier()
    with pytest.raises(TypeError):
        codifier.approve(candidate.candidate_id)  # type: ignore[call-arg]
    with pytest.raises(PermissionError, match="governor"):
        codifier.approve(candidate.candidate_id, governor="intruder")
    assert codifier.pending_candidates[0].status == RuleCandidateStatus.PENDING


def test_c38_empty_governor_roster_fails_closed() -> None:
    codifier, candidate = _approved_codifier(governors=())
    with pytest.raises(PermissionError, match="governor"):
        codifier.approve(candidate.candidate_id, governor=_GOVERNOR)


def test_c38_proposer_cannot_be_a_governor() -> None:
    store = c14_precedent_test_store(_BASE_HASH)
    with pytest.raises(ValueError, match="proposer"):
        RuleCodifier(
            _BASE_HASH,
            precedent_store=store,
            governors={"codifier-bot", _GOVERNOR},
            proposer_id="codifier-bot",
        )


def test_c38_activate_requires_rostered_governor() -> None:
    codifier, candidate = _approved_codifier()
    codifier.approve(candidate.candidate_id, governor=_GOVERNOR)
    with pytest.raises(PermissionError, match="governor"):
        codifier.activate(candidate.candidate_id, _BASE_YAML, governor="intruder")
    assert codifier.constitutional_hash == _BASE_HASH


def test_c38_activate_rejects_yaml_that_is_not_the_pinned_base() -> None:
    codifier, candidate = _approved_codifier()
    codifier.approve(candidate.candidate_id, governor=_GOVERNOR)
    unrelated = "name: unrelated\nrules: []\n"

    with pytest.raises(ValueError, match="constitutional hash"):
        codifier.activate(candidate.candidate_id, unrelated, governor=_GOVERNOR)
    assert codifier.constitutional_hash == _BASE_HASH
    assert codifier.active_rules == []
    [stored] = codifier.all_candidates()
    assert stored.status == RuleCandidateStatus.APPROVED


def test_c38_activation_records_the_governance_chain() -> None:
    codifier, candidate = _approved_codifier()
    approved = codifier.approve(candidate.candidate_id, governor=_GOVERNOR)
    activated, new_yaml = codifier.activate(
        candidate.candidate_id, _BASE_YAML, governor=_GOVERNOR
    )
    assert approved.proposed_by == "rule-codifier"
    assert approved.approved_by == _GOVERNOR
    assert activated.activated_by == _GOVERNOR
    assert activated.constitutional_hash_before == _BASE_HASH
    assert activated.constitutional_hash_after == constitution_hash(new_yaml)


def test_c38_precedent_backed_codifier_forwards_governor_roster() -> None:
    store = c14_precedent_test_store(_BASE_HASH)
    adapter = PrecedentBackedCodifier(
        precedent_store=store,
        constitutional_hash=_BASE_HASH,
        min_cluster_size=1,
        min_validator_agreement=0.5,
        governors={_GOVERNOR},
    )
    adapter.observe(store.admit(_record("adapter-1")))
    adapter.propose_rules(adapter.find_clusters([]))
    [candidate] = adapter.inner.pending_candidates
    adapter.inner.approve(candidate.candidate_id, governor=_GOVERNOR)
    with pytest.raises(PermissionError):
        adapter.inner.activate(candidate.candidate_id, _BASE_YAML, governor="rule-codifier")


# ---------------------------------------------------------------------------
# bittensor-rest-10: YAML is parsed, not string-appended
# ---------------------------------------------------------------------------


def _rule(rule_id: str = "PREC-NEW-001", text: str = "new rule") -> dict:
    return {"id": rule_id, "text": text, "severity": "high"}


def test_c38_rule_appended_under_rules_even_when_rules_is_not_last_key() -> None:
    out = _append_rule_to_yaml(_BASE_YAML, _rule())
    data = yaml.safe_load(out)
    assert [rule["id"] for rule in data["rules"]] == ["R1", "PREC-NEW-001"]
    assert data["meta"] == {"owner": "x"}


def test_c38_substring_rules_key_does_not_capture_new_rule() -> None:
    out = _append_rule_to_yaml("sub_rules: []\n# rules: commented\n", _rule())
    data = yaml.safe_load(out)
    assert data["sub_rules"] == []
    assert [rule["id"] for rule in data["rules"]] == ["PREC-NEW-001"]


def test_c38_rule_text_with_yaml_metacharacters_round_trips() -> None:
    hostile = 'quote " colon: newline\n- id: INJECTED\n  severity: critical'
    out = _append_rule_to_yaml("name: c\nrules: []\n", _rule(text=hostile))
    data = yaml.safe_load(out)
    assert len(data["rules"]) == 1
    assert data["rules"][0]["text"] == hostile


@pytest.mark.parametrize(
    "base",
    [
        "- just\n- a list\n",
        "rules: not-a-list\n",
        "rules:\n  - id: PREC-NEW-001\n",
        "name: [unclosed\n",
    ],
)
def test_c38_invalid_base_constitution_is_rejected(base: str) -> None:
    with pytest.raises(ValueError):
        _append_rule_to_yaml(base, _rule())


def test_c38_candidate_yaml_block_escapes_rule_text() -> None:
    codifier, candidate = _approved_codifier()
    hostile = dataclasses.replace(candidate, rule_text='x"\n    severity: low')
    [parsed] = yaml.safe_load(hostile.to_yaml_block())
    assert parsed["text"] == 'x"\n    severity: low'
    assert parsed["severity"] == candidate.severity


# ---------------------------------------------------------------------------
# bittensor-rest-5: threshold evidence is store-admitted and de-duplicated
# ---------------------------------------------------------------------------


def _updater_with_store():  # type: ignore[no-untyped-def]
    store = c14_precedent_test_store(_BASE_HASH)
    return BayesianThresholdUpdater(min_evidence_count=1, precedent_store=store), store


def test_c38_threshold_evidence_requires_an_injected_store() -> None:
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    with pytest.raises(ValueError, match="PrecedentStore"):
        updater.collect_evidence([_record("no-store")])


def test_c38_threshold_rejects_repeated_precedent_amplification() -> None:
    """PoC from the finding: [rec] * 5 moved security 0.20 -> 0.28."""
    updater, store = _updater_with_store()
    canonical = store.admit(_record("repeat"))
    before = updater.weights()
    with pytest.raises(ValueError, match="Duplicate"):
        updater.update_from_precedents([canonical] * 5)
    assert updater.weights() == before


def test_c38_threshold_rejects_unadmitted_and_altered_precedents() -> None:
    updater, store = _updater_with_store()
    forged = _record("forged")
    with pytest.raises(ValueError):
        updater.collect_evidence([forged])
    canonical = store.admit(_record("altered"))
    altered = dataclasses.replace(canonical, impact_vector={"security": 1.0})
    with pytest.raises(ValueError, match="canonical"):
        updater.collect_evidence([altered])


def test_c38_threshold_rejects_non_store_injection() -> None:
    with pytest.raises(TypeError):
        BayesianThresholdUpdater(precedent_store=object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# bittensor-rest-6: domain-scoped update requires exactly-scoped evidence
# ---------------------------------------------------------------------------


def test_c38_global_evidence_cannot_update_a_domain_table() -> None:
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    global_evidence = [DimensionEvidence("security", "", 5, 5.0, 0.0)]
    before = updater.weights("healthcare")
    with pytest.raises(ValueError, match="does not match update domain"):
        updater.update(global_evidence, domain="healthcare")
    assert updater.weights("healthcare") == before
    assert updater.all_cycles() == []


# ---------------------------------------------------------------------------
# optimisation findings (owned files only)
# ---------------------------------------------------------------------------


def test_c38_single_dimension_table_and_hash_helper() -> None:
    assert tu_mod._DIMENSIONS is rc_mod._DIMENSIONS
    assert rc_mod._deterministic_winner is nmc_mod._deterministic_winner
    assert constitution_hash("x") == constitution_hash("x")
    assert len(constitution_hash("x")) == 16


def test_c38_cluster_fingerprints_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(RuleCodifier, "_MAX_CLUSTER_FINGERPRINTS", 3)
    store = c14_precedent_test_store(_BASE_HASH)
    canonical = store.admit(_record("lru"))
    codifier = RuleCodifier(
        _BASE_HASH, precedent_store=store, min_cluster_size=1, min_validator_agreement=0.5
    )
    clusters = [codifier.find_clusters([canonical])[0] for _ in range(5)]
    assert len(codifier._cluster_fingerprints) == 3
    # Evicted (oldest) cluster is no longer a canonical source; the newest still is.
    with pytest.raises(ValueError, match="canonical cluster"):
        codifier.propose_rules([clusters[0]])
    assert len(codifier.propose_rules([clusters[-1]])) == 1


def test_c38_update_cycle_history_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BayesianThresholdUpdater, "_MAX_CYCLE_HISTORY", 2)
    updater = BayesianThresholdUpdater(min_evidence_count=1)
    for _ in range(4):
        updater.update([DimensionEvidence("security", "", 5, 5.0, 0.0)])
    assert len(updater.all_cycles()) == 2
    assert isinstance(updater.all_cycles(), list)


# ---------------------------------------------------------------------------
# bittensor-rest-9 (rework r1): reject/revoke are governor-gated too
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("actor", ["rule-codifier", "intruder"])
def test_c38_proposer_or_unrostered_actor_cannot_reject(actor: str) -> None:
    codifier, candidate = _approved_codifier()
    with pytest.raises(TypeError):
        codifier.reject(candidate.candidate_id)  # type: ignore[call-arg]
    with pytest.raises(PermissionError, match="governor"):
        codifier.reject(candidate.candidate_id, reason="spite", governor=actor)
    [stored] = codifier.all_candidates()
    assert stored.status == RuleCandidateStatus.PENDING
    assert stored.rejection_reason == ""


@pytest.mark.parametrize("actor", ["rule-codifier", "intruder"])
def test_c38_proposer_or_unrostered_actor_cannot_revoke(actor: str) -> None:
    codifier, candidate = _approved_codifier()
    codifier.approve(candidate.candidate_id, governor=_GOVERNOR)
    codifier.activate(candidate.candidate_id, _BASE_YAML, governor=_GOVERNOR)
    with pytest.raises(TypeError):
        codifier.revoke(candidate.candidate_id)  # type: ignore[call-arg]
    with pytest.raises(PermissionError, match="governor"):
        codifier.revoke(candidate.candidate_id, reason="spite", governor=actor)
    assert [rule.candidate_id for rule in codifier.active_rules] == [candidate.candidate_id]


def test_c38_rostered_governor_rejects_and_revokes_with_attribution() -> None:
    codifier, candidate = _approved_codifier()
    rejected = codifier.reject(candidate.candidate_id, reason="no", governor=_GOVERNOR)
    assert rejected.status == RuleCandidateStatus.REJECTED

    codifier, candidate = _approved_codifier()
    codifier.approve(candidate.candidate_id, governor=_GOVERNOR)
    codifier.activate(candidate.candidate_id, _BASE_YAML, governor=_GOVERNOR)
    revoked = codifier.revoke(candidate.candidate_id, reason="bad", governor=_GOVERNOR)
    assert revoked.status == RuleCandidateStatus.REVOKED
    assert codifier.active_rules == []
