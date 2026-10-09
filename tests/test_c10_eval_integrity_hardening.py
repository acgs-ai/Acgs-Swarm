"""Regression coverage for the C10 evaluation-integrity findings."""

from dataclasses import FrozenInstanceError, replace
import math
from math import nan
import sqlite3

import pytest

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.debate_resolver import (
    Challenge,
    DebateRecord,
    DebateResolver,
    Defense,
    FinalVerdict,
    Proposal,
    VerdictOutcome,
)
from constitutional_swarm.evolution_log import (
    DuplicateRecordError,
    EvolutionLog,
    EvolutionViolationError,
    NonIncreasingValueError,
)
from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
)


class TestC10EvolutionTransactionalWrites:
    def test_rejected_record_rolls_back_before_exception_escapes(self, tmp_path):
        db_path = tmp_path / "evolution-rollback.sqlite"

        with EvolutionLog(db_path) as log:
            log.record(1, "primary", 10.0)

            with pytest.raises(NonIncreasingValueError):
                log.record(2, "primary", 9.0)

            assert log._conn is not None
            assert log._conn.in_transaction is False

            with sqlite3.connect(db_path, timeout=0.0) as other:
                other.execute(
                    "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                    (1, "independent", 1.0),
                )

            assert log._conn.execute(
                "SELECT value FROM evolution_log WHERE epoch = 1 AND metric = 'independent'"
            ).fetchone()[0] == pytest.approx(1.0)


class TestC10EvolutionCanonicalSchema:
    def test_open_rejects_weak_primary_table_without_schema_mutation(self, tmp_path):
        db_path = tmp_path / "evolution-weak-table.sqlite"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE evolution_log (epoch INTEGER, metric TEXT, value REAL)"
            )
            schema_before = conn.execute(
                "SELECT type, name, sql FROM sqlite_schema ORDER BY type, name"
            ).fetchall()

        weak = EvolutionLog(db_path)
        with pytest.raises(EvolutionViolationError, match="table.*canonical"):
            weak.open()
        assert weak._conn is None

        with sqlite3.connect(db_path) as conn:
            assert conn.execute(
                "SELECT type, name, sql FROM sqlite_schema ORDER BY type, name"
            ).fetchall() == schema_before

    def test_insert_or_replace_cannot_overwrite_existing_record(self):
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            assert log._conn is not None

            with pytest.raises(sqlite3.IntegrityError, match="DUPLICATE RECORD"):
                log._conn.execute(
                    "INSERT OR REPLACE INTO evolution_log (epoch, metric, value) "
                    "VALUES (?, ?, ?)",
                    (1, "x", 99.0),
                )
            log._conn.rollback()

            assert log._conn.execute(
                "SELECT value FROM evolution_log WHERE epoch = 1 AND metric = 'x'"
            ).fetchone()[0] == pytest.approx(10.0)

    def test_open_replaces_stale_owned_trigger_and_view(self, tmp_path):
        db_path = tmp_path / "evolution-stale-schema.sqlite"
        with EvolutionLog(db_path) as log:
            log.record(1, "valid", 1.0)
            log.record(2, "valid", 2.0)

        with sqlite3.connect(db_path) as conn:
            conn.execute("DROP TRIGGER validate_evolution_insert")
            conn.execute(
                "CREATE TRIGGER validate_evolution_insert "
                "BEFORE INSERT ON evolution_log BEGIN SELECT 1; END"
            )
            conn.execute("DROP VIEW evolution_derived")
            conn.execute(
                "CREATE VIEW evolution_derived AS "
                "SELECT epoch, metric, value, NULL AS delta, NULL AS accel FROM evolution_log"
            )

        with EvolutionLog(db_path) as reopened:
            assert reopened._conn is not None
            with pytest.raises(sqlite3.IntegrityError, match="MISSING PRIOR EPOCH"):
                reopened._conn.execute(
                    "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                    (2, "gap", 1.0),
                )
            reopened._conn.rollback()

            delta = reopened._conn.execute(
                "SELECT delta FROM evolution_derived WHERE epoch = 2 AND metric = 'valid'"
            ).fetchone()[0]
            assert delta == pytest.approx(1.0)

    @pytest.mark.parametrize("replacement", ["duplicate record", "DUPLICATE  RECORD"])
    def test_open_repairs_trigger_literal_tampering(self, tmp_path, replacement):
        db_path = tmp_path / "evolution-literal-tampering.sqlite"
        with EvolutionLog(db_path) as log:
            log.record(1, "x", 10.0)

        with sqlite3.connect(db_path) as conn:
            trigger_sql = conn.execute(
                "SELECT sql FROM sqlite_schema "
                "WHERE type = 'trigger' AND name = 'validate_evolution_insert'"
            ).fetchone()[0]
            conn.execute("DROP TRIGGER validate_evolution_insert")
            conn.execute(
                trigger_sql.replace("'DUPLICATE RECORD'", f"'{replacement}'")
            )

        with EvolutionLog(db_path) as reopened:
            with pytest.raises(DuplicateRecordError):
                reopened.record(1, "x", 99.0)

    def test_open_fails_closed_on_corrupt_historical_rows(self, tmp_path):
        db_path = tmp_path / "evolution-corrupt-history.sqlite"
        with EvolutionLog(db_path) as log:
            assert log._conn is not None
            log._conn.execute("DROP TRIGGER validate_evolution_insert")
            log._conn.execute(
                "CREATE TRIGGER validate_evolution_insert "
                "BEFORE INSERT ON evolution_log BEGIN SELECT 1; END"
            )
            log._conn.execute(
                "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                (2, "gap", 1.0),
            )
            log._conn.commit()

        with sqlite3.connect(db_path) as conn:
            schema_before = conn.execute(
                "SELECT type, name, sql FROM sqlite_schema "
                "WHERE name IN ('evolution_log_schema', 'evolution_derived', "
                "'validate_evolution_insert', 'block_evolution_update', "
                "'block_evolution_delete') ORDER BY type, name"
            ).fetchall()

        corrupt = EvolutionLog(db_path)
        with pytest.raises(EvolutionViolationError):
            corrupt.open()
        assert corrupt._conn is None

        with sqlite3.connect(db_path) as conn:
            assert conn.execute(
                "SELECT epoch, metric, value FROM evolution_log"
            ).fetchall() == [(2, "gap", 1.0)]
            assert conn.execute(
                "SELECT type, name, sql FROM sqlite_schema "
                "WHERE name IN ('evolution_log_schema', 'evolution_derived', "
                "'validate_evolution_insert', 'block_evolution_update', "
                "'block_evolution_delete') ORDER BY type, name"
            ).fetchall() == schema_before

    def test_open_rejects_unknown_future_schema_version_without_mutation(
        self, tmp_path
    ):
        db_path = tmp_path / "evolution-future-schema.sqlite"
        with EvolutionLog(db_path):
            pass

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE evolution_log_schema SET schema_version = 999 "
                "WHERE singleton = 1"
            )

        future = EvolutionLog(db_path)
        with pytest.raises(EvolutionViolationError, match="unsupported.*version 999"):
            future.open()
        assert future._conn is None

        with sqlite3.connect(db_path) as conn:
            assert conn.execute(
                "SELECT schema_version FROM evolution_log_schema WHERE singleton = 1"
            ).fetchone()[0] == 999

    @pytest.mark.parametrize("value", [math.inf, -math.inf])
    def test_direct_sql_rejects_non_finite_values(self, value):
        with EvolutionLog(":memory:") as log:
            assert log._conn is not None
            with pytest.raises(sqlite3.IntegrityError, match="NON-FINITE VALUE"):
                log._conn.execute(
                    "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                    (1, "non-finite", value),
                )
            log._conn.rollback()

    def test_direct_sql_rejects_fractional_epoch(self):
        with EvolutionLog(":memory:") as log:
            assert log._conn is not None
            with pytest.raises(sqlite3.IntegrityError):
                log._conn.execute(
                    "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                    (1.5, "fractional-epoch", 1.0),
                )
            log._conn.rollback()


class TestC10EvolutionAdmissionConsistency:
    @pytest.mark.parametrize("epoch", [True, "1", 1.0])
    def test_record_and_admit_share_strict_integer_epoch_validation(self, epoch):
        with EvolutionLog(":memory:") as log:
            assert log.admit("typed-epoch", epoch, 1.0) is False

            with pytest.raises(EvolutionViolationError, match="positive integer"):
                log.record(epoch, "typed-epoch", 1.0)

            assert log._conn is not None
            assert log._conn.in_transaction is False
            assert log._conn.execute("SELECT COUNT(*) FROM evolution_log").fetchone()[0] == 0

    @pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
    def test_non_finite_values_fail_closed_without_leaking_a_transaction(self, value):
        with EvolutionLog(":memory:") as log:
            assert log.admit("non-finite", 1, value) is False
            assert log._conn is not None
            assert log._conn.in_transaction is False

            with pytest.raises(EvolutionViolationError):
                log.record(1, "non-finite", value)

            assert log._conn.in_transaction is False
            assert log._conn.execute("SELECT COUNT(*) FROM evolution_log").fetchone()[0] == 0

    def test_admissible_min_is_minimal_for_fractional_epoch_two(self):
        with EvolutionLog(":memory:") as log:
            log.record(1, "fractional", 0.3)

            candidate = log.admissible_min("fractional", 2)
            predecessor = math.nextafter(candidate, -math.inf)

            assert math.isfinite(candidate)
            assert log.admit("fractional", 2, candidate) is True
            assert log.admit("fractional", 2, predecessor) is False

    def test_admissible_min_uses_exact_trigger_arithmetic_after_cancellation(self):
        previous = 7.30567865375819e-09
        prior = 8.55607727752181e-09
        prior_delta = prior - previous
        rounded_sum = prior + prior_delta

        # The rounded sum already passes, so blindly applying nextafter(+inf)
        # overshoots the least admissible float by at least one representable value.
        assert rounded_sum - prior > prior_delta

        with EvolutionLog(":memory:") as log:
            log.record(1, "cancellation", previous)
            log.record(2, "cancellation", prior)

            candidate = log.admissible_min("cancellation", 3)
            predecessor = math.nextafter(candidate, -math.inf)

            assert candidate == rounded_sum
            assert log.admit("cancellation", 3, candidate) is True
            assert log.admit("cancellation", 3, predecessor) is False

    def test_admissible_min_raises_when_no_finite_successor_exists(self):
        with EvolutionLog(":memory:") as log:
            log.record(1, "exhausted", math.nextafter(math.inf, 0.0))

            with pytest.raises(EvolutionViolationError):
                log.admissible_min("exhausted", 2)

    def test_admit_propagates_unrecognized_integrity_failures(self):
        with EvolutionLog(":memory:") as log:
            assert log._conn is not None
            log._conn.execute(
                "CREATE TEMP TRIGGER unexpected_evolution_failure "
                "BEFORE INSERT ON evolution_log BEGIN "
                "SELECT RAISE(ABORT, 'UNEXPECTED INTEGRITY FAILURE'); END"
            )

            with pytest.raises(EvolutionViolationError, match="unexpected trigger"):
                log.admit("unexpected", 1, 1.0)

            assert log._conn.in_transaction is False


def _c10_bridge_credential(
    *,
    agent_id: str = "shared-agent",
    org_id: str = "org-a",
    pubkey: str = "key-a",
    issued_at: float = 1.0,
    expires_at: float = 0.0,
    domains: tuple[str, ...] = ("privacy",),
    status: CredentialStatus = CredentialStatus.ACTIVE,
) -> AgentCredential:
    return AgentCredential(
        agent_id=agent_id,
        org_id=org_id,
        pubkey_fingerprint=pubkey,
        constitutional_hash=CONSTITUTIONAL_HASH,
        issued_at=issued_at,
        expires_at=expires_at,
        domains=domains,
        status=status,
    )


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (CredentialStatus.PENDING, "CREDENTIAL_PENDING"),
        (CredentialStatus.REVOKED, "CREDENTIAL_REVOKED"),
        (CredentialStatus.EXPIRED, "CREDENTIAL_EXPIRED"),
    ],
)
def test_c10_bridge_denies_every_non_active_credential_status(
    status: CredentialStatus, reason: str
) -> None:
    bridge = FederatedConstitutionBridge()
    bridge.register_credential(_c10_bridge_credential(status=status))

    decision = bridge.gate("shared-agent", org_id="org-a", domain="privacy")

    assert decision.allowed is False
    assert decision.reason == reason


def test_c10_bridge_requires_nonempty_org_and_domain_scope() -> None:
    bridge = FederatedConstitutionBridge()
    bridge.register_credential(_c10_bridge_credential())

    with pytest.raises(TypeError):
        bridge.gate("shared-agent", org_id="org-a")
    assert not bridge.gate("shared-agent", org_id="", domain="privacy").allowed
    assert not bridge.gate("shared-agent", org_id="org-a", domain="").allowed


def test_c10_bridge_keys_credentials_and_revocations_by_org_and_agent() -> None:
    bridge = FederatedConstitutionBridge()
    bridge.register_credential(_c10_bridge_credential(org_id="org-a", pubkey="key-a"))
    bridge.register_credential(_c10_bridge_credential(org_id="org-b", pubkey="key-b"))

    assert bridge.summary()["registered_credentials"] == 2
    assert bridge.gate("shared-agent", org_id="org-a", domain="privacy").org_id == "org-a"
    assert bridge.gate("shared-agent", org_id="org-b", domain="privacy").org_id == "org-b"

    assert bridge.revoke("shared-agent", org_id="org-a") is True
    assert not bridge.gate("shared-agent", org_id="org-a", domain="privacy").allowed
    assert bridge.gate("shared-agent", org_id="org-b", domain="privacy").allowed


def test_c10_bridge_revocation_requires_explicit_newer_credential_renewal() -> None:
    bridge = FederatedConstitutionBridge()
    old = _c10_bridge_credential(issued_at=1.0, pubkey="key-old")
    bridge.register_credential(old)
    bridge.revoke(old.agent_id, org_id=old.org_id)

    with pytest.raises(ValueError, match="already registered"):
        bridge.register_credential(_c10_bridge_credential(issued_at=2.0, pubkey="key-new"))
    with pytest.raises(ValueError, match="newer"):
        bridge.renew_credential(_c10_bridge_credential(issued_at=1.0, pubkey="key-new"))

    bridge.renew_credential(_c10_bridge_credential(issued_at=2.0, pubkey="key-new"))
    assert bridge.gate("shared-agent", org_id="org-a", domain="privacy").allowed


def test_c10_bridge_unknown_revocation_does_not_poison_future_registration() -> None:
    bridge = FederatedConstitutionBridge()
    assert bridge.revoke("shared-agent", org_id="org-a") is False
    bridge.register_credential(_c10_bridge_credential())
    assert bridge.gate("shared-agent", org_id="org-a", domain="privacy").allowed


def test_c10_bridge_default_audit_ring_reports_entry_1001_overflow() -> None:
    bridge = FederatedConstitutionBridge()
    for index in range(1001):
        bridge.gate(f"unknown-{index}", org_id="org-a", domain="privacy")

    with pytest.raises(RuntimeError, match="truncated"):
        bridge.audit_log()
    assert len(bridge.audit_log(require_complete=False)) == 1000
    summary = bridge.summary()
    assert summary["total_decisions"] == 1001
    assert summary["audit_overflow_count"] == 1


def test_c10_bridge_bounded_audit_log_makes_truncation_loud() -> None:
    bridge = FederatedConstitutionBridge(audit_log_size=2)
    for index in range(3):
        bridge.gate(f"unknown-{index}", org_id="org-a", domain="privacy")

    with pytest.raises(RuntimeError, match="truncated"):
        bridge.audit_log()
    assert len(bridge.audit_log(require_complete=False)) == 2
    summary = bridge.summary()
    assert summary["total_decisions"] == 3
    assert summary["retained_decisions"] == 2
    assert summary["dropped_decisions"] == 1
    assert summary["audit_truncated"] is True


def test_c10_bridge_decision_and_audit_snapshots_cannot_mutate_internal_counts() -> None:
    bridge = FederatedConstitutionBridge()
    decision = bridge.gate("unknown", org_id="org-a", domain="privacy")

    with pytest.raises(FrozenInstanceError):
        decision.allowed = True
    snapshot = bridge.audit_log()
    snapshot[0]["allowed"] = True
    assert bridge.allowed_count() == 0
    assert bridge.denied_count() == 1


def test_c10_bridge_credential_fingerprint_uses_canonical_full_digest() -> None:
    delimiter_left = _c10_bridge_credential(agent_id="a:b", org_id="c", pubkey="d")
    delimiter_right = _c10_bridge_credential(agent_id="a", org_id="b:c", pubkey="d")
    reordered_domains = _c10_bridge_credential(domains=("safety", "privacy"))
    canonical_domains = _c10_bridge_credential(domains=("privacy", "safety"))

    assert delimiter_left.fingerprint != delimiter_right.fingerprint
    assert len(delimiter_left.fingerprint) == 64
    assert reordered_domains.fingerprint == canonical_domains.fingerprint


def test_c10_bridge_rejects_nonfinite_time_and_closes_expiry_boundary() -> None:
    with pytest.raises(ValueError, match="finite"):
        _c10_bridge_credential(expires_at=nan)
    credential = _c10_bridge_credential(expires_at=10.0)
    assert credential.is_expired(now=10.0)


def _c10_artifact(*, timestamp: float = 1.0) -> Artifact:
    return Artifact(
        artifact_id="fixed",
        task_id="task",
        agent_id="agent",
        content_type="text/plain",
        content="hello",
        domain="safety",
        tags=("a", "b"),
        timestamp=timestamp,
        constitutional_hash="608508a9bd224290",
        parent_artifacts=("parent",),
        metadata={"nested": {"value": 1}, "items": [2, 3]},
    )


def _c10_debate_record(*, constitutional_hash: str = "constitution-a") -> DebateRecord:
    return DebateRecord(
        proposal=Proposal(
            proposal_id="proposal",
            proposer_id="proposer",
            domain="safety",
            content="content",
            evidence="evidence",
            timestamp=1.0,
        ),
        challenges=(
            Challenge(
                proposal_id="proposal",
                challenger_id="challenger",
                objection="objection",
                alternative="alternative",
                severity=0.4,
                timestamp=2.0,
            ),
        ),
        defenses=(
            Defense(
                proposal_id="proposal",
                defender_id="defender",
                rebuttal="rebuttal",
                concession="concession",
                timestamp=3.0,
            ),
        ),
        constitutional_hash=constitutional_hash,
    )


class TestC10ArtifactIntegrityRecords:
    def test_valid_artifact_digest_format_remains_compatible(self) -> None:
        assert _c10_artifact().content_hash == "df0b703baa958d24f6ba24e8557bb8ab"

    def test_integrity_uses_independent_publish_time_seal(self) -> None:
        store = ArtifactStore()
        artifact = _c10_artifact()
        store.publish(artifact)

        stored = store._artifacts[("", artifact.artifact_id)]
        object.__setattr__(stored, "content", "tampered")

        assert store.verify_integrity(artifact.artifact_id) is False

    def test_integrity_fails_closed_when_seal_is_missing(self) -> None:
        store = ArtifactStore()
        artifact = _c10_artifact()
        store.publish(artifact)
        del store._sealed_digests[("", artifact.artifact_id)]

        assert store.verify_integrity(artifact.artifact_id) is False

    def test_governed_projection_uses_same_sealing_path(self) -> None:
        store = ArtifactStore()
        projection = store._bind_governed(
            workflow_id="workflow",
            seal_id="seal",
            guard=lambda artifact_id: artifact_id == "fixed",
        )
        artifact = _c10_artifact()

        projection.publish(artifact)

        assert store.verify_integrity("fixed", workflow_id="workflow") is True
        stored = store._artifacts[("workflow", "fixed")]
        object.__setattr__(stored, "content", "tampered")
        assert store.verify_integrity("fixed", workflow_id="workflow") is False

    def test_unsealable_artifact_is_not_partially_published(self) -> None:
        store = ArtifactStore()

        with pytest.raises(ValueError):
            store.publish(_c10_artifact(timestamp=float("nan")))

        assert store.count == 0
        assert store.get("fixed") is None


class TestC10DebateTranscriptRecords:
    @pytest.mark.parametrize(
        "variant",
        [
            lambda record: replace(
                record, proposal=replace(record.proposal, proposer_id="other")
            ),
            lambda record: replace(
                record, proposal=replace(record.proposal, domain="privacy")
            ),
            lambda record: replace(
                record, proposal=replace(record.proposal, evidence="other")
            ),
            lambda record: replace(
                record, proposal=replace(record.proposal, timestamp=11.0)
            ),
            lambda record: replace(
                record,
                challenges=(replace(record.challenges[0], proposal_id="other"),),
            ),
            lambda record: replace(
                record,
                challenges=(replace(record.challenges[0], alternative="other"),),
            ),
            lambda record: replace(
                record,
                challenges=(replace(record.challenges[0], timestamp=12.0),),
            ),
            lambda record: replace(
                record,
                defenses=(replace(record.defenses[0], proposal_id="other"),),
            ),
            lambda record: replace(
                record,
                defenses=(replace(record.defenses[0], concession="other"),),
            ),
            lambda record: replace(
                record,
                defenses=(replace(record.defenses[0], timestamp=13.0),),
            ),
            lambda record: replace(record, constitutional_hash="constitution-b"),
        ],
        ids=[
            "proposer_id",
            "proposal_domain",
            "proposal_evidence",
            "proposal_timestamp",
            "challenge_proposal_id",
            "challenge_alternative",
            "challenge_timestamp",
            "defense_proposal_id",
            "defense_concession",
            "defense_timestamp",
            "constitutional_hash",
        ],
    )
    def test_digest_binds_every_previously_omitted_field(self, variant) -> None:
        record = _c10_debate_record()
        assert variant(record).compute_merkle_root() != record.compute_merkle_root()

    def test_digest_has_no_delimiter_collision(self) -> None:
        embedded = DebateRecord(
            proposal=Proposal(
                proposal_id="p",
                proposer_id="proposer-a",
                domain="safety",
                content="x|challenge:c:o:0.5",
                timestamp=1.0,
            )
        )
        structured = DebateRecord(
            proposal=Proposal(
                proposal_id="p",
                proposer_id="proposer-a",
                domain="safety",
                content="x",
                timestamp=1.0,
            ),
            challenges=(
                Challenge(
                    proposal_id="p",
                    challenger_id="c",
                    objection="o",
                    severity=0.5,
                    timestamp=2.0,
                ),
            ),
        )

        assert embedded.compute_merkle_root() != structured.compute_merkle_root()


class TestC10DebateVerdictIntegrityRecords:
    def test_forged_identity_strings_cannot_accumulate_unbounded_credit(self) -> None:
        resolver = DebateResolver(approval_threshold=0.6)
        resolver.propose("proposal", "proposer", "safety", "content")
        resolver.challenge(
            "proposal", "challenger", "critical flaw", severity=0.8
        )
        for index in range(12):
            resolver.defend("proposal", f"forged-{index}", f"rebuttal-{index}")

        verdict = resolver.resolve("proposal")

        assert verdict.outcome is VerdictOutcome.REJECTED
        assert verdict.approval_score < 0.6

    def test_repeated_defender_messages_receive_credit_once(self) -> None:
        resolver = DebateResolver(approval_threshold=0.6)
        resolver.propose("proposal", "proposer", "safety", "content")
        resolver.challenge("proposal", "challenger", "minor", severity=0.1)
        for index in range(3):
            resolver.defend("proposal", "same-defender", f"rebuttal-{index}")

        verdict = resolver.resolve("proposal")

        assert verdict.approval_score == pytest.approx(0.605)
        assert verdict.outcome is VerdictOutcome.APPROVED

    @pytest.mark.parametrize(
        ("severity", "expected_score", "expected_outcome"),
        [
            (0.05, 0.6275, VerdictOutcome.APPROVED),
            (0.1, 0.605, VerdictOutcome.APPROVED),
            (0.2, 0.56, VerdictOutcome.REJECTED),
            (0.8, 0.29, VerdictOutcome.REJECTED),
        ],
    )
    def test_defense_credit_is_one_fixed_response_credit(
        self,
        severity: float,
        expected_score: float,
        expected_outcome: VerdictOutcome,
    ) -> None:
        def resolve_with_defenders(defender_ids: list[str]) -> FinalVerdict:
            resolver = DebateResolver(approval_threshold=0.6)
            resolver.propose("proposal", "proposer", "safety", "content")
            resolver.challenge("proposal", "challenger", "flaw", severity=severity)
            for index, defender_id in enumerate(defender_ids):
                resolver.defend("proposal", defender_id, f"rebuttal-{index}")
            return resolver.resolve("proposal")

        verdicts = [
            resolve_with_defenders(["one"]),
            resolve_with_defenders(["one", "two"]),
            resolve_with_defenders([f"forged-{index}" for index in range(12)]),
            resolve_with_defenders(["repeated"] * 3),
        ]

        assert [verdict.approval_score for verdict in verdicts] == pytest.approx(
            [expected_score] * 4
        )
        assert {verdict.outcome for verdict in verdicts} == {expected_outcome}

    def test_explicit_empty_hash_fails_without_sealing_record(self) -> None:
        resolver = DebateResolver(constitutional_hash="constitution")
        resolver.propose("proposal", "proposer", "safety", "content")
        resolver.challenge("proposal", "challenger", "minor", severity=0.1)

        with pytest.raises(PermissionError, match="hash mismatch"):
            resolver.resolve("proposal", constitutional_hash="")

        record = resolver.get_record("proposal")
        assert record is not None
        assert record.verdict is None
        resolver.resolve("proposal", constitutional_hash="constitution")

    def test_empty_configured_hash_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="constitutional_hash"):
            DebateResolver(constitutional_hash="")

    def test_resolved_record_graph_is_immutable(self) -> None:
        resolver = DebateResolver()
        resolver.propose("proposal", "proposer", "safety", "content")
        resolver.challenge("proposal", "challenger", "minor", severity=0.1)
        verdict = resolver.resolve("proposal")
        record = resolver.get_record("proposal")
        assert record is not None
        assert record.verdict is verdict

        with pytest.raises(FrozenInstanceError):
            verdict.outcome = VerdictOutcome.REJECTED
        with pytest.raises(FrozenInstanceError):
            record.merkle_root = "tampered"
        with pytest.raises(AttributeError):
            record.challenges.append(record.challenges[0])

        assert resolver.get_record("proposal") == record

    def test_record_binds_custom_constitutional_hash(self) -> None:
        resolver = DebateResolver(constitutional_hash="custom")
        resolver.propose("proposal", "proposer", "safety", "content")
        record = resolver.get_record("proposal")

        assert record is not None
        assert record.constitutional_hash == "custom"


def test_debate_quorum_counts_distinct_asserted_challengers() -> None:
    resolver = DebateResolver(min_challenges=2)
    resolver.propose("p-distinct-quorum", "proposer", "safety", "proposal")
    resolver.challenge(
        "p-distinct-quorum", "challenger-1", "first objection", severity=0.2
    )
    resolver.challenge(
        "p-distinct-quorum", "challenger-1", "second objection", severity=0.7
    )

    verdict = resolver.resolve("p-distinct-quorum")

    assert verdict.outcome is VerdictOutcome.DEADLOCK
    assert "1 distinct challengers" in verdict.reasoning


def test_debate_scoring_uses_strongest_severity_per_asserted_challenger() -> None:
    resolver = DebateResolver(min_challenges=2, escalation_threshold=0.5)
    resolver.propose("p-strongest", "proposer", "safety", "proposal")
    resolver.challenge("p-strongest", "challenger-1", "minor", severity=0.1)
    resolver.challenge("p-strongest", "challenger-1", "critical", severity=0.8)
    resolver.challenge("p-strongest", "challenger-2", "moderate", severity=0.2)

    verdict = resolver.resolve("p-strongest")

    assert verdict.outcome is VerdictOutcome.ESCALATED
    assert verdict.approval_score == pytest.approx(0.2)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"min_challenges": 0}, "min_challenges"),
        ({"min_challenges": True}, "min_challenges"),
        ({"approval_threshold": math.nan}, "approval_threshold"),
        ({"approval_threshold": math.inf}, "approval_threshold"),
        ({"approval_threshold": -0.01}, "approval_threshold"),
        ({"approval_threshold": 1.01}, "approval_threshold"),
        ({"escalation_threshold": math.nan}, "escalation_threshold"),
        ({"escalation_threshold": math.inf}, "escalation_threshold"),
        ({"escalation_threshold": -0.01}, "escalation_threshold"),
        ({"escalation_threshold": 1.01}, "escalation_threshold"),
    ],
)
def test_debate_resolver_rejects_invalid_configuration(
    kwargs: dict[str, object], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        DebateResolver(**kwargs)


def test_manually_constructed_debate_record_coerces_collections_to_tuples() -> None:
    proposal = Proposal("p-manual", "proposer", "safety", "proposal", timestamp=1.0)
    challenge = Challenge(
        "p-manual", "challenger", "objection", severity=0.4, timestamp=2.0
    )
    defense = Defense("p-manual", "defender", "rebuttal", timestamp=3.0)

    record = DebateRecord(
        proposal=proposal,
        challenges=[challenge],
        defenses=[defense],
        constitutional_hash="constitution-v1",
    )

    assert record.challenges == (challenge,)
    assert record.defenses == (defense,)
    assert isinstance(record.challenges, tuple)
    assert isinstance(record.defenses, tuple)


class TestC10BridgeFollowups:
    @pytest.mark.parametrize(
        "revocation_path",
        ["register-revoked", "renew-revoked", "explicit-revoke"],
    )
    def test_rotation_cannot_reinstate_historically_revoked_key(
        self, revocation_path: str
    ) -> None:
        bridge = FederatedConstitutionBridge()
        old_key = _c10_bridge_credential(
            issued_at=1.0,
            pubkey="revoked-key",
            status=(
                CredentialStatus.REVOKED
                if revocation_path == "register-revoked"
                else CredentialStatus.ACTIVE
            ),
        )
        bridge.register_credential(old_key)
        next_issued_at = 2.0
        if revocation_path == "renew-revoked":
            bridge.renew_credential(
                _c10_bridge_credential(
                    issued_at=next_issued_at,
                    pubkey="revoked-key",
                    status=CredentialStatus.REVOKED,
                )
            )
            next_issued_at += 1.0
        elif revocation_path == "explicit-revoke":
            assert bridge.revoke(old_key.agent_id, org_id=old_key.org_id)

        bridge.renew_credential(
            _c10_bridge_credential(
                issued_at=next_issued_at,
                pubkey="never-revoked-key",
            )
        )
        assert bridge.gate(
            old_key.agent_id,
            org_id=old_key.org_id,
            domain="privacy",
            now=next_issued_at,
        ).allowed

        bridge.renew_credential(
            _c10_bridge_credential(
                issued_at=next_issued_at + 1.0,
                pubkey="revoked-key",
            )
        )

        decision = bridge.gate(
            old_key.agent_id,
            org_id=old_key.org_id,
            domain="privacy",
            now=next_issued_at + 1.0,
        )
        assert decision.allowed is False
        assert decision.reason == "REVOKED"

    @pytest.mark.parametrize("variant", ["DEADBEEF01", " deadbeef01", "deadbeef01 ", "DeadBeef01"])
    def test_case_or_whitespace_variant_cannot_reinstate_revoked_key(self, variant: str) -> None:
        bridge = FederatedConstitutionBridge()
        original = _c10_bridge_credential(issued_at=1.0, pubkey="deadbeef01")
        bridge.register_credential(original)
        assert bridge.revoke(original.agent_id, org_id=original.org_id)
        bridge.renew_credential(_c10_bridge_credential(issued_at=2.0, pubkey="cafe0002"))
        bridge.renew_credential(_c10_bridge_credential(issued_at=3.0, pubkey=variant))

        decision = bridge.gate(
            original.agent_id, org_id=original.org_id, domain="privacy", now=3.0
        )
        assert decision.allowed is False
        assert decision.reason == "REVOKED"

    def test_fingerprint_is_canonicalised(self) -> None:
        cred = _c10_bridge_credential(pubkey="  AbC123  ")
        assert cred.pubkey_fingerprint == "abc123"

    def test_same_key_renewal_does_not_clear_explicit_revocation(self) -> None:
        bridge = FederatedConstitutionBridge()
        original = _c10_bridge_credential(issued_at=1.0, pubkey="same-key")
        bridge.register_credential(original)
        bridge.revoke(original.agent_id, org_id=original.org_id)

        bridge.renew_credential(
            _c10_bridge_credential(issued_at=2.0, pubkey="same-key")
        )

        decision = bridge.gate(
            original.agent_id,
            org_id=original.org_id,
            domain="privacy",
            now=2.0,
        )
        assert decision.allowed is False
        assert decision.reason == "REVOKED"

    def test_same_key_renewal_does_not_clear_status_revocation(self) -> None:
        bridge = FederatedConstitutionBridge()
        revoked = _c10_bridge_credential(
            issued_at=1.0,
            pubkey="same-key",
            status=CredentialStatus.REVOKED,
        )
        bridge.register_credential(revoked)

        bridge.renew_credential(
            _c10_bridge_credential(issued_at=2.0, pubkey="same-key")
        )

        decision = bridge.gate(
            revoked.agent_id,
            org_id=revoked.org_id,
            domain="privacy",
            now=2.0,
        )
        assert decision.allowed is False
        assert decision.reason == "REVOKED"

    def test_key_rotation_clears_revocation_tombstone(self) -> None:
        bridge = FederatedConstitutionBridge()
        original = _c10_bridge_credential(issued_at=1.0, pubkey="old-key")
        bridge.register_credential(original)
        bridge.revoke(original.agent_id, org_id=original.org_id)

        bridge.renew_credential(
            _c10_bridge_credential(issued_at=2.0, pubkey="new-key")
        )

        assert bridge.gate(
            original.agent_id,
            org_id=original.org_id,
            domain="privacy",
            now=2.0,
        ).allowed

    def test_gate_enforces_credential_not_before_time(self) -> None:
        bridge = FederatedConstitutionBridge()
        credential = _c10_bridge_credential(issued_at=10.0)
        bridge.register_credential(credential)

        early = bridge.gate(
            credential.agent_id,
            org_id=credential.org_id,
            domain="privacy",
            now=9.0,
        )
        on_time = bridge.gate(
            credential.agent_id,
            org_id=credential.org_id,
            domain="privacy",
            now=10.0,
        )

        assert early.allowed is False
        assert early.reason == "NOT_YET_VALID"
        assert on_time.allowed is True

    def test_empty_domains_deny_and_explicit_wildcard_allows(self) -> None:
        from constitutional_swarm.federated_bridge import ALL_DOMAINS

        bridge = FederatedConstitutionBridge()
        empty = _c10_bridge_credential(agent_id="empty", domains=())
        wildcard = _c10_bridge_credential(
            agent_id="wildcard",
            domains=(ALL_DOMAINS,),
        )
        bridge.register_credential(empty)
        bridge.register_credential(wildcard)

        denied = bridge.gate("empty", org_id="org-a", domain="unlisted", now=1.0)
        allowed = bridge.gate(
            "wildcard", org_id="org-a", domain="unlisted", now=1.0
        )

        assert denied.allowed is False
        assert denied.reason == "DOMAIN_DENIED"
        assert allowed.allowed is True

    def test_audit_overflow_sink_runs_after_gate_lock_is_released(self) -> None:
        import threading

        callback_snapshots: list[int] = []
        callback_threads: list[threading.Thread] = []
        bridge: FederatedConstitutionBridge

        def sink(_decision) -> None:
            thread = threading.Thread(
                target=lambda: callback_snapshots.append(
                    bridge.summary()["audit_overflow_count"]
                )
            )
            callback_threads.append(thread)
            thread.start()
            thread.join(timeout=1.0)
            assert not thread.is_alive(), "audit sink ran while the gate lock was held"

        bridge = FederatedConstitutionBridge(
            audit_log_size=1,
            audit_overflow_sink=sink,
        )
        bridge.gate("first", org_id="org-a", domain="privacy", now=1.0)
        bridge.gate("second", org_id="org-a", domain="privacy", now=2.0)

        assert callback_snapshots == [1]
        assert len(callback_threads) == 1

    def test_audit_sink_failure_is_counted_and_raised(self) -> None:
        def failing_sink(_decision) -> None:
            raise LookupError("sink unavailable")

        bridge = FederatedConstitutionBridge(
            audit_log_size=1,
            audit_overflow_sink=failing_sink,
        )
        bridge.gate("first", org_id="org-a", domain="privacy", now=1.0)

        with pytest.raises(RuntimeError, match="audit overflow sink failed"):
            bridge.gate("second", org_id="org-a", domain="privacy", now=2.0)

        summary = bridge.summary()
        assert summary["total_decisions"] == 2
        assert summary["audit_overflow_count"] == 1
        assert summary["audit_sink_failures"] == 1
        assert "LookupError: sink unavailable" in summary["last_audit_sink_error"]


class TestC10EvolutionFollowups:
    def test_admit_translates_exclusive_lock_to_domain_error(self, tmp_path) -> None:
        import constitutional_swarm.evolution_log as evolution_module

        db_path = tmp_path / "evolution-admit-exclusive-lock.sqlite"
        with EvolutionLog(db_path) as log:
            log.record(1, "locked", 1.0)
            assert log._conn is not None
            log._conn.execute("PRAGMA busy_timeout = 0")

            locker = sqlite3.connect(db_path, isolation_level=None)
            try:
                locker.execute("BEGIN EXCLUSIVE")
                try:
                    log.admit("locked", 2, 2.0)
                except Exception as exc:
                    locked_error = getattr(
                        evolution_module, "EvolutionLockedError", None
                    )
                    assert locked_error is not None
                    assert isinstance(exc, locked_error)
                    assert isinstance(exc, EvolutionViolationError)
                    assert isinstance(exc.__cause__, sqlite3.OperationalError)
                else:
                    pytest.fail("admit unexpectedly succeeded under an exclusive lock")
            finally:
                locker.rollback()
                locker.close()

            assert log.admit("locked", 2, 2.0) is True

    def test_admit_preserves_unrelated_operational_error(
        self, monkeypatch
    ) -> None:
        with EvolutionLog(":memory:") as log:
            assert log._conn is not None

            def raise_unrelated(*, validate_history: bool) -> None:
                assert validate_history is False
                log._conn.execute("SELECT * FROM missing_evolution_table")

            monkeypatch.setattr(log, "_verify_canonical_schema", raise_unrelated)

            with pytest.raises(sqlite3.OperationalError) as caught:
                log.admit("metric", 1, 1.0)

            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_ERROR

    def test_commit_failure_rolls_back_and_releases_transaction(self, tmp_path) -> None:
        db_path = tmp_path / "evolution-commit-rollback.sqlite"
        with EvolutionLog(db_path) as log:
            log.record(1, "commit", 1.0)
            assert log._conn is not None
            log._conn.execute("PRAGMA busy_timeout = 0")

            reader = sqlite3.connect(db_path, isolation_level=None)
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT value FROM evolution_log").fetchone()
                with pytest.raises(sqlite3.OperationalError, match="database is locked"):
                    log.record(2, "commit", 2.0)
                assert log._conn.in_transaction is False
            finally:
                reader.rollback()
                reader.close()

            log.record(2, "commit", 2.0)

    def test_admit_remains_read_only_while_another_connection_holds_write_lock(
        self, tmp_path
    ) -> None:
        db_path = tmp_path / "evolution-admit-read-only.sqlite"
        with EvolutionLog(db_path) as log:
            log.record(1, "locked", 1.0)
            assert log._conn is not None
            log._conn.execute("PRAGMA busy_timeout = 0")

            locker = sqlite3.connect(db_path, isolation_level=None)
            try:
                locker.execute("BEGIN IMMEDIATE")
                assert log.admit("locked", 2, 2.0) is True
                assert log.admit("locked", 2, 1.0) is False
                assert log._conn.in_transaction is False
            finally:
                locker.rollback()
                locker.close()

    def test_read_only_open_verifies_and_supports_queries_without_writes(
        self, tmp_path
    ) -> None:
        db_path = tmp_path / "evolution-read-only.sqlite"
        with EvolutionLog(db_path) as writer:
            writer.record(1, "verified", 1.0)

        locker = sqlite3.connect(db_path, isolation_level=None)
        try:
            locker.execute("BEGIN IMMEDIATE")
            with EvolutionLog(db_path).open(read_only=True) as reader:
                assert reader.open(read_only=True) is reader
                with pytest.raises(EvolutionViolationError, match="access mode"):
                    reader.open()
                assert reader.dashboard()[0].metric == "verified"
                assert reader.admit("verified", 2, 2.0) is True
                assert reader.admissible_min("verified", 2) == math.nextafter(
                    1.0, math.inf
                )
                with pytest.raises(EvolutionViolationError, match="read-only"):
                    reader.record(2, "verified", 2.0)
        finally:
            locker.rollback()
            locker.close()

    def test_read_only_open_rejects_schema_drift_without_repair(self, tmp_path) -> None:
        db_path = tmp_path / "evolution-read-only-drift.sqlite"
        with EvolutionLog(db_path):
            pass

        with sqlite3.connect(db_path) as conn:
            conn.execute("DROP TRIGGER validate_evolution_insert")
            conn.execute(
                "CREATE TRIGGER validate_evolution_insert "
                "BEFORE INSERT ON evolution_log BEGIN SELECT 1; END"
            )

        reader = EvolutionLog(db_path)
        with pytest.raises(EvolutionViolationError, match="canonical"):
            reader.open(read_only=True)
        assert reader._conn is None

        with sqlite3.connect(db_path) as conn:
            trigger_sql = conn.execute(
                "SELECT sql FROM sqlite_schema "
                "WHERE type = 'trigger' AND name = 'validate_evolution_insert'"
            ).fetchone()[0]
        assert "SELECT 1" in trigger_sql


class TestC10RecordFollowups:
    def test_unsealed_debate_record_fails_integrity_verification(self) -> None:
        assert _c10_debate_record().verify_integrity() is False

    @pytest.mark.parametrize(
        ("field_name", "replacement"),
        [
            ("proposal_id", "other-proposal"),
            ("outcome", VerdictOutcome.REJECTED),
            ("approval_score", 0.605000001),
            ("reasoning", "tampered reasoning"),
            ("constitutional_hash", "other-constitution"),
            ("timestamp", 987654321.125),
        ],
        ids=[
            "proposal_id",
            "outcome",
            "approval_score",
            "reasoning",
            "constitutional_hash",
            "timestamp",
        ],
    )
    def test_debate_seal_binds_every_verdict_field(
        self, field_name: str, replacement: object
    ) -> None:
        resolver = DebateResolver(constitutional_hash="constitution-a")
        resolver.propose("proposal", "proposer", "safety", "content")
        resolver.challenge("proposal", "challenger", "minor", severity=0.1)
        resolver.defend("proposal", "defender", "rebuttal")
        resolver.resolve("proposal")
        record = resolver.get_record("proposal")
        assert record is not None and record.verdict is not None
        assert record.compute_merkle_root() == record.merkle_root

        object.__setattr__(record.verdict, field_name, replacement)

        assert record.compute_merkle_root() != record.merkle_root
        assert record.verify_integrity() is False

    @pytest.mark.parametrize(
        "metadata",
        [
            {"nested": {"score": float("nan")}},
            {"nested": {"payload": object()}},
            {"nested": {"values": {"a", "b"}}},
            {"nested": {1: "integer", "1": "string"}},
        ],
        ids=["non_finite", "non_json", "set", "non_string_key"],
    )
    def test_artifact_publish_rejects_invalid_canonical_values_explicitly(
        self, metadata: dict[str, object]
    ) -> None:
        store = ArtifactStore()

        with pytest.raises(
            ValueError,
            match="Artifact metadata and canonical fields must be finite JSON values",
        ):
            artifact = replace(_c10_artifact(), metadata=metadata)
            store.publish(artifact)

        assert store.count == 0
        assert store.get("fixed") is None
        assert store._sealed_digests == {}
        assert store._by_task == {}
        assert store._by_domain == {}
        assert store._by_agent == {}

    def test_frozen_finite_json_metadata_remains_publishable(self) -> None:
        store = ArtifactStore()
        source = _c10_artifact()
        artifact = replace(source, metadata=source.metadata)

        store.publish(artifact)

        assert store.verify_integrity(artifact.artifact_id) is True

    def test_cyclic_metadata_is_rejected_with_canonical_value_error(self) -> None:
        metadata: dict[str, object] = {}
        metadata["self"] = metadata

        with pytest.raises(
            ValueError,
            match="Artifact metadata and canonical fields must be finite JSON values",
        ):
            replace(_c10_artifact(), metadata=metadata)
