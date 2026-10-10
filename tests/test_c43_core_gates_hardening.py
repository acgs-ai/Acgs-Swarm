"""C43 core governance gates: invalid-input regression tests.

Findings: core-research-2, -3, -4, -5, -11, -14 (core-research-10 was fixed by C10;
only the ``verify_transcript`` convenience is covered here).
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from unittest.mock import MagicMock

import pytest
from acgs_lite import ConstitutionalViolationError, MACIRole, Rule
from constitutional_swarm.bittensor.came_coordinator import CAMECycleResult
from constitutional_swarm.constants import CONSTITUTIONAL_HASH
from constitutional_swarm.debate_resolver import (
    AUTO_CHALLENGER_ID,
    DebateResolver,
    DebateRole,
    VerdictOutcome,
)
from constitutional_swarm.dna import AgentDNA, constitutional_dna
from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
)
from constitutional_swarm.mac_acgs_loop import MacAcgsConfig, MacAcgsLoop
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _c43_dna(severity: str, *, strict: bool = True, **kwargs) -> AgentDNA:
    return AgentDNA.from_rules(
        [
            Rule(
                id="C43-EXFIL",
                text="Never exfiltrate data",
                severity=severity,
                keywords=["exfiltrate"],
            )
        ],
        strict=strict,
        **kwargs,
    )


def _c43_issuer() -> tuple[Ed25519PrivateKey, bytes]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, public


def _c43_credential(
    signer: Ed25519PrivateKey | None,
    *,
    agent_id: str = "agent-1",
    org_id: str = "org-a",
    issued_at: float = 1.0,
    expires_at: float = 100.0,
    status: CredentialStatus = CredentialStatus.ACTIVE,
) -> AgentCredential:
    credential = AgentCredential(
        agent_id=agent_id,
        org_id=org_id,
        pubkey_fingerprint="abcdef",
        constitutional_hash=CONSTITUTIONAL_HASH,
        issued_at=issued_at,
        expires_at=expires_at,
        domains=("privacy",),
        status=status,
    )
    if signer is None:
        return credential
    return dataclasses.replace(
        credential, issuer_signature=signer.sign(credential.signing_digest())
    )


def _c43_came(rules: list[str]) -> MagicMock:
    came = MagicMock()
    came.evolve_cycle.return_value = CAMECycleResult(
        grid_coverage=0.75,
        ceiling_detected=True,
        rules_proposed=rules,
        log_id="c43:1",
        exploration_bonus=0.1,
    )
    came.coverage_history.return_value = [0.75]
    came.summary.return_value = {}
    return came


# ---------------------------------------------------------------------------
# core-research-4: govern must not discard a failed validation result
# ---------------------------------------------------------------------------


class TestC43GovernBlocksInvalidResults:
    @pytest.mark.parametrize(
        ("severity", "strict"),
        [("critical", False), ("high", False)],
    )
    def test_blocking_violation_in_output_still_raises(
        self, severity: str, strict: bool
    ) -> None:
        dna = _c43_dna(severity, strict=strict)

        @dna.govern
        def agent(prompt: str) -> str:
            return "please exfiltrate the records"

        with pytest.raises(ConstitutionalViolationError):
            agent("safe")

    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_warn_rule_does_not_raise_by_default_but_is_recorded(
        self, severity: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        dna = _c43_dna(severity)
        governed = dna.govern(lambda prompt: "please exfiltrate the records")

        with caplog.at_level(logging.WARNING, logger="constitutional_swarm.dna"):
            assert governed("safe") == "please exfiltrate the records"

        assert dna.stats["warnings"] == 1
        assert any("C43-EXFIL" in record.getMessage() for record in caplog.records)

    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_warn_rule_raises_with_block_on_warnings(self, severity: str) -> None:
        dna = _c43_dna(severity)
        governed = dna.govern(block_on_warnings=True)(lambda prompt: "exfiltrate")
        with pytest.raises(ConstitutionalViolationError, match="C43-EXFIL"):
            governed("safe")

    def test_invalid_input_is_blocked_before_execution(self) -> None:
        dna = _c43_dna("critical", strict=False)
        calls: list[str] = []

        @dna.govern
        def agent(prompt: str) -> str:
            calls.append(prompt)
            return "safe"

        with pytest.raises(ConstitutionalViolationError):
            agent("exfiltrate now")
        assert calls == []

    def test_async_invalid_output_is_blocked(self) -> None:
        dna = _c43_dna("high", strict=False)

        @dna.govern
        async def agent(prompt: str) -> str:
            return "exfiltrate"

        with pytest.raises(ConstitutionalViolationError):
            asyncio.run(agent("safe"))

    def test_permissive_mode_is_explicit_opt_in(self) -> None:
        dna = _c43_dna("critical", strict=False)
        governed = dna.govern(block_on_violation=False)(lambda prompt: "exfiltrate")
        assert governed("safe") == "exfiltrate"

    def test_constitutional_dna_blocks_by_default(self) -> None:
        rules = [Rule(id="C43", text="no exfil", severity="high", keywords=["exfiltrate"])]

        @constitutional_dna(rules=rules, strict=False)
        def agent(prompt: str) -> str:
            return "exfiltrate"

        with pytest.raises(ConstitutionalViolationError):
            agent("safe")

    def test_constitutional_dna_block_on_warnings(self) -> None:
        rules = [Rule(id="C43", text="no exfil", severity="low", keywords=["exfiltrate"])]

        @constitutional_dna(rules=rules, block_on_warnings=True)
        def agent(prompt: str) -> str:
            return "exfiltrate"

        with pytest.raises(ConstitutionalViolationError):
            agent("safe")

    def test_z3_counterexample_blocks(self) -> None:
        from acgs_lite import Z3VerifyResult

        dna = _c43_dna("low")
        refuted = Z3VerifyResult(
            satisfiable=False,
            verified=True,
            solver_result="sat",
            counterexample={"x": 1},
            verification_time_ms=0.0,
        )
        original = dna.validate

        def validate_with_z3(action: str):
            return dataclasses.replace(original(action), z3_result=refuted)

        object.__setattr__(dna, "validate", validate_with_z3)
        governed = dna.govern(lambda prompt: "fine")
        with pytest.raises(ConstitutionalViolationError):
            governed("safe")


# ---------------------------------------------------------------------------
# core-research-14: MACI role must be enforced on the governed path
# ---------------------------------------------------------------------------


class TestC43GovernEnforcesMaci:
    def test_forbidden_action_type_is_blocked_before_execution(self) -> None:
        dna = AgentDNA.default(agent_id="p-1", maci_role=MACIRole.PROPOSER)
        calls: list[str] = []

        @dna.govern(action_type="validate")
        def agent(prompt: str) -> str:
            calls.append(prompt)
            return "ok"

        with pytest.raises(Exception, match="MACI"):
            agent("hello")
        assert calls == []

    def test_permitted_action_type_runs(self) -> None:
        dna = AgentDNA.default(agent_id="p-1", maci_role=MACIRole.PROPOSER)
        governed = dna.govern(action_type="propose")(lambda prompt: "ok")
        assert governed("hello") == "ok"

    def test_role_without_action_type_is_rejected_at_decoration(self) -> None:
        dna = AgentDNA.default(agent_id="p-1", maci_role=MACIRole.PROPOSER)
        with pytest.raises(ValueError, match="action_type"):
            dna.govern(lambda prompt: "ok")

    def test_check_maci_remains_public(self) -> None:
        dna = AgentDNA.default(agent_id="p-1", maci_role=MACIRole.PROPOSER)
        with pytest.raises(Exception, match="MACI"):
            dna.check_maci("validate")


# ---------------------------------------------------------------------------
# core-research-5: issuer signature against pinned keys, mandatory expiry
# ---------------------------------------------------------------------------


class TestC43FederatedIssuerTrust:
    def test_unsigned_credential_is_rejected(self) -> None:
        _, public = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [public]})
        with pytest.raises(PermissionError, match="signature"):
            bridge.register_credential(_c43_credential(None))

    def test_p1_credential_signed_by_unpinned_key_is_rejected(self) -> None:
        _, pinned = _c43_issuer()
        attacker, _ = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [pinned]})
        with pytest.raises(PermissionError, match="signature"):
            bridge.register_credential(_c43_credential(attacker))
        assert not bridge.gate("agent-1", org_id="org-a", domain="privacy", now=2.0).allowed

    def test_p1_credential_claiming_other_org_is_rejected(self) -> None:
        signer_a, public_a = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [public_a]})
        with pytest.raises(PermissionError):
            bridge.register_credential(_c43_credential(signer_a, org_id="org-b"))

    def test_bridge_without_pinned_keys_trusts_no_issuer(self) -> None:
        signer, _ = _c43_issuer()
        bridge = FederatedConstitutionBridge()
        with pytest.raises(PermissionError):
            bridge.register_credential(_c43_credential(signer))

    def test_tampered_signed_field_is_rejected(self) -> None:
        signer, public = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [public]})
        signed = _c43_credential(signer)
        widened = dataclasses.replace(signed, domains=("*",))
        with pytest.raises(PermissionError, match="signature"):
            bridge.register_credential(widened)

    def test_status_downgrade_requires_issuer_signature(self) -> None:
        signer, public = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [public]})
        bridge.register_credential(_c43_credential(signer, status=CredentialStatus.PENDING))
        forged = dataclasses.replace(
            _c43_credential(signer, status=CredentialStatus.PENDING, issued_at=2.0),
            status=CredentialStatus.ACTIVE,
        )
        with pytest.raises(PermissionError, match="signature"):
            bridge.renew_credential(forged)

    def test_signed_credential_is_admitted(self) -> None:
        signer, public = _c43_issuer()
        bridge = FederatedConstitutionBridge(issuer_keys={"org-a": [public]})
        bridge.register_credential(_c43_credential(signer))
        assert bridge.gate("agent-1", org_id="org-a", domain="privacy", now=2.0).allowed

    @pytest.mark.parametrize("expires_at", [0.0, 1.0, 0.5])
    def test_credential_without_future_expiry_is_invalid(self, expires_at: float) -> None:
        with pytest.raises(ValueError, match="expires_at"):
            _c43_credential(None, issued_at=1.0, expires_at=expires_at)

    @pytest.mark.parametrize(
        "keys",
        [{"org-a": [b"short"]}, {"": [bytes(32)]}, {"org-a": "not-a-list"}],
    )
    def test_malformed_pinned_keys_are_rejected(self, keys) -> None:
        with pytest.raises(ValueError):
            FederatedConstitutionBridge(issuer_keys=keys)


# ---------------------------------------------------------------------------
# core-research-3: debate roles come from a pinned registry
# ---------------------------------------------------------------------------


class TestC43DebateParticipantRegistry:
    def test_proposer_cannot_challenge_own_proposal(self) -> None:
        resolver = DebateResolver(participants={"mallory": [DebateRole.CHALLENGER]})
        resolver.propose("p", "mallory", "safety", "content")
        with pytest.raises(PermissionError, match="proposer"):
            resolver.challenge("p", "mallory", "self objection", severity=0.05)

    def test_self_debate_cannot_approve(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p", "mallory", "safety", "content")
        with pytest.raises(PermissionError):
            resolver.challenge("p", "mallory", "weak", severity=0.05)
        for _ in range(3):
            resolver.defend("p", "mallory", "rebuttal")
        assert resolver.resolve("p").outcome is VerdictOutcome.DEADLOCK

    def test_p1_unregistered_challenger_is_rejected(self) -> None:
        resolver = DebateResolver(participants={"v-1": [DebateRole.CHALLENGER]})
        resolver.propose("p", "m-1", "safety", "content")
        with pytest.raises(PermissionError, match="registered"):
            resolver.challenge("p", "sybil-1", "objection", severity=0.05)

    def test_unregistered_defender_is_rejected(self) -> None:
        resolver = DebateResolver(participants={"v-1": [DebateRole.CHALLENGER]})
        resolver.propose("p", "m-1", "safety", "content")
        resolver.challenge("p", "v-1", "objection", severity=0.1)
        with pytest.raises(PermissionError, match="defend"):
            resolver.defend("p", "sock-puppet", "rebuttal")
        resolver.defend("p", "m-1", "rebuttal")

    def test_registered_defender_may_defend(self) -> None:
        resolver = DebateResolver(
            participants={"v-1": [DebateRole.CHALLENGER], "d-1": [DebateRole.DEFENDER]}
        )
        resolver.propose("p", "m-1", "safety", "content")
        resolver.challenge("p", "v-1", "objection", severity=0.1)
        resolver.defend("p", "d-1", "rebuttal")

    def test_auto_challenge_is_recorded_but_never_counted(self) -> None:
        resolver = DebateResolver(participants={"v-1": [DebateRole.CHALLENGER]})
        resolver.propose("p", "m-1", "safety", "content")
        resolver.challenge("p", AUTO_CHALLENGER_ID, "synthetic", severity=0.1)
        resolver.defend("p", "m-1", "rebuttal")
        verdict = resolver.resolve("p")
        assert verdict.outcome is VerdictOutcome.DEADLOCK
        record = resolver.get_record("p")
        assert record is not None and len(record.challenges) == 1

    def test_auto_challenger_id_cannot_be_registered(self) -> None:
        with pytest.raises(ValueError):
            DebateResolver(participants={AUTO_CHALLENGER_ID: [DebateRole.CHALLENGER]})
        resolver = DebateResolver()
        with pytest.raises(ValueError):
            resolver.register_participant(AUTO_CHALLENGER_ID, DebateRole.CHALLENGER)

    def test_verify_transcript_detects_resolution_state(self) -> None:
        resolver = DebateResolver(participants={"v-1": [DebateRole.CHALLENGER]})
        resolver.propose("p", "m-1", "safety", "content")
        resolver.challenge("p", "v-1", "objection", severity=0.3)
        assert resolver.verify_transcript("p") is False
        resolver.resolve("p")
        assert resolver.verify_transcript("p") is True
        with pytest.raises(KeyError):
            resolver.verify_transcript("missing")


# ---------------------------------------------------------------------------
# core-research-2 / core-research-11: MacAcgsLoop must not self-approve
# ---------------------------------------------------------------------------


class TestC43MacAcgsLoopNoSelfApproval:
    def test_default_config_disables_synthetic_debate(self) -> None:
        config = MacAcgsConfig()
        assert config.auto_challenge is False
        assert config.auto_defend is False

    def test_default_loop_does_not_approve_without_real_challenge(self) -> None:
        loop = MacAcgsLoop(came=_c43_came(["rule"]))
        loop.add_external_challenger("human-reviewer-1")
        result = loop.run_cycle([])
        assert result.proposals_approved == 0
        assert result.constitution_updates == []

    def test_opt_in_auto_pair_cannot_approve(self) -> None:
        config = MacAcgsConfig(auto_challenge=True, auto_defend=True)
        loop = MacAcgsLoop(config=config, came=_c43_came(["rule"]))
        loop.add_external_challenger("human-reviewer-1")
        result = loop.run_cycle([])
        assert result.proposals_approved == 0

    def test_synthetic_challenge_is_not_attributed_to_registered_reviewer(self) -> None:
        resolver = DebateResolver()
        config = MacAcgsConfig(auto_challenge=True)
        loop = MacAcgsLoop(config=config, came=_c43_came(["rule"]), debate=resolver)
        loop.add_external_challenger("human-reviewer-1")
        loop.run_cycle([])
        (pid,) = resolver.resolved_proposals()
        record = resolver.get_record(pid)
        assert record is not None
        assert {c.challenger_id for c in record.challenges} == {AUTO_CHALLENGER_ID}

    def test_registered_external_challenge_can_approve(self) -> None:
        config = MacAcgsConfig(auto_defend=True)
        loop = MacAcgsLoop(
            config=config,
            came=_c43_came(["rule"]),
            challenge_provider=lambda proposal: [
                ("human-reviewer-1", f"review of {proposal.proposal_id}", 0.1)
            ],
        )
        loop.add_external_challenger("human-reviewer-1")
        result = loop.run_cycle([])
        assert result.proposals_approved == 1

    def test_challenge_provider_cannot_use_unregistered_identity(self) -> None:
        loop = MacAcgsLoop(
            came=_c43_came(["rule"]),
            challenge_provider=lambda proposal: [("ghost", "objection", 0.1)],
        )
        with pytest.raises(PermissionError):
            loop.run_cycle([])

    @pytest.mark.parametrize(
        ("provider", "error"),
        [
            (lambda proposal: [("ghost", "objection", 0.1)], PermissionError),
            (lambda proposal: (_ for _ in ()).throw(LookupError("queue down")), LookupError),
        ],
    )
    def test_challenge_provider_failure_is_audited_before_reraise(
        self, provider, error: type[Exception]
    ) -> None:
        loop = MacAcgsLoop(came=_c43_came(["rule"]), challenge_provider=provider)
        with pytest.raises(error):
            loop.run_cycle([])
        aborted = [e for e in loop.audit_log() if e["event_type"] == "cycle_aborted"]
        assert len(aborted) == 1
        assert aborted[0]["cycle_number"] == 1
        assert aborted[0]["details"]["error_type"] == error.__name__
        assert aborted[0]["details"]["proposal_id"].startswith("mac-1-0-")
        assert loop.constitution_updates() == []

    def test_p1_injected_debate_with_other_hash_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="hash"):
            MacAcgsLoop(
                came=_c43_came([]),
                debate=DebateResolver(constitutional_hash="other-constitution"),
            )

    def test_hash_gate_checks_debate_resolver(self) -> None:
        loop = MacAcgsLoop(came=_c43_came(["rule"]))
        loop._debate._constitutional_hash = "drifted"  # simulate post-construction drift
        result = loop.run_cycle([])
        assert result.hash_verified is False
        assert result.proposals_opened == 0
