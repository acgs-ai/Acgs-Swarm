"""Regression guards for the 2026-06 deep security scan findings.

These tests encode the attacker-controlled inputs and broken controls from the
validated scan report so future changes cannot reintroduce them.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.bittensor.axon_server import MinerAxonServer
from constitutional_swarm.bittensor.chain_anchor import ChainAnchor, ProofEvidence
from constitutional_swarm.bittensor.compliance_certificate import (
    AuditPeriod,
    CertificateIssuer,
    CertificateStatus,
    ComplianceSnapshot,
)
from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionReceiver,
    ConstitutionSyncMessage,
)
from constitutional_swarm.bittensor.nmc_protocol import NMCSession, SynthesisMethod
from constitutional_swarm.gossip_protocol import GossipServer
from constitutional_swarm.governed_handoff import DENY, PolicyEngine
from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.private_vote import BallotChoice, build_commit, tally
from constitutional_swarm.quorum_certificate import (
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    build_vote_message,
    verify_certificate,
)
from constitutional_swarm.swe_bench import run_one_by_one
from constitutional_swarm.validator_set import ValidatorIdentity, ValidatorSet


def _pubkey_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_quorum_certificate_rejects_embedded_attacker_public_key() -> None:
    """Verifier must use registered validator keys, not certificate-supplied keys."""
    registered_sk = Ed25519PrivateKey.generate()
    attacker_sk = Ed25519PrivateKey.generate()
    attacker_pk = _pubkey_bytes(attacker_sk)
    msg = build_vote_message("assignment", "artifact", 1)
    forged_vote = SignedVote(
        voter_id="validator-1",
        assignment_id="assignment",
        artifact_hash="artifact",
        epoch=1,
        signature=attacker_sk.sign(msg),
        public_key_bytes=attacker_pk,
    )
    qc = QuorumCertificate(
        assignment_id="assignment",
        artifact_hash="artifact",
        epoch=1,
        votes=(forged_vote,),
        threshold_weight=1.0,
        achieved_weight=1.0,
    )
    validators = ValidatorSet(
        [
            ValidatorIdentity(
                "validator-1",
                stake=1.0,
                public_key_bytes=_pubkey_bytes(registered_sk),
            )
        ]
    )

    with pytest.raises(InvalidCertificateError, match="public key"):
        verify_certificate(qc, validator_set=validators)


def test_quorum_certificate_rejects_under_threshold_serialized_certificate() -> None:
    sk = Ed25519PrivateKey.generate()
    pk = _pubkey_bytes(sk)
    vote = SignedVote(
        voter_id="validator-1",
        assignment_id="assignment",
        artifact_hash="artifact",
        epoch=1,
        signature=sk.sign(build_vote_message("assignment", "artifact", 1)),
        public_key_bytes=pk,
    )
    qc = QuorumCertificate(
        assignment_id="assignment",
        artifact_hash="artifact",
        epoch=1,
        votes=(vote,),
        threshold_weight=2.0,
        achieved_weight=0.1,
    )
    validators = ValidatorSet(
        [
            ValidatorIdentity("validator-1", stake=1.0, public_key_bytes=pk),
            ValidatorIdentity("validator-2", stake=1.0),
            ValidatorIdentity("validator-3", stake=1.0),
        ]
    )

    with pytest.raises(InvalidCertificateError, match="threshold"):
        verify_certificate(qc, validator_set=validators)


@pytest.mark.asyncio
async def test_gossip_server_requires_authentication_by_default() -> None:
    server = GossipServer(MerkleCRDT("server"), host="127.0.0.1", port=0)
    with pytest.raises(ValueError, match="secret_token"):
        await server.start()


def test_swe_bench_run_id_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="run_id"):
        run_one_by_one._run_dir("../escape")


def test_swe_bench_patch_save_rejects_instance_id_path_traversal(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(run_one_by_one, "_DEFAULT_RUN_ROOT", tmp_path / "runs")
    with pytest.raises(ValueError, match="instance_id"):
        run_one_by_one._save_patch("safe-run", "../../owned", "diff --git a/x b/x")


def test_governed_handoff_denies_interpreter_commands_even_if_allowlisted() -> None:
    policy = PolicyEngine(
        constitution={},
        swarm={"policies": {"command_allowlist": ["python", "pytest"]}},
        repo_root=Path("."),
    )
    decision = policy.decide("tool_call", "python -c pass")
    assert decision.outcome == DENY
    assert "interpreter" in decision.reason


def _commitment(judgment: str, nonce: str) -> str:
    return hashlib.sha256(f"{judgment}:{nonce}".encode()).hexdigest()


def test_nmc_rejects_commitments_from_miners_outside_required_set() -> None:
    session = NMCSession("case", required_miners={"m1", "m2"})
    with pytest.raises(ValueError, match="not required"):
        session.accept_commitment("outsider", _commitment("deny", "n"))


def test_nmc_rejects_untrusted_reveal_weight() -> None:
    session = NMCSession("case", required_miners={"m1", "m2"}, miner_weights={"m1": 1.0, "m2": 2.0})
    session.accept_commitment("m1", _commitment("allow", "n1"))
    session.accept_commitment("m2", _commitment("deny", "n2"))
    session.accept_reveal("m1", "allow", "n1", weight=999.0)
    session.accept_reveal("m2", "deny", "n2", weight=1.0)

    consensus = session.synthesize(SynthesisMethod.WEIGHTED_VOTE)

    assert consensus.judgment_text == "deny"


def test_nmc_defaults_to_equal_weights_when_no_trusted_weight_map() -> None:
    session = NMCSession("case", required_miners={"m1", "m2"})
    session.accept_commitment("m1", _commitment("allow", "n1"))
    session.accept_commitment("m2", _commitment("deny", "n2"))
    session.accept_reveal("m1", "allow", "n1", weight=999.0)
    session.accept_reveal("m2", "deny", "n2", weight=1.0)

    consensus = session.synthesize(SynthesisMethod.WEIGHTED_VOTE)

    assert consensus.confidence == 0.5


def test_axon_blacklist_and_priority_fail_closed_without_trusted_hotkey() -> None:
    server = MinerAxonServer(
        SimpleNamespace(constitution_hash="const"),
        trusted_validator_hotkeys={"validator-good"},
    )
    attacker = SimpleNamespace(
        impact_score=999.0,
        dendrite=SimpleNamespace(hotkey="validator-evil"),
    )
    trusted = SimpleNamespace(
        impact_score=4.0,
        dendrite=SimpleNamespace(hotkey="validator-good"),
    )

    assert server.blacklist(attacker) is True
    assert server.priority(attacker) == 0.0
    assert server.blacklist(trusted) is False
    assert server.priority(trusted) == 4.0


def test_constitution_sync_rejects_unsigned_message_by_default() -> None:
    yaml_content = "constitutional_hash: attacker\n"
    msg = ConstitutionSyncMessage(
        version_id="v-attacker",
        expected_hash=hashlib.sha256(yaml_content.encode()).hexdigest()[:16],
        yaml_content=yaml_content,
        issued_at=time.time(),
        issuer_id="attacker",
    )
    receiver = ConstitutionReceiver("miner-1")

    result = receiver.apply(msg)

    assert result.success is False
    assert "signature" in result.message.lower() or "transition" in result.message.lower()


def test_chain_anchor_membership_binds_proof_id_and_vote_hashes() -> None:
    proof = ProofEvidence(
        proof_id="proof-1",
        root_hash="root",
        content_hash="content",
        vote_hashes=("vote-a",),
        constitutional_hash="const",
    )
    anchor = ChainAnchor("const", batch_size=1)
    record = anchor.add_proof(proof)
    assert record is not None
    substituted = ProofEvidence(
        proof_id="proof-2",
        root_hash="root",
        content_hash="content",
        vote_hashes=("vote-b",),
        constitutional_hash="const",
    )

    assert record.verify_membership(substituted) is False


def _snapshot() -> ComplianceSnapshot:
    return ComplianceSnapshot(
        total_decisions=100,
        passed_decisions=100,
        escalated_decisions=0,
        auto_resolved_decisions=0,
        constitutional_hash="const",
    )


def test_compliance_certificate_proof_binds_subject_and_period() -> None:
    issuer = CertificateIssuer(issuer_id="issuer", secret_key="secret")
    cert = issuer.issue(
        "subject-a",
        AuditPeriod(start_at=1.0, end_at=2.0, label="p1"),
        _snapshot(),
        threshold=1.0,
    )
    replayed = dataclasses.replace(
        cert,
        subject_id="subject-b",
        period=AuditPeriod(start_at=3.0, end_at=4.0, label="p2"),
    )

    assert issuer.verify(replayed) is False


def test_compliance_certificate_verifier_rejects_revoked_status_copy() -> None:
    issuer = CertificateIssuer(issuer_id="issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(start_at=1.0, end_at=2.0), _snapshot())
    revoked_copy = dataclasses.replace(cert, status=CertificateStatus.REVOKED)

    assert issuer.verify(revoked_copy) is False


def test_private_vote_rejects_same_voter_key_with_rotated_nullifier() -> None:
    sk = Ed25519PrivateKey.generate()
    c1, r1 = build_commit(
        voter_private_key=sk,
        voter_secret=b"secret-a",
        epoch=b"epoch",
        subject=b"subject",
        choice=BallotChoice.YEA,
    )
    c2, r2 = build_commit(
        voter_private_key=sk,
        voter_secret=b"secret-b",
        epoch=b"epoch",
        subject=b"subject",
        choice=BallotChoice.YEA,
    )

    result = tally([c1, c2], [r1, r2], epoch=b"epoch", subject=b"subject")

    assert len(result.accepted) == 1
    assert any(reason == "duplicate voter" for _, reason in result.rejected)
