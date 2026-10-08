"""Regression coverage for C5 durable audit and certificate hardening."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from collections.abc import Callable

import pytest

from constitutional_swarm.bittensor.arweave_audit_log import (
    ArweaveAuditLogger,
    AuditBatch,
    AuditDecisionType,
    AuditLogEntry,
    InMemoryArweaveClient,
)
from constitutional_swarm.bittensor.chain_anchor import ChainAnchor, ProofEvidence
from constitutional_swarm.bittensor.compliance_certificate import (
    AuditPeriod,
    CertificateIssuer,
    ComplianceCertificate,
    ComplianceSnapshot,
    HashCommitmentProver,
    HMACProver,
    ZKPStubProver,
    _certificate_payload,
)


CONST_HASH = "608508a9bd224290"


def _proof(proof_id: str) -> ProofEvidence:
    return ProofEvidence(
        proof_id=proof_id,
        root_hash=f"root-{proof_id}",
        content_hash=f"content-{proof_id}",
        vote_hashes=(f"vote-{proof_id}",),
        constitutional_hash=CONST_HASH,
    )


def _entry(entry_id: str) -> AuditLogEntry:
    return AuditLogEntry(
        entry_id=entry_id,
        case_id=f"case-{entry_id}",
        constitutional_hash=CONST_HASH,
        decision_type=AuditDecisionType.ESCALATED,
        compliance_passed=True,
    )


def _snapshot(**overrides: object) -> ComplianceSnapshot:
    values: dict[str, object] = {
        "total_decisions": 100,
        "passed_decisions": 99,
        "escalated_decisions": 4,
        "auto_resolved_decisions": 3,
        "constitutional_hash": CONST_HASH,
    }
    values.update(overrides)
    return ComplianceSnapshot(**values)  # type: ignore[arg-type]


class CallbackSubmitter:
    def __init__(self, callback: Callable[[str, str, int, int], int]) -> None:
        self.callback = callback
        self.calls: list[tuple[str, str, int]] = []

    def submit(self, batch_root: str, constitutional_hash: str, proof_count: int) -> int:
        self.calls.append((batch_root, constitutional_hash, proof_count))
        return self.callback(batch_root, constitutional_hash, proof_count, len(self.calls))


class AmbiguousUploadClient(InMemoryArweaveClient):
    def __init__(self) -> None:
        super().__init__()
        self.payloads: list[bytes] = []
        self._fail_once = True

    def upload(self, data: bytes, tags: dict[str, str] | None = None) -> str:
        self.payloads.append(data)
        tx_id = super().upload(data, tags)
        if self._fail_once:
            self._fail_once = False
            raise RuntimeError("ambiguous phase 1 response")
        return tx_id


class FailingUploadClient(InMemoryArweaveClient):
    def __init__(self) -> None:
        super().__init__()
        self.fail = True

    def upload(self, data: bytes, tags: dict[str, str] | None = None) -> str:
        if self.fail:
            raise RuntimeError("upload unavailable")
        return super().upload(data, tags)


class RevokingHMACProver(HMACProver):
    def __init__(self, secret_key: str) -> None:
        super().__init__(secret_key)
        self.on_verify: Callable[[], None] = lambda: None

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        self.on_verify()
        return super().verify_certificate(cert)


class IssuerMutatingProver:
    def prove(
        self,
        _snapshot: ComplianceSnapshot,
        _threshold: float,
        _constitutional_hash: str,
    ) -> str:
        return "opaque-proof"

    def verify(
        self,
        _proof: str,
        _snapshot: ComplianceSnapshot,
        _threshold: float,
        _constitutional_hash: str,
    ) -> bool:
        return True

    def prove_certificate(self, _cert: ComplianceCertificate) -> str:
        return "opaque-proof"

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        object.__setattr__(cert, "issuer_id", "other-issuer")
        return True


def test_chain_failure_keeps_stable_stage_and_later_suffix() -> None:
    anchor: ChainAnchor

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, call: int
    ) -> int:
        if call <= 2:
            raise RuntimeError("RPC failure")
        return 100 + call

    submitter = CallbackSubmitter(submit)
    anchor = ChainAnchor(CONST_HASH, submitter=submitter, batch_size=10)
    anchor.add_proof(_proof("first"))
    anchor.add_proof(_proof("second"))

    with pytest.raises(RuntimeError, match="RPC failure"):
        anchor.flush()

    anchor.add_proof(_proof("suffix"))
    assert anchor.pending_count == 3
    with pytest.raises(RuntimeError, match="RPC failure"):
        anchor.flush()
    retry = anchor.flush()
    assert retry is not None
    assert retry.proof_count == 2
    assert retry.proof_ids == ("first", "second")
    assert submitter.calls[0] == submitter.calls[1]
    assert anchor.pending_count == 1

    suffix = anchor.flush()
    assert suffix is not None
    assert suffix.proof_ids == ("suffix",)
    assert anchor.pending_count == 0
    assert len(anchor.anchor_history) == 2


@pytest.mark.parametrize("batch_size", [0, -1, True])
def test_batch_writers_reject_nonpositive_or_nonintegral_size(batch_size: object) -> None:
    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        ChainAnchor(CONST_HASH, batch_size=batch_size)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        ArweaveAuditLogger(
            CONST_HASH,
            arweave_client=InMemoryArweaveClient(),
            batch_size=batch_size,  # type: ignore[arg-type]
        )


def test_chain_producer_progresses_while_submit_is_blocked_and_overlap_fails() -> None:
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, _call: int
    ) -> int:
        entered.set()
        assert release.wait(timeout=5)
        return 22

    anchor = ChainAnchor(CONST_HASH, submitter=CallbackSubmitter(submit), batch_size=2)
    anchor.add_proof(_proof("staged"))

    def run_flush() -> None:
        try:
            anchor.flush()
        except BaseException as exc:  # pragma: no cover - assertion reports unexpected errors
            errors.append(exc)

    flush_thread = threading.Thread(target=run_flush)
    flush_thread.start()
    assert entered.wait(timeout=5)

    def add_suffix() -> None:
        anchor.add_proof(_proof("suffix-1"))
        anchor.add_proof(_proof("suffix-2"))

    producer = threading.Thread(target=add_suffix)
    producer.start()
    producer.join(timeout=5)
    assert not producer.is_alive()
    with pytest.raises(RuntimeError, match="flush already in progress"):
        anchor.flush()

    release.set()
    flush_thread.join(timeout=5)
    assert not flush_thread.is_alive()
    assert errors == []
    assert len(anchor.anchor_history) == 1
    assert anchor.pending_count == 2
    suffix = anchor.flush()
    assert suffix is not None
    assert suffix.proof_ids == ("suffix-1", "suffix-2")
    assert anchor.pending_count == 0
    assert len(anchor.anchor_history) == 2


def test_chain_auto_flush_transport_failure_is_staged_and_observable() -> None:
    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, call: int
    ) -> int:
        if call <= 2:
            raise RuntimeError("RPC unavailable")
        return 42

    submitter = CallbackSubmitter(submit)
    anchor = ChainAnchor(CONST_HASH, submitter=submitter, batch_size=1)

    assert anchor.add_proof(_proof("accepted-once")) is None
    assert anchor.pending_count == 1
    assert isinstance(anchor.last_flush_error, RuntimeError)
    assert str(anchor.last_flush_error) == "RPC unavailable"

    with pytest.raises(RuntimeError, match="RPC unavailable"):
        anchor.flush()
    assert anchor.pending_count == 1
    assert isinstance(anchor.last_flush_error, RuntimeError)

    record = anchor.flush()
    assert record is not None
    assert record.proof_ids == ("accepted-once",)
    assert anchor.pending_count == 0
    assert anchor.last_flush_error is None
    assert len(anchor.anchor_history) == 1


def test_chain_auto_flush_does_not_reenter_active_flush() -> None:
    anchor: ChainAnchor

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, _call: int
    ) -> int:
        assert anchor.add_proof(_proof("suffix")) is None
        return 17

    anchor = ChainAnchor(CONST_HASH, submitter=CallbackSubmitter(submit), batch_size=2)
    anchor.add_proof(_proof("first"))
    record = anchor.add_proof(_proof("second"))

    assert record is not None
    assert record.proof_ids == ("first", "second")
    assert anchor.pending_count == 1


def test_explicit_reentrant_chain_flush_fails_loudly() -> None:
    anchor: ChainAnchor

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, _call: int
    ) -> int:
        anchor.flush()
        return 1

    anchor = ChainAnchor(CONST_HASH, submitter=CallbackSubmitter(submit), batch_size=10)
    anchor.add_proof(_proof("first"))

    with pytest.raises(RuntimeError, match="flush already in progress"):
        anchor.flush()
    assert anchor.pending_count == 1
    assert anchor.anchor_history == []


def test_arweave_phase2_retry_commits_only_staged_prefix() -> None:
    logger: ArweaveAuditLogger

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, call: int
    ) -> int:
        if call <= 2:
            raise RuntimeError("phase 2 failure")
        return 500 + call

    client = InMemoryArweaveClient()
    submitter = CallbackSubmitter(submit)
    logger = ArweaveAuditLogger(
        CONST_HASH,
        arweave_client=client,
        chain_submitter=submitter,
        batch_size=10,
    )
    logger.add_entry(_entry("first"))
    logger.add_entry(_entry("second"))

    with pytest.raises(RuntimeError, match="phase 2 failure"):
        logger.flush()

    logger.add_entry(_entry("suffix"))
    assert logger.pending_count == 3
    with pytest.raises(RuntimeError, match="phase 2 failure"):
        logger.flush()
    retry = logger.flush()
    assert retry is not None
    assert retry.entry_count == 2
    assert submitter.calls[0] == submitter.calls[1]
    assert client.transaction_count == 1
    assert logger.pending_count == 1

    suffix = logger.flush()
    assert suffix is not None
    assert suffix.entry_count == 1
    assert logger.pending_count == 0
    assert len(logger.receipts) == 2


def test_arweave_producer_progresses_while_submit_is_blocked_and_overlap_fails() -> None:
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, _call: int
    ) -> int:
        entered.set()
        assert release.wait(timeout=5)
        return 33

    logger = ArweaveAuditLogger(
        CONST_HASH,
        arweave_client=InMemoryArweaveClient(),
        chain_submitter=CallbackSubmitter(submit),
        batch_size=2,
    )
    logger.add_entry(_entry("staged"))

    def run_flush() -> None:
        try:
            logger.flush()
        except BaseException as exc:  # pragma: no cover - assertion reports unexpected errors
            errors.append(exc)

    flush_thread = threading.Thread(target=run_flush)
    flush_thread.start()
    assert entered.wait(timeout=5)

    def add_suffix() -> None:
        logger.add_entry(_entry("suffix-1"))
        logger.add_entry(_entry("suffix-2"))

    producer = threading.Thread(target=add_suffix)
    producer.start()
    producer.join(timeout=5)
    assert not producer.is_alive()
    with pytest.raises(RuntimeError, match="flush already in progress"):
        logger.flush()

    release.set()
    flush_thread.join(timeout=5)
    assert not flush_thread.is_alive()
    assert errors == []
    assert len(logger.receipts) == 1
    assert logger.pending_count == 2
    suffix = logger.flush()
    assert suffix is not None
    assert suffix.entry_count == 2
    assert logger.pending_count == 0
    assert len(logger.receipts) == 2


def test_arweave_auto_flush_transport_failure_is_staged_and_observable() -> None:
    client = FailingUploadClient()
    logger = ArweaveAuditLogger(CONST_HASH, arweave_client=client, batch_size=1)

    assert logger.add_entry(_entry("accepted-once")) is None
    assert logger.pending_count == 1
    assert isinstance(logger.last_flush_error, RuntimeError)
    assert str(logger.last_flush_error) == "upload unavailable"

    with pytest.raises(RuntimeError, match="upload unavailable"):
        logger.flush()
    assert logger.pending_count == 1
    assert isinstance(logger.last_flush_error, RuntimeError)

    client.fail = False
    receipt = logger.flush()
    assert receipt is not None
    assert receipt.entry_count == 1
    assert logger.pending_count == 0
    assert logger.last_flush_error is None
    assert len(logger.receipts) == 1


def test_arweave_auto_phase2_failure_reuses_upload_without_duplicate_entry() -> None:
    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, call: int
    ) -> int:
        if call == 1:
            raise RuntimeError("chain unavailable")
        return 88

    client = InMemoryArweaveClient()
    logger = ArweaveAuditLogger(
        CONST_HASH,
        arweave_client=client,
        chain_submitter=CallbackSubmitter(submit),
        batch_size=1,
    )

    assert logger.add_entry(_entry("accepted-once")) is None
    assert logger.pending_count == 1
    assert client.transaction_count == 1
    assert isinstance(logger.last_flush_error, RuntimeError)

    receipt = logger.flush()
    assert receipt is not None
    assert receipt.entry_count == 1
    assert logger.pending_count == 0
    assert client.transaction_count == 1
    assert logger.last_flush_error is None


def test_arweave_phase1_retry_reuses_identical_staged_payload() -> None:
    client = AmbiguousUploadClient()
    logger = ArweaveAuditLogger(CONST_HASH, arweave_client=client, batch_size=10)
    logger.add_entry(_entry("first"))
    logger.add_entry(_entry("second"))

    with pytest.raises(RuntimeError, match="ambiguous phase 1 response"):
        logger.flush()

    logger.add_entry(_entry("suffix"))
    receipt = logger.flush()
    assert receipt is not None
    assert receipt.entry_count == 2
    assert client.payloads[0] == client.payloads[1]
    assert json.loads(client.payloads[0])["batch_id"] == receipt.batch_id
    assert logger.pending_count == 1


def test_empty_audit_batch_cannot_claim_full_compliance() -> None:
    batch = AuditBatch("empty", CONST_HASH, [])

    with pytest.raises(ValueError, match="requires at least one entry"):
        batch.compliance_rate()


def test_explicit_reentrant_arweave_flush_fails_loudly() -> None:
    logger: ArweaveAuditLogger

    def submit(
        _root: str, _constitutional_hash: str, _proof_count: int, _call: int
    ) -> int:
        logger.flush()
        return 1

    logger = ArweaveAuditLogger(
        CONST_HASH,
        arweave_client=InMemoryArweaveClient(),
        chain_submitter=CallbackSubmitter(submit),
        batch_size=10,
    )
    logger.add_entry(_entry("first"))

    with pytest.raises(RuntimeError, match="flush already in progress"):
        logger.flush()
    assert logger.pending_count == 1
    assert logger.receipts == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_decisions", 0),
        ("total_decisions", True),
        ("passed_decisions", -1),
        ("passed_decisions", 101),
        ("escalated_decisions", -1),
        ("escalated_decisions", 101),
        ("auto_resolved_decisions", -1),
        ("auto_resolved_decisions", 101),
    ],
)
def test_snapshot_requires_real_bounded_integral_evidence(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _snapshot(**{field: value})


@pytest.mark.parametrize(
    ("start_at", "end_at"),
    [(0.0, 0.0), (2.0, 1.0), (math.nan, 1.0), (0.0, math.inf)],
)
def test_audit_period_requires_positive_finite_window(start_at: float, end_at: float) -> None:
    with pytest.raises(ValueError):
        AuditPeriod(start_at=start_at, end_at=end_at)


@pytest.mark.parametrize("threshold", [-0.1, 1.1, math.nan, math.inf])
def test_issuer_rejects_invalid_threshold(threshold: float) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    with pytest.raises(ValueError, match="threshold must"):
        issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=threshold)


@pytest.mark.parametrize("valid_for_days", [0, -1, math.nan, math.inf])
def test_issuer_rejects_nonpositive_or_nonfinite_lifetime(valid_for_days: float) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    with pytest.raises(ValueError, match="valid_for_days must"):
        issuer.issue(
            "subject",
            AuditPeriod(1.0, 2.0),
            _snapshot(),
            threshold=0.9,
            valid_for_days=valid_for_days,  # type: ignore[arg-type]
        )


def test_fresh_verifier_requires_trusted_revocation_evidence() -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    fresh = CertificateIssuer("issuer", secret_key="secret")

    assert fresh.verify(cert) is False
    assert fresh.verify(cert, revoked_certificate_ids=frozenset()) is True

    issuer.revoke(cert.cert_id)
    exported = issuer.revoked_certificate_ids
    assert isinstance(exported, frozenset)
    assert cert.cert_id in exported
    assert issuer.verify(cert, revoked_certificate_ids=frozenset()) is False
    assert fresh.verify(cert, revoked_certificate_ids=exported) is False


@pytest.mark.parametrize("revocations", ["cert-id", b"cert-id"])
def test_revocation_evidence_rejects_scalar_text(revocations: object) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    fresh = CertificateIssuer("issuer", secret_key="secret")

    with pytest.raises(TypeError, match="revoked_certificate_ids"):
        fresh.verify(cert, revoked_certificate_ids=revocations)  # type: ignore[arg-type]


@pytest.mark.parametrize("revocations", [{1}, {""}, {"  "}])
def test_revocation_evidence_rejects_invalid_set_members(revocations: set[object]) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    fresh = CertificateIssuer("issuer", secret_key="secret")

    with pytest.raises(TypeError, match="non-empty strings"):
        fresh.verify(cert, revoked_certificate_ids=revocations)  # type: ignore[arg-type]


def test_verifier_rejects_same_key_certificate_from_different_issuer() -> None:
    issuer = CertificateIssuer("issuer-a", secret_key="shared-secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    verifier = CertificateIssuer("issuer-b", secret_key="shared-secret")

    assert verifier.verify(cert, revoked_certificate_ids=frozenset()) is False


def test_verifier_rechecks_issuer_identity_after_custom_proof_verification() -> None:
    issuer = CertificateIssuer("issuer", prover=IssuerMutatingProver())
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)

    assert issuer.verify(cert) is False


@pytest.mark.parametrize("field", ["period", "snapshot"])
def test_issuer_verify_returns_false_for_malformed_certificate_graph(field: str) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    object.__setattr__(cert, field, None)

    assert issuer.verify(cert) is False


@pytest.mark.parametrize(
    "prover",
    [HMACProver("secret"), ZKPStubProver(), HashCommitmentProver("secret")],
)
@pytest.mark.parametrize("field", ["period", "snapshot"])
def test_builtin_prover_verify_returns_false_for_malformed_certificate_graph(
    prover: object, field: str
) -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    object.__setattr__(cert, field, None)

    assert prover.verify_certificate(cert) is False  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "prover",
    [HMACProver("secret"), ZKPStubProver(), HashCommitmentProver("secret")],
)
def test_issuer_verify_rejects_non_ascii_proof_text(prover: object) -> None:
    issuer = CertificateIssuer("issuer", prover=prover)  # type: ignore[arg-type]
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    assert issuer.verify(cert) is True

    object.__setattr__(cert, "proof", "é")

    assert issuer.verify(cert) is False


@pytest.mark.parametrize(
    "prover",
    [HMACProver("secret"), ZKPStubProver(), HashCommitmentProver("secret")],
)
def test_builtin_certificate_verifier_rejects_non_ascii_proof_text(prover: object) -> None:
    issuer = CertificateIssuer("issuer", prover=prover)  # type: ignore[arg-type]
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    assert prover.verify_certificate(cert) is True  # type: ignore[attr-defined]

    object.__setattr__(cert, "proof", "é")

    assert prover.verify_certificate(cert) is False  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "prover",
    [HMACProver("secret"), ZKPStubProver(), HashCommitmentProver("secret")],
)
@pytest.mark.parametrize("invalid_proof", ["é", b"proof", 7, None])
def test_builtin_legacy_verifier_rejects_malformed_proof_text(
    prover: object, invalid_proof: object
) -> None:
    snapshot = _snapshot()
    valid_proof = prover.prove(snapshot, 0.9, CONST_HASH)  # type: ignore[attr-defined]
    assert prover.verify(valid_proof, snapshot, 0.9, CONST_HASH) is True  # type: ignore[attr-defined]

    assert (
        prover.verify(invalid_proof, snapshot, 0.9, CONST_HASH)  # type: ignore[attr-defined]
        is False
    )


def test_staged_batch_helper_has_dedicated_private_module() -> None:
    from constitutional_swarm.bittensor._staging import _StagedBatch

    assert _StagedBatch.__module__ == "constitutional_swarm.bittensor._staging"


def test_revocation_during_proof_verification_is_observed() -> None:
    prover = RevokingHMACProver("secret")
    issuer = CertificateIssuer("issuer", prover=prover)
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    prover.on_verify = lambda: issuer.revoke(cert.cert_id)

    assert issuer.verify(cert) is False


def test_verifier_rejects_semantically_invalid_forged_certificate() -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    object.__setattr__(cert, "threshold", 2.0)
    forged_proof = hmac.new(b"secret", _certificate_payload(cert), hashlib.sha256).hexdigest()
    object.__setattr__(cert, "proof", forged_proof)

    assert issuer.verify(cert) is False


def test_verifier_rejects_signed_certificate_below_its_threshold() -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    object.__setattr__(cert, "threshold", 1.0)
    forged_proof = hmac.new(b"secret", _certificate_payload(cert), hashlib.sha256).hexdigest()
    object.__setattr__(cert, "proof", forged_proof)

    assert issuer.verify(cert) is False


def test_direct_prover_rejects_semantically_invalid_certificate() -> None:
    issuer = CertificateIssuer("issuer", secret_key="secret")
    cert = issuer.issue("subject", AuditPeriod(1.0, 2.0), _snapshot(), threshold=0.9)
    object.__setattr__(cert, "threshold", -1.0)

    with pytest.raises(ValueError, match="threshold must"):
        HMACProver("secret").prove_certificate(cert)
