"""Compliance Certificate — Phase 2.2: ZKP-ready governance attestation.

Enterprises need to prove their AI systems were governed constitutionally
during a given time window — without revealing what decisions were made.

Two-layer architecture:
  Layer 1 (now):  HMAC-SHA256 signed certificate — production-ready,
                  no external dependency. Verifiable by any party with
                  the shared secret. Used for governance certification
                  and Revenue Stream 2 from day one.

  Layer 2 (Phase 2.3):  ZKP prover (Noir/circom) — proves
                  "compliance_rate ≥ threshold" without revealing
                  individual decisions. Plugged in via ZKProver Protocol.

The ComplianceCertificate is the artifact issued to enterprises after
a governance audit. It records: period, constitutional hash, decision
counts, compliance rate, and the cryptographic proof.

Design:
  • Pluggable prover — swap HMAC for ZKP without changing the API
  • Certificate is immutable once issued
  • Verifier works for both HMAC and ZKP certificates
  • AuditPeriod defines the time window being certified

Roadmap: 08-subnet-implementation-roadmap.md § Phase 2.2
Q&A:     07-subnet-concept-qa-responses.md § 3B
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import time
import uuid
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, ClassVar, Protocol

COMPLIANCE_CERTIFICATE_SECRET_ENV_KEY = "CONSTITUTIONAL_SWARM_COMPLIANCE_CERTIFICATE_SECRET"


def _resolve_compliance_certificate_secret(secret_key: str | None) -> str:
    if secret_key:
        return secret_key

    configured_secret = (os.getenv(COMPLIANCE_CERTIFICATE_SECRET_ENV_KEY) or "").strip()
    if configured_secret:
        return configured_secret

    raise ValueError(
        "Compliance certificate secret is required. Provide secret_key or set "
        f"{COMPLIANCE_CERTIFICATE_SECRET_ENV_KEY}."
    )


# ---------------------------------------------------------------------------
# Certificate types and status
# ---------------------------------------------------------------------------


class ProofType(Enum):
    HMAC_SHA256 = "hmac_sha256"  # current — HMAC signed, no ZKP
    ZKP_STUB = "zkp_stub"  # keyless placeholder — forgeable, testing only
    ZKP_NOIR = "zkp_noir"  # future — Noir ZK-SNARK
    ZKP_CIRCOM = "zkp_circom"  # future — circom/snarkjs


class CertificateStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


# ---------------------------------------------------------------------------
# Audit period
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditPeriod:
    """Time window being certified."""

    start_at: float
    end_at: float
    label: str = ""  # e.g. "Q1-2026", "2026-03"

    def __post_init__(self) -> None:
        _validate_audit_period(self)

    @property
    def duration_days(self) -> float:
        return (self.end_at - self.start_at) / 86_400

    @classmethod
    def last_n_days(cls, n: int, label: str = "") -> AuditPeriod:
        end = time.time()
        return cls(start_at=end - n * 86_400, end_at=end, label=label or f"last-{n}d")

    @classmethod
    def current_month(cls) -> AuditPeriod:
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return cls(
            start_at=start.timestamp(),
            end_at=now.timestamp(),
            label=now.strftime("%Y-%m"),
        )


# ---------------------------------------------------------------------------
# Compliance snapshot (what the certificate attests to)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplianceSnapshot:
    """Summary of governance decisions in the audit period.

    This is the plaintext behind the proof — revealed for HMAC certs,
    hidden for ZKP certs (only the compliance_rate is proven).
    """

    total_decisions: int
    passed_decisions: int
    escalated_decisions: int
    auto_resolved_decisions: int
    constitutional_hash: str
    framework: str = "general"  # e.g. "eu_ai_act", "nist_ai_rmf"

    def __post_init__(self) -> None:
        _validate_snapshot(self)

    @property
    def compliance_rate(self) -> float:
        return self.passed_decisions / self.total_decisions

    @property
    def escalation_rate(self) -> float:
        return self.escalated_decisions / self.total_decisions

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_decisions": self.total_decisions,
            "passed_decisions": self.passed_decisions,
            "escalated_decisions": self.escalated_decisions,
            "auto_resolved_decisions": self.auto_resolved_decisions,
            "compliance_rate": round(self.compliance_rate, 6),
            "escalation_rate": round(self.escalation_rate, 6),
            "constitutional_hash": self.constitutional_hash,
            "framework": self.framework,
        }


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplianceCertificate:
    """Immutable governance compliance certificate.

    Issued by the CertificateIssuer after verifying a ComplianceSnapshot.
    The proof field contains the HMAC or ZKP proving the attestation.

    For HMAC certificates: snapshot data is included and the proof is
    the HMAC of the canonical representation.

    For ZKP certificates: snapshot data may be omitted (private); the
    proof proves "compliance_rate ≥ threshold" without revealing counts.
    """

    cert_id: str
    issued_at: float
    expires_at: float
    issuer_id: str
    subject_id: str  # enterprise/client being certified
    period: AuditPeriod
    snapshot: ComplianceSnapshot
    proof_type: ProofType
    proof: str  # HMAC hex or ZKP proof blob
    threshold: float  # compliance_rate must be ≥ this
    status: CertificateStatus = CertificateStatus.VALID

    def __post_init__(self) -> None:
        _validate_certificate_semantics(self)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.status == CertificateStatus.VALID and not self.is_expired

    @property
    def attests_compliance(self) -> bool:
        """True if the snapshot meets the stated threshold."""
        return self.snapshot.compliance_rate >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "cert_id": self.cert_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "period": {
                "start": self.period.start_at,
                "end": self.period.end_at,
                "label": self.period.label,
            },
            "snapshot": self.snapshot.to_dict(),
            "proof_type": self.proof_type.value,
            "proof": self.proof,
            "threshold": self.threshold,
            "status": self.status.value,
            "is_valid": self.is_valid,
            "attests_compliance": self.attests_compliance,
        }


def _finite_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        numeric = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be a finite number")
    return numeric


def _non_empty_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


def _validate_audit_period(period: AuditPeriod) -> None:
    if not isinstance(period, AuditPeriod):
        raise TypeError("period must be an AuditPeriod")
    start = _finite_number(period.start_at, "period.start_at")
    end = _finite_number(period.end_at, "period.end_at")
    if end <= start:
        raise ValueError("audit period end_at must be greater than start_at")


def _validate_snapshot(snapshot: ComplianceSnapshot) -> None:
    if not isinstance(snapshot, ComplianceSnapshot):
        raise TypeError("snapshot must be a ComplianceSnapshot")
    counts = {
        "total_decisions": snapshot.total_decisions,
        "passed_decisions": snapshot.passed_decisions,
        "escalated_decisions": snapshot.escalated_decisions,
        "auto_resolved_decisions": snapshot.auto_resolved_decisions,
    }
    for name, value in counts.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    if snapshot.total_decisions <= 0:
        raise ValueError("total_decisions must be greater than zero")
    for name in ("passed_decisions", "escalated_decisions", "auto_resolved_decisions"):
        value = counts[name]
        if value < 0 or value > snapshot.total_decisions:
            raise ValueError(f"{name} must be between zero and total_decisions")
    _non_empty_text(snapshot.constitutional_hash, "constitutional_hash")


def _validate_threshold(threshold: object) -> float:
    numeric = _finite_number(threshold, "threshold")
    if numeric < 0 or numeric > 1:
        raise ValueError("threshold must be between zero and one")
    return numeric


def _validate_proof_inputs(
    snapshot: ComplianceSnapshot,
    threshold: float,
    constitutional_hash: str,
) -> None:
    _validate_snapshot(snapshot)
    _validate_threshold(threshold)
    _non_empty_text(constitutional_hash, "constitutional_hash")


def _validate_certificate_semantics(cert: ComplianceCertificate) -> None:
    if not isinstance(cert, ComplianceCertificate):
        raise TypeError("cert must be a ComplianceCertificate")
    _non_empty_text(cert.cert_id, "cert_id")
    _non_empty_text(cert.issuer_id, "issuer_id")
    _non_empty_text(cert.subject_id, "subject_id")
    if not isinstance(cert.proof_type, ProofType):
        raise ValueError("proof_type must be a ProofType")
    if not isinstance(cert.status, CertificateStatus):
        raise ValueError("status must be a CertificateStatus")
    if not isinstance(cert.proof, str):
        raise TypeError("proof must be a string")
    _validate_audit_period(cert.period)
    _validate_snapshot(cert.snapshot)
    issued_at = _finite_number(cert.issued_at, "issued_at")
    expires_at = _finite_number(cert.expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ValueError("expires_at must be greater than issued_at")
    _validate_threshold(cert.threshold)
    if cert.snapshot.compliance_rate < cert.threshold:
        raise ValueError("certificate evidence does not meet threshold")


def _validate_revocation_snapshot(
    revoked_certificate_ids: AbstractSet[str] | None,
) -> frozenset[str] | None:
    if revoked_certificate_ids is None:
        return None
    if isinstance(revoked_certificate_ids, (str, bytes)) or not isinstance(
        revoked_certificate_ids, AbstractSet
    ):
        raise TypeError("revoked_certificate_ids must be a set of non-empty strings")
    if any(
        not isinstance(cert_id, str) or not cert_id.strip()
        for cert_id in revoked_certificate_ids
    ):
        raise TypeError("revoked_certificate_ids must contain only non-empty strings")
    return frozenset(revoked_certificate_ids)


def _proof_text_matches(proof: object, expected: str) -> bool:
    """Timing-safely compare ASCII proof text; reject malformed values."""
    if not isinstance(proof, str) or not isinstance(expected, str):
        return False
    try:
        proof_bytes = proof.encode("ascii")
        expected_bytes = expected.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(proof_bytes, expected_bytes)


def _certificate_payload(cert: ComplianceCertificate) -> bytes:
    """Canonical bytes for certificate-scoped proofs.

    The old HMAC payload covered only the snapshot/threshold.  That let an
    attacker replay a valid proof onto a different subject, period, issuer, or
    status copy.  Bind every semantically attested certificate field except the
    proof itself so verification authenticates the exact certificate presented.
    """

    return json.dumps(
        {
            "cert_id": cert.cert_id,
            "issued_at": cert.issued_at,
            "expires_at": cert.expires_at,
            "issuer_id": cert.issuer_id,
            "subject_id": cert.subject_id,
            "period": {
                "start_at": cert.period.start_at,
                "end_at": cert.period.end_at,
                "label": cert.period.label,
            },
            "snapshot": cert.snapshot.to_dict(),
            "proof_type": cert.proof_type.value,
            "threshold": cert.threshold,
            "status": cert.status.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Prover interface (pluggable)
# ---------------------------------------------------------------------------


class ComplianceProver(Protocol):
    """Protocol for generating compliance proofs.

    ``CertificateIssuer`` only ever uses the certificate-scoped pair
    (``prove_certificate``/``verify_certificate``), which binds subject, period,
    issuer, proof type, and status. Provers lacking it are refused at issuer
    construction; there is no fallback to the snapshot-only legacy pair.

    Implementations should also declare a ``proof_type`` class attribute so the
    issuer can label certificates truthfully.

    Implement for ZKP backends:
        class NoirProver:
            proof_type = ProofType.ZKP_NOIR

            def prove(self, snapshot, threshold, constitutional_hash) -> str: ...
            def verify(self, proof, snapshot, threshold, constitutional_hash) -> bool: ...
            def prove_certificate(self, cert) -> str: ...
            def verify_certificate(self, cert) -> bool: ...
    """

    def prove(
        self,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> str:
        """Generate a proof string for the given snapshot."""
        ...

    def verify(
        self,
        proof: str,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> bool:
        """Verify a proof. Returns True if valid."""
        ...

    def prove_certificate(self, cert: ComplianceCertificate) -> str:
        """Generate a proof bound to every attested certificate field."""
        ...

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        """Verify a certificate-scoped proof. Returns True if valid."""
        ...


class HMACProver:
    """HMAC-SHA256 prover — production-ready, no ZKP dependency.

    Proof = HMAC(key, canonical_payload) where:
      canonical_payload = f"{constitutional_hash}:{compliance_rate:.6f}:{threshold:.4f}"

    Reveals: compliance_rate and all snapshot counts (included in cert).
    Does NOT reveal: individual decision content (only aggregate counts).
    """

    proof_type: ClassVar[ProofType] = ProofType.HMAC_SHA256

    def __init__(self, secret_key: str) -> None:
        self._key = secret_key.encode()

    def prove(
        self,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> str:
        _validate_proof_inputs(snapshot, threshold, constitutional_hash)
        payload = (
            f"{constitutional_hash}:{snapshot.compliance_rate:.6f}:"
            f"{threshold:.4f}:{snapshot.total_decisions}:{snapshot.passed_decisions}:"
            f"{snapshot.escalated_decisions}:{snapshot.auto_resolved_decisions}"
        )
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def verify(
        self,
        proof: str,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> bool:
        try:
            expected = self.prove(snapshot, threshold, constitutional_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(proof, expected)

    def prove_certificate(self, cert: ComplianceCertificate) -> str:
        _validate_certificate_semantics(cert)
        return hmac.new(self._key, _certificate_payload(cert), hashlib.sha256).hexdigest()

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        try:
            expected = self.prove_certificate(cert)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(cert.proof, expected)


class ZKPStubProver:
    """ZKP stub — records circuit inputs for when Noir SDK is available.

    Generates a deterministic placeholder proof from the circuit inputs.
    NOT cryptographically sound — for API compatibility testing only.
    Replace with NoirProver when Noir SDK is integrated.

    The proof is an unkeyed hash of public fields, so anyone can forge it.
    ``CertificateIssuer`` refuses it unless ``allow_insecure_stub=True``.
    """

    proof_type: ClassVar[ProofType] = ProofType.ZKP_STUB
    insecure_stub: ClassVar[bool] = True

    def prove(
        self,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> str:
        _validate_proof_inputs(snapshot, threshold, constitutional_hash)
        # Deterministic stub: hash of circuit inputs (not a real ZKP)
        payload = f"zkp_stub:{constitutional_hash}:{snapshot.compliance_rate:.6f}:{threshold:.4f}"
        return "zkp_stub:" + hashlib.sha256(payload.encode()).hexdigest()

    def verify(
        self,
        proof: str,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> bool:
        try:
            expected = self.prove(snapshot, threshold, constitutional_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(proof, expected)

    def prove_certificate(self, cert: ComplianceCertificate) -> str:
        _validate_certificate_semantics(cert)
        return "zkp_stub:cert:" + hashlib.sha256(
            b"zkp_stub:cert:" + _certificate_payload(cert)
        ).hexdigest()

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        try:
            expected = self.prove_certificate(cert)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(cert.proof, expected)


class HashCommitmentProver:
    """Hash-commitment prover — production-grade, deterministic, tamper-evident.

    Proof = H(secret || constitutional_hash || compliance_rate || threshold || counts)

    This is NOT true zero-knowledge — the verifier needs the secret to
    verify.  However it IS:
      • Deterministic: same inputs always produce the same proof
      • Tamper-evident: any field change invalidates the proof
      • Timing-safe: uses hmac.compare_digest for verification

    For true ZKP (prove "rate >= threshold" without revealing rate),
    integrate the Noir SDK and implement NoirProver.  This prover
    serves as the production bridge until then.
    """

    proof_type: ClassVar[ProofType] = ProofType.HMAC_SHA256

    def __init__(self, secret_key: str | None = None) -> None:
        self._key = _resolve_compliance_certificate_secret(secret_key).encode()

    def prove(
        self,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> str:
        _validate_proof_inputs(snapshot, threshold, constitutional_hash)
        payload = (
            f"commitment:{constitutional_hash}:"
            f"{snapshot.compliance_rate:.6f}:{threshold:.4f}:"
            f"{snapshot.total_decisions}:{snapshot.passed_decisions}:"
            f"{snapshot.escalated_decisions}:{snapshot.auto_resolved_decisions}"
        )
        mac = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        return "commitment:" + mac

    def verify(
        self,
        proof: str,
        snapshot: ComplianceSnapshot,
        threshold: float,
        constitutional_hash: str,
    ) -> bool:
        try:
            expected = self.prove(snapshot, threshold, constitutional_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(proof, expected)

    def prove_certificate(self, cert: ComplianceCertificate) -> str:
        _validate_certificate_semantics(cert)
        mac = hmac.new(
            self._key,
            b"commitment-cert-v1:" + _certificate_payload(cert),
            hashlib.sha256,
        ).hexdigest()
        return "commitment:" + mac

    def verify_certificate(self, cert: ComplianceCertificate) -> bool:
        try:
            expected = self.prove_certificate(cert)
        except (AttributeError, TypeError, ValueError):
            return False
        return _proof_text_matches(cert.proof, expected)


def _resolve_proof_type(prover: object, requested: ProofType | None) -> ProofType:
    """Label certificates from what the prover is, never from a free default."""
    if requested is not None and not isinstance(requested, ProofType):
        raise TypeError("proof_type must be a ProofType")
    declared = getattr(prover, "proof_type", None)
    if declared is not None and not isinstance(declared, ProofType):
        raise TypeError("prover.proof_type must be a ProofType")
    if declared is None:
        if requested is None:
            raise TypeError(
                "prover does not declare proof_type; pass proof_type= explicitly"
            )
        return requested
    if requested is not None and requested is not declared:
        raise ValueError(
            f"proof_type {requested.value!r} does not match the prover's "
            f"declared proof_type {declared.value!r}"
        )
    return declared


# ---------------------------------------------------------------------------
# Certificate Issuer
# ---------------------------------------------------------------------------


class CertificateIssuer:
    """Issues ComplianceCertificates for governance audit periods.

    Revocation state is process-local and its immutable export is not signed.
    Relying parties must authenticate and freshness-check exported snapshots
    out of band before supplying them to :meth:`verify`. Sharing a proof key
    does not authorize a different ``issuer_id``.

    Usage::

        issuer = CertificateIssuer(
            issuer_id="acgs-subnet-owner",
            secret_key="production-secret",      # for HMAC prover
        )

        snapshot = ComplianceSnapshot(
            total_decisions=10_000,
            passed_decisions=9_970,
            escalated_decisions=300,
            auto_resolved_decisions=200,
            constitutional_hash="608508a9bd224290",
            framework="eu_ai_act",
        )
        period = AuditPeriod.last_n_days(90, label="Q1-2026")

        cert = issuer.issue(
            subject_id="enterprise-42",
            period=period,
            snapshot=snapshot,
            threshold=0.997,         # 99.7% compliance required
            valid_for_days=365,
        )
        print(cert.attests_compliance)   # True (99.70% >= 99.70%)

        # Verify
        assert issuer.verify(cert)
    """

    def __init__(
        self,
        issuer_id: str = "acgs-subnet-owner",
        secret_key: str | None = None,
        prover: ComplianceProver | None = None,
        proof_type: ProofType | None = None,
        *,
        allow_insecure_stub: bool = False,
    ) -> None:
        _non_empty_text(issuer_id, "issuer_id")
        if type(allow_insecure_stub) is not bool:
            raise TypeError("allow_insecure_stub must be a bool")
        self._issuer_id = issuer_id
        resolved_prover: ComplianceProver = (
            prover
            if prover is not None
            else HMACProver(_resolve_compliance_certificate_secret(secret_key))
        )
        for method in ("prove_certificate", "verify_certificate"):
            if not callable(getattr(resolved_prover, method, None)):
                raise TypeError(
                    f"prover must implement {method}(); snapshot-only legacy proofs "
                    "do not bind subject, period, or issuer and are not accepted"
                )
        self._proof_type = _resolve_proof_type(resolved_prover, proof_type)
        if getattr(resolved_prover, "insecure_stub", False) is True and not allow_insecure_stub:
            raise ValueError(
                "prover is a keyless insecure stub whose proofs anyone can forge; "
                "pass allow_insecure_stub=True to use it outside production"
            )
        self._prover = resolved_prover
        self._issued: dict[str, ComplianceCertificate] = {}
        self._revoked: set[str] = set()
        self._state_lock = threading.RLock()

    def issue(
        self,
        subject_id: str,
        period: AuditPeriod,
        snapshot: ComplianceSnapshot,
        threshold: float = 0.997,
        valid_for_days: float = 365,
    ) -> ComplianceCertificate:
        """Issue a compliance certificate.

        Raises ValueError if compliance_rate < threshold (cannot certify).
        """
        _validate_audit_period(period)
        _validate_snapshot(snapshot)
        _validate_threshold(threshold)
        _non_empty_text(subject_id, "subject_id")
        validity = _finite_number(valid_for_days, "valid_for_days")
        if validity <= 0:
            raise ValueError("valid_for_days must be greater than zero")
        if snapshot.compliance_rate < threshold:
            raise ValueError(
                f"Cannot issue certificate: compliance_rate "
                f"{snapshot.compliance_rate:.4%} < threshold {threshold:.4%}"
            )

        now = time.time()
        cert = ComplianceCertificate(
            cert_id=uuid.uuid4().hex[:16],
            issued_at=now,
            expires_at=now + validity * 86_400,
            issuer_id=self._issuer_id,
            subject_id=subject_id,
            period=period,
            snapshot=snapshot,
            proof_type=self._proof_type,
            proof="",
            threshold=threshold,
        )
        cert = replace(cert, proof=self._prover.prove_certificate(cert))
        with self._state_lock:
            self._issued[cert.cert_id] = cert
        return cert

    def verify(
        self,
        cert: ComplianceCertificate,
        *,
        revoked_certificate_ids: AbstractSet[str] | None = None,
    ) -> bool:
        """Verify proof, semantics, and trusted current revocation status.

        External certificates require an explicitly supplied revocation snapshot.
        The caller is responsible for authenticating that snapshot and ensuring
        it is fresh enough for the relying party's policy. An explicit empty set
        asserts that the caller checked a current, authenticated snapshot and it
        contained no revocations; it does not discover revocation by itself.
        Omitting the snapshot for an external certificate fails closed.
        """
        external_revocations = _validate_revocation_snapshot(revoked_certificate_ids)
        with self._state_lock:
            try:
                _validate_certificate_semantics(cert)
            except (AttributeError, TypeError, ValueError):
                return False
            if cert.issuer_id != self._issuer_id:
                return False
            if cert.proof_type is not self._proof_type:
                return False
            if cert.status != CertificateStatus.VALID:
                return False
            locally_issued = cert.cert_id in self._issued
            if not locally_issued and external_revocations is None:
                return False
            trusted_revocations = self._revoked | (external_revocations or set())
            if cert.cert_id in trusted_revocations:
                return False
            if cert.is_expired:
                return False

        if self._prover.verify_certificate(cert) is not True:
            return False

        with self._state_lock:
            try:
                _validate_certificate_semantics(cert)
            except (AttributeError, TypeError, ValueError):
                return False
            if cert.issuer_id != self._issuer_id:
                return False
            if cert.proof_type is not self._proof_type:
                return False
            trusted_revocations = self._revoked | (external_revocations or set())
            return (
                cert.status == CertificateStatus.VALID
                and cert.cert_id not in trusted_revocations
                and not cert.is_expired
            )

    @property
    def revoked_certificate_ids(self) -> frozenset[str]:
        """Return an unsigned immutable snapshot of process-local revocations.

        Consumers must authenticate its source, enforce freshness/rollback
        policy, and persist or transport it outside this object.
        """
        with self._state_lock:
            return frozenset(self._revoked)

    def revoke(self, cert_id: str, reason: str = "") -> None:
        """Revoke a certificate (e.g. if constitutional hash changed)."""
        with self._state_lock:
            self._revoked.add(cert_id)
            if cert_id in self._issued:
                import dataclasses

                cert = self._issued[cert_id]
                self._issued[cert_id] = dataclasses.replace(
                    cert, status=CertificateStatus.REVOKED
                )

    def get(self, cert_id: str) -> ComplianceCertificate | None:
        with self._state_lock:
            return self._issued.get(cert_id)

    def issued_for(self, subject_id: str) -> list[ComplianceCertificate]:
        with self._state_lock:
            return [c for c in self._issued.values() if c.subject_id == subject_id]

    def summary(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "issuer_id": self._issuer_id,
                "proof_type": self._proof_type.value,
                "total_issued": len(self._issued),
                "total_revoked": len(self._revoked),
            }
