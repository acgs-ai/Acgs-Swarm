"""Verifier-first governance receipts for ACGS v0.1.

This module implements a local in-toto/DSSE-shaped receipt profile. It is not an
implementation of in-toto, DSSE, SCITT, Sigstore, COSE, or W3C VC.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Final so mypy infers the literal type, matching the Literal[...] model fields.
PROFILE_VERSION: Final = "acgs.local.intoto-dsse-shaped.v0.1"
CANONICALIZATION_ALGORITHM: Final = "json-sort-keys-separators-v0"
REQUIRED_ROLES = (
    "constitution_author",
    "executor",
    "validator",
    "auditor",
)


class RoleIdentity(BaseModel):
    """Role identity bound into a governance receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["constitution_author", "executor", "validator", "auditor"]
    identity_id: str = Field(min_length=1)
    display_name: str = Field(min_length=1)


class ValidatorVote(BaseModel):
    """Validator decision captured in the receipt payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    validator_id: str = Field(min_length=1)
    decision: Literal["approve", "deny", "abstain"]
    rationale: str = Field(min_length=1)
    dissent: bool = False


class SignatureRecord(BaseModel):
    """Detached signature metadata over canonical payload bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1)
    algorithm: Literal["ed25519", "none"]
    public_key_hex: str | None = None
    signature_hex: str | None = None


class ReceiptPayload(BaseModel):
    """Canonical payload carried by a local v0.1 governance receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    policy_hash: str = Field(min_length=1)
    roles: dict[str, RoleIdentity]
    evidence_hashes: dict[str, str]
    decision: Literal["approved", "denied", "escalated"]
    validator_votes: list[ValidatorVote]
    rejected_alternative: str = Field(min_length=1)
    previous_receipt_hash: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("roles")
    @classmethod
    def require_roles(cls, value: dict[str, RoleIdentity]) -> dict[str, RoleIdentity]:
        missing = [role for role in REQUIRED_ROLES if role not in value]
        if missing:
            msg = f"missing required roles: {', '.join(missing)}"
            raise ValueError(msg)
        for role_name, identity in value.items():
            if role_name != identity.role:
                msg = f"role key {role_name!r} does not match identity role {identity.role!r}"
                raise ValueError(msg)
        return value

    @field_validator("evidence_hashes")
    @classmethod
    def require_evidence_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        if not value:
            msg = "at least one evidence hash is required"
            raise ValueError(msg)
        for name, digest in value.items():
            if not name or not digest:
                msg = "evidence names and hashes must be non-empty"
                raise ValueError(msg)
        return value

    @field_validator("validator_votes")
    @classmethod
    def require_validator_votes(cls, value: list[ValidatorVote]) -> list[ValidatorVote]:
        if not value:
            msg = "at least one validator vote is required"
            raise ValueError(msg)
        return value


class GovernanceReceipt(BaseModel):
    """Local ACGS v0.1 receipt envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_version: Literal["acgs.local.intoto-dsse-shaped.v0.1"] = PROFILE_VERSION
    payload_type: Literal["application/vnd.acgs.governance-receipt.v0.1+json"] = (
        "application/vnd.acgs.governance-receipt.v0.1+json"
    )
    canonicalization: Literal["json-sort-keys-separators-v0"] = CANONICALIZATION_ALGORITHM
    payload: ReceiptPayload
    payload_digest: str
    signatures: list[SignatureRecord]


class GovernanceReceiptBundle(BaseModel):
    """Portable receipt bundle consumed by the independent verifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_version: Literal["acgs.local.intoto-dsse-shaped.v0.1"] = PROFILE_VERSION
    receipts: list[GovernanceReceipt]
    answer_key: dict[str, str] = Field(default_factory=dict)
    benchmark_metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("receipts")
    @classmethod
    def require_receipts(cls, value: list[GovernanceReceipt]) -> list[GovernanceReceipt]:
        if not value:
            msg = "at least one receipt is required"
            raise ValueError(msg)
        return value


class ReceiptIssue(BaseModel):
    """One verifier finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    receipt_id: str | None = None


class VerificationVerdict(BaseModel):
    """Machine-readable verifier result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    mode: Literal["fail_closed", "report"]
    profile_version: str | None = None
    receipt_count: int = 0
    signature_status: Literal["valid", "invalid", "unverifiable", "not_checked"]
    issues: list[ReceiptIssue] = Field(default_factory=list)
    receipt_hashes: list[str] = Field(default_factory=list)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return deterministic canonical bytes for the local v0.1 profile."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def payload_canonical_bytes(payload: ReceiptPayload) -> bytes:
    """Return canonical bytes for a receipt payload."""

    return canonical_json_bytes(payload.model_dump(mode="json", exclude_none=False))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_digest(payload: ReceiptPayload) -> str:
    return sha256_hex(payload_canonical_bytes(payload))


def receipt_hash(receipt: GovernanceReceipt) -> str:
    """Hash the complete receipt envelope excluding no fields."""

    return sha256_hex(canonical_json_bytes(receipt.model_dump(mode="json", exclude_none=False)))


def settlement_canonical_digest(record: Any) -> str:
    """SHA-256 of the protocol v1 settlement encoding.

    ``receipt_digest`` is a pointer and is not part of this digest.
    """

    from constitutional_swarm.protocol import (
        encode_settlement_record_v1,
        protocol_sha256_hex,
    )

    return protocol_sha256_hex(encode_settlement_record_v1(record))


def receipt_from_mesh_settlement(
    record: Any,
    votes: list[Any],
    *,
    previous_receipt_hash: str | None = None,
    signatures: list[SignatureRecord] | None = None,
) -> GovernanceReceipt:
    """Project a mesh settlement onto the existing v0.1 receipt profile.

    This does not invent a fourth evidence format. The settlement digest is
    bound into ``evidence_hashes`` and the receipt digest can be stored on the
    settlement as a pointer. The receipt remains a local DSSE-shaped profile,
    not SCITT, Sigstore, or a compliance certificate.
    """

    assignment = dict(record.assignment)
    assignment_id = str(assignment.get("assignment_id", ""))
    if not assignment_id:
        raise ValueError("settlement assignment_id is required")
    settlement_digest = settlement_canonical_digest(record)
    validator_votes = []
    for vote in votes:
        approved = bool(getattr(vote, "approved", vote.get("approved") if isinstance(vote, dict) else False))
        voter_id = str(getattr(vote, "voter_id", vote.get("voter_id") if isinstance(vote, dict) else ""))
        reason = str(getattr(vote, "reason", vote.get("reason") if isinstance(vote, dict) else "vote"))
        validator_votes.append(
            ValidatorVote(
                validator_id=voter_id or "unknown-validator",
                decision="approve" if approved else "deny",
                rationale=reason or "no-reason",
            )
        )
    if not validator_votes:
        validator_votes.append(
            ValidatorVote(
                validator_id="mesh-validator",
                decision="approve" if bool(record.result.get("accepted", False)) else "deny",
                rationale="settlement quorum recorded without inline vote copies",
            )
        )
    producer_id = str(assignment.get("producer_id", "producer"))
    validator_id = validator_votes[0].validator_id
    payload = ReceiptPayload(
        receipt_id=f"mesh-{assignment_id}",
        action=str(assignment.get("artifact_id", assignment_id)),
        policy_version="local-constitution",
        policy_hash=str(record.constitutional_hash),
        roles={
            "constitution_author": RoleIdentity(
                role="constitution_author",
                identity_id="constitution",
                display_name="constitution",
            ),
            "executor": RoleIdentity(
                role="executor",
                identity_id=producer_id,
                display_name=producer_id,
            ),
            "validator": RoleIdentity(
                role="validator",
                identity_id=validator_id if validator_id != producer_id else "mesh-validator",
                display_name="mesh-validator",
            ),
            "auditor": RoleIdentity(
                role="auditor",
                identity_id="acgs-verify-receipts",
                display_name="acgs-verify-receipts",
            ),
        },
        evidence_hashes={
            "settlement": settlement_digest,
            "content": str(assignment.get("content_hash", "none")),
        },
        decision="approved" if bool(record.result.get("accepted", False)) else "denied",
        validator_votes=validator_votes,
        rejected_alternative="execute-without-settlement",
        previous_receipt_hash=previous_receipt_hash,
        metadata={
            "assignment_id": assignment_id,
            "profile": PROFILE_VERSION,
            "claim": "local-dsse-shaped-receipt",
            **({"recovery": "degraded-votes"} if not votes else {}),
        },
    )
    return build_receipt(payload=payload, signatures=signatures)


def build_receipt(
    *,
    payload: ReceiptPayload,
    signatures: list[SignatureRecord] | None = None,
) -> GovernanceReceipt:
    """Construct a receipt with the correct digest for the supplied payload."""

    return GovernanceReceipt(
        payload=payload,
        payload_digest=payload_digest(payload),
        signatures=signatures or [SignatureRecord(key_id="unsigned", algorithm="none")],
    )


def verify_bundle(
    bundle: GovernanceReceiptBundle,
    *,
    report_mode: bool = False,
    trusted_signers: Mapping[str, str] | None = None,
) -> VerificationVerdict:
    """Verify a receipt bundle.

    Default mode is fail-closed. Report mode allows unverifiable signatures to be
    reported without failing the whole bundle, but other integrity failures still fail.
    """

    issues: list[ReceiptIssue] = []
    hashes: list[str] = []
    signature_statuses: list[str] = []
    previous_hash: str | None = None
    signer_registry = trusted_signers or {}

    for index, receipt in enumerate(bundle.receipts):
        receipt_id = receipt.payload.receipt_id
        actual_digest = payload_digest(receipt.payload)
        if receipt.payload_digest != actual_digest:
            issues.append(
                ReceiptIssue(
                    code="payload_digest_mismatch",
                    message="payload digest does not match canonical payload bytes",
                    receipt_id=receipt_id,
                )
            )

        if index == 0:
            if receipt.payload.previous_receipt_hash is not None:
                issues.append(
                    ReceiptIssue(
                        code="unexpected_previous_hash",
                        message="first receipt must not declare a previous receipt hash",
                        receipt_id=receipt_id,
                    )
                )
        elif receipt.payload.previous_receipt_hash != previous_hash:
            issues.append(
                ReceiptIssue(
                    code="broken_hash_chain",
                    message="receipt previous hash does not match prior receipt hash",
                    receipt_id=receipt_id,
                )
            )

        role_ids = [receipt.payload.roles[role].identity_id for role in REQUIRED_ROLES]
        if len(set(role_ids)) != len(role_ids):
            issues.append(
                ReceiptIssue(
                    code="role_separation_violation",
                    message="required governance roles must be distinct identities",
                    receipt_id=receipt_id,
                )
            )

        payload_bytes = payload_canonical_bytes(receipt.payload)
        signature_statuses.append(
            _verify_receipt_signatures(
                receipt,
                payload_bytes,
                issues,
                trusted_signers=signer_registry,
            )
        )

        current_hash = receipt_hash(receipt)
        hashes.append(current_hash)
        previous_hash = current_hash

    aggregate_signature_status = _aggregate_signature_status(signature_statuses)
    fatal_issues = [
        issue
        for issue in issues
        if not (report_mode and issue.code == "signature_unverifiable")
    ]
    valid = not fatal_issues and (
        report_mode or aggregate_signature_status not in {"invalid", "unverifiable"}
    )

    return VerificationVerdict(
        valid=valid,
        mode="report" if report_mode else "fail_closed",
        profile_version=bundle.profile_version,
        receipt_count=len(bundle.receipts),
        signature_status=aggregate_signature_status,  # type: ignore[arg-type]
        issues=issues,
        receipt_hashes=hashes,
    )


def _verify_receipt_signatures(
    receipt: GovernanceReceipt,
    payload_bytes: bytes,
    issues: list[ReceiptIssue],
    *,
    trusted_signers: Mapping[str, str],
) -> str:
    if not receipt.signatures:
        issues.append(
            ReceiptIssue(
                code="signature_unverifiable",
                message="receipt has no signatures",
                receipt_id=receipt.payload.receipt_id,
            )
        )
        return "unverifiable"

    statuses: list[str] = []
    for signature in receipt.signatures:
        if signature.algorithm == "none":
            issues.append(
                ReceiptIssue(
                    code="signature_unverifiable",
                    message="receipt signature is marked none",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        trusted_public_key = trusted_signers.get(signature.key_id)
        if trusted_public_key is None:
            issues.append(
                ReceiptIssue(
                    code="signature_unverifiable",
                    message="signature key id is absent from verifier trust root",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        if signature.public_key_hex and signature.public_key_hex != trusted_public_key:
            issues.append(
                ReceiptIssue(
                    code="signature_invalid",
                    message="embedded public key does not match verifier trust root",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("invalid")
            continue
        if not signature.signature_hex:
            issues.append(
                ReceiptIssue(
                    code="signature_unverifiable",
                    message="ed25519 signature is missing signature bytes",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key))
            public_key.verify(bytes.fromhex(signature.signature_hex), payload_bytes)
        except (InvalidSignature, ValueError):
            issues.append(
                ReceiptIssue(
                    code="signature_invalid",
                    message="ed25519 signature does not verify canonical payload bytes",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("invalid")
        else:
            statuses.append("valid")
    return _aggregate_signature_status(statuses)


def _aggregate_signature_status(statuses: list[str]) -> str:
    if not statuses:
        return "not_checked"
    if "invalid" in statuses:
        return "invalid"
    if "unverifiable" in statuses:
        return "unverifiable"
    return "valid"


def bundle_from_json(data: str) -> GovernanceReceiptBundle:
    return GovernanceReceiptBundle.model_validate_json(data)


def bundle_to_json(bundle: GovernanceReceiptBundle) -> str:
    return json.dumps(bundle.model_dump(mode="json"), indent=2, sort_keys=True)


def verdict_to_json(verdict: VerificationVerdict) -> str:
    return json.dumps(verdict.model_dump(mode="json"), indent=2, sort_keys=True)


def reconstructability_score(*, correct_answers: int, required_answers: int) -> float:
    if required_answers <= 0:
        msg = "required_answers must be positive"
        raise ValueError(msg)
    return correct_answers / required_answers


def benchmark_summary(
    *,
    bundle: GovernanceReceiptBundle,
    correct_answers: int,
    required_answers: int,
    time_limit_minutes: int,
    governed_harm: float,
    ungoverned_harm: float,
    n_roles: int,
    k_compromised: int,
    first_failure_k: int,
    wall_clock_seconds: float,
    token_estimate: int,
    dollar_estimate: float,
    model_backend: str,
    command_line: str,
    trusted_signers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    verdict = verify_bundle(bundle, trusted_signers=trusted_signers)
    elapsed = time.perf_counter() - started
    return {
        "official_swebench_claimed": False,
        "healthcare_compliance_claimed": False,
        "production_grade_governance_claimed": False,
        "verifier_valid": verdict.valid,
        "verifier_seconds": elapsed,
        "reconstructability": {
            "correct_answers": correct_answers,
            "required_answers": required_answers,
            "time_limit_minutes": time_limit_minutes,
            "score": reconstructability_score(
                correct_answers=correct_answers,
                required_answers=required_answers,
            ),
        },
        "containment_delta": {
            "ungoverned_harm": ungoverned_harm,
            "governed_harm": governed_harm,
            "delta": ungoverned_harm - governed_harm,
        },
        "k_of_n_compromise": {
            "n_roles": n_roles,
            "k_compromised": k_compromised,
            "first_failure_k": first_failure_k,
        },
        "overhead_curve": {
            "wall_clock_seconds": wall_clock_seconds,
            "token_estimate": token_estimate,
            "dollar_estimate": dollar_estimate,
            "model_backend": model_backend,
            "command_line": command_line,
        },
    }
