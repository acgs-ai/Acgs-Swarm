"""Verifier-first governance receipts for ACGS v0.1.

This module implements a local in-toto/DSSE-shaped receipt profile. It is not an
implementation of in-toto, DSSE, SCITT, Sigstore, COSE, or W3C VC.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from functools import lru_cache
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Final so mypy infers the literal type, matching the Literal[...] model fields.
PROFILE_VERSION: Final = "acgs.local.intoto-dsse-shaped.v0.1"
PAYLOAD_TYPE: Final = "application/vnd.acgs.governance-receipt.v0.1+json"
CANONICALIZATION_ALGORITHM: Final = "json-sort-keys-separators-v0"
VOTE_EVIDENCE_VERSION: Final = "constitutional-swarm.vote-envelope.v3"
MIN_RECEIPT_QUORUM: Final = 3
_LOWER_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX_64_RE = re.compile(r"^[0-9a-f]{128}$")
# Identity prefix carried by every deterministic fixture grant that is not
# embedded in signed receipt bytes (see governance_fixtures.py).
FIXTURE_IDENTITY_PREFIX: Final = "fixture-"
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

    @field_validator("validator_id")
    @classmethod
    def canonicalize_validator_id(cls, value: str) -> str:
        from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

        return normalize_voter_id(value)


class SignatureRecord(BaseModel):
    """Detached signature metadata over canonical payload bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1)
    algorithm: Literal["ed25519", "none"]
    public_key_hex: str | None = None
    signature_hex: str | None = None

    @field_validator("public_key_hex")
    @classmethod
    def require_canonical_public_key_hex(cls, value: str | None) -> str | None:
        if value is not None and not _LOWER_HEX_32_RE.fullmatch(value):
            raise ValueError("public_key_hex must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("signature_hex")
    @classmethod
    def require_canonical_signature_hex(cls, value: str | None) -> str | None:
        if value is not None and not _LOWER_HEX_64_RE.fullmatch(value):
            raise ValueError("signature_hex must be 128 lowercase hexadecimal characters")
        return value


class SignerTrustGrant(BaseModel):
    """Externally provisioned identity, public key, and authorized signing roles."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(min_length=1)
    public_key_hex: str
    roles: frozenset[Literal["assigner", "validator", "coordinator", "settlement"]]

    @field_validator("identity_id")
    @classmethod
    def canonicalize_identity_id(cls, value: str) -> str:
        from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

        return normalize_voter_id(value)

    @field_validator("public_key_hex")
    @classmethod
    def validate_public_key_hex(cls, value: str) -> str:
        if not _LOWER_HEX_32_RE.fullmatch(value):
            raise ValueError("public_key_hex must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("roles")
    @classmethod
    def require_roles(
        cls,
        value: frozenset[
            Literal["assigner", "validator", "coordinator", "settlement"]
        ],
    ) -> frozenset[
        Literal["assigner", "validator", "coordinator", "settlement"]
    ]:
        if not value:
            raise ValueError("at least one signer role is required")
        if "assigner" in value and "validator" in value:
            raise ValueError("assigner and validator roles are mutually exclusive")
        if "settlement" in value and ("assigner" in value or "validator" in value):
            raise ValueError(
                "settlement role is mutually exclusive with assigner and validator roles"
            )
        return value


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
    vote_envelopes: list[dict[str, Any]] | None = None
    assigned_peers: list[str] | None = None
    signed_assignment: dict[str, Any] | None = None
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

    @model_validator(mode="after")
    def require_semantic_consistency(self) -> ReceiptPayload:
        _validate_receipt_payload(self)
        return self


class GovernanceReceipt(BaseModel):
    """Local ACGS v0.1 receipt envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_version: Literal["acgs.local.intoto-dsse-shaped.v0.1"] = PROFILE_VERSION
    payload_type: Literal["application/vnd.acgs.governance-receipt.v0.1+json"] = PAYLOAD_TYPE
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
    evidence_policy: Literal["proof_grade", "development"] = "proof_grade"
    issues: list[ReceiptIssue] = Field(default_factory=list)
    receipt_hashes: list[str] = Field(default_factory=list)


def _receipt_payload_semantic_issues(payload: ReceiptPayload) -> list[tuple[str, str]]:
    """Return semantic receipt issues shared by constructors and verifiers."""

    issues: list[tuple[str, str]] = []
    normalized_validator_ids = [
        vote.validator_id.strip().casefold() for vote in payload.validator_votes
    ]
    if any(not validator_id for validator_id in normalized_validator_ids):
        issues.append(
            (
                "blank_validator_id",
                "validator IDs must be non-blank",
            )
        )
    if len(set(normalized_validator_ids)) != len(normalized_validator_ids):
        issues.append(
            (
                "duplicate_validator_id",
                "validator IDs must be unique within a receipt after normalization",
            )
        )

    approve_count = sum(vote.decision == "approve" for vote in payload.validator_votes)
    deny_count = sum(vote.decision == "deny" for vote in payload.validator_votes)
    abstain_count = sum(vote.decision == "abstain" for vote in payload.validator_votes)
    decision_supported = (
        (payload.decision == "approved" and approve_count > deny_count)
        or (
            payload.decision == "denied"
            and deny_count > 0
            and deny_count >= approve_count
        )
        or (
            payload.decision == "escalated"
            and (deny_count > 0 or abstain_count > 0)
        )
    )
    if not decision_supported:
        issues.append(
            (
                "decision_vote_mismatch",
                f"receipt decision {payload.decision!r} is not supported by validator votes",
            )
        )
    return issues


def _validate_receipt_payload(payload: ReceiptPayload) -> None:
    issues = _receipt_payload_semantic_issues(payload)
    if issues:
        raise ValueError("; ".join(message for _, message in issues))


def _canonical_assigned_peers(raw_peers: Any, *, producer_id: str) -> list[str]:
    """Validate a signed assignment roster without silently normalizing it."""

    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    if not isinstance(raw_peers, list) or not raw_peers:
        raise ValueError("assigned peers must be a non-empty string list")
    canonical: list[str] = []
    for peer in raw_peers:
        if not isinstance(peer, str):
            raise ValueError("assigned peers must be a non-empty string list")
        normalized = normalize_voter_id(peer)
        if peer != normalized:
            raise ValueError("assigned peer identities must already be canonical")
        canonical.append(normalized)
    if len(set(canonical)) != len(canonical):
        raise ValueError("assigned peers must contain distinct canonical identities")
    if normalize_voter_id(producer_id) in canonical:
        raise ValueError("producer identity cannot appear in assigned peers")
    return canonical


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return deterministic canonical bytes for the local v0.1 profile."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _payload_mapping(payload: ReceiptPayload) -> dict[str, Any]:
    data = payload.model_dump(mode="json", exclude_none=False)
    if data.get("vote_envelopes") is None:
        data.pop("vote_envelopes", None)
    if data.get("assigned_peers") is None:
        data.pop("assigned_peers", None)
    if data.get("signed_assignment") is None:
        data.pop("signed_assignment", None)
    return data


def payload_canonical_bytes(
    payload: ReceiptPayload,
    *,
    profile_version: str = PROFILE_VERSION,
) -> bytes:
    """Return canonical receipt signing bytes for the stable wrapper profile."""

    if profile_version != PROFILE_VERSION:
        raise ValueError(f"unsupported governance receipt profile {profile_version!r}")
    return canonical_json_bytes(_payload_mapping(payload))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_digest(payload: ReceiptPayload, *, profile_version: str = PROFILE_VERSION) -> str:
    return sha256_hex(payload_canonical_bytes(payload, profile_version=profile_version))


def receipt_hash(receipt: GovernanceReceipt) -> str:
    """Hash the complete receipt envelope excluding no fields."""

    data = receipt.model_dump(mode="json", exclude_none=False)
    if data["payload"].get("vote_envelopes") is None:
        data["payload"].pop("vote_envelopes", None)
    if data["payload"].get("assigned_peers") is None:
        data["payload"].pop("assigned_peers", None)
    if data["payload"].get("signed_assignment") is None:
        data["payload"].pop("signed_assignment", None)
    return sha256_hex(canonical_json_bytes(data))


def settlement_canonical_digest(
    record: Any,
    *,
    vote_envelopes: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> str:
    """SHA-256 of the versioned settlement encoding.

    ``receipt_digest`` is a pointer and is not part of this digest.
    """

    from constitutional_swarm.protocol import (
        encode_settlement_record_v1,
        protocol_sha256_hex,
    )

    schema_version = int(getattr(record, "schema_version", 1))
    if schema_version == 1:
        return protocol_sha256_hex(encode_settlement_record_v1(record))
    if schema_version != 2:
        raise ValueError(f"unsupported settlement schema_version {schema_version}")
    votes = list(record.votes if vote_envelopes is None else vote_envelopes)
    return protocol_sha256_hex(
        canonical_json_bytes(
            {
                "domain": "settlement-record",
                "payload": {
                    "assignment": record.assignment,
                    "constitutional_hash": record.constitutional_hash,
                    "is_recovered": record.is_recovered,
                    "result": record.result,
                    "schema_version": 2,
                    "vote_envelopes": votes,
                },
                "version": 2,
            }
        )
    )


def _parse_trust_grants(
    trusted_signers: Mapping[str, Any] | None,
) -> dict[str, SignerTrustGrant]:
    if not trusted_signers:
        raise ValueError("structured signer trust registry is required to verify vote envelopes")
    grants: dict[str, SignerTrustGrant] = {}
    identities: dict[str, tuple[str, str]] = {}
    public_key_owners: dict[str, str] = {}
    for key_id, raw_grant in trusted_signers.items():
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("signer trust registry key IDs must be non-empty strings")
        if isinstance(raw_grant, SignerTrustGrant):
            # Re-run every validator: model_construct() and subclasses bypass them.
            grant = SignerTrustGrant.model_validate(raw_grant.model_dump())
        elif isinstance(raw_grant, Mapping):
            grant = SignerTrustGrant.model_validate(dict(raw_grant))
        else:
            raise ValueError(
                "signer trust registry values must contain identity_id, public_key_hex, and roles"
            )
        registered = identities.get(grant.identity_id)
        if registered is not None and registered != (key_id, grant.public_key_hex):
            raise ValueError("signer identity is already registered to another key")
        key_owner = public_key_owners.get(grant.public_key_hex)
        if key_owner is not None and key_owner != grant.identity_id:
            raise ValueError("signer public key is already registered to another identity")
        grants[key_id] = grant
        identities[grant.identity_id] = (key_id, grant.public_key_hex)
        public_key_owners[grant.public_key_hex] = grant.identity_id
    return grants


@lru_cache(maxsize=1)
def _repeated_byte_seed_public_keys() -> frozenset[str]:
    """Public keys of Ed25519 seeds ``bytes([n]) * 32``; their private keys are public."""

    return frozenset(
        Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
        for seed in range(256)
    )


def _is_fixture_trust_registry(grants: Mapping[str, SignerTrustGrant]) -> bool:
    """True when any grant is a deterministic fixture key or fixture identity."""

    weak_keys = _repeated_byte_seed_public_keys()
    return any(
        grant.identity_id.startswith(FIXTURE_IDENTITY_PREFIX)
        or grant.public_key_hex in weak_keys
        for grant in grants.values()
    )


def _settlement_signer_conflict_issue(
    payload: ReceiptPayload, signer_identity: str
) -> tuple[str, str] | None:
    """Return an issue when the settlement signer is a voter, the assigner, or the producer.

    Fails closed: a present candidate identity that is not an exact, non-blank ``str``
    cannot be compared and is reported as malformed instead of being skipped.
    """

    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    candidates: list[Any] = [vote.validator_id for vote in payload.validator_votes]
    candidates.extend(payload.assigned_peers or [])
    candidates.append(payload.metadata.get("producer_id"))
    candidates.append(payload.roles["executor"].identity_id)
    if payload.signed_assignment is not None:
        candidates.append(payload.signed_assignment.get("assigner_id"))
        candidates.append(payload.signed_assignment.get("producer_id"))
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            normalized = normalize_voter_id(candidate)
        except (TypeError, ValueError):
            return (
                "settlement_signer_identity_malformed",
                "receipt identity compared against the settlement signer is not a "
                "non-blank string",
            )
        if normalized == signer_identity:
            return (
                "settlement_signer_role_conflict",
                "settlement signer identity must not be a voter, the assigner, or the producer",
            )
    return None


def _vote_registry_from_grants(grants: Mapping[str, SignerTrustGrant]) -> Any:
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    registry = VoteSignerRegistry()
    for trust_key_id, grant in grants.items():
        roles = set()
        if "validator" in grant.roles:
            roles.add("voter")
        if "assigner" in grant.roles:
            roles.add("assigner")
        if roles:
            derived_key_id = registry.register(
                grant.identity_id,
                bytes.fromhex(grant.public_key_hex),
                roles=frozenset(roles),
            )
            if trust_key_id != derived_key_id:
                raise ValueError(
                    "vote trust registry key ID must equal the public-key fingerprint"
                )
    return registry


def _verify_bound_vote_envelopes(
    raw_assignment: Mapping[str, Any],
    raw_envelopes: list[Any] | tuple[Any, ...],
    grants: Mapping[str, SignerTrustGrant],
    *,
    task_id: str,
    assignment_id: str,
    producer_id: str,
    artifact_id: str,
    content_hash: str,
    constitutional_hash: str,
    expected_assigned_peers: list[str] | tuple[str, ...] | None = None,
    expected_quorum: int | None = None,
    require_independent_votes: bool = True,
) -> tuple[Any, ...]:
    from constitutional_swarm.mesh.vote_envelope import (
        VoteEnvelope,
        signed_assignment_from_dict,
        verify_assignment_vote_envelopes,
        vote_envelope_from_dict,
    )

    if not raw_envelopes:
        raise ValueError("at least one signed vote envelope is required")
    envelopes = tuple(
        envelope
        if isinstance(envelope, VoteEnvelope)
        else vote_envelope_from_dict(dict(envelope))
        for envelope in raw_envelopes
    )
    assignment = signed_assignment_from_dict(raw_assignment)
    return verify_assignment_vote_envelopes(
        assignment,
        envelopes,
        _vote_registry_from_grants(grants),
        task_id=task_id,
        assignment_id=assignment_id,
        producer_id=producer_id,
        artifact_id=artifact_id,
        content_hash=content_hash,
        constitutional_hash=constitutional_hash,
        expected_assigned_peers=expected_assigned_peers,
        expected_quorum=expected_quorum,
        require_independent=require_independent_votes,
    )


def receipt_from_mesh_settlement(
    record: Any,
    votes: list[Any],
    *,
    previous_receipt_hash: str | None = None,
    signatures: list[SignatureRecord] | None = None,
    trusted_signers: Mapping[str, Any] | None = None,
    require_independent_votes: bool = True,
) -> GovernanceReceipt:
    """Project verified mesh VoteEnvelopes onto the proof-grade receipt profile.

    The original signed envelopes remain the source of truth. ValidatorVote is
    retained only as an exact human-readable projection.
    """

    assignment = dict(record.assignment)
    assignment_id = str(assignment.get("assignment_id", ""))
    if not assignment_id:
        raise ValueError("settlement assignment_id is required")
    if int(getattr(record, "schema_version", 1)) != 2:
        raise ValueError("proof-grade receipts require settlement schema_version 2")
    task_id = str(assignment.get("task_id", ""))
    producer_id = str(assignment.get("producer_id", ""))
    artifact_id = str(assignment.get("artifact_id", ""))
    content_hash = str(assignment.get("content_hash", ""))
    constitutional_hash = str(record.constitutional_hash)
    if not all((task_id, producer_id, artifact_id, content_hash, constitutional_hash)):
        raise ValueError("settlement is missing vote-envelope subject bindings")
    if not votes:
        raise ValueError("at least one signed vote envelope is required")
    raw_signed_assignment = assignment.get("signed_assignment")
    if not isinstance(raw_signed_assignment, Mapping):
        raise ValueError("settlement signed assignment evidence is required")
    assigned_peers = _canonical_assigned_peers(
        assignment.get("peers"),
        producer_id=producer_id,
    )
    raw_assignment_quorum = assignment.get("quorum")
    if raw_assignment_quorum is not None and type(raw_assignment_quorum) is not int:
        raise ValueError("settlement assignment quorum must be an integer")
    grants = _parse_trust_grants(trusted_signers)
    envelopes = _verify_bound_vote_envelopes(
        raw_signed_assignment,
        votes,
        grants,
        task_id=task_id,
        assignment_id=assignment_id,
        producer_id=producer_id,
        artifact_id=artifact_id,
        content_hash=content_hash,
        constitutional_hash=constitutional_hash,
        expected_assigned_peers=assigned_peers,
        expected_quorum=raw_assignment_quorum,
        require_independent_votes=require_independent_votes,
    )
    quorum = envelopes[0].quorum
    if quorum < MIN_RECEIPT_QUORUM:
        raise ValueError(
            f"proof-grade receipt quorum must be at least {MIN_RECEIPT_QUORUM}"
        )
    from constitutional_swarm.mesh.vote_envelope import vote_envelope_to_dict

    envelope_dicts = [vote_envelope_to_dict(envelope) for envelope in envelopes]
    approvals = sum(envelope.decision == "approved" for envelope in envelopes)
    denials = len(envelopes) - approvals
    claimed_approvals = record.result.get("votes_for")
    claimed_denials = record.result.get("votes_against")
    if claimed_approvals is not None and (
        type(claimed_approvals) is not int or claimed_approvals != approvals
    ):
        raise ValueError(
            "settlement votes_for does not match verified vote envelope tally"
        )
    if claimed_denials is not None and (
        type(claimed_denials) is not int or claimed_denials != denials
    ):
        raise ValueError(
            "settlement votes_against does not match verified vote envelope tally"
        )
    accepted = record.result.get("accepted")
    if type(accepted) is not bool:
        raise ValueError("settlement accepted result must be a boolean")
    decision_threshold = max(len(assigned_peers) // 2 + 1, quorum)
    approval_outcome = approvals >= decision_threshold
    denial_outcome = denials >= decision_threshold
    if approval_outcome == denial_outcome:
        raise ValueError("settlement vote envelopes have no unique strict-majority outcome")
    recomputed_accepted = approval_outcome
    if accepted != recomputed_accepted:
        raise ValueError("settlement accepted result does not match verified vote envelope tally")
    settlement_digest = settlement_canonical_digest(record, vote_envelopes=envelope_dicts)
    validator_votes = [
        ValidatorVote(
            validator_id=envelope.voter_id,
            decision="approve" if envelope.decision == "approved" else "deny",
            rationale=envelope.reason or "No rationale provided",
        )
        for envelope in envelopes
    ]
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
        decision="approved" if accepted else "denied",
        validator_votes=validator_votes,
        vote_envelopes=envelope_dicts,
        assigned_peers=assigned_peers,
        signed_assignment=dict(raw_signed_assignment),
        rejected_alternative="execute-without-settlement",
        previous_receipt_hash=previous_receipt_hash,
        metadata={
            "assignment_id": assignment_id,
            "assigned_peer_count": str(len(assigned_peers)),
            "quorum": str(quorum),
            "artifact_id": artifact_id,
            "content_hash": content_hash,
            "producer_id": producer_id,
            "profile": PROFILE_VERSION,
            "claim": "local-dsse-shaped-receipt",
            "signer_role": "settlement",
            "task_id": task_id,
            "vote_evidence_version": VOTE_EVIDENCE_VERSION,
            "vote_evidence_mode": envelopes[0].evidence_mode,
        },
    )
    return build_receipt(payload=payload, signatures=signatures)


def build_receipt(
    *,
    payload: ReceiptPayload,
    signatures: list[SignatureRecord] | None = None,
    profile_version: Literal["acgs.local.intoto-dsse-shaped.v0.1"] = PROFILE_VERSION,
) -> GovernanceReceipt:
    """Construct a receipt with the correct digest for the supplied payload."""

    _validate_receipt_payload(payload)
    return GovernanceReceipt(
        profile_version=profile_version,
        payload_type=PAYLOAD_TYPE,
        canonicalization=CANONICALIZATION_ALGORITHM,
        payload=payload,
        payload_digest=payload_digest(payload, profile_version=profile_version),
        signatures=signatures or [SignatureRecord(key_id="unsigned", algorithm="none")],
    )


def _receipt_vote_evidence_issues(
    receipt: GovernanceReceipt,
    grants: Mapping[str, SignerTrustGrant],
    *,
    require_independent_votes: bool,
) -> list[tuple[str, str]]:
    payload = receipt.payload
    if not payload.vote_envelopes:
        return [
            (
                "vote_envelope_missing",
                "proof-grade receipt requires original signed vote envelopes",
            )
        ]
    if payload.signed_assignment is None:
        return [
            (
                "vote_assignment_missing",
                "proof-grade receipt requires the authenticated signed assignment",
            )
        ]
    if payload.metadata.get("vote_evidence_version") != VOTE_EVIDENCE_VERSION:
        return [
            (
                "vote_evidence_version_invalid",
                "receipt vote evidence version is missing or unsupported",
            )
        ]
    binding_names = (
        "task_id",
        "assignment_id",
        "producer_id",
        "artifact_id",
        "content_hash",
    )
    bindings = {name: payload.metadata.get(name, "") for name in binding_names}
    if any(not value for value in bindings.values()):
        return [
            (
                "vote_envelope_binding_missing",
                "receipt metadata is missing vote-envelope subject bindings",
            )
        ]
    try:
        assigned_peers = _canonical_assigned_peers(
            payload.assigned_peers,
            producer_id=bindings["producer_id"],
        )
    except (TypeError, ValueError) as exc:
        return [
            (
                "vote_peer_assignment_invalid",
                f"receipt assigned peer roster is invalid: {exc}",
            )
        ]
    raw_peer_count = payload.metadata.get("assigned_peer_count", "")
    try:
        assigned_peer_count = int(raw_peer_count)
    except ValueError:
        return [
            (
                "vote_peer_count_invalid",
                "receipt assigned peer count is missing or invalid",
            )
        ]
    if assigned_peer_count != len(assigned_peers):
        return [
            (
                "vote_peer_count_invalid",
                "receipt assigned peer count does not match the signed peer roster",
            )
        ]
    raw_quorum = payload.metadata.get("quorum", "")
    try:
        quorum = int(raw_quorum)
    except ValueError:
        return [
            (
                "vote_quorum_invalid",
                "receipt quorum is missing or invalid",
            )
        ]
    if quorum < MIN_RECEIPT_QUORUM or quorum > assigned_peer_count:
        return [
            (
                "vote_quorum_invalid",
                f"receipt quorum must be between {MIN_RECEIPT_QUORUM} and the assigned peer count",
            )
        ]
    try:
        envelopes = _verify_bound_vote_envelopes(
            payload.signed_assignment,
            payload.vote_envelopes,
            grants,
            task_id=bindings["task_id"],
            assignment_id=bindings["assignment_id"],
            producer_id=bindings["producer_id"],
            artifact_id=bindings["artifact_id"],
            content_hash=bindings["content_hash"],
            constitutional_hash=payload.policy_hash,
            expected_assigned_peers=assigned_peers,
            expected_quorum=quorum,
            require_independent_votes=require_independent_votes,
        )
    except (TypeError, ValueError) as exc:
        return [("vote_electorate_invalid", f"vote envelope verification failed: {exc}")]
    if payload.metadata.get("vote_evidence_mode") != envelopes[0].evidence_mode:
        return [
            (
                "vote_evidence_mode_invalid",
                "receipt vote evidence mode does not match the signed envelopes",
            )
        ]
    projected = [
        (
            envelope.voter_id,
            "approve" if envelope.decision == "approved" else "deny",
            envelope.reason or "No rationale provided",
        )
        for envelope in envelopes
    ]
    claimed = [
        (vote.validator_id, vote.decision, vote.rationale) for vote in payload.validator_votes
    ]
    if claimed != projected:
        return [
            (
                "vote_projection_mismatch",
                "validator vote projection does not match verified vote envelopes",
            )
        ]
    approvals = sum(envelope.decision == "approved" for envelope in envelopes)
    denials = len(envelopes) - approvals
    decision_threshold = max(len(assigned_peers) // 2 + 1, quorum)
    approval_outcome = approvals >= decision_threshold
    denial_outcome = denials >= decision_threshold
    if approval_outcome == denial_outcome:
        return [
            (
                "vote_tally_no_majority",
                "verified vote envelopes have no unique strict-majority outcome",
            )
        ]
    expected_decision = "approved" if approval_outcome else "denied"
    if payload.decision != expected_decision:
        return [
            (
                "vote_tally_mismatch",
                "receipt decision does not match tally recomputed from verified vote envelopes",
            )
        ]
    return []


def _required_receipt_signer_role(
    payload: ReceiptPayload,
    expected_signer_role: Literal["validator", "coordinator", "settlement"] | None,
) -> Literal["validator", "coordinator", "settlement"]:
    settlement_bound = (
        "settlement" in payload.evidence_hashes
        or payload.vote_envelopes is not None
        or "assignment_id" in payload.metadata
    )
    if settlement_bound:
        return "settlement"
    return expected_signer_role or "coordinator"


def verify_bundle(
    bundle: GovernanceReceiptBundle,
    *,
    report_mode: bool = False,
    trusted_signers: Mapping[str, Any] | None = None,
    expected_signer_role: Literal["validator", "coordinator", "settlement"] | None = None,
    require_independent_votes: bool = True,
    require_proof_grade: bool = False,
) -> VerificationVerdict:
    """Verify a receipt bundle.

    Both modes fail closed. Report mode changes the output mode label while preserving
    signature diagnostics for callers that need a complete report.

    ``evidence_policy`` is ``development`` when independent votes are not required or
    when the trust registry holds a deterministic fixture key or ``fixture-`` identity.
    With ``require_proof_grade=True`` a ``development`` policy makes the verdict invalid
    (issue ``evidence_policy_not_proof_grade``).
    """

    issues: list[ReceiptIssue] = []
    hashes: list[str] = []
    signature_statuses: list[str] = []
    previous_hash: str | None = None
    try:
        signer_registry = _parse_trust_grants(trusted_signers)
    except (TypeError, ValueError) as exc:
        signer_registry = {}
        issues.append(
            ReceiptIssue(
                code="trust_registry_invalid",
                message=f"structured signer trust registry is invalid: {exc}",
            )
        )

    for index, receipt in enumerate(bundle.receipts):
        receipt_id = receipt.payload.receipt_id
        if receipt.profile_version != bundle.profile_version:
            issues.append(
                ReceiptIssue(
                    code="bundle_profile_mismatch",
                    message="receipt profile does not match bundle profile",
                    receipt_id=receipt_id,
                )
            )
        if receipt.payload_type != PAYLOAD_TYPE:
            issues.append(
                ReceiptIssue(
                    code="payload_type_mismatch",
                    message="receipt payload type does not match its profile version",
                    receipt_id=receipt_id,
                )
            )
        if receipt.canonicalization != CANONICALIZATION_ALGORITHM:
            issues.append(
                ReceiptIssue(
                    code="canonicalization_mismatch",
                    message="receipt canonicalization does not match its profile version",
                    receipt_id=receipt_id,
                )
            )
        actual_digest = payload_digest(
            receipt.payload,
            profile_version=receipt.profile_version,
        )
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

        for code, message in _receipt_payload_semantic_issues(receipt.payload):
            issues.append(
                ReceiptIssue(
                    code=code,
                    message=message,
                    receipt_id=receipt_id,
                )
            )

        for code, message in _receipt_vote_evidence_issues(
            receipt,
            signer_registry,
            require_independent_votes=require_independent_votes,
        ):
            issues.append(
                ReceiptIssue(code=code, message=message, receipt_id=receipt_id)
            )

        payload_bytes = payload_canonical_bytes(
            receipt.payload,
            profile_version=receipt.profile_version,
        )
        required_role = _required_receipt_signer_role(
            receipt.payload,
            expected_signer_role,
        )
        declared_role = receipt.payload.metadata.get("signer_role")
        if declared_role != required_role:
            issues.append(
                ReceiptIssue(
                    code="signer_role_mismatch",
                    message=(
                        "signed signer_role metadata does not match the verifier-required "
                        f"role {required_role!r}"
                    ),
                    receipt_id=receipt_id,
                )
            )
        signature_statuses.append(
            _verify_receipt_signatures(
                receipt,
                payload_bytes,
                issues,
                trusted_signers=signer_registry,
                required_role=required_role,
            )
        )

        current_hash = receipt_hash(receipt)
        hashes.append(current_hash)
        previous_hash = current_hash

    proof_grade = require_independent_votes and not _is_fixture_trust_registry(signer_registry)
    if require_proof_grade and not proof_grade:
        issues.append(
            ReceiptIssue(
                code="evidence_policy_not_proof_grade",
                message=(
                    "proof-grade evidence was required, but the evidence policy is development "
                    "(dev vote opt-out or deterministic fixture trust root)"
                ),
            )
        )
    aggregate_signature_status = _aggregate_signature_status(signature_statuses)
    valid = not issues and aggregate_signature_status == "valid"

    return VerificationVerdict(
        valid=valid,
        mode="report" if report_mode else "fail_closed",
        profile_version=bundle.profile_version,
        receipt_count=len(bundle.receipts),
        signature_status=aggregate_signature_status,  # type: ignore[arg-type]
        evidence_policy="proof_grade" if proof_grade else "development",
        issues=issues,
        receipt_hashes=hashes,
    )


def _verify_receipt_signatures(
    receipt: GovernanceReceipt,
    payload_bytes: bytes,
    issues: list[ReceiptIssue],
    *,
    trusted_signers: Mapping[str, SignerTrustGrant],
    required_role: str,
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
        grant = trusted_signers.get(signature.key_id)
        if grant is None:
            issues.append(
                ReceiptIssue(
                    code="signature_unverifiable",
                    message="signature key id is absent from verifier trust root",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        if required_role not in {"validator", "coordinator", "settlement"}:
            issues.append(
                ReceiptIssue(
                    code="signer_role_missing",
                    message="receipt signed metadata must declare a recognized signer_role",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        if required_role not in grant.roles:
            issues.append(
                ReceiptIssue(
                    code="signer_role_unauthorized",
                    message=f"signature key is not authorized for role {required_role!r}",
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        conflict = (
            _settlement_signer_conflict_issue(receipt.payload, grant.identity_id)
            if required_role == "settlement"
            else None
        )
        if conflict is not None:
            issues.append(
                ReceiptIssue(
                    code=conflict[0],
                    message=conflict[1],
                    receipt_id=receipt.payload.receipt_id,
                )
            )
            statuses.append("unverifiable")
            continue
        if signature.public_key_hex and signature.public_key_hex != grant.public_key_hex:
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
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(grant.public_key_hex))
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
    trusted_signers: Mapping[str, Any] | None = None,
    expected_signer_role: Literal["validator", "coordinator", "settlement"] | None = None,
    require_independent_votes: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    verdict = verify_bundle(
        bundle,
        trusted_signers=trusted_signers,
        expected_signer_role=expected_signer_role,
        require_independent_votes=require_independent_votes,
    )
    elapsed = time.perf_counter() - started
    return {
        "official_swebench_claimed": False,
        "healthcare_compliance_claimed": False,
        "production_grade_governance_claimed": False,
        "verifier_valid": verdict.valid,
        "evidence_policy": verdict.evidence_policy,
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
