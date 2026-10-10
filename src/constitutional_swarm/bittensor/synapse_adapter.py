"""Adapter layer bridging constitutional_swarm synapses to bittensor.Synapse.

When bittensor is installed, GovernanceDeliberation subclasses bt.Synapse
for real testnet communication. When not installed, it falls back to a
standalone Pydantic BaseModel with the same field contract.

Usage:
    # Convert internal dataclass → bt synapse for wire transport
    bt_syn = deliberation_to_bt(deliberation_synapse)

    # Extract judgment from completed bt synapse
    judgment = bt_to_judgment(completed_bt_synapse)

    # Convert bt synapse back to internal dataclass
    delib = bt_to_deliberation(bt_syn)
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from constitutional_swarm.bittensor.synapses import (
    DeliberationSynapse,
    JudgmentSynapse,
    _canonical_synapse_hash,
)
from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

_JUDGMENT_RESPONSE_DOMAIN = b"constitutional-swarm.bittensor-judgment-response.v2\x00"
JUDGMENT_RESPONSE_PROTOCOL_VERSION = 2
_REQUEST_BINDING_DOMAIN = b"constitutional-swarm.bittensor-request-binding.v1\x00"

# Every request field a miner consumes. All of them are covered by the
# bittensor transport body hash (``required_hash_fields``) and by the
# request-binding digest that the miner signs into its response.
REQUEST_BINDING_FIELDS: tuple[str, ...] = (
    "task_id",
    "task_dag_json",
    "constitution_hash",
    "domain",
    "required_capabilities",
    "deadline_seconds",
    "escalation_type",
    "impact_score",
    "impact_vector",
    "context",
    "request_timestamp",
)

if TYPE_CHECKING:
    # bittensor.Synapse is unstubbed (treated as Any), which is not valid as a
    # static base class. Pin the type-check base to the always-present pydantic
    # BaseModel so GovernanceDeliberation has a concrete base for analysis; the
    # runtime base is bt.Synapse when bittensor is installed.
    _SynapseBase = BaseModel
    HAS_BITTENSOR: bool
else:
    try:
        import bittensor as bt

        _SynapseBase = bt.Synapse
        HAS_BITTENSOR = True
    except ImportError:
        _SynapseBase = BaseModel
        HAS_BITTENSOR = False


class GovernanceDeliberation(_SynapseBase):
    """Combined request/response synapse for governance deliberation.

    In bittensor's protocol, a single synapse object carries both the
    request (validator → miner) and the response (miner fills in fields
    and returns). This class bridges that model with our internal
    split-synapse design (DeliberationSynapse + JudgmentSynapse).

    Request fields are populated by the validator/SN Owner before sending.
    Response fields are filled by the miner's forward_fn handler.
    """

    model_config = ConfigDict(validate_assignment=True)

    # --- Request fields (validator/SN Owner → miner) ---
    task_id: str = ""
    task_dag_json: str = ""
    constitution_hash: str = ""
    domain: str = ""
    required_capabilities: list[str] = Field(default_factory=list)
    deadline_seconds: int = 3600
    escalation_type: str = ""
    impact_score: float = 0.0
    impact_vector: dict[str, float] = Field(default_factory=dict)
    context: str = ""
    request_timestamp: float = 0.0

    # --- Response fields (miner → validator, None until filled) ---
    judgment: str | None = None
    reasoning: str | None = None
    artifact_hash: str | None = None
    dna_valid: bool | None = None
    dna_violations: list[str] = Field(default_factory=list)
    dna_latency_ns: int = 0
    miner_uid: str = ""
    response_timestamp: float = 0.0
    response_protocol_version: int = JUDGMENT_RESPONSE_PROTOCOL_VERSION
    response_signer_hotkey: str = ""
    response_signature: str = ""

    # Miner may report a different constitution hash during grace window
    miner_constitution_hash: str = ""

    # --- Error reporting ---
    error_message: str | None = None

    # Bittensor's dendrite signs a body hash over these fields and the axon
    # recomputes it, so every request field the miner consumes is listed.
    required_hash_fields: ClassVar[tuple[str, ...]] = REQUEST_BINDING_FIELDS

    @property
    def request_content_hash(self) -> str:
        """Deterministic hash of the request payload."""
        return _canonical_synapse_hash(
            "deliberation",
            {
                "task_id": self.task_id,
                "constitutional_hash": self.constitution_hash,
                "task_dag_json": self.task_dag_json,
            },
        )

    @property
    def has_response(self) -> bool:
        """Whether the miner has filled in response fields."""
        return self.judgment is not None

    def deserialize(self) -> GovernanceDeliberation:
        """No-op deserialization (fields are already native types)."""
        return self


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def request_binding_digest(request: Any) -> str:
    """Domain-separated SHA-256 over every request field a miner consumes.

    ``request_content_hash`` covers only task_id, constitution hash and DAG;
    this digest additionally binds the case context, routing metadata and
    deadline. Raises ``ValueError`` for missing fields or non-finite numbers.
    """
    fields: dict[str, Any] = {}
    for name in REQUEST_BINDING_FIELDS:
        try:
            value = getattr(request, name)
        except AttributeError as exc:
            raise ValueError(f"request is missing bound field {name!r}") from exc
        if isinstance(value, (list, tuple)):
            value = list(value)
        elif isinstance(value, dict):
            value = dict(value)
        fields[name] = value
    for name in ("impact_score", "request_timestamp"):
        if isinstance(fields[name], float) and not math.isfinite(fields[name]):
            raise ValueError(f"request field {name!r} must be finite")
    return hashlib.sha256(_REQUEST_BINDING_DOMAIN + _canonical_json(fields)).hexdigest()


def canonical_judgment_response_bytes(bt_syn: GovernanceDeliberation) -> bytes:
    """Encode the request-bound judgment response for miner signing."""
    dendrite = getattr(bt_syn, "dendrite", None)
    payload = {
        "protocol_version": bt_syn.response_protocol_version,
        "request": {
            "binding_hash": request_binding_digest(bt_syn),
            "content_hash": bt_syn.request_content_hash,
            "dendrite_hotkey": getattr(dendrite, "hotkey", None),
            "task_id": bt_syn.task_id,
        },
        "response": {
            "artifact_hash": bt_syn.artifact_hash,
            "dna_latency_ns": bt_syn.dna_latency_ns,
            "dna_valid": bt_syn.dna_valid,
            "dna_violations": list(bt_syn.dna_violations),
            "domain": bt_syn.domain,
            "judgment": bt_syn.judgment,
            "miner_constitution_hash": bt_syn.miner_constitution_hash,
            "miner_uid": bt_syn.miner_uid,
            "reasoning": bt_syn.reasoning,
            "request_constitution_hash": bt_syn.constitution_hash,
            "response_signer_hotkey": bt_syn.response_signer_hotkey,
            "response_timestamp": bt_syn.response_timestamp,
        },
    }
    return _JUDGMENT_RESPONSE_DOMAIN + _canonical_json(payload)


def sign_judgment_response(bt_syn: GovernanceDeliberation, signing_key: Any) -> None:
    """Sign a completed judgment response with the miner's Bittensor hotkey."""
    signer_hotkey = getattr(signing_key, "ss58_address", None)
    if not isinstance(signer_hotkey, str) or not signer_hotkey:
        raise ValueError("response signing key must expose an SS58 address")
    if normalize_voter_id(bt_syn.miner_uid) != normalize_voter_id(signer_hotkey):
        raise ValueError("judgment miner_uid does not match the response signing hotkey")
    if bt_syn.judgment is None:
        raise ValueError("cannot sign an empty judgment response")
    bt_syn.response_protocol_version = JUDGMENT_RESPONSE_PROTOCOL_VERSION
    bt_syn.response_signer_hotkey = signer_hotkey
    bt_syn.response_signature = "0x" + signing_key.sign(
        canonical_judgment_response_bytes(bt_syn)
    ).hex()


def verify_judgment_response_signature(
    bt_syn: GovernanceDeliberation,
    *,
    expected_signer_hotkey: str,
    expected_dendrite_hotkey: str,
) -> None:
    """Verify request-bound response content before converting the judgment."""
    if bt_syn.response_protocol_version != JUDGMENT_RESPONSE_PROTOCOL_VERSION:
        raise ValueError("unsupported judgment response protocol version")
    if bt_syn.response_signer_hotkey != expected_signer_hotkey:
        raise ValueError("judgment response signer does not match the selected axon")
    dendrite = getattr(bt_syn, "dendrite", None)
    if getattr(dendrite, "hotkey", None) != expected_dendrite_hotkey:
        raise ValueError("judgment response requester does not match the local dendrite")
    if normalize_voter_id(bt_syn.miner_uid) != normalize_voter_id(expected_signer_hotkey):
        raise ValueError("judgment miner_uid does not match the response signer")
    if not bt_syn.response_signature:
        raise ValueError("judgment response body signature is missing")
    import bittensor as bt

    try:
        verified = bt.Keypair(ss58_address=expected_signer_hotkey).verify(
            canonical_judgment_response_bytes(bt_syn),
            bt_syn.response_signature,
        )
    except Exception as exc:
        raise ValueError("judgment response body signature is invalid") from exc
    if not verified:
        raise ValueError("judgment response body signature is invalid")


def verify_axon_response_signature(
    response: Any,
    *,
    expected_axon_hotkey: str,
    expected_dendrite_hotkey: str,
) -> None:
    """Verify the SDK's axon response-authentication tuple.

    Bittensor 10.2 signs response routing metadata only. This authenticates the
    selected axon key but does not provide payload-integrity evidence; payload
    integrity comes from :func:`verify_judgment_response_signature`.
    """
    axon = getattr(response, "axon", None)
    dendrite = getattr(response, "dendrite", None)
    nonce = getattr(axon, "nonce", None)
    uuid = getattr(axon, "uuid", None)
    signature = getattr(axon, "signature", None)
    if getattr(axon, "hotkey", None) != expected_axon_hotkey:
        raise ValueError("response axon hotkey does not match the selected request target")
    if getattr(dendrite, "hotkey", None) != expected_dendrite_hotkey:
        raise ValueError("response dendrite hotkey does not match the local requester")
    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise ValueError("response axon signature is missing its nonce")
    if not isinstance(uuid, str) or not uuid:
        raise ValueError("response axon signature is missing its UUID")
    if not isinstance(signature, str) or not signature:
        raise ValueError("response axon signature is missing")
    import bittensor as bt

    message = f"{nonce}.{expected_dendrite_hotkey}.{expected_axon_hotkey}.{uuid}"
    try:
        verified = bt.Keypair(ss58_address=expected_axon_hotkey).verify(message, signature)
    except Exception as exc:
        raise ValueError("response axon signature is invalid") from exc
    if not verified:
        raise ValueError("response axon signature is invalid")


def _canonical_identity(value: Any, missing: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(missing)
    try:
        return normalize_voter_id(value)
    except ValueError as exc:
        raise ValueError(missing) from exc


def authenticate_response(
    response: Any,
    *,
    dispatched: GovernanceDeliberation,
    expected_axon_hotkey: str,
    expected_dendrite_hotkey: str,
) -> JudgmentSynapse:
    """Authenticate one network judgment response against the caller's request.

    Every expected value comes from the caller: the axon hotkey the request was
    sent to, the local dendrite hotkey, and the dispatched request itself.
    Structural identity and request-binding checks run first; then the axon
    routing signature and the miner's request-bound body signature are
    verified. Returns the judgment with ``miner_uid`` set to the authenticated
    canonical identity. Raises ``ValueError`` on any mismatch.
    """
    expected_identity = _canonical_identity(
        expected_axon_hotkey, "request target is missing an authenticated hotkey"
    )
    authenticated_identity = _canonical_identity(
        getattr(getattr(response, "axon", None), "hotkey", None),
        "response is missing an authenticated hotkey",
    )
    if authenticated_identity != expected_identity:
        raise ValueError(
            f"authenticated response identity {authenticated_identity!r} does not match "
            f"request target {expected_identity!r}"
        )
    payload_identity = _canonical_identity(
        getattr(response, "miner_uid", None), "response payload is missing miner_uid"
    )
    if payload_identity != authenticated_identity:
        raise ValueError(
            f"payload miner_uid {payload_identity!r} does not match authenticated "
            f"identity {authenticated_identity!r}"
        )
    if getattr(response, "request_content_hash", None) != dispatched.request_content_hash:
        raise ValueError("signed judgment response does not match the dispatched request")
    if request_binding_digest(response) != request_binding_digest(dispatched):
        raise ValueError("signed judgment response context does not match the dispatched request")
    verify_axon_response_signature(
        response,
        expected_axon_hotkey=expected_axon_hotkey,
        expected_dendrite_hotkey=expected_dendrite_hotkey,
    )
    verify_judgment_response_signature(
        response,
        expected_signer_hotkey=expected_axon_hotkey,
        expected_dendrite_hotkey=expected_dendrite_hotkey,
    )
    return replace(bt_to_judgment(response), miner_uid=authenticated_identity)


# ---------------------------------------------------------------------------
# Conversion: DeliberationSynapse <-> GovernanceDeliberation
# ---------------------------------------------------------------------------


def deliberation_to_bt(synapse: DeliberationSynapse) -> GovernanceDeliberation:
    """Convert an internal DeliberationSynapse to a bt-compatible synapse.

    Maps frozen dataclass fields to the mutable Pydantic model.
    tuple → list for bittensor serialization compatibility.
    """
    return GovernanceDeliberation(
        task_id=synapse.task_id,
        task_dag_json=synapse.task_dag_json,
        constitution_hash=synapse.constitution_hash,
        domain=synapse.domain,
        required_capabilities=list(synapse.required_capabilities),
        deadline_seconds=synapse.deadline_seconds,
        escalation_type=synapse.escalation_type,
        impact_score=synapse.impact_score,
        impact_vector=dict(synapse.impact_vector),
        context=synapse.context,
        request_timestamp=synapse.timestamp,
    )


def bt_to_deliberation(bt_syn: GovernanceDeliberation) -> DeliberationSynapse:
    """Convert a bt synapse back to an internal DeliberationSynapse.

    Maps list → tuple for frozen dataclass compatibility.
    """
    return DeliberationSynapse(
        task_id=bt_syn.task_id,
        task_dag_json=bt_syn.task_dag_json,
        constitution_hash=bt_syn.constitution_hash,
        domain=bt_syn.domain,
        required_capabilities=tuple(bt_syn.required_capabilities),
        deadline_seconds=bt_syn.deadline_seconds,
        escalation_type=bt_syn.escalation_type,
        impact_score=bt_syn.impact_score,
        impact_vector=dict(bt_syn.impact_vector),
        context=bt_syn.context,
        timestamp=bt_syn.request_timestamp if bt_syn.request_timestamp else time.time(),
    )


# ---------------------------------------------------------------------------
# Conversion: JudgmentSynapse <-> GovernanceDeliberation response fields
# ---------------------------------------------------------------------------


def bt_to_judgment(bt_syn: GovernanceDeliberation) -> JudgmentSynapse:
    """Extract a JudgmentSynapse from a completed GovernanceDeliberation.

    The miner must have filled in response fields (judgment, reasoning, etc.).

    Raises:
        ValueError: If the synapse has no judgment (response not filled).
    """
    if bt_syn.judgment is None:
        raise ValueError(
            f"GovernanceDeliberation {bt_syn.task_id!r} has no judgment — "
            f"response fields not filled by miner"
        )
    # The miner must report the constitution it judged under (grace window
    # rotation may differ from the request); silence is not agreement.
    const_hash = bt_syn.miner_constitution_hash
    if not isinstance(const_hash, str) or not const_hash:
        raise ValueError(
            f"GovernanceDeliberation {bt_syn.task_id!r} has no miner_constitution_hash"
        )
    return JudgmentSynapse(
        task_id=bt_syn.task_id,
        miner_uid=bt_syn.miner_uid,
        judgment=bt_syn.judgment,
        reasoning=bt_syn.reasoning or "",
        artifact_hash=bt_syn.artifact_hash or "",
        constitutional_hash=const_hash,
        dna_valid=bt_syn.dna_valid if bt_syn.dna_valid is not None else False,
        dna_violations=tuple(bt_syn.dna_violations),
        dna_latency_ns=bt_syn.dna_latency_ns,
        domain=bt_syn.domain,
        timestamp=bt_syn.response_timestamp if bt_syn.response_timestamp else time.time(),
    )


def judgment_to_bt(
    judgment: JudgmentSynapse,
    bt_syn: GovernanceDeliberation,
) -> GovernanceDeliberation:
    """Fill response fields on a GovernanceDeliberation from a JudgmentSynapse.

    Mutates bt_syn in place and returns it (following bittensor's pattern
    where forward_fn modifies the synapse and returns it).
    """
    bt_syn.judgment = judgment.judgment
    bt_syn.reasoning = judgment.reasoning
    bt_syn.artifact_hash = judgment.artifact_hash
    bt_syn.dna_valid = judgment.dna_valid
    bt_syn.dna_violations = list(judgment.dna_violations)
    bt_syn.dna_latency_ns = judgment.dna_latency_ns
    bt_syn.miner_uid = judgment.miner_uid
    bt_syn.miner_constitution_hash = judgment.constitutional_hash
    bt_syn.response_timestamp = judgment.timestamp
    return bt_syn
