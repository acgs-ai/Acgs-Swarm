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

import json
import time
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from constitutional_swarm.bittensor.synapses import (
    DeliberationSynapse,
    JudgmentSynapse,
    _canonical_synapse_hash,
)
from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

_JUDGMENT_RESPONSE_DOMAIN = b"constitutional-swarm.bittensor-judgment-response.v1\x00"
JUDGMENT_RESPONSE_PROTOCOL_VERSION = 1

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

    # When bittensor is available, declare hash fields for integrity
    required_hash_fields: ClassVar[tuple[str, ...]] = (
        "task_id",
        "constitution_hash",
        "task_dag_json",
    )

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


def canonical_judgment_response_bytes(bt_syn: GovernanceDeliberation) -> bytes:
    """Encode the request-bound judgment response for miner signing."""
    dendrite = getattr(bt_syn, "dendrite", None)
    payload = {
        "protocol_version": bt_syn.response_protocol_version,
        "request": {
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
    encoded = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return _JUDGMENT_RESPONSE_DOMAIN + encoded


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
    import bittensor as bt

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
    try:
        verified = bt.Keypair(ss58_address=expected_signer_hotkey).verify(
            canonical_judgment_response_bytes(bt_syn),
            bt_syn.response_signature,
        )
    except Exception as exc:
        raise ValueError("judgment response body signature is invalid") from exc
    if not verified:
        raise ValueError("judgment response body signature is invalid")


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
    # Miner may report its own constitution hash (grace window);
    # fall back to the request's constitution_hash
    const_hash = bt_syn.miner_constitution_hash or bt_syn.constitution_hash
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
