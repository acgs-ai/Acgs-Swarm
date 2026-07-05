"""DSSE / in-toto projection for local v0.1 governance receipts.

One-way *shape* projection of a local ``acgs.local.intoto-dsse-shaped.v0.1``
governance receipt (see ``governance_receipts.py``) onto the in-toto Statement
and DSSE envelope shapes, so external supply-chain tooling can read it. This is a
projection for interoperability only -- it is not an implementation of, and
asserts no standards claim against, in-toto, DSSE, SCITT, Sigstore, COSE, or
W3C VC. The authoritative artifact remains the ``GovernanceReceipt`` itself.

Design constraint (load-bearing): DSSE signs the Pre-Authentication Encoding
(PAE) of ``(payloadType, body)``, which is a *different* pre-image from the
receipt's detached signature (which signs ``payload_canonical_bytes`` directly).
Therefore a historical receipt's signature cannot be reused as a DSSE signature.
Legacy receipts project to an *unsigned* envelope (re-verify against the
authoritative receipt); new receipts may be signed at projection time by passing
a :class:`DsseSigner`.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.governance_receipts import (
    GovernanceReceipt,
    canonical_json_bytes,
)

# in-toto Statement v1 type and media type. Using the canonical strings is what
# makes the projection readable by in-toto tooling; it is not a conformance claim.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
# ACGS-owned predicate type — the governance semantics are ours, not in-toto's.
PREDICATE_TYPE = "https://acgs.ai/attestations/governance-receipt/v0.1"
# Default algorithm label for an evidence digest recorded without an ``alg:`` prefix.
EVIDENCE_DIGEST_ALG = "sha256"
# Human-readable marker placed on unsigned projections. Worded to avoid asserting
# any standards conformance (see the claim-boundary test).
UNSIGNED_PROJECTION_NOTE = (
    "Unsigned one-way shape projection of a local v0.1 governance receipt. "
    "Re-verify against the authoritative receipt; this projection is for "
    "interoperability only and is not the authoritative artifact."
)

__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "EVIDENCE_DIGEST_ALG",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "UNSIGNED_PROJECTION_NOTE",
    "DsseSigner",
    "pae",
    "to_dsse_envelope",
    "to_in_toto_statement",
    "verify_dsse_envelope",
]


@dataclass(frozen=True)
class DsseSigner:
    """Binds a key id to an Ed25519 private key for DSSE signing of new receipts."""

    key_id: str
    private_key: Ed25519PrivateKey


def _digest_set(raw_digest: str) -> dict[str, str]:
    """Project a receipt evidence digest onto an in-toto digest set.

    Receipt evidence digests use the ``alg:value`` convention (e.g.
    ``"sha256:diff001"``). The value is carried verbatim -- this projection does
    not re-hash or validate upstream evidence. A digest without an ``alg:``
    prefix is labelled :data:`EVIDENCE_DIGEST_ALG`.
    """

    if ":" in raw_digest:
        alg, _, value = raw_digest.partition(":")
        alg = alg.strip().lower() or EVIDENCE_DIGEST_ALG
        return {alg: value}
    return {EVIDENCE_DIGEST_ALG: raw_digest}


def to_in_toto_statement(receipt: GovernanceReceipt) -> dict:
    """Project a governance receipt onto an in-toto Statement v1 dict.

    The statement is deterministic: subjects are sorted by name and the bytes are
    produced via the receipt module's canonical JSON encoding.
    """

    payload = receipt.payload
    subjects = [
        {"name": name, "digest": _digest_set(digest)}
        for name, digest in sorted(payload.evidence_hashes.items())
    ]
    predicate = {
        "receipt_id": payload.receipt_id,
        "action": payload.action,
        "policy_version": payload.policy_version,
        "policy_hash": payload.policy_hash,
        "decision": payload.decision,
        "roles": {
            role: identity.model_dump(mode="json") for role, identity in payload.roles.items()
        },
        "validator_votes": [vote.model_dump(mode="json") for vote in payload.validator_votes],
        "rejected_alternative": payload.rejected_alternative,
        "previous_receipt_hash": payload.previous_receipt_hash,
        "metadata": payload.metadata,
        "profile_version": receipt.profile_version,
        "source_payload_digest": receipt.payload_digest,
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: ``DSSEv1 SP len(type) SP type SP len(body) SP body``.

    Lengths are byte counts; ``body`` is the raw (pre-base64) payload.
    """

    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(body)).encode("ascii"),
            body,
        ]
    )


def to_dsse_envelope(receipt: GovernanceReceipt, *, signer: DsseSigner | None = None) -> dict:
    """Project a receipt onto a DSSE envelope.

    The envelope is strict DSSE -- exactly ``payloadType``/``payload``/``signatures``,
    no extra top-level keys -- so strict consumers (e.g. cosign) can ingest it.
    With no ``signer`` the projection is unsigned (``signatures: []``); its
    unsigned status is surfaced by :func:`verify_dsse_envelope` as
    ``unsigned_projection`` rather than by an in-envelope marker. With a
    ``signer`` the statement bytes are signed over the DSSE PAE with Ed25519. The
    receipt's own detached signatures are never copied into the envelope
    (different pre-image).
    """

    statement = to_in_toto_statement(receipt)
    body = canonical_json_bytes(statement)
    envelope: dict = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.standard_b64encode(body).decode("ascii"),
        "signatures": [],
    }
    if signer is None:
        return envelope

    signature = signer.private_key.sign(pae(DSSE_PAYLOAD_TYPE, body))
    envelope["signatures"] = [
        {
            "keyid": signer.key_id,
            "sig": base64.standard_b64encode(signature).decode("ascii"),
        }
    ]
    return envelope


def verify_dsse_envelope(
    envelope: Mapping,
    *,
    trusted_public_keys: Mapping[str, str],
) -> dict:
    """Verify a projected DSSE envelope.

    Returns a structured result. Every result carries the same keys --
    ``status`` (str), ``valid`` (bool), ``reason`` (str), ``key_ids`` (list[str])
    -- so callers can read one shape regardless of outcome. ``status`` is one of:

    - ``unsigned_projection`` -- no signatures present (a legacy projection).
    - ``untrusted_key`` -- a signature references a key id not in
      ``trusted_public_keys``.
    - ``invalid`` -- a signature failed verification or the envelope is malformed.
    - ``valid`` -- every signature verified against a trusted key.

    ``trusted_public_keys`` maps key id to a hex-encoded raw Ed25519 public key.

    A ``valid`` result attests only that the envelope's own payload was signed by
    a trusted key. It does **not** bind that payload to any particular receipt:
    callers must decode the statement and check ``source_payload_digest`` /
    ``receipt_id`` against the receipt they expected before trusting it.
    """

    signatures = list(envelope.get("signatures") or [])
    if not signatures:
        return {
            "status": "unsigned_projection",
            "valid": False,
            "reason": UNSIGNED_PROJECTION_NOTE,
            "key_ids": [],
        }

    try:
        body = base64.standard_b64decode(str(envelope["payload"]))
        message = pae(str(envelope["payloadType"]), body)
    except (KeyError, ValueError, TypeError) as exc:
        return {
            "status": "invalid",
            "valid": False,
            "reason": f"malformed envelope: {exc}",
            "key_ids": [],
        }

    for entry in signatures:
        if not isinstance(entry, Mapping):
            return {
                "status": "invalid",
                "valid": False,
                "reason": "malformed signature entry",
                "key_ids": [],
            }
        key_id = entry.get("keyid", "")
        public_hex = trusted_public_keys.get(key_id)
        if public_hex is None:
            return {
                "status": "untrusted_key",
                "valid": False,
                "reason": f"key id {key_id!r} is not trusted",
                "key_ids": [key_id],
            }
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            public_key.verify(base64.standard_b64decode(str(entry["sig"])), message)
        except (InvalidSignature, ValueError, KeyError) as exc:
            return {
                "status": "invalid",
                "valid": False,
                "reason": str(exc),
                "key_ids": [key_id],
            }

    return {
        "status": "valid",
        "valid": True,
        "reason": "",
        "key_ids": [e.get("keyid", "") for e in signatures],
    }
