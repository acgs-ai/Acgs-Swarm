"""Tests for the DSSE / in-toto governance-receipt projector (Rung 1)."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import governance_receipts_dsse as dsse
from constitutional_swarm.governance_fixtures import valid_provenance_bundle
from constitutional_swarm.governance_receipts import canonical_json_bytes


def _receipt():
    # A real, signed governance receipt (carries an ed25519 SignatureRecord).
    return valid_provenance_bundle().receipts[0]


def _signer(seed: int = 7, key_id: str = "projector-key") -> dsse.DsseSigner:
    return dsse.DsseSigner(
        key_id=key_id,
        private_key=Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32),
    )


def _trusted(signer: dsse.DsseSigner) -> dict[str, str]:
    public_hex = signer.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return {signer.key_id: public_hex}


def test_statement_shape_happy_path() -> None:
    receipt = _receipt()
    statement = dsse.to_in_toto_statement(receipt)

    assert statement["_type"] == dsse.STATEMENT_TYPE
    assert statement["predicateType"] == dsse.PREDICATE_TYPE
    # subject derived from evidence_hashes, sorted by name, alg:value parsed.
    names = [s["name"] for s in statement["subject"]]
    assert names == sorted(receipt.payload.evidence_hashes)
    assert statement["subject"][0]["digest"] == {"sha256": "diff001"}  # "sha256:diff001"
    predicate = statement["predicate"]
    assert predicate["source_payload_digest"] == receipt.payload_digest
    assert predicate["decision"] == receipt.payload.decision
    assert set(predicate["roles"]) == set(receipt.payload.roles)
    assert predicate["validator_votes"][0]["validator_id"] == "review-agent"


def test_statement_canonical_bytes_are_deterministic() -> None:
    receipt = _receipt()
    first = canonical_json_bytes(dsse.to_in_toto_statement(receipt))
    second = canonical_json_bytes(dsse.to_in_toto_statement(receipt))
    assert first == second


def test_evidence_digest_parsing() -> None:
    # alg:value is split; a bare value defaults to the sha256 label.
    assert dsse._digest_set("sha256:deadbeef") == {"sha256": "deadbeef"}
    assert dsse._digest_set("blake3:abc") == {"blake3": "abc"}
    assert dsse._digest_set("deadbeef") == {"sha256": "deadbeef"}


def test_pae_known_answer_vector() -> None:
    # Authoritative DSSE spec example.
    assert (
        dsse.pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_signed_new_receipt_round_trip() -> None:
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)

    assert envelope["payloadType"] == dsse.DSSE_PAYLOAD_TYPE
    assert len(envelope["signatures"]) == 1
    assert envelope["signatures"][0]["keyid"] == signer.key_id
    # strict-DSSE shape: exactly payloadType/payload/signatures.
    assert set(envelope) == {"payloadType", "payload", "signatures"}

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))
    assert result["status"] == "valid"
    assert result["valid"] is True
    assert result["key_ids"] == [signer.key_id]


def test_tampered_payload_is_invalid() -> None:
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    # Re-encode a mutated statement under the same (now stale) signature.
    envelope["payload"] = base64.standard_b64encode(b'{"_type":"tampered"}').decode("ascii")

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))
    assert result["status"] == "invalid"
    assert result["valid"] is False


def test_untrusted_key_is_rejected() -> None:
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys={})
    assert result["status"] == "untrusted_key"
    assert result["valid"] is False


def test_unsigned_legacy_projection() -> None:
    envelope = dsse.to_dsse_envelope(_receipt())

    # strict-DSSE shape: no extra top-level keys; unsignedness == empty signatures.
    assert set(envelope) == {"payloadType", "payload", "signatures"}
    assert envelope["signatures"] == []

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys={"any": "00" * 32})
    assert result["status"] == "unsigned_projection"
    assert result["valid"] is False
    assert result["reason"] == dsse.UNSIGNED_PROJECTION_NOTE


def test_existing_receipt_signature_is_never_fabricated_into_envelope() -> None:
    receipt = _receipt()
    # The fixture receipt carries a real ed25519 detached signature.
    assert receipt.signatures[0].algorithm == "ed25519"
    assert receipt.signatures[0].signature_hex

    envelope = dsse.to_dsse_envelope(receipt)  # no signer
    # The old signature must not leak into the DSSE envelope.
    assert envelope["signatures"] == []
    old_sig_b64 = base64.standard_b64encode(
        bytes.fromhex(receipt.signatures[0].signature_hex)
    ).decode("ascii")
    assert old_sig_b64 not in canonical_json_bytes(envelope).decode("ascii")


def test_real_fixture_bundle_projects_without_error() -> None:
    # Regression: the alg:value evidence convention must project cleanly.
    for receipt in valid_provenance_bundle().receipts:
        statement = dsse.to_in_toto_statement(receipt)
        assert statement["subject"]
        envelope = dsse.to_dsse_envelope(receipt)
        assert envelope["payloadType"] == dsse.DSSE_PAYLOAD_TYPE


def test_non_dict_signature_entry_is_invalid() -> None:
    # A truthy-but-malformed signatures list must not crash the verifier.
    for bad in (["x"], [None], [5]):
        result = dsse.verify_dsse_envelope(
            {"payloadType": dsse.DSSE_PAYLOAD_TYPE, "payload": "e30=", "signatures": bad},
            trusted_public_keys={},
        )
        assert result["status"] == "invalid"
        assert result["valid"] is False

    # A valid first signature followed by a non-dict entry must still not crash.
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    envelope["signatures"].append("x")
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))
    assert result["status"] == "invalid"
    assert result["valid"] is False


def test_malformed_envelope_is_invalid() -> None:
    signer = _signer()
    base = dsse.to_dsse_envelope(_receipt(), signer=signer)
    trusted = _trusted(signer)

    no_payload = {k: v for k, v in base.items() if k != "payload"}
    assert dsse.verify_dsse_envelope(no_payload, trusted_public_keys=trusted)["status"] == "invalid"

    bad_b64 = {**base, "payload": "AAAAA"}  # length not a multiple of 4
    assert dsse.verify_dsse_envelope(bad_b64, trusted_public_keys=trusted)["status"] == "invalid"

    no_type = {k: v for k, v in base.items() if k != "payloadType"}
    assert dsse.verify_dsse_envelope(no_type, trusted_public_keys=trusted)["status"] == "invalid"


def test_missing_sig_key_is_invalid() -> None:
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    del envelope["signatures"][0]["sig"]
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))
    assert result["status"] == "invalid"


def test_wrong_pubkey_for_trusted_keyid_is_invalid() -> None:
    signer = _signer(seed=7)
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    # Same key_id is trusted, but mapped to a different public key.
    wrong = _trusted(_signer(seed=8, key_id=signer.key_id))
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=wrong)
    assert result["status"] == "invalid"
    assert result["valid"] is False


def test_payloadtype_swap_is_invalid() -> None:
    # PAE binds payloadType, so a signature is not transferable to another type.
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    envelope["payloadType"] = "application/octet-stream"
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))
    assert result["status"] == "invalid"


def test_multi_signature_one_forged_is_invalid() -> None:
    signer = _signer()
    envelope = dsse.to_dsse_envelope(_receipt(), signer=signer)
    forged = _signer(seed=9, key_id="forged-key")
    envelope["signatures"].append(
        {"keyid": forged.key_id, "sig": base64.standard_b64encode(b"\x00" * 64).decode("ascii")}
    )
    trusted = {**_trusted(signer), **_trusted(forged)}
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=trusted)
    assert result["valid"] is False


def test_digest_set_edge_cases() -> None:
    assert dsse._digest_set("sha256:") == {"sha256": ""}
    assert dsse._digest_set(":value") == {"sha256": "value"}  # empty alg -> default label
    assert dsse._digest_set("FOO:bar") == {"foo": "bar"}  # alg normalized lowercase


def test_claim_boundary_no_compliance_wording() -> None:
    banned = ("compliant", "certified", "compliance")
    strings = [
        dsse.__doc__ or "",
        dsse.STATEMENT_TYPE,
        dsse.DSSE_PAYLOAD_TYPE,
        dsse.PREDICATE_TYPE,
        dsse.UNSIGNED_PROJECTION_NOTE,
    ]
    for value in strings:
        lowered = value.lower()
        for word in banned:
            assert word not in lowered, f"claim-boundary leak: {word!r} in {value!r}"

    # The projected profile string stays the local "-shaped" profile.
    predicate = dsse.to_in_toto_statement(_receipt())["predicate"]
    assert predicate["profile_version"].endswith("intoto-dsse-shaped.v0.1")
