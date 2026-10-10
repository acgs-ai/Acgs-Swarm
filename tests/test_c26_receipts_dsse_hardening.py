"""C26 regression tests: governance receipt signer separation, grant re-validation,
fixture trust-root labelling, and strict DSSE envelope parsing.

Each test feeds an invalid input that the pre-C26 verifier accepted (or crashed on).
"""

from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from constitutional_swarm import governance_receipts_dsse as dsse
from constitutional_swarm.governance_fixtures import (
    fixture_trusted_signers,
    valid_provenance_bundle,
)
from constitutional_swarm.governance_receipts import (
    SignerTrustGrant,
    verify_bundle,
)


def _public_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _codes(verdict) -> set[str]:
    return {issue.code for issue in verdict.issues}


# --- governance-5: settlement signer separation ---------------------------------


@pytest.mark.parametrize("other_role", ["validator", "assigner"])
def test_c26_settlement_grant_rejects_combined_voter_or_assigner_role(other_role):
    with pytest.raises(ValidationError, match="settlement"):
        SignerTrustGrant(
            identity_id="settler",
            public_key_hex=_public_hex(Ed25519PrivateKey.generate()),
            roles=frozenset({"settlement", other_role}),
        )


@pytest.mark.parametrize("producer_alias", ["migration-plan-agent", " Migration-Plan-Agent"])
def test_c26_settlement_signer_that_is_the_producer_is_rejected(producer_alias):
    bundle = valid_provenance_bundle()
    trusted = copy.deepcopy(fixture_trusted_signers())
    # The settlement key signs receipts whose producer is migration-plan-agent.
    trusted["audit-agent-key"]["identity_id"] = producer_alias

    verdict = verify_bundle(bundle, trusted_signers=trusted)

    assert verdict.valid is False
    assert "settlement_signer_role_conflict" in _codes(verdict)


def test_c26_settlement_signer_conflict_does_not_flag_distinct_identities():
    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=fixture_trusted_signers())

    assert verdict.valid is True
    assert "settlement_signer_role_conflict" not in _codes(verdict)


# --- governance-6: grant instances are always re-validated ----------------------


def test_c26_model_construct_grant_with_overlapping_roles_is_rejected():
    trusted = dict(fixture_trusted_signers())
    raw = trusted["audit-agent-key"]
    trusted["audit-agent-key"] = SignerTrustGrant.model_construct(
        identity_id=raw["identity_id"],
        public_key_hex=raw["public_key_hex"],
        roles=frozenset({"assigner", "validator", "settlement"}),
    )

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trusted)

    assert verdict.valid is False
    assert "trust_registry_invalid" in _codes(verdict)


def test_c26_model_construct_grant_with_noncanonical_key_hex_is_rejected():
    trusted = dict(fixture_trusted_signers())
    raw = trusted["audit-agent-key"]
    trusted["audit-agent-key"] = SignerTrustGrant.model_construct(
        identity_id=raw["identity_id"],
        public_key_hex=str(raw["public_key_hex"]).upper(),
        roles=frozenset({"settlement"}),
    )

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trusted)

    assert verdict.valid is False
    assert "trust_registry_invalid" in _codes(verdict)


# --- governance-7: fixture trust roots never yield proof-grade evidence ---------


def test_c26_fixture_settlement_identities_carry_fixture_prefix():
    trusted = fixture_trusted_signers()
    settlement_ids = [
        grant["identity_id"] for grant in trusted.values() if grant["roles"] == ["settlement"]
    ]

    assert settlement_ids
    assert all(str(identity).startswith("fixture-") for identity in settlement_ids)


def test_c26_fixture_trust_root_is_labelled_development():
    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=fixture_trusted_signers())

    assert verdict.valid is True
    assert verdict.evidence_policy == "development"


def test_c26_renamed_fixture_keys_are_still_labelled_development():
    trusted = copy.deepcopy(fixture_trusted_signers())
    for key_id in ("audit-agent-key", "audit-agent-key-2"):
        trusted[key_id]["identity_id"] = f"production-coordinator-{key_id}"

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trusted)

    assert verdict.evidence_policy == "development"


def test_c26_non_fixture_trust_root_keeps_proof_grade_label():
    trusted = {
        "operator-key": {
            "identity_id": "operator-settlement",
            "public_key_hex": _public_hex(Ed25519PrivateKey.generate()),
            "roles": ["settlement"],
        }
    }

    verdict = verify_bundle(valid_provenance_bundle(), trusted_signers=trusted)

    assert verdict.valid is False
    assert verdict.evidence_policy == "proof_grade"


# --- governance-15: strict DSSE envelope parsing --------------------------------


def _signer() -> dsse.DsseSigner:
    return dsse.DsseSigner(key_id="projector-key", private_key=Ed25519PrivateKey.generate())


def _trusted(signer: dsse.DsseSigner) -> dict[str, str]:
    return {signer.key_id: _public_hex(signer.private_key)}


def test_c26_dsse_foreign_payload_type_with_valid_signature_is_rejected():
    signer = _signer()
    envelope = dsse.to_dsse_envelope(valid_provenance_bundle().receipts[0], signer=signer)
    foreign_type = "application/octet-stream"
    body = base64.b64decode(envelope["payload"])
    signature = signer.private_key.sign(dsse.pae(foreign_type, body))
    envelope["payloadType"] = foreign_type
    envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode("ascii")

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))

    assert result["status"] == "invalid"
    assert result["valid"] is False


@pytest.mark.parametrize("field", ["payload", "sig"])
@pytest.mark.parametrize("mutation", ["embedded_newline", "non_alphabet_suffix"])
def test_c26_dsse_noncanonical_base64_is_rejected(field, mutation):
    signer = _signer()
    envelope = dsse.to_dsse_envelope(valid_provenance_bundle().receipts[0], signer=signer)
    target = envelope if field == "payload" else envelope["signatures"][0]
    value = target[field]
    target[field] = (
        value[:8] + "\n" + value[8:] if mutation == "embedded_newline" else value + "!!!!"
    )

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))

    assert result["status"] == "invalid"
    assert result["valid"] is False


@pytest.mark.parametrize("bad_keyid", [["projector-key"], {"k": 1}, 5, None])
def test_c26_dsse_non_string_keyid_is_structured_invalid(bad_keyid):
    signer = _signer()
    envelope = dsse.to_dsse_envelope(valid_provenance_bundle().receipts[0], signer=signer)
    envelope["signatures"][0]["keyid"] = bad_keyid

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))

    assert result["status"] == "invalid"
    assert result["valid"] is False
    assert result["key_ids"] == []


@pytest.mark.parametrize("field", ["payload", "payloadType"])
def test_c26_dsse_non_string_envelope_fields_are_rejected(field):
    signer = _signer()
    envelope = dsse.to_dsse_envelope(valid_provenance_bundle().receipts[0], signer=signer)
    envelope[field] = envelope[field].encode("ascii")

    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys=_trusted(signer))

    assert result["status"] == "invalid"
    assert result["valid"] is False


# --- rework r1 ------------------------------------------------------------------


class _StrSubclass(str):
    """A str subclass: passes isinstance(str) but is not an exact str."""


def _bundle_with_identity(field, value):
    bundle = valid_provenance_bundle()
    first = bundle.receipts[0]
    if field == "metadata.producer_id":
        update = {"metadata": {**first.payload.metadata, "producer_id": value}}
    else:
        update = {"signed_assignment": {**first.payload.signed_assignment, "assigner_id": value}}
    payload = first.payload.model_copy(update=update)
    receipt = first.model_copy(update={"payload": payload})
    return bundle.model_copy(update={"receipts": [receipt, *bundle.receipts[1:]]})


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("metadata.producer_id", _StrSubclass("migration-plan-agent")),
        ("metadata.producer_id", "   "),
        ("signed_assignment.assigner_id", _StrSubclass("fixture-assignment-authority")),
        ("signed_assignment.assigner_id", 7),
        ("signed_assignment.assigner_id", ["fixture-assignment-authority"]),
    ],
)
def test_c26_r1_malformed_settlement_conflict_candidate_is_structured_issue(field, bad):
    verdict = verify_bundle(
        _bundle_with_identity(field, bad), trusted_signers=fixture_trusted_signers()
    )

    assert verdict.valid is False
    assert "settlement_signer_identity_malformed" in _codes(verdict)


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        5,
        "envelope",
        ["payloadType"],
        {"payloadType": dsse.DSSE_PAYLOAD_TYPE, "payload": "e30=", "signatures": 5},
        {"payloadType": dsse.DSSE_PAYLOAD_TYPE, "payload": "e30=", "signatures": "sig"},
        {"payloadType": dsse.DSSE_PAYLOAD_TYPE, "payload": "e30=", "signatures": {"k": 1}},
        {"payloadType": dsse.DSSE_PAYLOAD_TYPE, "payload": "e30=", "signatures": (1,)},
    ],
)
def test_c26_r1_dsse_malformed_envelope_or_signatures_is_structured_invalid(envelope):
    result = dsse.verify_dsse_envelope(envelope, trusted_public_keys={})

    assert result == {
        "status": "invalid",
        "valid": False,
        "reason": result["reason"],
        "key_ids": [],
    }
    assert result["reason"]


def test_c26_r1_dsse_missing_or_empty_signatures_stays_unsigned_projection():
    for signatures in (None, []):
        envelope = dsse.to_dsse_envelope(valid_provenance_bundle().receipts[0])
        envelope["signatures"] = signatures
        result = dsse.verify_dsse_envelope(envelope, trusted_public_keys={})
        assert result["status"] == "unsigned_projection"


def test_c26_r1_require_proof_grade_rejects_development_evidence():
    bundle = valid_provenance_bundle()
    trusted = fixture_trusted_signers()

    default = verify_bundle(bundle, trusted_signers=trusted)
    strict = verify_bundle(bundle, trusted_signers=trusted, require_proof_grade=True)

    assert default.valid is True
    assert default.evidence_policy == "development"
    assert strict.valid is False
    assert strict.evidence_policy == "development"
    assert "evidence_policy_not_proof_grade" in _codes(strict)


def test_c26_r1_require_proof_grade_rejects_dev_vote_opt_out():
    verdict = verify_bundle(
        valid_provenance_bundle(),
        trusted_signers=fixture_trusted_signers(),
        require_independent_votes=False,
        require_proof_grade=True,
    )

    assert verdict.valid is False
    assert "evidence_policy_not_proof_grade" in _codes(verdict)


def test_c26_r1_require_proof_grade_does_not_add_issue_for_proof_grade_policy():
    trusted = {
        "operator-key": {
            "identity_id": "operator-settlement",
            "public_key_hex": _public_hex(Ed25519PrivateKey.generate()),
            "roles": ["settlement"],
        }
    }

    verdict = verify_bundle(
        valid_provenance_bundle(), trusted_signers=trusted, require_proof_grade=True
    )

    assert verdict.evidence_policy == "proof_grade"
    assert "evidence_policy_not_proof_grade" not in _codes(verdict)


def _write_cli_inputs(tmp_path):
    import json

    from constitutional_swarm.governance_receipts import bundle_to_json

    bundle_path = tmp_path / "bundle.json"
    trust_path = tmp_path / "trust.json"
    bundle_path.write_text(bundle_to_json(valid_provenance_bundle()), encoding="utf-8")
    trust_path.write_text(json.dumps(fixture_trusted_signers()), encoding="utf-8")
    return bundle_path, trust_path


def test_c26_r1_cli_require_proof_grade_fails_closed_on_fixture_root(tmp_path, capsys):
    import json

    from constitutional_swarm.governance_receipts_cli import main

    bundle_path, trust_path = _write_cli_inputs(tmp_path)
    base_args = [str(bundle_path), "--trusted-signers", str(trust_path)]

    assert main(base_args) == 0
    assert json.loads(capsys.readouterr().out)["evidence_policy"] == "development"

    assert main([*base_args, "--require-proof-grade"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False
    assert "evidence_policy_not_proof_grade" in {i["code"] for i in output["issues"]}


def test_c26_r1_cli_rejects_require_proof_grade_with_dev_opt_out(tmp_path, capsys):
    import json

    from constitutional_swarm.governance_receipts_cli import main

    bundle_path, trust_path = _write_cli_inputs(tmp_path)

    code = main(
        [
            str(bundle_path),
            "--trusted-signers",
            str(trust_path),
            "--require-proof-grade",
            "--allow-dev-evidence",
        ]
    )

    assert code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False
    assert "cannot be combined" in output["issues"][0]["message"]
