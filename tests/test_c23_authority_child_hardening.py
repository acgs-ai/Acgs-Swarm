"""C23 regression tests: authority child key loading, validation and error surface.

Each test feeds invalid or adversarial input and expects fail-closed rejection.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import authority_child
from constitutional_swarm.apcc.verifier import TrustBinding, TrustRole
from constitutional_swarm.authority_child import (
    KeySourceRef,
    OutboxSinkRef,
    _load_file_keys_raw,
    _LoadedKeys,
    _PolicySigner,
    _validate_keys,
)
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.strict_json import StrictJSONError
from tests.gcb_apcc_support import authority_child_config


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _b64(key: Ed25519PrivateKey) -> str:
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(seed).rstrip(b"=").decode()


def _fixture(tmp_path: Path, **kwargs):
    config = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys", **kwargs
    )
    raw = Path(config.key_source.location).read_bytes()
    return config, raw, _load_file_keys_raw(raw, config.key_source)


# ------------------------------------------------------------- authority-child-1


def test_baseline_fixture_keys_validate(tmp_path) -> None:
    config, _raw_bundle, keys = _fixture(tmp_path)
    _validate_keys(config.authority, keys)


@pytest.mark.parametrize(
    ("field", "source"),
    [
        ("control", "commit"),
        ("control", "registry"),
        ("identity", "registry"),
        ("identity", "status"),
        ("identity", "control"),
    ],
)
def test_validate_keys_rejects_one_private_key_serving_two_roles(
    tmp_path, field: str, source: str
) -> None:
    config, _raw_bundle, keys = _fixture(tmp_path)
    reused = replace(keys, **{field: getattr(keys, source)})
    with pytest.raises(PermissionError, match="distinct"):
        _validate_keys(config.authority, reused)


def test_validate_keys_rejects_control_key_equal_to_a_policy_key(tmp_path) -> None:
    config, _raw_bundle, keys = _fixture(tmp_path)
    reused = replace(keys, control=keys.policy["1"])
    with pytest.raises(PermissionError, match="distinct"):
        _validate_keys(config.authority, reused)


def test_validate_keys_rejects_two_policy_versions_sharing_one_key(tmp_path) -> None:
    config, _raw_bundle, keys = _fixture(tmp_path, policy_versions=(("1", 1), ("2", 2)))
    shared = keys.policy["1"]
    # The config must also pin the shared key for both versions, so only the
    # distinctness rule can reject it.
    authority = replace(
        config.authority,
        policy_trust=tuple(
            replace(binding, public_key=_raw(shared))
            for binding in config.authority.policy_trust
        ),
    )
    reused = replace(keys, policy={"1": shared, "2": shared})
    with pytest.raises(PermissionError, match="distinct"):
        _validate_keys(authority, reused)


@pytest.mark.parametrize("role", ["control", "identity"])
def test_validate_keys_rejects_producer_key_doubling_as_authority_key(
    tmp_path, role: str
) -> None:
    # An agent holding a producer key must never also hold a control or
    # identity key; the config's cross-role check cannot see those two roles.
    config, _raw_bundle, keys = _fixture(tmp_path)
    first = config.authority.producer_trust[0]
    authority = replace(
        config.authority,
        producer_trust=(
            *config.authority.producer_trust,
            TrustBinding(
                TrustRole.PRODUCER,
                ("c23-agent", *first.scope[1:]),
                "c23-producer-key",
                _raw(getattr(keys, role)),
            ),
        ),
    )
    with pytest.raises(PermissionError, match="distinct"):
        _validate_keys(authority, keys)


def test_validate_keys_rejects_unmatched_second_registry_binding(tmp_path) -> None:
    config, _raw_bundle, keys = _fixture(tmp_path)
    first = config.authority.registry_trust[0]
    stranger = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    authority = replace(
        config.authority,
        registry_trust=(
            first,
            TrustBinding(
                TrustRole.REGISTRY,
                (*first.scope[:-1], "2"),
                "c23-unmatched-registry-key",
                _raw(stranger),
            ),
        ),
    )
    with pytest.raises(PermissionError, match="registry public key mismatch"):
        _validate_keys(authority, keys)


# ------------------------------------------------------------- authority-child-2


def _two_version_signer() -> tuple[_PolicySigner, Ed25519PrivateKey, Ed25519PrivateKey]:
    first = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    second = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
    return _PolicySigner({"1": first, "2": second}), first, second


def test_policy_signer_rejects_implicit_version() -> None:
    signer, _first, _second = _two_version_signer()
    with pytest.raises(ValueError, match="policy version"):
        signer.public_key_bytes()
    with pytest.raises(ValueError, match="policy version"):
        signer.public_key_bytes(None)


@pytest.mark.parametrize("version", [1, b"1", "", "3"])
def test_policy_signer_rejects_non_string_or_unknown_version(version: object) -> None:
    signer, _first, _second = _two_version_signer()
    with pytest.raises(ValueError, match="policy version"):
        signer.public_key_bytes(version)  # type: ignore[arg-type]


def test_policy_signer_returns_exact_requested_version() -> None:
    signer, first, second = _two_version_signer()
    assert signer.public_key_bytes("2") == _raw(second)
    assert signer.public_key_bytes("1") == _raw(first)


def test_policy_signer_error_is_not_type_error_for_caller_fallback() -> None:
    # governed_commit._policy_signer_public_key retries with no argument on
    # TypeError; the child signer must never raise TypeError for a bad version.
    signer, _first, _second = _two_version_signer()
    with pytest.raises(ValueError) as caught:
        signer.public_key_bytes(None)
    assert not isinstance(caught.value, TypeError)


# ------------------------------------------------------------- authority-child-3


@pytest.mark.parametrize(
    ("error", "channel", "code"),
    [
        (ValueError("/var/lib/secret.db: column x has bad bytes"), "execution", "invalid_request"),
        (TypeError("unsupported operand for 'str' and 'int'"), "admin", "invalid_request"),
        (KeyError("leak-marker-node"), "execution", "unknown_operation"),
        (KeyError("leak-marker-node"), "admin", "unknown_admin_operation"),
        (KeyError("leak-marker-node"), "status-signing", "unknown_status_signing_operation"),
        (RuntimeError("sqlite at /tmp/x: disk I/O error"), "execution", "internal_error"),
        (OSError(5, "Input/output error"), "admin", "internal_error"),
        (PermissionError("policy public key mismatch for 0xdead"), "admin", "permission_denied"),
        (GovernanceBypassDenied("APCC authority service is not attached"), "execution", "governance_denied"),
        (GovernanceBypassDenied(""), "execution", "governance_denied"),
        (ValueError("bad 'quoted' value"), "execution", "invalid_request"),
        (ValueError("path/to/secret"), "execution", "invalid_request"),
        (ValueError("x" * 65), "execution", "invalid_request"),
        # Space-free attacker-chosen strings must not be echoed either.
        (ValueError("leak_marker_node"), "execution", "invalid_request"),
        (GovernanceBypassDenied("attacker_node_name"), "execution", "governance_denied"),
        (GovernanceBypassDenied("node_not_ready:attacker_status"), "execution", "governance_denied"),
        (GovernanceBypassDenied("stale_or_mismatched_attempt_attacker"), "execution", "governance_denied"),
        (LookupError("leak_marker_node"), "admin", "unknown_admin_operation"),
        (PermissionError("secret_token_value"), "admin", "permission_denied"),
        (ValueError("invalid_commit_operation"), "execution", "invalid_request"),
    ],
)
def test_request_error_code_never_forwards_free_text(
    error: BaseException, channel: str, code: str
) -> None:
    assert authority_child._request_error_code(error, channel) == code


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ValueError("empty_node_status_batch"), "empty_node_status_batch"),
        (ValueError("invalid_request"), "invalid_request"),
        (GovernanceBypassDenied("untrusted_policy_binding"), "untrusted_policy_binding"),
        (GovernanceBypassDenied("node_not_ready:blocked"), "node_not_ready:blocked"),
        (GovernanceBypassDenied("node_not_ready:result_produced"), "node_not_ready:result_produced"),
        (GovernanceBypassDenied("ISOLATION_UNAVAILABLE"), "ISOLATION_UNAVAILABLE"),
        (ValueError("INVALID_DECIMAL_STRING"), "INVALID_DECIMAL_STRING"),
        (GovernanceBypassDenied("stale_or_mismatched_attempt_agent_id"), "stale_or_mismatched_attempt_agent_id"),
        (LookupError("unknown_operation"), "unknown_operation"),
    ],
)
def test_request_error_code_keeps_stable_protocol_tokens(
    error: BaseException, code: str
) -> None:
    assert authority_child._request_error_code(error, "execution") == code


def test_real_child_request_error_does_not_echo_exception_text(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "leak.db", tmp_path / "leak.keys")
    )
    try:
        assert handle._execution_channel is not None
        channel = handle._execution_channel
        with pytest.raises(GovernanceBypassDenied) as caught:
            channel._rpc(
                "node_state", {"workflow_id": "wf", "node_id": "leak-marker-node"}
            )
        assert "leak-marker-node" not in str(caught.value)
        assert str(caught.value) == "unknown_operation"
        assert channel.health()["authority_pid"] == handle.pid
    finally:
        handle.close()


def test_real_child_startup_error_sends_type_name_only(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys"
    )
    wrong = replace(
        config,
        key_source=KeySourceRef("file", config.key_source.location, bytes(range(32))),
    )
    with pytest.raises(RuntimeError, match="startup failed") as caught:
        start_authority(wrong)
    message = str(caught.value)
    assert "identity mismatch" not in message
    assert message.rstrip(": ").endswith("PermissionError")


# ------------------------------------------------------------- opt-4


@pytest.mark.parametrize("kind", ["kms", "pkcs11", "", "FILE"])
def test_key_source_ref_rejects_unsupported_custody_kind(kind: str) -> None:
    with pytest.raises(ValueError, match="key source"):
        KeySourceRef(kind, "somewhere", b"\x00" * 32)  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["file", "consumed"])
def test_key_source_ref_accepts_supported_kinds(kind: str) -> None:
    assert KeySourceRef(kind, "somewhere", b"\x00" * 32).kind == kind  # type: ignore[arg-type]


def test_outbox_sink_ref_has_no_unused_location_field() -> None:
    names = {field.name for field in dataclasses.fields(OutboxSinkRef)}
    assert names == {"kind"}
    with pytest.raises(TypeError):
        OutboxSinkRef(location="anywhere")  # type: ignore[call-arg]


# ------------------------------------------------------------- opt-1


def test_key_bundle_duplicate_member_is_rejected_by_shared_strict_parser(
    tmp_path,
) -> None:
    config, raw, _keys = _fixture(tmp_path)
    body = json.loads(raw)
    stranger = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
    text = raw.decode()
    duplicated = text[:-1] + f',"commit":"{_b64(stranger)}"' + "}"
    assert json.loads(duplicated)["commit"] != body["commit"]
    with pytest.raises(StrictJSONError, match="duplicate"):
        _load_file_keys_raw(duplicated.encode(), config.key_source)


@pytest.mark.parametrize("payload", [b'{"policy": NaN}', b'{"policy": 1.5}'])
def test_key_bundle_rejects_non_strict_numbers(tmp_path, payload: bytes) -> None:
    config, _raw_bundle, _keys = _fixture(tmp_path)
    with pytest.raises(StrictJSONError):
        _load_file_keys_raw(payload, config.key_source)


def test_key_bundle_rejects_oversized_input_with_strict_error(tmp_path) -> None:
    config, _raw_bundle, _keys = _fixture(tmp_path)
    with pytest.raises(StrictJSONError):
        _load_file_keys_raw(b" " * 1_048_577, config.key_source)


def test_authority_child_has_no_private_duplicate_key_hook() -> None:
    assert not hasattr(authority_child, "_reject_duplicate_keys")


def test_loaded_keys_type_is_unchanged() -> None:
    assert {field.name for field in dataclasses.fields(_LoadedKeys)} == {
        "policy",
        "registry",
        "control",
        "commit",
        "status",
        "identity",
    }


def _literal_codes(module_path: Path) -> set[str]:
    pattern = re.compile(
        r"(?:GovernanceBypassDenied|ValueError|LookupError|PermissionError|TypeError)"
        r"\(\s*\"([A-Za-z][A-Za-z0-9_:]*)\""
    )
    return set(pattern.findall(module_path.read_text(encoding="utf-8")))


def test_error_code_allowlist_covers_every_literal_handler_code() -> None:
    src = Path(authority_child.__file__).resolve().parent
    literal = set()
    for name in ("authority_service.py", "governed_commit.py"):
        literal |= _literal_codes(src / name)
    for path in sorted((src / "apcc").glob("*.py")):
        literal |= _literal_codes(path)
    missing = literal - authority_child._PROTOCOL_ERROR_CODES
    assert not missing, sorted(missing)


def test_error_code_allowlist_is_a_fixed_frozenset() -> None:
    assert type(authority_child._PROTOCOL_ERROR_CODES) is frozenset
    assert not hasattr(authority_child, "_STABLE_ERROR_CODE")
