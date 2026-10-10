"""Regression coverage for C17 cleanup hardening."""

import pytest

from constitutional_swarm.governed_handoff import PolicyEngine


@pytest.mark.parametrize(
    "raw_path",
    [
        ".envrc~",
        "config/.envrc~",
        ".envrc.local",
        "config/.ENVRC.bak",
        "nested/../config/.ENVRC.bak",
    ],
)
def test_c17_envrc_backup_and_suffix_variants_require_review(
    tmp_path, raw_path
) -> None:
    engine = PolicyEngine(
        {"policy": {"protected_paths": []}},
        {"roles": {}},
        tmp_path,
    )

    decision = engine.decide("file_write", raw_path)

    assert decision.outcome == "human_review_required"
    assert "protected path" in decision.reason


@pytest.mark.parametrize(
    "raw_path",
    [
        ".envrc-template",
        ".envrcfile",
        "config/service.envrc.local",
    ],
)
def test_c17_similarly_named_envrc_files_remain_allowed(tmp_path, raw_path) -> None:
    engine = PolicyEngine(
        {"policy": {"protected_paths": []}},
        {"roles": {}},
        tmp_path,
    )

    assert engine.decide("file_write", raw_path).outcome == "allow"


def _c17_load_testnet_deploy_module():
    import importlib.util
    from pathlib import Path

    script_path = Path(__file__).parents[1] / "scripts" / "testnet_deploy.py"
    spec = importlib.util.spec_from_file_location("c17_testnet_deploy", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _c17_write_authority_keyfile(path) -> None:
    import json

    path.write_text(
        json.dumps(
            {
                "assigner_id": "c17-assigner",
                "assigner_private_key_hex": "11" * 32,
                "request_signing_private_key_hex": "22" * 32,
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("mode", "accepted"),
    [
        (0o600, True),
        (0o640, False),
        (0o644, False),
    ],
)
def test_c17_authority_keyfile_requires_owner_only_permissions(
    tmp_path, mode, accepted
) -> None:
    deploy = _c17_load_testnet_deploy_module()
    keyfile = tmp_path / "authority-keys.json"
    _c17_write_authority_keyfile(keyfile)
    keyfile.chmod(mode)

    if accepted:
        assert deploy._load_authority_keys(str(keyfile)).assigner_id == "c17-assigner"
    else:
        with pytest.raises(ValueError, match="group or other permissions"):
            deploy._load_authority_keys(str(keyfile))


def test_c17_authority_keyfile_requires_effective_user_ownership(
    tmp_path, monkeypatch
) -> None:
    import os

    deploy = _c17_load_testnet_deploy_module()
    keyfile = tmp_path / "authority-keys.json"
    _c17_write_authority_keyfile(keyfile)
    keyfile.chmod(0o600)
    monkeypatch.setattr(deploy.os, "geteuid", lambda: os.stat(keyfile).st_uid + 1)
    monkeypatch.setattr(
        deploy.json,
        "load",
        lambda _handle: pytest.fail("untrusted keyfile was parsed"),
    )

    with pytest.raises(ValueError, match="owned by the current effective user"):
        deploy._load_authority_keys(str(keyfile))


def test_c17_authority_keyfile_rejects_symlink(tmp_path) -> None:
    deploy = _c17_load_testnet_deploy_module()
    target = tmp_path / "authority-keys-target.json"
    _c17_write_authority_keyfile(target)
    target.chmod(0o600)
    symlink = tmp_path / "authority-keys.json"
    symlink.symlink_to(target)

    with pytest.raises(ValueError, match="regular file"):
        deploy._load_authority_keys(str(symlink))


def test_c17_authority_keyfile_rejects_directory(tmp_path) -> None:
    deploy = _c17_load_testnet_deploy_module()
    directory = tmp_path / "authority-keys"
    directory.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="regular file"):
        deploy._load_authority_keys(str(directory))


def test_c17_authority_keyfile_rejects_fifo_without_blocking(tmp_path) -> None:
    import os
    from pathlib import Path
    import subprocess
    import sys

    fifo = tmp_path / "authority-keys.fifo"
    os.mkfifo(fifo, mode=0o600)
    script_path = Path(__file__).parents[1] / "scripts" / "testnet_deploy.py"
    probe = f"""
import importlib.util

spec = importlib.util.spec_from_file_location("c17_testnet_deploy_fifo", {str(script_path)!r})
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module._load_authority_keys({str(fifo)!r})
except ValueError as exc:
    print(exc)
    raise SystemExit(0)
raise SystemExit(1)
"""

    completed = subprocess.run(
        [sys.executable, "-c", probe],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0, completed.stderr
    assert "regular file" in completed.stdout


def _c17_assignment_fixture(*, producer_id: str):
    from tests.test_c14_protocol_hardening import (
        c14_precedent_signed_record,
        c14_precedent_test_registry,
    )

    record = c14_precedent_signed_record(miner_uid=producer_id)
    assert record.signed_assignment is not None
    return record, c14_precedent_test_registry()


def _c17_verify_record_assignment(record, registry):
    from constitutional_swarm.mesh.vote_envelope import verify_signed_assignment

    return verify_signed_assignment(
        record.signed_assignment,
        registry,
        task_id=record.task_id,
        assignment_id=record.assignment_id,
        producer_id=record.miner_uid,
        artifact_id=record.artifact_id,
        content_hash=record.content_hash,
        constitutional_hash=record.constitutional_hash,
    )


class _C17ProducerAliasRegistry:
    def __init__(self, delegate, producer_id: str, producer_key) -> None:
        from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

        self._delegate = delegate
        self._producer_id = normalize_voter_id(producer_id)
        self._producer_key = producer_key

    def authorize(self, voter_id, key_id, *, role="voter"):
        return self._delegate.authorize(voter_id, key_id, role=role)

    def public_key_for_identity(self, identity):
        from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

        normalized = normalize_voter_id(identity)
        if normalized == self._producer_id:
            return self._producer_key
        grant = self._delegate._identities.get(normalized)
        return None if grant is None else grant.key

    def trust_grants(self, *, role="validator"):
        return self._delegate.trust_grants(role=role)

    def validate_trust_root(self) -> None:
        self._delegate.validate_trust_root()

    def frozen_copy(self):
        return self


def _c17_registry_with_producer_alias(record, registry):
    assignment = record.signed_assignment
    assert assignment is not None
    frozen = registry.frozen_copy()
    assigner_key = frozen.authorize(
        assignment.assigner_id,
        assignment.key_id,
        role="assigner",
    )
    return _C17ProducerAliasRegistry(frozen, record.miner_uid, assigner_key)


def test_c17_signed_assignment_rejects_assigner_as_producer() -> None:
    record, registry = _c17_assignment_fixture(producer_id="c14-test-assigner")

    with pytest.raises(ValueError, match="assigner.*producer"):
        _c17_verify_record_assignment(record, registry)


def test_c17_precedent_store_rejects_assigner_as_producer() -> None:
    from constitutional_swarm.bittensor.precedent_store import PrecedentStore

    record, registry = _c17_assignment_fixture(producer_id="c14-test-assigner")
    store = PrecedentStore(record.constitutional_hash, vote_registry=registry)

    with pytest.raises(ValueError, match="assigner.*producer"):
        store.admit(record)


def test_c17_signed_assignment_rejects_producer_alias_of_assigner_key() -> None:
    record, registry = _c17_assignment_fixture(producer_id="c17-producer-alias")
    aliased = _c17_registry_with_producer_alias(record, registry)

    with pytest.raises(ValueError, match="assigner.*producer.*key"):
        _c17_verify_record_assignment(record, aliased)


def test_c17_precedent_store_rejects_producer_alias_of_assigner_key() -> None:
    from constitutional_swarm.bittensor.precedent_store import PrecedentStore

    record, registry = _c17_assignment_fixture(producer_id="c17-producer-alias")
    aliased = _c17_registry_with_producer_alias(record, registry)
    store = PrecedentStore(record.constitutional_hash, vote_registry=aliased)

    with pytest.raises(ValueError, match="assigner.*producer.*key"):
        store.admit(record)


def test_c17_signed_assignment_accepts_distinct_registered_producer_key() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    record, registry = _c17_assignment_fixture(producer_id="c17-distinct-producer")
    registry.register(
        record.miner_uid,
        Ed25519PrivateKey.generate().public_key(),
        roles={"producer"},
    )

    assert _c17_verify_record_assignment(record, registry) == record.signed_assignment


def test_c17_signed_assignment_allows_unregistered_producer() -> None:
    record, registry = _c17_assignment_fixture(producer_id="c17-unknown-producer")

    assert _c17_verify_record_assignment(record, registry) == record.signed_assignment


def test_c17_frozen_registry_rejects_frozenset_role_subclass() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    class SpoofedRoles(frozenset[str]):
        def __contains__(self, value: object) -> bool:
            return value in {"assigner", "voter"}

        def __and__(self, other: object) -> frozenset[str]:
            return frozenset()

    public_key = Ed25519PrivateKey.generate().public_key()
    key_id = key_id_for_public_key(public_key)

    with pytest.raises(TypeError, match="immutable frozenset"):
        FrozenVoteSignerRegistry(
            (_Grant("c17-role-spoof", key_id, public_key, SpoofedRoles({"voter"})),)
        )

    exact = FrozenVoteSignerRegistry(
        (_Grant("c17-exact-role", key_id, public_key, frozenset({"voter"})),)
    )
    stored_key = exact.authorize("c17-exact-role", key_id)
    assert stored_key is not public_key
    assert stored_key.public_bytes_raw() == public_key.public_bytes_raw()
    assert key_id_for_public_key(stored_key) == key_id


def test_c17_remote_peer_rejects_frozen_registry_subclass() -> None:
    from acgs_lite import Constitution

    from constitutional_swarm.mesh.vote_envelope import FrozenVoteSignerRegistry
    from constitutional_swarm.remote_vote_transport import LocalRemotePeer
    from tests.test_c14_protocol_hardening import c14_precedent_test_registry

    exact = c14_precedent_test_registry().frozen_copy()

    class SpoofedFrozenRegistry(FrozenVoteSignerRegistry):
        def authorize(self, voter_id, key_id, *, role="voter"):
            raise AssertionError("untrusted registry method must not be called")

    spoofed = SpoofedFrozenRegistry(exact._grants)

    with pytest.raises(TypeError, match="immutable registry snapshot"):
        LocalRemotePeer(
            agent_id="c17-peer",
            constitution=Constitution.default(),
            trusted_assigners=spoofed,
        )

    peer = LocalRemotePeer(
        agent_id="c17-peer",
        constitution=Constitution.default(),
        trusted_assigners=exact,
    )
    assert peer.agent_id == "c17-peer"


def _c17_public_key_subclass_accepting_any_signature():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    real = Ed25519PrivateKey.generate().public_key()

    class AcceptAnythingKey(Ed25519PublicKey):
        def public_bytes(self, encoding, format):
            return real.public_bytes(encoding, format)

        def public_bytes_raw(self):
            return real.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )

        def verify(self, signature, data):
            return None

        def __eq__(self, other):
            return self is other

        def __copy__(self):
            return self

        def __deepcopy__(self, memo):
            return self

    return AcceptAnythingKey()


def test_c17_frozen_registry_rejects_grant_subclass() -> None:
    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    roles = {"value": frozenset({"voter"})}

    class PropertyShadowedGrant(_Grant):
        __slots__ = ()

        @property
        def roles(self):
            return roles["value"]

    key = _c17_public_key_subclass_accepting_any_signature()
    grant = object.__new__(PropertyShadowedGrant)
    for name, value in (
        ("identity", "c17-shadowed"),
        ("key_id", key_id_for_public_key(key)),
        ("key", key),
        ("roles", frozenset({"voter"})),
    ):
        _Grant.__dict__[name].__set__(grant, value)

    with pytest.raises(TypeError, match="exact registry grants"):
        registry = FrozenVoteSignerRegistry((grant,))
        roles["value"] = frozenset({"assigner", "voter"})
        registry.authorize("c17-shadowed", key_id_for_public_key(key), role="assigner")
        registry.authorize("c17-shadowed", key_id_for_public_key(key), role="voter")


@pytest.mark.parametrize("field", ["identity", "key_id", "role"])
def test_c17_frozen_registry_rejects_string_subclasses(field) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
    )

    class HostileString(str):
        def __hash__(self):
            return hash("assigner")

        def __eq__(self, other):
            return True

    key = Ed25519PrivateKey.generate().public_key()
    identity = HostileString("c17-hostile") if field == "identity" else "c17-hostile"
    key_id = key_id_for_public_key(key)
    if field == "key_id":
        key_id = HostileString(key_id)
    role = HostileString("voter") if field == "role" else "voter"

    with pytest.raises(TypeError, match="exact strings"):
        FrozenVoteSignerRegistry((_Grant(identity, key_id, key, frozenset({role})),))


@pytest.mark.parametrize("frozen", [False, True])
def test_c17_registry_rebuilds_public_key_subclasses_before_verification(
    frozen,
) -> None:
    from dataclasses import replace
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        FrozenVoteSignerRegistry,
        VoteSignerRegistry,
        _Grant,
        key_id_for_public_key,
        sign_assignment,
        verify_signed_assignment,
    )

    accepting_key = _c17_public_key_subclass_accepting_any_signature()
    key_id = key_id_for_public_key(accepting_key)
    if frozen:
        registry = FrozenVoteSignerRegistry(
            (
                _Grant(
                    "c17-forged-assigner",
                    key_id,
                    accepting_key,
                    frozenset({"assigner"}),
                ),
            )
        )
    else:
        mutable = VoteSignerRegistry()
        mutable.register("c17-forged-assigner", accepting_key, roles={"assigner"})
        registry = mutable
    forged = replace(
        sign_assignment(
            Ed25519PrivateKey.generate(),
            task_id="c17-task",
            assignment_id="c17-assignment",
            assigner_id="c17-forged-assigner",
            producer_id="c17-producer",
            artifact_id="c17-artifact",
            content_hash="c17-content",
            constitutional_hash="c17-constitution",
            assigned_peers=("c17-peer",),
            quorum=1,
            selection_seed="c17-seed",
            issued_at=1.0,
        ),
        key_id=key_id,
    )

    with pytest.raises(ValueError, match="signature is invalid"):
        verify_signed_assignment(
            forged,
            registry,
            task_id=forged.task_id,
            assignment_id=forged.assignment_id,
            producer_id=forged.producer_id,
            artifact_id=forged.artifact_id,
            content_hash=forged.content_hash,
            constitutional_hash=forged.constitutional_hash,
        )


def test_c17_mesh_rebuilds_remote_public_key_subclass() -> None:
    from acgs_lite import Constitution

    from constitutional_swarm.mesh import ConstitutionalMesh

    accepting_key = _c17_public_key_subclass_accepting_any_signature()
    mesh = ConstitutionalMesh(Constitution.default(), peers_per_validation=1, quorum=1)
    mesh.register_remote_agent("c17-remote", vote_public_key=accepting_key)

    assert mesh._agent_vote_public_keys["c17-remote"] is not accepting_key
    assert (
        mesh.verify_vote_signature(
            public_key=mesh._agent_vote_public_keys["c17-remote"],
            assignment_id="c17-assignment",
            voter_id="c17-remote",
            approved=True,
            reason="ok",
            constitutional_hash=mesh.constitutional_hash,
            content_hash="c17-content",
            signature="00" * 64,
        )
        is False
    )


@pytest.mark.parametrize("allowlist_attack", ["string", "public_key"])
def test_c17_remote_peer_canonicalizes_request_signer_allowlist(
    allowlist_attack,
) -> None:
    from dataclasses import replace
    from acgs_lite import Constitution
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from constitutional_swarm.mesh import ConstitutionalMesh
    from constitutional_swarm.remote_vote_transport import LocalRemotePeer

    constitution = Constitution.default()
    requester = ConstitutionalMesh(
        constitution,
        peers_per_validation=1,
        quorum=1,
        evidence_mode="single_operator_dev",
    )
    attacker = Ed25519PrivateKey.generate()
    attacker_hex = (
        attacker.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )

    class AlwaysEqualSigner(str):
        def __hash__(self):
            return hash(attacker_hex)

        def __eq__(self, other):
            return True

    requester_hex = requester.get_request_signing_public_key()

    class AlwaysEqualPublicKey(Ed25519PublicKey):
        def public_bytes(self, encoding, format):
            return bytes.fromhex(requester_hex)

        def public_bytes_raw(self):
            return bytes.fromhex(requester_hex)

        def verify(self, signature, data):
            return None

        def __hash__(self):
            return hash(attacker_hex)

        def __eq__(self, other):
            return True

        def __copy__(self):
            return self

        def __deepcopy__(self, memo):
            return self

    malicious_signer = (
        AlwaysEqualSigner(requester_hex)
        if allowlist_attack == "string"
        else AlwaysEqualPublicKey()
    )

    peer = LocalRemotePeer(
        agent_id="c17-peer",
        constitution=constitution,
        trusted_request_signers={
            malicious_signer,
            requester_hex,
        },
        trusted_assigners=requester.vote_registry.frozen_copy(),
    )
    requester.register_local_signer("c17-producer")
    requester.register_remote_agent("c17-peer", vote_public_key=peer.public_key_hex)
    assignment = requester.request_validation(
        "c17-producer", "safe content", "c17-artifact"
    )
    legitimate = requester.prepare_remote_vote(assignment.assignment_id, "c17-peer")

    payload = requester.build_remote_vote_request_payload(
        assignment_id=legitimate.assignment_id,
        voter_id=legitimate.voter_id,
        producer_id=legitimate.producer_id,
        artifact_id=legitimate.artifact_id,
        content=legitimate.content,
        content_hash=legitimate.content_hash,
        constitutional_hash=legitimate.constitutional_hash,
        voter_public_key=legitimate.voter_public_key,
        nonce="c17-attacker-nonce",
        timestamp=legitimate.timestamp,
        task_id=legitimate.task_id,
        assigned_peers=legitimate.assigned_peers,
        quorum=legitimate.quorum,
        evidence_mode=legitimate.evidence_mode,
        protocol_version=legitimate.protocol_version,
        signed_assignment=legitimate.signed_assignment,
    )
    forged = replace(
        legitimate,
        nonce="c17-attacker-nonce",
        request_signer_public_key=attacker_hex,
        request_signature=attacker.sign(payload).hex(),
    )

    with pytest.raises(ValueError, match="signer is not trusted"):
        peer.handle_vote_request(forged)
    assert peer.handle_vote_request(legitimate).envelope.voter_id == "c17-peer"


@pytest.mark.parametrize("evidence_kind", ["assignment", "vote"])
def test_c17_structural_registry_view_key_is_rebuilt_before_verification(
    evidence_kind,
) -> None:
    from dataclasses import replace
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh.vote_envelope import (
        key_id_for_public_key,
        sign_assignment,
        sign_vote_envelope,
        verify_signed_assignment,
        verify_vote_envelope,
    )

    accepting_key = _c17_public_key_subclass_accepting_any_signature()
    key_id = key_id_for_public_key(accepting_key)

    class StructuralView:
        def validate_trust_root(self) -> None:
            pass

        def authorize(self, voter_id, candidate_key_id, *, role="voter"):
            assert candidate_key_id == key_id
            return accepting_key

        def public_key_for_identity(self, identity):
            return None

        def trust_grants(self, *, role="validator"):
            return {}

    registry = StructuralView()
    wrong_signer = Ed25519PrivateKey.generate()
    if evidence_kind == "assignment":
        evidence = replace(
            sign_assignment(
                wrong_signer,
                task_id="c17-view-task",
                assignment_id="c17-view-assignment",
                assigner_id="c17-view-assigner",
                producer_id="c17-view-producer",
                artifact_id="c17-view-artifact",
                content_hash="c17-view-content",
                constitutional_hash="c17-view-constitution",
                assigned_peers=("c17-view-voter",),
                quorum=1,
                selection_seed="c17-view-seed",
                issued_at=1.0,
            ),
            key_id=key_id,
        )
        with pytest.raises(ValueError, match="signature is invalid"):
            verify_signed_assignment(
                evidence,
                registry,
                task_id=evidence.task_id,
                assignment_id=evidence.assignment_id,
                producer_id=evidence.producer_id,
                artifact_id=evidence.artifact_id,
                content_hash=evidence.content_hash,
                constitutional_hash=evidence.constitutional_hash,
            )
    else:
        evidence = replace(
            sign_vote_envelope(
                wrong_signer,
                voter_id="c17-view-voter",
                task_id="c17-view-task",
                assignment_id="c17-view-assignment",
                producer_id="c17-view-producer",
                artifact_id="c17-view-artifact",
                content_hash="c17-view-content",
                constitutional_hash="c17-view-constitution",
                decision="approved",
                reason="ok",
                nonce="c17-view-nonce",
                issued_at=1.0,
                assigned_peers=("c17-view-voter",),
                quorum=1,
                evidence_mode="single_operator_dev",
                assignment_digest="a" * 64,
            ),
            key_id=key_id,
        )
        with pytest.raises(ValueError, match="signature is invalid"):
            verify_vote_envelope(
                evidence,
                registry,
                task_id=evidence.task_id,
                assignment_id=evidence.assignment_id,
                producer_id=evidence.producer_id,
                artifact_id=evidence.artifact_id,
                content_hash=evidence.content_hash,
                constitutional_hash=evidence.constitutional_hash,
            )


def test_c17_remote_peer_rejects_request_signer_string_subclass_before_lookup() -> None:
    from dataclasses import replace
    from acgs_lite import Constitution
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from constitutional_swarm.mesh import ConstitutionalMesh
    from constitutional_swarm.remote_vote_transport import LocalRemotePeer

    constitution = Constitution.default()
    requester = ConstitutionalMesh(
        constitution,
        peers_per_validation=1,
        quorum=1,
        evidence_mode="single_operator_dev",
    )
    trusted_hex = requester.get_request_signing_public_key()
    peer = LocalRemotePeer(
        agent_id="c17-request-peer",
        constitution=constitution,
        trusted_request_signers={trusted_hex},
        trusted_assigners=requester.vote_registry.frozen_copy(),
    )
    requester.register_local_signer("c17-request-producer")
    requester.register_remote_agent(
        "c17-request-peer", vote_public_key=peer.public_key_hex
    )
    assignment = requester.request_validation(
        "c17-request-producer", "safe request content", "c17-request-artifact"
    )
    legitimate = requester.prepare_remote_vote(
        assignment.assignment_id, "c17-request-peer"
    )
    attacker = Ed25519PrivateKey.generate()
    attacker_hex = (
        attacker.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )
    method_calls = []

    class HostileRequestSigner(str):
        def __hash__(self):
            method_calls.append("hash")
            return hash(trusted_hex)

        def __eq__(self, other):
            method_calls.append("eq")
            return True

    payload = requester.build_remote_vote_request_payload(
        assignment_id=legitimate.assignment_id,
        voter_id=legitimate.voter_id,
        producer_id=legitimate.producer_id,
        artifact_id=legitimate.artifact_id,
        content=legitimate.content,
        content_hash=legitimate.content_hash,
        constitutional_hash=legitimate.constitutional_hash,
        voter_public_key=legitimate.voter_public_key,
        nonce="c17-request-attacker-nonce",
        timestamp=legitimate.timestamp,
        task_id=legitimate.task_id,
        assigned_peers=legitimate.assigned_peers,
        quorum=legitimate.quorum,
        evidence_mode=legitimate.evidence_mode,
        protocol_version=legitimate.protocol_version,
        signed_assignment=legitimate.signed_assignment,
    )
    forged = replace(
        legitimate,
        nonce="c17-request-attacker-nonce",
        request_signer_public_key=HostileRequestSigner(attacker_hex),
        request_signature=attacker.sign(payload).hex(),
    )

    with pytest.raises(ValueError, match="exact string"):
        peer.handle_vote_request(forged)
    assert method_calls == []
