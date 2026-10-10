"""C29 regression tests: vote envelopes, settlement proofs and remote vote transport.

Every test feeds invalid or adversarial input and expects rejection (or, for the
optimisation items, asserts the redundant work is no longer performed).
"""

from __future__ import annotations

import asyncio
import dataclasses
import ssl
from collections import OrderedDict

import pytest
from acgs_lite import Constitution
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer
from constitutional_swarm.mesh import vote_envelope as ve
from constitutional_swarm.mesh.settlement import MeshProof, _compute_merkle_root
from constitutional_swarm.mesh.vote_envelope import (
    FrozenVoteSignerRegistry,
    VoteSignerRegistry,
    sign_assignment,
    sign_vote_envelope,
    signed_assignment_digest,
    verify_assignment_vote_envelopes,
    verify_signed_assignment,
)

_BINDING = {
    "task_id": "c29-task",
    "assignment_id": "c29-assignment",
    "producer_id": "c29-producer",
    "artifact_id": "c29-artifact",
    "content_hash": "c29-content",
    "constitutional_hash": "608508a9bd224290",
}
_PEERS = ("c29-voter-a", "c29-voter-b", "c29-voter-c")


def _c29_fixture(*, assigner_id: str = "c29-assigner"):
    """Build a voter registry, a pinned assigner trust root and signed evidence."""
    assigner_key = Ed25519PrivateKey.generate()
    voter_keys = {peer: Ed25519PrivateKey.generate() for peer in _PEERS}
    trust_root_source = VoteSignerRegistry()
    trust_root_source.register(assigner_id, assigner_key.public_key(), roles={"assigner"})
    voters = VoteSignerRegistry()
    for peer, key in voter_keys.items():
        voters.register(peer, key.public_key(), roles={"voter"})
    assignment = _c29_assignment(assigner_key, assigner_id)
    envelopes = _c29_envelopes(voter_keys, assignment)
    return {
        "assigner_key": assigner_key,
        "assigner_id": assigner_id,
        "trust_root": trust_root_source.frozen_copy(),
        "voters": voters,
        "voter_keys": voter_keys,
        "assignment": assignment,
        "envelopes": envelopes,
    }


def _c29_assignment(key: Ed25519PrivateKey, assigner_id: str):
    return sign_assignment(
        key,
        assigner_id=assigner_id,
        assigned_peers=_PEERS,
        quorum=2,
        selection_seed="c29-seed",
        issued_at=1_700_000_000.0,
        **_BINDING,
    )


def _c29_envelopes(voter_keys, assignment):
    digest = signed_assignment_digest(assignment)
    return tuple(
        sign_vote_envelope(
            key,
            voter_id=peer,
            decision="approved",
            reason="ok",
            nonce=f"nonce-{peer}",
            issued_at=1_700_000_001.0,
            assigned_peers=_PEERS,
            quorum=2,
            assignment_digest=digest,
            **_BINDING,
        )
        for peer, key in voter_keys.items()
    )


# --------------------------------------------------------------------------- mesh-trust-1


def test_c29_assignment_verifier_accepts_evidence_under_pinned_trust_root() -> None:
    fx = _c29_fixture()

    verified = verify_assignment_vote_envelopes(
        fx["assignment"],
        fx["envelopes"],
        fx["voters"],
        assigner_trust_root=fx["trust_root"],
        expected_assigner_id=fx["assigner_id"],
        expected_assigner_key_id=fx["assignment"].key_id,
        **_BINDING,
    )

    assert {item.voter_id for item in verified} == set(_PEERS)


def test_c29_assignment_verifier_rejects_assigner_absent_from_pinned_trust_root() -> None:
    """P1: an assigner that only the voter registry vouches for must be rejected."""
    fx = _c29_fixture()
    rogue_key = Ed25519PrivateKey.generate()
    fx["voters"].register("c29-rogue-assigner", rogue_key.public_key(), roles={"assigner"})
    rogue_assignment = _c29_assignment(rogue_key, "c29-rogue-assigner")
    rogue_envelopes = _c29_envelopes(fx["voter_keys"], rogue_assignment)

    # Legacy single-registry verification accepts it: the voter registry holds the grant.
    verify_assignment_vote_envelopes(
        rogue_assignment, rogue_envelopes, fx["voters"], **_BINDING
    )
    with pytest.raises(ValueError, match="not authorized"):
        verify_assignment_vote_envelopes(
            rogue_assignment,
            rogue_envelopes,
            fx["voters"],
            assigner_trust_root=fx["trust_root"],
            **_BINDING,
        )


def test_c29_assignment_verifier_rejects_assigner_identity_differing_from_pin() -> None:
    """P1: the verified object's assigner id/key must equal the caller's pins."""
    fx = _c29_fixture()
    other_key = Ed25519PrivateKey.generate()
    source = VoteSignerRegistry()
    source.register("c29-assigner", fx["assigner_key"].public_key(), roles={"assigner"})
    source.register("c29-other-assigner", other_key.public_key(), roles={"assigner"})
    trust_root = source.frozen_copy()
    other_assignment = _c29_assignment(other_key, "c29-other-assigner")
    other_envelopes = _c29_envelopes(fx["voter_keys"], other_assignment)

    with pytest.raises(ValueError, match="assigner identity does not match"):
        verify_assignment_vote_envelopes(
            other_assignment,
            other_envelopes,
            fx["voters"],
            assigner_trust_root=trust_root,
            expected_assigner_id="c29-assigner",
            **_BINDING,
        )
    with pytest.raises(ValueError, match="assigner key does not match"):
        verify_assignment_vote_envelopes(
            other_assignment,
            other_envelopes,
            fx["voters"],
            assigner_trust_root=trust_root,
            expected_assigner_key_id=fx["assignment"].key_id,
            **_BINDING,
        )
    with pytest.raises(ValueError, match="assigner identity does not match"):
        verify_signed_assignment(
            other_assignment,
            trust_root,
            expected_assigner_id="c29-assigner",
            **_BINDING,
        )


def test_c29_assignment_verifier_rejects_mutable_or_subclassed_trust_root() -> None:
    fx = _c29_fixture()

    class C29SubclassedRoot(FrozenVoteSignerRegistry):
        __slots__ = ()

    subclassed = C29SubclassedRoot(fx["trust_root"]._grants)
    for root in (fx["voters"], subclassed):
        with pytest.raises(TypeError, match="assigner_trust_root"):
            verify_assignment_vote_envelopes(
                fx["assignment"],
                fx["envelopes"],
                fx["voters"],
                assigner_trust_root=root,
                **_BINDING,
            )


def test_c29_assignment_verifier_rejects_voter_reusing_trust_root_assigner_key() -> None:
    fx = _c29_fixture()
    voters = VoteSignerRegistry()
    voter_keys = dict(fx["voter_keys"])
    voter_keys["c29-voter-a"] = fx["assigner_key"]
    for peer, key in voter_keys.items():
        voters.register(peer, key.public_key(), roles={"voter"})
    envelopes = _c29_envelopes(voter_keys, fx["assignment"])

    with pytest.raises(ValueError, match="assigner key must not be used by a voter"):
        verify_assignment_vote_envelopes(
            fx["assignment"],
            envelopes,
            voters,
            assigner_trust_root=fx["trust_root"],
            **_BINDING,
        )


def test_c29_assignment_verifier_rejects_producer_sharing_trust_root_assigner_key() -> None:
    fx = _c29_fixture()
    fx["voters"].register(
        _BINDING["producer_id"], fx["assigner_key"].public_key(), roles={"producer"}
    )

    with pytest.raises(ValueError, match="assigner and producer keys must differ"):
        verify_assignment_vote_envelopes(
            fx["assignment"],
            fx["envelopes"],
            fx["voters"],
            assigner_trust_root=fx["trust_root"],
            **_BINDING,
        )


class C29ShiftingRegistry:
    """Registry view whose authorize() returns a real key once, then garbage."""

    def __init__(self, inner, *, garbage_first: bool = False):
        self._inner = inner
        self._seen: set[str] = set()
        self._garbage_first = garbage_first

    def authorize(self, voter_id, key_id, *, role="voter"):
        key = self._inner.authorize(voter_id, key_id, role=role)
        first = voter_id not in self._seen
        self._seen.add(voter_id)
        if first and not self._garbage_first:
            return key
        return object()

    def public_key_for_identity(self, identity):
        return self._inner.public_key_for_identity(identity)

    def trust_grants(self, *, role="validator"):
        return self._inner.trust_grants(role=role)

    def validate_trust_root(self):
        self._inner.validate_trust_root()


def test_c29_assignment_verifier_consumes_each_authorization_once() -> None:
    """Authorized keys are reused, never re-fetched unwrapped from the registry."""
    fx = _c29_fixture()
    combined = VoteSignerRegistry()
    combined.register(fx["assigner_id"], fx["assigner_key"].public_key(), roles={"assigner"})
    for peer, key in fx["voter_keys"].items():
        combined.register(peer, key.public_key(), roles={"voter"})

    verified = verify_assignment_vote_envelopes(
        fx["assignment"], fx["envelopes"], C29ShiftingRegistry(combined), **_BINDING
    )
    assert len(verified) == len(_PEERS)


def test_c29_assignment_verifier_wraps_registry_authorize_output() -> None:
    """A registry view returning a non-Ed25519 object must not reach comparisons."""
    fx = _c29_fixture()

    class C29LyingRegistry(C29ShiftingRegistry):
        def __init__(self, inner):
            super().__init__(inner, garbage_first=True)

    with pytest.raises(TypeError, match="invalid public key type"):
        verify_assignment_vote_envelopes(
            fx["assignment"],
            fx["envelopes"],
            C29LyingRegistry(fx["voters"]),
            assigner_trust_root=fx["trust_root"],
            **_BINDING,
        )


# --------------------------------------------------------------------------- opt-perf-4


def test_c29_frozen_registry_validates_once_and_reuses_authorized_keys(monkeypatch) -> None:
    fx = _c29_fixture()
    calls = {"validate": 0, "authorize": 0}
    real_validate = ve._validate_registry_grants
    real_authorize = FrozenVoteSignerRegistry.authorize

    def counting_validate(grants):
        calls["validate"] += 1
        return real_validate(grants)

    def counting_authorize(self, *args, **kwargs):
        calls["authorize"] += 1
        return real_authorize(self, *args, **kwargs)

    voters = fx["voters"].frozen_copy()
    monkeypatch.setattr(ve, "_validate_registry_grants", counting_validate)
    monkeypatch.setattr(FrozenVoteSignerRegistry, "authorize", counting_authorize)

    verify_assignment_vote_envelopes(
        fx["assignment"],
        fx["envelopes"],
        voters,
        assigner_trust_root=fx["trust_root"],
        **_BINDING,
    )

    assert calls["validate"] == 0
    # One assigner authorization plus one per voter; no re-authorization pass.
    assert calls["authorize"] == 1 + len(_PEERS)


def test_c29_frozen_registry_revalidates_after_attribute_tampering() -> None:
    fx = _c29_fixture()
    root = fx["trust_root"]
    tampered_identities = dict(root._identities)
    tampered_identities["c29-injected"] = next(iter(root._identities.values()))
    object.__setattr__(root, "_identities", tampered_identities)

    with pytest.raises(ValueError, match="identity index does not match"):
        root.validate_trust_root()


# --------------------------------------------------------------------------- proof-1


def _c29_legacy_proof() -> MeshProof:
    vote_hashes = ("a" * 32, "b" * 32)
    return MeshProof(
        assignment_id="c29-assignment",
        content_hash="c29-content",
        constitutional_hash="608508a9bd224290",
        vote_hashes=vote_hashes,
        root_hash=_compute_merkle_root(
            "c29-assignment", "c29-content", "608508a9bd224290", vote_hashes, True
        ),
        accepted=True,
        timestamp=1.0,
        protocol_version=1,
    )


def test_c29_mesh_proof_rejects_legacy_v1_without_explicit_opt_in() -> None:
    proof = _c29_legacy_proof()

    assert proof.verify() is False
    assert proof.verify(allow_legacy_v1=True) is True
    assert dataclasses.replace(proof, root_hash="0" * 32).verify(allow_legacy_v1=True) is False


# --------------------------------------------------------------------------- remote peer


def _c29_peer_and_request(*, vote_private_key=None):
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        seed=2929,
        evidence_mode="single_operator_dev",
        assigner_id="c29-peer-assigner",
    )
    peer = LocalRemotePeer(
        agent_id="remote",
        constitution=constitution,
        vote_private_key=vote_private_key,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("remote", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-two")
    mesh.register_local_signer("peer-three")
    assignment = mesh.request_validation("producer", "safe", "artifact")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "remote")
    return peer, request


def test_c29_peer_rejects_request_subclass_before_any_processing() -> None:
    peer, request = _c29_peer_and_request()
    request_type = type(request)

    class C29RequestSubclass(request_type):  # type: ignore[misc, valid-type]
        __slots__ = ()

    forged = C29RequestSubclass(
        **{f.name: getattr(request, f.name) for f in dataclasses.fields(request)}
    )
    with pytest.raises(TypeError, match="RemoteVoteRequest"):
        peer.handle_vote_request(forged)
    assert peer._request_nonce_caches == {}


@pytest.mark.parametrize(
    "bad_key",
    [
        "AB" * 32,
        " " + "ab" * 32,
        "ab" * 32 + "\n",
    ],
)
def test_c29_peer_rejects_non_canonical_private_key_hex(bad_key: str) -> None:
    with pytest.raises(ValueError, match="canonical lowercase hex"):
        LocalRemotePeer(
            agent_id="remote",
            constitution=Constitution.default(),
            vote_private_key=bad_key,
            trusted_assigners=VoteSignerRegistry().frozen_copy(),
        )


def test_c29_peer_verifies_request_signature_once(monkeypatch) -> None:
    peer, request = _c29_peer_and_request()
    calls = {"verify": 0}
    real_verify = ConstitutionalMesh.verify_remote_vote_request

    def counting_verify(*args, **kwargs):
        calls["verify"] += 1
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(ConstitutionalMesh, "verify_remote_vote_request", counting_verify)
    peer.handle_vote_request(request)

    assert calls["verify"] == 1
    assert len(peer._request_nonce_caches[request.request_signer_public_key]) == 1
    assert not hasattr(peer, "_request_nonce_cache")


def test_c29_peer_replay_is_still_rejected_after_single_verification() -> None:
    from constitutional_swarm.mesh import RemoteVoteReplayError

    peer, request = _c29_peer_and_request()
    peer.handle_vote_request(request)
    with pytest.raises(RemoteVoteReplayError, match="already used inside the replay window"):
        peer.handle_vote_request(request)


def test_c29_peer_rejects_tampered_content_with_shared_content_hash() -> None:
    peer, request = _c29_peer_and_request()
    assert ve.content_hash(request.content) == request.content_hash
    tampered = dataclasses.replace(request, content=request.content + " ")
    with pytest.raises(ValueError):
        peer.handle_vote_request(tampered)


def test_c29_public_key_helpers_are_canonical() -> None:
    key = Ed25519PrivateKey.generate()
    raw_hex = key.public_key().public_bytes_raw().hex()
    assert ve.public_key_from(raw_hex).public_bytes_raw() == bytes.fromhex(raw_hex)
    with pytest.raises(ValueError, match="canonical lowercase hex"):
        ve.public_key_from(raw_hex.upper())
    with pytest.raises(ValueError, match="canonical lowercase hex"):
        ve.private_key_from(key.private_bytes_raw().hex().upper())


# --------------------------------------------------------------------------- transport TLS


@pytest.mark.parametrize(
    ("check_hostname", "verify_mode"),
    [(False, ssl.CERT_NONE), (False, ssl.CERT_OPTIONAL), (False, ssl.CERT_REQUIRED)],
)
def test_c29_remote_vote_client_rejects_non_verifying_context(
    check_hostname: bool, verify_mode: ssl.VerifyMode
) -> None:
    from constitutional_swarm.remote_vote_transport import RemoteVoteClient

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = check_hostname
    context.verify_mode = verify_mode
    with pytest.raises(ValueError, match="client ssl_context must verify peers"):
        RemoteVoteClient(transport_security="tls", ssl_context=context)


def test_c29_remote_vote_client_rechecks_context_mutated_after_construction(
    monkeypatch,
) -> None:
    pytest.importorskip("websockets")
    import websockets

    from constitutional_swarm.remote_vote_transport import RemoteVoteClient

    context = ssl.create_default_context()
    client = RemoteVoteClient(transport_security="tls", ssl_context=context)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    def c29_forbidden_connect(*_args, **_kwargs):
        raise AssertionError("connection must not be attempted")

    monkeypatch.setattr(websockets, "connect", c29_forbidden_connect)
    _peer, request = _c29_peer_and_request()
    with pytest.raises(ValueError, match="client ssl_context must verify peers"):
        asyncio.run(client.request_vote("service.example", 9443, request))


# --------------------------------------------------------------------------- r1: replay window


def test_c29_peer_rejects_future_timestamped_replay_after_receipt_time_eviction() -> None:
    """A request dated up to W ahead must stay in the replay cache until ts + W."""
    from constitutional_swarm.mesh import RemoteVoteReplayError

    window = 300.0
    clock = {"now": 0.0}
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(
        constitution,
        seed=2930,
        evidence_mode="single_operator_dev",
        assigner_id="c29-r1-assigner",
    )
    peer = LocalRemotePeer(
        agent_id="remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
        replay_window_seconds=window,
        clock=lambda: clock["now"],
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("remote", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-two")
    mesh.register_local_signer("peer-three")
    assignment = mesh.request_validation("producer", "safe", "artifact")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "remote")

    # Receipt: the request is timestamped (window - 1)s in the peer's future.
    receipt = request.timestamp - (window - 1.0)
    clock["now"] = receipt
    peer.handle_vote_request(request)

    # Past the receipt-time eviction point, yet still inside the request's window.
    clock["now"] = receipt + window + 1.0
    assert abs(clock["now"] - request.timestamp) <= window
    with pytest.raises(RemoteVoteReplayError, match="already used inside the replay window"):
        peer.handle_vote_request(request)

    # Once the request itself is outside the window it is rejected as stale.
    clock["now"] = request.timestamp + window + 1.0
    with pytest.raises(ValueError, match="outside replay window"):
        peer.handle_vote_request(request)


def test_c29_peer_evicts_nonce_after_its_expiry() -> None:
    """Expired entries are swept even when an older entry expires later."""
    peer, _request = _c29_peer_and_request()
    cache = peer._request_nonce_caches.setdefault("signer", OrderedDict())
    cache["late"] = 1_000.0
    cache["early"] = 10.0
    peer._sweep_expired_nonces(cache, now=500.0)
    assert list(cache) == ["late"]
