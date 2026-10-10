"""C24 regression tests for the governed commit boundary.

Each test feeds the boundary an invalid or adversarial input (a forged seal row,
a policy signer whose key order disagrees with the trust config) or pins a
structural property (one commit owner, bounded per-workflow SQL) that the
reviewed findings showed was violated.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from constitutional_swarm import governed_commit
from constitutional_swarm.apcc.codec import canonical_statement
from constitutional_swarm.apcc.crypto import PROPOSAL_DOMAIN, domain_preimage, sha256_digest
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    GovernanceBypassDenied,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from tests.gcb_apcc_support import (
    DetachedSigner,
    PolicySigner,
    canonical_nonce,
    producer_key,
    typed_bootstrap,
)

_VERSIONS = (("1", 1), ("2", 2))


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _seal(path: Path) -> sqlite3.Row:
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM store_seal WHERE singleton=1").fetchone()


def _provisioned(path: Path, nodes: dict[str, tuple[str, ...]]):
    bootstrap = typed_bootstrap(policy_versions=_VERSIONS)
    admin = bootstrap.provision(path)
    admin.create_workflow(workflow_id="wf", nodes=nodes, policy_version="1")
    key = producer_key()
    admin.register_agent(
        workflow_id="wf", agent_id="agent", public_key=key.public_key(), capabilities=()
    )
    return bootstrap, admin, key


def _claim_and_stage(admin, key, node_id: str) -> None:
    port = admin.commit_port
    authorization = sign_attempt_authorization(
        port.prepare_attempt_authorization(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=f"a-{node_id}",
            agent_id="agent",
            nonce=canonical_nonce(f"claim:{node_id}"),
        ),
        key,
    )
    port.claim(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=f"a-{node_id}",
        agent_id="agent",
        authorization=authorization,
    )
    port.stage_result(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=f"a-{node_id}",
        artifact=Artifact(f"art-{node_id}", node_id, "agent", "text", node_id),
        authorization=authorization,
    )


def _request(admin, key, node_id: str):
    payload = admin.commit_port.prepare_receipt_payload(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=f"a-{node_id}",
        agent_id="agent",
        commit_id=f"commit-{node_id}",
        nonce=canonical_nonce(f"commit:{node_id}"),
    )
    return admin.build_request(sign_governed_receipt(payload, key))


def _commit(admin, key, node_id: str) -> None:
    _claim_and_stage(admin, key, node_id)
    decision = admin.commit(_request(admin, key, node_id))
    assert decision.outcome is CommitOutcome.COMMITTED, decision.reason


def _trace_sql(monkeypatch, port) -> list[str]:
    statements: list[str] = []
    original = port._connect

    def traced() -> sqlite3.Connection:
        conn = original()
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(port, "_connect", traced)
    return statements


# --- governance-8: seal trust anchors must match the caller's bootstrap ------


@pytest.mark.parametrize(
    "columns",
    [
        ("admin_public_key", "admin_key_fingerprint"),
        ("verifier_public_key", "verifier_key_fingerprint"),
        ("admin_key_id",),
        ("verifier_key_id",),
        ("verifier_policy_id",),
    ],
)
def test_open_rejects_store_seal_anchor_not_matching_bootstrap(tmp_path, columns) -> None:
    path = tmp_path / "authority.sqlite3"
    bootstrap = typed_bootstrap(policy_versions=_VERSIONS)
    bootstrap.provision(path)
    forged = _raw(Ed25519PrivateKey.generate())
    values: dict[str, object] = {}
    for column in columns:
        if column.endswith("_public_key"):
            values[column] = forged
        elif column.endswith("_fingerprint"):
            # Keep the self-referential fingerprint consistent so only an
            # external anchor comparison can detect the substitution.
            values[column] = hashlib.sha256(forged).hexdigest()
        else:
            values[column] = "attacker-chosen"
    assignments = ",".join(f"{column}=?" for column in values)
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"UPDATE store_seal SET {assignments} WHERE singleton=1",
            tuple(values.values()),
        )

    with pytest.raises(GovernanceBypassDenied, match="^authority_anchor_mismatch$"):
        bootstrap.open_admin(path)


def test_open_rejects_store_sealed_for_a_different_control_signer(tmp_path) -> None:
    path = tmp_path / "authority.sqlite3"
    typed_bootstrap(policy_versions=_VERSIONS).provision(path)
    other = typed_bootstrap(policy_versions=_VERSIONS)
    other._control_signer = DetachedSigner("other-control")

    with pytest.raises(GovernanceBypassDenied, match="^authority_anchor_mismatch$"):
        other.open_admin(path)


# --- authority-child-2 (caller side): explicit policy version at provision ---


def test_provision_seals_verifier_key_of_configured_policy_binding(tmp_path) -> None:
    path = tmp_path / "authority.sqlite3"
    bootstrap = typed_bootstrap(policy_versions=_VERSIONS)
    # Same keys, but the signer lists version "2" first: an implicit
    # ``public_key_bytes()`` would pick the wrong key for policy_trust[0].
    bootstrap._policy_signer = PolicySigner(tuple(reversed(_VERSIONS)))
    bootstrap.provision(path)

    seal = _seal(path)
    expected = bootstrap.config.policy_trust[0]
    assert seal["verifier_public_key"] == expected.public_key
    assert seal["verifier_key_id"] == expected.key_id
    assert bootstrap.open_admin(path).commit_port.store_id == bootstrap.store_id


def test_provision_refuses_policy_signer_not_matching_trust_config(tmp_path) -> None:
    path = tmp_path / "authority.sqlite3"
    bootstrap = typed_bootstrap(policy_versions=_VERSIONS)
    bootstrap._policy_signer = DetachedSigner("not-the-policy-key")

    with pytest.raises(GovernanceBypassDenied, match="^untrusted_policy_binding$"):
        bootstrap.provision(path)
    assert not path.exists() or path.stat().st_size == 0


# --- governance-9: REVOKE_ROOT has exactly one commit owner -----------------


def test_revoke_root_finalizes_once_inside_the_write_fence(tmp_path, monkeypatch) -> None:
    _bootstrap, admin, key = _provisioned(
        tmp_path / "authority.sqlite3", {"root": (), "child": ("root",)}
    )
    _commit(admin, key, "root")
    port = admin.commit_port
    store = port._apcc_store
    original = store._finalize_attached_gcb_transaction
    in_transaction: list[bool] = []

    def spy(connection: sqlite3.Connection) -> None:
        in_transaction.append(connection.in_transaction)
        original(connection)

    monkeypatch.setattr(store, "_finalize_attached_gcb_transaction", spy)
    admin.revoke_root(workflow_id="wf", node_id="root", event_id="ev", reason="fraud")

    assert in_transaction == [True]
    assert admin.node_state("wf", "root").status == "revoked"


# --- governance-16: one producer statement, one policy binding lookup -------


def test_apcc_producer_statement_is_the_agent_signed_statement(tmp_path) -> None:
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", {"root": ()})
    _claim_and_stage(admin, key, "root")
    request = _request(admin, key, "root")

    apcc = admin.commit_port._to_apcc_request(request)

    producer = canonical_statement(apcc.evidence.producer_statement)
    assert domain_preimage(PROPOSAL_DOMAIN, producer) == (request.receipt.payload.canonical_bytes())
    assert apcc.evidence.producer_statement_digest == sha256_digest(producer)


def test_policy_binding_lookup_is_exact_scope_match(tmp_path) -> None:
    bootstrap = typed_bootstrap(policy_versions=_VERSIONS)
    config = bootstrap.config
    for binding in config.policy_trust:
        assert governed_commit._policy_binding_for(config, binding.scope) is binding
    policy_id = config.policy_trust[0].scope[0]
    for scope in ((policy_id, "1", "2"), (policy_id, "3", "3"), ("other", "1", "1")):
        assert governed_commit._policy_binding_for(config, scope) is None


# --- governance-17: zero-reference symbols are gone --------------------------


@pytest.mark.parametrize(
    "owner, name",
    [
        (governed_commit, "_DOMAIN"),
        (governed_commit, "_CONTROL_DOMAIN"),
        (governed_commit, "sign_control_command"),
        (governed_commit.GovernedCommitBoundary, "_unlock_children"),
        (governed_commit.GovernedCommitBoundary, "_apcc_validation_reason"),
        (governed_commit.TrustedGovernanceBootstrap, "_key_id"),
    ],
)
def test_dead_governed_commit_symbols_are_removed(owner, name) -> None:
    assert not hasattr(owner, name)


# --- governance-18: closure work is linear and SQL is per workflow ----------


def test_agent_revocation_taints_chain_with_one_topology_read(tmp_path, monkeypatch) -> None:
    nodes = {"e": ("d",), "d": ("c",), "c": ("b",), "b": ("a",), "a": ()}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    _claim_and_stage(admin, key, "a")
    statements = _trace_sql(monkeypatch, admin.commit_port)

    admin.revoke_agent(workflow_id="wf", agent_id="agent")

    topology_reads = [sql for sql in statements if "SELECT node_id,predecessors FROM nodes" in sql]
    assert len(topology_reads) == 1
    monkeypatch.undo()
    with sqlite3.connect(admin.commit_port.path) as conn:
        tainted = dict(conn.execute("SELECT node_id,tainted FROM nodes WHERE workflow_id='wf'"))
    assert tainted == dict.fromkeys(nodes, 1)


def test_attach_workflow_reads_revoked_roots_once(tmp_path, monkeypatch) -> None:
    nodes = {"root": (), "child": ("root",), "leaf": ("child",), "side": ()}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    _commit(admin, key, "root")
    admin.revoke_root(workflow_id="wf", node_id="root", event_id="ev", reason="fraud")
    port = admin.commit_port
    statements = _trace_sql(monkeypatch, port)

    states = port.attach_workflow(workflow_id="wf", nodes=nodes, policy_version="1")

    root_reads = [sql for sql in statements if "FROM revoked_roots" in sql]
    assert len(root_reads) == 1
    assert {node_id: state.status for node_id, state in states.items()} == {
        "root": "revoked",
        "child": "blocked",
        "leaf": "blocked",
        "side": "ready",
    }


class _RecordingProjection:
    workflow_id = "wf"

    def __init__(self) -> None:
        self.published: list[str] = []

    def get(self, artifact_id: str):
        del artifact_id
        return None

    def publish(self, artifact: Artifact):
        self.published.append(artifact.artifact_id)
        return ()

    def dispatch(self, artifact_id: str, callbacks) -> None:
        del artifact_id, callbacks

    def redispatch(self, artifact: Artifact) -> None:
        raise AssertionError(artifact)


def test_outbox_dispatch_batches_authority_status_reads(tmp_path, monkeypatch) -> None:
    nodes = {"a": (), "b": (), "c": ()}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    for node_id in nodes:
        _commit(admin, key, node_id)
    store = admin.commit_port._apcc_store
    original = store.current_status_batch
    batch_sizes: list[int] = []

    def spy(requests):
        batch_sizes.append(len(requests))
        return original(requests)

    monkeypatch.setattr(store, "current_status_batch", spy)
    projection = _RecordingProjection()

    assert admin.dispatch_outbox(projection) == 3

    assert batch_sizes == [3]
    assert sorted(projection.published) == ["art-a", "art-b", "art-c"]


# --- C24 rework r1: batched status must not widen the blast radius -----------


def _tamper(path: str, sql: str, params: tuple) -> None:
    with sqlite3.connect(path) as conn:
        assert conn.execute(sql, params).rowcount == 1


def _outbox_pending(path: str) -> dict[str, int]:
    with sqlite3.connect(path) as conn:
        return dict(conn.execute("SELECT node_id,dispatched FROM outbox"))


def _certificate_digest(path: str, node_id: str) -> str:
    with sqlite3.connect(path) as conn:
        return conn.execute(
            "SELECT certificate_digest FROM logical_nodes WHERE workflow_id='wf' AND node_id=?",
            (node_id,),
        ).fetchone()[0]


@pytest.mark.parametrize("failure", ["unknown-certificate", "malformed-digest"])
def test_outbox_dispatch_skips_only_the_row_with_a_bad_certificate(
    tmp_path, monkeypatch, failure
) -> None:
    # logical_nodes is covered by the APCC semantic checkpoint, so the two
    # failure modes are injected at their real raise points instead of by
    # rewriting the row: the store's "unknown APCC certificate" ValueError and
    # CurrentStatusRequest's digest-validation ValueError.
    nodes = {"a": (), "b": (), "c": ()}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    for node_id in nodes:
        _commit(admin, key, node_id)
    port = admin.commit_port
    bad = _certificate_digest(port.path, "b")
    if failure == "unknown-certificate":
        store = port._apcc_store
        original_batch = store.current_status_batch

        def batch(requests):
            if any(request.certificate_digest == bad for request in requests):
                raise ValueError("unknown APCC certificate")
            return original_batch(requests)

        monkeypatch.setattr(store, "current_status_batch", batch)
    else:
        real_request = governed_commit.CurrentStatusRequest

        def request(digest: str, nonce: str):
            if digest == bad:
                raise ValueError("invalid certificate digest")
            return real_request(digest, nonce)

        monkeypatch.setattr(governed_commit, "CurrentStatusRequest", request)
    projection = _RecordingProjection()

    assert admin.dispatch_outbox(projection) == 2

    assert sorted(projection.published) == ["art-a", "art-c"]
    assert _outbox_pending(port.path) == {"a": 1, "b": 1, "c": 1}


@pytest.mark.parametrize("ghost_holder", ["child", "leaf"])
def test_dangling_predecessor_fails_closed_in_revocation_closure(tmp_path, ghost_holder) -> None:
    nodes = {"root": (), "child": ("root",), "leaf": ("child",)}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    _commit(admin, key, "root")
    admin.revoke_root(workflow_id="wf", node_id="root", event_id="ev", reason="fraud")
    path = admin.commit_port.path
    _tamper(
        path,
        "UPDATE nodes SET predecessors=? WHERE workflow_id='wf' AND node_id=?",
        ('["ghost"]', ghost_holder),
    )

    with pytest.raises(GovernanceBypassDenied, match="^workflow_topology_integrity_failure$"):
        admin.resume_revocation_propagation()
    with pytest.raises(GovernanceBypassDenied, match="^workflow_topology_integrity_failure$"):
        admin.dispatch_outbox(_RecordingProjection())
    assert admin.pending_revocations() == 1


def test_dangling_predecessor_fails_closed_in_agent_taint(tmp_path) -> None:
    nodes = {"a": (), "b": ("a",)}
    _bootstrap, admin, key = _provisioned(tmp_path / "authority.sqlite3", nodes)
    _claim_and_stage(admin, key, "a")
    path = admin.commit_port.path
    _tamper(
        path,
        "UPDATE nodes SET predecessors=? WHERE workflow_id='wf' AND node_id='b'",
        ('["a","ghost"]',),
    )

    with pytest.raises(GovernanceBypassDenied, match="^workflow_topology_integrity_failure$"):
        admin.revoke_agent(workflow_id="wf", agent_id="agent")
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT max(tainted) FROM nodes").fetchone()[0] == 0
        # The denied transition is atomic: no half-applied agent revocation.
        assert (
            conn.execute(
                "SELECT revoked FROM agents WHERE workflow_id='wf' AND agent_id='agent'"
            ).fetchone()[0]
            == 0
        )
        assert conn.execute(
            "SELECT outcome,reason FROM gcb_control_events WHERE action='revoke_agent'"
        ).fetchone() == ("denied", "workflow_topology_integrity_failure")
