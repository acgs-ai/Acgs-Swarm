"""Spawned W2 profile integrity and signed deep-chain observation checks."""

from dataclasses import replace
import time

import pytest

import constitutional_swarm.authority_service as service
from constitutional_swarm.apcc.model import FailureCode
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
)
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.verifier import ScopedTrust, verify_causal_closure
from constitutional_swarm.artifact import Artifact
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    authority_child_config,
    producer_key,
    provision_executor_workflow,
)
from tests.test_apcc_observation import _launch_expectations, _observer_launch
from tests.test_apcc_observation_target import _nonce


def _config(tmp_path, profile, producers=None):
    base = authority_child_config(
        tmp_path / "chain.db", tmp_path / "authority.keys", producers=producers
    )
    return replace(base, authority=replace(base.authority, causal_profile=profile))


@pytest.mark.parametrize("profile", list(AuthorityCausalProfile))
def test_observer_rejects_expected_config_mismatch_before_ready(
    tmp_path, monkeypatch, profile
):
    config = _config(tmp_path, profile)
    authority = service.start_authority(config)
    original = service._start_observer

    def mismatched(*args, **kwargs):
        kwargs["expected_authority_config_digest"] = "A" * 43
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "_start_observer", mismatched)
    try:
        with pytest.raises(RuntimeError, match="observer startup failed:.*ValueError"):
            service.start_authority_observer(
                authority, _observer_launch(config, tmp_path)
            )
        assert not authority._observers
        assert authority.controlled_boot.phase == "failed"
        with pytest.raises(GovernanceBypassDenied):
            authority.spawn_executor(CapabilityRegistry(), policy_version="1")
    finally:
        authority.close()


class _Envelopes:
    def __init__(self):
        self.envelopes = {}

    def resolve_predecessor(self, certificate_digest):
        return self.envelopes.get(certificate_digest)


def test_spawned_100_agent_chain_has_100_signed_consumable_observations(tmp_path):
    # This verifies the profile and topology; it is not a concurrency-16 W2 run.
    keys = {f"agent-{i}": producer_key(f"chain-agent-{i}") for i in range(100)}
    config = _config(tmp_path, AuthorityCausalProfile.W2_LINEAR_100, keys)
    authority = service.start_authority(config)
    observer = None
    try:
        launch_config = _observer_launch(config, tmp_path)
        observer = service.start_authority_observer(authority, launch_config)
        dag = TaskDAG(
            dag_id="linear-100",
            nodes={
                f"node-{i}": TaskNode(
                    node_id=f"node-{i}",
                    depends_on=() if i == 0 else (f"node-{i - 1}",),
                )
                for i in range(100)
            },
        )
        provision_executor_workflow(authority.admin_client, dag, policy_version="1")
        for agent_id, key in keys.items():
            authority.admin_client.register_agent(
                workflow_id=dag.dag_id,
                agent_id=agent_id,
                public_key=key.public_key(),
                capabilities=(),
            )
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        executor.load_dag(dag)
        with pytest.raises(ValueError, match="blocked, not ready"):
            executor.prepare_claim("node-99", "agent-99")
        stream = AuthorityObservationVerificationStream(
            observer.launch_attestation.session_id
        )
        trust = ScopedTrust(config.authority.trust_bindings)
        resolver = _Envelopes()
        previous_commit = None
        last_envelope = None
        for i in range(100):
            node_id, agent_id = f"node-{i}", f"agent-{i}"
            key = keys[agent_id]
            authorization = sign_attempt_authorization(
                executor.prepare_claim(node_id, agent_id), key
            )
            executor.claim(node_id, agent_id, authorization)
            payload = executor.produce_result(
                node_id,
                Artifact(f"artifact-{i}", node_id, agent_id, "text", f"output-{i}"),
                authorization=authorization,
            )
            receipt = sign_governed_receipt(payload, key)
            request = executor.build_request(receipt)
            assert executor.commit(request).outcome is CommitOutcome.COMMITTED
            target = executor.observation_target(request, request_nonce=_nonce(str(i)))
            response = observer.client.observe(target)
            verified = stream.consume(
                response,
                launch=observer.launch_attestation,
                pinned_controller_public_key=launch_config.controller_key_source.expected_public_key,
                expected_experiment_id=launch_config.experiment_id,
                expected_run_id=launch_config.run_id,
                expected_launch=_launch_expectations(observer.launch_attestation),
                trust=trust,
                now_ms=int(time.time() * 1000),
                maximum_staleness_ms=5000,
            )
            assert verified.consumable
            assert (
                verified.authority_proof
                is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
            )
            snapshot = response.snapshot
            assert snapshot.request.node_id == node_id
            assert snapshot.certificate_envelope_bytes is not None
            closure = verify_causal_closure(
                snapshot.certificate_envelope_bytes,
                trust=ScopedTrust(config.authority.trust_bindings),
                resolver=resolver,
                limits=config.authority.causal_limits,
            )
            assert closure.ok
            assert closure.certificate is not None
            predecessors = closure.certificate.bindings.predecessors
            assert len(predecessors) == (0 if i == 0 else 1)
            if i:
                assert predecessors[0].commit_id == previous_commit
                assert predecessors[0].node_id == f"node-{i - 1}"
            resolver.envelopes[snapshot.certificate_digest] = (
                snapshot.certificate_envelope_bytes
            )
            previous_commit = request.commit_id
            last_envelope = snapshot.certificate_envelope_bytes
        assert executor.is_complete
        assert len(resolver.envelopes) == 100
        assert stream.next_sequence == 101
        assert last_envelope is not None
        assert (
            verify_causal_closure(
                last_envelope,
                trust=ScopedTrust(config.authority.trust_bindings),
                resolver=resolver,
            ).code
            is FailureCode.DEPTH_LIMIT_EXCEEDED
        )
    finally:
        if observer is not None:
            observer.close()
        authority.close()
