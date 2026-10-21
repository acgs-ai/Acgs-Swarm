"""Opt-in W2 observer renewal with child-owned keys and epoch fencing.

This module is an experimental control plane. It never changes APCC bytes,
SQLite transaction boundaries, or default authority bootstrap semantics.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import secrets
import socket
import time
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import (
    ObserverLaunchExpectationsV1,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    verify_authority_observation,
)
from constitutional_swarm.apcc.ports import AuthorityCausalProfile
from constitutional_swarm.apcc.verifier import ScopedTrust
from constitutional_swarm.apcc_empirical.w2_renewal_codec import (
    CONTINUITY_DOMAIN,
    DELEGATION_DOMAIN,
    encode_continuity,
    encode_delegation,
    w2_config_digest,
)
from constitutional_swarm.apcc_empirical.w2_renewal_journal import RenewalJournal
from constitutional_swarm.authority_ipc import canonical_json

TAIL_DOMAIN = b"APCC-W2-OBSERVER-TAIL-V1"
TAIL_FIELDS = {
    "launch_digest",
    "session_id",
    "observation_sequence",
    "observation_digest",
    "epoch",
    "plan_digest",
    "nonce",
}


def sign_observer_tail(key: Ed25519PrivateKey, body: dict[str, str]) -> dict[str, Any]:
    if set(body) != TAIL_FIELDS or any(
        type(value) is not str for value in body.values()
    ):
        raise ValueError("invalid observer tail fields")
    return {
        "body": body,
        "key_id": sha256_digest(key.public_key().public_bytes_raw()),
        "signature": b64u_encode(key.sign(TAIL_DOMAIN + b"\0" + canonical_json(body))),
    }


def verify_observer_tail(
    raw: bytes, *, launch: Any, observation: Any, epoch: int, plan_digest: str
) -> dict[str, Any]:
    from constitutional_swarm.apcc.codec import _parse
    from constitutional_swarm.apcc.observation import (
        encode_signed_authority_observation,
    )

    value = _parse(raw)
    if (
        type(value) is not dict
        or set(value) != {"body", "key_id", "signature"}
        or canonical_json(value) != raw
    ):
        raise ValueError("invalid observer tail envelope")
    body = value["body"]
    if (
        type(body) is not dict
        or set(body) != TAIL_FIELDS
        or any(type(item) is not str for item in body.values())
    ):
        raise ValueError("invalid observer tail fields")
    b64u_decode(body["nonce"], expected_length=16)
    expected = {
        "launch_digest": launch.canonical_digest,
        "session_id": launch.session_id,
        "observation_sequence": observation.sequence,
        "observation_digest": sha256_digest(
            encode_signed_authority_observation(observation)
        ),
        "epoch": str(epoch),
        "plan_digest": plan_digest,
    }
    if (
        any(body[name] != item for name, item in expected.items())
        or value["key_id"] != launch.observer_key_id
    ):
        raise ValueError("observer tail binding mismatch")
    Ed25519PublicKey.from_public_bytes(
        b64u_decode(launch.observer_public_key, expected_length=32)
    ).verify(
        b64u_decode(value["signature"], expected_length=64),
        TAIL_DOMAIN + b"\0" + canonical_json(body),
    )
    return value


@dataclass(frozen=True)
class W2RenewalConfig:
    plan_digest: str
    journal_path: str
    repetition_id: str
    controller_public_key: bytes
    experiment_id: str
    run_id: str
    maximum_renewals: int
    maximum_total_lifetime_ms: int
    maximum_single_launch_ms: int = 1_200_000
    handover_timeout_ms: int = 2_000

    def validate(self, child: Any) -> None:
        if child.provision is not True:
            raise ValueError(
                "W2 renewal requires fresh provisioning; restart unsupported"
            )
        if child.authority.causal_profile is not AuthorityCausalProfile.W2_LINEAR_100:
            raise ValueError("renewal requires exact W2 profile")
        b64u_decode(self.plan_digest, expected_length=32)
        if len(self.controller_public_key) != 32:
            raise ValueError("invalid renewal controller pin")
        if (
            type(self.maximum_renewals) is not int
            or not 1 <= self.maximum_renewals <= 16
        ):
            raise ValueError("renewal count outside bounded profile")
        for value in (
            self.maximum_total_lifetime_ms,
            self.maximum_single_launch_ms,
            self.handover_timeout_ms,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("invalid renewal lifetime")
        if (
            self.maximum_single_launch_ms > 1_200_000
            or self.maximum_total_lifetime_ms
            > (self.maximum_renewals + 1) * self.maximum_single_launch_ms
        ):
            raise ValueError("renewal lifetime exceeds bounded epochs")
        if not Path(self.journal_path).is_absolute():
            raise ValueError("renewal journal must be absolute")


def _expect(launch: Any) -> ObserverLaunchExpectationsV1:
    return ObserverLaunchExpectationsV1(
        **{
            name: getattr(launch, name)
            for name in ObserverLaunchExpectationsV1.__dataclass_fields__
        }
    )


class _RenewalOwner:
    """Lives only in the single-threaded authority child dispatch loop."""

    def __init__(
        self, config: W2RenewalConfig, child: Any, keys: Any, admin: Any, session: str
    ) -> None:
        config.validate(child)
        self.config, self.child, self.keys, self.admin = config, child, keys, admin
        self.session = session
        self.signer = Ed25519PrivateKey.generate()
        self.key_id = "renewal-" + sha256_digest(
            self.signer.public_key().public_bytes_raw()
        )
        self.journal: RenewalJournal | None = None
        self.launch: Any = None
        self.final: Any = None
        self.epoch = 0
        self.admitted_workflows: set[str] = set()
        self.handover_start = 0.0
        self.delegation = b""
        self.failed = False
        self.plan_bound = False
        self.monotonic_origin = time.monotonic_ns()
        self.highest_wall_ms = int(time.time() * 1000)
        self.control_replies: dict[str, tuple[bytes, Any]] = {}
        self.latest_status: bytes | None = None
        self.prepared_launch: Any = None
        self.prepared_continuity = b""

    def _clock_gate(self) -> None:
        now = int(time.time() * 1000)
        elapsed = (time.monotonic_ns() - self.monotonic_origin) // 1_000_000
        if (
            now < self.highest_wall_ms
            or elapsed >= self.config.maximum_total_lifetime_ms
        ):
            self.failed = True
            raise ValueError("renewal clock rollback or lifetime exhausted")
        self.highest_wall_ms = now

    def _handover_boundary(self, successor: Any) -> int:
        self._clock_gate()
        now = int(time.time() * 1000)
        if (
            time.monotonic() - self.handover_start
        ) * 1000 > self.config.handover_timeout_ms:
            raise ValueError("renewal handover deadline exceeded")
        if not (
            int(self.launch.not_before_ms) <= now < int(self.launch.not_after_ms)
            and int(successor.not_before_ms) <= now < int(successor.not_after_ms)
            and int(successor.not_after_ms)
            <= self.start_ms + self.config.maximum_total_lifetime_ms
        ):
            raise ValueError("renewal activation validity exhausted")
        return now

    @property
    def mutations_enabled(self) -> bool:
        if self.failed or self.journal is None:
            return False
        try:
            self._gate(self.epoch)
        except ValueError:
            return False
        return True

    def _checkpoint(self) -> tuple[str, str, str]:
        from constitutional_swarm.apcc.sqlite_store import (
            _semantic_checkpoint_row,
            _semantic_checkpoint_body,
            _SCHEMA_FINGERPRINT,
        )

        store = self.admin.commit_port._apcc_store
        with store._read_transaction() as connection:
            change, prior, checkpoint, key_id, signature = _semantic_checkpoint_row(
                connection
            )
            self.checkpoint_proof = {
                "body": b64u_encode(
                    _semantic_checkpoint_body(
                        self.child.authority, _SCHEMA_FINGERPRINT, change, prior
                    )
                ),
                "checkpoint_digest": checkpoint,
                "key_id": key_id,
                "signature": signature,
            }
            sequence, head = store._trust_head(connection)
        return checkpoint, sequence, head

    def _gate(self, epoch: int) -> None:
        self._clock_gate()
        if self.failed or self.journal is None:
            raise ValueError("renewal_not_active")
        self.journal.gate(epoch, now_ms=int(time.time() * 1000))

    def route(self, channel: str, envelope: Any, physical_epoch: int | None) -> Any:
        if channel == "w2-renewal-control":
            return envelope
        if channel == "status-signing":
            if physical_epoch != self.epoch:
                raise ValueError("retired_or_unprepared_status_epoch")
            self._gate(physical_epoch)
            return envelope
        if (
            type(envelope) is not dict
            or set(envelope) != {"operation", "request"}
            or envelope["operation"] != "w2_epoch_v1"
        ):
            raise ValueError("missing_w2_epoch")
        body = envelope["request"]
        if type(body) is not dict or set(body) != {
            "epoch",
            "plan_digest",
            "operation",
            "request",
        }:
            raise ValueError("invalid_w2_epoch")
        if (
            type(body["epoch"]) is not int
            or body["plan_digest"] != self.config.plan_digest
        ):
            raise ValueError("w2_epoch_plan_mismatch")
        self._gate(body["epoch"])
        return {"operation": body["operation"], "request": body["request"]}

    def after_request(self, channel: str, request: Any, result: Any) -> None:
        if channel == "status-signing":
            self.latest_status = b64u_decode(result["authority_status_b64u"])
        if channel == "execution" and request["operation"] in {
            "claim",
            "stage_result",
            "prepare_receipt_payload",
        }:
            self.admitted_workflows.add(request["request"]["workflow_id"])
        if channel == "execution" and request["operation"] == "commit":
            from constitutional_swarm.authority_service import _decode_commit_request

            commit = _decode_commit_request(request["request"]["commit_request"])
            self.admitted_workflows.add(commit.receipt.payload.workflow_id)

    def _verify_launch(self, raw: str) -> Any:
        launch = decode_observer_launch_attestation(b64u_decode(raw))
        if (launch.experiment_id, launch.run_id, launch.authority_store_id) != (
            self.config.experiment_id,
            self.config.run_id,
            self.child.authority.authority_store_id,
        ):
            raise ValueError("renewal launch scope mismatch")
        launch.verify(
            pinned_controller_public_key=self.config.controller_public_key,
            expected=_expect(launch),
            now_ms=int(time.time() * 1000),
        )
        if (
            int(launch.not_after_ms) - int(launch.not_before_ms)
            > self.config.maximum_single_launch_ms
        ):
            raise ValueError("renewal launch lifetime exceeds plan")
        return launch

    def control(self, envelope: Any) -> Any:
        if type(envelope) is not dict or set(envelope) != {"operation", "request"}:
            raise ValueError("invalid renewal control envelope")
        wrapped = envelope["request"]
        if (
            type(wrapped) is not dict
            or set(wrapped) != {"request_id", "body"}
            or type(wrapped["request_id"]) is not str
            or not wrapped["request_id"]
        ):
            raise ValueError("invalid renewal request identity")
        request_id = wrapped["request_id"]
        raw = canonical_json(envelope)
        previous = self.control_replies.get(request_id)
        if previous is not None:
            if previous[0] != raw:
                raise ValueError("renewal request identity reused with changed body")
            return previous[1]
        try:
            result = self._control_once(
                {"operation": envelope["operation"], "request": wrapped["body"]}
            )
        except BaseException:
            if self.journal is not None:
                try:
                    if self.journal.records()[-1]["body"]["state"] in {
                        "DRAINED",
                        "PREPARED",
                        "RETIRED",
                    }:
                        self.failed = True
                        self.journal.transition(
                            "FAILED",
                            self.epoch,
                            secrets.token_hex(16),
                            {"reason": "handover_request_failed"},
                            now_ms=max(self.highest_wall_ms, int(time.time() * 1000)),
                        )
                except BaseException:
                    self.failed = True
            raise
        if envelope["operation"] != "records":
            if len(self.control_replies) >= 8 + 4 * self.config.maximum_renewals:
                self.failed = True
                raise ValueError("renewal control request budget exhausted")
            self.control_replies[request_id] = (raw, result)
        return result

    def _control_once(self, envelope: Any) -> Any:
        if envelope.get("operation") not in {"records", "abort"}:
            self._clock_gate()
        if type(envelope) is not dict or set(envelope) != {"operation", "request"}:
            raise ValueError("invalid renewal control envelope")
        operation, body = envelope["operation"], envelope["request"]
        if type(body) is not dict:
            raise ValueError("invalid renewal control body")
        now = int(time.time() * 1000)
        if operation == "abort" and not body:
            self.failed = True
            if self.journal is None:
                return {"state": "FAILED"}
            last = self.journal.records()[-1]
            if last["body"]["state"] == "FAILED":
                return last
            return self.journal.transition(
                "FAILED",
                self.epoch,
                secrets.token_hex(16),
                {"reason": "supervisor_abort"},
                now_ms=max(now, self.highest_wall_ms),
            )
        if operation == "prepare_key" and not body and self.journal is None:
            return {
                "renewal_key_id": self.key_id,
                "renewal_public_key": b64u_encode(
                    self.signer.public_key().public_bytes_raw()
                ),
                "authority_session_id": self.session,
            }
        if operation == "bind_plan" and set(body) == {"plan_digest"}:
            if self.plan_bound or self.journal is not None:
                raise ValueError("renewal plan already bound")
            from dataclasses import replace

            b64u_decode(body["plan_digest"], expected_length=32)
            self.config = replace(self.config, plan_digest=body["plan_digest"])
            self.plan_bound = True
            return {"plan_digest": self.config.plan_digest}
        if operation == "records" and not body:
            return {
                "delegation": b64u_encode(self.delegation),
                "records": [] if self.journal is None else self.journal.records(),
                "checkpoint_proof": getattr(self, "checkpoint_proof", None),
                "initial_checkpoint_proof": getattr(
                    self, "initial_checkpoint_proof", None
                ),
            }
        if operation == "bind_initial" and set(body) == {"launch"}:
            if self.launch is not None or self.failed or not self.plan_bound:
                raise ValueError("initial renewal already bound")
            launch = self._verify_launch(body["launch"])
            checkpoint, sequence, head = self._checkpoint()
            self.initial_checkpoint_proof = dict(self.checkpoint_proof)
            if (launch.initial_trust_sequence, launch.initial_trust_head) != (
                sequence,
                head,
            ):
                raise ValueError("renewal launch trust mismatch")
            self.launch = launch
            self.start_ms = int(launch.not_before_ms)
            self.common = {
                "authority_store_id": launch.authority_store_id,
                "authority_session_id": self.session,
                "repetition_id": self.config.repetition_id,
                "plan_digest": self.config.plan_digest,
                "config_digest": w2_config_digest(self.child.authority),
            }
            self.delegation = encode_delegation(
                {
                    **self.common,
                    "checkpoint_digest": checkpoint,
                    "protocol": DELEGATION_DOMAIN.decode(),
                    "renewal_key_id": self.key_id,
                    "renewal_public_key": b64u_encode(
                        self.signer.public_key().public_bytes_raw()
                    ),
                    "role": "observer-renewal-v1",
                    "initial_launch_digest": launch.canonical_digest,
                    "not_before_ms": str(self.start_ms),
                    "not_after_ms": str(
                        self.start_ms + self.config.maximum_total_lifetime_ms
                    ),
                    "nonce": b64u_encode(secrets.token_bytes(16)),
                },
                self.child.authority.commit_trust.key_id,
                self.keys.commit,
            )
            self.journal = RenewalJournal.create(
                Path(self.config.journal_path),
                self.signer,
                key_id=self.key_id,
                context={
                    k: self.common[k]
                    for k in (
                        "authority_store_id",
                        "authority_session_id",
                        "repetition_id",
                    )
                },
                plan_digest=self.config.plan_digest,
                not_before_ms=self.start_ms,
                expires_at_ms=int(launch.not_after_ms),
                maximum_total_lifetime_ms=self.config.maximum_total_lifetime_ms,
                maximum_renewals=self.config.maximum_renewals,
            )
            return {
                "delegation": b64u_encode(self.delegation),
                "journal": self.journal.records()[-1],
            }
        if self.journal is None or self.failed:
            raise ValueError("renewal not initialized")
        if operation == "drain" and set(body) == {
            "final_observation",
            "ledger_digest",
            "ledger_seal_digest",
            "observer_tail",
        }:
            self._gate(self.epoch)
            for name in ("ledger_digest", "ledger_seal_digest"):
                b64u_decode(body[name], expected_length=32)
            final = decode_signed_authority_observation(
                b64u_decode(body["final_observation"])
            )
            verify_observer_tail(
                b64u_decode(body["observer_tail"]),
                launch=self.launch,
                observation=final,
                epoch=self.epoch,
                plan_digest=self.config.plan_digest,
            )
            checked = verify_authority_observation(
                final,
                launch=self.launch,
                pinned_controller_public_key=self.config.controller_public_key,
                expected_experiment_id=self.config.experiment_id,
                expected_run_id=self.config.run_id,
                expected_launch=_expect(self.launch),
                trust=ScopedTrust(self.child.authority.trust_bindings),
                now_ms=now,
                maximum_staleness_ms=5000,
                highest_trust_log_sequence=self.launch.initial_trust_sequence,
                highest_trust_log_head=self.launch.initial_trust_head,
            )
            if not checked.consumable:
                raise ValueError("renewal final observation not consumable")
            if (
                self.latest_status is None
                or final.snapshot.current_status_evidence != self.latest_status
            ):
                raise ValueError(
                    "renewal final observation is not latest authority status"
                )
            store = self.admin.commit_port._apcc_store
            with store._read_transaction() as connection:
                workflow_nodes = {}
                for workflow in self.admitted_workflows:
                    workflow_nodes[workflow] = tuple(
                        row[0]
                        for row in connection.execute(
                            "SELECT node_id FROM nodes WHERE workflow_id=?", (workflow,)
                        )
                    )
            for workflow, nodes in workflow_nodes.items():
                if not nodes or any(
                    state.status != "governed_committed"
                    for state in self.admin.workflow_node_states(workflow, nodes)
                ):
                    raise ValueError("renewal requires complete admitted workflow")
            checkpoint, sequence, head = self._checkpoint()
            if (checked.trust_log_sequence, checked.trust_log_head) != (sequence, head):
                raise ValueError("renewal final trust mismatch")
            self.final, self.checked, self.checkpoint = final, checked, checkpoint
            self.handover_start = time.monotonic()
            self._gate(self.epoch)
            now = int(time.time() * 1000)
            record = self.journal.transition(
                "DRAINED",
                self.epoch,
                secrets.token_hex(16),
                {
                    "final_observation_digest": sha256_digest(
                        b64u_decode(body["final_observation"])
                    ),
                    "checkpoint_digest": checkpoint,
                    "controller_ledger_digest": body["ledger_digest"],
                    "controller_ledger_seal_digest": body["ledger_seal_digest"],
                    "observer_tail": body["observer_tail"],
                },
                now_ms=now,
            )
            self._handover_boundary(self.launch)
            return record
        if operation == "retire" and not body:
            if self.prepared_launch is None:
                raise ValueError("renewal successor not prepared")
            now = self._handover_boundary(self.prepared_launch)
            record = self.journal.transition(
                "RETIRED",
                self.epoch,
                secrets.token_hex(16),
                {
                    "observer_pid": self.launch.observer_pid,
                    "successor_launch_digest": self.prepared_launch.canonical_digest,
                    "continuity_digest": sha256_digest(self.prepared_continuity),
                },
                now_ms=now,
            )
            self._handover_boundary(self.prepared_launch)
            return record
        if operation == "prepare" and set(body) == {"launch"}:
            if self.epoch >= self.config.maximum_renewals:
                raise ValueError("renewal budget exhausted")
            successor = self._verify_launch(body["launch"])
            checkpoint, sequence, head = self._checkpoint()
            if checkpoint != self.checkpoint or (sequence, head) != (
                successor.initial_trust_sequence,
                successor.initial_trust_head,
            ):
                self.failed = True
                raise ValueError("renewal snapshot changed while fenced")
            if (
                successor.session_id == self.launch.session_id
                or successor.observer_key_id == self.launch.observer_key_id
            ):
                raise ValueError("renewal observer is not fresh")
            from constitutional_swarm.apcc.observation import (
                encode_signed_authority_observation,
            )

            now = self._handover_boundary(successor)
            continuity = encode_continuity(
                {
                    **self.common,
                    "protocol": CONTINUITY_DOMAIN.decode(),
                    "checkpoint_digest": checkpoint,
                    "experiment_id": self.config.experiment_id,
                    "run_id": self.config.run_id,
                    "delegation_digest": sha256_digest(self.delegation),
                    "renewal_index": str(self.epoch + 1),
                    "prior_launch_digest": self.launch.canonical_digest,
                    "successor_launch_digest": successor.canonical_digest,
                    "prior_observer_session_id": self.launch.session_id,
                    "successor_observer_session_id": successor.session_id,
                    "prior_final_observation_sequence": self.final.sequence,
                    "prior_final_observation_digest": sha256_digest(
                        encode_signed_authority_observation(self.final)
                    ),
                    "trust_change_sequence": sequence,
                    "trust_log_head": head,
                    "issued_at_ms": str(now),
                    "successor_not_after_ms": successor.not_after_ms,
                    "cumulative_elapsed_ms": str(
                        (time.monotonic_ns() - self.monotonic_origin) // 1_000_000
                    ),
                    "nonce": b64u_encode(secrets.token_bytes(16)),
                },
                self.key_id,
                self.signer,
            )
            self.prepared_launch, self.prepared_continuity = successor, continuity
            record = self.journal.transition(
                "PREPARED",
                self.epoch,
                secrets.token_hex(16),
                {
                    "next_epoch": str(self.epoch + 1),
                    "continuity_digest": sha256_digest(continuity),
                    "launch_digest": successor.canonical_digest,
                },
                now_ms=now,
            )
            self._handover_boundary(successor)
            return {"continuity": b64u_encode(continuity), "journal": record}
        if operation == "activate" and set(body) == {"launch"}:
            successor = self._verify_launch(body["launch"])
            if self.prepared_launch is None or successor != self.prepared_launch:
                raise ValueError("successor differs from durable prepared launch")
            checkpoint, sequence, head = self._checkpoint()
            if checkpoint != self.checkpoint or (sequence, head) != (
                successor.initial_trust_sequence,
                successor.initial_trust_head,
            ):
                raise ValueError("renewal snapshot changed after preparation")
            now = self._handover_boundary(successor)
            continuity = self.prepared_continuity
            record = self.journal.transition(
                "ACTIVE",
                self.epoch + 1,
                secrets.token_hex(16),
                {
                    "continuity_digest": sha256_digest(continuity),
                    "launch_digest": successor.canonical_digest,
                },
                now_ms=now,
                expires_at_ms=int(successor.not_after_ms),
            )
            try:
                self._handover_boundary(successor)
            except BaseException:
                self.failed = True
                self.journal.transition(
                    "FAILED",
                    self.epoch + 1,
                    secrets.token_hex(16),
                    {"reason": "activation_expired_during_persistence"},
                    now_ms=max(int(time.time() * 1000), self.highest_wall_ms),
                )
                raise
            self.epoch += 1
            self.launch = successor
            self.admitted_workflows.clear()
            self.latest_status = None
            return {"continuity": b64u_encode(continuity), "journal": record}
        raise ValueError("unknown renewal control operation")

    def close(self) -> None:
        if self.journal is not None:
            self.journal.close()


def _bind_renewal(
    handle: Any, config: W2RenewalConfig, endpoints: list[socket.socket]
) -> Any:
    from constitutional_swarm.authority_service import (
        _JSONClient,
        _StatusSigningClient,
        _bind_verified_child_channel,
    )

    def bind(endpoint: socket.socket, cls: Any, role: str) -> Any:
        return _bind_verified_child_channel(
            cls,
            endpoint,
            channel_role=role,
            session=handle._session_id,
            authority_pid=handle.pid,
            ipc_public_key=Ed25519PublicKey.from_public_bytes(handle._ipc_public_key),
            max_frame_bytes=handle._max_frame_bytes,
        )

    return {
        "config": config,
        "control": bind(endpoints[0], _JSONClient, "w2-renewal-control"),
        "status": [
            bind(endpoint, _StatusSigningClient, "status-signing")
            for endpoint in endpoints[1:]
        ],
    }


def _persistent_signer_child(
    reference: Any, config: W2RenewalConfig, channel: Any
) -> None:
    from constitutional_swarm.authority_isolation import (
        harden_current_process,
        erase_secret,
    )
    from constitutional_swarm.authority_observer import (
        _decode_controller_key,
        _LAUNCH_CANDIDATE_FIELDS,
        _reject_duplicate_keys,
        sign_launch_candidate,
    )

    try:
        harden_current_process()
        channel.send({"stage": "HARDENED_READY", "pid": os.getpid(), "dumpable": 0})
        secret = bytearray(channel.recv_bytes(257))
        try:
            key = _decode_controller_key(secret, reference)
        finally:
            erase_secret(secret)
        channel.send(
            {
                "stage": "TCB_READY",
                "pid": os.getpid(),
                "controller_key_id": sha256_digest(reference.expected_public_key),
            }
        )
        sessions: set[str] = set()
        for _ in range(config.maximum_renewals + 1):
            candidate = json.loads(
                channel.recv_bytes(16385), object_pairs_hook=_reject_duplicate_keys
            )
            if (
                type(candidate) is not dict
                or set(candidate) != _LAUNCH_CANDIDATE_FIELDS
                or any(type(v) is not str for v in candidate.values())
            ):
                raise ValueError("invalid renewal launch candidate")
            if (candidate["experiment_id"], candidate["run_id"]) != (
                config.experiment_id,
                config.run_id,
            ):
                raise ValueError("renewal launch candidate scope mismatch")
            if (
                candidate["session_id"] in sessions
                or not 0
                < int(candidate["not_after_ms"]) - int(candidate["not_before_ms"])
                <= config.maximum_single_launch_ms
            ):
                raise ValueError("renewal launch candidate reused or oversized")
            sessions.add(candidate["session_id"])
            channel.send_bytes(
                canonical_json(
                    sign_launch_candidate(
                        candidate, key, sha256_digest(reference.expected_public_key)
                    )
                )
            )
        # Remain owned and observable until supervisor teardown, even after
        # the last permitted signature. Further requests fail closed.
        channel.recv_bytes(1)
        raise ValueError("renewal signer budget exhausted")
    except EOFError:
        pass
    finally:
        channel.close()


class _PersistentSigner:
    def __init__(self, reference: Any, config: W2RenewalConfig, on_spawn: Any) -> None:
        from constitutional_swarm.authority_isolation import (
            consume_secret_file,
            erase_secret,
        )
        from constitutional_swarm.authority_service import _verify_hardened_ready
        from constitutional_swarm.authority_observer import ControllerKeySourceRef

        context = multiprocessing.get_context("spawn")
        self.channel, child = context.Pipe(duplex=True)
        self.process = context.Process(
            target=_persistent_signer_child,
            args=(
                ControllerKeySourceRef(
                    "consumed:w2-controller", reference.expected_public_key
                ),
                config,
                child,
            ),
            name="apcc-w2-renewal-controller",
        )
        secret = consume_secret_file(
            reference.location, maximum_bytes=256, label="W2 renewal controller"
        )
        try:
            self.process.start()
            child.close()
            if self.process.pid is None:
                raise RuntimeError("renewal signer missing PID")
            on_spawn("controller", self.process.pid)
            if not self.channel.poll(5):
                raise TimeoutError("renewal signer startup timeout")
            _verify_hardened_ready(
                self.channel.recv(), self.process.pid, "W2 renewal controller"
            )
            self.channel.send_bytes(secret)
            erase_secret(secret)
            if not self.channel.poll(5):
                raise TimeoutError("renewal signer TCB timeout")
            if self.channel.recv() != {
                "stage": "TCB_READY",
                "pid": self.process.pid,
                "controller_key_id": sha256_digest(reference.expected_public_key),
            }:
                raise ValueError("renewal signer identity mismatch")
        except BaseException:
            self.shutdown()
            raise
        finally:
            erase_secret(secret)

    def sign(self, candidate: dict[str, object]) -> dict[str, object]:
        self.channel.send_bytes(canonical_json(candidate))
        if not self.channel.poll(5):
            raise TimeoutError("renewal signer timed out")
        result = json.loads(self.channel.recv_bytes(16385))
        if type(result) is not dict:
            raise ValueError("invalid renewal signer response")
        return result

    def close(self) -> None:
        # Borrowed by one observer bootstrap; owner closes it after all epochs.
        pass

    def shutdown(self) -> None:
        from constitutional_swarm.authority_service import _abort_process

        self.channel.close()
        _abort_process(self.process)


class _EpochAdminTransport:
    def __init__(self, service: W2RenewalService, transport: Any) -> None:
        self.service, self.transport = service, transport

    def _rpc(self, operation: str, request: Any) -> Any:
        return self.transport._rpc(
            "w2_epoch_v1",
            {
                "epoch": self.service.epoch,
                "plan_digest": self.service.config.plan_digest,
                "operation": operation,
                "request": request,
            },
        )

    def close(self) -> None:
        self.transport.close()


class W2RenewalService:
    """Supervisor ownership of one authority, one scheduler and bounded observers."""

    def __init__(
        self,
        authority: Any,
        config: W2RenewalConfig,
        launch: Any,
        plan_builder: Any,
        on_spawn: Any,
        owned_pids: list[int],
    ) -> None:
        from constitutional_swarm.authority_service import (
            AuthorityAdminClient,
            _JSONClient,
        )

        self.authority, self.config, self.launch_config = authority, config, launch
        self._on_spawn = on_spawn
        self.owned_pids = owned_pids
        self._admission_condition = threading.Condition(threading.RLock())
        self._admission_local = threading.local()
        self._admission_count = 0
        self._fencing = False
        self.epoch = 0
        self._renewal_results: dict[str, tuple[bytes, dict[str, Any]]] = {}
        self.observer: Any = None
        self.signer = _PersistentSigner(launch.controller_key_source, config, on_spawn)
        authority._w2_renewal["signer"] = self.signer
        with authority._lifecycle_lock:
            authority._watch_process_locked("w2-controller", self.signer.process)
        self.admin_client = AuthorityAdminClient(
            cast(
                _JSONClient, _EpochAdminTransport(self, authority.admin_client._client)
            )
        )
        self._closed = False
        try:
            from dataclasses import replace

            key_info = self._control("prepare_key", {})
            plan_digest = plan_builder(key_info)
            self._control("bind_plan", {"plan_digest": plan_digest})
            self.config = replace(config, plan_digest=plan_digest)
            self.observer = self._start_observer(launch)
            self._control(
                "bind_initial",
                {
                    "launch": b64u_encode(
                        canonical_json(asdict(self.observer.launch_attestation))
                    )
                },
            )
        except BaseException:
            try:
                self._control("abort", {})
            except BaseException:
                pass
            self.close()
            raise

    def _control(
        self, operation: str, request: Any, *, request_id: str | None = None
    ) -> Any:
        if operation in {"drain", "prepare", "retire", "activate"}:
            with self._admission_condition:
                if not self._fencing or self._admission_count:
                    raise ValueError(
                        "handover requires controller admission fence and drained permits"
                    )
        return self.authority._w2_renewal["control"]._rpc(
            operation,
            {
                "request_id": request_id or secrets.token_hex(16),
                "body": request,
            },
        )

    def _start_observer(self, launch: Any, *, epoch: int | None = None) -> Any:
        from constitutional_swarm.authority_service import (
            _start_authority_observer_locked,
            _controlled_boot_result,
            ControlledBootPhase,
        )

        handle = self.authority
        selected_epoch = self.epoch if epoch is None else epoch
        role = "w2-observer-" + str(selected_epoch)
        with handle._lifecycle_lock:
            observer = _start_authority_observer_locked(
                handle,
                launch,
                postgres_observer_dsn=None,
                _controller_signer_override=self.signer,
                _observer_role=role,
                _w2_binding=(selected_epoch, self.config.plan_digest),
                _w2_on_spawn=lambda _role, pid: self._on_spawn(
                    f"observer-{selected_epoch}", pid
                ),
            )
            role += "-" + str(observer.pid)
            observer._on_close = lambda: handle._component_failed(role)
            handle._observers.append(observer)
            handle._watch_process_locked(role, observer._process)
            if selected_epoch == 0:
                handle._controlled_boot = _controlled_boot_result(
                    ControlledBootPhase.OBSERVER_READY
                )
            handle._refresh_liveness_locked()
            return observer

    def spawn_executor(self, registry: Any, *, policy_version: str) -> Any:
        return self.authority.spawn_executor(registry, policy_version=policy_version)

    @contextmanager
    def admission_scope(self) -> Any:
        from constitutional_swarm.governance_errors import GovernanceBypassDenied

        with self._admission_condition:
            if self._fencing or self._closed:
                raise GovernanceBypassDenied("W2 renewal admission fenced")
            if getattr(self._admission_local, "inside", False):
                raise ValueError("nested W2 admission scope")
            self._admission_local.inside = True
            try:
                yield self.epoch
            finally:
                self._admission_local.inside = False

    def begin_admission(self) -> None:
        if not getattr(self._admission_local, "inside", False):
            raise ValueError("W2 admission requires atomic admission scope")
        if self._fencing or self._closed:
            raise ValueError("W2 renewal admission fenced")
        self._admission_count += 1

    def end_admission(self) -> None:
        with self._admission_condition:
            if self._admission_count <= 0:
                raise ValueError("unbalanced W2 admission release")
            self._admission_count -= 1
            self._admission_condition.notify_all()

    def evidence(self) -> dict[str, Any]:
        return {
            **self._control("records", {}),
            "epoch": self.epoch,
            "authority_session_id": self.authority._session_id,
            "launch": asdict(self.observer.launch_attestation),
        }

    def renew(
        self,
        *,
        final_observation: bytes,
        ledger_digest: str,
        ledger_seal_digest: str,
        launch_lifetime_ms: int,
    ) -> dict[str, Any]:
        from dataclasses import replace

        renewal_started = time.monotonic()
        handle = self.authority
        request_bytes = canonical_json(
            {
                "final_observation": b64u_encode(final_observation),
                "ledger_digest": ledger_digest,
                "ledger_seal_digest": ledger_seal_digest,
                "launch_lifetime_ms": launch_lifetime_ms,
            }
        )
        prior = self._renewal_results.get(ledger_digest)
        if prior is not None:
            if prior[0] != request_bytes:
                raise ValueError("renewal ledger identity reused with changed request")
            return prior[1]
        try:
            with self._admission_condition:
                if self._fencing or self._closed:
                    raise ValueError("concurrent renewal or closed session")
                self._fencing = True
                while self._admission_count:
                    remaining = self.config.handover_timeout_ms / 1000 - (
                        time.monotonic() - renewal_started
                    )
                    if remaining <= 0:
                        raise TimeoutError(
                            "renewal full-proof admission drain timed out"
                        )
                    self._admission_condition.wait(remaining)
            tail = self.observer.client._rpc(
                "w2_seal_tail_v1", {"nonce": b64u_encode(secrets.token_bytes(16))}
            )
            self._control(
                "drain",
                {
                    "final_observation": b64u_encode(final_observation),
                    "ledger_digest": ledger_digest,
                    "ledger_seal_digest": ledger_seal_digest,
                    "observer_tail": b64u_encode(canonical_json(tail)),
                },
            )
            if self.epoch >= self.config.maximum_renewals:
                raise ValueError("renewal budget exhausted")
            with handle._lifecycle_lock:
                handle._status_signing_channel = handle._w2_renewal["status"][
                    self.epoch
                ]
                successor = self._start_observer(
                    replace(self.launch_config, launch_lifetime_ms=launch_lifetime_ms),
                    epoch=self.epoch + 1,
                )
            successor_body = {
                "launch": b64u_encode(
                    canonical_json(asdict(successor.launch_attestation))
                )
            }
            self._control("prepare", successor_body)
            retirement = self._control("retire", {})
            # Only a durable retirement response allows this exact old watcher
            # and close callback to become nonfatal. An early crash stays fatal.
            with handle._lifecycle_lock:
                handle._refresh_liveness_locked()
                if handle._closed:
                    raise RuntimeError("observer died before durable retirement")
                role = "w2-observer-" + str(self.epoch) + "-" + str(self.observer.pid)
                handle._w2_retired_observers.add(role)
                handle._observers.remove(self.observer)
                self.observer.close()
                activated = self._control("activate", successor_body)
                self.epoch += 1
                self.observer = successor
                if (
                    time.monotonic() - renewal_started
                ) * 1000 > self.config.handover_timeout_ms:
                    raise TimeoutError("renewal total handover deadline exceeded")
            with self._admission_condition:
                self._fencing = False
                self._admission_condition.notify_all()
            result = {**activated, **self.evidence(), "retirement": retirement}
            self._renewal_results[ledger_digest] = (request_bytes, result)
            return result
        except BaseException:
            try:
                self._control("abort", {})
            except BaseException:
                pass
            self.close()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._admission_condition:
            self._fencing = True
            self._admission_condition.notify_all()
        try:
            self.authority.close()
        finally:
            self.signer.shutdown()


def start_w2_renewal_authority(
    child: Any,
    config: W2RenewalConfig,
    launch: Any,
    *,
    plan_builder: Any,
    on_spawn: Any = None,
) -> W2RenewalService:
    from constitutional_swarm.authority_service import start_authority

    config.validate(child)
    owned_pids: list[int] = []

    def record(role: str, pid: int) -> None:
        owned_pids.append(pid)
        if on_spawn is not None:
            on_spawn(role, pid)

    authority = start_authority(child, _w2_renewal=config, _w2_on_spawn=record)
    try:
        return W2RenewalService(
            authority, config, launch, plan_builder, record, owned_pids
        )
    except BaseException:
        authority.close()
        raise
