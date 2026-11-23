"""Adversarial end-to-end fault suite for ``APCCExecutionGateway``.

Real processes and real sockets only: the authority store, gateway ledger and
gateway run in separate worker processes (``tests/apcc_gateway_fault_procs.py``)
that open the SQLite databases from disk; the external target is a separate
HTTPS process with its own durable SQLite state; a byte-level TCP proxy thread
sits between them without terminating TLS. Nothing in the gateway, ledger,
store or HTTP stack is mocked. Every scenario ends with on-disk assertions
after recovery by a fresh worker process.

Scenario map: A ambiguous outcome, B SIGKILL cut points, C zombie fencing,
D credential binding, E TLS failures, F cross-tenant replay, G retry storm,
H key rotation. Expectations pin what the code does today; gaps are reported
in the change description, not hidden.
"""

from __future__ import annotations

import base64
import json
import signal
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.execution_gateway import (
    SQLiteExecutionLedger,
    derive_effect_idempotency_key,
)
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
from constitutional_swarm.apcc.verifier import (
    ScopedTrust,
    verify_current,
    verify_historical,
)
from tests.apcc_gateway_fault_harness import (
    BASE_NOW_MS,
    LEASE_EXPIRED_NOW_MS,
    FaultProxy,
    ProcessHandle,
    StoreHandle,
    TargetProcess,
    TestPKI,
    WorkerRun,
    authority_config,
    collect_worker,
    commit_effect,
    gateway_trust,
    key_provider,
    ledger_snapshot,
    outbox_states,
    provision_store,
    run_worker,
    running_target,
    start_worker,
    wait_for,
)

TOKEN = "gw-fault-suite-bearer-5f2c9e"
WRONG_TOKEN = "executor-forged-bearer-77ad01"


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> TestPKI:
    return TestPKI.generate(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def target(tmp_path: Path, pki: TestPKI) -> Any:
    with running_target(tmp_path / "target", pki, token=TOKEN) as process:
        yield process


@pytest.fixture
def proxy(target: TargetProcess) -> Any:
    fault_proxy = FaultProxy(target.ports["good"])
    try:
        yield fault_proxy
    finally:
        fault_proxy.close()


class FaultEnv:
    """One scenario's databases, target, proxy and worker launcher."""

    def __init__(self, tmp_path: Path, pki: TestPKI, target: TargetProcess, proxy: FaultProxy):
        self.tmp = tmp_path
        self.pki = pki
        self.target = target
        self.proxy = proxy
        self.ledger_path = tmp_path / "gateway_ledger.sqlite"
        self._labels: set[str] = set()

    @property
    def proxy_url(self) -> str:
        return f"https://127.0.0.1:{self.proxy.port}/execute"

    def provision(self, store_id: str = "store-1", generation: str = "gen1") -> StoreHandle:
        path = self.tmp / f"authority-{store_id}-{generation}.sqlite"
        return provision_store(path, store_id=store_id, generation=generation)

    def spec(
        self,
        store: StoreHandle,
        *,
        now_ms: int = BASE_NOW_MS,
        endpoint: str | None = None,
        trusted_ca: bool = True,
        timeout_s: float = 5.0,
        cut_point: str | None = None,
        cycles: int = 1,
        commit_trust: str | None = None,
        status_trust: str | None = None,
        inject: Any = None,
    ) -> dict[str, Any]:
        return {
            "store_path": str(store.path),
            "authority_store_id": store.store_id,
            "store_generation": store.generation,
            "ledger_path": str(self.ledger_path),
            "now_ms": now_ms,
            "endpoint_url": endpoint or self.proxy_url,
            "ca_file": str(self.pki.ca_cert) if trusted_ca else None,
            "timeout_seconds": timeout_s,
            "max_items": 10,
            "cycles": cycles,
            "cut_point": cut_point,
            "trust_commit_generation": commit_trust or store.generation,
            "trust_status_generation": status_trust or store.generation,
            "inject_event": None
            if inject is None
            else {
                "event_id": inject.event_id,
                "payload_b64": base64.b64encode(inject.payload).decode("ascii"),
            },
        }

    def _workdir(self, label: str) -> Path:
        assert label not in self._labels, label
        self._labels.add(label)
        return self.tmp / "workers" / label

    def worker(
        self, store: StoreHandle, label: str, *, bearer: str = TOKEN, **kw: Any
    ) -> WorkerRun:
        return run_worker(self.spec(store, **kw), self._workdir(label), bearer_token=bearer)

    def start(self, store: StoreHandle, label: str, **kw: Any) -> tuple[ProcessHandle, Path]:
        workdir = self._workdir(label)
        return start_worker(self.spec(store, **kw), workdir, bearer_token=TOKEN), workdir

    # ---- on-disk views ---------------------------------------------------
    def effects(self) -> list[dict[str, Any]]:
        return ledger_snapshot(self.ledger_path)["effects"]

    def effect(self) -> dict[str, Any]:
        effects = self.effects()
        assert len(effects) == 1, effects
        return effects[0]

    def trace(self) -> list[tuple[int, str, int | None]]:
        return [
            (row["status_code"], row["reason"], row["fencing_token"])
            for row in self.target.view.requests()
        ]


@pytest.fixture
def env(tmp_path: Path, pki: TestPKI, target: TargetProcess, proxy: FaultProxy) -> FaultEnv:
    return FaultEnv(tmp_path, pki, target, proxy)


def _only_outbox_state(store: StoreHandle) -> str:
    states = outbox_states(store.path)
    assert len(states) == 1, states
    return states[0][2]


def _assert_clean_run(run: WorkerRun) -> None:
    assert run.returncode == 0, run.stderr
    assert run.errors == [None], run.errors


def _assert_applied_exactly_once(
    env: FaultEnv, *, key: str, applied_token: int, final_token: int, attempts: int
) -> dict[str, Any]:
    applied = env.target.view.applied()
    assert [(row["idempotency_key"], row["fencing_token"]) for row in applied] == [
        (key, applied_token)
    ]
    effect = env.effect()
    assert effect["idempotency_key"] == key
    assert effect["state"] == "APPLIED"
    assert effect["fencing_token"] == final_token
    assert effect["attempt_count"] == attempts
    assert effect["target_reference"] == applied[0]["target_reference"]
    assert effect["applied_digest"] == applied[0]["applied_digest"]
    return applied[0]


# --------------------------------------------------------------------------- #
# A. Ambiguous outcome: upstream applied, response lost                        #
# --------------------------------------------------------------------------- #

_AMBIGUOUS_FAULTS = {
    # fault -> (gateway timeout, recorded exception type, cause type, message fragment)
    # The reset surfaces in getresponse(), outside urllib's URLError wrapping.
    "drop_before_response": (
        5.0,
        "ExecutionGatewayError",
        "ConnectionResetError",
        "transport error",
    ),
    "delay_past_client_timeout": (1.0, "ExecutionGatewayError", "TimeoutError", "transport error"),
    # The headers arrive (HTTP 201) and the body is cut.  The gateway reads a
    # bounded number of bytes, so the truncated body is an unparseable receipt.
    "close_mid_response": (
        5.0,
        "ExecutionGatewayError",
        None,
        "invalid JSON receipt",
    ),
}


@pytest.mark.parametrize("fault", sorted(_AMBIGUOUS_FAULTS))
def test_a_ambiguous_outcome_is_replayed_exactly_once_after_restart(
    env: FaultEnv, fault: str
) -> None:
    timeout_s, error_type, cause_type, fragment = _AMBIGUOUS_FAULTS[fault]
    store = env.provision()
    _result, event = commit_effect(store, commit_id="a-ambiguous", nonce_byte=101)
    env.proxy.arm(fault)

    first = env.worker(store, "first", timeout_s=timeout_s)
    assert first.returncode == 0, first.stderr
    [error] = first.errors
    assert error is not None
    assert error["type"] == error_type, error
    assert error["cause_type"] == cause_type, error
    assert fragment in error["message"], error
    # Every lost-response shape stays inside the gateway's error contract,
    # including a response cut off after its headers.
    assert "ExecutionGatewayError" in error["mro"]
    assert "HTTPException" not in error["mro"]
    assert env.proxy.connections[0].mode == fault
    assert env.proxy.connections[0].fault_fired

    # The upstream really applied the effect; the gateway saw no receipt.
    assert env.trace() == [(201, "applied", 1)]
    [applied] = env.target.view.applied()
    key = applied["idempotency_key"]
    effect = env.effect()
    assert (effect["state"], effect["fencing_token"], effect["attempt_count"]) == (
        "IN_FLIGHT",
        1,
        1,
    )
    assert _only_outbox_state(store) == "PENDING"

    second = env.worker(store, "fresh-process-redelivery")
    _assert_clean_run(second)
    # Target-side truth first: same Idempotency-Key, strictly higher fencing
    # token, exactly one application.
    assert [(r["idempotency_key"], r["fencing_token"]) for r in env.target.view.applied()] == [
        (key, 1)
    ]
    assert [(r["idempotency_key"], r["fencing_token"]) for r in env.target.view.requests()] == [
        (key, 1),
        (key, 2),
    ]
    assert env.trace() == [(201, "applied", 1), (200, "idempotent_replay", 2)]
    [outcome] = second.outcomes
    assert outcome["event_id"] == event.event_id
    assert outcome["disposition"] == "replayed"
    assert outcome["idempotency_key"] == key
    assert outcome["fencing_token"] == 2
    assert outcome["receipt"]["replayed"] is True
    _assert_applied_exactly_once(env, key=key, applied_token=1, final_token=2, attempts=2)
    assert _only_outbox_state(store) == "DELIVERED"


def test_a_refused_connection_is_unambiguous_and_applies_once_on_redelivery(
    env: FaultEnv,
) -> None:
    store = env.provision()
    commit_effect(store, commit_id="a-refused", nonce_byte=102)
    env.proxy.refuse()

    first = env.worker(store, "refused")
    assert first.returncode == 0, first.stderr
    [error] = first.errors
    assert error is not None
    assert error["type"] == "ExecutionGatewayError"
    assert error["cause_type"] == "URLError"
    assert "Connection refused" in error["message"]
    assert env.target.view.requests() == []
    effect = env.effect()
    # The fencing token was spent before the connect attempt.
    assert (effect["state"], effect["fencing_token"], effect["attempt_count"]) == (
        "IN_FLIGHT",
        1,
        1,
    )
    assert _only_outbox_state(store) == "PENDING"

    env.proxy.resume()
    second = env.worker(store, "after-resume")
    _assert_clean_run(second)
    assert [o["disposition"] for o in second.outcomes] == ["applied"]
    assert env.trace() == [(201, "applied", 2)]
    _assert_applied_exactly_once(
        env, key=effect["idempotency_key"], applied_token=2, final_token=2, attempts=2
    )
    assert _only_outbox_state(store) == "DELIVERED"


# --------------------------------------------------------------------------- #
# B. SIGKILL at four cut points, recovery by a fresh process                   #
# --------------------------------------------------------------------------- #

_CUT_EXPECTATIONS: dict[str, dict[str, Any]] = {
    # (a) killed after verification, before the IN_FLIGHT transaction.
    "before_in_flight_write": {
        "effect_after_kill": None,
        "next_token_after_kill": 1,
        "trace_after_kill": [],
        "final_trace": [(201, "applied", 1)],
        "applied_token": 1,
        "final_token": 1,
        "attempts": 1,
        "disposition": "applied",
    },
    # (b) IN_FLIGHT committed with token 1; token 1 never leaves the process.
    "after_in_flight_commit": {
        "effect_after_kill": ("IN_FLIGHT", 1, 1),
        "next_token_after_kill": 2,
        "trace_after_kill": [],
        "final_trace": [(201, "applied", 2)],
        "applied_token": 2,
        "final_token": 2,
        "attempts": 2,
        "disposition": "applied",
    },
    # (c) target applied token 1; the response was never read.
    "after_request_before_response": {
        "effect_after_kill": ("IN_FLIGHT", 1, 1),
        "next_token_after_kill": 2,
        "trace_after_kill": [(201, "applied", 1)],
        "final_trace": [(201, "applied", 1), (200, "idempotent_replay", 2)],
        "applied_token": 1,
        "final_token": 2,
        "attempts": 2,
        "disposition": "replayed",
    },
    # (d) receipt received and validated; APPLIED never written.
    "after_response_before_mark_applied": {
        "effect_after_kill": ("IN_FLIGHT", 1, 1),
        "next_token_after_kill": 2,
        "trace_after_kill": [(201, "applied", 1)],
        "final_trace": [(201, "applied", 1), (200, "idempotent_replay", 2)],
        "applied_token": 1,
        "final_token": 2,
        "attempts": 2,
        "disposition": "replayed",
    },
}


@pytest.mark.parametrize("cut_point", list(_CUT_EXPECTATIONS))
def test_b_sigkill_at_cut_point_recovers_exactly_once(env: FaultEnv, cut_point: str) -> None:
    expected = _CUT_EXPECTATIONS[cut_point]
    store = env.provision()
    _result, event = commit_effect(store, commit_id="b-cut", nonce_byte=110)
    key = derive_effect_idempotency_key(
        store.store_id, event.event_id, sha256_digest(event.payload), "b-cut"
    )

    killed = env.worker(store, "killed", cut_point=cut_point)
    assert killed.returncode == -signal.SIGKILL, (killed.returncode, killed.stderr)
    assert killed.result is None  # died before writing any result
    assert killed.marker is not None and killed.marker["cut_point"] == cut_point
    if cut_point == "after_response_before_mark_applied":
        assert killed.marker["receipt"]["fencing_token"] == 1
        assert killed.marker["receipt"]["replayed"] is False
        assert killed.marker["receipt"]["idempotency_key"] == key
    if cut_point == "after_request_before_response":
        assert killed.marker["response_bytes_pending_unread"] is True

    # Disk state is exactly what the cut point implies.
    snapshot = ledger_snapshot(env.ledger_path)
    assert snapshot["next_fencing_token"] == expected["next_token_after_kill"]
    if expected["effect_after_kill"] is None:
        assert snapshot["effects"] == []
    else:
        [effect] = snapshot["effects"]
        assert effect["idempotency_key"] == key
        assert (effect["state"], effect["fencing_token"], effect["attempt_count"]) == expected[
            "effect_after_kill"
        ]
    assert env.trace() == expected["trace_after_kill"]
    assert _only_outbox_state(store) == "CLAIMED"  # SIGKILL never released the lease

    recovered = env.worker(store, "recovery", now_ms=LEASE_EXPIRED_NOW_MS)
    _assert_clean_run(recovered)
    # Target-side truth first, then the gateway's own view.
    assert [(r["idempotency_key"], r["fencing_token"]) for r in env.target.view.applied()] == [
        (key, expected["applied_token"])
    ]
    assert env.trace() == expected["final_trace"]
    assert {row["idempotency_key"] for row in env.target.view.requests()} == {key}
    [outcome] = recovered.outcomes
    assert outcome["disposition"] == expected["disposition"]
    assert outcome["idempotency_key"] == key
    assert outcome["fencing_token"] == expected["final_token"]
    _assert_applied_exactly_once(
        env,
        key=key,
        applied_token=expected["applied_token"],
        final_token=expected["final_token"],
        attempts=expected["attempts"],
    )
    assert _only_outbox_state(store) == "DELIVERED"


# --------------------------------------------------------------------------- #
# C. Zombie worker with an older fencing token                                 #
# --------------------------------------------------------------------------- #


def test_c_zombie_attempt_with_older_token_is_rejected_and_changes_nothing(
    env: FaultEnv,
) -> None:
    store = env.provision()
    commit_effect(store, commit_id="c-zombie", nonce_byte=120)
    env.proxy.arm("hold_request", "pass")

    zombie, zombie_dir = env.start(store, "zombie", timeout_s=30.0)
    try:
        wait_for(env.proxy.holding.is_set, timeout_s=30.0, what="zombie request held at proxy")
        assert env.target.view.requests() == []
        held = env.effect()
        assert (held["state"], held["fencing_token"], held["attempt_count"]) == (
            "IN_FLIGHT",
            1,
            1,
        )

        # The zombie still holds the outbox lease; a fresh worker takes over
        # after lease expiry and applies with token 2.
        fresh = env.worker(store, "fresh", now_ms=LEASE_EXPIRED_NOW_MS)
        _assert_clean_run(fresh)
        assert [(o["disposition"], o["fencing_token"]) for o in fresh.outcomes] == [("applied", 2)]
        assert _only_outbox_state(store) == "DELIVERED"

        env.proxy.release_held()
        zombie_run = collect_worker(zombie, zombie_dir, timeout_s=30.0)
    finally:
        zombie.kill()

    assert zombie_run.returncode == 0, zombie_run.stderr
    [error] = zombie_run.errors
    assert error is not None and error["type"] == "StaleFencingTokenError", error
    assert "409" in error["message"]
    assert env.trace() == [(201, "applied", 2), (409, "stale_fencing_token", 1)]
    applied = _assert_applied_exactly_once(
        env, key=held["idempotency_key"], applied_token=2, final_token=2, attempts=2
    )
    assert env.target.view.key_state(applied["idempotency_key"])["highest_fencing_token"] == 2
    assert _only_outbox_state(store) == "DELIVERED"  # zombie's release did not regress it


# --------------------------------------------------------------------------- #
# D. Credential binding mismatch                                               #
# --------------------------------------------------------------------------- #


def test_d_wrong_bearer_fails_closed_then_correct_credential_applies(env: FaultEnv) -> None:
    store = env.provision()
    commit_effect(store, commit_id="d-cred", nonce_byte=130)

    rejected = env.worker(store, "wrong-bearer", bearer=WRONG_TOKEN)
    assert rejected.returncode == 0, rejected.stderr
    [error] = rejected.errors
    assert error is not None and error["type"] == "TargetAuthorizationError", error
    assert "(401)" in error["message"]
    assert env.trace() == [(401, "unauthorized", None)]
    assert env.target.view.applied() == []
    effect = env.effect()
    assert effect["state"] == "IN_FLIGHT"
    assert _only_outbox_state(store) == "PENDING"  # redeliverable
    # Neither credential leaks into results, errors, repr or durable state.
    for secret in (WRONG_TOKEN, TOKEN):
        assert secret not in rejected.all_text()
        assert secret.encode() not in env.ledger_path.read_bytes()
        assert secret.encode() not in store.path.read_bytes()
    assert "<redacted>" in rejected.result["target_repr"]

    accepted = env.worker(store, "correct-bearer")
    _assert_clean_run(accepted)
    assert [o["disposition"] for o in accepted.outcomes] == ["applied"]
    assert env.trace() == [(401, "unauthorized", None), (201, "applied", 2)]
    _assert_applied_exactly_once(
        env, key=effect["idempotency_key"], applied_token=2, final_token=2, attempts=2
    )
    assert TOKEN not in accepted.all_text()
    assert _only_outbox_state(store) == "DELIVERED"


_REFLECTED = {
    403: ("TargetAuthorizationError", "external target rejected authorization (403)"),
    409: ("StaleFencingTokenError", "external target rejected stale fence or conflict (409)"),
    500: ("ExecutionGatewayError", "external target HTTP error (500)"),
}


@pytest.mark.parametrize("status", sorted(_REFLECTED))
def test_d_target_reflected_credential_must_not_reach_gateway_error(
    env: FaultEnv, status: int
) -> None:
    """A target that echoes the Authorization header must not leak the token.

    The gateway reports the status code only.  The target's body and reason
    phrase reach neither the message nor ``__cause__`` nor ``__context__``.
    """
    store = env.provision()
    commit_effect(store, commit_id=f"d-reflect-{status}", nonce_byte=131)
    env.target.view.push_faults(("echo_authorization", status))

    run = env.worker(store, "reflected")
    [error] = run.errors
    expected_type, expected_message = _REFLECTED[status]
    assert error is not None and error["type"] == expected_type, error
    assert error["message"] == expected_message
    assert error["cause_type"] is None
    assert error["context_type"] is None
    assert TOKEN not in json.dumps(error)
    assert env.target.view.applied() == []


# --------------------------------------------------------------------------- #
# E. TLS failures                                                              #
# --------------------------------------------------------------------------- #

_TLS_FAILURES = {
    "expired": "certificate has expired",
    "untrusted": "unable to get local issuer certificate",
    "wrong_host": "mismatch, certificate is not valid for '127.0.0.1'",
}


@pytest.mark.parametrize("listener", sorted(_TLS_FAILURES))
def test_e_tls_failure_fails_closed_before_target_handler(env: FaultEnv, listener: str) -> None:
    store = env.provision()
    commit_effect(store, commit_id="e-tls", nonce_byte=140)

    rejected = env.worker(store, "bad-tls", endpoint=env.target.url(listener))
    assert rejected.returncode == 0, rejected.stderr
    [error] = rejected.errors
    assert error is not None and error["type"] == "ExecutionGatewayError", error
    assert "CERTIFICATE_VERIFY_FAILED" in error["message"]
    assert _TLS_FAILURES[listener] in error["message"]
    assert env.target.view.requests() == []  # never reached the application handler
    assert env.target.view.applied() == []
    effect = env.effect()
    assert (effect["state"], effect["attempt_count"]) == ("IN_FLIGHT", 1)
    assert _only_outbox_state(store) == "PENDING"

    recovered = env.worker(store, "good-tls", endpoint=env.target.url("good"))
    _assert_clean_run(recovered)
    _assert_applied_exactly_once(
        env, key=effect["idempotency_key"], applied_token=2, final_token=2, attempts=2
    )


def test_e_default_opener_has_no_tls_trust_parameter_and_rejects_private_ca(
    env: FaultEnv,
) -> None:
    store = env.provision()
    commit_effect(store, commit_id="e-default", nonce_byte=141)

    run = env.worker(store, "default-opener", endpoint=env.target.url("good"), trusted_ca=False)
    assert run.returncode == 0, run.stderr
    [error] = run.errors
    assert error is not None and error["type"] == "ExecutionGatewayError", error
    assert "CERTIFICATE_VERIFY_FAILED" in error["message"]
    assert env.target.view.requests() == []
    assert env.effect()["state"] == "IN_FLIGHT"


# --------------------------------------------------------------------------- #
# F. Cross-tenant replay                                                       #
# --------------------------------------------------------------------------- #


def _tenants(env: FaultEnv) -> tuple[StoreHandle, Any, StoreHandle, Any]:
    tenant_1 = env.provision("store-1")
    tenant_2 = env.provision("store-2")
    _r1, event_1 = commit_effect(tenant_1, commit_id="shared-commit", nonce_byte=150)
    _r2, event_2 = commit_effect(tenant_2, commit_id="shared-commit", nonce_byte=150)
    return tenant_1, event_1, tenant_2, event_2


def _key(handle: StoreHandle, event: Any) -> str:
    return derive_effect_idempotency_key(
        handle.store_id, event.event_id, sha256_digest(event.payload), "shared-commit"
    )


def test_f_cross_tenant_event_is_denied_and_tenants_never_share_an_effect(
    env: FaultEnv,
) -> None:
    tenant_1, event_1, tenant_2, event_2 = _tenants(env)
    key_1, key_2 = _key(tenant_1, event_1), _key(tenant_2, event_2)
    assert key_1 != key_2  # authority_store_id is framed into the key

    # Tenant-1's persisted event replayed into tenant-2's gateway.
    crossed = env.worker(tenant_2, "cross-tenant", inject=event_1)
    [error] = crossed.errors
    assert error is not None and error["type"] == "ExecutionGatewayError", error
    assert error["failure_code"] == "AUTHORITY_FROM_OUTBOX_DENIED"
    assert env.target.view.requests() == []
    assert ledger_snapshot(env.ledger_path)["effects"] == []

    # Each tenant's own event applies once, under its own key, on a shared ledger.
    _assert_clean_run(env.worker(tenant_1, "tenant-1"))
    _assert_clean_run(env.worker(tenant_2, "tenant-2"))
    applied = env.target.view.applied()
    assert sorted((r["authority_store_id"], r["idempotency_key"]) for r in applied) == sorted(
        [("store-1", key_1), ("store-2", key_2)]
    )
    snapshot = ledger_snapshot(env.ledger_path)
    assert {(e["idempotency_key"], e["state"]) for e in snapshot["effects"]} == {
        (key_1, "APPLIED"),
        (key_2, "APPLIED"),
    }
    assert [w["authority_store_id"] for w in snapshot["watermarks"]] == ["store-1", "store-2"]

    # Re-delivering tenant-1's event is a ledger-local replay: no HTTP request.
    again = env.worker(tenant_1, "tenant-1-again", inject=event_1)
    _assert_clean_run(again)
    assert [o["disposition"] for o in again.outcomes] == ["replayed"]
    assert len(env.target.view.requests()) == 2
    assert len(env.target.view.applied()) == 2


def test_f_target_rejects_same_key_under_another_tenant(env: FaultEnv) -> None:
    tenant_1, event_1, _tenant_2, _event_2 = _tenants(env)
    _assert_clean_run(env.worker(tenant_1, "tenant-1"))
    [logged] = env.target.view.requests()
    body = json.loads(logged["body"])
    forged = dict(body, authority_store_id="store-2", fencing_token=body["fencing_token"] + 1)
    context = ssl.create_default_context(cafile=str(env.pki.ca_cert))
    request = urllib.request.Request(
        env.target.url("good"),
        data=json.dumps(forged, sort_keys=True).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
            "Idempotency-Key": body["idempotency_key"],
            "X-Fencing-Token": str(forged["fencing_token"]),
        },
    )
    hermetic = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    with pytest.raises(urllib.error.HTTPError) as caught:
        hermetic.open(request, timeout=5.0)
    assert caught.value.code == 409
    assert json.loads(caught.value.read())["error"] == "idempotency_payload_mismatch"
    assert len(env.target.view.applied()) == 1
    assert env.target.view.key_state(body["idempotency_key"])["authority_store_id"] == "store-1"


def test_f_gateway_ledger_rejects_key_collision_with_other_tenant_identity(
    env: FaultEnv,
) -> None:
    tenant_1, event_1, _tenant_2, event_2 = _tenants(env)
    key_1 = _key(tenant_1, event_1)
    # Seed tenant-2's effect identity under tenant-1's key (only reachable via
    # a key collision or ledger corruption: gateway_effects has no store column).
    ledger = SQLiteExecutionLedger(env.ledger_path)
    ledger.begin_attempt(
        idempotency_key=key_1,
        event_id=event_2.event_id,
        commit_id="shared-commit",
        certificate_digest=sha256_digest(event_2.payload),
        workflow_id="workflow-1",
        node_id="node-1",
        now_ms=BASE_NOW_MS,
    )

    run = env.worker(tenant_1, "collided")
    [error] = run.errors
    assert error is not None and error["type"] == "ExecutionGatewayError", error
    assert "ledger idempotency conflict with existing record IDENTITY" in error["message"]
    assert env.target.view.requests() == []
    assert _only_outbox_state(tenant_1) == "PENDING"

    with pytest.raises(Exception, match="idempotency key collision with mismatched effect"):
        ledger.begin_attempt(
            idempotency_key=key_1,
            event_id=event_1.event_id,
            commit_id="shared-commit",
            certificate_digest=sha256_digest(event_1.payload),
            workflow_id="workflow-1",
            node_id="node-1",
            now_ms=BASE_NOW_MS,
        )
    assert [e["state"] for e in env.effects()] == ["IN_FLIGHT"]


# --------------------------------------------------------------------------- #
# G. Retry storm on 429 / non-standard 5xx / unexpected 2xx                     #
# --------------------------------------------------------------------------- #

_STORM = (429, 500, 503, 529, 599, 202) * 2


def test_g_retry_storm_has_no_amplification_and_applies_once_on_recovery(
    env: FaultEnv,
) -> None:
    store = env.provision()
    commit_effect(store, commit_id="g-storm", nonce_byte=160)
    env.target.view.push_faults(*[("status", code) for code in _STORM])

    storm = env.worker(store, "storm", cycles=len(_STORM))
    assert storm.returncode == 0, storm.stderr
    assert len(storm.errors) == len(_STORM)
    for code, error in zip(_STORM, storm.errors, strict=True):
        assert error is not None and error["type"] == "ExecutionGatewayError", error
        expected = (
            f"unexpected external target status code: {code}"
            if code == 202
            else f"external target HTTP error ({code})"
        )
        assert expected in error["message"]
    requests = env.target.view.requests()
    # Exactly one outbound request per delivery attempt, at proxy and target.
    assert len(env.proxy.connections) == len(_STORM)
    assert [(r["status_code"], r["reason"]) for r in requests] == [
        (code, "injected_status") for code in _STORM
    ]
    assert len({r["idempotency_key"] for r in requests}) == 1
    assert [r["fencing_token"] for r in requests] == list(range(1, len(_STORM) + 1))
    assert env.target.view.applied() == []
    effect = env.effect()
    assert (effect["state"], effect["attempt_count"], effect["fencing_token"]) == (
        "IN_FLIGHT",
        len(_STORM),
        len(_STORM),
    )
    assert _only_outbox_state(store) == "PENDING"

    recovered = env.worker(store, "recovered")
    _assert_clean_run(recovered)
    final = len(_STORM) + 1
    assert env.trace()[-1] == (201, "applied", final)
    assert len(env.proxy.connections) == final
    _assert_applied_exactly_once(
        env, key=effect["idempotency_key"], applied_token=final, final_token=final, attempts=final
    )


def test_g_unexpected_202_after_apply_is_replayed_not_reapplied(env: FaultEnv) -> None:
    store = env.provision()
    commit_effect(store, commit_id="g-202", nonce_byte=161)
    env.target.view.push_faults(("applied_status", 202))

    first = env.worker(store, "accepted-202")
    [error] = first.errors
    assert error is not None and "unexpected external target status code: 202" in error["message"]
    assert env.trace() == [(202, "applied_then_status_202", 1)]
    assert env.effect()["state"] == "IN_FLIGHT"

    second = env.worker(store, "redelivery")
    _assert_clean_run(second)
    assert [o["disposition"] for o in second.outcomes] == ["replayed"]
    _assert_applied_exactly_once(
        env, key=env.effect()["idempotency_key"], applied_token=1, final_token=2, attempts=2
    )


# --------------------------------------------------------------------------- #
# H. Key rotation / cross-generation verification                              #
# --------------------------------------------------------------------------- #

_GENERATION_MISMATCH = {
    # gateway trust (commit, status) for a generation-1 certificate -> failure code
    "commit_gen2_new_key_id": (("gen2", "gen1"), "UNKNOWN_KEY"),
    "commit_gen2_same_key_id": (("gen2-same-key-id", "gen1"), "INVALID_COMMIT_SEAL"),
    "status_gen2": (("gen1", "gen2"), "UNKNOWN_KEY"),
}


@pytest.mark.parametrize("case", sorted(_GENERATION_MISMATCH))
def test_h_gen1_certificate_against_gen2_gateway_trust_fails_closed(
    env: FaultEnv, case: str
) -> None:
    (commit_gen, status_gen), code = _GENERATION_MISMATCH[case]
    store = env.provision()
    commit_effect(store, commit_id="h-gen1", nonce_byte=170)
    # A second, independent commit queued behind the first.
    commit_effect(store, commit_id="h-gen1-behind", nonce_byte=174, node_id="root")

    rotated = env.worker(store, "gen2-trust", commit_trust=commit_gen, status_trust=status_gen)
    [error] = rotated.errors
    assert error is not None and error["type"] == "ExecutionGatewayError", error
    assert error["failure_code"] == code
    # Raised, not BLOCKED: no ledger row, the head stays redeliverable and the
    # valid commit behind it is stalled (head-of-line) until trust is fixed.
    assert ledger_snapshot(env.ledger_path)["effects"] == []
    assert env.target.view.requests() == []
    assert [state for _e, _k, state in outbox_states(store.path)] == ["PENDING", "PENDING"]

    restored = env.worker(store, "gen1-trust")
    _assert_clean_run(restored)
    assert [o["disposition"] for o in restored.outcomes] == ["applied", "applied"]
    assert [state for _e, _k, state in outbox_states(store.path)] == ["DELIVERED", "DELIVERED"]


def test_h_gen2_certificate_against_gen1_gateway_trust_fails_closed(env: FaultEnv) -> None:
    store = env.provision(generation="gen2")
    commit_effect(store, commit_id="h-gen2", nonce_byte=171)

    stale = env.worker(store, "gen1-trust", commit_trust="gen1", status_trust="gen1")
    [error] = stale.errors
    assert error is not None and error["failure_code"] == "UNKNOWN_KEY", error
    assert env.target.view.requests() == []
    assert _only_outbox_state(store) == "PENDING"

    current = env.worker(store, "gen2-trust")
    _assert_clean_run(current)
    assert [o["disposition"] for o in current.outcomes] == ["applied"]


def test_h_no_in_place_rotation_and_gen1_history_needs_gen1_trust(tmp_path: Path) -> None:
    gen1 = provision_store(tmp_path / "gen1.sqlite")
    result, _event = commit_effect(gen1, commit_id="h-history", nonce_byte=172)
    envelope = result.certificate_envelope_bytes
    assert envelope is not None
    gen2 = provision_store(tmp_path / "gen2.sqlite", generation="gen2")
    commit_effect(gen2, commit_id="h-history-gen2", nonce_byte=173)

    # A provisioned store cannot be reopened under rotated COMMIT/STATUS keys.
    from constitutional_swarm.apcc.ports import AuthorityRuntime
    from tests.apcc_gateway_fault_harness import FixedClock

    with pytest.raises(ValueError, match="configuration does not match provisioned store"):
        SQLiteAuthorityStore.open(
            gen1.path,
            config=authority_config("store-1", "gen2"),
            runtime=AuthorityRuntime(key_provider("gen2"), FixedClock(BASE_NOW_MS), None),
        )
    # One ScopedTrust cannot hold both generations for the same role and scope.
    with pytest.raises(ValueError, match="duplicate APCC trust role/scope binding"):
        ScopedTrust(
            (
                *gateway_trust("store-1").bindings,
                authority_config("store-1", "gen2").commit_trust,
            )
        )

    # After "rotation", generation-1 history still verifies with retained gen-1 trust ...
    gen1_trust = gateway_trust("store-1")
    historical = verify_historical(envelope, trust=gen1_trust)
    assert historical.ok and historical.certificate_digest == result.certificate_digest
    status = gen1.store.current_status(result.certificate_digest, "AAAAAAAAAAAAAAAAAAAAAA")
    current = verify_current(
        envelope,
        trust=gen1_trust,
        authority_status=status,
        request_nonce="AAAAAAAAAAAAAAAAAAAAAA",
        now_ms=str(BASE_NOW_MS),
        highest_trust_log_sequence="0",
        highest_trust_log_head=sha256_digest(b"APCC-1/trust-log/genesis"),
        maximum_staleness_ms="5000",
    )
    assert current.ok, current.code
    # ... and never with generation-2 trust (no historical key set exists).
    rotated = verify_historical(envelope, trust=gateway_trust("store-1", commit_generation="gen2"))
    assert not rotated.ok and rotated.code.value == "UNKNOWN_KEY"
