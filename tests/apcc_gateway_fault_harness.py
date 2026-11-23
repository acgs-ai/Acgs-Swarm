"""Parent-side harness for the APCC execution-gateway fault-injection suite.

Everything here runs inside the pytest process except the two subprocess entry
points in ``tests/apcc_gateway_fault_procs.py`` (HTTPS target and gateway
worker), which import this module for the shared configuration helpers.

Pieces:

* ``TestPKI``: a throwaway CA, a rogue CA, and leaf certificates (valid,
  expired, wrong host, untrusted issuer) generated with ``cryptography``.
* ``authority_config`` / ``key_provider`` / ``gateway_trust``: generation-1
  and generation-2 APCC trust material. Generation 1 is the fixture set used by
  every existing APCC test; generation 2 replaces the COMMIT and STATUS keys.
* ``FaultProxy``: a real TCP proxy thread between gateway and target. It never
  terminates TLS. The target pins TLS 1.2 without session tickets, so the proxy
  can tell handshake/CCS/alert records (content types 20-22) from encrypted
  HTTP bytes (content type 23) by reading only the 5-byte record headers.
* ``ProcessHandle``: subprocess lifecycle in a dedicated process group that is
  SIGKILLed on teardown.
* ``TargetView`` / ``ledger_snapshot`` / ``outbox_states``: read-only views of
  the three on-disk databases used for assertions.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASE_NOW_MS = 1_760_000_001_000
# Outbox leases are 30 s (sqlite_store.recover_outbox). A worker SIGKILLed while
# holding a lease leaves the row CLAIMED; recovery must run with a later clock.
LEASE_EXPIRED_NOW_MS = BASE_NOW_MS + 31_000

TARGET_TOKEN_ENV = "APCC_FAULT_TARGET_TOKEN"
WORKER_TOKEN_ENV = "APCC_FAULT_BEARER_TOKEN"

# Generation-2 signing seeds (generation 1 uses tests.test_apcc_verifier.SEEDS).
GEN2_COMMIT_SEED = bytes([0xA2]) * 32
GEN2_STATUS_SEED = bytes([0xB2]) * 32

_TLS_HANDSHAKE_TYPES = frozenset({20, 21, 22})
_TLS_APPLICATION_DATA = 23
_WAIT_STEP_S = 0.02


# --------------------------------------------------------------------------- #
# Clock / config / trust generations                                          #
# --------------------------------------------------------------------------- #


class FixedClock:
    """Authority + gateway clock pinned to one instant for a whole process."""

    def __init__(self, now_ms: int) -> None:
        self._now_ms = int(now_ms)

    def now_ms(self) -> int:
        return self._now_ms


def _raw_public_key(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _commit_binding(store_id: str, generation: str) -> Any:
    from constitutional_swarm.apcc.verifier import TrustBinding, TrustRole
    from tests.test_apcc_sqlite import _config

    gen1 = _config(store_id).commit_trust
    if generation == "gen1":
        return gen1
    if generation == "gen2":
        return TrustBinding(
            TrustRole.COMMIT, (store_id,), "commit-key-gen2", _raw_public_key(GEN2_COMMIT_SEED)
        )
    if generation == "gen2-same-key-id":
        # New key material published under the unchanged generation-1 key_id.
        return replace(gen1, public_key=_raw_public_key(GEN2_COMMIT_SEED))
    raise ValueError(f"unknown commit generation {generation!r}")


def _status_binding(store_id: str, generation: str) -> Any:
    from constitutional_swarm.apcc.verifier import TrustBinding, TrustRole
    from tests.test_apcc_sqlite import _config

    gen1 = _config(store_id).status_trust
    if generation == "gen1":
        return gen1
    if generation == "gen2":
        return TrustBinding(
            TrustRole.STATUS, (store_id,), "status-key-gen2", _raw_public_key(GEN2_STATUS_SEED)
        )
    raise ValueError(f"unknown status generation {generation!r}")


def authority_config(store_id: str = "store-1", generation: str = "gen1") -> Any:
    """APCC authority config whose COMMIT/STATUS keys belong to ``generation``."""
    from tests.test_apcc_sqlite import _config

    return replace(
        _config(store_id),
        commit_trust=_commit_binding(store_id, generation),
        status_trust=_status_binding(store_id, generation),
    )


def key_provider(generation: str = "gen1") -> Any:
    from tests.test_apcc_sqlite import _KeyProvider

    if generation == "gen1":
        return _KeyProvider()
    if generation == "gen2":
        return _KeyProvider(commit_seed=GEN2_COMMIT_SEED, status_seed=GEN2_STATUS_SEED)
    raise ValueError(f"unknown key generation {generation!r}")


def gateway_trust(
    store_id: str, *, commit_generation: str = "gen1", status_generation: str = "gen1"
) -> Any:
    """Gateway-side ScopedTrust: gen-1 producer/policy/registry + chosen COMMIT/STATUS."""
    from constitutional_swarm.apcc.verifier import ScopedTrust
    from tests.test_apcc_sqlite import _config

    base = _config(store_id)
    return ScopedTrust(
        (
            *base.producer_trust,
            *base.policy_trust,
            *base.registry_trust,
            _commit_binding(store_id, commit_generation),
            _status_binding(store_id, status_generation),
        )
    )


class _ParentNeverDrainsSink:
    """The pytest process only provisions and commits; workers drain the outbox."""

    def deliver(self, event_id: str, payload: bytes) -> None:
        raise AssertionError(f"parent process must not drain outbox event {event_id}")


@dataclass(frozen=True)
class StoreHandle:
    path: Path
    store_id: str
    generation: str
    store: Any


def provision_store(
    path: Path, *, store_id: str = "store-1", generation: str = "gen1"
) -> StoreHandle:
    from constitutional_swarm.apcc.ports import AuthorityRuntime
    from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore
    from tests.test_apcc_sqlite import _initial_contexts

    config = authority_config(store_id, generation)
    runtime = AuthorityRuntime(
        key_provider(generation), FixedClock(BASE_NOW_MS), _ParentNeverDrainsSink()
    )
    SQLiteAuthorityStore.provision(
        path, config=config, initial_contexts=_initial_contexts(), runtime=runtime
    )
    store = SQLiteAuthorityStore.open(path, config=config, runtime=runtime)
    return StoreHandle(path=path, store_id=store_id, generation=generation, store=store)


def commit_effect(
    handle: StoreHandle, *, commit_id: str, nonce_byte: int, node_id: str = "node-1"
) -> tuple[Any, Any]:
    """Commit one certificate; return (CommitResult, PersistedOutboxEvent)."""
    from constitutional_swarm.apcc.model import RequestOutcome
    from tests.test_apcc_sqlite import _advance_candidate, _request

    request = _request(commit_id=commit_id, nonce_byte=nonce_byte, node_id=node_id)
    _advance_candidate(handle.store, request)
    result = handle.store.atomic_commit(request)
    assert result.decision.outcome is RequestOutcome.COMMITTED, result.decision
    return result, handle.store.get_outbox_event(commit_id)


# --------------------------------------------------------------------------- #
# PKI                                                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LeafFiles:
    cert: Path
    key: Path


@dataclass(frozen=True)
class TestPKI:
    __test__ = False  # not a pytest test class

    ca_cert: Path
    rogue_ca_cert: Path
    leaves: Mapping[str, LeafFiles]

    @classmethod
    def generate(cls, directory: Path) -> TestPKI:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        directory.mkdir(parents=True, exist_ok=True)
        now = _dt.datetime.now(_dt.timezone.utc)

        def _name(common_name: str) -> x509.Name:
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

        def _ca(common_name: str) -> tuple[Any, Any]:
            key = ec.generate_private_key(ec.SECP256R1())
            ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
            cert = (
                x509.CertificateBuilder()
                .subject_name(_name(common_name))
                .issuer_name(_name(common_name))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(days=30))
                .not_valid_after(now + _dt.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(ski, critical=False)
                .sign(key, hashes.SHA256())
            )
            return key, cert

        def _leaf(
            issuer: tuple[Any, Any],
            *,
            san: x509.GeneralName,
            not_before: _dt.datetime,
            not_after: _dt.datetime,
        ) -> tuple[Any, Any]:
            issuer_key, issuer_cert = issuer
            key = ec.generate_private_key(ec.SECP256R1())
            cert = (
                x509.CertificateBuilder()
                .subject_name(_name("apcc-fault-target"))
                .issuer_name(issuer_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
                )
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                    critical=False,
                )
                .sign(issuer_key, hashes.SHA256())
            )
            return key, cert

        def _write_cert(path: Path, cert: Any) -> Path:
            path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            return path

        def _write_key(path: Path, key: Any) -> Path:
            path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            return path

        trusted = _ca("apcc-fault-test-ca")
        rogue = _ca("apcc-fault-rogue-ca")
        loopback = x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        valid = (now - _dt.timedelta(days=1), now + _dt.timedelta(days=1))
        profiles = {
            "good": (trusted, loopback, valid),
            "expired": (
                trusted,
                loopback,
                (now - _dt.timedelta(days=10), now - _dt.timedelta(days=1)),
            ),
            "wrong_host": (trusted, x509.DNSName("not-the-target.invalid"), valid),
            "untrusted": (rogue, loopback, valid),
        }
        leaves: dict[str, LeafFiles] = {}
        for name, (issuer, san, (not_before, not_after)) in profiles.items():
            key, cert = _leaf(issuer, san=san, not_before=not_before, not_after=not_after)
            leaves[name] = LeafFiles(
                cert=_write_cert(directory / f"{name}.crt", cert),
                key=_write_key(directory / f"{name}.key", key),
            )
        return cls(
            ca_cert=_write_cert(directory / "ca.crt", trusted[1]),
            rogue_ca_cert=_write_cert(directory / "rogue-ca.crt", rogue[1]),
            leaves=leaves,
        )


# --------------------------------------------------------------------------- #
# Subprocess lifecycle                                                         #
# --------------------------------------------------------------------------- #


def child_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        # Deterministic TLS trust: only the CA file the worker is given counts.
        if key not in {"SSL_CERT_FILE", "SSL_CERT_DIR", TARGET_TOKEN_ENV, WORKER_TOKEN_ENV}
    }
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "src")])
    env["PYTHONUNBUFFERED"] = "1"
    if extra:
        env.update(extra)
    return env


class ProcessHandle:
    """A child running ``python -m tests.apcc_gateway_fault_procs`` in its own group."""

    def __init__(
        self, role: str, spec: Mapping[str, Any], workdir: Path, env_extra: Mapping[str, str]
    ) -> None:
        workdir.mkdir(parents=True, exist_ok=True)
        self.spec_path = workdir / "spec.json"
        self.spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
        self.stdout_path = workdir / "stdout.log"
        self.stderr_path = workdir / "stderr.log"
        with self.stdout_path.open("wb") as out, self.stderr_path.open("wb") as err:
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "tests.apcc_gateway_fault_procs", role, str(self.spec_path)],
                cwd=ROOT,
                env=child_env(env_extra),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )

    def wait(self, timeout_s: float) -> int:
        try:
            return self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.kill()
            raise

    def kill(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - kernel did not reap
            pass

    def terminate(self, timeout_s: float = 5.0) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=timeout_s)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        self.kill()

    def stderr_text(self) -> str:
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")


def wait_for(predicate: Any, *, timeout_s: float, what: str) -> Any:
    """Poll a real condition with a bounded deadline (no fixed sleeps)."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s}s waiting for {what}")
        time.sleep(_WAIT_STEP_S)


@dataclass
class WorkerRun:
    returncode: int
    result: dict[str, Any] | None
    marker: dict[str, Any] | None
    stderr: str
    workdir: Path

    @property
    def errors(self) -> list[dict[str, Any] | None]:
        assert self.result is not None, self.stderr
        return [cycle["error"] for cycle in self.result["cycles"]]

    @property
    def outcomes(self) -> list[dict[str, Any]]:
        assert self.result is not None, self.stderr
        return list(self.result["outcomes"])

    def all_text(self) -> str:
        parts = [self.stderr]
        for path in (self.workdir / "result.json", self.workdir / "marker.json"):
            if path.exists():
                parts.append(path.read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def start_worker(spec: Mapping[str, Any], workdir: Path, *, bearer_token: str) -> ProcessHandle:
    full = dict(spec)
    full["result_path"] = str(workdir / "result.json")
    full["marker_path"] = str(workdir / "marker.json")
    return ProcessHandle("worker", full, workdir, {WORKER_TOKEN_ENV: bearer_token})


def collect_worker(handle: ProcessHandle, workdir: Path, *, timeout_s: float) -> WorkerRun:
    try:
        code = handle.wait(timeout_s)
    finally:
        handle.kill()
    return WorkerRun(
        returncode=code,
        result=_read_json(workdir / "result.json"),
        marker=_read_json(workdir / "marker.json"),
        stderr=handle.stderr_text(),
        workdir=workdir,
    )


def run_worker(
    spec: Mapping[str, Any], workdir: Path, *, bearer_token: str, timeout_s: float = 60.0
) -> WorkerRun:
    return collect_worker(
        start_worker(spec, workdir, bearer_token=bearer_token), workdir, timeout_s=timeout_s
    )


@dataclass
class TargetProcess:
    handle: ProcessHandle
    ports: Mapping[str, int]
    view: TargetView
    token: str

    def url(self, listener: str = "good") -> str:
        return f"https://127.0.0.1:{self.ports[listener]}/execute"


@contextmanager
def running_target(
    workdir: Path, pki: TestPKI, *, token: str, startup_timeout_s: float = 20.0
) -> Iterator[TargetProcess]:
    db_path = workdir / "target.sqlite"
    ready_path = workdir / "ready.json"
    spec = {
        "db_path": str(db_path),
        "ready_path": str(ready_path),
        "listeners": {
            name: {"cert": str(files.cert), "key": str(files.key)}
            for name, files in pki.leaves.items()
        },
    }
    handle = ProcessHandle("target", spec, workdir, {TARGET_TOKEN_ENV: token})
    try:

        def _ready() -> dict[str, Any] | None:
            if handle.proc.poll() is not None:
                raise RuntimeError(f"target exited early: {handle.stderr_text()}")
            return _read_json(ready_path)

        ready = wait_for(_ready, timeout_s=startup_timeout_s, what="target ready file")
        yield TargetProcess(
            handle=handle,
            ports={k: int(v) for k, v in ready["ports"].items()},
            view=TargetView(db_path),
            token=token,
        )
    finally:
        handle.terminate()


# --------------------------------------------------------------------------- #
# On-disk views                                                                #
# --------------------------------------------------------------------------- #


def _ro_connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    conn = _ro_connect(path)
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


@dataclass(frozen=True)
class TargetView:
    db_path: Path

    def applied(self) -> list[dict[str, Any]]:
        """Append-only application log: one row per real side effect."""
        return _rows(self.db_path, "SELECT * FROM applied_effects ORDER BY seq")

    def requests(self) -> list[dict[str, Any]]:
        """Every request that reached the application handler, in arrival order."""
        return _rows(self.db_path, "SELECT * FROM request_log ORDER BY seq")

    def key_state(self, idempotency_key: str) -> dict[str, Any] | None:
        rows = _rows(
            self.db_path, "SELECT * FROM key_index WHERE idempotency_key = ?", (idempotency_key,)
        )
        return rows[0] if rows else None

    def push_faults(self, *faults: tuple[str, int]) -> None:
        """Queue (kind, status) faults; the handler pops one per authorized request."""
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                "INSERT INTO fault_queue(kind, status_code) VALUES (?, ?)", list(faults)
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

    def pending_faults(self) -> int:
        return int(_rows(self.db_path, "SELECT COUNT(*) AS n FROM fault_queue")[0]["n"])


def ledger_snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "effects": [], "next_fencing_token": None, "watermarks": []}
    return {
        "exists": True,
        "effects": _rows(path, "SELECT * FROM gateway_effects ORDER BY idempotency_key"),
        "next_fencing_token": _rows(path, "SELECT next_fencing_token FROM gateway_sequence")[0][
            "next_fencing_token"
        ],
        "watermarks": _rows(path, "SELECT * FROM gateway_watermarks ORDER BY authority_store_id"),
    }


def outbox_states(path: Path) -> list[tuple[str, str, str]]:
    return [
        (row["event_id"], row["event_kind"], row["state"])
        for row in _rows(
            path, "SELECT event_id, event_kind, state FROM apcc_outbox ORDER BY event_sequence"
        )
    ]


# --------------------------------------------------------------------------- #
# Byte-level fault proxy                                                       #
# --------------------------------------------------------------------------- #

PROXY_MODES = frozenset(
    {
        "pass",
        # Forward the request; when the upstream's first encrypted record (the
        # HTTP response) arrives, reset the client with SO_LINGER=0 instead.
        "drop_before_response",
        # Hold the upstream's response until the client gives up and closes.
        "delay_past_client_timeout",
        # Forward the first encrypted response record (status line + headers),
        # then close the client before the second record (the JSON body).
        "close_mid_response",
        # Hold the client's encrypted request until ``release_held`` is called.
        "hold_request",
    }
)


class _TLSRecordReader:
    """Splits a TLS byte stream into whole records using only the 5-byte header."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self._buffer.extend(data)
        records: list[tuple[int, bytes]] = []
        while len(self._buffer) >= 5:
            content_type = self._buffer[0]
            (length,) = struct.unpack("!H", bytes(self._buffer[3:5]))
            if len(self._buffer) < 5 + length:
                break
            records.append((content_type, bytes(self._buffer[: 5 + length])))
            del self._buffer[: 5 + length]
        return records


@dataclass
class ProxyConnection:
    mode: str
    client_app_records: int = 0
    upstream_app_records: int = 0
    fault_fired: bool = False
    upstream_connected: bool = False
    events: list[str] = field(default_factory=list)


class FaultProxy:
    """Real-socket TCP proxy in a thread; TLS stays end-to-end gateway<->target."""

    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self._lock = threading.Lock()
        self._modes: deque[str] = deque()
        self.connections: list[ProxyConnection] = []
        self._stop = threading.Event()
        self._release = threading.Event()
        self.holding = threading.Event()
        self._threads: list[threading.Thread] = []
        self._listener: socket.socket | None = None
        self.port = 0
        self._open_listener(0)
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    # ---- control --------------------------------------------------------
    def arm(self, *modes: str) -> None:
        """Queue per-connection modes; unqueued connections use ``pass``."""
        for mode in modes:
            if mode not in PROXY_MODES:
                raise ValueError(mode)
        with self._lock:
            self._modes.extend(modes)

    def refuse(self) -> None:
        """Close the listening socket: new connects get ECONNREFUSED."""
        with self._lock:
            if self._listener is not None:
                self._listener.close()
                self._listener = None

    def resume(self) -> None:
        with self._lock:
            if self._listener is None:
                self._open_listener(self.port)

    def release_held(self) -> None:
        self._release.set()

    def close(self) -> None:
        self._stop.set()
        self._release.set()
        self.refuse()
        self._accept_thread.join(timeout=5)
        for thread in list(self._threads):
            thread.join(timeout=5)

    # ---- internals ------------------------------------------------------
    def _open_listener(self, port: int) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(16)
        self._listener = listener
        self.port = listener.getsockname()[1]

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                self._stop.wait(_WAIT_STEP_S)
                continue
            try:
                ready, _, _ = select.select([listener], [], [], 0.1)
                if not ready:
                    continue
                client, _addr = listener.accept()
            except (OSError, ValueError):
                continue  # listener closed by refuse()/close()
            with self._lock:
                mode = self._modes.popleft() if self._modes else "pass"
                record = ProxyConnection(mode=mode)
                self.connections.append(record)
            thread = threading.Thread(target=self._serve, args=(client, record), daemon=True)
            self._threads.append(thread)
            thread.start()

    @staticmethod
    def _reset(sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        sock.close()

    def _wait_client_gone(self, client: socket.socket, deadline_s: float) -> bool:
        end = time.monotonic() + deadline_s
        while time.monotonic() < end and not self._stop.is_set():
            ready, _, _ = select.select([client], [], [], 0.1)
            if ready:
                try:
                    if client.recv(65536) == b"":
                        return True
                except OSError:
                    return True
        return False

    def _serve(self, client: socket.socket, conn: ProxyConnection) -> None:
        try:
            upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=10)
        except OSError:
            conn.events.append("upstream_connect_failed")
            self._reset(client)
            return
        conn.upstream_connected = True
        upstream.settimeout(None)
        c2s, s2c = _TLSRecordReader(), _TLSRecordReader()
        held: list[bytes] = []
        try:
            while not self._stop.is_set():
                if held and self._release.is_set():
                    conn.events.append("released_held_request")
                    for chunk in held:
                        upstream.sendall(chunk)
                    held.clear()
                ready, _, _ = select.select([client, upstream], [], [], 0.05)
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        conn.events.append("client_eof" if sock is client else "upstream_eof")
                        return
                    if sock is client:
                        for content_type, record in c2s.feed(data):
                            if content_type == _TLS_APPLICATION_DATA:
                                conn.client_app_records += 1
                                if conn.mode == "hold_request" and not self._release.is_set():
                                    held.append(record)
                                    conn.fault_fired = True
                                    self.holding.set()
                                    continue
                            upstream.sendall(record)
                        continue
                    for content_type, record in s2c.feed(data):
                        if content_type != _TLS_APPLICATION_DATA:
                            client.sendall(record)
                            continue
                        conn.upstream_app_records += 1
                        if conn.mode == "drop_before_response":
                            conn.fault_fired = True
                            conn.events.append("reset_client_before_response")
                            self._reset(client)
                            return
                        if conn.mode == "delay_past_client_timeout":
                            conn.fault_fired = True
                            gone = self._wait_client_gone(client, 30.0)
                            conn.events.append("client_gave_up" if gone else "client_never_gave_up")
                            try:
                                client.sendall(record)
                            except OSError:
                                conn.events.append("late_response_undeliverable")
                            return
                        if conn.mode == "close_mid_response" and conn.upstream_app_records == 2:
                            conn.fault_fired = True
                            conn.events.append("closed_client_mid_response")
                            client.shutdown(socket.SHUT_RDWR)
                            return
                        client.sendall(record)
        except OSError as error:
            conn.events.append(f"socket_error:{type(error).__name__}")
        finally:
            for sock in (client, upstream):
                try:
                    sock.close()
                except OSError:
                    pass
