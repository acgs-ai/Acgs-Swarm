"""
WebSocket Gossip Transport — MCFS Phase 5.

Replaces in-process MerkleCRDT.merge() with a real network layer.
Each SwarmNode runs a WebSocket server and gossips DAGNode batches
to random peers. Integration point: MerkleCRDT.merge_nodes() already
accepts raw DAGNode lists — this module wires it to the network.

Architecture:
    GossipPeerRegistry  — registry of known peer addresses (host:port)
    GossipServer        — WebSocket server; receives batches, calls merge_nodes()
    GossipClient        — sends DAGNode batches to a single peer
    SwarmNode           — combines MerkleCRDT + server + periodic gossip loop

Wire format (JSON):
    Each message is a JSON array of node objects:
    [
        {
            "cid": "<sha256-hex>",
            "agent_id": "...",
            "payload": "...",
            "payload_type": "artifact",
            "parent_cids": ["..."],
            "bodes_passed": false,
            "constitutional_hash": ""
        },
        ...
    ]

Optional dependency: websockets>=12.0
Install: pip install 'constitutional-swarm[transport]'

    from constitutional_swarm.gossip_protocol import SwarmNode

    async with SwarmNode("agent-0", host="127.0.0.1", port=8765) as node:
        node.registry.add("127.0.0.1", 8766)
        node.crdt.append(payload="hello from agent-0")
        await node.gossip_round(n_peers=2)
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import math
import random
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from constitutional_swarm.merkle_crdt import (
    AncestryScanLimitExceeded,
    DAGNode,
    MerkleCRDT,
    normalize_json_value,
    thaw_json_value,
)

log = logging.getLogger(__name__)

# Maximum bytes allowed in a single node's metadata field.
# Prevents memory exhaustion via oversized gossip payloads (DoS defence).
MAX_METADATA_BYTES = 65_536  # 64 KiB
MAX_BATCH_BYTES: int = 4 * 1024 * 1024
MAX_BATCH_NODES: int = 1000
MAX_JSON_DEPTH = 32
MAX_PARENT_CIDS = 4096
MAX_FRONTIER_CIDS = 256
MAX_FETCH_CIDS = 1024
MAX_PROTOCOL_ROUNDS = 256
MAX_FRONTIER_PAGES = MAX_PROTOCOL_ROUNDS * 4
MAX_SESSION_FRAMES = MAX_PROTOCOL_ROUNDS * 8
MAX_ANCESTRY_SCAN = 100_000
MAX_FIELD_BYTES = 1 * 1024 * 1024
MAX_SESSION_NODES = 100_000
MAX_SESSION_BYTES = 32 * 1024 * 1024
MAX_CONNECTIONS = 4096
DEFAULT_GOSSIP_CHUNK_SIZE = 256
PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Wire serialization helpers
# ---------------------------------------------------------------------------


def _node_to_wire(node: DAGNode) -> dict[str, Any]:
    """Serialize a DAGNode to a wire-format dict (includes CID and metadata)."""
    return {
        "cid": node.cid,
        "agent_id": node.agent_id,
        "payload": node.payload,
        "payload_type": node.payload_type,
        "parent_cids": list(node.parent_cids),
        "bodes_passed": node.bodes_passed,
        "constitutional_hash": node.constitutional_hash,
        "metadata": thaw_json_value(node.metadata),
    }


def _is_cid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _utf8_size(value: str, field_name: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError(f"{field_name} must contain valid Unicode") from exc


def _require_text(value: Any, field_name: str, *, max_bytes: int = MAX_FIELD_BYTES) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if _utf8_size(value, field_name) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} bytes")
    return value


def _wire_to_node(data: dict[str, Any]) -> DAGNode:
    """Deserialize a wire-format dict to a DAGNode.

    The node's CID is taken from the wire — verify_cid() on the receiver
    ensures integrity before insertion into the replica.

    Raises ValueError if the metadata field exceeds MAX_METADATA_BYTES to
    prevent memory exhaustion via oversized gossip payloads.
    """
    if not isinstance(data, dict):
        raise ValueError("gossip node must be an object")
    _require_fields(
        data,
        required={"cid", "agent_id", "payload"},
        optional={
            "payload_type",
            "parent_cids",
            "bodes_passed",
            "constitutional_hash",
            "metadata",
        },
        context="gossip node",
    )
    raw_metadata = data.get("metadata", {})
    if not isinstance(raw_metadata, dict):
        raise ValueError("metadata must be an object")
    try:
        metadata_json = json.dumps(
            raw_metadata,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError(f"metadata must be valid JSON: {exc}") from exc
    metadata_size = len(metadata_json.encode("utf-8"))
    if metadata_size > MAX_METADATA_BYTES:
        raise ValueError(
            f"Gossip node metadata exceeds {MAX_METADATA_BYTES} bytes "
            f"({metadata_size} bytes)"
        )
    cid = _require_text(data["cid"], "cid", max_bytes=256)
    if not _is_cid(cid):
        raise ValueError("cid must be a lowercase SHA-256 CID")
    agent_id = _require_text(data.get("agent_id"), "agent_id", max_bytes=1024)
    payload = _require_text(data.get("payload"), "payload")
    payload_type = _require_text(data.get("payload_type", "artifact"), "payload_type", max_bytes=256)
    constitutional_hash = _require_text(
        data.get("constitutional_hash", ""), "constitutional_hash", max_bytes=1024
    )
    parent_cids = data.get("parent_cids", [])
    if not isinstance(parent_cids, list):
        raise ValueError("parent_cids must be an array")
    if len(parent_cids) > MAX_PARENT_CIDS:
        raise ValueError(f"parent_cids exceeds {MAX_PARENT_CIDS} entries")
    if any(not _is_cid(parent) for parent in parent_cids):
        raise ValueError("parent_cids must contain lowercase SHA-256 CIDs")
    if len(set(parent_cids)) != len(parent_cids):
        raise ValueError("parent_cids must not contain duplicates")
    bodes_passed = data.get("bodes_passed", False)
    if type(bodes_passed) is not bool:
        raise ValueError("bodes_passed must be a boolean")
    normalized_metadata = normalize_json_value(raw_metadata)

    return DAGNode(
        cid=cid,
        agent_id=agent_id,
        payload=payload,
        payload_type=payload_type,
        parent_cids=tuple(parent_cids),
        bodes_passed=bodes_passed,
        constitutional_hash=constitutional_hash,
        metadata=normalized_metadata,
    )


def encode_batch(nodes: list[DAGNode]) -> str:
    """Encode a batch of nodes to a JSON string for transmission."""
    return json.dumps([_node_to_wire(n) for n in nodes])


def _validate_json_depth(message: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in message:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
        elif character in "]}":
            depth -= 1


def _parse_json_frame(message: Any) -> Any:
    if not isinstance(message, str):
        raise ValueError("gossip frames must be text")
    message_bytes = _utf8_size(message, "gossip frame")
    if message_bytes > MAX_BATCH_BYTES:
        raise ValueError(f"Gossip frame too large: {message_bytes} bytes (limit {MAX_BATCH_BYTES})")
    _validate_json_depth(message)
    try:
        return json.loads(message, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Malformed gossip frame: {exc}") from exc


def decode_batch(message: str) -> list[DAGNode]:
    """Decode a JSON string to a list of DAGNodes."""
    try:
        items = _parse_json_frame(message)
        if not isinstance(items, list):
            raise ValueError(f"Expected JSON array, got {type(items)}")
        if len(items) > MAX_BATCH_NODES:
            raise ValueError(f"Gossip batch too many nodes: {len(items)} (limit {MAX_BATCH_NODES})")
        return [_wire_to_node(item) for item in items]
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Expected JSON array"):
            raise
        raise ValueError(f"Malformed gossip batch: {exc}") from exc


def _encode_envelope(message_type: str, **fields: Any) -> str:
    return json.dumps(
        {"version": PROTOCOL_VERSION, "type": message_type, **fields},
        sort_keys=True,
        separators=(",", ":"),
    )


def _require_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    if missing:
        raise ValueError(f"{context} missing required fields: {sorted(missing)}")
    unexpected = value.keys() - required - optional
    if unexpected:
        raise ValueError(f"{context} has unexpected fields: {sorted(unexpected)}")


def _validated_cids(value: Any, field_name: str, *, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field_name} must be an array with at most {limit} CIDs")
    if any(not _is_cid(cid) for cid in value) or len(set(value)) != len(value):
        raise ValueError(f"{field_name} contains invalid or duplicate CIDs")
    return tuple(value)


def _decode_envelope(message: Any) -> dict[str, Any] | list[DAGNode]:
    value = _parse_json_frame(message)
    if isinstance(value, list):
        return decode_batch(message)
    if not isinstance(value, dict):
        raise ValueError("gossip envelope must be an object")
    if value.get("version") != PROTOCOL_VERSION or not isinstance(value.get("type"), str):
        raise ValueError("unsupported gossip envelope")
    message_type = value["type"]
    if message_type == "frontier":
        _require_fields(
            value,
            required={"version", "type", "cids", "page", "final"},
            context="frontier",
        )
        value["cids"] = _validated_cids(value.get("cids"), "frontier.cids", limit=MAX_FRONTIER_CIDS)
        if type(value.get("page")) is not int or value["page"] < 0:
            raise ValueError("frontier.page must be a non-negative integer")
        if type(value.get("final")) is not bool:
            raise ValueError("frontier.final must be a boolean")
    elif message_type == "fetch":
        _require_fields(
            value,
            required={"version", "type", "cids", "budget"},
            context="fetch",
        )
        value["cids"] = _validated_cids(value.get("cids"), "fetch.cids", limit=MAX_FETCH_CIDS)
        if (
            type(value.get("budget")) is not int
            or not 0 <= value["budget"] <= MAX_SESSION_NODES
        ):
            raise ValueError(f"fetch.budget must be between 0 and {MAX_SESSION_NODES}")
    elif message_type == "nodes":
        _require_fields(
            value,
            required={"version", "type", "nodes"},
            context="nodes",
        )
        nodes = value.get("nodes")
        if not isinstance(nodes, list) or not 0 < len(nodes) <= MAX_BATCH_NODES:
            raise ValueError("nodes must be a non-empty bounded array")
        value["nodes"] = [_wire_to_node(node) for node in nodes]
    elif message_type == "complete":
        _require_fields(
            value,
            required={"version", "type", "complete"},
            optional={"nodes_received"},
            context="complete",
        )
        if type(value.get("complete")) is not bool:
            raise ValueError("complete.complete must be a boolean")
        if "nodes_received" in value and (
            type(value["nodes_received"]) is not int
            or not 0 <= value["nodes_received"] <= MAX_SESSION_NODES
        ):
            raise ValueError("complete.nodes_received must be a bounded non-negative integer")
    elif message_type == "ack":
        _require_fields(
            value,
            required={"version", "type", "ok"},
            optional={"nodes_received", "message"},
            context="ack",
        )
        if type(value.get("ok")) is not bool:
            raise ValueError("ack.ok must be a boolean")
        if "nodes_received" in value and (
            type(value["nodes_received"]) is not int
            or not 0 <= value["nodes_received"] <= MAX_BATCH_NODES
        ):
            raise ValueError("ack.nodes_received must be a bounded non-negative integer")
        if "message" in value:
            _require_text(value["message"], "ack.message", max_bytes=1024)
    elif message_type == "error":
        _require_fields(
            value,
            required={"version", "type", "message"},
            context="error",
        )
        _require_text(value.get("message"), "error.message", max_bytes=1024)
    else:
        raise ValueError(f"unsupported gossip message type: {message_type}")
    return value


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------


@dataclass
class GossipPeerRegistry:
    """Thread-safe registry of known peer addresses.

    Each entry is a (host, port) tuple. The local node's own address
    is stored in `self_addr` and is always excluded from gossip targets.
    """

    self_addr: tuple[str, int] | None = None
    _peers: list[tuple[str, int]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, host: str, port: int) -> None:
        """Register a peer. Silently ignores the local node's own address."""
        addr = (host, port)
        if addr == self.self_addr:
            return
        with self._lock:
            if addr not in self._peers:
                self._peers.append(addr)

    def remove(self, host: str, port: int) -> None:
        """Unregister a peer."""
        addr = (host, port)
        with self._lock:
            self._peers = [p for p in self._peers if p != addr]

    def sample(self, n: int, *, rng: random.Random | None = None) -> list[tuple[str, int]]:
        """Return up to n random peers."""
        rng = rng or random.SystemRandom()
        with self._lock:
            pool = list(self._peers)
        return rng.sample(pool, min(n, len(pool)))

    @property
    def all_peers(self) -> list[tuple[str, int]]:
        """Snapshot of all registered peers."""
        with self._lock:
            return list(self._peers)

    def __len__(self) -> int:
        with self._lock:
            return len(self._peers)


# ---------------------------------------------------------------------------
# Gossip server (WebSocket)
# ---------------------------------------------------------------------------


class GossipServer:
    """WebSocket server that receives DAGNode batches and merges them.

    Each incoming message is a JSON-encoded batch of nodes. The server
    deserializes them and calls `crdt.merge_nodes()`. CID verification
    is delegated to MerkleCRDT (reject_unverified=True by default).

    Args:
        crdt: The local MerkleCRDT replica to receive gossip into.
        host: Bind address.
        port: Bind port.
        secret_token: Optional shared secret. When set, every connecting
            client must send ``{"type":"auth","token":"<secret>"}`` as its
            first message before any node batches are accepted.  Connections
            that omit or fail the auth message are closed immediately.
            This is a defence-in-depth measure; production deployments
            should additionally use TLS and network-level access control.
    """

    def __init__(
        self,
        crdt: MerkleCRDT,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        secret_token: str | None = None,
        allow_unauthenticated: bool = False,
        auth_timeout_s: float = 5.0,
        frame_timeout_s: float = 10.0,
        max_connections: int = 128,
        max_nodes_per_session: int = 8192,
        max_bytes_per_session: int = MAX_SESSION_BYTES,
    ) -> None:
        if (
            isinstance(auth_timeout_s, bool)
            or isinstance(frame_timeout_s, bool)
            or not isinstance(auth_timeout_s, (int, float))
            or not isinstance(frame_timeout_s, (int, float))
            or not math.isfinite(auth_timeout_s)
            or not math.isfinite(frame_timeout_s)
            or auth_timeout_s <= 0
            or frame_timeout_s <= 0
        ):
            raise ValueError("gossip timeouts must be positive")
        if type(max_connections) is not int or not 1 <= max_connections <= MAX_CONNECTIONS:
            raise ValueError(f"max_connections must be between 1 and {MAX_CONNECTIONS}")
        if (
            type(max_nodes_per_session) is not int
            or not 1 <= max_nodes_per_session <= MAX_SESSION_NODES
        ):
            raise ValueError(
                f"max_nodes_per_session must be between 1 and {MAX_SESSION_NODES}"
            )
        if (
            type(max_bytes_per_session) is not int
            or not 1 <= max_bytes_per_session <= MAX_SESSION_BYTES
        ):
            raise ValueError(
                f"max_bytes_per_session must be between 1 and {MAX_SESSION_BYTES}"
            )
        if secret_token is not None:
            _require_text(secret_token, "secret_token", max_bytes=4096)
        self.crdt = crdt
        self.host = host
        self.port = port
        self._secret_token = secret_token
        self._allow_unauthenticated = allow_unauthenticated
        self._auth_timeout_s = auth_timeout_s
        self._frame_timeout_s = frame_timeout_s
        self._max_nodes_per_session = max_nodes_per_session
        self._max_bytes_per_session = max_bytes_per_session
        self._connection_slots = asyncio.Semaphore(max_connections)
        self._server: Any = None  # websockets.Server
        self._actual_port: int = port

    async def start(self) -> None:
        """Start the WebSocket server. Raises ImportError if websockets not installed."""
        if self._secret_token is None and not self._allow_unauthenticated:
            raise ValueError(
                "GossipServer requires secret_token unless "
                "allow_unauthenticated=True is set explicitly"
            )
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "WebSocket transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            max_size=MAX_BATCH_BYTES,
        )
        # Record actual bound port (useful when port=0 for OS-assigned)
        sockets = self._server.sockets
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]
        log.debug("GossipServer listening at %s:%d", self.host, self._actual_port)

    async def stop(self) -> None:
        """Gracefully shut down the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def actual_port(self) -> int:
        """The port the server is actually bound to (after start())."""
        return self._actual_port

    async def _handle_connection(self, websocket: Any) -> None:
        """Handle one bounded authenticated anti-entropy session."""
        try:
            from websockets.exceptions import ConnectionClosed  # type: ignore[import]
        except ImportError:
            connection_closed_error: type[BaseException] = RuntimeError
        else:
            connection_closed_error = ConnectionClosed

        peer = websocket.remote_address
        log.debug("Gossip connection from %s", peer)
        if self._connection_slots.locked():
            await websocket.close(code=4429, reason="too many connections")
            return
        await self._connection_slots.acquire()
        try:
            if self._secret_token is not None:
                try:
                    first_msg = await asyncio.wait_for(
                        websocket.recv(), timeout=self._auth_timeout_s
                    )
                except TimeoutError:
                    await websocket.close(code=4408, reason="authentication timeout")
                    return
                except (connection_closed_error, StopAsyncIteration):
                    return
                try:
                    auth = _parse_json_frame(first_msg)
                    if isinstance(auth, dict):
                        _require_fields(
                            auth,
                            required={"type", "token"},
                            context="authentication",
                        )
                    token = auth.get("token") if isinstance(auth, dict) else None
                    if isinstance(token, str):
                        _require_text(token, "auth.token", max_bytes=4096)
                    if not (
                        isinstance(auth, dict)
                        and auth.get("type") == "auth"
                        and isinstance(token, str)
                        and hmac.compare_digest(
                            token.encode("utf-8"), self._secret_token.encode("utf-8")
                        )
                    ):
                        raise ValueError("auth failed")
                except (TypeError, UnicodeError, ValueError):
                    log.warning("Gossip auth failed from %s — closing", peer)
                    await websocket.close(code=4401, reason="unauthorized")
                    return
                log.debug("Gossip auth OK from %s", peer)

            frontier: tuple[str, ...] | None = None
            frontier_is_final = False
            frontier_scan_truncated = False
            expected_page = 0
            nodes_received = 0
            bytes_received = 0
            work_rounds = 0
            frames_received = 0

            async def resolve_frontier_page() -> bool:
                """Request missing ancestry or close the current frontier page."""
                nonlocal frontier, frontier_is_final, frontier_scan_truncated
                if frontier is None:
                    raise ValueError("sender completion without an active frontier page")
                if frontier_scan_truncated:
                    await websocket.send(
                        _encode_envelope(
                            "complete", complete=False, nodes_received=nodes_received
                        )
                    )
                    return True
                try:
                    missing = self.crdt.missing_ancestry(
                        frontier, limit=MAX_FETCH_CIDS, scan_limit=MAX_ANCESTRY_SCAN
                    )
                except AncestryScanLimitExceeded as exc:
                    remaining = self._max_nodes_per_session - nodes_received
                    if remaining <= 0 or not exc.checkpoints:
                        await websocket.send(
                            _encode_envelope(
                                "complete", complete=False, nodes_received=nodes_received
                            )
                        )
                        return True
                    frontier_scan_truncated = True
                    await websocket.send(
                        _encode_envelope(
                            "fetch", cids=list(exc.checkpoints), budget=remaining
                        )
                    )
                    return False
                if missing:
                    remaining = self._max_nodes_per_session - nodes_received
                    if remaining <= 0:
                        await websocket.send(
                            _encode_envelope(
                                "complete", complete=False, nodes_received=nodes_received
                            )
                        )
                        return True
                    await websocket.send(
                        _encode_envelope("fetch", cids=list(missing), budget=remaining)
                    )
                    return False
                if frontier_is_final:
                    await websocket.send(
                        _encode_envelope(
                            "complete", complete=True, nodes_received=nodes_received
                        )
                    )
                    return True
                await websocket.send(_encode_envelope("ack", ok=True))
                frontier = None
                frontier_is_final = False
                frontier_scan_truncated = False
                return False

            while True:
                if frames_received >= MAX_SESSION_FRAMES:
                    await websocket.send(
                        _encode_envelope(
                            "complete", complete=False, nodes_received=nodes_received
                        )
                    )
                    return
                if work_rounds >= MAX_PROTOCOL_ROUNDS and frontier is None:
                    await websocket.send(
                        _encode_envelope(
                            "complete", complete=False, nodes_received=nodes_received
                        )
                    )
                    return
                try:
                    message = await asyncio.wait_for(
                        websocket.recv(), timeout=self._frame_timeout_s
                    )
                except TimeoutError:
                    await websocket.close(code=4408, reason="frame timeout")
                    return
                except (connection_closed_error, StopAsyncIteration):
                    return
                frames_received += 1
                try:
                    if not isinstance(message, str):
                        raise ValueError("gossip frames must be text")
                    bytes_received += _utf8_size(message, "gossip frame")
                    if bytes_received > self._max_bytes_per_session:
                        raise ValueError("gossip session byte budget exceeded")
                    envelope = _decode_envelope(message)
                    if isinstance(envelope, list):
                        if nodes_received + len(envelope) > self._max_nodes_per_session:
                            raise ValueError("node session budget exceeded")
                        if any(not node.verify_cid() for node in envelope):
                            await websocket.send(
                                _encode_envelope("ack", ok=False, message="invalid CID")
                            )
                            continue
                        self.crdt.merge_nodes(envelope)
                        nodes_received += len(envelope)
                        await websocket.send(
                            _encode_envelope("ack", ok=True, nodes_received=len(envelope))
                        )
                        continue

                    message_type = envelope["type"]
                    if message_type == "frontier":
                        if frontier is not None:
                            raise ValueError("previous frontier page is not resolved")
                        if envelope["page"] != expected_page:
                            raise ValueError("frontier pages must be contiguous")
                        if expected_page >= MAX_FRONTIER_PAGES:
                            raise ValueError("frontier page limit exceeded")
                        frontier = envelope["cids"]
                        frontier_is_final = envelope["final"]
                        expected_page += 1
                        if await resolve_frontier_page():
                            return
                    elif message_type == "nodes":
                        work_rounds += 1
                        if frontier is None:
                            raise ValueError("nodes received without an active frontier page")
                        nodes = envelope["nodes"]
                        if nodes_received + len(nodes) > self._max_nodes_per_session:
                            raise ValueError("node session budget exceeded")
                        if any(not node.verify_cid() for node in nodes):
                            raise ValueError("node CID verification failed")
                        self.crdt.merge_nodes(nodes)
                        nodes_received += len(nodes)
                    elif message_type == "complete":
                        work_rounds += 1
                        if envelope["complete"] is not True:
                            raise ValueError("sender completion marker must be true")
                        if await resolve_frontier_page():
                            return
                    else:
                        raise ValueError(f"unexpected client message: {message_type}")
                except ValueError as exc:
                    log.warning("Rejected malformed batch from %s: %s", peer, exc)
                    try:
                        await websocket.send(_encode_envelope("error", message=str(exc)[:1024]))
                    except Exception:
                        pass
                    return
        except (connection_closed_error, OSError, StopAsyncIteration) as exc:
            log.debug("Connection from %s closed: %s", peer, type(exc).__name__)
        finally:
            self._connection_slots.release()


# ---------------------------------------------------------------------------
# Gossip client (WebSocket)
# ---------------------------------------------------------------------------


class GossipClient:
    """Sends DAGNode batches to a single peer over WebSocket.

    Usage (fire-and-forget, one connection per send):

        client = GossipClient()
        await client.send_batch("127.0.0.1", 8766, nodes)

    The client is stateless — it opens, sends, closes. For long-running
    agents, SwarmNode reuses GossipClient across rounds.
    """

    def __init__(self, *, connect: Callable[..., Any] | None = None) -> None:
        self._connect = connect

    def _connection(self, uri: str) -> Any:
        if self._connect is not None:
            return self._connect(uri)
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "WebSocket transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc
        return websockets.connect(uri, max_size=MAX_BATCH_BYTES)

    @staticmethod
    def _is_connection_failure(exc: Exception) -> bool:
        transport_errors: tuple[type[BaseException], ...] = ()
        try:
            from websockets.exceptions import WebSocketException  # type: ignore[import]
        except ImportError:
            pass
        else:
            transport_errors = (WebSocketException,)
        return isinstance(
            exc,
            (TimeoutError, OSError, StopAsyncIteration, ValueError, *transport_errors),
        )

    @staticmethod
    def _node_chunks(nodes: list[DAGNode], chunk_size: int) -> list[list[DAGNode]]:
        if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_BATCH_NODES:
            raise ValueError(f"chunk_size must be between 1 and {MAX_BATCH_NODES}")
        chunks: list[list[DAGNode]] = []
        current: list[DAGNode] = []
        empty_frame_size = len(_encode_envelope("nodes", nodes=[]).encode("utf-8"))
        current_size = empty_frame_size
        for node in nodes:
            wire_node = _node_to_wire(node)
            node_size = len(
                json.dumps(wire_node, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            separator_size = 1 if current else 0
            if current and (
                len(current) == chunk_size
                or current_size + separator_size + node_size > MAX_BATCH_BYTES
            ):
                chunks.append(current)
                current = [node]
                current_size = empty_frame_size + node_size
            else:
                current.append(node)
                current_size += separator_size + node_size
            if current_size > MAX_BATCH_BYTES:
                raise ValueError("single node exceeds gossip frame byte limit")
        if current:
            chunks.append(current)
        return chunks

    async def sync(
        self,
        host: str,
        port: int,
        source: MerkleCRDT,
        *,
        chunk_size: int = DEFAULT_GOSSIP_CHUNK_SIZE,
        timeout: float = 5.0,
        secret_token: str | None = None,
    ) -> dict[str, Any]:
        """Synchronize missing frontier ancestry and await terminal acknowledgement."""
        if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_BATCH_NODES:
            raise ValueError(f"chunk_size must be between 1 and {MAX_BATCH_NODES}")
        uri = f"ws://{host}:{port}"
        nodes_sent = 0
        try:
            async with asyncio.timeout(timeout):
                async with self._connection(uri) as websocket:
                    if secret_token is not None:
                        await websocket.send(json.dumps({"type": "auth", "token": secret_token}))
                    frontier = source.frontier_snapshot()
                    pages = [
                        frontier[index : index + MAX_FRONTIER_CIDS]
                        for index in range(0, len(frontier), MAX_FRONTIER_CIDS)
                    ] or [()]
                    work_responses = 0
                    for page_number, page in enumerate(pages):
                        final_page = page_number == len(pages) - 1
                        await websocket.send(
                            _encode_envelope(
                                "frontier",
                                cids=list(page),
                                page=page_number,
                                final=final_page,
                            )
                        )
                        while work_responses < MAX_PROTOCOL_ROUNDS:
                            response = _decode_envelope(await websocket.recv())
                            if isinstance(response, list):
                                raise ValueError("unexpected legacy response")
                            if response["type"] != "ack":
                                work_responses += 1
                            if response["type"] == "complete":
                                return {
                                    "complete": response["complete"],
                                    "nodes_sent": nodes_sent,
                                }
                            if response["type"] == "error":
                                return {"complete": False, "nodes_sent": nodes_sent}
                            if response["type"] == "ack":
                                if not response["ok"] or final_page:
                                    raise ValueError("unexpected frontier acknowledgement")
                                break
                            if response["type"] != "fetch":
                                raise ValueError(
                                    f"unexpected server response: {response['type']}"
                                )
                            budget = response["budget"]
                            requested = response["cids"]
                            nodes = source.ancestry_nodes(requested, limit=budget)
                            if not nodes or any(source.get(cid) is None for cid in requested):
                                await websocket.send(
                                    _encode_envelope(
                                        "error", message="requested CID unavailable"
                                    )
                                )
                                return {"complete": False, "nodes_sent": nodes_sent}
                            for chunk in self._node_chunks(nodes, chunk_size):
                                await websocket.send(
                                    _encode_envelope(
                                        "nodes", nodes=[_node_to_wire(node) for node in chunk]
                                    )
                                )
                                nodes_sent += len(chunk)
                            await websocket.send(_encode_envelope("complete", complete=True))
                        else:
                            return {"complete": False, "nodes_sent": nodes_sent}
            return {"complete": False, "nodes_sent": nodes_sent}
        except Exception as exc:
            if not self._is_connection_failure(exc):
                raise
            log.debug("Failed to synchronize with %s:%d: %s", host, port, type(exc).__name__)
            return {"complete": False, "nodes_sent": nodes_sent}

    async def send_batch(
        self,
        host: str,
        port: int,
        nodes: list[DAGNode],
        *,
        timeout: float = 5.0,
        secret_token: str | None = None,
    ) -> bool:
        """Send nodes to a peer. Returns True on success, False on failure.

        Failures are logged at DEBUG level and swallowed — gossip is
        best-effort and partial delivery is acceptable for convergence.

        Args:
            secret_token: If provided, send an auth frame before the node
                batch.  Must match the server's ``secret_token``.
        """
        if not nodes:
            return True

        uri = f"ws://{host}:{port}"
        try:
            async with asyncio.timeout(timeout):
                async with self._connection(uri) as ws:
                    if secret_token is not None:
                        auth_msg = json.dumps({"type": "auth", "token": secret_token})
                        await ws.send(auth_msg)
                    for chunk in self._node_chunks(nodes, MAX_BATCH_NODES):
                        encoded = encode_batch(chunk)
                        await ws.send(encoded)
                        response = _decode_envelope(await ws.recv())
                        if (
                            isinstance(response, list)
                            or response["type"] != "ack"
                            or response["ok"] is not True
                        ):
                            return False
            log.debug("Sent %d nodes to %s:%d", len(nodes), host, port)
            return True
        except Exception as exc:
            if not self._is_connection_failure(exc):
                raise
            log.debug("Failed to reach %s:%d: %s", host, port, type(exc).__name__)
            return False


# ---------------------------------------------------------------------------
# SwarmNode: CRDT + server + gossip loop
# ---------------------------------------------------------------------------


class SwarmNode:
    """Self-contained swarm participant: local CRDT replica + gossip transport.

    Each SwarmNode runs a WebSocket gossip server and maintains a peer
    registry. Call gossip_round() to push current DAG heads to random peers.

    Args:
        agent_id: Unique identifier for this node in the swarm.
        host: WebSocket server bind address.
        port: WebSocket server port. 0 = OS-assigned (use actual_port after start).
        reject_unverified: If True (default), reject nodes with invalid CIDs.
        gossip_batch_size: Positive maximum nodes per anti-entropy chunk.

    Usage as async context manager:

        async with SwarmNode("agent-0", port=8765) as node:
            node.registry.add("127.0.0.1", 8766)
            node.crdt.append(payload="hello")
            await node.gossip_round(n_peers=2)
    """

    def __init__(
        self,
        agent_id: str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        reject_unverified: bool = True,
        gossip_batch_size: int = DEFAULT_GOSSIP_CHUNK_SIZE,
        secret_token: str | None = None,
        allow_unauthenticated: bool = False,
    ) -> None:
        if (
            type(gossip_batch_size) is not int
            or not 1 <= gossip_batch_size <= MAX_BATCH_NODES
        ):
            raise ValueError(
                f"gossip_batch_size must be between 1 and {MAX_BATCH_NODES}"
            )
        self.agent_id = agent_id
        self.crdt = MerkleCRDT(agent_id, reject_unverified=reject_unverified)
        self.registry = GossipPeerRegistry()
        self.client = GossipClient()
        self._secret_token = secret_token
        self._server = GossipServer(
            self.crdt,
            host=host,
            port=port,
            secret_token=secret_token,
            allow_unauthenticated=allow_unauthenticated,
        )
        self._gossip_batch_size = gossip_batch_size
        self._running = False

    async def start(self) -> None:
        """Start the WebSocket gossip server."""
        await self._server.start()
        self.registry.self_addr = (self._server.host, self._server.actual_port)
        self._running = True
        log.info(
            "SwarmNode %s started at %s:%d",
            self.agent_id,
            self._server.host,
            self._server.actual_port,
        )

    async def stop(self) -> None:
        """Shut down the gossip server."""
        await self._server.stop()
        self._running = False

    async def __aenter__(self) -> SwarmNode:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    @property
    def actual_port(self) -> int:
        """The port the server is bound to (after start())."""
        return self._server.actual_port

    @property
    def host(self) -> str:
        return self._server.host

    def _select_nodes_for_gossip(self) -> list[DAGNode]:
        """Compatibility snapshot; anti-entropy uses peer-requested ancestry."""
        return self.crdt.get_many(
            list(self.crdt.frontier_snapshot()), limit=self._gossip_batch_size
        )

    async def gossip_round(
        self,
        n_peers: int = 2,
        *,
        rng: random.Random | None = None,
    ) -> dict[str, Any]:
        """Gossip current DAG state to n_peers random peers.

        Returns a summary dict with peer count and send results.
        """
        peers = self.registry.sample(n_peers, rng=rng)
        if not peers:
            return {"peers_contacted": 0, "successes": 0, "nodes_sent": 0}

        if self.crdt.size == 0:
            return {"peers_contacted": 0, "successes": 0, "nodes_sent": 0}

        results = await asyncio.gather(
            *[
                self.client.sync(
                    host,
                    port,
                    self.crdt,
                    chunk_size=self._gossip_batch_size,
                    secret_token=self._secret_token,
                )
                for host, port in peers
            ],
            return_exceptions=True,
        )
        successful_results = [
            result
            for result in results
            if isinstance(result, dict) and result.get("complete") is True
        ]
        return {
            "peers_contacted": len(peers),
            "successes": len(successful_results),
            "nodes_sent": sum(int(result["nodes_sent"]) for result in successful_results),
        }

    async def run_gossip_loop(
        self,
        *,
        interval_s: float = 1.0,
        n_peers: int = 2,
        max_rounds: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        """Run continuous gossip loop until cancelled or max_rounds reached.

        Typically run as a background task:

            task = asyncio.create_task(node.run_gossip_loop(interval_s=0.5))
            # ... do work ...
            task.cancel()
        """
        rounds = 0
        while True:
            if max_rounds is not None and rounds >= max_rounds:
                break
            await self.gossip_round(n_peers=n_peers, rng=rng)
            rounds += 1
            if max_rounds is None or rounds < max_rounds:
                await asyncio.sleep(interval_s)


# ---------------------------------------------------------------------------
# Multi-node convergence helper (for testing and benchmarks)
# ---------------------------------------------------------------------------


async def spin_up_swarm(
    n_nodes: int,
    *,
    host: str = "127.0.0.1",
    reject_unverified: bool = True,
    secret_token: str | None = None,
) -> list[SwarmNode]:
    """Spin up n_nodes SwarmNodes on localhost with OS-assigned ports.

    All nodes are registered with each other in a full mesh.
    Returns the started nodes. Caller is responsible for stopping them.

    Example:
        nodes = await spin_up_swarm(5)
        try:
            nodes[0].crdt.append(payload="hello")
            await nodes[0].gossip_round(n_peers=2)
        finally:
            await asyncio.gather(*[n.stop() for n in nodes])
    """
    shared_secret = secret_token or secrets.token_urlsafe(32)
    nodes = [
        SwarmNode(
            f"agent-{i}",
            host=host,
            reject_unverified=reject_unverified,
            secret_token=shared_secret,
        )
        for i in range(n_nodes)
    ]
    # Start all servers
    await asyncio.gather(*[node.start() for node in nodes])

    # Register full mesh (every node knows every other)
    for node in nodes:
        for other in nodes:
            if other is not node:
                node.registry.add(other.host, other.actual_port)

    return nodes


async def simulate_ws_gossip_convergence(
    n_nodes: int = 5,
    n_rounds: int = 10,
    artifacts_per_round: int = 2,
    n_peers: int = 2,
    *,
    seed: int = 42,
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Simulate convergence over real WebSocket connections.

    Analogous to merkle_crdt.simulate_gossip_convergence() but uses
    actual network I/O instead of in-process merge().

    Returns:
        dict with convergence result, per-node sizes, total artifacts.
    """
    rng = random.Random(seed)
    nodes = await spin_up_swarm(n_nodes, host=host)

    try:
        for round_idx in range(n_rounds):
            # Each node appends artifacts
            for node in nodes:
                for art_idx in range(artifacts_per_round):
                    node.crdt.append(
                        payload=f"round={round_idx} art={art_idx} by={node.agent_id}",
                        payload_type="task_output",
                        bodes_passed=True,
                        constitutional_hash="608508a9bd224290",
                    )

            # Gossip round (all nodes push to n_peers)
            await asyncio.gather(*[node.gossip_round(n_peers=n_peers, rng=rng) for node in nodes])
            # Small pause to let receivers process
            await asyncio.sleep(0.02)

        # Final full-mesh convergence round
        for node in nodes:
            await node.gossip_round(n_peers=len(nodes), rng=rng)
        await asyncio.sleep(0.1)

    finally:
        await asyncio.gather(*[node.stop() for node in nodes])

    cid_sets = [node.crdt.all_cids() for node in nodes]
    converged = all(s == cid_sets[0] for s in cid_sets)
    sizes = {node.agent_id: node.crdt.size for node in nodes}
    total_artifacts = n_nodes * n_rounds * artifacts_per_round

    return {
        "converged": converged,
        "n_nodes": n_nodes,
        "n_rounds": n_rounds,
        "total_artifacts": total_artifacts,
        "sizes": sizes,
        "unique_cids": len(cid_sets[0]) if converged else -1,
    }


# Backwards-compatible alias — CI smoke test imports this name
GossipNode = SwarmNode
