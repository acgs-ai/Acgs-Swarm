"""
Merkle-CRDT Artifact Store — MCFS Phase 3.

Decentralized, conflict-free replicated artifact store built on a Merkle DAG.
Each agent maintains its own local replica. Replicas converge via gossip
without any central coordinator or database locks.

Key properties:
    - Content-addressed: every node's CID is SHA-256(canonical(payload + parents))
    - Causal ordering: parent_cids encode happened-before relationships
    - CRDT merge: set union of nodes — commutative, associative, idempotent
    - Eventual Epistemic Convergence: all replicas reach identical state
    - Byzantine rejection: malformed nodes (broken hash, unresolvable CID) rejected
                            (missing-parent acceptance is by CRDT design: nodes with
                            unknown parents are stored and causality is resolved lazily)

Integration with other MCFS phases:
    - Phase 1: bodes_passed flag records whether payload survived Latent DNA check
    - Phase 2: payload can carry spectral-projected trust matrices
    - Phase 3: DP noise + MACI proofs embedded in node metadata
    - Phase 4: ODE trajectory snapshots can be published as artifacts

No external dependencies — pure Python with hashlib and asyncio.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


MAX_METADATA_DEPTH = 32
MAX_METADATA_ITEMS = 10_000


class AncestryScanLimitExceeded(ValueError):
    """A bounded ancestry query stopped before it could prove closure."""

    def __init__(self, checkpoints: tuple[str, ...]) -> None:
        super().__init__("ancestry scan limit reached before closure")
        self.checkpoints = checkpoints


class FrozenJSONList(tuple[Any, ...]):
    """Tuple-backed JSON array that compares equal to ordinary sequences."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (list, tuple)):
            return tuple(self) == tuple(other)
        return False

    def __ne__(self, other: object) -> bool:
        return not self == other

    __hash__ = None  # type: ignore[assignment]


class FrozenJSONDict(Mapping[str, Any]):
    """Recursively immutable JSON object with mapping-compatible equality."""

    __slots__ = ("_data",)
    _data: Mapping[str, Any]

    def __init__(self, data: dict[str, Any]) -> None:
        object.__setattr__(self, "_data", MappingProxyType(data))

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("frozen JSON objects cannot be modified")

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return repr(self._data)


def normalize_json_value(
    value: Any,
    *,
    max_depth: int = MAX_METADATA_DEPTH,
    max_items: int = MAX_METADATA_ITEMS,
) -> Any:
    """Validate, detach, and recursively freeze a JSON-compatible value."""
    remaining = [max_items]

    def freeze(item: Any, depth: int) -> Any:
        if depth > max_depth:
            raise ValueError(f"JSON value exceeds maximum depth {max_depth}")
        if item is None or isinstance(item, (str, bool, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
            return item
        if isinstance(item, Mapping):
            remaining[0] -= len(item)
            if remaining[0] < 0:
                raise ValueError(f"JSON value exceeds maximum item count {max_items}")
            frozen: dict[str, Any] = {}
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise TypeError("JSON object keys must be strings")
                frozen[key] = freeze(nested, depth + 1)
            return FrozenJSONDict(frozen)
        if isinstance(item, (list, tuple)):
            remaining[0] -= len(item)
            if remaining[0] < 0:
                raise ValueError(f"JSON value exceeds maximum item count {max_items}")
            return FrozenJSONList(freeze(nested, depth + 1) for nested in item)
        raise TypeError(f"unsupported JSON value type: {type(item).__name__}")

    return freeze(value, 0)


def thaw_json_value(value: Any) -> Any:
    """Return a detached, JSON-serializable copy of a normalized value."""
    if isinstance(value, Mapping):
        return {key: thaw_json_value(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw_json_value(nested) for nested in value]
    return value


def _normalize_metadata(metadata: Any) -> FrozenJSONDict:
    normalized = normalize_json_value(metadata)
    if not isinstance(normalized, FrozenJSONDict):
        raise TypeError("metadata must be a JSON object")
    return normalized


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for content-addressing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class DAGNode:
    """An immutable, content-addressed node in the Merkle DAG.

    Every agent action (task claim, code output, trust update, ODE snapshot)
    becomes a DAGNode. The CID is computed deterministically from the payload
    and parent CIDs, creating an immutable causal graph.

    Attributes:
        cid: Content Identifier — SHA-256 of canonical(payload + parent_cids).
        agent_id: Which agent created this node.
        payload: The artifact content (code, trust matrix, vote, etc).
        payload_type: Discriminator for payload interpretation.
        parent_cids: CIDs of causal predecessors (the DAG edges).
        timestamp: Wall-clock time of creation (informational, not used for ordering).
        bodes_passed: True if payload passed Phase 1 Latent DNA validation.
        constitutional_hash: The constitutional hash active when this node was created.
        metadata: Extensible metadata (DP proof, MACI proof, etc).
    """

    cid: str
    agent_id: str
    payload: str
    payload_type: str = "artifact"
    parent_cids: tuple[str, ...] = ()
    timestamp: float = field(default_factory=time.time)
    bodes_passed: bool = False
    constitutional_hash: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "cid",
            "agent_id",
            "payload",
            "payload_type",
            "constitutional_hash",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise TypeError(f"{field_name} must be a string")
        if not isinstance(self.parent_cids, (list, tuple)) or any(
            not isinstance(parent, str) for parent in self.parent_cids
        ):
            raise TypeError("parent_cids must be a sequence of strings")
        parents = tuple(self.parent_cids)
        if len(set(parents)) != len(parents):
            raise ValueError("parent_cids must not contain duplicates")
        if type(self.bodes_passed) is not bool:
            raise TypeError("bodes_passed must be a boolean")
        normalized = _normalize_metadata(self.metadata)
        object.__setattr__(self, "parent_cids", parents)
        object.__setattr__(self, "metadata", normalized)

    def to_canonical_dict(self) -> dict[str, Any]:
        """The fields that define the CID (everything except cid itself)."""
        return {
            "agent_id": self.agent_id,
            "payload": self.payload,
            "payload_type": self.payload_type,
            "parent_cids": list(self.parent_cids),
            "bodes_passed": self.bodes_passed,
            "constitutional_hash": self.constitutional_hash,
            "metadata": thaw_json_value(self.metadata),
        }

    def verify_cid(self) -> bool:
        """Verify this node's CID matches its canonical content."""
        expected = _sha256_hex(_canonical_bytes(self.to_canonical_dict()))
        return self.cid == expected


def compute_cid(
    agent_id: str,
    payload: str,
    parent_cids: tuple[str, ...],
    *,
    payload_type: str = "artifact",
    bodes_passed: bool = False,
    constitutional_hash: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    """Compute the CID for a node before constructing it."""
    normalized_metadata = _normalize_metadata(metadata or {})
    data = {
        "agent_id": agent_id,
        "payload": payload,
        "payload_type": payload_type,
        "parent_cids": list(parent_cids),
        "bodes_passed": bodes_passed,
        "constitutional_hash": constitutional_hash,
        "metadata": thaw_json_value(normalized_metadata),
    }
    return _sha256_hex(_canonical_bytes(data))


class MerkleCRDT:
    """Local replica of the Merkle-CRDT artifact DAG.

    Each agent in the swarm maintains one instance. Replicas are synchronized
    via merge() — the CRDT operation that takes the set union of nodes.

    Merge is:
        - Commutative: merge(A, B) == merge(B, A)
        - Associative: merge(merge(A, B), C) == merge(A, merge(B, C))
        - Idempotent: merge(A, A) == A

    These properties guarantee eventual consistency without coordination.

    Thread-safe: all mutations protected by a lock for concurrent agent access.

    Args:
        agent_id: The owning agent's identifier.
        reject_unverified: If True, reject nodes whose CID doesn't verify.
            Enables Byzantine fault tolerance at the cost of rejecting
            nodes from buggy (but not malicious) implementations.
    """

    def __init__(self, agent_id: str, *, reject_unverified: bool = True) -> None:
        self.agent_id = agent_id
        self._reject_unverified = reject_unverified
        self._nodes: dict[str, DAGNode] = {}  # cid → node
        self._children: dict[str, set[str]] = {}  # cid → set of child cids
        self._heads: set[str] = set()
        self._causally_closed: set[str] = set()
        self._missing_parent_count: dict[str, int] = {}
        self._lock = threading.Lock()

    # ──────────────────────────────────────────────────────────────────────
    # Append
    # ──────────────────────────────────────────────────────────────────────

    def append(
        self,
        payload: str,
        *,
        payload_type: str = "artifact",
        bodes_passed: bool = False,
        constitutional_hash: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> DAGNode:
        """Create and store a new node linked to the current DAG heads.

        The new node's parent_cids are the current frontier (all DAG heads),
        establishing causal ordering: this node happened-after all current heads.

        Returns the newly created DAGNode.
        """
        with self._lock:
            heads = self._heads_unlocked()
            parent_cids = tuple(sorted(heads))

            cid = compute_cid(
                self.agent_id,
                payload,
                parent_cids,
                payload_type=payload_type,
                bodes_passed=bodes_passed,
                constitutional_hash=constitutional_hash,
                metadata=metadata or {},
            )

            node = DAGNode(
                cid=cid,
                agent_id=self.agent_id,
                payload=payload,
                payload_type=payload_type,
                parent_cids=parent_cids,
                bodes_passed=bodes_passed,
                constitutional_hash=constitutional_hash,
                metadata=metadata or {},
            )

            self._store_unlocked(node)
            return node

    # ──────────────────────────────────────────────────────────────────────
    # Merge (the CRDT operation)
    # ──────────────────────────────────────────────────────────────────────

    def merge(self, other: MerkleCRDT) -> int:
        """Merge another replica's DAG into this one.

        Takes the set union of nodes. Nodes already present (by CID) are
        skipped. New nodes are validated (CID integrity check) before insertion.

        Returns the number of new nodes added.
        """
        with other._lock:
            remote_nodes = list(other._nodes.values())

        added = 0
        with self._lock:
            for node in remote_nodes:
                if node.cid in self._nodes:
                    continue  # Already have it — idempotent

                if self._reject_unverified and not node.verify_cid():
                    continue  # Byzantine rejection

                self._store_unlocked(node)
                added += 1

        return added

    def merge_nodes(self, nodes: list[DAGNode]) -> int:
        """Merge a list of nodes (from network gossip) into this replica.

        Same as merge() but accepts raw nodes instead of a MerkleCRDT instance.
        Useful for network-layer integration where full replica isn't available.

        Returns the number of new nodes added.
        """
        added = 0
        with self._lock:
            for node in nodes:
                if node.cid in self._nodes:
                    continue
                if self._reject_unverified and not node.verify_cid():
                    continue
                self._store_unlocked(node)
                added += 1
        return added

    # ──────────────────────────────────────────────────────────────────────
    # DAG queries
    # ──────────────────────────────────────────────────────────────────────

    @property
    def heads(self) -> frozenset[str]:
        """Current DAG frontier — nodes with no children (causal tips)."""
        with self._lock:
            return self._heads_unlocked()

    def _heads_unlocked(self) -> frozenset[str]:
        """Heads computation without lock (caller must hold lock)."""
        return frozenset(self._heads)

    def get(self, cid: str) -> DAGNode | None:
        """Retrieve a node by CID."""
        with self._lock:
            return self._nodes.get(cid)

    def frontier_snapshot(self) -> tuple[str, ...]:
        """Return a deterministic immutable snapshot of the current frontier."""
        with self._lock:
            return tuple(sorted(self._heads_unlocked()))

    def get_many(
        self, cids: list[str] | tuple[str, ...], *, limit: int
    ) -> list[DAGNode]:
        """Return up to ``limit`` requested nodes in deterministic CID order."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            return [
                self._nodes[cid]
                for cid in sorted(set(cids))[:limit]
                if cid in self._nodes
            ]

    def missing_ancestry(
        self,
        frontier: list[str] | tuple[str, ...],
        *,
        limit: int,
        scan_limit: int | None = None,
    ) -> tuple[str, ...]:
        """Find missing CIDs needed to causally close an advertised frontier."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        max_scan = scan_limit if scan_limit is not None else max(limit * 16, limit)
        if max_scan <= 0:
            raise ValueError("scan_limit must be positive")
        with self._lock:
            pending = list(reversed(sorted(set(frontier))))
            seen: set[str] = set()
            missing: list[str] = []
            scanned = 0
            while pending and len(missing) < limit and scanned < max_scan:
                cid = pending.pop()
                if cid in seen:
                    continue
                seen.add(cid)
                scanned += 1
                if cid in self._causally_closed:
                    continue
                node = self._nodes.get(cid)
                if node is None:
                    missing.append(cid)
                    continue
                pending.extend(reversed(sorted(node.parent_cids)))
            checkpoints: list[str] = []
            while pending and len(checkpoints) < limit:
                cid = pending.pop()
                if cid not in seen and cid not in self._causally_closed:
                    checkpoints.append(cid)
        if checkpoints and not missing:
            raise AncestryScanLimitExceeded(tuple(sorted(checkpoints)))
        return tuple(sorted(missing))

    def ancestry_nodes(
        self,
        roots: list[str] | tuple[str, ...],
        *,
        limit: int,
    ) -> list[DAGNode]:
        """Return a bounded, head-first ancestry closure for requested roots."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            pending = list(reversed(sorted(set(roots))))
            seen: set[str] = set()
            result: list[DAGNode] = []
            while pending and len(result) < limit:
                cid = pending.pop()
                if cid in seen:
                    continue
                seen.add(cid)
                node = self._nodes.get(cid)
                if node is None:
                    continue
                result.append(node)
                pending.extend(reversed(sorted(node.parent_cids)))
            return result

    @property
    def size(self) -> int:
        """Total number of nodes in the local DAG."""
        with self._lock:
            return len(self._nodes)

    def all_cids(self) -> frozenset[str]:
        """Set of all CIDs in the local DAG."""
        with self._lock:
            return frozenset(self._nodes.keys())

    def topological_order(self) -> list[DAGNode]:
        """Return nodes in causal (topological) order.

        Parents always appear before children. Deterministic: ties broken by CID.
        This is the canonical global ordering that all replicas converge to.
        """
        with self._lock:
            nodes = dict(self._nodes)
            children = {
                cid: tuple(sorted(child for child in child_cids if child in nodes))
                for cid, child_cids in self._children.items()
                if cid in nodes
            }

        # Kahn's algorithm
        in_degree: dict[str, int] = {cid: 0 for cid in nodes}
        for node in nodes.values():
            in_degree[node.cid] = len(
                {parent for parent in node.parent_cids if parent in nodes}
            )

        queue = [cid for cid, degree in in_degree.items() if degree == 0]
        heapq.heapify(queue)
        result: list[DAGNode] = []

        while queue:
            cid = heapq.heappop(queue)
            result.append(nodes[cid])
            for child_cid in children.get(cid, ()):
                in_degree[child_cid] -= 1
                if in_degree[child_cid] == 0:
                    heapq.heappush(queue, child_cid)

        if len(result) != len(nodes):
            raise ValueError("Merkle DAG contains a cycle or inconsistent child index")

        return result

    def verify_integrity(self) -> list[str]:
        """Verify CID integrity of all nodes. Returns list of invalid CIDs."""
        with self._lock:
            nodes = list(self._nodes.values())
        return [node.cid for node in nodes if not node.verify_cid()]

    def summary(self) -> dict[str, Any]:
        """DAG summary statistics."""
        with self._lock:
            agents = set(n.agent_id for n in self._nodes.values())
            bodes_count = sum(1 for n in self._nodes.values() if n.bodes_passed)
            return {
                "total_nodes": len(self._nodes),
                "heads": len(self._heads_unlocked()),
                "agents": len(agents),
                "bodes_validated": bodes_count,
            }

    # ──────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────

    def _store_unlocked(self, node: DAGNode) -> None:
        """Store a node and update the child index. Caller must hold lock."""
        if node.cid in self._nodes:
            return
        self._nodes[node.cid] = node
        self._heads.add(node.cid)
        for parent_cid in node.parent_cids:
            self._children.setdefault(parent_cid, set()).add(node.cid)
            if parent_cid in self._nodes:
                self._heads.discard(parent_cid)
        if any(
            child_cid in self._nodes for child_cid in self._children.get(node.cid, ())
        ):
            self._heads.discard(node.cid)
        self._missing_parent_count[node.cid] = sum(
            parent_cid not in self._causally_closed for parent_cid in node.parent_cids
        )
        if self._missing_parent_count[node.cid] == 0:
            self._close_causality_unlocked(node.cid)

    def _close_causality_unlocked(self, cid: str) -> None:
        """Mark a node and newly satisfied descendants causally closed."""
        pending = [cid]
        while pending:
            closed_cid = pending.pop()
            if closed_cid in self._causally_closed:
                continue
            self._causally_closed.add(closed_cid)
            self._missing_parent_count[closed_cid] = 0
            for child_cid in self._children.get(closed_cid, ()):
                if child_cid not in self._nodes or child_cid in self._causally_closed:
                    continue
                remaining = self._missing_parent_count[child_cid] - 1
                self._missing_parent_count[child_cid] = remaining
                if remaining == 0:
                    pending.append(child_cid)


# ──────────────────────────────────────────────────────────────────────────────
# Async gossip simulator (for testing convergence)
# ──────────────────────────────────────────────────────────────────────────────


async def simulate_gossip_convergence(
    n_agents: int = 5,
    n_rounds: int = 10,
    artifacts_per_round: int = 2,
    gossip_partners: int = 2,
    *,
    seed: int = 42,
) -> dict[str, Any]:
    """Simulate N agents generating artifacts and gossiping DAG heads.

    Each round:
    1. Every agent appends `artifacts_per_round` new nodes to its local DAG.
    2. Every agent gossips with `gossip_partners` random peers (merge).

    After all rounds, checks that all replicas have converged to the same
    set of CIDs (Eventual Epistemic Convergence).

    Returns:
        dict with convergence result, per-agent sizes, and total artifacts.
    """
    import random

    rng = random.Random(seed)
    agents = [MerkleCRDT(f"agent-{i}") for i in range(n_agents)]

    for round_idx in range(n_rounds):
        # Phase 1: each agent generates artifacts
        for agent in agents:
            for art_idx in range(artifacts_per_round):
                agent.append(
                    payload=f"round={round_idx} art={art_idx} by={agent.agent_id}",
                    payload_type="task_output",
                    bodes_passed=True,
                    constitutional_hash="608508a9bd224290",
                )

        # Phase 2: gossip (each agent merges with random peers)
        for agent in agents:
            peers = [a for a in agents if a is not agent]
            selected = rng.sample(peers, min(gossip_partners, len(peers)))
            for peer in selected:
                agent.merge(peer)

    # Final convergence round: full mesh gossip to ensure convergence
    for agent in agents:
        for peer in agents:
            if peer is not agent:
                agent.merge(peer)

    # Check convergence
    cid_sets = [agent.all_cids() for agent in agents]
    converged = all(s == cid_sets[0] for s in cid_sets)

    sizes = {agent.agent_id: agent.size for agent in agents}
    total_artifacts = n_agents * n_rounds * artifacts_per_round

    return {
        "converged": converged,
        "n_agents": n_agents,
        "n_rounds": n_rounds,
        "total_artifacts": total_artifacts,
        "sizes": sizes,
        "unique_cids": len(cid_sets[0]) if converged else -1,
    }
