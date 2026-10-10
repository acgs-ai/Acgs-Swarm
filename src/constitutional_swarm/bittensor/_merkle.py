"""Count-committed RFC 6962-style Merkle helpers for Bittensor records."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Sequence
from typing import Literal, TypeAlias


MERKLE_VERSION = 2
_DIGEST_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_MAX_LEAF_COUNT = (1 << 64) - 1

MerklePosition: TypeAlias = Literal["left", "right", "promote"]
MerkleStep: TypeAlias = tuple[str, MerklePosition]
MerkleLayers: TypeAlias = tuple[tuple[str, ...], ...]


def is_digest(value: object) -> bool:
    """Return whether *value* is an exact 64-character hexadecimal string."""
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _digest_bytes(value: str, *, name: str) -> bytes:
    if not is_digest(value):
        raise ValueError(f"{name} must be a 64-character hexadecimal digest")
    return bytes.fromhex(value)


def _leaf_node(leaf_hash: str) -> str:
    return hashlib.sha256(b"\x00" + _digest_bytes(leaf_hash, name="leaf hash")).hexdigest()


def _parent_node(left: str, right: str) -> str:
    return hashlib.sha256(
        b"\x01" + _digest_bytes(left, name="left node") + _digest_bytes(right, name="right node")
    ).hexdigest()


def _counted_root(tree_root: str, leaf_count: int) -> str:
    if type(leaf_count) is not int or not 0 <= leaf_count <= _MAX_LEAF_COUNT:
        raise ValueError("leaf_count must be an integer in uint64 range")
    return hashlib.sha256(
        b"\x02" + leaf_count.to_bytes(8, "big") + _digest_bytes(tree_root, name="tree root")
    ).hexdigest()


def build_merkle_layers(leaves: Sequence[str]) -> MerkleLayers:
    """Build immutable domain-separated layers while promoting odd nodes."""
    if isinstance(leaves, (str, bytes, bytearray)):
        raise TypeError("leaves must be a sequence of digests")
    leaf_nodes = tuple(_leaf_node(leaf) for leaf in leaves)
    if not leaf_nodes:
        return ((),)

    layers: list[tuple[str, ...]] = [leaf_nodes]
    current = leaf_nodes
    while len(current) > 1:
        parents: list[str] = []
        for index in range(0, len(current), 2):
            if index + 1 == len(current):
                parents.append(current[index])
            else:
                parents.append(_parent_node(current[index], current[index + 1]))
        current = tuple(parents)
        layers.append(current)
    return tuple(layers)


def merkle_root_from_layers(layers: MerkleLayers, leaf_count: int) -> str:
    """Return the count-committed root for immutable Merkle layers."""
    if type(leaf_count) is not int or not 0 <= leaf_count <= _MAX_LEAF_COUNT:
        raise ValueError("leaf_count must be an integer in uint64 range")
    if leaf_count == 0:
        if layers != ((),):
            raise ValueError("empty leaf set has invalid Merkle layers")
        tree_root = hashlib.sha256(b"").hexdigest()
    else:
        if not layers or len(layers[0]) != leaf_count or len(layers[-1]) != 1:
            raise ValueError("Merkle layers do not match leaf_count")
        tree_root = layers[-1][0]
    return _counted_root(tree_root, leaf_count)


def compute_merkle_root(leaves: Sequence[str]) -> str:
    """Compute a count-committed Merkle root over leaf digests in caller order."""
    layers = build_merkle_layers(leaves)
    return merkle_root_from_layers(layers, len(leaves))


def merkle_path_for_index(layers: MerkleLayers, target_index: int) -> tuple[MerkleStep, ...]:
    """Build an exact-shape path from cached layers for one leaf index."""
    if not layers:
        raise ValueError("Merkle layers are empty")
    leaf_count = len(layers[0])
    if type(target_index) is not int or not 0 <= target_index < leaf_count:
        raise IndexError("target_index is outside the leaf set")

    path: list[MerkleStep] = []
    index = target_index
    for layer in layers[:-1]:
        if index % 2 == 1:
            path.append((layer[index - 1], "left"))
        elif index + 1 < len(layer):
            path.append((layer[index + 1], "right"))
        else:
            path.append(("", "promote"))
        index //= 2
    return tuple(path)


def verify_merkle_path(
    leaf_hash: str,
    path: Sequence[tuple[str, str]],
    expected_root: str,
    *,
    leaf_count: int,
    leaf_index: int,
) -> bool:
    """Verify a path, rejecting malformed digests and impossible proof shapes."""
    try:
        if type(path) not in (list, tuple):
            return False
        if type(leaf_count) is not int or not 1 <= leaf_count <= _MAX_LEAF_COUNT:
            return False
        if type(leaf_index) is not int or not 0 <= leaf_index < leaf_count:
            return False
        _digest_bytes(expected_root, name="expected root")
        current = _leaf_node(leaf_hash)
        width = leaf_count
        index = leaf_index
        step_index = 0

        while width > 1:
            if step_index >= len(path):
                return False
            step = path[step_index]
            if type(step) is not tuple or len(step) != 2:
                return False
            sibling, position = step
            if type(sibling) is not str or type(position) is not str:
                return False

            if index % 2 == 1:
                if position != "left":
                    return False
                current = _parent_node(sibling, current)
            elif index + 1 < width:
                if position != "right":
                    return False
                current = _parent_node(current, sibling)
            else:
                if position != "promote" or sibling != "":
                    return False

            width = (width + 1) // 2
            index //= 2
            step_index += 1

        if step_index != len(path):
            return False
        actual_root = _counted_root(current, leaf_count)
        return hmac.compare_digest(actual_root, expected_root.lower())
    except (TypeError, ValueError):
        return False
