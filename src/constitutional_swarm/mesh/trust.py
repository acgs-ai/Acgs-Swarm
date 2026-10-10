"""ID-stable canonical trust state for the Constitutional Mesh."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TrustSnapshot:
    """Detached trust snapshot whose identity is agent IDs, not matrix indexes."""

    agent_ids: tuple[str, ...]
    matrix: tuple[tuple[float, ...], ...]
    round_number: int

    def value(self, from_agent: str, to_agent: str) -> float:
        """Return one directional value by stable agent identity."""
        indices = {agent_id: index for index, agent_id in enumerate(self.agent_ids)}
        return self.matrix[indices[from_agent]][indices[to_agent]]


@dataclass(frozen=True, slots=True)
class _ArchivedTrust:
    """Directional relationships captured at a trust-round boundary."""

    relationships: dict[str, tuple[float, float, int]]


class _TrustState:
    """Single owner of membership order and canonical directional trust values."""

    def __init__(self, *, decay_rate: float, archive_limit: int) -> None:
        self._agent_ids: list[str] = []
        self._values: dict[tuple[str, str], float] = {}
        self._archive: dict[str, _ArchivedTrust] = {}
        self._round = 0
        self._decay_rate = decay_rate
        self._archive_limit = archive_limit

    @property
    def indices(self) -> dict[str, int]:
        return {agent_id: index for index, agent_id in enumerate(self._agent_ids)}

    @property
    def values(self) -> dict[tuple[str, str], float]:
        return dict(self._values)

    @property
    def archive(self) -> dict[str, _ArchivedTrust]:
        return {
            agent_id: _ArchivedTrust(dict(archived.relationships))
            for agent_id, archived in self._archive.items()
        }

    @property
    def round_number(self) -> int:
        return self._round

    def register(self, agent_id: str) -> None:
        if agent_id in self._agent_ids:
            return
        self._agent_ids.append(agent_id)
        archived = self._archive.get(agent_id)
        if archived is not None:
            remaining: dict[str, tuple[float, float, int]] = {}
            for partner_id, relationship in archived.relationships.items():
                if partner_id in self._agent_ids:
                    self._restore_pair(agent_id, partner_id, relationship)
                else:
                    remaining[partner_id] = relationship
            self._replace_archive(agent_id, remaining)

        # If this agent returned second, complete relationships retained by an
        # already-active archive owner. A pair is restored only when both IDs
        # are active, so rejoin order cannot discard trust.
        for owner_id, owner_archive in list(self._archive.items()):
            if owner_id == agent_id or owner_id not in self._agent_ids:
                continue
            returning_relationship = owner_archive.relationships.get(agent_id)
            if returning_relationship is None:
                continue
            self._restore_pair(owner_id, agent_id, returning_relationship)
            remaining = dict(owner_archive.relationships)
            remaining.pop(agent_id)
            self._replace_archive(owner_id, remaining)

    def unregister(self, agent_id: str) -> None:
        if agent_id not in self._agent_ids:
            return
        existing = self._archive.pop(agent_id, None)
        relationships = {} if existing is None else dict(existing.relationships)
        for partner_id in self._agent_ids:
            if partner_id == agent_id:
                continue
            outgoing = self._values.get((agent_id, partner_id), 0.0)
            incoming = self._values.get((partner_id, agent_id), 0.0)
            if outgoing != 0.0 or incoming != 0.0:
                relationships[partner_id] = (outgoing, incoming, self._round)
        if relationships:
            if len(self._archive) >= self._archive_limit:
                oldest = min(
                    self._archive,
                    key=lambda archived_id: min(
                        relationship[2]
                        for relationship in self._archive[
                            archived_id
                        ].relationships.values()
                    ),
                )
                self._archive.pop(oldest)
            self._archive[agent_id] = _ArchivedTrust(relationships)
        self._agent_ids.remove(agent_id)
        self._values = {
            pair: value for pair, value in self._values.items() if agent_id not in pair
        }

    def apply_updates(self, updates: list[tuple[str, str, float]]) -> None:
        for from_agent, to_agent, delta in updates:
            if from_agent not in self._agent_ids or to_agent not in self._agent_ids:
                raise KeyError(
                    f"unknown trust agent pair: {from_agent!r}, {to_agent!r}"
                )
            if not math.isfinite(delta):
                raise ValueError(f"trust delta must be finite, got {delta!r}")
        if not updates:
            return
        for from_agent, to_agent, delta in updates:
            self._set(
                from_agent,
                to_agent,
                self._values.get((from_agent, to_agent), 0.0) + delta,
            )
        self._round += 1

    def advance_rounds(self, count: int) -> None:
        if count < 0:
            raise ValueError("trust rounds must be non-negative")
        self._round += count

    def reset(self) -> None:
        self._values.clear()
        self._archive.clear()
        self._round = 0

    def raw_snapshot(self) -> TrustSnapshot:
        matrix = tuple(
            tuple(
                self._values.get((from_agent, to_agent), 0.0)
                for to_agent in self._agent_ids
            )
            for from_agent in self._agent_ids
        )
        return TrustSnapshot(tuple(self._agent_ids), matrix, self._round)

    def _set(self, from_agent: str, to_agent: str, value: float) -> None:
        if value == 0.0:
            self._values.pop((from_agent, to_agent), None)
        else:
            self._values[(from_agent, to_agent)] = value

    def _restore_pair(
        self,
        owner_id: str,
        partner_id: str,
        relationship: tuple[float, float, int],
    ) -> None:
        outgoing, incoming, archived_round = relationship
        elapsed = max(0, self._round - archived_round)
        decay = (1.0 - self._decay_rate) ** elapsed
        self._set(owner_id, partner_id, outgoing * decay)
        self._set(partner_id, owner_id, incoming * decay)

    def _replace_archive(
        self,
        agent_id: str,
        relationships: dict[str, tuple[float, float, int]],
    ) -> None:
        if relationships:
            self._archive[agent_id] = _ArchivedTrust(relationships)
        else:
            self._archive.pop(agent_id, None)
