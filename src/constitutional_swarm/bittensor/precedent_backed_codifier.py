"""Precedent-backed codifier — closes the CAME auto-constitution loop.

``CAMECoordinator`` is deliberately precedent-agnostic. When the MAP-Elites
grid hits a ceiling it delegates rule codification entirely to its codifier,
passing an *empty* ``live_approaches`` list — feeding raw, unadmitted
``MinerApproach`` grid data into rule proposal would bypass canonical
precedent admission, which is exactly what the coordinator refuses to do (see
``CAMECoordinator`` docstring and PR #118). Consequently a plain
:class:`~constitutional_swarm.bittensor.rule_codifier.RuleCodifier` wired into
the coordinator always receives an empty precedent list and proposes nothing,
even at ceiling.

:class:`PrecedentBackedCodifier` is the sanctioned adapter that closes that
loop. It observes exact active snapshots from an explicit
:class:`~constitutional_swarm.bittensor.precedent_store.PrecedentStore` and
ignores the grid argument entirely, feeding its accumulated precedents into a
real ``RuleCodifier``. Store admission verifies at least five distinct authorized
signed voter envelopes and recomputes the 3/5 outcome from their bound evidence.
The coordinator stays precedent-agnostic; this codifier is where admitted
precedent enters the pipeline.

Usage::

    from constitutional_swarm.bittensor import (
        CAMECoordinator,
        PrecedentBackedCodifier,
        PrecedentRecord,
        PrecedentStore,
    )
    from constitutional_swarm.constants import CONSTITUTIONAL_HASH

    store = PrecedentStore(
        CONSTITUTIONAL_HASH,
        vote_registry=provisioned_vote_registry,
    )
    codifier = PrecedentBackedCodifier(
        precedent_store=store,
        min_cluster_size=5,
    )
    for record in validated_precedents:
        canonical = store.admit(record)
        codifier.observe(canonical)

    coordinator = CAMECoordinator(codifier=codifier)
    result = coordinator.evolve_cycle(approaches)
    # On a ceiling cycle, result.rules_proposed holds proposed rule texts (str).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from constitutional_swarm.bittensor.precedent_store import PrecedentStore
from constitutional_swarm.bittensor.rule_codifier import RuleCodifier
from constitutional_swarm.constants import CONSTITUTIONAL_HASH

if TYPE_CHECKING:
    from collections.abc import Iterable

    from constitutional_swarm.bittensor.precedent_store import PrecedentRecord


class PrecedentBackedCodifier:
    """A real :class:`RuleCodifier` fed by an accumulated precedent stream.

    Presents the duck-typed ``find_clusters`` / ``propose_rules`` interface
    that :class:`~constitutional_swarm.bittensor.came_coordinator.CAMECoordinator`
    expects, but sources clusters from its own store-admitted precedents rather
    than from the live MAP-Elites grid. This is the loop-closing adapter: the
    coordinator is intentionally precedent-agnostic, so this class observes an
    explicit canonical ``PrecedentRecord`` stream.

    Parameters
    ----------
    codifier:
        A pre-built :class:`RuleCodifier` to wrap. If ``None`` (the default), a
        fresh one is constructed from the tuning knobs below.
    precedents:
        Optional iterable of records already admitted to ``precedent_store`` to
        seed the observed stream; equivalent to calling :meth:`observe_many`
        afterwards.
    precedent_store:
        Canonical admission store for records observed by a newly constructed
        codifier. Populated workflows must admit records to this same instance
        before observation. Cannot be supplied with ``codifier``.
    constitutional_hash:
        Hash pin for the constructed codifier. Defaults to the package-wide
        :data:`~constitutional_swarm.constants.CONSTITUTIONAL_HASH`. Ignored
        when ``codifier`` is supplied.
    min_cluster_size:
        Minimum precedents in a cluster before it may be proposed as a rule.
        Ignored when ``codifier`` is supplied.
    min_validator_agreement:
        Minimum mean validator grade for a cluster to be proposed. Ignored when
        ``codifier`` is supplied.
    similarity_threshold:
        Cosine-similarity threshold for agglomerative precedent clustering.
        Ignored when ``codifier`` is supplied.
    """

    def __init__(
        self,
        codifier: RuleCodifier | None = None,
        *,
        precedents: Iterable[PrecedentRecord] | None = None,
        precedent_store: PrecedentStore | None = None,
        constitutional_hash: str = CONSTITUTIONAL_HASH,
        min_cluster_size: int = 5,
        min_validator_agreement: float = 0.85,
        similarity_threshold: float = 0.80,
    ) -> None:
        if codifier is not None and precedent_store is not None:
            raise ValueError("precedent_store cannot be supplied with a pre-built codifier")
        self.inner: RuleCodifier = codifier or RuleCodifier(
            constitutional_hash=constitutional_hash,
            min_cluster_size=min_cluster_size,
            min_validator_agreement=min_validator_agreement,
            similarity_threshold=similarity_threshold,
            precedent_store=precedent_store,
        )
        self._precedent_ids: list[str] = []
        if precedents:
            self.observe_many(precedents)

    @property
    def precedent_store(self) -> PrecedentStore:
        """Return the explicit admission store or fail before evidence use."""
        return self.inner.precedent_store

    @property
    def precedents(self) -> list[PrecedentRecord]:
        """Defensive snapshots of observed records that remain active."""
        if not self._precedent_ids:
            return []
        active = {record.precedent_id: record for record in self.precedent_store.active_records()}
        return [active[precedent_id] for precedent_id in self._precedent_ids if precedent_id in active]

    def observe(self, precedent: PrecedentRecord) -> None:
        """Observe an exact record already admitted to the configured store."""
        [canonical] = self.precedent_store.require_canonical_records([precedent])
        if canonical.precedent_id not in self._precedent_ids:
            self._precedent_ids.append(canonical.precedent_id)

    def observe_many(self, precedents: Iterable[PrecedentRecord]) -> None:
        """Append several validated precedents to the internal stream."""
        for precedent in precedents:
            self.observe(precedent)

    def find_clusters(self, _live_approaches: list) -> list:
        """Cluster the accumulated precedents, ignoring the live grid argument.

        The ``_live_approaches`` argument is deliberately discarded: the whole
        point of this adapter is that codification is driven by the validated
        precedent stream, never by raw grid approaches (PR #118).
        """
        return self.inner.find_clusters(self.precedents)

    def propose_rules(self, clusters: list) -> list[str]:
        """Propose rule texts for the qualifying clusters.

        Returns plain rule-text strings (not ``RuleCandidate`` objects), which
        is what ``MacAcgsLoop`` consumes downstream.
        """
        return [candidate.rule_text for candidate in self.inner.propose_rules(clusters)]
