"""Abliteration-aware node admission for quorum committee selection.

Bridges the abliteration detector (:mod:`constitutional_swarm.eval.monotonic_mas.
abliteration_detector`) and the quorum :class:`~constitutional_swarm.validator_set.
CommitteeSelector`: before a committee is sampled, candidate validators whose
residual-stream write matrices show a collapsed refusal direction are screened
out so an abliterated model cannot be admitted to quorum.

The gate uses the ``"min"`` aggregation preset by default -- the strictest
setting, which flags a candidate if *any* probed write matrix has been
abliterated against the refusal direction. This deliberately favors keeping a
tampered model out of quorum over admitting a partially-abliterated one, closing
the minority-subset evasion that the ``"median"`` default cannot see (see
``docs/internal/abliteration_threat_model.md`` and dogfood finding F1).

The screen requires candidate *weights*, so it runs wherever an operator has
access to a candidate node's residual-stream write matrices (the ``research``
deployment with a live model). It does not modify any model and is independent
of the VRF committee sampling itself -- it only contributes to the ``exclude``
set that :meth:`CommitteeSelector.select` already honors.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

import numpy as np

from .eval.monotonic_mas.abliteration_detector import (
    AbliterationReport,
    detect_from_activations,
    detect_from_weights,
)
from .validator_set import CommitteeSelection, CommitteeSelector

__all__ = [
    "AbliterationAdmissionGate",
    "ActivationAdmissionGate",
    "ActivationProbe",
    "AdmissionDecision",
]


@dataclass(frozen=True)
class AdmissionDecision:
    """Outcome of screening candidate validators for abliteration.

    ``admitted`` and ``rejected`` partition the screened agent ids (each sorted
    for determinism). ``reports`` maps every screened agent id to its
    :class:`AbliterationReport`, so a caller can log *why* a node was rejected or
    down-weight rather than exclude.
    """

    admitted: tuple[str, ...]
    rejected: tuple[str, ...]
    reports: Mapping[str, AbliterationReport]

    @property
    def rejected_set(self) -> frozenset[str]:
        """The rejected agent ids as a set, ready to feed ``select(exclude=...)``."""
        return frozenset(self.rejected)


_Candidate = TypeVar("_Candidate")


def _partition(
    candidates: Mapping[str, _Candidate],
    evaluate: Callable[[_Candidate], AbliterationReport],
) -> AdmissionDecision:
    """Run ``evaluate`` on each candidate payload and partition the agent ids.

    Shared by the weight- and activation-based gates: only the per-candidate
    ``evaluate`` differs. Propagates ``ValueError`` from the detector for a
    malformed candidate.
    """
    reports: dict[str, AbliterationReport] = {}
    admitted: list[str] = []
    rejected: list[str] = []
    for agent_id, payload in candidates.items():
        report = evaluate(payload)
        reports[agent_id] = report
        (rejected if report.abliterated else admitted).append(agent_id)
    return AdmissionDecision(
        admitted=tuple(sorted(admitted)),
        rejected=tuple(sorted(rejected)),
        reports=reports,
    )


def _select_with_exclusions(
    selector: CommitteeSelector,
    seed: str,
    committee_size: int,
    decision: AdmissionDecision,
    *,
    exclude: Sequence[str],
    require_independent: bool,
    threshold_fraction: float,
    max_retries: int,
) -> CommitteeSelection:
    """Select a committee with the decision's rejected ids unioned into ``exclude``.

    A flagged node can never be sampled into the committee. With
    ``require_independent`` the fault-domain-aware
    :meth:`CommitteeSelector.select_until_independent` is used.
    """
    full_exclude = tuple(frozenset(exclude) | decision.rejected_set)
    if require_independent:
        return selector.select_until_independent(
            seed,
            committee_size,
            exclude=full_exclude,
            threshold_fraction=threshold_fraction,
            max_retries=max_retries,
        )
    return selector.select(seed, committee_size, exclude=full_exclude)


class AbliterationAdmissionGate:
    """Screen candidate validators by abliteration before quorum admission.

    Parameters
    ----------
    direction:
        Unit (or unnormalized) refusal direction in residual-stream space,
        re-extracted from a trusted reference model
        (:func:`~constitutional_swarm.eval.monotonic_mas.abliteration_detector.refusal_direction`).
    reference:
        Optional trusted-model write matrices (matrix name -> ``[d_model, d_in]``)
        used for the reference-ratio test. When omitted, the absolute-floor test
        is used instead. The same reference is compared against every candidate.
    aggregate:
        Per-matrix aggregation preset. Defaults to ``"min"`` (strictest: flag if
        any single write matrix collapses). See :func:`detect_from_weights`.
    ratio_threshold, abs_floor, quantile:
        Forwarded to :func:`detect_from_weights`.
    """

    def __init__(
        self,
        direction: np.ndarray,
        *,
        reference: Mapping[str, np.ndarray] | None = None,
        aggregate: str = "min",
        ratio_threshold: float = 0.25,
        abs_floor: float = 1e-3,
        quantile: float = 0.25,
    ) -> None:
        # Validated downstream by detect_from_weights / _unit; copy the direction
        # so a caller mutating their array can't change the gate's verdict.
        self._direction = np.array(direction, dtype=np.float64)
        self._reference = reference
        self._aggregate = aggregate
        self._ratio_threshold = ratio_threshold
        self._abs_floor = abs_floor
        self._quantile = quantile

    def evaluate(self, write_matrices: Mapping[str, np.ndarray]) -> AbliterationReport:
        """Run the configured detector on one candidate's write matrices."""
        return detect_from_weights(
            write_matrices,
            self._direction,
            reference=self._reference,
            ratio_threshold=self._ratio_threshold,
            abs_floor=self._abs_floor,
            aggregate=self._aggregate,
            quantile=self._quantile,
        )

    def screen(
        self,
        candidate_write_matrices: Mapping[str, Mapping[str, np.ndarray]],
    ) -> AdmissionDecision:
        """Screen each candidate ``agent_id -> {matrix_name: W}`` for abliteration.

        Returns an :class:`AdmissionDecision` partitioning the candidates into
        admitted / rejected with a per-agent report. Propagates ``ValueError``
        from the detector for a malformed candidate (e.g. empty matrices).
        """
        return _partition(candidate_write_matrices, self.evaluate)

    def select_admissible(
        self,
        selector: CommitteeSelector,
        seed: str,
        committee_size: int,
        candidate_write_matrices: Mapping[str, Mapping[str, np.ndarray]],
        *,
        exclude: Sequence[str] = (),
        require_independent: bool = False,
        threshold_fraction: float = 2 / 3,
        max_retries: int = 8,
    ) -> tuple[CommitteeSelection, AdmissionDecision]:
        """Screen candidates, then select a committee with abliterated nodes excluded.

        The gate's rejected ids are unioned with ``exclude`` (e.g. the producer
        under MACI) and passed to the selector, so a flagged node can never be
        sampled into the committee. With ``require_independent=True`` the
        fault-domain-aware :meth:`CommitteeSelector.select_until_independent` is
        used; otherwise plain :meth:`CommitteeSelector.select`.

        Returns the :class:`CommitteeSelection` and the :class:`AdmissionDecision`
        so the caller can audit which candidates were screened out and why.
        """
        decision = self.screen(candidate_write_matrices)
        selection = _select_with_exclusions(
            selector,
            seed,
            committee_size,
            decision,
            exclude=exclude,
            require_independent=require_independent,
            threshold_fraction=threshold_fraction,
            max_retries=max_retries,
        )
        return selection, decision


@dataclass(frozen=True)
class ActivationProbe:
    """Harmful/benign final-hidden-state activations for one candidate node.

    Each array is ``[n, d_model]`` -- ``n`` prompts, the last-token hidden state
    at the probed layer -- for the harmful and harmless prompt sets respectively.
    This is the input to :func:`detect_from_activations`.
    """

    harmful: np.ndarray
    harmless: np.ndarray


class ActivationAdmissionGate:
    """Screen candidate validators by harmful/benign separation collapse.

    The activation-path counterpart to :class:`AbliterationAdmissionGate`, for
    nodes that expose final-hidden-state activations but **not** residual-stream
    write matrices. Abliteration collapses the Euclidean distance between mean
    harmful and mean harmless representations (arXiv:2505.19056); a candidate
    whose separation drops below ``ratio_threshold`` of the trusted
    ``reference_separation`` is rejected from quorum admission.

    Parameters
    ----------
    reference_separation:
        :func:`~constitutional_swarm.eval.monotonic_mas.abliteration_detector.latent_separation`
        measured on a trusted (un-abliterated) model with the same prompt sets.
    ratio_threshold:
        Reject below this fraction of the reference separation (default 0.75 --
        abliteration typically collapses separation by 28-38%). Forwarded to
        :func:`detect_from_activations`.
    """

    def __init__(
        self,
        reference_separation: float,
        *,
        ratio_threshold: float = 0.75,
    ) -> None:
        # detect_from_activations re-validates per call; check here too so a
        # misconfigured gate fails at construction rather than first screen.
        if not np.isfinite(reference_separation) or reference_separation <= 0.0:
            msg = "reference_separation must be finite and positive"
            raise ValueError(msg)
        self._reference_separation = float(reference_separation)
        self._ratio_threshold = ratio_threshold

    def evaluate(self, probe: ActivationProbe) -> AbliterationReport:
        """Run the separation-collapse detector on one candidate's activations."""
        return detect_from_activations(
            probe.harmful,
            probe.harmless,
            reference_separation=self._reference_separation,
            ratio_threshold=self._ratio_threshold,
        )

    def screen(
        self,
        candidate_activations: Mapping[str, ActivationProbe],
    ) -> AdmissionDecision:
        """Screen each candidate ``agent_id -> ActivationProbe`` for abliteration.

        Returns an :class:`AdmissionDecision` partitioning the candidates into
        admitted / rejected with a per-agent report. Propagates ``ValueError``
        from the detector for a malformed candidate (e.g. empty or
        dimension-mismatched activations).
        """
        return _partition(candidate_activations, self.evaluate)

    def select_admissible(
        self,
        selector: CommitteeSelector,
        seed: str,
        committee_size: int,
        candidate_activations: Mapping[str, ActivationProbe],
        *,
        exclude: Sequence[str] = (),
        require_independent: bool = False,
        threshold_fraction: float = 2 / 3,
        max_retries: int = 8,
    ) -> tuple[CommitteeSelection, AdmissionDecision]:
        """Screen candidates, then select a committee with collapsed nodes excluded.

        Mirrors :meth:`AbliterationAdmissionGate.select_admissible`: the gate's
        rejected ids are unioned with ``exclude`` and passed to the selector, so a
        flagged node can never be sampled into the committee. Returns the
        :class:`CommitteeSelection` and the :class:`AdmissionDecision`.
        """
        decision = self.screen(candidate_activations)
        selection = _select_with_exclusions(
            selector,
            seed,
            committee_size,
            decision,
            exclude=exclude,
            require_independent=require_independent,
            threshold_fraction=threshold_fraction,
            max_retries=max_retries,
        )
        return selection, decision
