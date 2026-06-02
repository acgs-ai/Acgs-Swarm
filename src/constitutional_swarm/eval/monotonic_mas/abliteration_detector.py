"""Abliteration detector for swarm node admission / trust.

Detects whether a candidate model has been *abliterated* -- had its safety
refusal mechanism removed by orthogonalizing the residual-stream write matrices
against the "refusal direction" (Arditi et al., "Refusal in Language Models Is
Mediated by a Single Direction", arXiv:2406.11717; automated by Heretic,
github.com/p-e-w/heretic).

`constitutional_swarm` externalizes governance (``AgentDNA.validate`` on outputs,
mesh peer quorum, Z3), so it catches a *violation* regardless of whether the
emitting model is aligned. What it could not previously do is detect that an
agent's model has been *tampered* -- which matters because (a) the activation
steering in ``latent_dna`` / ``violation_subspace`` operates in the same space
abliteration attacks and silently loses efficacy on an abliterated model, and
(b) the mesh's Byzantine tolerance assumes fewer than 1/3 of peers are
compromised, with no way to count abliterated ones. This module supplies the
missing signal so abliterated agents can be flagged, down-weighted, or excluded
from quorum.

Two complementary, published detection signals are implemented, both pure-numpy
(no torch / live model required to run the detector logic or its tests):

1. **Weight null-space signature** (mechanistically exact). The abliteration edit
   ``W' = (I - r rᵀ) W`` forces ``rᵀ W' = 0`` for every residual-stream *write*
   matrix (attention out-projection ``W_O``, MLP down-projection ``W_out``). So
   the "refusal energy" ``‖rᵀ W‖ / ‖W‖_F`` collapses toward zero when abliterated.
2. **Latent-separation collapse** (arXiv:2505.19056, "An Embarrassingly Simple
   Defense Against LLM Abliteration Attacks"). Abliteration collapses the
   Euclidean distance between mean harmful and mean benign final-hidden-state
   representations by ~28-38%; a low ratio versus a trusted reference is a flag.

This is a measurement/admission tool. It does not modify any model.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import numpy as np

__all__ = [
    "refusal_direction",
    "apply_abliteration",
    "weight_refusal_energy",
    "latent_separation",
    "AbliterationReport",
    "detect_from_weights",
    "detect_from_activations",
]


def _unit(vector: np.ndarray) -> np.ndarray:
    """Return ``vector`` normalized to unit length, or raise on a zero vector."""

    vector = np.asarray(vector, dtype=np.float64).reshape(-1)
    norm = float(np.linalg.norm(vector))
    if not np.isfinite(norm):
        msg = "vector contains NaN or Inf; cannot normalize"
        raise ValueError(msg)
    if norm == 0.0:
        msg = "refusal direction is the zero vector; cannot normalize"
        raise ValueError(msg)
    return vector / norm


def _require_finite(name: str, array: np.ndarray) -> None:
    """Raise if ``array`` contains NaN or Inf values."""

    if not np.all(np.isfinite(array)):
        msg = f"{name} contains NaN or Inf"
        raise ValueError(msg)


def refusal_direction(harmful: np.ndarray, harmless: np.ndarray) -> np.ndarray:
    """Extract a unit refusal direction by difference-of-means.

    ``harmful`` and ``harmless`` are ``[n, d_model]`` arrays of residual-stream
    activations (e.g. last-token, at one layer) for harmful and harmless prompts.
    The direction is ``mean(harmful) - mean(harmless)``, unit-normalized -- the
    Arditi et al. extraction.
    """

    harmful = np.asarray(harmful, dtype=np.float64)
    harmless = np.asarray(harmless, dtype=np.float64)
    if harmful.ndim != 2 or harmless.ndim != 2:
        msg = "harmful and harmless activations must be 2D [n, d_model] arrays"
        raise ValueError(msg)
    if harmful.shape[0] == 0 or harmless.shape[0] == 0:
        msg = "harmful and harmless activations must not be empty"
        raise ValueError(msg)
    if harmful.shape[1] == 0 or harmless.shape[1] == 0:
        msg = "harmful and harmless activation dimension must not be empty"
        raise ValueError(msg)
    if harmful.shape[1] != harmless.shape[1]:
        msg = f"activation dim mismatch: {harmful.shape[1]} vs {harmless.shape[1]}"
        raise ValueError(msg)
    _require_finite("harmful activations", harmful)
    _require_finite("harmless activations", harmless)
    return _unit(harmful.mean(axis=0) - harmless.mean(axis=0))


def apply_abliteration(write_matrix: np.ndarray, direction: np.ndarray) -> np.ndarray:
    """Return the abliterated write matrix ``W' = (I - r rᵀ) W``.

    Models the Heretic / Arditi weight edit for a residual-stream write matrix
    ``W`` of shape ``[d_model, d_in]`` against unit ``direction`` ``r`` in
    ``R^{d_model}``. Provided so callers can build reference/adversarial fixtures
    and so the detector's signal is verifiable end to end.
    """

    matrix = np.asarray(write_matrix, dtype=np.float64)
    if matrix.ndim != 2:
        msg = "write_matrix must be a 2D [d_model, d_in] array"
        raise ValueError(msg)
    if matrix.shape[0] == 0 or matrix.shape[1] == 0:
        msg = "write_matrix dimensions must not be empty"
        raise ValueError(msg)
    _require_finite("write_matrix", matrix)
    r = _unit(direction)
    if r.shape[0] != matrix.shape[0]:
        msg = f"direction dim {r.shape[0]} != write-matrix output dim {matrix.shape[0]}"
        raise ValueError(msg)
    # W - r (rᵀ W): remove the refusal component from the matrix's output space.
    return matrix - np.outer(r, r @ matrix)


def weight_refusal_energy(write_matrix: np.ndarray, direction: np.ndarray) -> float:
    """Refusal energy ``‖rᵀ W‖ / ‖W‖_F`` of a residual-stream write matrix.

    High for a clean matrix; ~0 for one abliterated against ``direction`` (since
    ``rᵀ W' = 0`` after the edit). ``‖W‖_F`` normalizes out raw matrix scale so
    the value is comparable across matrices.
    """

    matrix = np.asarray(write_matrix, dtype=np.float64)
    if matrix.ndim != 2:
        msg = "write_matrix must be a 2D [d_model, d_in] array"
        raise ValueError(msg)
    if matrix.shape[0] == 0 or matrix.shape[1] == 0:
        msg = "write_matrix dimensions must not be empty"
        raise ValueError(msg)
    _require_finite("write_matrix", matrix)
    r = _unit(direction)
    if r.shape[0] != matrix.shape[0]:
        msg = f"direction dim {r.shape[0]} != write-matrix output dim {matrix.shape[0]}"
        raise ValueError(msg)
    frob = float(np.linalg.norm(matrix))
    if frob == 0.0:
        return 0.0
    return float(np.linalg.norm(r @ matrix) / frob)


def latent_separation(harmful: np.ndarray, harmless: np.ndarray) -> float:
    """Euclidean distance between mean harmful and mean harmless representations.

    Computed on final-hidden-state activations. Abliteration collapses this
    distance (arXiv:2505.19056); compare against a trusted reference via
    :func:`detect_from_activations`.
    """

    harmful = np.asarray(harmful, dtype=np.float64)
    harmless = np.asarray(harmless, dtype=np.float64)
    if harmful.ndim != 2 or harmless.ndim != 2:
        msg = "harmful and harmless activations must be 2D [n, d_model] arrays"
        raise ValueError(msg)
    if harmful.shape[0] == 0 or harmless.shape[0] == 0:
        msg = "harmful and harmless activations must not be empty"
        raise ValueError(msg)
    if harmful.shape[1] == 0 or harmless.shape[1] == 0:
        msg = "harmful and harmless activation dimension must not be empty"
        raise ValueError(msg)
    if harmful.shape[1] != harmless.shape[1]:
        msg = f"activation dim mismatch: {harmful.shape[1]} vs {harmless.shape[1]}"
        raise ValueError(msg)
    _require_finite("harmful activations", harmful)
    _require_finite("harmless activations", harmless)
    return float(np.linalg.norm(harmful.mean(axis=0) - harmless.mean(axis=0)))


@dataclass(frozen=True)
class AbliterationReport:
    """Verdict from an abliteration probe.

    ``score`` is in ``[0, 1]`` where higher means more likely abliterated (1 minus
    the surviving energy/separation ratio). ``per_layer_energy`` maps each probed
    write-matrix name to its refusal energy (weight mode only).
    """

    abliterated: bool
    mode: str  # "weight" | "activation"
    score: float
    per_layer_energy: dict[str, float] = field(default_factory=dict)
    separation_ratio: float | None = None
    reasons: list[str] = field(default_factory=list)


_AGGREGATORS = ("median", "mean", "min", "quantile")


def _aggregate(values: np.ndarray, method: str, quantile: float) -> float:
    """Reduce per-matrix ``values`` to one scalar for thresholding.

    Lower output -> more likely flagged (the caller flags when it drops below a
    threshold/floor). ``"median"`` (default) is robust but only fires on a
    *majority* collapse; ``"min"`` flags if *any* single matrix collapses (most
    sensitive); ``"quantile"`` flags off the ``quantile``-th percentile (e.g.
    0.25 fires once ~a quarter of matrices collapse); ``"mean"`` is the average.
    """

    if method == "median":
        return float(np.median(values))
    if method == "mean":
        return float(np.mean(values))
    if method == "min":
        return float(np.min(values))
    if method == "quantile":
        return float(np.quantile(values, quantile))
    msg = f"unknown aggregate {method!r}; expected one of {_AGGREGATORS}"
    raise ValueError(msg)


def detect_from_weights(
    write_matrices: Mapping[str, np.ndarray],
    direction: np.ndarray,
    *,
    reference: Mapping[str, np.ndarray] | None = None,
    ratio_threshold: float = 0.25,
    abs_floor: float = 1e-3,
    aggregate: str = "median",
    quantile: float = 0.25,
) -> AbliterationReport:
    """Detect abliteration from residual-stream write matrices.

    Computes per-matrix refusal energy against ``direction`` (a refusal direction
    re-extracted from a trusted reference model).

    - With a ``reference`` (matched matrix names): flag when the aggregated
      candidate/reference energy ratio drops below ``ratio_threshold`` (default
      0.25 -- i.e. >=75% of the refusal energy removed).
    - Without a reference: flag when the aggregated absolute energy falls below
      ``abs_floor`` (an exact abliteration drives energy to ~0).

    ``aggregate`` selects how the per-matrix ratios/energies are reduced to the
    single value that is thresholded (see :func:`_aggregate`):

    - ``"median"`` (default, backward-compatible): robust to a noisy/mismatched
      reference, but only fires when a *majority* of probed matrices collapse --
      a sparse subset (<=50% of matrices) ablated against ``direction`` evades
      it. Inspect ``per_layer_energy`` to catch a minority-layer attack.
    - ``"min"``: flags if *any* single matrix collapses -- most sensitive to a
      minority-layer attack, highest false-positive risk on a noisy reference.
    - ``"quantile"`` with ``quantile`` (default 0.25): fires once roughly that
      fraction of matrices collapse -- a tunable middle ground for
      admission-gating where subset attacks matter.
    - ``"mean"``: the average ratio/energy.
    """

    if not write_matrices:
        msg = "write_matrices is empty; nothing to probe"
        raise ValueError(msg)
    if not 0.0 < ratio_threshold <= 1.0:
        msg = "ratio_threshold must be in (0, 1]"
        raise ValueError(msg)
    if not np.isfinite(abs_floor) or abs_floor <= 0.0:
        msg = "abs_floor must be finite and positive"
        raise ValueError(msg)
    if aggregate not in _AGGREGATORS:
        msg = f"aggregate must be one of {_AGGREGATORS}, got {aggregate!r}"
        raise ValueError(msg)
    if not 0.0 <= quantile <= 1.0:
        msg = "quantile must be in [0, 1]"
        raise ValueError(msg)
    r = _unit(direction)
    per_layer = {name: weight_refusal_energy(W, r) for name, W in write_matrices.items()}
    energies = np.array(list(per_layer.values()), dtype=np.float64)
    reasons: list[str] = []

    if reference is not None:
        ratios = []
        for name, energy in per_layer.items():
            ref_W = reference.get(name)
            if ref_W is None:
                continue
            ref_energy = weight_refusal_energy(ref_W, r)
            if ref_energy <= 0.0:
                msg = f"reference refusal energy for {name!r} must be positive"
                raise ValueError(msg)
            ratios.append(energy / ref_energy)
        if not ratios:
            msg = "reference shares no matrix names with write_matrices"
            raise ValueError(msg)
        agg_ratio = _aggregate(np.array(ratios, dtype=np.float64), aggregate, quantile)
        abliterated = agg_ratio < ratio_threshold
        score = float(np.clip(1.0 - agg_ratio, 0.0, 1.0))
        if abliterated:
            reasons.append(
                f"{aggregate} refusal-energy ratio {agg_ratio:.3f} < {ratio_threshold} "
                f"({len([x for x in ratios if x < ratio_threshold])}/{len(ratios)} matrices collapsed)"
            )
        return AbliterationReport(
            abliterated=abliterated,
            mode="weight",
            score=score,
            per_layer_energy=per_layer,
            reasons=reasons,
        )

    agg_energy = _aggregate(energies, aggregate, quantile)
    abliterated = agg_energy < abs_floor
    # Score relative to the floor: at/below floor -> ~1, well above -> ~0.
    score = float(np.clip(1.0 - agg_energy / (abs_floor * 10.0), 0.0, 1.0))
    if abliterated:
        reasons.append(
            f"{aggregate} refusal energy {agg_energy:.2e} < absolute floor {abs_floor:.0e}"
        )
    return AbliterationReport(
        abliterated=abliterated,
        mode="weight",
        score=score,
        per_layer_energy=per_layer,
        reasons=reasons,
    )


def detect_from_activations(
    harmful: np.ndarray,
    harmless: np.ndarray,
    *,
    reference_separation: float,
    ratio_threshold: float = 0.75,
) -> AbliterationReport:
    """Detect abliteration from harmful/benign final-hidden-state separation.

    ``reference_separation`` is :func:`latent_separation` measured on a trusted
    (un-abliterated) model with the same prompt sets. Flag when the candidate's
    separation drops below ``ratio_threshold`` of the reference (default 0.75 --
    abliteration typically collapses separation by 28-38%, i.e. ratio ~0.62-0.72).
    """

    if not np.isfinite(reference_separation) or reference_separation <= 0.0:
        msg = "reference_separation must be finite and positive"
        raise ValueError(msg)
    if not 0.0 < ratio_threshold <= 1.0:
        msg = "ratio_threshold must be in (0, 1]"
        raise ValueError(msg)
    candidate = latent_separation(harmful, harmless)
    ratio = candidate / reference_separation
    abliterated = ratio < ratio_threshold
    score = float(np.clip(1.0 - ratio, 0.0, 1.0))
    reasons: list[str] = []
    if abliterated:
        reasons.append(
            f"harmful/benign separation ratio {ratio:.3f} < {ratio_threshold} "
            f"(candidate {candidate:.3f} vs reference {reference_separation:.3f})"
        )
    return AbliterationReport(
        abliterated=abliterated,
        mode="activation",
        score=score,
        separation_ratio=ratio,
        reasons=reasons,
    )
