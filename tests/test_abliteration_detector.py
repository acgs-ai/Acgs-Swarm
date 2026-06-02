"""Tests for the abliteration detector.

Synthetic and deterministic (numpy only, no torch / live models): we build a
clean residual-stream write matrix and activation sets, apply the exact Heretic /
Arditi weight edit, and confirm the detector separates clean from abliterated.
"""

from __future__ import annotations

import numpy as np
import pytest

from constitutional_swarm.eval.monotonic_mas import abliteration_detector as ad

D_MODEL = 64
D_IN = 48


def _rng() -> np.random.Generator:
    return np.random.default_rng(0)


def test_refusal_direction_recovers_planted_direction() -> None:
    rng = _rng()
    r = rng.standard_normal(D_MODEL)
    r = r / np.linalg.norm(r)
    base = rng.standard_normal((128, D_MODEL))
    harmless = base
    harmful = base + 3.0 * r  # shift harmful prompts along the planted direction
    recovered = ad.refusal_direction(harmful, harmless)
    cos = abs(float(recovered @ r))
    assert cos > 0.99


def test_apply_abliteration_zeroes_refusal_rowspace() -> None:
    rng = _rng()
    W = rng.standard_normal((D_MODEL, D_IN))
    r = ad._unit(rng.standard_normal(D_MODEL))

    clean_energy = ad.weight_refusal_energy(W, r)
    W_ab = ad.apply_abliteration(W, r)
    ab_energy = ad.weight_refusal_energy(W_ab, r)

    # After the edit, the matrix can no longer write along r.
    assert np.linalg.norm(r @ W_ab) < 1e-9
    assert ab_energy < 1e-9
    assert clean_energy > 0.05  # a clean matrix has meaningful refusal energy


def test_detect_from_weights_with_reference_flags_abliterated() -> None:
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    clean = {f"layer{i}.W_O": rng.standard_normal((D_MODEL, D_IN)) for i in range(6)}
    abliterated = {name: ad.apply_abliteration(W, r) for name, W in clean.items()}

    clean_report = ad.detect_from_weights(clean, r, reference=clean)
    assert clean_report.abliterated is False
    assert clean_report.score < 0.25

    ab_report = ad.detect_from_weights(abliterated, r, reference=clean)
    assert ab_report.abliterated is True
    assert ab_report.score > 0.9
    assert ab_report.reasons


def test_detect_from_weights_partial_abliteration() -> None:
    # Heretic ablates some layers harder than others: 4/6 fully ablated.
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    clean = {f"layer{i}.W_out": rng.standard_normal((D_MODEL, D_IN)) for i in range(6)}
    candidate = dict(clean)
    for i in range(4):
        candidate[f"layer{i}.W_out"] = ad.apply_abliteration(clean[f"layer{i}.W_out"], r)

    report = ad.detect_from_weights(candidate, r, reference=clean)
    # Median ratio across 6 layers: 4 at ~0, 2 at ~1 -> median ~0 -> flagged.
    assert report.abliterated is True


def test_detect_from_weights_minority_subset_is_not_flagged_by_median() -> None:
    # Documented limitation: the reference-ratio test aggregates with the MEDIAN,
    # so it only fires when a *majority* of probed matrices collapse. A sparse
    # subset (<=50% of matrices) ablated against r evades the ratio flag, even
    # though per-layer energies still expose it. Pinning this so the median
    # aggregation stays an intentional contract (see detector docstring).
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    clean = {f"layer{i}.W_out": rng.standard_normal((D_MODEL, D_IN)) for i in range(6)}
    candidate = dict(clean)
    for i in range(3):  # exactly half -> median sits at the clean side
        candidate[f"layer{i}.W_out"] = ad.apply_abliteration(clean[f"layer{i}.W_out"], r)

    report = ad.detect_from_weights(candidate, r, reference=clean)
    assert report.abliterated is False
    # ...but the collapse is still visible per layer for a caller who inspects it.
    ablated_energies = [report.per_layer_energy[f"layer{i}.W_out"] for i in range(3)]
    assert all(e < 1e-9 for e in ablated_energies)


def _subset_candidate(r, n_total=6, n_ablated=3):
    rng = _rng()
    clean = {f"layer{i}.W_out": rng.standard_normal((D_MODEL, D_IN)) for i in range(n_total)}
    candidate = dict(clean)
    for i in range(n_ablated):
        candidate[f"layer{i}.W_out"] = ad.apply_abliteration(clean[f"layer{i}.W_out"], r)
    return clean, candidate


def test_aggregate_min_catches_minority_subset_median_misses() -> None:
    # The minority-subset attack median misses (3/6) is caught by aggregate="min",
    # which flags if *any* single matrix collapses.
    r = ad._unit(_rng().standard_normal(D_MODEL))
    clean, candidate = _subset_candidate(r, n_total=6, n_ablated=3)
    assert ad.detect_from_weights(candidate, r, reference=clean).abliterated is False
    report = ad.detect_from_weights(candidate, r, reference=clean, aggregate="min")
    assert report.abliterated is True
    assert "min refusal-energy ratio" in report.reasons[0]


def test_aggregate_quantile_tunable_sensitivity() -> None:
    # A single collapsed layer out of 6 (1/6 ~ 0.167): the 0.25 quantile sits
    # just above it (clean), but min flags it.
    r = ad._unit(_rng().standard_normal(D_MODEL))
    clean, candidate = _subset_candidate(r, n_total=6, n_ablated=1)
    q_report = ad.detect_from_weights(candidate, r, reference=clean, aggregate="quantile", quantile=0.25)
    assert q_report.abliterated is False
    assert ad.detect_from_weights(candidate, r, reference=clean, aggregate="min").abliterated is True
    # Three of six collapsed -> the 0.25 quantile drops into the ablated cluster.
    _, half = _subset_candidate(r, n_total=6, n_ablated=3)
    assert ad.detect_from_weights(half, r, reference=clean, aggregate="quantile", quantile=0.25).abliterated is True


def test_aggregate_no_reference_min_uses_absolute_floor() -> None:
    # aggregate also applies on the no-reference (absolute-floor) path.
    r = ad._unit(_rng().standard_normal(D_MODEL))
    _, candidate = _subset_candidate(r, n_total=6, n_ablated=2)
    assert ad.detect_from_weights(candidate, r).abliterated is False
    report = ad.detect_from_weights(candidate, r, aggregate="min")
    assert report.abliterated is True
    assert "min refusal energy" in report.reasons[0]


def test_aggregate_default_is_backward_compatible_median() -> None:
    r = ad._unit(_rng().standard_normal(D_MODEL))
    clean, candidate = _subset_candidate(r, n_total=6, n_ablated=5)
    default = ad.detect_from_weights(candidate, r, reference=clean)
    explicit = ad.detect_from_weights(candidate, r, reference=clean, aggregate="median")
    assert default.abliterated == explicit.abliterated is True
    assert default.score == explicit.score


def test_aggregate_invalid_inputs_raise() -> None:
    r = ad._unit(_rng().standard_normal(D_MODEL))
    _, candidate = _subset_candidate(r, n_total=4, n_ablated=2)
    with pytest.raises(ValueError, match="aggregate must be one of"):
        ad.detect_from_weights(candidate, r, aggregate="bogus")
    with pytest.raises(ValueError, match="quantile must be in"):
        ad.detect_from_weights(candidate, r, aggregate="quantile", quantile=1.5)


def test_detect_from_weights_absolute_floor_no_reference() -> None:
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    clean = {f"layer{i}.W_O": rng.standard_normal((D_MODEL, D_IN)) for i in range(6)}
    abliterated = {name: ad.apply_abliteration(W, r) for name, W in clean.items()}

    assert ad.detect_from_weights(clean, r).abliterated is False
    assert ad.detect_from_weights(abliterated, r).abliterated is True


def test_detect_from_weights_reference_calibration_edges() -> None:
    r = np.array([1.0, 0.0])
    reference = {"layer0.W_O": np.array([[1.0], [0.0]])}
    exactly_at_threshold = {"layer0.W_O": np.array([[1.0], [np.sqrt(15.0)]])}

    report = ad.detect_from_weights(exactly_at_threshold, r, reference=reference)

    assert report.abliterated is False
    assert report.score == pytest.approx(0.75)
    assert report.per_layer_energy["layer0.W_O"] == pytest.approx(0.25)
    assert report.reasons == []

    below_threshold = {"layer0.W_O": np.array([[1.0], [np.sqrt(24.0)]])}
    assert ad.detect_from_weights(below_threshold, r, reference=reference).abliterated is True


def test_detect_from_weights_rejects_unusable_reference() -> None:
    rng = _rng()
    r = ad._unit(rng.standard_normal(8))
    candidate = {"candidate.W_O": rng.standard_normal((8, 8))}

    with pytest.raises(ValueError, match="shares no matrix names"):
        ad.detect_from_weights(candidate, r, reference={"other.W_O": rng.standard_normal((8, 8))})

    with pytest.raises(ValueError, match="reference refusal energy"):
        ad.detect_from_weights(candidate, r, reference={"candidate.W_O": np.zeros((8, 8))})


def test_detect_from_activations_flags_collapse() -> None:
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    base = rng.standard_normal((200, D_MODEL)) * 0.3
    harmless = base
    harmful = base + 2.0 * r  # clean model separates harmful from benign along r

    ref_sep = ad.latent_separation(harmful, harmless)
    assert ref_sep > 1.5

    # Abliterated model can't write along r -> project the separation out.
    proj = np.eye(D_MODEL) - np.outer(r, r)
    harmful_ab = harmful @ proj.T
    harmless_ab = harmless @ proj.T

    clean_report = ad.detect_from_activations(harmful, harmless, reference_separation=ref_sep)
    assert clean_report.abliterated is False
    assert clean_report.separation_ratio == pytest.approx(1.0, abs=1e-6)

    ab_report = ad.detect_from_activations(harmful_ab, harmless_ab, reference_separation=ref_sep)
    assert ab_report.abliterated is True
    assert ab_report.separation_ratio < 0.75
    assert ab_report.reasons


def test_detect_from_activations_boundary_and_report_shape() -> None:
    harmful = np.array([[1.0, 0.0], [1.0, 0.0]])
    harmless = np.array([[0.0, 0.0], [0.0, 0.0]])

    report = ad.detect_from_activations(
        harmful,
        harmless,
        reference_separation=2.0,
        ratio_threshold=0.5,
    )

    assert report.abliterated is False
    assert report.mode == "activation"
    assert report.score == pytest.approx(0.5)
    assert report.separation_ratio == pytest.approx(0.5)
    assert report.per_layer_energy == {}
    assert report.reasons == []


def test_input_validation() -> None:
    rng = _rng()
    # dimension mismatch
    with pytest.raises(ValueError):
        ad.refusal_direction(rng.standard_normal((4, 8)), rng.standard_normal((4, 16)))
    # empty activation arrays -> would otherwise produce NaN means
    with pytest.raises(ValueError):
        ad.refusal_direction(rng.standard_normal((0, 8)), rng.standard_normal((4, 8)))
    with pytest.raises(ValueError):
        ad.latent_separation(rng.standard_normal((4, 8)), rng.standard_normal((0, 8)))
    with pytest.raises(ValueError):
        ad.latent_separation(rng.standard_normal((4, 0)), rng.standard_normal((4, 0)))
    with pytest.raises(ValueError):
        bad = rng.standard_normal((4, 8))
        bad[0, 0] = np.nan
        ad.refusal_direction(bad, rng.standard_normal((4, 8)))
    with pytest.raises(ValueError):
        bad = rng.standard_normal((4, 8))
        bad[0, 0] = np.inf
        ad.latent_separation(bad, rng.standard_normal((4, 8)))
    # zero / non-finite directions
    with pytest.raises(ValueError):
        ad._unit(np.zeros(8))
    with pytest.raises(ValueError):
        ad._unit(np.array([np.nan, 1.0]))
    with pytest.raises(ValueError):
        ad._unit(np.array([np.inf, 1.0]))
    # shape mismatch
    with pytest.raises(ValueError):
        ad.apply_abliteration(rng.standard_normal((8, 8)), rng.standard_normal(16))
    with pytest.raises(ValueError):
        ad.apply_abliteration(rng.standard_normal((8, 0)), rng.standard_normal(8))
    with pytest.raises(ValueError):
        bad = rng.standard_normal((8, 8))
        bad[0, 0] = np.nan
        ad.apply_abliteration(bad, rng.standard_normal(8))
    with pytest.raises(ValueError):
        bad = rng.standard_normal((8, 8))
        bad[0, 0] = np.inf
        ad.weight_refusal_energy(bad, rng.standard_normal(8))
    # empty / non-positive-threshold weight probes
    with pytest.raises(ValueError):
        ad.detect_from_weights({}, rng.standard_normal(8))
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), ratio_threshold=-0.1
        )
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), ratio_threshold=1.1
        )
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), abs_floor=0.0
        )
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), abs_floor=np.nan
        )
    # non-positive thresholds on the activation probe
    with pytest.raises(ValueError):
        ad.detect_from_activations(
            rng.standard_normal((4, 8)),
            rng.standard_normal((4, 8)),
            reference_separation=0.0,
        )
    with pytest.raises(ValueError):
        ad.detect_from_activations(
            rng.standard_normal((4, 8)),
            rng.standard_normal((4, 8)),
            reference_separation=np.inf,
        )
    with pytest.raises(ValueError):
        ad.detect_from_activations(
            rng.standard_normal((4, 8)),
            rng.standard_normal((4, 8)),
            reference_separation=1.0,
            ratio_threshold=0.0,
        )
    with pytest.raises(ValueError):
        ad.detect_from_activations(
            rng.standard_normal((4, 8)),
            rng.standard_normal((4, 8)),
            reference_separation=1.0,
            ratio_threshold=1.1,
        )
