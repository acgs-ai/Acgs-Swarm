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


def test_detect_from_weights_absolute_floor_no_reference() -> None:
    rng = _rng()
    r = ad._unit(rng.standard_normal(D_MODEL))
    clean = {f"layer{i}.W_O": rng.standard_normal((D_MODEL, D_IN)) for i in range(6)}
    abliterated = {name: ad.apply_abliteration(W, r) for name, W in clean.items()}

    assert ad.detect_from_weights(clean, r).abliterated is False
    assert ad.detect_from_weights(abliterated, r).abliterated is True


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
    # empty / non-positive-threshold weight probes
    with pytest.raises(ValueError):
        ad.detect_from_weights({}, rng.standard_normal(8))
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), ratio_threshold=-0.1
        )
    with pytest.raises(ValueError):
        ad.detect_from_weights(
            {"W": rng.standard_normal((8, 8))}, rng.standard_normal(8), abs_floor=0.0
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
            reference_separation=1.0,
            ratio_threshold=0.0,
        )
