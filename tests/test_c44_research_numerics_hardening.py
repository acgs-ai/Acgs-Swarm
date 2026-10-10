"""C44 regression tests: research numerics (spectral_sphere, latent_dna).

Spectral-sphere tests are pure Python; latent_dna tests importorskip torch per test
so the spectral tests still run in torch-free environments.
"""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any

import pytest
from constitutional_swarm import spectral_sphere
from constitutional_swarm.spectral_sphere import (
    SpectralSphereManifold,
    spectral_sphere_project,
)

NAN = math.nan
INF = math.inf

# ── core-research-15: non-finite trust matrices are rejected ─────────────────


@pytest.mark.parametrize("bad", [NAN, INF, -INF])
def test_replace_raw_trust_rejects_non_finite_entry(bad: float) -> None:
    m = SpectralSphereManifold(3)
    m.update_trust(0, 1, 0.5)
    before_raw = [list(row) for row in m._raw_trust]
    before_proj = m.trust_matrix
    before_gen = m.commit_generation

    with pytest.raises(ValueError, match="finite"):
        m.replace_raw_trust([[bad, 0.0, 0.0], [0.0, 5.0, 0.0], [0.0, 0.0, 1.0]])

    assert m._raw_trust == before_raw
    assert m.trust_matrix == before_proj
    assert m.commit_generation == before_gen


def test_replace_raw_trust_rejects_non_finite_without_commit() -> None:
    m = SpectralSphereManifold(2)
    with pytest.raises(ValueError, match="finite"):
        m.replace_raw_trust([[NAN, 0.0], [0.0, 1.0]], commit=False)
    assert m._raw_trust == [[0.0, 0.0], [0.0, 0.0]]


@pytest.mark.parametrize("bad", [NAN, INF, -INF])
def test_project_rejects_non_finite_entry(bad: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        spectral_sphere_project([[1.0, 0.0], [0.0, bad]])


def test_project_rejects_non_square_matrix() -> None:
    with pytest.raises(ValueError, match="square"):
        spectral_sphere_project([[1.0, 0.0], [0.0]])


@pytest.mark.parametrize("bad_r", [0.0, -1.0, NAN, INF])
def test_project_rejects_invalid_radius(bad_r: float) -> None:
    with pytest.raises(ValueError, match="r must be"):
        spectral_sphere_project([[2.0]], r=bad_r)


def test_project_rejects_overflowing_matrix_instead_of_zeroing_it() -> None:
    """Finite entries whose power iteration overflows must not yield a silent zero matrix."""
    with pytest.raises(ValueError, match="finite"):
        spectral_sphere_project([[1e200, 0.0], [0.0, 1e200]])


def test_unconverged_verification_raises_instead_of_claiming_radius(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A projection whose bound is never verified must not report spectral_norm == r."""
    monkeypatch.setattr(spectral_sphere, "spectral_norm_power_iter", lambda *_a, **_k: 5.0)
    with pytest.raises(ArithmeticError, match="did not converge"):
        spectral_sphere_project([[5.0, 0.0], [0.0, 1.0]], r=1.0)


def test_verification_reports_measured_sigma_after_rescale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a rescale is needed, the reported norm is the measured one (<= r)."""
    real = spectral_sphere.spectral_norm_power_iter
    calls = {"n": 0}

    def underestimating(matrix: list[list[float]], **kwargs: Any) -> float:
        calls["n"] += 1
        sigma = real(matrix, **kwargs)
        return sigma * 0.5 if calls["n"] == 1 else sigma

    monkeypatch.setattr(spectral_sphere, "spectral_norm_power_iter", underestimating)
    result = spectral_sphere_project([[4.0, 0.0], [0.0, 1.0]], r=1.0)
    assert result.clipped is True
    assert result.spectral_norm <= 1.0 + 1e-10
    assert real([list(row) for row in result.matrix]) <= 1.0 + 1e-8


# ── core-research-opt-4: no redundant verification when nothing was clipped ──


def test_unclipped_projection_runs_power_iteration_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = spectral_sphere.spectral_norm_power_iter
    calls = {"n": 0}

    def counting(matrix: list[list[float]], **kwargs: Any) -> float:
        calls["n"] += 1
        return real(matrix, **kwargs)

    monkeypatch.setattr(spectral_sphere, "spectral_norm_power_iter", counting)
    matrix = [[0.1, 0.0], [0.0, 0.05]]
    result = spectral_sphere_project(matrix, r=1.0)
    assert calls["n"] == 1
    assert result.clipped is False
    assert result.matrix == ((0.1, 0.0), (0.0, 0.05))
    assert result.spectral_norm == pytest.approx(0.1, abs=1e-6)


def test_clipped_projection_still_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    real = spectral_sphere.spectral_norm_power_iter
    calls = {"n": 0}

    def counting(matrix: list[list[float]], **kwargs: Any) -> float:
        calls["n"] += 1
        return real(matrix, **kwargs)

    monkeypatch.setattr(spectral_sphere, "spectral_norm_power_iter", counting)
    result = spectral_sphere_project([[3.0, 0.0], [0.0, 1.0]], r=1.0)
    assert result.clipped is True
    assert calls["n"] >= 2
    assert result.spectral_norm == pytest.approx(1.0, abs=1e-6)


# ── latent_dna helpers (torch-only) ──────────────────────────────────────────


def _torch() -> Any:
    return pytest.importorskip("torch")


def _fake_model(hidden_dim: int, *, config: Any, tuple_layers: bool = True) -> Any:
    torch = _torch()
    nn = torch.nn

    class _TupleLayer(nn.Module):
        def forward(self, x: Any) -> Any:
            return x, None

    class _TensorLayer(nn.Module):
        def forward(self, x: Any) -> Any:
            return x

    class _NS(nn.Module):
        pass

    class _Model(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.config = config
            self.model = _NS()
            layer_cls = _TupleLayer if tuple_layers else _TensorLayer
            self.model.layers = nn.ModuleList([layer_cls() for _ in range(2)])
            self.hidden_dim = hidden_dim

        def forward(self, hidden_states: Any) -> Any:
            for layer in self.model.layers:
                out = layer(hidden_states)
                hidden_states = out[0] if isinstance(out, tuple) else out
            return hidden_states

        def generate(self, *a: Any, **k: Any) -> Any:  # pragma: no cover - unused
            raise NotImplementedError

    return _Model()


# ── core-research-16: width mismatch is rejected at enable() ────────────────


@pytest.mark.parametrize("width_attr", ["hidden_size", "n_embd", "d_model"])
def test_enable_rejects_rank1_vector_width_mismatch(width_attr: str) -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    config = SimpleNamespace(model_type="llama", **{width_attr: 8})
    model = _fake_model(8, config=config)
    v = torch.zeros(4)
    v[0] = 1.0
    wrapper = LatentDNAWrapper(model, v, layer_idx=0)
    with pytest.raises(ValueError, match="width"):
        wrapper.enable()
    assert wrapper.enabled is False
    assert not model.model.layers[0]._forward_hooks


def test_enable_rejects_subspace_width_mismatch() -> None:
    _torch()
    np = pytest.importorskip("numpy")
    from constitutional_swarm.latent_dna import LatentDNAWrapper
    from constitutional_swarm.violation_subspace import ViolationSubspace

    basis = np.zeros((1, 4))
    basis[0, 0] = 1.0
    sub = ViolationSubspace(basis=basis, mean=np.zeros(4))
    model = _fake_model(6, config=SimpleNamespace(model_type="llama", hidden_size=6))
    wrapper = LatentDNAWrapper(model, subspace=sub, layer_idx=1)
    with pytest.raises(ValueError, match="width"):
        wrapper.enable()
    assert wrapper.enabled is False


def test_enable_accepts_matching_width_and_steers() -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _fake_model(4, config=SimpleNamespace(model_type="llama", hidden_size=4))
    v = torch.tensor([1.0, 0.0, 0.0, 0.0])
    wrapper = LatentDNAWrapper(model, v, layer_idx=0)
    with wrapper:
        out = model(torch.tensor([[[3.0, 1.0, 0.0, 0.0]]]))
    assert torch.allclose(out, torch.tensor([[[0.0, 1.0, 0.0, 0.0]]]))
    stats = wrapper.intervention_stats()
    assert stats["steered_tokens"] == 1
    assert stats["steer_failures"] == 0


def test_enable_without_declared_width_still_works() -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _fake_model(4, config=SimpleNamespace(model_type="llama"))
    wrapper = LatentDNAWrapper(model, torch.tensor([0.0, 1.0, 0.0, 0.0]), layer_idx=0)
    wrapper.enable()
    try:
        assert wrapper.enabled is True
    finally:
        wrapper.disable()


# ── core-research-opt-3: shared helpers preserve extractor behaviour ────────


def _inputs(torch: Any, rows: list[list[list[float]]]) -> list[dict[str, Any]]:
    return [{"hidden_states": torch.tensor([r])} for r in rows]


def test_split_output_handles_tuple_and_tensor() -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import _split_output

    h = torch.zeros(1, 1, 2)
    extra = torch.tensor([7])
    assert _split_output((h, extra)) == (h, (extra,))
    hidden, rest = _split_output(h)
    assert hidden is h
    assert rest is None


def test_extractors_match_reference_and_layer_output_kind() -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    safe_rows = [[[1.0, 0.0, 0.0], [1.0, 0.0, 0.0]], [[0.0, 1.0, 0.0], [0.0, 1.0, 0.0]]]
    unsafe_rows = [[[1.0, 0.0, 2.0], [1.0, 0.0, 2.0]], [[0.0, 1.0, 4.0], [0.0, 1.0, 4.0]]]

    results = []
    for tuple_layers in (True, False):
        model = _fake_model(
            3, config=SimpleNamespace(model_type="llama"), tuple_layers=tuple_layers
        )
        mean_vec = LatentDNAWrapper.extract_violation_vector(
            model, _inputs(torch, safe_rows), _inputs(torch, unsafe_rows), 0
        )
        pca_vec = LatentDNAWrapper.extract_violation_vector_pca(
            model, _inputs(torch, safe_rows), _inputs(torch, unsafe_rows), 1
        )
        # Hooks are removed after extraction.
        assert not any(layer._forward_hooks for layer in model.model.layers)
        results.append((mean_vec, pca_vec))

    expected_mean = torch.tensor([0.0, 0.0, 1.0])
    for mean_vec, pca_vec in results:
        assert torch.allclose(mean_vec, expected_mean)
        # Paired diffs are [0,0,2] and [0,0,4]: centred -> principal axis is e2 (sign-free).
        assert torch.allclose(pca_vec.abs(), expected_mean, atol=1e-6)
    assert torch.allclose(results[0][0], results[1][0])
    assert torch.allclose(results[0][1].abs(), results[1][1].abs())


def test_collect_mean_activations_removes_hook_on_error() -> None:
    torch = _torch()
    from constitutional_swarm.latent_dna import _collect_mean_activations

    model = _fake_model(3, config=SimpleNamespace(model_type="llama"))
    with pytest.raises(TypeError):
        _collect_mean_activations(model, [{"bogus_kwarg": torch.zeros(1, 1, 3)}], 0, None)
    assert not any(layer._forward_hooks for layer in model.model.layers)
