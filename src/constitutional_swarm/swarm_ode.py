"""
Continuous-Time Swarm Dynamics — MCFS Phase 4.

Replaces the discrete `GovernanceManifold.compose()` loop with a continuous ODE
on the trust matrix H(t) ∈ ℝⁿˣⁿ, integrated via a custom Projected RK4 solver.

State variable: S(t) = H(t), the nxn trust/routing matrix (Candidate A).

At each RK4 step, the derivative dH/dt = f_θ(H, t) is evaluated in Euclidean
space, then blended with the residual alpha * I before a final projection onto
the spectral sphere. This guarantees BIBO stability without computing tangent
spaces of the spectral norm ball (which requires differentiating through SVD).

The approach directly extends Phase 2:
    Discrete:   H_{k+1} = spectral_project(alpha * I + (1 - alpha) * (H_k @ H_0))
    Continuous: H(t+dt) = spectral_project((1 - alpha) * RK4_step(f, H, t, dt) + alpha * I)

Dependencies: torch (optional, same isolation as latent_dna.py).
"""

from __future__ import annotations

import math
import re
import secrets
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from constitutional_swarm.merkle_crdt import MerkleCRDT

try:
    import torch
    import torch.nn as nn
    from torch import Tensor
except ImportError as exc:
    raise ImportError("swarm_ode requires torch. Install with: pip install torch>=2.0") from exc

from constitutional_swarm.constants import CONSTITUTIONAL_HASH as _CONSTITUTIONAL_HASH
from constitutional_swarm.privacy_accountant import PrivacyAccountant, matrix_l2_sensitivity

_DRAND_CHAIN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_DISCRETE_GAUSSIAN_SUPPORT_SIZE = 1_000_001


class SwarmVectorField(Protocol):
    """Protocol for the vector field f_θ(H, t) → dH/dt.

    Any nn.Module or callable that accepts (H: Tensor[n,n], t: float) and
    returns dH/dt: Tensor[n,n] satisfies this protocol.
    """

    def __call__(self, H: Tensor, t: float) -> Tensor: ...


class TrustDecayField(nn.Module):
    """Default vector field: learned task-pressure with exponential decay.

    dH/dt = tanh(W @ H) - lambda * H

    W is a learnable nxn matrix representing how each agent's trust influences
    others' evolution. lambda controls the natural decay rate - without reinforcement,
    trust fades. tanh prevents unbounded growth.

    Args:
        n: Number of agents.
        decay: Decay coefficient λ. Default 0.1.
        seed: Random seed for W initialization.
    """

    def __init__(self, n: int, *, decay: float = 0.1, seed: int = 0) -> None:
        super().__init__()
        gen = torch.Generator().manual_seed(seed)
        self.W = nn.Parameter(torch.randn(n, n, generator=gen) * 0.1)
        self.decay = decay

    def forward(self, H: Tensor, t: float) -> Tensor:
        return torch.tanh(self.W @ H) - self.decay * H


class StationaryField(nn.Module):
    """Trivial vector field for testing: dH/dt = W (constant flow).

    Useful for verifying the RK4 integrator independently of learned dynamics.

    Args:
        W: Constant flow matrix [n, n].
    """

    def __init__(self, W: Tensor) -> None:
        super().__init__()
        self.register_buffer("W", W)

    def forward(self, H: Tensor, t: float) -> Tensor:
        return self.W


def _spectral_norm_torch(M: Tensor, max_iter: int = 20) -> float:
    """Estimate sigma_max(M) via power iteration on M^T @ M. GPU-friendly."""
    n = M.shape[0]
    v = torch.randn(n, device=M.device, dtype=M.dtype)
    v = v / v.norm()

    sigma = 0.0
    for _ in range(max_iter):
        Mv = M @ v
        MTMv = M.T @ Mv
        new_norm = MTMv.norm().item()
        if new_norm < 1e-14:
            return 0.0
        new_sigma = new_norm**0.5
        v = MTMv / new_norm
        if abs(new_sigma - sigma) / (sigma + 1e-12) < 1e-8:
            return new_sigma
        sigma = new_sigma
    return sigma


def spectral_project_torch(
    H: Tensor,
    r: float = 1.0,
    max_power_iter: int = 20,
) -> Tensor:
    """Approximately project ``H`` toward the spectral sphere ``‖H‖₂ ≤ r``.

    The stochastic power iterations used here estimate the spectral norm; they
    do not certify an upper bound. Callers calibrating differential privacy
    must supply an independently certified spectral bound rather than treating
    this estimate or the returned matrix as a DP sensitivity certificate.
    """
    sigma = _spectral_norm_torch(H, max_iter=max_power_iter)
    if sigma <= r + 1e-10:
        return H
    H_proj = H * (r / sigma)
    # Refinement passes reduce estimator error, but stochastic power iteration
    # cannot certify that the true spectral norm is within the requested ball.
    for _ in range(3):
        sigma_check = _spectral_norm_torch(H_proj, max_iter=max_power_iter)
        if sigma_check <= r + 1e-10:
            break
        H_proj = H_proj * (r / sigma_check)
    return H_proj


def exact_spectral_project_torch(H: Tensor, r: float = 1.0) -> Tensor:
    """Project a square matrix into ``||H||_2 <= r`` using an exact SVD.

    Unlike :func:`spectral_project_torch`, this helper does not use stochastic
    power iteration. It computes and rechecks the largest singular value with
    :func:`torch.linalg.svdvals`, adding a dtype-aware rounding guard when a
    rescale is required. Inputs must be non-empty, square, finite, real
    floating-point tensors and ``r`` must be finite and positive.

    The input tensor is returned unchanged when its SVD already certifies the
    bound. A projected result is returned only after a second SVD verifies
    ``||H||_2 <= r``; failure to obtain that finite-precision postcondition is
    reported loudly.
    """
    if not isinstance(H, Tensor):
        raise TypeError(f"H must be a torch.Tensor, got {type(H).__name__}")
    if H.ndim != 2 or H.shape[0] != H.shape[1] or H.shape[0] == 0:
        raise ValueError(f"H must be a non-empty square matrix, got shape {tuple(H.shape)}")
    if not H.is_floating_point():
        raise TypeError(f"H must use a real floating-point dtype, got {H.dtype}")
    if not bool(torch.isfinite(H).all().item()):
        raise ValueError("H must contain only finite values")
    if (
        isinstance(r, bool)
        or not isinstance(r, (int, float))
        or not math.isfinite(r)
        or r <= 0
    ):
        raise ValueError(f"r must be a finite positive radius, got {r}")

    radius = float(r)
    certificate_dtype = (
        torch.float32 if H.dtype in (torch.float16, torch.bfloat16) else H.dtype
    )

    def certified_norm(matrix: Tensor) -> float:
        singular_values = torch.linalg.svdvals(matrix.to(dtype=certificate_dtype))
        norm = float(singular_values.amax().item())
        if not math.isfinite(norm):
            raise RuntimeError("SVD did not produce a finite spectral norm")
        return norm

    norm = certified_norm(H)
    if norm <= radius:
        return H

    dtype_epsilon = torch.finfo(certificate_dtype).eps
    guarded_radius = radius * (1.0 - 8.0 * dtype_epsilon)
    if guarded_radius <= 0.0 or guarded_radius >= radius:
        guarded_radius = math.nextafter(radius, 0.0)

    projected = H * (guarded_radius / norm)
    for _ in range(4):
        projected_norm = certified_norm(projected)
        if projected_norm <= radius:
            return projected
        projected = projected * (guarded_radius / projected_norm)

    raise RuntimeError("unable to certify the projected spectral norm within radius r")


def projected_rk4_step(
    f: SwarmVectorField,
    H: Tensor,
    t: float,
    dt: float,
    *,
    r: float = 1.0,
    residual_alpha: float = 0.1,
    max_power_iter: int = 20,
) -> Tensor:
    """Single Projected RK4 step with spectral-sphere projection + residual.

    Computes:
        k1 = f(H, t)
        k2 = f(H + dt/2 · k1, t + dt/2)
        k3 = f(H + dt/2 · k2, t + dt/2)
        k4 = f(H + dt · k3, t + dt)
        H_unprojected = H + dt/6 · (k1 + 2k2 + 2k3 + k4)
        H_residual = (1 - alpha) * H_unprojected + alpha * I
        H_next = spectral_project(H_residual, r)

    Args:
        f: Vector field dH/dt = f(H, t).
        H: Current trust matrix [n, n].
        t: Current time.
        dt: Step size.
        r: Spectral sphere radius.
        residual_alpha: Identity injection coefficient.
        max_power_iter: Power iterations for spectral norm estimation.

    Returns:
        H at time t + dt after residual injection and final projection onto
        the spectral sphere.
    """
    k1 = f(H, t)
    k2 = f(H + 0.5 * dt * k1, t + 0.5 * dt)
    k3 = f(H + 0.5 * dt * k2, t + 0.5 * dt)
    k4 = f(H + dt * k3, t + dt)

    H_unprojected = H + (dt / 6.0) * (k1 + 2.0 * k2 + 2.0 * k3 + k4)

    if residual_alpha > 0.0:
        n = H.shape[0]
        identity = torch.eye(n, device=H.device, dtype=H.dtype)
        H_unprojected = (1.0 - residual_alpha) * H_unprojected + residual_alpha * identity

    # Project AFTER residual injection to guarantee sigma_max <= r
    H_next = spectral_project_torch(H_unprojected, r=r, max_power_iter=max_power_iter)

    return H_next


def integrate(
    f: SwarmVectorField,
    H0: Tensor,
    *,
    t_span: tuple[float, float] = (0.0, 1.0),
    n_steps: int = 100,
    r: float = 1.0,
    residual_alpha: float = 0.1,
    max_power_iter: int = 20,
    record_every: int = 0,
    crdt: MerkleCRDT | None = None,
) -> dict[str, Any]:
    """Integrate the swarm ODE from t_span[0] to t_span[1].

    Args:
        f: Vector field dH/dt = f(H, t).
        H0: Initial trust matrix [n, n].
        t_span: (t_start, t_end).
        n_steps: Number of RK4 steps.
        r: Spectral sphere radius.
        residual_alpha: Identity injection coefficient.
        max_power_iter: Power iterations for spectral norm.
        record_every: If > 0, record H and variance every k steps.
            If 0, only return the final state.
        crdt: Optional MerkleCRDT replica that receives compact ODE snapshot
            metadata at the same recording points as trajectory entries.

    Returns:
        dict with keys:
            "H_final": Final trust matrix [n, n].
            "t_final": Final time.
            "n_steps": Total steps taken.
            "trajectory": list of (t, H, variance) tuples if record_every > 0.
    """
    t_start, t_end = t_span
    if n_steps < 1:
        raise ValueError(f"n_steps must be >= 1, got {n_steps}")
    dt = (t_end - t_start) / n_steps
    H = H0.clone()
    t = t_start

    trajectory: list[tuple[float, Tensor, float]] = []

    for step in range(n_steps):
        if record_every > 0 and step % record_every == 0:
            var = _trust_variance_torch(H)
            trajectory.append((t, H.clone().detach(), var))
            if crdt is not None:
                import json

                crdt.append(
                    payload=json.dumps({"step": step, "t": t, "variance": var}),
                    payload_type="ode_snapshot",
                    bodes_passed=True,
                    constitutional_hash=_CONSTITUTIONAL_HASH,
                )

        H = projected_rk4_step(
            f,
            H,
            t,
            dt,
            r=r,
            residual_alpha=residual_alpha,
            max_power_iter=max_power_iter,
        )
        t += dt

    # Record final state
    if record_every > 0:
        var = _trust_variance_torch(H)
        trajectory.append((t, H.clone().detach(), var))
        if crdt is not None:
            import json

            crdt.append(
                payload=json.dumps({"step": n_steps, "t": t, "variance": var}),
                payload_type="ode_snapshot",
                bodes_passed=True,
                constitutional_hash=_CONSTITUTIONAL_HASH,
            )

    return {
        "H_final": H,
        "t_final": t,
        "n_steps": n_steps,
        "trajectory": trajectory,
    }


def _trust_variance_torch(H: Tensor) -> float:
    """Variance of trust matrix entries around their mean."""
    mean = H.mean()
    return ((H - mean) ** 2).mean().item()


# ---------------------------------------------------------------------------
# Differential Privacy helpers (NDSS 2027, §3.4)
# ---------------------------------------------------------------------------


def calibrate_sigma(
    *,
    certified_spectral_bound: float,
    matrix_dimension: int,
    epsilon: float,
    delta: float,
) -> float:
    """Calibrate Gaussian noise for an entrywise ``n × n`` matrix release.

    The flattened L2 sensitivity is the Frobenius diameter of the certified
    spectral-norm ball: ``Δ2 = 2 * r * sqrt(n)``. The residual coefficient is
    deliberately absent because the update path does not establish a smaller
    neighboring-dataset sensitivity. Calibration inverts the accountant's RDP
    conversion, which is valid across positive epsilon values supported by the
    configured finite order grid.

    Args:
        certified_spectral_bound: Caller-certified spectral-norm bound ``r``.
            A stochastic power-iteration estimate is not sufficient.
        matrix_dimension: Positive matrix dimension ``n`` for the ``n × n``
            trust matrix.
        epsilon: Privacy budget ε > 0.
        delta: Privacy failure probability δ ∈ (0,1).

    Returns:
        σ such that the Gaussian mechanism H̃ = H_proj + N(0,σ²I) satisfies
        (ε,δ)-DP per round.
    """
    sensitivity = matrix_l2_sensitivity(
        certified_spectral_bound=certified_spectral_bound,
        matrix_dimension=matrix_dimension,
    )
    if not math.isfinite(epsilon) or epsilon <= 0:
        raise ValueError(f"epsilon must be finite and positive, got {epsilon}")
    if not math.isfinite(delta) or not (0 < delta < 1):
        raise ValueError(f"delta must be finite and in (0,1), got {delta}")
    return PrivacyAccountant(epsilon=epsilon, delta=delta).required_sigma(
        sensitivity=sensitivity
    )


def add_dp_noise(H_proj: Tensor, sigma: float) -> Tensor:
    """Add calibrated Gaussian noise for DP gossip broadcast (NDSS Eq. 3).

    Step 4 of Algorithm 1: Z ~ N(0, σ²·I_{n×n}), H̃ = H_proj + Z.

    This must be called AFTER spectral projection and BEFORE broadcast. The
    sigma must have been calibrated from a caller-certified spectral bound and
    the released matrix dimension; the projection's stochastic norm estimate
    is not itself a DP sensitivity certificate.
    The noise is additive; the receiver re-projects to maintain the
    spectral-sphere constraint (post-processing does not hurt DP).

    Args:
        H_proj: Projected trust matrix (already on spectral sphere).
        sigma: Noise standard deviation from calibrate_sigma().

    Returns:
        Noisy matrix H̃ with the same shape as H_proj.
    """
    if not math.isfinite(sigma) or sigma <= 0:
        raise ValueError(f"sigma must be positive, got {sigma}")
    noise = torch.randn_like(H_proj) * sigma
    return H_proj + noise


# ---------------------------------------------------------------------------
# Discrete Gaussian Sampler (Canonne, Kamath & Steinke 2020)
# ---------------------------------------------------------------------------
# Circuit-oriented integer noise from a truncated float64 PMF/CDF approximation.
# Supports reproducible circuit witnesses; callers retain the full DP analysis.
# Reference: arXiv:2004.00010 — "The Discrete Gaussian for Differential Privacy"
# ---------------------------------------------------------------------------


class DiscreteGaussianSampler:
    """Discrete Gaussian distribution N_Z(0, sigma^2) over the integers.

    Samples from a truncated discrete Gaussian approximation using
    inverse-transform sampling over a float64 CDF (Cumulative Distribution
    Function). Each integer-valued output is selected by a linear scan of the
    precomputed CDF. The caller must include truncation error in its privacy
    analysis; this sampler alone is not an exact DP certificate. The local
    torch generator receives OS entropy when no seed is supplied, but torch's
    pseudorandom generator is not a cryptographic RNG.

    Properties:
    - Output is an integer in [-tail_bound, +tail_bound]
    - PMF: Pr[X=k] ∝ exp(-k²/(2σ²))
    - The PMF table is pre-computed at construction time; each sample
      is O(tail_bound) for the CDT scan (acceptable for small sigma).
    - Support tables are capped at 1,000,001 entries as a resource-safety
      contract. This operational cap is not a differential-privacy theorem;
      callers needing wider support must use a streaming sampler.
    - Reproducible: a verifier given the seed can reconstruct the CDF stream.

    Args:
        sigma: Distribution standard deviation.
        tail_bound: Truncation at ±tail_bound (default = ceil(6σ)).
        seed: Optional integer seed for reproducibility.

    Example::

        sampler = DiscreteGaussianSampler(sigma=1.0)
        noise = sampler.sample()            # single integer
        noise_vec = sampler.sample_vector(n=8)  # list of n integers
    """

    def __init__(
        self,
        sigma: float,
        tail_bound: int | None = None,
        seed: int | None = None,
    ) -> None:
        if not math.isfinite(sigma) or sigma <= 0:
            raise ValueError(f"sigma must be positive, got {sigma}")
        if tail_bound is not None and (
            isinstance(tail_bound, bool) or not isinstance(tail_bound, int) or tail_bound <= 0
        ):
            raise ValueError(f"tail_bound must be a positive integer, got {tail_bound}")
        self._sigma = sigma
        self._seed = seed
        self._noise_call_counter = 0
        if tail_bound is None:
            six_sigma = 6.0 * sigma
            if not math.isfinite(six_sigma):
                raise ValueError("sigma implies an unrepresentable default support")
            tail_bound = max(6, math.ceil(six_sigma))
        support_size = 2 * tail_bound + 1
        if support_size > sys.maxsize:
            raise ValueError("tail_bound implies an unrepresentable support")
        if support_size > _MAX_DISCRETE_GAUSSIAN_SUPPORT_SIZE:
            raise ValueError(
                "discrete Gaussian support table exceeds the resource limit of "
                f"{_MAX_DISCRETE_GAUSSIAN_SUPPORT_SIZE} entries"
            )
        self._tail = tail_bound
        effective_seed = seed if seed is not None else secrets.randbits(64)
        self._rng = torch.Generator().manual_seed(effective_seed)

        # Build CDT (Cumulative Distribution Table)
        self._support = list(range(-self._tail, self._tail + 1))
        log_unnorm = torch.tensor(
            [-0.5 * (float(k) / sigma) * (float(k) / sigma) for k in self._support],
            dtype=torch.float64,
        )
        # numerically stable softmax-style normalization
        log_z = torch.logsumexp(log_unnorm, dim=0)
        self._pmf = (log_unnorm - log_z).exp()
        self._cdf = torch.cumsum(self._pmf, dim=0)

    @property
    def sigma(self) -> float:
        return self._sigma

    @property
    def tail_bound(self) -> int:
        return self._tail

    def pmf(self, k: int) -> float:
        """Probability mass at integer k (0.0 outside support)."""
        idx = k + self._tail
        if idx < 0 or idx >= len(self._support):
            return 0.0
        return float(self._pmf[idx].item())

    def sample(self) -> int:
        """Draw a single sample from N_Z(0, σ²)."""
        u = torch.rand(1, generator=self._rng, dtype=torch.float64).item()
        for i, cdf_val in enumerate(self._cdf):
            if u <= cdf_val.item():
                return self._support[i]
        return self._support[-1]  # numerical safety

    def sample_vector(self, n: int) -> list[int]:
        """Draw n independent samples."""
        return [self.sample() for _ in range(n)]

    def sample_tensor(self, shape: tuple[int, ...]) -> Tensor:
        """Draw samples into a torch Tensor of the given shape (float32)."""
        total = 1
        for s in shape:
            total *= s
        raw = [float(self.sample()) for _ in range(total)]
        return torch.tensor(raw, dtype=torch.float32).reshape(shape)

    def sensitivity_clipped_noise(
        self,
        shape: tuple[int, ...],
        sensitivity: float = 1.0,
    ) -> Tensor:
        """Add sensitivity-scaled discrete Gaussian noise to a zero tensor.

        Approximates sensitivity-scaled Gaussian noise with integer-valued,
        truncated output for circuit-oriented workflows.

        Args:
            shape: Output shape.
            sensitivity: L2 sensitivity of the mechanism (default 1.0).

        Returns:
            Float tensor of shape ``shape`` containing integer noise values.
        """
        if not math.isfinite(sensitivity) or sensitivity <= 0:
            raise ValueError(f"sensitivity must be positive, got {sensitivity}")
        scaled_sigma = self._sigma * sensitivity
        # Derive a unique seed per call to avoid identical noise vectors.
        self._noise_call_counter += 1
        derived_seed = (
            (self._seed * 2654435761 + self._noise_call_counter) & 0xFFFFFFFF
            if self._seed is not None
            else None
        )
        sampler = (
            self
            if sensitivity == 1.0
            else DiscreteGaussianSampler(
                sigma=scaled_sigma,
                seed=derived_seed,
            )
        )
        return sampler.sample_tensor(shape)


# ---------------------------------------------------------------------------
# drand VRF Client — threshold VRF-seeded DP noise
# ---------------------------------------------------------------------------
# Uses drand's publicly verifiable randomness beacon as a VRF seed for
# DiscreteGaussianSampler. This makes DP noise generation auditable:
# any verifier can confirm the noise was seeded from the public beacon.
# Reference: drand.love — League of Entropy threshold VRF
# API: https://api.drand.sh/public/{round}
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DrandBeaconEntry:
    """A single drand randomness beacon entry.

    Attributes:
        round_number: Beacon round (monotonically increasing).
        randomness_hex: 64-char hex string — the public randomness.
        signature_hex: BLS12-381 threshold signature.
        previous_sig_hex: Previous round's signature (chain link).
    """

    round_number: int
    randomness_hex: str
    signature_hex: str
    previous_sig_hex: str


class DrandClient:
    """Thin client for the drand League of Entropy randomness beacon.

    Fetches publicly verifiable threshold VRF randomness from the drand
    HTTP API.  The randomness field is a BLS12-381 aggregate signature
    over the round number — verifiable by any party with the chain's
    public key.

    Usage::

        client = DrandClient()
        entry = client.latest()
        seed = client.seed_from_entry(entry)
        sampler = DiscreteGaussianSampler(sigma=1.0, seed=seed)
        noise = sampler.sample_vector(n=10)

    Args:
        chain_hash: drand chain hash (default = unchained mainnet).
        base_url: drand API base URL.
        timeout: HTTP request timeout seconds.
    """

    DEFAULT_BASE_URL = "https://api.drand.sh"
    DEFAULT_CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"

    def __init__(
        self,
        chain_hash: str = DEFAULT_CHAIN,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
    ) -> None:
        if not _DRAND_CHAIN_HASH_RE.match(chain_hash):
            raise ValueError(
                f"chain_hash must be a 64-char lowercase hex string, got {chain_hash!r}"
            )
        if not base_url.startswith("https://"):
            raise ValueError(f"base_url must use HTTPS, got {base_url!r}")
        self._chain = chain_hash
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _fetch(self, round_spec: str) -> DrandBeaconEntry:
        """Fetch a beacon entry by round spec ('latest' or round number)."""
        import urllib.error
        import urllib.request

        url = f"{self._base}/{self._chain}/public/{round_spec}"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                import json

                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"drand fetch failed for {url}: {exc}") from exc

        return DrandBeaconEntry(
            round_number=int(data["round"]),
            randomness_hex=data["randomness"],
            signature_hex=data.get("signature", ""),
            previous_sig_hex=data.get("previous_signature", ""),
        )

    def latest(self) -> DrandBeaconEntry:
        """Fetch the latest beacon entry."""
        return self._fetch("latest")

    def at_round(self, round_number: int) -> DrandBeaconEntry:
        """Fetch the beacon entry at a specific round."""
        return self._fetch(str(round_number))

    @staticmethod
    def seed_from_entry(entry: DrandBeaconEntry) -> int:
        """Convert a beacon randomness hex string to an integer seed.

        Takes the first 8 bytes of randomness as a big-endian integer.
        This deterministic derivation lets any verifier reproduce the seed.
        """
        raw = bytes.fromhex(entry.randomness_hex[:16])  # first 8 bytes
        return int.from_bytes(raw, byteorder="big")

    def seeded_sampler(
        self,
        sigma: float,
        round_number: int | None = None,
        tail_bound: int | None = None,
        *,
        private_seed: int | None = None,
    ) -> tuple[DiscreteGaussianSampler, DrandBeaconEntry]:
        """Create a DiscreteGaussianSampler seeded from a drand beacon.

        Args:
            sigma: Noise standard deviation.
            round_number: Specific round (None = latest).
            tail_bound: Truncation bound (None = 6σ).
            private_seed: Optional private entropy mixed into the public beacon
                seed via XOR.  **Without this, the noise is fully reconstructible
                from the public beacon, which voids any DP guarantee.** Use this
                parameter to add a secret component when strong DP is required.
                When ``None``, the sampler is deterministic from the public beacon —
                suitable only for auditability/demonstration purposes.

        Returns:
            (sampler, beacon_entry) — entry for audit/verification.
        """
        entry = self.at_round(round_number) if round_number is not None else self.latest()
        seed = self.seed_from_entry(entry)
        if private_seed is not None:
            seed ^= private_seed
        sampler = DiscreteGaussianSampler(sigma=sigma, tail_bound=tail_bound, seed=seed)
        return sampler, entry
