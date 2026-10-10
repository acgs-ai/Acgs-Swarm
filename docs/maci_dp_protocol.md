# Path B: ε-DP FedSink-MACI Protocol Specification

**Document:** Decentralized Differential Privacy for Continuous Swarm Routing  
**Track:** MCFS Phase 3 — Decentralized State and Cryptography  
**Target:** NDSS 2027 / IEEE S&P 2027  
**Status:** Draft v0.1 — 2026-04-12

---

## Context

In the MCFS architecture, agents broadcast updated routing matrices (or Sinkhorn
scaling vectors) to the peer-to-peer Merkle-CRDT. If broadcast in the clear,
adversarial nodes can reverse-engineer an agent's internal state, prompts, or latent
activations — a severe vulnerability when BODES (Phase 1) is active and the routing
matrix encodes the agent's constitutional threat model.

This protocol provides `(ε, δ)`-Differential Privacy over the routing broadcast
combined with Minimal Anti-Collusion Infrastructure (MACI) via zk-SNARKs.

---

## 1. Threat Model

**Honest-but-Curious Peers**  
Nodes that read the Merkle-CRDT to update local global-state and attempt to infer
the private data (activations, prompts, trust specialization) of other agents.

**Byzantine / Colluding Nodes**  
Nodes that bribe or coerce agents into routing tasks to specific sub-manifolds
(Sybil routing attack). Target: force high-value tasks toward controlled executors.

**Out of scope (v1)**  
Timing side-channels, traffic analysis, compromised VRF oracles.

---

## 2. Gaussian Mechanism for Spectral-Sphere Routing

### Lemma 1: L₂ Sensitivity (Δf)

Let `f(D)` be the local computation producing the projected routing matrix
`H_proj ∈ ℝⁿˣⁿ` from agent data/activations `D`.

The privacy API requires a caller-certified final-output bound
`‖H_proj‖₂ ≤ r`. A deterministic SVD-based projection with a checked
finite-precision postcondition, or an independently verified certificate, may
establish this bound; stochastic power iteration is only an estimate and is not
accepted as a DP certificate.

The Gaussian mechanism acts on the vectorized matrix, so its L₂ norm is the
matrix Frobenius norm. For an `n × n` matrix, `‖A‖F ≤ √n ‖A‖₂`. The certified
spectral bound therefore implies the following worst-case sensitivity:

```
Δ₂f = max_{D, D'} ‖vec(f(D) − f(D'))‖₂
     = max_{D, D'} ‖f(D) − f(D')‖F
     ≤ 2r√n
```

**Proof sketch:** Both outputs have spectral norm at most `r`, hence Frobenius
norm at most `r√n`. The triangle inequality gives a Frobenius diameter of
`2r√n`. The spectral diameter `2r` is not an L₂ bound for the vectorized
matrix. □

### Theorem 1: (ε, δ)-DP Guarantee

To satisfy `(ε, δ)`-DP, agent `i` adds a noise matrix `Z` drawn from a Gaussian
distribution to `H_proj` before broadcast:

```
H̃ = H_proj + Z,    Z ~ N(0, σ²I)
```

The implementation calibrates the Gaussian mechanism by inverting its Rényi-DP
bound and the Balle et al. conversion used by `PrivacyAccountant`. The RDP
bound is valid for all positive `ε`; the finite configured order grid fails
closed if it cannot certify an extreme budget:

```
Δ₂f = 2r√n
σ = PrivacyAccountant(ε, δ).required_sigma(sensitivity=Δ₂f)
```

**Parameter guidance (`r = 1.0`, `n = 50`, `δ = 10⁻⁵`):**

| Privacy budget | δ      | σ (r=1.0, n=50) | Notes                      |
|---------------|--------|------------------|----------------------------|
| ε = 1.0       | 10⁻⁵   | 57.21038854      | Strong privacy, high noise |
| ε = 2.0       | 10⁻⁵   | 30.39300970      | Moderate privacy budget    |
| ε = 4.0       | 10⁻⁵   | 16.37049377      | Looser privacy budget      |
| ε = 8.0       | 10⁻⁵   | 9.01801824       | Loose privacy budget       |

**Composition:** Use one session-scoped `PrivacyAccountant`. Before each
broadcast, call `required_sigma` with the certified sensitivity; after the
mechanism runs, call `spend` with the same sensitivity and sigma, then
`assert_budget`. The accountant composes RDP across the recorded history and
fails closed when the configured finite order grid cannot certify the budget.

---

## 3. MACI Integration — zk-SNARK Protocol Execution

Gaussian noise protects underlying data from honest-but-curious peers. MACI via
zk-SNARKs additionally prevents bribery: an agent cannot prove to a colluder that
it routed a specific task in a specific direction.

### Protocol Steps

**Step 1 — Local Computation**
Agent `i` computes its unprojected routing update `H_new` from local activations.

**Step 2 — Residual Injection** (stability, α = 0.1)
```python
H_res = (1 - alpha) * H_new + alpha * I
```

**Step 3 — Final Certified Spectral Projection**
```python
from constitutional_swarm.swarm_ode import exact_spectral_project_torch

H_proj = exact_spectral_project_torch(H_res, r=1.0)
```

Here `H_res` is a finite floating-point `torch.Tensor`. The helper computes the
largest singular value with `torch.linalg.svdvals`, rescales when needed, and
rechecks the result. Its finite-precision contract is `‖H_proj‖₂ ≤ r`; it raises
if that postcondition cannot be certified.

**Step 4 — DP Noise Addition**
Sample `Z ~ N(0, σ²I)` and compute noisy public matrix:
```
H̃ = H_proj + Z
```

**Step 5 — zk-SNARK Generation**  
Agent `i` generates proof `π` asserting:
- `H̃` was computed correctly from a valid `H_new`
- The projection `‖H_proj‖₂ ≤ r` was enforced (spectral constraint satisfied)
- `Z` was drawn from the correct distribution (via VRF or hash-to-curve)

Circuit statement (informal):
```
∃ H_res, H_proj, Z  such that:
    H_res = (1-α) · H_new + α·I
    H_proj = certified_spectral_projection(H_res, r)
    spectral_norm(H_proj) ≤ r
    H̃ = H_proj + Z
    Z is a valid Gaussian sample (via verifiable randomness)
```

**Step 6 — Merkle-CRDT Broadcast**  
Agent appends tuple `(CID, H̃, π)` to the Merkle-CRDT.

**Step 7 — Peer Verification**  
Receiving agents verify `π` before accepting `H̃` into their local state.
Invalid proofs are rejected without gossip propagation (BFT rejection function).

---

## 4. Impact on Neural ODE Dynamics (Phase 4)

Because `Z` is zero-mean (`E[Z] = 0`), the macroscopic mean-field dynamics of
the swarm are unaffected. The Neural ODE solver integrates over Gaussian noise
on the ensemble trajectory:

```
dH/dt = f_θ(H, t) + Z(t)    where E[Z(t)] = 0
```

This is a stochastic differential equation (Langevin dynamics) with the noise
term serving as a temperature parameter for the swarm's exploration-exploitation
tradeoff. At low `σ` (high ε, loose privacy) the swarm is deterministic. At
high `σ` (tight privacy) it explores more, potentially discovering novel routing
solutions.

**Heuristic stability scale:** an `n × n` iid Gaussian matrix has leading
spectral-norm scale about `2σ√n`. Thus `σ ≤ r/(2√n)` keeps that leading scale at
or below `r`. This is a dynamics heuristic, not part of the DP proof.

---

## 5. Security Properties

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| Input privacy | Gaussian noise (σ calibrated) | `(ε, δ)`-DP |
| Routing integrity | Spectral constraint in circuit | ‖H_proj‖₂ ≤ r always |
| Anti-bribery | zk-SNARK — agent cannot prove routing intent | MACI |
| Byzantine fault tolerance | Proof rejection + Merkle-DAG causal links | BFT-CRDT |
| Eventual consistency | Commutative CRDT merge | Strong EEC |

---

## 6. Open Questions

1. **Sensitivity tightness:** Can the update be clipped directly in Frobenius
   norm, yielding a declared clip bound smaller than `2r√n`? Residual structure
   alone does not certify a discount for the final projected output.

2. **zk-SNARK circuit complexity:** Proving the Gaussian draw is valid requires
   either a VRF (cheap, online assumption) or hash-to-curve (more expensive, fully
   non-interactive). For n > 100 agents, the circuit size needs benchmarking.

3. **Composition with BODES:** If `H_proj` is derived from the BODES latent
   steering vector, the sensitivity analysis must account for the CBF projection
   — the output space may be a strict subset of the spectral sphere, lowering `Δf`.

4. **Adaptive ε schedule:** High-stakes governance rounds (constitutional amendments)
   should use tight ε. Routine task routing can use loose ε. A session-level ε
   budget with adaptive allocation per round is unexplored.

---

## 7. Implementation Sketch

```python
import numpy as np
import torch
from constitutional_swarm.swarm_ode import calibrate_sigma, exact_spectral_project_torch


def dp_broadcast_matrix(
    h_new: list[list[float]],
    *,
    r: float = 1.0,
    residual_alpha: float = 0.1,
    epsilon: float = 2.0,
    delta: float = 1e-5,
) -> tuple[list[list[float]], float]:
    """Apply residual injection, final spectral projection, and Gaussian noise.

    Returns (H_tilde, sigma) — the noisy matrix and the noise standard deviation.
    The zk-SNARK proof generation (Step 5) is out of scope here.
    """
    n = len(h_new)

    # Step 2: residual injection
    beta = 1.0 - residual_alpha
    residual = [
        [beta * h_new[i][j] + (residual_alpha if i == j else 0.0) for j in range(n)]
        for i in range(n)
    ]

    # Step 3: exact-SVD projection with a checked finite-precision postcondition.
    residual_tensor = torch.tensor(residual, dtype=torch.float64)
    projected = exact_spectral_project_torch(residual_tensor, r=r)
    H = projected.detach().cpu().numpy().tolist()

    # Step 4: Gaussian DP noise
    sigma = calibrate_sigma(
        certified_spectral_bound=r,
        matrix_dimension=n,
        epsilon=epsilon,
        delta=delta,
    )
    noise = np.random.normal(0, sigma, (n, n))
    H_tilde = [[H[i][j] + noise[i][j] for j in range(n)] for i in range(n)]

    return H_tilde, sigma
```

---

## 8. Addendum: Why Residual Injection Does Not Reduce the Certified Bound

In Phase 2, the MCFS architecture introduced residual identity injection to prevent
Birkhoff Uniformity Collapse:

```
H_proj = (1 − α) · Proj_r(H_new) + α · I
```

where α ∈ (0, 1). The identity term cancels when comparing adjacent inputs, but
that observation does not establish the sensitivity used by the production
mechanism. The implementation applies residual blending before a final spectral
projection, and the certified public contract bounds only that final output in
spectral norm. Projection onto a convex set is non-expansive in Frobenius norm,
but there is no certified Frobenius sensitivity for the unprojected update to
which a `(1−α)` factor can safely be applied.

The fail-closed bound therefore remains:

```
Δ₂ ≤ 2r√n
```

independent of α. A smaller value is valid only when the mechanism enforces and
declares a Frobenius clip norm, or when a separate proof certifies a tighter
adjacency Lipschitz bound for the complete update path. The previously stated
10%, 20%, and 50% residual discounts are withdrawn; author-facing replacements
are listed in `papers/DP_SENSITIVITY_ERRATA.md`.

---

## References

- Dwork, C., McSherry, F., Nissim, K., & Smith, A. "Calibrating Noise to Sensitivity in Private Data Analysis." *Theory of Cryptography Conference (TCC)*, pp. 265–284, 2006. doi:10.1007/11681878_14
- Dwork, C. & Roth, A. "The Algorithmic Foundations of Differential Privacy." *Foundations and Trends in Theoretical Computer Science*, 9(3–4):211–407, 2014. doi:10.1561/0400000042
- Kleppmann, M. & Beresford, A. R. "Merkle-CRDTs: Merkle-DAGs Meet CRDTs." arXiv:2004.00107, 2022.
- Shapiro, M., Preguiça, N., Baquero, C., & Zawirski, M. "Conflict-Free Replicated Data Types." *Stabilization, Safety, and Security of Distributed Systems*, pp. 386–400, 2011. doi:10.1007/978-3-642-24550-3_29
- Anonymous. "Spectral-Sphere-Constrained Hyper-Connections (sHC)." arXiv:2603.20896, 2026.
- Xie, Z., et al. "Manifold-Constrained Hyper-Connections (mHC)." arXiv:2512.24880, 2025.
- Anonymous. "Federated Sinkhorn: Distributed Doubly-Stochastic Matrix Scaling Under Differential Privacy." arXiv:2502.07021, 2025.
- Buterin, V., et al. "MACI: Minimal Anti-Collusion Infrastructure." Privacy & Scaling Explorations, 2023. <https://privacy-scaling-explorations.github.io/maci/>

> The master BibTeX file for all references above is [`references.bib`](../references.bib) at the repository root.
