# Proposed DP Sensitivity Errata for the ICLR 2027 and NDSS 2027 Drafts

Status: author proposal. The venue `.tex` files are intentionally unchanged.

## Corrected contract and derivation

The released text confuses the matrix spectral norm with the Euclidean norm
required by the Gaussian mechanism. For an `n × n` broadcast matrix, vector L2
is the Frobenius norm:

```text
||vec(A)||2 = ||A||F <= sqrt(n) ||A||2.
```

If every released matrix has a caller-certified spectral bound `||H||2 <= r`,
then for adjacent inputs `D,D'`:

```text
Delta2 = sup ||H(D) - H(D')||F
       <= ||H(D)||F + ||H(D')||F
       <= 2 r sqrt(n).
```

The production contract is therefore
`matrix_l2_sensitivity(certified_spectral_bound=r, matrix_dimension=n) =
2*r*sqrt(n)`. Noise is calibrated by `PrivacyAccountant.required_sigma`, which
inverts the Gaussian RDP bound and the accountant's Balle et al. conversion.
That bound is valid for every positive epsilon; the configured finite order
grid fails closed if it cannot certify an extreme budget. The classical
`sqrt(2 ln(1.25/delta))/epsilon` expression is not used because its usual
theorem is stated only for `epsilon < 1`.

Residual injection does not reduce this certified bound. The current update
blends the residual before a final spectral projection, while the public
contract certifies only the final spectral radius. No Frobenius clip or complete
adjacency Lipschitz proof exists from which to deduct a `(1-alpha)` factor. A
future mechanism may use a smaller declared Frobenius clip norm, but it must
enforce that clip directly.

For `n=50`, `r=1`, and `delta=1e-5`, the corrected values are:

| epsilon | proposed sigma |
|---:|---:|
| 1.0 | 57.21038854 |
| 2.0 | 30.39300970 |
| 4.0 | 16.37049377 |
| 8.0 | 9.01801824 |

These are theoretical calibration values. Existing empirical samples were
generated under the old scale and must remain historical until rerun.

## ICLR 2027 proposed replacements

### `sections/method.tex:147-178` — lemma, proof, and significance

Old text:

> Let `f(D) = Pi_r(H_new)` be the spectral projection with L2 sensitivity
> `Delta f <= 2r` ... `Delta g <= 2(1-alpha)r`. ... At `alpha = 0.1`, required
> noise is reduced by exactly `10%`.

Proposed replacement:

> Let `f(D)` release an `n x n` matrix whose spectral norm is certified at most
> `r`. The Gaussian mechanism uses vector L2 sensitivity, equal to matrix
> Frobenius sensitivity. Since `||A||F <= sqrt(n)||A||2`, the certified global
> sensitivity is `Delta2 f <= 2r sqrt(n)`. Residual injection does not change
> this fail-closed bound without an enforced Frobenius clip or a certified
> Lipschitz bound for the complete update. Calibrate Gaussian noise by inverting
> the RDP guarantee for sensitivity `2r sqrt(n)` and the stated `(epsilon,
> delta)` budget.

Replace the proof with the norm inequality and triangle-inequality derivation
above. Delete the claim that larger `alpha` implies less required noise.

### `sections/method.tex:180-202` — algorithm

Old text:

> `sigma <- 2(1-alpha)r * sqrt(2 ln(1.25/delta)) / epsilon`

Proposed replacement:

> `Delta2 <- 2r sqrt(n)` from the certified spectral bound; `sigma <-`
> all-epsilon RDP calibration for `(Delta2, epsilon, delta)`.

### Abstract, introduction, related work, and conclusion

Old text includes:

> residual injection at `alpha=0.1` reduces epsilon-DP noise requirements by
> exactly `10%`

> reduces the L2 sensitivity from `2r` to `2(1-alpha)r`

> reducing noise requirements by exactly `alpha * 100%`

Proposed replacement in each location:

> A certified spectral radius `r` for an `n x n` release implies vector-L2
> sensitivity at most `2r sqrt(n)`. The implementation calibrates Gaussian
> noise with an all-epsilon RDP accountant. Residual stability does not provide
> a privacy discount without an additional certified Frobenius bound.

Affected locations are `sections/abstract.tex:23-25`,
`sections/introduction.tex:68-71`, `sections/related_work.tex:39-47`, and
`sections/conclusion.tex:17-21`.

### `sections/experiments.tex:132-157` — DP table and narrative

Old values:

```text
epsilon  alpha=0  alpha=0.1  alpha=0.2  alpha=0.5
1.0      9.69     8.72        7.75       4.84
2.0      4.84     4.36        3.88       2.42
4.0      2.42     2.18        1.94       1.21
8.0      1.21     1.09        0.97       0.61
```

Proposed replacement: remove the residual-discount columns and report the
corrected table above with explicit `n=50`, `r=1`, and `delta=1e-5`. Replace
the `10%`, `20%`, and `50%` reduction narrative with:

> Alpha is not a calibration parameter under the certified sensitivity
> contract. At `epsilon=2`, the corrected theoretical noise is
> `sigma=30.39300970`.

## NDSS 2027 proposed replacements

### Abstract and introduction

Old text:

> `sigma = 2(1-alpha)r sqrt(2 ln(1.25/delta))/epsilon`; residual injection at
> `alpha=0.1` reduces required noise by `10%`.

> residual injection ... reduces the L2 sensitivity ... from `2r` to
> `2(1-alpha)r`.

Proposed replacement:

> For an `n x n` released matrix with certified spectral bound `r`, vector-L2
> sensitivity is at most `2r sqrt(n)`. The Gaussian noise scale is calibrated
> with an all-epsilon RDP accountant. No residual-based reduction is certified.

Affected locations are `sections/abstract.tex:20-23` and
`sections/introduction.tex:55-76`.

### `sections/protocol.tex:50-106` and `main.tex:96-110` — circuit and algorithm

Old text:

> This provides topological stability ... and tightens the DP sensitivity by
> factor `(1-alpha)`.

> `sigma = 2(1-alpha)r * sqrt(2ln(1.25/delta))/epsilon`.

Proposed replacement:

> Residual injection provides topological stability. It does not alter the
> certified DP sensitivity. The circuit must bind the matrix dimension and
> certified spectral bound used to derive `Delta2=2r sqrt(n)`, plus the
> accountant-derived sigma for `(epsilon,delta)`.

Replace both algorithm formula occurrences with the all-epsilon calibration.

### `sections/security_analysis.tex:72-100` — sensitivity lemma and DP theorem

Old lemma:

> `Delta g := max ||g(D_i)-g(D_i')||2 <= 2(1-alpha)r`, because spectral radius
> `r` implies diameter `2r`.

Proposed lemma:

> Interpreting L2 on the vectorized matrix, `||A||F <= sqrt(n)||A||2` gives
> `Delta2 g <= 2r sqrt(n)` from the certified final-output spectral bound. No
> `(1-alpha)` discount is claimed.

Old theorem proof:

> Gaussian noise with `sigma >= Delta g sqrt(2ln(1.25/delta))/epsilon` is DP;
> substitute `Delta g=2(1-alpha)r`.

Proposed theorem proof:

> Apply the Gaussian RDP bound at sensitivity `Delta2=2r sqrt(n)` and convert
> RDP to `(epsilon,delta)` with the same Balle et al. conversion used by the
> implementation. Choosing sigma by numerical inversion proves the stated
> guarantee whenever the finite configured order grid finds a certificate; it
> fails closed otherwise.

In `sections/security_analysis.tex:136`, replace `-10% at alpha=0.1` with
`Delta2 <= 2r sqrt(n); no residual discount`.

### `sections/evaluation.tex:53-77` — theoretical and empirical table

Old theoretical values are `8.721`, `4.360`, `2.180`, and `1.090`; the text also
compares `4.84` baseline with `4.36` residual injection and claims a `10%`
reduction.

Proposed theoretical values are `57.21038854`, `30.39300970`, `16.37049377`,
and `9.01801824`. The current table contains no empirical samples: its empirical
column literally says `formula check`. Remove the relative-error and
`DP verified` columns until the sampling experiment is rerun; neither an exact
formula self-check nor the existing `Yes` entries verify differential privacy.

### `sections/conclusion.tex:21-24` and `:37-39`

Old text claims residual injection reduces DP noise by `(1-alpha)` and suggests
tightening below `2(1-alpha)r`.

Proposed replacement:

> Spectral certification gives the conservative vector-L2 bound `2r sqrt(n)`.
> Future work may reduce it through an enforced Frobenius clip or a proof for
> the complete update path; residual injection alone supplies no discount.

## Empirical rerun requirement

The legacy harness contained constants `3.461`, `1.730`, `0.865`, and `0.433`,
plus `1.92` versus `1.73`. No measurement provenance is available for those
constants, and the current immutable NDSS table uses the literal marker
`formula check` instead of empirical numbers. Treat all of the legacy constants
as unverified historical artifacts. They must not be rescaled algebraically or
represented as measurements. A rerun must record the matrix dimension,
certified spectral bound, exact accountant orders, epsilon, delta, calibrated
sigma, sample count, seed provenance, and observed entrywise standard deviation.

## Verbatim old text inventory

The following excerpts are copied exactly from the immutable venue sources so
authors can apply the proposals above without guessing which text is superseded.

### ICLR `sections/abstract.tex:23-25`

```latex
Finally, we show that residual injection at $\alpha{=}0.1$ reduces $\varepsilon$-DP
noise requirements by exactly $10\%$ (Lemma~\ref{lem:residual_sensitivity}), proving
that topological stability and cryptographic privacy are complementary rather than
competing objectives.
```

### ICLR `sections/introduction.tex:68-71`

```latex
  \item \textbf{$\varepsilon$-DP compatibility (Lemma~\ref{lem:residual_sensitivity}).}
    Residual injection at strength $\alpha$ reduces the $\ell_2$ sensitivity from $2r$
    to $2(1-\alpha)r$, cutting required DP noise by a factor $(1-\alpha)$.  Stability and
    privacy are synergistic.
```

### ICLR `sections/related_work.tex:39-47`

```latex
\paragraph{Differential privacy for multi-agent systems.}
Federated learning with differential privacy \cite{mcmahan2018dp,geyer2017dp} adds
calibrated Gaussian noise to model updates before aggregation.  The Gaussian mechanism
\cite{dwork2014algorithmic} requires calibration to the $\ell_2$ sensitivity of the
function being privatized.  Our Lemma~\ref{lem:residual_sensitivity} tightens the
sensitivity bound from $2r$ to $2(1-\alpha)r$ via the algebraic cancellation of $\alpha I$
terms, reducing noise requirements by exactly $\alpha \cdot 100\%$.  A related
sensitivity analysis appears in federated Sinkhorn \cite{federated_sinkhorn2025}, but
without the residual-injection tightening.
```

### ICLR `sections/method.tex:147-178`

```latex
\subsection{Differential Privacy via Residual Sensitivity}

\begin{lemma}[$\ell_2$ Sensitivity with Residual Injection]
  \label{lem:residual_sensitivity}
  Let $f(D) = \Pi_r(H_{\mathrm{new}})$ be the spectral projection with $\ell_2$
  sensitivity $\Delta f \leq 2r$ (from the diameter of $\mathcal{S}_r$).  Let
  $g(D) = (1-\alpha)f(D) + \alpha I$ be the residual-injected function.  Then:
  \[
    \left\|g(D) - g(D')\right\|_2
      = (1-\alpha)\left\|f(D) - f(D')\right\|_2
      \leq 2(1-\alpha)r =: \Delta g.
  \]
  The $\alpha I$ terms cancel exactly.  The Gaussian mechanism with noise $Z \sim
  \mathcal{N}(0, \sigma^2 I)$ achieves $(\varepsilon, \delta)$-DP if:
  \[
    \sigma = \frac{2(1-\alpha)r \cdot \sqrt{2 \ln(1.25/\delta)}}{\varepsilon}.
  \]
  At $\alpha = 0.1$, required noise is reduced by exactly $10\%$ relative to the
  baseline $\Delta f = 2r$.
\end{lemma}

\begin{proof}
  $\|g(D) - g(D')\|_2 = \|(1-\alpha)f(D) + \alpha I - (1-\alpha)f(D') - \alpha I\|_2
  = (1-\alpha)\|f(D) - f(D')\|_2 \leq 2(1-\alpha)r$. \qed
\end{proof}

\paragraph{Significance.}
The factor $(1-\alpha)$ means that the same $\alpha$ controlling topological stability
also controls DP noise.  There is no tradeoff: more stability ($\alpha$ larger) implies
less required noise.  At $\alpha = 0.2$ the noise budget shrinks by $20\%$; at $\alpha =
0.5$ by $50\%$.  This synergy is a structural consequence of the algebraic form of
residual injection and holds for any $r > 0$ and any $(\varepsilon, \delta)$.
```

### ICLR `sections/method.tex:192-197`

```latex
  \tcp{Step 2: Residual injection}
  $H_{\mathrm{proj}} \leftarrow (1-\alpha)\,H_{\mathrm{proj}} + \alpha I$\;
  \BlankLine
  \tcp{Step 3: Calibrate Gaussian noise (Lemma~\ref{lem:residual_sensitivity})}
  $\sigma \leftarrow 2(1-\alpha)r \cdot \sqrt{2 \ln(1.25/\delta)} \,/\, \varepsilon$\;
  $Z \sim \mathcal{N}(0, \sigma^2 I_{n^2})$\;
```

### ICLR `sections/experiments.tex:137-157`

```latex
  \caption{Noise $\sigma$ required for $(\varepsilon, \delta)$-DP as a function of
    residual strength $\alpha$, with $r=1.0$, $\delta=10^{-5}$.
    Baseline ($\alpha{=}0$) sensitivity $\Delta f = 2r = 2.0$.}
  \label{tab:dp_noise}
  \begin{tabular}{ccccc}
    \toprule
    $\varepsilon$ & $\alpha{=}0$ (baseline) & $\alpha{=}0.1$ & $\alpha{=}0.2$ & $\alpha{=}0.5$ \\
    \midrule
    1.0 & 9.69 & 8.72 ($-10\%$) & 7.75 ($-20\%$) & 4.84 ($-50\%$) \\
    2.0 & 4.84 & 4.36 ($-10\%$) & 3.88 ($-20\%$) & 2.42 ($-50\%$) \\
    4.0 & 2.42 & 2.18 ($-10\%$) & 1.94 ($-20\%$) & 1.21 ($-50\%$) \\
    8.0 & 1.21 & 1.09 ($-10\%$) & 0.97 ($-20\%$) & 0.61 ($-50\%$) \\
    \bottomrule
  \end{tabular}
\end{table}

Table~\ref{tab:dp_noise} verifies Lemma~\ref{lem:residual_sensitivity} numerically.
The noise reduction at $\alpha{=}0.1$ is exactly $10\%$ across all $\varepsilon$
values, confirming the algebraic cancellation.  At the recommended operating point
($\varepsilon{=}2.0$, $\alpha{=}0.1$), the required noise is $\sigma = 4.36$, down from
the baseline $4.84$.
```

### ICLR `sections/conclusion.tex:17-21`

```latex
A secondary contribution is the algebraic proof (Lemma~\ref{lem:residual_sensitivity})
that residual injection reduces $\varepsilon$-DP noise requirements by exactly
$(1-\alpha) \cdot 100\%$.  At $\alpha{=}0.1$, the stability fix reduces required DP
noise by $10\%$ — confirming that topological stability and differential privacy are
synergistic rather than competing objectives.
```

### NDSS `sections/abstract.tex:20-23`

```latex
\textbf{$(\varepsilon, \delta)$-DP Privacy}: agent trust weights satisfy differential
privacy with noise $\sigma = 2(1-\alpha)r\sqrt{2\ln(1.25/\delta)}/\varepsilon$; residual
injection at $\alpha{=}0.1$ reduces required noise by $10\%$ relative to the
non-residual baseline.
```

### NDSS `sections/introduction.tex:55-60` and `:75-76`

```latex
\paragraph{Key insight: residual injection tightens DP.}
A structural observation (Lemma~\ref{lem:sensitivity}) is that residual injection —
introduced in \cite{mcfs_iclr2027} to prevent trust collapse — also reduces the
$\ell_2$ sensitivity of the broadcast function from $2r$ to $2(1-\alpha)r$.  At
$\alpha = 0.1$, this reduces required Gaussian noise by $10\%$ for the same
$(\varepsilon, \delta)$ budget.  Stability and privacy are synergistic rather than
competing.
```

```latex
  \item Sensitivity tightening via residual injection (Lemma~\ref{lem:sensitivity}),
    reducing DP noise by $(1-\alpha)$ multiplicatively.
```

### NDSS `sections/protocol.tex:86-106`

```latex
\paragraph{Step 3 — Residual injection.}
\begin{equation}
  \label{eq:residual}
  H_{\mathrm{proj}} \leftarrow (1-\alpha)\,H_{\mathrm{proj}} + \alpha I,
  \quad \alpha = 0.1.
\end{equation}
This provides topological stability (Section~\ref{sec:security}) and tightens the DP
sensitivity by factor $(1-\alpha)$ (Lemma~\ref{lem:sensitivity}).

\paragraph{Step 4 — DP noise addition.}
Calibrate $\sigma$ to Lemma~\ref{lem:sensitivity}:
\begin{equation}
  \label{eq:sigma}
  \sigma = \frac{2(1-\alpha)r \cdot \sqrt{2\ln(1.25/\delta)}}{\varepsilon}.
\end{equation}
Sample $Z \sim \mathcal{N}(0, \sigma^2 I_{n^2})$ using VRF-seeded randomness and
compute the noisy matrix:
\begin{equation}
  \label{eq:noisy_matrix}
  \tilde{H} \leftarrow H_{\mathrm{proj}} + Z.
\end{equation}
```

### NDSS `main.tex:101-106`

```latex
  $H_{\mathrm{new}} \leftarrow \phi(D_i)$ \tcp*{Local trust computation}
  $H_{\mathrm{proj}} \leftarrow \Pi_r(H_{\mathrm{new}})$ \tcp*{Spectral projection}
  $H_{\mathrm{proj}} \leftarrow (1-\alpha)H_{\mathrm{proj}} + \alpha I$
    \tcp*{Residual injection}
  $\sigma \leftarrow 2(1-\alpha)r\sqrt{2\ln(1.25/\delta)}/\eps$ \tcp*{Lemma~\ref{lem:sensitivity}}
  $Z \sim \mathcal{N}(0, \sigma^2 I)$ \tcp*{DP noise}
```

### NDSS `sections/security_analysis.tex:74-100`

```latex
\begin{lemma}[$\ell_2$ Sensitivity with Residual Injection]
  \label{lem:sensitivity}
  Let $g(D_i) = (1-\alpha)\Pi_r(\phi(D_i)) + \alpha I$ be the residual-injected
  projection function.  Then:
  \[
    \Delta g := \max_{D_i, D_i'} \|g(D_i) - g(D_i')\|_2 \leq 2(1-\alpha)r.
  \]
  \emph{Proof.} $\|g(D) - g(D')\|_2 = (1-\alpha)\|\Pi_r(\phi(D)) - \Pi_r(\phi(D'))\|_2
  \leq (1-\alpha) \cdot 2r$, since the $\alpha I$ terms cancel and
  $\|\Pi_r(\cdot)\|_2 \leq r$ implies diameter $2r$.  \qed
\end{lemma}

\begin{theorem}[$(\varepsilon,\delta)$-DP Guarantee]
  \label{thm:dp_guarantee}
  The \fedsink{} broadcast mechanism $\mathcal{M}(D_i) = g(D_i) + Z$,
  $Z \sim \mathcal{N}(0, \sigma^2 I)$, with $\sigma$ as in equation~\eqref{eq:sigma},
  satisfies $(\varepsilon, \delta)$-differential privacy.
\end{theorem}

\begin{proof}
  By the Gaussian mechanism \cite{dwork2014algorithmic}: a mechanism adding
  $\mathcal{N}(0, \sigma^2 I)$ to a function of sensitivity $\Delta g$ achieves
  $(\varepsilon, \delta)$-DP if
  $\sigma \geq \Delta g \sqrt{2\ln(1.25/\delta)}/\varepsilon$.
  Substituting $\Delta g = 2(1-\alpha)r$ (Lemma~\ref{lem:sensitivity}) gives
  equation~\eqref{eq:sigma}.
\end{proof}
```

### NDSS `sections/security_analysis.tex:130-136`

```latex
    Input privacy        & Gaussian DP noise        & $(\varepsilon,\delta)$-DP \\
    Routing integrity    & Spectral constraint       & $\spnorm{H_{\mathrm{proj}}} \leq r$ \\
    Anti-bribery         & zk-SNARK ZK               & MACI \\
    Byzantine tolerance  & Proof rejection + CID     & $f < N/3$ \\
    Eventual consistency & CAI CRDT merge            & EEC in $O(\log N)$ \\
    Collapse prevention  & Residual injection        & $\mathrm{VR} > 0$ always \\
    Noise reduction      & Residual sensitivity      & $-10\%$ at $\alpha{=}0.1$ \\
```

### NDSS `sections/evaluation.tex:57-77`

```latex
  \caption{Empirical noise $\sigma$ vs.\ theoretical calibration.
    $r=1.0$, $\delta=10^{-5}$, $\alpha=0.1$.
    ``Relative error'' is $|{\sigma_{\mathrm{emp}} - \sigma_{\mathrm{theory}}}|/\sigma_{\mathrm{theory}}$.}
  \label{tab:dp_accuracy}
  \begin{tabular}{ccccc}
    \toprule
    $\varepsilon$ & $\sigma_{\mathrm{theory}}$ & $\sigma_{\mathrm{emp}}$ & Rel.\ error & DP verified \\
    \midrule
    1.0 & 8.721 & formula check & exact & Yes \\
    2.0 & 4.360 & formula check & exact & Yes \\
    4.0 & 2.180 & formula check & exact & Yes \\
    8.0 & 1.090 & formula check & exact & Yes \\
    \bottomrule
  \end{tabular}
\end{table}

Table~\ref{tab:dp_accuracy} confirms that implementation calibration matches
equation~\eqref{eq:sigma}.  The $10\%$ noise reduction from $\alpha{=}0.1$ residual
injection (Lemma~\ref{lem:sensitivity}) is verified: at $\varepsilon{=}2.0$, baseline
$\sigma = 4.84$ vs.\ residual-injection
$\sigma = 4.36$, a reduction of $10\%$.
```

### NDSS `sections/conclusion.tex:21-24` and `:37-39`

```latex
A structural observation (Lemma~\ref{lem:sensitivity}) is that residual injection reduces
DP noise requirements by $(1-\alpha)$ multiplicatively — at $\alpha{=}0.1$, a $10\%$
reduction with no tradeoff in stability or security.  The stability fix and the
cryptographic efficiency improvement are synergistic.
```

```latex
  \item \textbf{Tight sensitivity via BODES composition.}  When $H_{\mathrm{proj}}$
    derives from BODES latent steering vectors, the output space may be a strict subset
    of $\mathcal{S}_r$, lowering $\Delta g$ further below $2(1-\alpha)r$.
```
