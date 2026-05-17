# ACGS-Swarm Gap Register

This register keeps claim closure evidence separate from implementation health.
Closing a gap requires either deterministic evidence or an explicit non-claim boundary.

| gap id | area | status | evidence artifact | closure condition |
|---|---|---|---|---|
| GAP-SWEBENCH-OFFICIAL | Official SWE-bench | open external validation | `scripts/run_official_swarm_swebench.py`; `scripts/convert_swarm_output_to_swebench_predictions.py`; `docs/internal/official_swebench_artifact_checklist.md` | Official SWE-bench Docker/container harness output exists, predictions are JSONL with `instance_id`, `model_name_or_path`, and `model_patch`, and resolved/completed metrics are archived. Until then, official SWE-bench results are not claimed. |
| GAP-SWEBENCH-SYNTHETIC | Local SWE-bench-shaped routing | closed local evidence | `scripts/eval_swe_bench_synthetic.py`; `scripts/reproduce_paper_claims.py --claim-id NDSS-20`; `scripts/reproduce_paper_claims.py --claim-id NDSS-21` | Deterministic seeds report flat, explicit Sinkhorn-CRDT, FedSink, and oracle baselines with `synthetic_only=true` and both official-SWE-bench flags false. |
| GAP-SINKHORN-BASELINE | Sinkhorn-CRDT comparator | closed local evidence | `scripts/eval_swe_bench_synthetic.py` | Baseline uses `GovernanceManifold`/Sinkhorn as a research-control routing baseline and is not described as repaired SpectralSphere behavior. |
| GAP-LATENCY-PORTABILITY | CPU-specific latency claims | closed boundary | `papers/ndss2027/sections/evaluation.tex`; `scripts/reproduce_paper_claims.py --claim-id NDSS-22`; `scripts/reproduce_paper_claims.py --claim-id NDSS-23` | Paper reports latency values as machine-specific JSON/formula evidence, not portable constants. |
| GAP-DP-SCALE | DP table scale mismatch | closed explanation | `docs/internal/claims_map.md`; `scripts/reproduce_paper_claims.py --claim-id ICLR-15` | Table consistency and formula-derived sigma are recorded separately; future paper edits must either adjust constants or preserve the explicit calibration-boundary note. |
| GAP-CLAIM-MAP-TRUTH | Stale claims-map verification rows | closed gate | `tests/test_paper_reproducibility.py::test_claim_map_reproducer_row_matches_live_registry` | Test runs the live claim registry and checks the verification row still states the matching exit code/result. |
| GAP-RUNTIME-GOVERNANCE | Governance framing | closed wording boundary | `papers/ndss2027/sections/introduction.tex` | Paper frames governance as runtime path/routing/tool-authority enforcement, not prompt-only policy. |
| GAP-PYTEST-HYGIENE | Global pytest plugin contamination | closed gate hygiene | `pyproject.toml` | Repo pytest config disables the global Braintrust pytest plugin and pins pytest-asyncio fixture loop scope. |
| GAP-V01-VERIFIER-FIRST-SCOPE | Public v0.1 scope | closed planning boundary | `docs/internal/acgs_v0_1_verifier_first_scope.md`; `docs/internal/governance_benchmark_plan.md` | v0.1 is bounded to portable receipts, independent verifier tooling, focused DevOps adversarial benchmark workloads, four metrics, strong central baseline, explicit non-goals, and no production-grade governance claims. |
| GAP-V01-PORTABLE-RECEIPTS | Portable receipt profile | closed local evidence | `docs/internal/acgs_v0_1_receipt_profile_adr.md`; `src/constitutional_swarm/governance_receipts.py`; `tests/test_governance_receipts.py` | A local in-toto/DSSE-shaped receipt profile is implemented with explicit non-claims and migration notes for future SCITT, Sigstore/Rekor, COSE, and W3C VC alignment. |
| GAP-V01-EVIDENCE-VERIFIER | Independent evidence verifier | closed local evidence | `src/constitutional_swarm/governance_receipts.py`; `src/constitutional_swarm/governance_receipts_cli.py`; `scripts/verify_governance_receipts.py`; `tests/test_governance_receipts.py` | Standalone verifier checks schema, chain continuity, missing decisions, tampering, trusted-signer signatures, role separation, and deterministic replay verdicts; re-signed tampering with unknown keys fails closed. |
| GAP-V01-ADVERSARIAL-BENCHMARK | Focused adversarial benchmark | owner-published public-study artifacts verified; external independent rerun still open | `src/constitutional_swarm/governance_fixtures.py`; `src/constitutional_swarm/forensic_benchmark.py`; `scripts/run_governance_benchmark.py --protocol-manifest`; `scripts/run_governance_benchmark.py --generate-incident-pack`; `scripts/run_governance_benchmark.py --validate-result-bundle`; `scripts/run_governance_benchmark.py --write-external-replication-submission`; `scripts/run_governance_benchmark.py --validate-external-replication-submission`; `tests/test_governance_receipts.py`; `docs/public-replication.md`; `docs/public-replication-request.json`; `.github/ISSUE_TEMPLATE/external_replication.yml`; GitHub release `acgs-v0.1-benchmark-kit-2026-05-16` | Runnable offline DevOps workloads cover collusion, slow-burn harm, and provenance forgery as local conformance fixtures. The public-study scaffold generates 50 matched artifacts with hidden answer keys separated. Fresh local smoke on 2026-05-16 validated incident pack generation, reviewer packet generation, result-bundle construction, scorecard validation, reviewer-cohort validation, replication metadata, attestation, submission-package rendering, and submission-package validation on synthetic data. The benchmark kit is publicly released at `https://github.com/dislovelhl/Acgs-Swarm/releases/tag/acgs-v0.1-benchmark-kit-2026-05-16` with immutable assets, the public guide, request template, issue template, and release notes all pointing to the rerun assets. Fresh web/GitHub sweeps on 2026-05-16 still found no independent rerun bundle; issue `#48` and discussion `#49` remain owner-authored only; repo metadata still reports `forks_count=0` / `network_count=0`. Those owner-published public-study artifacts are verified, but closure still requires a non-ACGS rerun bundle from an external group. |
| GAP-V01-STRONG-BASELINE | Non-strawman baseline | protocol defined; local scorecard and public-release evidence now verified; external study still open | `src/constitutional_swarm/forensic_benchmark.py`; `scripts/run_governance_benchmark.py --protocol-manifest`; `tests/test_governance_receipts.py`; GitHub release `acgs-v0.1-benchmark-kit-2026-05-16` | The study protocol requires matched artifact conditions for ungoverned raw logs, centralized structured logs, and ACGS receipts/audit artifacts, and scores ACGS against the strongest non-ACGS baseline. Fresh local validation shows the scorecard and result bundle can be built and validated, and the public GitHub release now exposes those artifacts, but closure still requires an external independent rerun and public evidence from outside this checkout, not only the local comparator. |
| GAP-V01-REPRODUCTION-BUDGET | External adoption budget | public release bundle and local replication commands verified; external replication still open | `src/constitutional_swarm/forensic_benchmark.py`; `scripts/run_governance_benchmark.py --protocol-manifest`; `scripts/run_governance_benchmark.py --generate-incident-pack`; `scripts/run_governance_benchmark.py --score-reviewer-answers --answer-key-json`; `scripts/run_governance_benchmark.py --build-result-bundle --answer-key-json`; `scripts/run_governance_benchmark.py --write-external-replication-submission`; `scripts/run_governance_benchmark.py --validate-external-replication-submission`; `scripts/run_governance_benchmark.py --validate-result-bundle`; `tests/test_governance_receipts.py`; GitHub release `acgs-v0.1-benchmark-kit-2026-05-16` | Benchmark reports command, model/backend, wall-clock, tokens, estimated cost, and runs the default conformance suite offline with zero token and dollar cost. Fresh local validation shows the result bundle, scorecard, reviewer cohort manifest, replication metadata, attestation, submission package, and submission validator can all validate on synthetic data, and the public release now exposes them under immutable GitHub asset URLs, but closure still requires a non-ACGS rerun bundle with generated artifact sets, blind-review answers that omit ground truth, significant scorecard, and completed external replication metadata from outside this checkout. |

## ACGS v0.1 Scope Boundary

The public v0.1 target is verifier-first infrastructure, not a broad governance
platform. The first independently runnable artifact should be the evidence verifier,
followed by a focused DevOps adversarial benchmark. The scope contract is captured
in `docs/internal/acgs_v0_1_verifier_first_scope.md` and the benchmark skeleton is
captured in `docs/internal/governance_benchmark_plan.md`.

Allowed v0.1 claims:

- portable governance receipts can be verified independently;
- receipt bundles are tamper-evident under the implemented hash/signature model;
- benchmark traces can be scored for reconstructability, containment delta,
  k-of-n compromise, and overhead;
- the public-study protocol can validate 50 to 200 blind-reviewed incidents,
  matched artifact conditions, fixed forensic questions, confidence calibration,
  inter-reviewer agreement, and performance delta against the strongest baseline;
- official SWE-bench, healthcare compliance, and production-grade governance are
  not claimed.
- the benchmark is a governance overlay for agent benchmarks, not a competing
  SWE-bench task-success claim.

## Official SWE-bench Artifact Boundary

Official SWE-bench remains open until a real harness bundle exists. Synthetic local
routing evidence may support architecture claims, but it must not be described as
official SWE-bench performance.

Required official bundle:

- predictions JSONL with `instance_id`, `model_name_or_path`, and `model_patch`;
- exact dataset/split/model/backend command line;
- Docker/containerized SWE-bench harness logs;
- resolved/completed summary metrics;
- archive path committed or referenced from a reproducible internal report;
- update to `docs/internal/claims_map.md` changing official status only after the
  bundle exists.
