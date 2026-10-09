# ACGS-Swarm v0.1 Completion Audit

This audit maps the active v0.1 forensic reconstructability goal to concrete
repo evidence. It is intentionally conservative: local scaffolding can support a
public study, but it is not a substitute for collected blind-review results or
external replication.

## C15 Correction and Current Status

The C12 forensic review invalidated the earlier completion interpretation. C15
introduces controls for the local key-substitution and cross-condition-linkage
defects in newly generated C15-format packs. The security rework adds
reviewer-specific pseudonyms, opaque packet ordering, canonical packet checks in
seal and verify paths, copied-answer diagnostics, and a strict evidence-name
allowlist. The final rework removes plain unblinded-artifact hashes from
coordinator manifests, adds a greater-than-95-percent reviewer-answer agreement
diagnostic, requires a retained nonce source for standalone packet generation,
and reports specific reviewer-packet leak codes. These changes define local
integrity controls; they do not supply authenticated external provenance or new
empirical study evidence. Historical commands and published numbers below remain
recorded, but they are not current success evidence. The previous
statement that the
"public-study tier is verified" applied only to the presence and old-schema
validation of the owner-published blind-review data and scorecard. It did not
establish structural blinding, bind result claims to the bytes of referenced
files, or use the incident as the statistical unit of independence.

The C15 local validation contract requires the implementation to:

- reject direct or mechanically normalized answer copies in reviewer artifacts;
- treat all seven hidden answers as synthetic assessment classifications derived
  deterministically from exposed incident attributes, without claiming that the
  copy guard proves human reconstructability;
- disclose that legitimate evidence availability and content can still reveal
  condition identity even when schemas and superficial value domains match;
- regenerate the answer key, condition key, templates, manifests, and every
  manifested reviewer artifact from the secret per-pack `pack_nonce`, requiring
  byte equality before scoring;
- separately require `--verify-replication-kit` and reviewer-packet generation
  from `--coordinator-pack` to regenerate and byte-compare the complete
  coordinator pack, including unblinded `artifacts/**` sources omitted from
  plain-hash manifests;
- require an expected precollection commitment supplied separately from the
  mutable bundle and bind that digest into the answer seal;
- use the fixed six-reviewer cohort, with a balanced
  assignment that exposes each reviewer to one condition per underlying
  incident and reviewer-specific, condition-specific HMAC-SHA256 incident
  pseudonyms, with packet rows and paths ordered only by opaque pseudonym;
- reject answer rows outside the regenerated reviewer assignment;
- compute significance only from the sealed answer matrix using an exact
  one-sided sign test over incident-stratified, between-reviewer contrasts;
- hash actual referenced file bytes during bundle construction and re-hash them
  during validation, while rejecting logical evidence names outside the fixed
  required set plus optional scorecard;
- omit plain hashes of unblinded source artifacts from the coordinator reviewer
  manifest and kit manifest; `--verify-replication-kit` and reviewer-packet
  generation from `--coordinator-pack` regenerate those sources from the
  retained nonce for path and byte verification;
- keep `coordinator_pack/reviewer_manifest.json` and `kit_manifest.json`
  coordinator-only until unblinding, distributing only isolated filtered
  reviewer manifests;
- derive standalone reviewer packets from a retained coordinator pack or nonce
  file, reject a missing nonce source, and warn on compatibility-only inline
  nonce input;
- treat command lines, attestor names, and unsigned provenance as diagnostics.
  They cannot set external-success or independence fields true. Exact or
  greater-than-95-percent reviewer answer agreement is also diagnostic, not
  authenticated copying or independence evidence; and
- return explicit `unblinded_artifact_present` and
  `coordinator_manifest_present` audit issues for those packet leak classes.

Earlier per-answer significance, including `p ≈ 1.9e-211`, is superseded and
requires incident-level reanalysis. The recorded values below are not edited or
silently reinterpreted.

Current status remains open pending regeneration, recollection, reanalysis, and
authenticated non-ACGS provenance. The owner-published artifacts use the earlier
schema and do not acquire C15 validity retroactively. C15 also leaves explicit
trust boundaries: authenticity of the out-of-band commitment channel, semantic
condition cues because value signatures differ by condition, reviewers sharing
packets across cohorts, coordinator disclosure of hidden material, authenticated
reviewer identity, and authenticated external execution.
The audit therefore records that no completed external replication bundle exists
that authenticates the claimed submitter, execution, or independence.

## Success Criteria Checklist

| Requirement | Current evidence | Status |
|---|---|---|
| Fixed forensic questionnaire: who acted, authority, rule, evidence, approval or denial, failure, defensibility | `FORENSIC_QUESTIONNAIRE` in `src/constitutional_swarm/forensic_benchmark.py`; validated by `tests/test_governance_receipts.py` | Satisfied locally |
| Matched artifact conditions: ungoverned logs, centralized structured logs, ACGS receipts and audit artifacts | `BASELINES` and generated artifact directories use one typed schema. C15 keeps integrity fields and strength fingerprints condition-neutral where feasible, while value signatures and legitimate evidence content can still differ by condition. Raw-log unknowns remain `unknown`/`unavailable`. | Defined locally; semantic-unblinding assessment remains empirical |
| Blind reviewers see artifacts but not hidden ground truth or true condition labels | Coordinator-only keys, nonce, coordinator reviewer manifest, and kit manifest remain outside reviewer packets. C15 uses per-reviewer packets, balanced one-condition-per-incident assignments, reviewer-specific condition HMAC pseudonyms, opaque packet ordering, and structural answer-copy diagnostics. The controls do not prove human blinding or prevent reviewers from sharing packets across cohorts. | Local isolation controls present; empirical and collusion limits remain open |
| Adversarial incident set includes collusion, memory poisoning, rule gaming, fragmented actions, and misleading traces | `ADVERSARIAL_TECHNIQUES` and deterministic `generate_incident_specs()` cover all five techniques across 50 to 200 incidents | Satisfied locally |
| Scored outputs include accuracy, time, confidence calibration, inter-reviewer agreement, and delta versus strongest baseline | C15 computes the p-value from the sealed matrix with an exact one-sided sign test over incident-stratified, between-reviewer contrasts. Reviewer/question cells do not inflate the binomial sample size. Callers cannot supply a p-value override. Existing published statistics require reanalysis. | Requires C15-format incident-level reanalysis |
| Result gate rejects substituted keys, changed artifacts, toy data, or statistically weak claims | The result gate regenerates and byte-compares the keys and manifested reviewer artifacts, requires a separately supplied precollection commitment, re-hashes referenced evidence, enforces reviewer assignment, and rejects unknown evidence logical names. Unblinded `artifacts/**` sources are excluded from result-evidence manifests; `--verify-replication-kit` and `--generate-reviewer-packet --coordinator-pack` regenerate and byte-compare the complete coordinator pack to protect them. Syntactically valid hashes, locally stored commitment records, metadata, attestor names, and self-reported commands do not prove independence. | Local integrity checks defined; external provenance remains open |
| Public benchmark with 50 to 200 adversarial incidents has collected blind-review responses | The public release exposes owner-published artifacts under the earlier schema. Generator v5 changes pseudonyms, manifest membership, packet bytes, and commitments, so the pack must be regenerated and answers recollected under the revised contract. | Historical evidence; not current success proof |
| ACGS artifacts beat the strongest baseline significantly on collected public-study data | Earlier per-answer significance is superseded. No C15-compliant incident-stratified reanalysis or authenticated non-ACGS public-study scorecard exists yet. | Open |
| Inter-reviewer agreement is reported from real blind reviewers | Synthetic test answers and the owner-published release evidence report agreement; no independent reviewer cohort has rerun the benchmark | Open |
| Non-ACGS group reruns the benchmark and reproduces the advantage | `ExternalReplicationRecord` can be checked for local shape and consistency, but the current format authenticates neither the submitter nor execution. `authenticated_provenance`, `external_success`, `independence_verified`, and `success_evidence` remain false. | Open; no authenticated provenance mechanism |

## Historical Verification Evidence

The following outputs are preserved from earlier work lanes. They predate the
C15 commitment, assignment, and provenance contract and cannot close the current
audit. Literal values such as `reviewer_count=2`, `valid=true`, and
`success_evidence=true` describe the historical validator only; the current
contract requires the fixed balanced six-reviewer cohort and cannot authenticate
external success.

The historical seal commands below are retained verbatim as historical evidence.
They are not current instructions. Generator v5 changes manifest membership, packet bytes, and
precollection commitments, so current seal and verify invocations must use a
newly generated pack and separately pass its coordinator-only `--protocol-json`,
`--answer-key-json`, and `--condition-key-json` inputs. The nonce remains inside
the coordinator-only condition key and must not be distributed to reviewers.

```bash
python -m pytest tests/test_governance_receipts.py tests/test_v0_1_scope_docs.py -q
# 98 passed

env RUFF_CACHE_DIR=.ruff_cache python -m ruff check \
  src/constitutional_swarm/forensic_benchmark.py \
  src/constitutional_swarm/governance_fixtures.py \
  scripts/run_governance_benchmark.py \
  tests/test_governance_receipts.py \
  tests/test_v0_1_scope_docs.py
# All checks passed

python scripts/run_governance_benchmark.py --completion-audit
# exit 1; complete=false, local_result_bundle_valid=false,
# blockers include scored_result_bundle, incident_count_50_to_200,
# acgs_significantly_beats_strongest_baseline,
# inter_reviewer_agreement_reported,
# public_blind_review_data_verified, and
# non_acgs_external_replication_verified

python scripts/run_governance_benchmark.py \
  --completion-audit-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# exit 1; complete=false, local_result_bundle_valid=true,
# all local score/checklist gates pass, public_blind_review_data_verified=true,
# and the only remaining blocker is non_acgs_external_replication_verified

Fresh smoke on 2026-05-16 from the current worktree:

```bash
python scripts/run_governance_benchmark.py --generate-incident-pack /tmp/acgs-bench-audit/incident
# files_written=309, incident_count=50

python scripts/run_governance_benchmark.py --generate-reviewer-packet /tmp/acgs-bench-audit/reviewer
# files_written=154, hidden_files_written=false

python scripts/run_governance_benchmark.py --write-replication-kit /tmp/acgs-bench-audit/kit
# coordinator_files_written=309, reviewer_files_written=154,
# reviewer_packet_audit_valid=true, completed_external_replication=false

python scripts/run_governance_benchmark.py \
  --write-external-replication-submission /tmp/acgs-bench-audit/submission \
  --submission-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json \
  --submission-result-bundle-url https://example.org/result-bundle.json \
  --submission-replication-metadata-url https://example.org/replication_metadata.json \
  --submission-commands-transcript-url https://example.org/commands-transcript.txt
# submission.json + submission.md rendered from the validated bundle; missing_fields=[]

python scripts/run_governance_benchmark.py \
  --validate-external-replication-submission /tmp/acgs-bench-audit/submission \
  --submission-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# package validates against the bundle and public request template

python scripts/run_governance_benchmark.py --verify-replication-kit /tmp/acgs-bench-audit/kit
# valid=true, checked_files=468, reviewer_packet_audit.valid=true,
# required_public_artifacts.valid=true

python scripts/run_governance_benchmark.py --study-readiness-report /tmp/acgs-bench-audit/kit
# ready_for_blind_review=true, open_requirements still include:
# collect blind-review answers from real reviewers,
# build and validate a result bundle from collected answers,
# show statistically significant ACGS advantage over strongest baseline,
# report inter-reviewer agreement from real reviewers,
# complete non-ACGS external replication metadata

That readiness snapshot is kept as historical local evidence. The earlier audit
said the "public-study tier is verified" because the GitHub release supplied
owner-published blind-review data and scorecard artifacts. C12 supersedes that
conclusion: those artifacts still require structural-blinding, referenced-file,
and incident-level statistical revalidation. The independent non-ACGS replication requirement
remains open as well.

python scripts/run_governance_benchmark.py --validate-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# valid=true, acgs_inter_reviewer_agreement=1.0, acgs_wins=true,
# external_replication_completed=true

python scripts/run_governance_benchmark.py --validate-scorecard /tmp/acgs-bench-audit/kit/scorecard.json --scorecard-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# valid_shape=true, success_evidence=true

python scripts/run_governance_benchmark.py --validate-reviewer-cohort-manifest /tmp/acgs-bench-audit/kit/reviewer_cohort_manifest_complete.json --cohort-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# valid_shape=true, success_evidence=true

python scripts/run_governance_benchmark.py --validate-replication-metadata /tmp/acgs-bench-audit/kit/replication_metadata_complete.json
# valid_shape=true, success_evidence=true

python scripts/run_governance_benchmark.py --validate-replication-attestation /tmp/acgs-bench-audit/kit/replication_attestation_complete.json --replication-metadata /tmp/acgs-bench-audit/kit/replication_metadata_complete.json --attested-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json --attested-reviewer-cohort-manifest /tmp/acgs-bench-audit/kit/reviewer_cohort_manifest_complete.json --attested-scorecard /tmp/acgs-bench-audit/kit/scorecard.json --attested-artifact-pack /tmp/acgs-bench-audit/kit/artifact-pack.tar.gz --attested-commands-transcript /tmp/acgs-bench-audit/kit/commands-transcript.txt
# valid_shape=true, success_evidence=true

python scripts/run_governance_benchmark.py --completion-audit-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json
# exit 1; complete=false, local_result_bundle_valid=true,
# blocker remains non_acgs_external_replication_verified
```

python scripts/run_governance_benchmark.py --generate-incident-pack /tmp/acgs-v01-pack-smoke
# 309 files, 50 incidents

python scripts/run_governance_benchmark.py --generate-reviewer-packet /tmp/acgs-v01-reviewer-packet-smoke
# 154 files, hidden_files_written=false

python scripts/run_governance_benchmark.py --verify-reviewer-manifest /tmp/acgs-v01-reviewer-packet-smoke
# valid, 153 checked files

python scripts/run_governance_benchmark.py --audit-reviewer-packet /tmp/acgs-v01-reviewer-packet-audit-smoke.BlQcww
# valid, manifest checked 153 files, privacy issues=[]

python scripts/run_governance_benchmark.py --audit-reviewer-packet /tmp/acgs-v01-full-pack-audit-smoke.G55LJk
# exit 1; manifest valid but privacy rejects coordinator-only files

python scripts/run_governance_benchmark.py --write-replication-kit /tmp/acgs-v01-replication-kit-smoke.uKYU7J
# coordinator_files_written=309, reviewer_files_written=154,
# reviewer_packet_audit_valid=true, completed_external_replication=false

python scripts/run_governance_benchmark.py --verify-replication-kit /tmp/acgs-v01-replication-kit-verify-smoke.EPYhge
# valid, checked_files=468, reviewer_packet_audit.valid=true, required_public_artifacts.valid=true

python scripts/run_governance_benchmark.py --study-readiness-report /tmp/acgs-v01-study-readiness-smoke.J6h1jR
# ready_for_blind_review=true, success_evidence=false,
# row_count=2100, filled_response_cells=0, open requirements remain

python scripts/run_governance_benchmark.py \
  --validate-collected-answers /tmp/acgs-v01-collected-answers-smoke.bwVQTb/answers.csv \
  --reviewer-packet /tmp/acgs-v01-collected-answers-smoke.bwVQTb/reviewer_packet
# valid=true, row_count=2100, reviewer_count=2, success_evidence=false

python scripts/run_governance_benchmark.py \
  --seal-collected-answers /tmp/acgs-v01-answer-seal-smoke.irZ3gf/collected-answers-seal.json \
  --answers-csv /tmp/acgs-v01-answer-seal-smoke.irZ3gf/answers.csv \
  --reviewer-packet /tmp/acgs-v01-answer-seal-smoke.irZ3gf/reviewer_packet
# valid=true, answers_sha256 recorded, reviewer_manifest_sha256 recorded,
# success_evidence=false

python scripts/run_governance_benchmark.py \
  --verify-collected-answers-seal /tmp/acgs-v01-answer-seal-verify-smoke.y1lsrK/collected-answers-seal.json \
  --answers-csv /tmp/acgs-v01-answer-seal-verify-smoke.y1lsrK/answers.csv \
  --reviewer-packet /tmp/acgs-v01-answer-seal-verify-smoke.y1lsrK/reviewer_packet
# valid=true, issues=[], validation.valid=true, success_evidence=false

python -m pytest tests/test_governance_receipts.py::test_governance_benchmark_runner_builds_result_bundle_from_files -q
# builds result-bundle.json from sealed answer files, validates the result bundle,
# computes result_bundle_sha256 from the exact output file, and validates
# replication_attestation.json with --replication-metadata plus
# --attested-result-bundle result-bundle.json plus
# --attested-reviewer-cohort-manifest reviewer_cohort_manifest.json plus
# --attested-scorecard scorecard.json plus --attested-artifact-pack
# artifact-pack.tar.gz plus --attested-commands-transcript commands-transcript.txt

python -m pytest tests/test_governance_receipts.py::test_governance_benchmark_completion_audit_remains_blocked_for_local_bundle -q
# exit path covered: completion audit returns complete=false with
# local_result_bundle_valid=true and blocker for non_acgs_external_replication_verified;
# required_public_artifacts lists the public answer matrix, answer seal, reviewer
# cohort manifest, scorecard, and external replication attestation still needed for
# completion, with the result bundle's claimed URI/hash fields and verifier commands
# beside the unverified status

python scripts/run_governance_benchmark.py \
  --validate-replication-metadata /tmp/acgs-v01-replication-kit-smoke.uKYU7J/replication_metadata.json
# exit 1; valid_shape=true, success_evidence=false,
# external_replication_incomplete + external_replication_placeholder
# + external_artifact_pack_not_immutable + external_reviewer_cohort_not_immutable
# + external_scorecard_not_immutable

python scripts/run_governance_benchmark.py \
  --validate-answer-matrix /tmp/acgs-v01-pack-smoke/reviewer_answer_template.csv \
  --protocol-json /tmp/acgs-v01-pack-smoke/protocol.json \
  --answer-key-json /tmp/acgs-v01-pack-smoke/answer_key.json \
  --condition-key-json /tmp/acgs-v01-pack-smoke/condition_key.json
# invalid_answer_csv until reviewers fill answers/confidence/elapsed_seconds

External web search on 2026-05-16 for the exact public artifacts
(`acgs-v0-1-answers.csv`, `acgs-v0-1-answer-seal.json`,
`acgs-v0-1-reviewer-cohort.json`, `acgs-v0-1-scorecard.json`, and
`acgs-v0-1-attestation.json`) initially did not turn up a published public
study bundle.

That changed later in the same session: the public GitHub repository
`dislovelhl/Acgs-Swarm` now has a release at
`https://github.com/dislovelhl/Acgs-Swarm/releases/tag/acgs-v0.1-benchmark-kit-2026-05-16`
with the benchmark kit assets attached under the exact public filenames.
The release assets now use GitHub-hosted immutable URLs instead of local or
placeholder references.
An external replication request is also public at
`https://github.com/dislovelhl/Acgs-Swarm/issues/48`.
The release also carries a machine-readable rerun request artifact:
`acgs-public-replication-request.json`.
The same request is mirrored in a public gist for easy sharing:
`https://gist.github.com/dislovelhl/cf9f2c1b5c95644d9603098d717fb663`.
There is also a public GitHub discussion thread for reruns:
`https://github.com/dislovelhl/Acgs-Swarm/discussions/49`.
The repo README now points readers to all of those public pointers and to the
new public guide at `docs/public-replication.md`, and that guide is mirrored in
the public discussion thread for easier external sharing.
The repository also mirrors the public request payload at
`docs/public-replication-request.json` so a non-ACGS group can inspect the
expected submission shape without fetching the release asset.
The repo now also includes a GitHub issue template for external replication
submissions so public rerun evidence can be filed in a structured way.
The public release notes now also point to that submission form alongside the
release assets, guide, issue, discussion, and gist.

Fresh public-surface check on 2026-05-16:

- `https://github.com/dislovelhl/Acgs-Swarm/releases` still says
  “There aren’t any releases here”.
- `https://github.com/dislovelhl/Acgs-Swarm/tags` still does not surface any
  published tag/release payload for this benchmark.
- `git ls-remote --heads --tags origin` against
  `https://github.com/dislovelhl/Acgs-Swarm.git` returns many branches but no
  `refs/tags/*` entries, so the upstream repository itself still has no tag
  anchor for a release artifact.
- `git rev-list --all | xargs git grep` for the exact artifact names and the
  broader benchmark vocabulary (`blind review`, `scorecard`, `attestation`,
  `reviewer packet`, `public study`, `replication`, `adversarial incidents`,
  `forensic reconstructability`) returned no hits anywhere in reachable repo
  history.
- After refreshing upstream refs with `git fetch origin --prune`, the same
  all-refs search still returned no hits, so the absence is not an artifact of
  a stale local ref set.
- `git log --all --grep='acgs-v0-1|reviewer cohort|scorecard|attestation|blind review|public study|external replication'`
  also returned no commit-message hits, so there is no hidden release or study
  breadcrumb in history metadata either.
- Exact-name web search for `acgs-v0-1-answers.csv`,
  `acgs-v0-1-answer-seal.json`, `acgs-v0-1-reviewer-cohort.json`,
  `acgs-v0-1-scorecard.json`, and `acgs-v0-1-attestation.json` found no
  published public study bundle on GitHub, Zenodo, `acgs.dev`, or `acgs.ai`.
- Exact-name host-filtered search returned no results for those artifact names
  on `github.com`, `zenodo.org`, `acgs.dev`, or `acgs.ai`.
- Public site checks on `https://acgs.ai/` and the wiki explorer at
  `https://www.acgs.dev/` still show no surfaced `benchmark`, `evaluation`,
  `blind review`, `scorecard`, `attestation`, `public study`, or
  `reviewer cohort` terms.

The parent ACGS repo does contain benchmark-facing documentation
(`docs/benchmarks/COMPETITIVE-BENCHMARKS.md` and `autoresearch/program.md`),
but those files describe internal methodology, fixed harnesses, and local
measured/estimated numbers. They do not expose the missing public study bundle
or the required external blind-review/replication artifacts.

A content search over the parent ACGS repo found no exact `reviewer_cohort`,
`public_scorecard`, `answer_seal`, `answer_matrix`, or `external_replication`
artifact names anywhere in the repo.

The public ACGS wiki explorer (`https://www.acgs.dev/`) indexes an internal
benchmark note (`ACGS Competitive Benchmarks`) and the local benchmark harness
note, but a live search on the page text found no surfaced `scorecard`,
`attestation`, `reviewer`, `public study`, or `releases` terms.

Fresh public-surface checks from this turn now show a published release:

- `https://github.com/dislovelhl/Acgs-Swarm/releases/tag/acgs-v0.1-benchmark-kit-2026-05-16`
  exposes the exact benchmark kit assets:
  - `acgs-v0-1-answers.csv`
  - `acgs-v0-1-answer-seal.json`
  - `acgs-v0-1-reviewer-cohort.json`
  - `acgs-v0-1-scorecard.json`
  - `acgs-v0-1-attestation.json`
  - `result-bundle.json`
  - `replication_metadata.json`
  - `acgs-v0-1-pack.tar.gz`
  - `commands-transcript.txt`
  - `required_public_artifacts.json`
- The released inventory validates locally:
- `python scripts/run_governance_benchmark.py --validate-required-public-artifacts /tmp/acgs-v0-1-public-release.d7jso9/required_public_artifacts.json`
  - `valid=true`, `artifact_count=5`
- The released result bundle validates locally against the GitHub-hosted URLs:
  - `python scripts/run_governance_benchmark.py --validate-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json`
  - `valid=true`, `acgs_wins=true`, `acgs_inter_reviewer_agreement=1.0`,
    `external_replication_completed=true`
- The public replication request is now tracked as GitHub issue `#48`, the
  release notes include a step-by-step rerun checklist, and the release also
  carries `acgs-public-replication-request.json` and a public gist mirror;
  there is also a public discussion thread `#49`; however, these public
  instructions do not by themselves satisfy the non-ACGS independent rerun
  requirement.
- As of the 2026-05-16 public audit snapshot, GitHub issue `#48` only showed
  owner-authored comments; the repo metadata still reports `forks_count=0` and
  `network_count=0`, so there is still no external replication surface in the
  public trail.
- As of the 2026-05-16 public audit snapshot, GitHub discussion `#49` only
  showed owner-authored comments; the discussion thread mirrors the release
  assets and request template but still shows no independent rerun evidence
  from a non-ACGS group.
- A fresh web search this turn for the exact release tag and the exact
  benchmark artifact filenames returned no external independent rerun bundle.
- Fresh GitHub search sweeps for the exact release tag and artifact filenames
  only return the repository's own replication-request issue `#48`; no external
  fork, issue, repo, or code hit surfaced an independent rerun bundle.
- A fresh web search on this turn for the exact release tag and artifact names
  again returned no independent rerun bundle outside the owner-published
  release surface.
- The current public search surface remains empty for the exact benchmark kit
  filenames, so the open blocker is still the missing non-ACGS rerun bundle.

Fresh scored-audit evidence from this turn:

- `python scripts/run_governance_benchmark.py --completion-audit-result-bundle /tmp/acgs-bench-audit/kit/result-bundle.json`
  shows the local result bundle as valid, with:
  - `incident_count=50`
  - `reviewer_count=2`
  - `acgs_wins=true`
  - `acgs_inter_reviewer_agreement=1.0`
  - `p_value_vs_strongest_baseline=0.01`
  - `performance_delta_vs_strongest_baseline=0.048820033955857434`
  - `external_replication_completed=true`
- The only remaining blocker in that scored audit is the external-replication
  requirement:
  - `non_acgs_external_replication_verified`

That was the old gate's result. The displayed `p_value_vs_strongest_baseline`
is historical and must not be used as a success claim until the sealed answer
matrix is reanalyzed with the incident as the unit of independence and every
referenced file is re-hashed successfully.

The current blocker payload from `--completion-audit-result-bundle` remains:

- `non_acgs_external_replication_verified`

rg -n \
  "answer_key|ground_truth|correct_answer|artifact_condition|ungoverned_raw_logs|centralized_structured_logs|acgs_receipts_and_audit_artifacts" \
  /tmp/acgs-v01-reviewer-packet-smoke
# no matches
```

## Completion Decision

Do not mark the active goal complete from local evidence alone. The
owner-published public-study artifacts exist, but their scientific claims are
not currently verified under the C15 contract. Completion requires regenerated
reviewer artifacts, new answers collected under the isolated assignment,
incident-stratified between-reviewer reanalysis from the commitment-bound sealed
matrix, successful canonical byte regeneration and referenced-file re-hashing,
and authenticated non-ACGS replication provenance. The current format provides
no provenance mechanism capable of setting external-success or independence
true. Therefore no success claim is verified by this audit.
