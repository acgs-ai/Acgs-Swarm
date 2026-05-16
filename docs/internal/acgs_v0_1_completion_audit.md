# ACGS-Swarm v0.1 Completion Audit

This audit maps the active v0.1 forensic reconstructability goal to concrete
repo evidence. It is intentionally conservative: local scaffolding can support a
public study, but it is not a substitute for collected blind-review results or
external replication.

## Success Criteria Checklist

| Requirement | Current evidence | Status |
|---|---|---|
| Fixed forensic questionnaire: who acted, authority, rule, evidence, approval or denial, failure, defensibility | `FORENSIC_QUESTIONNAIRE` in `src/constitutional_swarm/forensic_benchmark.py`; validated by `tests/test_governance_receipts.py` | Satisfied locally |
| Matched artifact conditions: ungoverned logs, centralized structured logs, ACGS receipts and audit artifacts | `BASELINES` and generated artifact directories in `artifact_pack_to_files()` | Satisfied locally |
| Blind reviewers see artifacts but not hidden ground truth or true condition labels | `artifact_pack_to_files()` writes coordinator-only `protocol.json`, `answer_key.json`, and `condition_key.json` separately; `--generate-reviewer-packet` writes only reviewer-safe files; reviewer-facing `reviewer_protocol.json`, `reviewer_instructions.md`, `reviewer_artifacts/<condition_label>/`, and `reviewer_answer_template.csv` use blinded labels and omit `ground_truth`, `answer_key`, `correct_answer`, `artifact_condition`, and true baseline names; `reviewer_manifest.json` hashes only reviewer-safe files; `--audit-reviewer-packet` verifies checksums and rejects coordinator-only files or true condition-name leaks | Satisfied locally |
| Adversarial incident set includes collusion, memory poisoning, rule gaming, fragmented actions, and misleading traces | `ADVERSARIAL_TECHNIQUES` and deterministic `generate_incident_specs()` cover all five techniques across 50 to 200 incidents | Satisfied locally |
| Scored outputs include accuracy, time, confidence calibration, inter-reviewer agreement, and delta versus strongest baseline | `score_reviewer_answers()`, `paired_sign_test_p_value()`, `build_result_bundle()`, and `validate_result_bundle()` compute and gate the required fields; `--validate-collected-answers` checks returned reviewer CSVs before unblinding; `--seal-collected-answers` hashes the collected blind CSV and reviewer manifest after validation; `--verify-collected-answers-seal` proves the scored CSV still matches the pre-unblinding seal; `--build-result-bundle` now requires the verified seal, reviewer packet, and public answer-matrix/seal references before loading hidden keys; `--validate-result-bundle` emits a compact summary of incidents, reviewers, questions, conditions, strongest baseline, delta, p-value, answer evidence, and external replication references; `--completion-audit-result-bundle` emits a conservative prompt-to-artifact checklist plus `required_public_artifacts` mapping with bundle references, known hashes, and verifier commands; `--validate-required-public-artifacts` validates the standalone public-evidence inventory, including required proof claims, duplicate/unknown artifact rejection, and artifact-specific verifier-command coverage, and exact required-reference mapping, immutable/non-placeholder bundle references, sha256 shape checks, and reference-field mapping, and canonical verifier-command equality, and completion remains blocked until live public-study and external-replication evidence is independently verified; `validate_answer_matrix()` and `--validate-answer-matrix` reject incomplete incident/condition/reviewer/question answer matrices before scoring | Satisfied locally |
| Result gate rejects toy, internal-only, or statistically weak success claims | `ExternalReplicationRecord` requires immutable/public reviewer-cohort and independent-attestation URIs; `ConditionScore` bounds reject impossible metric values; `validate_result_bundle()` recomputes strongest baseline, performance delta, and `acgs_wins` from condition scores, and rejects insufficient incidents, reviewers, questions, conditions, scorecard answer-count mismatches, non-significant p-values, incomplete replication, ACGS-internal replicators, TODO placeholders, weak artifact/reviewer-cohort/scorecard/attestation references that are not `https://`, `ipfs://`, `ar://`, or `sha256:`, plus reserved example/local placeholder hosts, and replication commands that skip reviewer-packet audit, replication-kit manifest verification, reviewer-cohort manifest validation, reviewer-cohort/result-bundle count binding, public-scorecard/result-bundle binding, answer-matrix/result-bundle hash and count binding, collected-answer seal/result-bundle hash and count binding, collected-answer seal verification, answer-matrix validation, result-bundle construction, independent attestation validation cross-checked against replication metadata, the attested result bundle, the attested reviewer cohort manifest, the attested scorecard, the attested artifact pack, the attested commands transcript, commands-transcript command-line binding, final result-bundle validation, or the v0.1 completion-audit result-bundle gate; `--validate-replication-metadata` applies the external replication metadata subset of the same gate; `--verify-replication-kit` proves copied kits still match `kit_manifest.json` and reruns the blind reviewer-packet audit; `--study-readiness-report` can declare the kit ready for reviewer launch while still reporting `success_evidence: false`; replication metadata templates are generated with `completed: false` and tested as non-success evidence | Satisfied locally |
| Public benchmark with 50 to 200 adversarial incidents has collected blind-review responses | No reviewer cohort data is present in the repo | Open |
| ACGS artifacts beat the strongest baseline significantly on collected public-study data | Only deterministic test fixtures demonstrate the scoring path; no public-study scorecard exists | Open |
| Inter-reviewer agreement is reported from real blind reviewers | Only synthetic test answers report agreement | Open |
| Non-ACGS group reruns the benchmark and reproduces the advantage | `ExternalReplicationRecord` schema and validation exist, but no completed external replication bundle exists | Open |

## Current Verification Evidence

Fresh local checks from this work lane:

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

Fresh smoke on 2026-05-16 from the current worktree:

```bash
python scripts/run_governance_benchmark.py --generate-incident-pack /tmp/acgs-bench-audit/incident
# files_written=309, incident_count=50

python scripts/run_governance_benchmark.py --generate-reviewer-packet /tmp/acgs-bench-audit/reviewer
# files_written=154, hidden_files_written=false

python scripts/run_governance_benchmark.py --write-replication-kit /tmp/acgs-bench-audit/kit
# coordinator_files_written=309, reviewer_files_written=154,
# reviewer_packet_audit_valid=true, completed_external_replication=false

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
# blockers remain public_blind_review_data_verified and
# non_acgs_external_replication_verified
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
# local_result_bundle_valid=true and blockers for public_blind_review_data_verified
# plus non_acgs_external_replication_verified; required_public_artifacts lists
# the public answer matrix, answer seal, reviewer cohort manifest, scorecard,
# and external replication attestation still needed for completion, with the
# result bundle's claimed URI/hash fields and verifier commands beside the
# unverified status

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
`acgs-v0-1-attestation.json`) and the benchmark names themselves did not turn
up a published public study bundle.

The public GitHub repository `dislovelhl/Acgs-Swarm` is visible, but it
currently reports **no releases published** and the repository page does not
surface the benchmark artifact names (`scorecard`, `attestation`, or
`reviewer`).

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

The current blocker payload from `--completion-audit-result-bundle` remains:

- `public_blind_review_data_verified`
- `non_acgs_external_replication_verified`

rg -n \
  "answer_key|ground_truth|correct_answer|artifact_condition|ungoverned_raw_logs|centralized_structured_logs|acgs_receipts_and_audit_artifacts" \
  /tmp/acgs-v01-reviewer-packet-smoke
# no matches
```

## Completion Decision

Do not mark the active goal complete from local evidence alone. The remaining
completion blockers are external to this repo state: real blind-review answer
collection, significant public-study scorecard results, reported agreement, and
completed non-ACGS replication.
