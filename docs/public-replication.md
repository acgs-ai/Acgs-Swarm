# Public benchmark replication guide

This guide is the public entrypoint for rerunning the ACGS-Swarm v0.1 benchmark
kit and verifying the release artifacts.

## Public assets

- Release: <https://github.com/dislovelhl/Acgs-Swarm/releases/tag/acgs-v0.1-benchmark-kit-2026-05-16>
- Request asset: <https://github.com/dislovelhl/Acgs-Swarm/releases/download/acgs-v0.1-benchmark-kit-2026-05-16/acgs-public-replication-request.json>
- Repo-mirrored request template: [docs/public-replication-request.json](public-replication-request.json)
- Replication issue: <https://github.com/dislovelhl/Acgs-Swarm/issues/48>
- Replication discussion: <https://github.com/dislovelhl/Acgs-Swarm/discussions/49>
- Rerun checklist gist: <https://gist.github.com/dislovelhl/cf9f2c1b5c95644d9603098d717fb663>

## What the benchmark asks reviewers to reconstruct

The fixed questionnaire covers:

- who acted
- what authority existed
- what rule applied
- what evidence was used
- who approved or denied
- what failed
- whether the outcome was defensible

The public study compares three conditions:

1. ungoverned raw logs
2. centralized structured logs
3. ACGS receipts and audit artifacts

## External rerun checklist

1. Download the public release assets from the release page.
2. Verify the artifact inventory against `required_public_artifacts.json`.
3. Run the study-readiness report on the replication kit:

   ```bash
   python scripts/run_governance_benchmark.py --study-readiness-report artifacts/v0_1_replication_kit
   ```

4. Validate the blind reviewer packet before collection:

   ```bash
   python scripts/run_governance_benchmark.py --audit-reviewer-packet artifacts/v0_1_reviewer_packet
   ```

5. Collect blind-review answers using only reviewer-visible artifacts.
6. Validate the collected answers before unblinding:

   ```bash
   python scripts/run_governance_benchmark.py \
     --validate-collected-answers answers.csv \
     --reviewer-packet artifacts/v0_1_replication_kit/reviewer_packet
   ```

7. Seal the collected answers before scoring:

   ```bash
   python scripts/run_governance_benchmark.py \
     --seal-collected-answers collected-answers-seal.json \
     --answers-csv answers.csv \
     --reviewer-packet artifacts/v0_1_replication_kit/reviewer_packet
   ```

8. Verify the seal, build the result bundle, and validate the scorecard.
9. Fill `replication_metadata.json` with your rerun evidence.
10. Validate the replication attestation and the final result bundle.

If you want a copy-paste submission draft for the rerun, render it from the
completed bundle:

```bash
python scripts/run_governance_benchmark.py \
  --write-external-replication-submission submission-package \
  --submission-result-bundle result-bundle.json \
  --submission-result-bundle-url https://example.org/result-bundle.json \
  --submission-replication-metadata-url https://example.org/replication_metadata.json \
  --submission-commands-transcript-url https://example.org/commands-transcript.txt
```

Validate the rendered package before publishing it:

```bash
python scripts/run_governance_benchmark.py \
  --validate-external-replication-submission submission-package \
  --submission-result-bundle result-bundle.json
```

If you are submitting the rerun back to this repository, use the GitHub
`External replication submission` issue template so your evidence lines up with
the required URLs and hashes.

## Success standard

v0.1 is successful only if a non-ACGS group can rerun the protocol on 50 to 200
adversarial incidents, reproduce the advantage over the strongest baseline,
report inter-reviewer agreement, and supply external replication evidence.

## Notes

- The release assets are owner-published public-study evidence. They support
  reruns, but they do not satisfy the external replication requirement by
  themselves.
- The public release assets are immutable references for the public study.
- The external replication requirement is not satisfied by this repository
  alone; it requires an independent rerun outside this checkout.
