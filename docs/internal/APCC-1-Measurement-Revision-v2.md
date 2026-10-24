# APCC-1 measurement revision v2

## Decision and scope

On 2026-10-16 the owner chose to retain at least 10,000 completed operations
and extend low-rate runs. `apcc-1.matrix.v2` implements that decision as an
additive measurement contract. The original `matrix.v1.json`,
`raw-result.schema.json`, experiment plan, and qualification-live v1/v2
protocols and evidence remain unchanged. No historical row is reclassified.

For every duration-based ordinary or ablation performance run, the scheduled
duration in seconds is:

```text
max(30, ceil(10000 / target_rate_per_second))
```

| Target proposals/second | Scheduled seconds | Scheduled proposals at target rate |
| --- | --- | --- |
| 10 | 1,000 | 10,000 |
| 100 | 100 | 10,000 |
| 500 | 30 | 15,000 |

The repetition field `run_duration_seconds: 30` is the base duration in v2.
The new, exact `performance_duration_policy` selects the formula. In v1 the
same repetition field retains its original fixed-duration meaning.
W6 still requires exactly 10,000 operations with no duration limit. Cell
membership, rates, seeds, warmup and measured repetitions, payloads, all
nonperformance dimensions, and thresholds are unchanged. Ablation performance
cells at 100/s use 100 seconds.

Scheduled duration alone does not establish completion. Runs with fewer than
10,000 completed operations remain retained with `incomplete_run: true`;
claiming a complete run with fewer operations is rejected by both the Python
contract and JSON Schema. An unsustainable rate remains an incomplete result.
This revision does not extend an individual run until it succeeds or silently
lower the operation threshold. Actual wall time and operation outcomes still
need measurement by the eventual runner.

## Reproducible artifacts

The generator is `scripts/generate_apcc_matrix_v2.py`. It verifies both frozen
v1 input hashes, derives new outputs, and refuses to replace differing outputs
unless explicitly invoked with `--replace`. Use the read-only check in reviews:

```bash
python scripts/generate_apcc_matrix_v2.py --check
```

| Artifact | SHA-256 |
| --- | --- |
| `experiments/apcc-1/matrix.v2.json` | `7bdd13fc902e654b344d2e63f79c2a0362964589f76e648fa72666c940eabda1` |
| `experiments/apcc-1/raw-result.v2.schema.json` | `36bd5035d31085462aa54921c71a231135017438b00bb7fd635f7b02e9989989` |

`src/constitutional_swarm/apcc_empirical/contract.py` applies version-qualified
planning and raw-record validation. `artifacts.py` pins each reviewed
matrix/schema pair and rejects cross-version combinations. A v2 artifact run
embeds `matrix.v2.json`; its schema is embedded under the existing
`raw-result.schema.json` filename and identified by its v2 version and hash.
Legacy artifact layout and v1 behavior are preserved.

Trial IDs and deterministic stimuli remain matched across revisions for
comparison. Identity across campaigns is the matrix hash plus trial ID; rows
from different matrix hashes must never be pooled or relabelled. Artifact
writer and reader checks enforce one matrix/schema pair per run.

## Runtime implications and unclosed work

The unchanged plan has 30,360 duration-based ordinary performance runs,
780 ablation performance runs, and 2,760 fixed-operation W6 runs.
The first two categories schedule 11,513,600 seconds, or approximately
133.259 sequential days, including warmups. This excludes W6, setup, storage,
security, parser, and formal tests. Under the target rates W6 adds an ideal
1,030,400 seconds (11.926 days); actual elapsed time can be longer.
Parallel execution would require isolated resources and a separately recorded
allocation so it does not contaminate the matched performance cells.

This change provides a plan, schema, planner, and artifact validation. It does
not execute or close the full campaign or any B6 qualification requirement.
The old qualification-live v2 runner remains frozen at 30 seconds and cannot
be used to claim v2-matrix completion. A future qualification-live v3 must be
precommitted separately, wire the supervised B6 path, record authoritative
outcomes, and supply enough distinct operations. The old B6 qualification
workload provisions only 400 nodes; increasing duration alone would exhaust
that node space. Existing qualification v2 results remain incomplete.
