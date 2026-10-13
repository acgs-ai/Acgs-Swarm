# Offline roadmap foundations

The bounded document workspace preserves its accepted implementation.
These separate Python modules implement T5 Stage A, deterministic SQLite T6,
and T7's offline record/accounting contracts. Every model vector, expectation,
score and proposal is synthetic or recorded. No model backend or optimizer executes.

From this isolated repository:

```sh
python3 -m pip install -r offline_foundations/requirements-test.txt -r document_workspace/requirements.txt
python3 -m offline_foundations.demo --output /tmp/acgs-fresh-fixture
python3 -m offline_foundations.verify --output /tmp/acgs-fresh-verification
python3 -m ruff check document_workspace offline_foundations
python3 -m ruff format --check document_workspace offline_foundations
```

The demo requires a fresh destination and writes three SQLite databases and a
JSON snapshot. Its 220 recorded outcomes comprise 40 selection and 180 final
fixture records. Their scores are authored; they measure no model quality.
The verifier explicitly selects only the foundations and product tests,
disables plugin autoload, inventories imports and refuses authority/model
imports. It never discovers the repository's broad suite. `--foundations-only`
uses only the new contracts. Python 3.14, pytest 9.0.3 and Ruff 0.15.7 were used.
SQLite foundations otherwise require only the standard library. The copied product
needs its already-installed FastAPI/Pydantic dependencies.

Pinned source parity tests use `tests/fixtures/pinned_sources` inside this package.
The six source-text inputs retain their qualified bytes and complete hashes,
with provenance and upstream licenses. They verify file hashes
before executing pure confidence functions or extracting explicitly named pure
ASTs. No Laya, SGLang, Torch, Transformers or constitutional package is imported.

## Contracts

`decisions.py` retains declared proposals, exposed and normalized vectors,
named reported/derived metrics, ties, gate state, coverage, identities and raw
diagnostics. The consumer uses its explicitly configured metric and rejects
uncovered buckets, malformed vectors, lost coverage and unavailable answers.
Only a fully recomputed UTF-8 serializer reference is consumable in this phase.
Its completeness is not tokenizer parity. Calibration identity checks do not
fit temperatures or certify reliability. The authority oracle is a pure pinned
reference, with no dispatch, signing, settlement or authority client.

`evidence.py` stores immutable source bytes, revisions and events transactionally
in SQLite. A caller supplies a trusted offline `Access` context, scoped by tenant,
project and explicit task/run or project class. This is fixture permission input,
not real IAM. Knowledge cutoff and valid time are separate. Source revision order
outranks arrival; effective expired, revoked or inaccessible successors prevent
fallback to older assertions. Equal-version forks remain conflicts even if a
current hash admits only one branch. Dependencies require current valid,
unambiguous parents. Consumption repeats eligibility, source hash and precedence
checks. Historical queries still obey current access and revocation. Source
eligibility and gold fixture claims establish no semantic truth.

`prompt_ledger.py` records 60 authored families with two paraphrases each,
split 20 training / 10 selection / 30 final. Source and template descendants stay
within a split. Only `task_instruction` changes. Model, decoding, data, source,
memory, evaluator, tools and policy identities are frozen. Reservations count
before outcomes; failures, unfinished work, retries and reflections consume the
same limits: 240 per search arm/seed, 1,440 search total, 180 final and 1,620 overall.
Four candidate slots include the seed. Recorded proposal tokens are separately
capped and distinct from actual model use, which is zero.

Complete common selection suites, original outcomes and no pending reservations
are required before deterministic selection. Severe violations exclude candidates.
One artifact and seed per arm, including its full manifest, freeze before holdout.
Final feedback cannot flow back to proposals. Cache keys cover the full manifest,
split and task. Proposer feedback is arm/seed scoped: P1 scalar fields, P2 typed
failure/evidence records. These are logical API boundaries; a local database/file
owner can inspect the whole synthetic dataset. Promotion is always unevaluated.

## Limits and integration

The separately retained Library evidence describes integration limits. No persistent LangGraph adapter,
GCB migration, Graphiti comparison, GEPA proposals, model
serving, inference, calibration, spend or GPU experiment ran. Existing authority
files are untouched. A source link or hash match does not prove a claim's meaning.
The fixture dataset is authored and not an independently sampled evaluation.
The UI is unchanged; prior browser journey evidence is historical, not rerun here.

## Optional PostgreSQL T6 storage

`postgres_evidence.PostgresEvidenceStore(dsn, schema="t6_evidence")` reuses the
SQLite observable evidence rules with PostgreSQL storage, through the optional
already-installed `psycopg2` driver. Import it explicitly; ordinary SQLite use
does not import this driver. Its explicit `t6_` schema is separate from APCC
authority storage. It creates its own tables and append-only mutation triggers;
it implements no authority migration or authentication service.

For a fresh environment, install the optional tested PostgreSQL driver with
`python3 -m pip install -r offline_foundations/requirements-postgres.txt`.
Installing it does not provision a database.

Writers serialize within a schema using a transaction-scoped advisory lock.
Readers use repeatable-read snapshots. BYTEA is returned as Python bytes; bounded
text identities containing NUL use reversible encoding for SQLite parity.
Bounded SHA-256 identity indexes admit maximum-length Unicode scopes and IDs;
full text predicates and persisted scope/body checks still enforce exact scope.
The internal connection bridge supports the fixed statements in `evidence.py`,
not arbitrary SQLite SQL. A database administrator can still change DDL; this
is not protection against a privileged storage owner.

For an explicitly provisioned disposable PostgreSQL database, set
`ACGS_T6_TEST_DSN` in the test process environment and run:

```sh
python3 -m offline_foundations.verify --postgresql-parity --output /tmp/acgs-pg-verification
```

The parity flag requires a real DSN and installed driver; unavailable PostgreSQL
is a failure, not a skipped or mocked qualification. Tests select only the shared
36-family synthetic evidence corpus, its edge cases and real storage/transaction
checks, plus the bounded existing regressions. They create isolated `t6_` schemas
inside the caller's disposable database. They do not provision, discover or
clean containers themselves. The task evidence records official image identity,
server/driver versions, container restart and ownership-checked teardown.
Fixtures establish scoped storage behavior, not semantic truth, extraction
quality, production IAM, performance or Graphiti parity.
