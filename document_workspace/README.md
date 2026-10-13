# Local procedure comparison prototype

This implements the bounded roadmap T0–T4 journey with the clearly labeled
`synthetic-line-diff-v1` adapter. It makes no model calls. It adds application
storage and commands beside Acgs-Swarm; it does not import or replace authority
components.

## Start locally

From the repository root, install the bounded product dependencies and build
the UI. The generated UI and dependency directories are intentionally ignored
by Git:

```sh
python3 -m pip install -r document_workspace/requirements.txt
npm --prefix document_workspace/ui install
npm --prefix document_workspace/ui run build
```

Then run these from the repository root in two terminals:

```sh
python3 -m document_workspace.server --db document_workspace/data/workspace.db --port 8765
```

```sh
python3 -m document_workspace.worker --db document_workspace/data/workspace.db
```

Open http://127.0.0.1:8765 and paste the ephemeral token printed by the server.
It is never saved as a credential. Server restart needs a fresh login and
preserves the run URL and database. Stop either process with Ctrl-C.

Runtime databases and saved examples are excluded from Git. Create fresh local
data through the UI; reopen a known run with `?run=<id>` after restarting.

## Data and recovery contract

- One ephemeral local session maps to workspace `local`, reviewer `local-reviewer`.
  Loopback host/origin, session and CSRF checks enforce all HTTP commands.
- Exactly two nonempty UTF-8 .txt/.md source versions; 50,000 bytes each.
  Submitted bytes are immutable, with full SHA-256, source IDs and byte spans.
  File import preserves UTF-8 BOM and line endings.
- Admission atomically saves task, run, sources and queued event. A scoped
  request key retries the same body; a changed body conflicts. An unresolved
  key survives tab remount; an acknowledged key is cleared. After a lost
  acknowledgement, an authenticated workspace/reviewer-scoped lookup resolves
  the key to the original admitted run. Exact sources are read from server
  persistence. No document content is put in browser storage, and recovery
  does not dispatch execution. An unresolved lookup blocks new admission
  while reconnecting; a confirmed missing admission requires restoring the
  original input before retrying that key.
- A separate worker uses renewable leases and generation/token fencing.
  Its persistent fixture checkpoint survives process death. This is not a
  LangGraph checkpointer integration. A model could execute more than once
  before checkpoint save; only one accepted result transition is promised.
- Saved UTF-8 draft bytes precede the manifest/state/event transaction.
  Read, download and review verify blob, manifest, checkpoint and source
  agreement. Orphans are retained and counted. Corruption blocks consumption
  and review instead of silently regenerating a result.
- Review binds run, artifact ID, full file hash, reviewer, immutable request
  version, review version and 24-hour expiry. Feedback is durable; request
  changes does not generate a replacement. A new comparison is explicit.
- Event cursors and IDs are durable. Gaps remain incomplete in the UI and
  block server review. A full, verified, non-regressing server snapshot may
  reconcile a restored history; event deltas alone cannot clear a gap.
  Browser cleanup owns subscriptions only.
- Cancellation requested, acknowledged and rejected are separate facts.
  A saved result that wins the race remains saved.

The brief has Changes, Operational implications and Open questions, and is
limited to 1,200 words. Claims quote bounded excerpts and link to both source
versions with hashes and exact UTF-8 spans. Empty comparison anchors prove
where text is absent relative to the whole hashed source.

Small inputs use granular line comparison. Above one million possible line
pairs, a cancellable linear prefix/suffix scan compares the entire changed
region. That region may include unchanged inner text. More than twelve
granular changes fails the bounded brief quality check. This adapter checks
lexical comparison support, not completeness of operational interpretation,
contradictions in the procedure, or real-world implications. Human assessment
is required.

Policy, peers, authority and delivery are separate, unevaluated facts. File
SHA-256 is not an ACGS envelope content hash or authority output digest; the
latter two are null in this prototype. The pinned research revision is absent
from both local checkouts, so its GCB/stream contracts have not been integrated
or requalified here. Existing tracked authority code is unchanged.

## Verification

From the isolated repository:

```sh
python3 -m pip install -r offline_foundations/requirements-test.txt
python3 -m offline_foundations.verify --output /tmp/acgs-product-verification
python3 -m ruff check document_workspace
python3 -m ruff format --check document_workspace
cd document_workspace/ui
npm run lint
npm run typecheck
npm test
npm run build
node browser-recovery.mjs
node browser-lost-ack.mjs
```

The browser recovery script owns a temporary database and loopback server on
port 8766. Lost-ack and restored-hole testing owns port 8767. The focused Python
suite covers simultaneous conflicting reviews. The browser recovery journey
also covers exact saved-review identity
across API/worker restart and keyboard-only entry, admission, source-span
inspection, feedback and approval. `browser.mjs` tests a separately running server on port 8765 using
`ACGS_TEST_TOKEN` passed only in the process environment. Browser testing uses
already-installed Chromium. Neither script downloads browsers.

Package manifests record the directly tested dependency versions. The source
checkout requires its own dependency installation and UI build; local dependency
symlinks, generated assets and databases are excluded. No dependencies were
installed during qualification. The system FastAPI TestClient and Node test
runner had sandbox-specific thread/reporting limitations; the final guarded
API and replay checks used supported local approval.

Qualification reports and database/log archives are retained separately in
Library. Historical broad-suite observations lack a separate clean-control
reproduction. No production-readiness claim,
retention policy, multi-user IAM, signing, APCC commitment, delivery or model
quality qualification is made.
