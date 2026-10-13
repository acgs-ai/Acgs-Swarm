"""Application persistence only. This database contains no governance authority."""

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .model import canonical, digest, validate


class Conflict(Exception):
    pass


def uid():
    return str(uuid.uuid4())


SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
 id TEXT PRIMARY KEY, workspace TEXT NOT NULL, actor TEXT NOT NULL,
 request_json TEXT NOT NULL, request_digest TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, role TEXT NOT NULL,
 name TEXT NOT NULL, bytes BLOB NOT NULL, file_sha256 TEXT NOT NULL,
 UNIQUE(task_id,role));
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, workspace TEXT NOT NULL,
 actor TEXT NOT NULL, launch_key TEXT NOT NULL, request_digest TEXT NOT NULL,
 request_version INTEGER NOT NULL DEFAULT 0,
 execution TEXT NOT NULL DEFAULT 'queued', quality TEXT NOT NULL DEFAULT 'not_evaluated',
 review TEXT NOT NULL DEFAULT 'unavailable', review_version INTEGER NOT NULL DEFAULT 0,
 review_expires REAL, cancellation TEXT NOT NULL DEFAULT 'none',
 generation INTEGER NOT NULL DEFAULT 0, lease_token TEXT, lease_until REAL,
 attempt_id TEXT, graph_thread_id TEXT NOT NULL, checkpoint_id TEXT NOT NULL,
 artifact_id TEXT, seq INTEGER NOT NULL DEFAULT 0,
 UNIQUE(workspace,actor,launch_key));
CREATE TABLE IF NOT EXISTS attempts (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL, worker TEXT NOT NULL,
 generation INTEGER NOT NULL, started REAL NOT NULL, ended REAL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS blobs (
 digest TEXT PRIMARY KEY, bytes BLOB NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS manifests (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, file_sha256 TEXT NOT NULL,
 acgs_envelope_content_hash TEXT, authority_output_digest TEXT,
 payload TEXT NOT NULL, quality_errors TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
 run_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL,
 payload TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(run_id,seq));
CREATE TABLE IF NOT EXISTS commands (
 workspace TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL,
 key TEXT NOT NULL, request_digest TEXT NOT NULL, result TEXT NOT NULL,
 PRIMARY KEY(workspace,actor,kind,key));
CREATE TABLE IF NOT EXISTS reviews (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, artifact_id TEXT NOT NULL,
 file_sha256 TEXT NOT NULL, reviewer TEXT NOT NULL, decision TEXT NOT NULL,
 request_version INTEGER NOT NULL, review_version INTEGER NOT NULL,
 expires REAL NOT NULL, feedback TEXT NOT NULL, created REAL NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.path = Path(path).absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def db(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def event(db, run_id, kind, payload=None):
        db.execute("UPDATE runs SET seq=seq+1 WHERE id=?", (run_id,))
        seq = db.execute("SELECT seq FROM runs WHERE id=?", (run_id,)).fetchone()[0]
        db.execute(
            "INSERT INTO events VALUES(?,?,?,?,?)",
            (run_id, seq, kind, canonical(payload or {}), time.time()),
        )

    @staticmethod
    def scoped(db, workspace, run_id):
        run = db.execute(
            "SELECT * FROM runs WHERE id=? AND workspace=?", (run_id, workspace)
        ).fetchone()
        if run is None:
            raise KeyError("Run unavailable in this workspace")
        return dict(run)

    @staticmethod
    def fenced(db, lease):
        run = db.execute("SELECT * FROM runs WHERE id=?", (lease["id"],)).fetchone()
        if (
            not run
            or run["execution"] != "running"
            or run["generation"] != lease["generation"]
            or run["lease_token"] != lease["lease_token"]
            or run["lease_until"] <= time.time()
        ):
            raise Conflict("Worker lease is stale; no transition accepted")
        return dict(run)

    def launch(self, workspace, actor, key, request):
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError("A bounded idempotency key is required")
        if set(request) != {"prior", "current"}:
            raise ValueError("Exactly prior and current sources are required")
        clean = {}
        for role in ("prior", "current"):
            source = request[role]
            if not isinstance(source, dict) or set(source) != {"name", "text"}:
                raise ValueError("Source requires name and UTF-8 text")
            name, text = source["name"], source["text"]
            if (
                not isinstance(name, str)
                or not 1 <= len(name) <= 120
                or "/" in name
                or "\\" in name
                or not name.lower().endswith((".txt", ".md"))
            ):
                raise ValueError("Use a plain .txt or .md filename")
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Both source versions must be nonempty text")
            try:
                raw = text.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ValueError("Source must be valid UTF-8") from exc
            if len(raw) > 50000 or any(ord(c) < 32 and c not in "\n\r\t" for c in text):
                raise ValueError(
                    "Source exceeds 50,000 bytes or contains binary controls"
                )
            clean[role] = {"name": name, "text": text}
        encoded = canonical(clean)
        request_digest = digest(encoded.encode())
        with self.db(True) as db:
            old = db.execute(
                "SELECT * FROM runs WHERE workspace=? AND actor=? AND launch_key=?",
                (workspace, actor, key),
            ).fetchone()
            if old:
                if old["request_digest"] != request_digest:
                    raise Conflict(
                        "Idempotency key was already used with a different request"
                    )
                return dict(old)
            task_id, run_id = uid(), uid()
            db.execute(
                "INSERT INTO tasks VALUES(?,?,?,?,?,?)",
                (task_id, workspace, actor, encoded, request_digest, time.time()),
            )
            for role, source in clean.items():
                raw = source["text"].encode()
                db.execute(
                    "INSERT INTO sources VALUES(?,?,?,?,?,?)",
                    (uid(), task_id, role, source["name"], raw, digest(raw)),
                )
            db.execute(
                """INSERT INTO runs
                (id,task_id,workspace,actor,launch_key,request_digest,graph_thread_id,checkpoint_id)
                VALUES(?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    task_id,
                    workspace,
                    actor,
                    key,
                    request_digest,
                    "fixture:" + run_id,
                    uid(),
                ),
            )
            self.event(db, run_id, "queued")
            return self.scoped(db, workspace, run_id)

    def resolve_launch(self, workspace, actor, key):
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError("A bounded launch key is required")
        with self.db() as db:
            row = db.execute(
                "SELECT id,execution FROM runs WHERE workspace=? AND actor=? AND launch_key=?",
                (workspace, actor, key),
            ).fetchone()
            if row is None:
                raise KeyError("Launch unavailable in this workspace/reviewer scope")
            return dict(row)

    @staticmethod
    def source_rows(db, run):
        rows = db.execute(
            "SELECT * FROM sources WHERE task_id=? ORDER BY CASE role "
            "WHEN 'prior' THEN 0 ELSE 1 END",
            (run["task_id"],),
        ).fetchall()
        result = []
        for row in rows:
            s = dict(row)
            raw = s.pop("bytes")
            if digest(raw) != s["file_sha256"]:
                raise Conflict("Immutable source checksum mismatch")
            s["text"] = raw.decode("utf-8")
            s["locator"] = (
                f"/api/workspaces/{run['workspace']}/runs/{run['id']}/sources/{s['id']}"
            )
            result.append(s)
        if len(result) != 2:
            raise Conflict("Immutable source version is missing")
        return result

    def sources(self, run_id):
        with self.db() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError("Run unavailable")
            return self.source_rows(db, dict(row))

    def claim(self, worker, lease_seconds=30):
        now = time.time()
        with self.db(True) as db:
            row = db.execute(
                """SELECT * FROM runs WHERE execution='queued'
                OR (execution='running' AND lease_until<=?) ORDER BY rowid LIMIT 1""",
                (now,),
            ).fetchone()
            if not row:
                return None
            run = dict(row)
            if run["attempt_id"]:
                db.execute(
                    "UPDATE attempts SET status='lease_expired',ended=? WHERE id=?",
                    (now, run["attempt_id"]),
                )
            generation, token, attempt_id = run["generation"] + 1, uid(), uid()
            db.execute(
                """UPDATE runs SET execution='running',generation=?,lease_token=?,
                lease_until=?,attempt_id=? WHERE id=?""",
                (generation, token, now + lease_seconds, attempt_id, run["id"]),
            )
            db.execute(
                "INSERT INTO attempts VALUES(?,?,?,?,?,?,?)",
                (attempt_id, run["id"], worker, generation, now, None, "running"),
            )
            self.event(db, run["id"], "worker_claimed", {"generation": generation})
            return self.scoped(db, run["workspace"], run["id"])

    def heartbeat(self, lease, lease_seconds=30):
        with self.db(True) as db:
            run = self.fenced(db, lease)
            db.execute(
                "UPDATE runs SET lease_until=? WHERE id=?",
                (time.time() + lease_seconds, run["id"]),
            )
            return run["cancellation"]

    def checkpoint_payload(self, lease):
        with self.db() as db:
            run = self.fenced(db, lease)
            cp = db.execute(
                "SELECT * FROM checkpoints WHERE id=?", (run["checkpoint_id"],)
            ).fetchone()
            if cp is None:
                return None
            if digest(cp["payload"].encode()) != cp["payload_sha256"]:
                raise Conflict("Checkpoint integrity mismatch")
            return json.loads(cp["payload"])

    def checkpoint(self, lease, payload):
        encoded = canonical(payload)
        with self.db(True) as db:
            run = self.fenced(db, lease)
            old = db.execute(
                "SELECT payload FROM checkpoints WHERE id=?", (run["checkpoint_id"],)
            ).fetchone()
            if old:
                if old[0] != encoded:
                    raise Conflict("Saved checkpoint cannot be silently regenerated")
                return
            db.execute(
                "INSERT INTO checkpoints VALUES(?,?,?,?,?)",
                (
                    run["checkpoint_id"],
                    run["id"],
                    encoded,
                    digest(encoded.encode()),
                    time.time(),
                ),
            )
            self.event(db, run["id"], "checkpoint_saved")

    @staticmethod
    def load_checkpoint(db, run):
        cp = db.execute(
            "SELECT * FROM checkpoints WHERE id=?", (run["checkpoint_id"],)
        ).fetchone()
        if cp is None or digest(cp["payload"].encode()) != cp["payload_sha256"]:
            raise Conflict("Checkpoint missing or corrupt")
        return json.loads(cp["payload"])

    def save_blob(self, lease):
        with self.db(True) as db:
            run = self.fenced(db, lease)
            payload = self.load_checkpoint(db, run)
            raw = payload["text"].encode("utf-8")
            sha = digest(raw)
            db.execute(
                "INSERT OR IGNORE INTO blobs VALUES(?,?,?)", (sha, raw, time.time())
            )
            saved = db.execute(
                "SELECT bytes FROM blobs WHERE digest=?", (sha,)
            ).fetchone()[0]
            if saved != raw or digest(saved) != sha:
                raise Conflict("Saved draft checksum mismatch")
            return sha

    @staticmethod
    def end_attempt(db, run, status):
        db.execute(
            "UPDATE attempts SET ended=?,status=? WHERE id=?",
            (time.time(), status, run["attempt_id"]),
        )
        db.execute(
            "UPDATE runs SET lease_until=NULL,lease_token=NULL WHERE id=?", (run["id"],)
        )

    def publish(self, lease):
        with self.db(True) as db:
            run = self.fenced(db, lease)
            if run["cancellation"] == "requested":
                self.cancelled(db, run)
                return
            payload = self.load_checkpoint(db, run)
            sha = digest(payload["text"].encode())
            blob = db.execute(
                "SELECT bytes FROM blobs WHERE digest=?", (sha,)
            ).fetchone()
            if blob is None or digest(blob[0]) != sha:
                raise Conflict(
                    "Draft bytes must be saved and verified before publishing"
                )
            errors = validate(self.source_rows(db, run), payload)
            artifact_id = uid()
            db.execute(
                "INSERT INTO manifests VALUES(?,?,?,?,?,?,?,?)",
                (
                    artifact_id,
                    run["id"],
                    sha,
                    None,
                    None,
                    canonical(payload),
                    canonical(errors),
                    time.time(),
                ),
            )
            db.execute(
                """UPDATE runs SET artifact_id=?,execution=?,quality=?,review=?,
                review_expires=? WHERE id=?""",
                (
                    artifact_id,
                    "quality_failed" if errors else "draft_ready",
                    "failed" if errors else "fixture_supported",
                    "unavailable" if errors else "pending",
                    time.time() + 86400,
                    run["id"],
                ),
            )
            self.end_attempt(db, run, "quality_failed" if errors else "completed")
            self.event(
                db,
                run["id"],
                "quality_failed" if errors else "draft_saved",
                {
                    "artifact_id": artifact_id,
                    "file_sha256": sha,
                    "quality_errors": errors,
                },
            )

    @staticmethod
    def command(db, workspace, actor, kind, key, request):
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError("A bounded command key is required")
        sha = digest(canonical(request).encode())
        old = db.execute(
            "SELECT * FROM commands WHERE workspace=? AND actor=? AND kind=? AND key=?",
            (workspace, actor, kind, key),
        ).fetchone()
        if old and old["request_digest"] != sha:
            raise Conflict("Command key was already used with a different body")
        return sha, json.loads(old["result"]) if old else None

    @staticmethod
    def remember(db, workspace, actor, kind, key, sha, result):
        db.execute(
            "INSERT INTO commands VALUES(?,?,?,?,?,?)",
            (workspace, actor, kind, key, sha, canonical(result)),
        )

    def review(
        self, workspace, actor, run_id, key, decision, file_sha256, version, feedback
    ):
        if decision not in ("approve", "request_changes", "reject"):
            raise ValueError("Unknown review decision")
        if not isinstance(feedback, str) or len(feedback.encode()) > 4000:
            raise ValueError("Feedback must be at most 4,000 bytes")
        if decision == "request_changes" and not feedback.strip():
            raise ValueError("Request changes requires feedback")
        request = {
            "run_id": run_id,
            "decision": decision,
            "file_sha256": file_sha256,
            "review_version": version,
            "feedback": feedback,
        }
        with self.db(True) as db:
            run = self.scoped(db, workspace, run_id)
            sha, old = self.command(db, workspace, actor, "review", key, request)
            if old:
                return old
            sequences = [
                row[0]
                for row in db.execute(
                    "SELECT seq FROM events WHERE run_id=? ORDER BY seq", (run_id,)
                )
            ]
            if sequences != list(range(1, run["seq"] + 1)):
                raise Conflict("Review requires complete durable evidence history")
            if (
                run["execution"] != "draft_ready"
                or run["review"] != "pending"
                or run["review_version"] != version
                or run["review_expires"] <= time.time()
            ):
                raise Conflict("Review is stale, expired, conflicting or unavailable")
            manifest = db.execute(
                "SELECT * FROM manifests WHERE id=?", (run["artifact_id"],)
            ).fetchone()
            blob = db.execute(
                "SELECT bytes FROM blobs WHERE digest=?", (file_sha256,)
            ).fetchone()
            if not manifest or manifest["file_sha256"] != file_sha256 or not blob:
                raise Conflict("Review must match the exact saved draft")
            if digest(blob[0]) != file_sha256:
                raise Conflict("Draft checksum mismatch")
            self.verified_artifact(db, run)
            errors = validate(
                self.source_rows(db, run), json.loads(manifest["payload"])
            )
            if errors:
                raise Conflict("Evidence is incomplete or unsupported")
            result = {
                **request,
                "artifact_id": manifest["id"],
                "reviewer": actor,
                "request_version": run["request_version"],
                "expires": run["review_expires"],
                "created": time.time(),
                "id": uid(),
            }
            db.execute(
                "INSERT INTO reviews VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result["id"],
                    run_id,
                    manifest["id"],
                    file_sha256,
                    actor,
                    decision,
                    run["request_version"],
                    version,
                    run["review_expires"],
                    feedback,
                    result["created"],
                ),
            )
            db.execute(
                "UPDATE runs SET review=?,review_version=review_version+1 WHERE id=?",
                (decision, run_id),
            )
            self.event(db, run_id, "review_recorded", result)
            self.remember(db, workspace, actor, "review", key, sha, result)
            return result

    def cancel(self, workspace, actor, run_id, key):
        with self.db(True) as db:
            run = self.scoped(db, workspace, run_id)
            sha, old = self.command(
                db, workspace, actor, "cancel", key, {"run_id": run_id}
            )
            if old:
                result = old
            else:
                rejected = run["execution"] not in ("queued", "running")
                result = {
                    "run_id": run_id,
                    "cancellation": "rejected" if rejected else "requested",
                }
                if run["cancellation"] == "acknowledged":
                    result["cancellation"] = "acknowledged"
                elif run["cancellation"] != "requested":
                    db.execute(
                        "UPDATE runs SET cancellation=? WHERE id=?",
                        (result["cancellation"], run_id),
                    )
                    self.event(db, run_id, "cancellation_" + result["cancellation"])
                self.remember(db, workspace, actor, "cancel", key, sha, result)
        if result["cancellation"] == "rejected":
            raise Conflict(
                "Cancellation rejected: the saved result already won the race"
            )
        return result

    def cancelled(self, db, run):
        db.execute(
            "UPDATE runs SET execution='cancelled',cancellation='acknowledged' WHERE id=?",
            (run["id"],),
        )
        self.end_attempt(db, run, "cancelled")
        self.event(db, run["id"], "cancellation_acknowledged")

    def ack_cancel(self, lease):
        with self.db(True) as db:
            run = self.fenced(db, lease)
            if run["cancellation"] != "requested":
                raise Conflict("Cancellation was not requested")
            self.cancelled(db, run)

    def fail(self, lease, message):
        with self.db(True) as db:
            run = self.fenced(db, lease)
            if run["cancellation"] == "requested":
                self.cancelled(db, run)
            else:
                db.execute(
                    "UPDATE runs SET execution='failed' WHERE id=?", (run["id"],)
                )
                self.end_attempt(db, run, "failed")
                self.event(db, run["id"], "worker_failed", {"message": message[:300]})

    @staticmethod
    def event_rows(db, run_id, after=0):
        return [
            {**dict(r), "payload": json.loads(r["payload"])}
            for r in db.execute(
                "SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq",
                (run_id, after),
            )
        ]

    def verified_artifact(self, db, run):
        """Construct a projection only from mutually consistent saved evidence."""
        try:
            manifest = db.execute(
                "SELECT * FROM manifests WHERE id=?", (run["artifact_id"],)
            ).fetchone()
            if not manifest or manifest["run_id"] != run["id"]:
                raise Conflict("Saved manifest is missing or belongs to another run")
            blob = db.execute(
                "SELECT bytes FROM blobs WHERE digest=?", (manifest["file_sha256"],)
            ).fetchone()
            if not blob or digest(blob[0]) != manifest["file_sha256"]:
                raise Conflict("Saved draft bytes are missing or corrupt")
            payload = json.loads(manifest["payload"])
            checkpoint = self.load_checkpoint(db, run)
            if payload != checkpoint or payload["text"].encode("utf-8") != blob[0]:
                raise Conflict("Manifest, checkpoint and saved bytes disagree")
            sources = self.source_rows(db, run)
            errors = validate(sources, payload)
            if errors != json.loads(manifest["quality_errors"]):
                raise Conflict("Saved claim validation disagrees with its manifest")
            if (run["quality"] == "fixture_supported") != (not errors):
                raise Conflict("Saved quality state disagrees with evidence")
            return {
                **dict(manifest),
                **payload,
                "text": blob[0].decode("utf-8"),
                "quality_errors": errors,
            }
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise Conflict("Saved document projection is corrupt") from exc

    def snapshot(self, workspace, run_id):
        with self.db() as db:
            run = self.scoped(db, workspace, run_id)
            run.update(
                policy="not_evaluated",
                peers="not_evaluated",
                authority="not_evaluated",
                delivery="not_requested",
            )
            events = self.event_rows(db, run_id)
            integrity = (
                "complete"
                if [e["seq"] for e in events] == list(range(1, run["seq"] + 1))
                else "incomplete_evidence"
            )
            artifact = None
            try:
                sources = self.source_rows(db, run)
            except (Conflict, UnicodeError):
                sources = []
                integrity = "incomplete_evidence"
            if run["artifact_id"]:
                try:
                    artifact = self.verified_artifact(db, run)
                except Conflict:
                    integrity = "incomplete_evidence"
            review = db.execute(
                "SELECT * FROM reviews WHERE run_id=?", (run_id,)
            ).fetchone()
            attempts = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM attempts WHERE run_id=? ORDER BY started", (run_id,)
                )
            ]
            # Worker fencing credentials are internal and never sent to browsers.
            run.pop("lease_token", None)
            return {
                "run": run,
                "sources": sources,
                "artifact": artifact,
                "review_record": dict(review) if review else None,
                "attempts": attempts,
                "events": events,
                "cursor": run["seq"],
                "integrity": integrity,
            }

    def replay(self, workspace, run_id, after):
        with self.db() as db:
            run = self.scoped(db, workspace, run_id)
            if not isinstance(after, int) or after < 0:
                raise ValueError("Replay cursor must be nonnegative")
            events = self.event_rows(db, run_id, after)
            expected = list(range(after + 1, run["seq"] + 1))
            complete = after <= run["seq"] and [e["seq"] for e in events] == expected
            return {
                "events": events,
                "cursor": run["seq"],
                "integrity": "complete" if complete else "incomplete_evidence",
            }

    def reconcile(self):
        # Retain orphan bytes: deletion/retention is a separate user decision.
        with self.db() as db:
            orphan = db.execute(
                "SELECT COUNT(*) FROM blobs WHERE digest NOT IN "
                "(SELECT file_sha256 FROM manifests)"
            ).fetchone()[0]
            missing = db.execute(
                "SELECT COUNT(*) FROM manifests WHERE file_sha256 NOT IN "
                "(SELECT digest FROM blobs)"
            ).fetchone()[0]
            corrupt = 0
            for row in db.execute("SELECT * FROM runs WHERE artifact_id IS NOT NULL"):
                try:
                    self.verified_artifact(db, dict(row))
                except Conflict:
                    corrupt += 1
            return {
                "orphan_blobs": orphan,
                "missing_blobs": missing,
                "corrupt_projections": corrupt,
            }
