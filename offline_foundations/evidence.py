"""Scoped append-only SQLite evidence. Eligibility is not semantic truth or authority."""

import json
from dataclasses import dataclass

from .records import (
    ContractError,
    Database,
    FrozenRecord,
    append_only,
    canonical,
    hash_id,
    identity,
    integer,
    sha,
)

EvidenceError = ContractError
KINDS = {"observed_fact", "reported_claim", "plan", "inference"}
FIELDS = {
    "evidence_id",
    "source_locator",
    "source_revision",
    "revision_order",
    "source_text",
    "content_sha256",
    "claim_key",
    "claim_value",
    "claim_type",
    "observed_at_ms",
    "valid_from_ms",
    "valid_to_ms",
    "authority_class",
    "extraction_version",
    "provenance",
}


@dataclass(frozen=True)
class Scope:
    tenant: str
    project: str
    scope_class: str
    task: str | None
    run: str | None

    def __post_init__(self):
        identity(self.tenant)
        identity(self.project)
        if self.scope_class == "task":
            identity(self.task)
            identity(self.run)
        elif (
            self.scope_class != "project"
            or self.task is not None
            or self.run is not None
        ):
            raise EvidenceError(
                "Task/project scopes must be explicit; no implicit promotion"
            )

    @property
    def data(self):
        return {
            "tenant": self.tenant,
            "project": self.project,
            "scope_class": self.scope_class,
            "task": self.task,
            "run": self.run,
        }

    @property
    def key(self):
        return canonical(self.data)


@dataclass(frozen=True, init=False)
class Access:
    scope: Scope
    now_ms: int
    allowed_sources: frozenset
    _hashes: str

    def __init__(self, scope, now_ms, allowed_sources, source_hashes):
        if not isinstance(scope, Scope):
            raise EvidenceError("Authenticated scope context required")
        integer(now_ms)
        for key in allowed_sources:
            if not isinstance(key, tuple) or len(key) != 2:
                raise EvidenceError("Access must name locator and revision")
            identity(key[0])
            identity(key[1])
        for key, value in source_hashes.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise EvidenceError("Hash lookup requires exact source revision")
            identity(key[0])
            identity(key[1])
            hash_id(value)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "now_ms", now_ms)
        object.__setattr__(self, "allowed_sources", frozenset(allowed_sources))
        object.__setattr__(
            self,
            "_hashes",
            canonical([[list(k), v] for k, v in sorted(source_hashes.items())]),
        )

    @property
    def source_hashes(self):
        return {tuple(k): v for k, v in json.loads(self._hashes)}


SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS revisions (
 scope_key TEXT NOT NULL,evidence_id TEXT NOT NULL,source_key TEXT NOT NULL,
 revision_order INTEGER NOT NULL,claim_key TEXT NOT NULL,claim_type TEXT NOT NULL,
 observed INTEGER NOT NULL,valid_from INTEGER NOT NULL,valid_to INTEGER,
 body TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(scope_key,evidence_id));
CREATE INDEX IF NOT EXISTS evidence_claim_scope ON revisions(scope_key,claim_key,claim_type,observed);
CREATE TABLE IF NOT EXISTS blobs (scope_key TEXT NOT NULL,digest TEXT NOT NULL,bytes BLOB NOT NULL,
 PRIMARY KEY(scope_key,digest));
CREATE TABLE IF NOT EXISTS events (scope_key TEXT NOT NULL,event_id TEXT NOT NULL,
 kind TEXT NOT NULL,target TEXT NOT NULL,observed INTEGER NOT NULL,effective INTEGER NOT NULL,
 body TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(scope_key,event_id));
"""
    + append_only("revisions")
    + append_only("blobs")
    + append_only("events")
)


class EvidenceStore(Database):
    def __init__(self, path):
        super().__init__(path, SCHEMA)

    @staticmethod
    def event(db, scope, event_id, kind, target, observed, effective, body):
        encoded = canonical(body)
        digest = sha(encoded.encode())
        old = db.execute(
            "SELECT body FROM events WHERE scope_key=? AND event_id=?",
            (scope.key, event_id),
        ).fetchone()
        if old:
            if old[0] != encoded:
                raise EvidenceError("Evidence event idempotency conflict")
            return
        db.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",
            (scope.key, event_id, kind, target, observed, effective, encoded, digest),
        )

    def append(self, scope, record):
        if not isinstance(scope, Scope) or set(record) != FIELDS:
            raise EvidenceError("Evidence schema/scope mismatch")
        for k in (
            "evidence_id",
            "source_locator",
            "source_revision",
            "claim_key",
            "authority_class",
            "extraction_version",
        ):
            identity(record[k])
        for k in ("revision_order", "observed_at_ms", "valid_from_ms"):
            integer(record[k])
        if record["valid_to_ms"] is not None:
            integer(record["valid_to_ms"])
            if record["valid_to_ms"] <= record["valid_from_ms"]:
                raise EvidenceError("Validity interval must be nonempty")
        if record["claim_type"] not in KINDS:
            raise EvidenceError(
                "Claim type must preserve plan/inference/fact distinction"
            )
        text = record["source_text"]
        if not isinstance(text, str) or not text or len(text.encode()) > 50000:
            raise EvidenceError("Bounded retained source text required")
        content = text.encode()
        hash_id(record["content_sha256"])
        if sha(content) != record["content_sha256"]:
            raise EvidenceError("Source hash mismatch before admission")
        if not isinstance(record["provenance"], list) or len(
            set(record["provenance"])
        ) != len(record["provenance"]):
            raise EvidenceError("Unique explicit provenance references required")
        for ref in record["provenance"]:
            identity(ref)
        if record["claim_type"] == "inference" and not record["provenance"]:
            raise EvidenceError("Derived claims need provenance")
        body = canonical(
            {"protocol": "evidence_revision/v1", "scope": scope.data, **record}
        )
        digest = sha(body.encode())
        with self.connect(True) as db:
            old = db.execute(
                "SELECT body FROM revisions WHERE scope_key=? AND evidence_id=?",
                (scope.key, record["evidence_id"]),
            ).fetchone()
            if old:
                if old[0] != body:
                    raise EvidenceError("Revision identity cannot be rewritten")
                return FrozenRecord(old[0])
            db.execute(
                "INSERT OR IGNORE INTO blobs VALUES(?,?,?)",
                (scope.key, record["content_sha256"], content),
            )
            blob = db.execute(
                "SELECT bytes FROM blobs WHERE scope_key=? AND digest=?",
                (scope.key, record["content_sha256"]),
            ).fetchone()
            if not blob or blob[0] != content:
                raise EvidenceError("Immutable blob disagreement")
            source_key = canonical([record["source_locator"], record["claim_type"]])
            db.execute(
                "INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scope.key,
                    record["evidence_id"],
                    source_key,
                    record["revision_order"],
                    record["claim_key"],
                    record["claim_type"],
                    record["observed_at_ms"],
                    record["valid_from_ms"],
                    record["valid_to_ms"],
                    body,
                    digest,
                ),
            )
            self.event(
                db,
                scope,
                "revision:" + record["evidence_id"],
                "revision",
                record["evidence_id"],
                record["observed_at_ms"],
                record["valid_from_ms"],
                {"revision_digest": digest},
            )
            return FrozenRecord(body)

    def revoke(self, scope, event_id, target, observed, effective, reason):
        identity(event_id)
        identity(target)
        integer(observed)
        integer(effective)
        identity(reason)
        with self.connect(True) as db:
            if not db.execute(
                "SELECT 1 FROM revisions WHERE scope_key=? AND evidence_id=?",
                (scope.key, target),
            ).fetchone():
                raise EvidenceError("Revocation target unavailable in scope")
            self.event(
                db,
                scope,
                event_id,
                "revoke",
                target,
                observed,
                effective,
                {
                    "reason": reason,
                    "target": target,
                    "observed_at_ms": observed,
                    "effective_at_ms": effective,
                },
            )

    @staticmethod
    def rows(db, ctx, cutoff, valid_at):
        integer(cutoff)
        integer(valid_at)
        if cutoff > ctx.now_ms:
            raise EvidenceError(
                "Knowledge cutoff cannot exceed current observation time"
            )
        result = {}
        for r in db.execute(
            "SELECT * FROM revisions WHERE scope_key=? AND observed<=? AND valid_from<=?",
            (ctx.scope.key, cutoff, valid_at),
        ):
            if sha(r["body"].encode()) != r["digest"]:
                raise EvidenceError("Evidence record checksum mismatch")
            body = json.loads(r["body"])
            if body["scope"] != ctx.scope.data:
                raise EvidenceError("Persisted scope disagreement")
            expected = (
                body["evidence_id"],
                canonical([body["source_locator"], body["claim_type"]]),
                body["revision_order"],
                body["claim_key"],
                body["claim_type"],
                body["observed_at_ms"],
                body["valid_from_ms"],
                body["valid_to_ms"],
            )
            if (
                tuple(
                    r[k]
                    for k in (
                        "evidence_id",
                        "source_key",
                        "revision_order",
                        "claim_key",
                        "claim_type",
                        "observed",
                        "valid_from",
                        "valid_to",
                    )
                )
                != expected
            ):
                raise EvidenceError("Persisted evidence index/body disagreement")
            result[body["evidence_id"]] = body
        return result

    @staticmethod
    def revoked(db, ctx):
        result = set()
        for r in db.execute(
            "SELECT * FROM events WHERE scope_key=? AND kind='revoke' AND observed<=? AND effective<=?",
            (ctx.scope.key, ctx.now_ms, ctx.now_ms),
        ):
            if sha(r["body"].encode()) != r["digest"]:
                raise EvidenceError("Revocation event checksum mismatch")
            result.add(r["target"])
        return result

    @staticmethod
    def ambiguous(record, known):
        siblings = [
            r
            for r in known.values()
            if (r["source_locator"], r["claim_key"], r["claim_type"])
            == (record["source_locator"], record["claim_key"], record["claim_type"])
            and (
                r["revision_order"] == record["revision_order"]
                or r["source_revision"] == record["source_revision"]
            )
        ]
        return (
            len(
                {
                    canonical(
                        [
                            r["source_revision"],
                            r["revision_order"],
                            r["content_sha256"],
                            r["claim_value"],
                        ]
                    )
                    for r in siblings
                }
            )
            > 1
        )

    def eligible(self, db, ctx, record, known, revoked, valid_at, visiting=None):
        visiting = set() if visiting is None else set(visiting)
        rid = record["evidence_id"]
        if rid in visiting or rid in revoked:
            return False
        if record["valid_to_ms"] is not None and record["valid_to_ms"] <= valid_at:
            return False
        visiting.add(rid)
        key = (record["source_locator"], record["source_revision"])
        if (
            key not in ctx.allowed_sources
            or ctx.source_hashes.get(key) != record["content_sha256"]
        ):
            return False
        blob = db.execute(
            "SELECT bytes FROM blobs WHERE scope_key=? AND digest=?",
            (ctx.scope.key, record["content_sha256"]),
        ).fetchone()
        if (
            not blob
            or sha(blob[0]) != record["content_sha256"]
            or blob[0] != record["source_text"].encode()
        ):
            return False
        # Supersession is determined before availability filtering. An unavailable
        # successor cannot cause an older revision to reappear as current evidence.
        siblings = [
            r
            for r in known.values()
            if (r["source_locator"], r["claim_key"], r["claim_type"])
            == (record["source_locator"], record["claim_key"], record["claim_type"])
        ]
        if any(r["revision_order"] > record["revision_order"] for r in siblings):
            return False
        for ref in record["provenance"]:
            parent = known.get(ref)
            if (
                not parent
                or self.ambiguous(parent, known)
                or not self.eligible(
                    db, ctx, parent, known, revoked, valid_at, visiting
                )
            ):
                return False
        return True

    def query_in(self, db, ctx, claim_key, cutoff, valid_at, claim_types):
        if not isinstance(ctx, Access):
            raise EvidenceError("Current authenticated access context required")
        identity(claim_key)
        if not claim_types or set(claim_types) - KINDS:
            raise EvidenceError("Explicit recognized claim types required")
        known = self.rows(db, ctx, cutoff, valid_at)
        revoked = self.revoked(db, ctx)
        candidates = [
            r
            for r in known.values()
            if r["claim_key"] == claim_key
            and r["claim_type"] in claim_types
            and self.eligible(db, ctx, r, known, revoked, valid_at)
        ]
        candidates.sort(key=lambda r: (r["source_locator"], r["evidence_id"]))
        values = {canonical([r["claim_type"], r["claim_value"]]) for r in candidates}
        same_source_forks = {}
        for r in candidates:
            same_source_forks.setdefault(
                (r["source_locator"], r["revision_order"], r["claim_type"]), set()
            ).add(r["content_sha256"])
        conflict = (
            any(self.ambiguous(r, known) for r in candidates)
            or len(values) > 1
            or any(len(v) > 1 for v in same_source_forks.values())
        )
        status = (
            "abstain" if not candidates else "conflict" if conflict else "available"
        )
        return FrozenRecord.seal(
            {
                "protocol": "evidence_selection/v1",
                "scope": ctx.scope.data,
                "claim_key": claim_key,
                "cutoff": cutoff,
                "valid_at": valid_at,
                "claim_types": list(claim_types),
                "mode": "current_knowledge"
                if cutoff == ctx.now_ms
                else "as_known_then",
                "status": status,
                "records": candidates,
                "semantic_support": "gold_extracted_fixture_only",
                "authority": "not_evaluated",
            }
        )

    def query(self, ctx, claim_key, cutoff, valid_at, claim_types=("observed_fact",)):
        with self.connect() as db:
            return self.query_in(db, ctx, claim_key, cutoff, valid_at, claim_types)

    def consume(self, selection, ctx):
        data = selection.data
        if data["scope"] != ctx.scope.data or data["status"] != "available":
            return FrozenRecord.seal(
                {"status": "abstain", "reason": "scope_or_conflicting_selection"}
            )
        cutoff = ctx.now_ms if data["mode"] == "current_knowledge" else data["cutoff"]
        with self.connect() as db:
            fresh = self.query_in(
                db,
                ctx,
                data["claim_key"],
                cutoff,
                data["valid_at"],
                tuple(data["claim_types"]),
            )
        if (
            fresh.data["status"] != "available"
            or fresh.data["records"] != data["records"]
        ):
            return FrozenRecord.seal(
                {
                    "status": "abstain",
                    "reason": "consume_time_eligibility_or_precedence_changed",
                }
            )
        return fresh

    def dependencies(self, ctx, evidence_id, cutoff, valid_at):
        with self.connect() as db:
            known = self.rows(db, ctx, cutoff, valid_at)
            revoked = self.revoked(db, ctx)
            record = known.get(evidence_id)
            if (
                not record
                or self.ambiguous(record, known)
                or not self.eligible(db, ctx, record, known, revoked, valid_at)
            ):
                return FrozenRecord.seal({"status": "abstain", "ids": []})
            result = set()

            def walk(r):
                for ref in r["provenance"]:
                    if ref not in result:
                        result.add(ref)
                        walk(known[ref])

            walk(record)
            return FrozenRecord.seal(
                {
                    "status": "available",
                    "ids": sorted(result),
                    "mechanism": "bounded_relational_provenance_join",
                }
            )

    def audit(self):
        with self.connect() as db:
            for r in db.execute("SELECT body,digest FROM revisions"):
                if sha(r["body"].encode()) != r["digest"]:
                    raise EvidenceError("Revision checksum mismatch")
            return {
                "backend": "SQLite",
                "revisions": db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0],
                "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "postgresql_parity": "unrun",
                "model_extraction": "unrun",
            }
